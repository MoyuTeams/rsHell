#![cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
//! producer 的隔离 C/事务实测不认证 normal artifact；normal 测试必须消费父构建桥。

#[path = "support/selected_helper_loaded_raw_fixture.rs"]
mod fixture;
#[path = "../src/bin/selected_read_helper/mod.rs"]
pub mod helper;
#[cfg(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64"))]
#[path = "support/selected_helper_normal_allocations.rs"]
mod normal_allocations;
#[path = "support/selected_helper_normal_candidate.rs"]
mod normal_candidate;

use fixture::Fixture;
use helper::{production_protocol as wire, protocol};
use std::{
    io::{self, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

fn request(connection: bool) -> wire::WireValidatedRequest {
    let fields = if connection { 278 } else { 6 };
    wire::Request {
        c_max: 8 * 1024 * 1024,
        field_max: 65536,
        total_max: 1048576,
        tags_max: 256,
        connection: connection.then(|| {
            uuid::Uuid::parse_str(fixture::CONNECTION)
                .unwrap()
                .into_bytes()
        }),
        profile: None,
        wire_max: wire::wire_upper(fields, 1048576, if connection { 10 } else { 0 }).unwrap(),
        helper_rust_max: 65536,
        frame_count_max: fields,
        nonce: [7; 16],
    }
    .validate()
    .unwrap()
}

struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: ExitStatus,
}

fn read_bounded(mut reader: impl Read, cap: usize) -> Vec<u8> {
    let mut bytes = vec![0; cap + 1];
    let mut len = 0;
    loop {
        let n = reader.read(&mut bytes[len..]).unwrap();
        if n == 0 {
            break;
        }
        len += n;
        assert!(len <= cap, "子进程超出已有读取额度");
    }
    bytes.truncate(len);
    bytes
}

fn wait_reader(
    mut child: Child,
    bytes: &[u8],
    cap: usize,
    stdout: impl Read + Send + 'static,
) -> Output {
    let stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || read_bounded(stdout, cap));
    let err = thread::spawn(move || read_bounded(stderr, 128));
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            out.join().unwrap();
            err.join().unwrap();
            panic!("真实 helper 未在测试期限内退出");
        }
        thread::sleep(Duration::from_millis(5));
    };
    // 已收割退出且双方 drain 完成后，调用者才可认可 LoadedRaw。
    Output {
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
        status,
    }
}

fn spawn_probe(
    f: &Fixture,
    fault: &str,
    barrier: Option<(&str, &std::net::TcpListener)>,
) -> (Child, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "producer_child", "--ignored", "--quiet"])
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("SELECTED_RAW_PROBE_DB", &f.path)
        .env("SELECTED_TEST_FAULT", fault)
        .env(
            "SELECTED_RAW_PROBE_RESULT",
            listener.local_addr().unwrap().to_string(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some((name, control)) = barrier {
        command.env("SELECTED_TEST_BARRIER", name).env(
            "SELECTED_TEST_CONTROL",
            control.local_addr().unwrap().to_string(),
        );
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return (child, stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if child.try_wait().unwrap().is_some() {
                    panic!("隔离 child 未连接 raw 通道就已退出");
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("隔离 child raw 通道超时");
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("raw 通道错误：{:?}", error.kind());
            }
        }
    }
}

fn probe(f: &Fixture, r: wire::WireValidatedRequest, fault: &str) -> Output {
    let (child, stream) = spawn_probe(f, fault, None);
    wait_reader(child, &r.encode(), r.limits().wire_max as usize, stream)
}

fn at_barrier(
    f: &Fixture,
    r: wire::WireValidatedRequest,
    name: &str,
    mutate: impl FnOnce(),
) -> Output {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (child, stream) = spawn_probe(f, "", Some((name, &listener)));
    let owner = thread::spawn(move || {
        wait_reader(child, &r.encode(), r.limits().wire_max as usize, stream)
    });
    let (mut control, _) = listener.accept().unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut ready = [0];
    control.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [1]);
    mutate();
    control.write_all(&[1]).unwrap();
    owner.join().unwrap()
}

#[derive(Debug)]
struct Raw {
    preamble: Option<wire::Preamble>,
    fields: Vec<(wire::FieldHeader, Vec<u8>)>,
    footer: Option<wire::Footer>,
    stats: wire::Statistics,
    required_facts: Option<wire::RequiredFacts>,
}

fn parse(
    bytes: &[u8],
    request: wire::WireValidatedRequest,
    footer_required: bool,
) -> Result<Raw, wire::ProtocolError> {
    let mut state = wire::StreamState::new(request);
    let mut offset = 0;
    let mut preamble = None;
    let mut fields = Vec::new();
    let mut footer = None;
    while offset < bytes.len() {
        let magic = bytes
            .get(offset..offset + 8)
            .ok_or(wire::ProtocolError::Length)?;
        let length = match magic {
            b"SHSELHD2" => wire::PREAMBLE_LEN,
            b"SHSELFD2" => wire::FIELD_HEADER_LEN,
            b"SHSELFN2" => wire::FOOTER_LEN,
            _ => return Err(wire::ProtocolError::Magic),
        };
        let frame = bytes
            .get(offset..offset + length)
            .ok_or(wire::ProtocolError::Length)?;
        offset += length;
        match magic {
            b"SHSELHD2" => {
                let value = wire::Preamble::decode(frame, request)?;
                state.accept_preamble(value)?;
                preamble = Some(value);
            }
            b"SHSELFD2" => {
                let header = wire::FieldHeader::decode(frame)?;
                state.check_header(header)?;
                let end = offset
                    .checked_add(wire::checked_size(header.len)?)
                    .ok_or(wire::ProtocolError::Overflow)?;
                let payload = bytes.get(offset..end).ok_or(wire::ProtocolError::Length)?;
                state.accept_field(header, payload)?;
                fields.push((header, payload.to_vec()));
                offset = end;
            }
            _ => {
                let value = wire::Footer::decode(frame)?;
                state.accept_footer(value)?;
                footer = Some(value);
                if offset != bytes.len() {
                    return Err(wire::ProtocolError::TrailingBytes);
                }
            }
        }
    }
    if footer_required && footer.is_none() {
        return Err(wire::ProtocolError::State);
    }
    Ok(Raw {
        preamble,
        fields,
        footer,
        stats: state.statistics(),
        required_facts: if footer.is_some_and(|footer| footer.outcome == wire::Outcome::LoadedRaw) {
            Some(state.required_facts()?)
        } else {
            None
        },
    })
}

fn probe_report(output: &Output) -> (protocol::Outcome, u16, u64) {
    assert!(output.status.success(), "隔离 producer 必须正常退出");
    assert_eq!(output.stderr.len(), 128);
    assert_eq!(&output.stderr[..8], b"SHSELRES");
    let number = u16::from_le_bytes(output.stderr[10..12].try_into().unwrap());
    let outcome = match number {
        0 => protocol::Outcome::PreflightPassed,
        1 => protocol::Outcome::MissingConnection,
        2 => protocol::Outcome::MissingProfile,
        3 => protocol::Outcome::SelectedLimit,
        4 => protocol::Outcome::CBudgetExceeded,
        5 => protocol::Outcome::StorageFailure,
        9 => protocol::Outcome::InternalFailure,
        _ => panic!("非预期隔离结果码 {number}"),
    };
    assert_eq!(
        u64::from_le_bytes(output.stderr[64..72].try_into().unwrap()),
        0
    );
    (
        outcome,
        u32::from_le_bytes(output.stderr[12..16].try_into().unwrap()) as u16,
        u64::from_le_bytes(output.stderr[120..128].try_into().unwrap()),
    )
}

fn text(raw: &Raw, tag: u16) -> &str {
    let (header, bytes) = raw
        .fields
        .iter()
        .find(|(header, _)| header.tag == tag)
        .unwrap();
    assert_eq!(header.kind, wire::Kind::Utf8);
    std::str::from_utf8(bytes).unwrap()
}

fn optional(raw: &Raw, tag: u16) -> Option<&str> {
    let (header, bytes) = raw
        .fields
        .iter()
        .find(|(header, _)| header.tag == tag)
        .unwrap();
    if header.kind == wire::Kind::Null {
        None
    } else {
        Some(std::str::from_utf8(bytes).unwrap())
    }
}

fn oracle(f: &Fixture, raw: &Raw, has_connection: bool) {
    use rshell_core::{ConnectionId, ConnectionProfile, TerminalProfile, TerminalProfileId};
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Overrides {
        version: u8,
        #[serde(flatten)]
        options: rshell_core::TerminalOverrides,
    }
    #[derive(Deserialize)]
    struct Bindings {
        version: u8,
        key_bindings: Vec<rshell_core::KeyBinding>,
    }
    let repository = rshell_storage::SqliteRepository::open(&f.path).unwrap();
    let configuration = repository.load_configuration().unwrap();
    let app = repository.load_settings().unwrap();
    let profile_id = TerminalProfileId(uuid::Uuid::parse_str(text(raw, 20)).unwrap());
    let old_profile = configuration
        .profiles
        .iter()
        .find(|p| p.id == profile_id)
        .unwrap();
    let decoded_profile = TerminalProfile {
        id: profile_id,
        name: text(raw, 21).into(),
        settings: serde_json::from_str(text(raw, 22)).unwrap(),
    };
    assert!(
        decoded_profile == *old_profile,
        "完整 profile 与旧 codec 不等价"
    );
    assert_eq!(raw.preamble.unwrap().revision, configuration.revision);
    assert!(uuid::Uuid::parse_str(text(raw, 17)).unwrap() == app.default_terminal_profile.0);
    let color: rshell_core::ColorScheme =
        serde_json::from_value(serde_json::Value::String(text(raw, 18).into())).unwrap();
    assert!(color == app.color_scheme);
    let bindings: Bindings = serde_json::from_str(text(raw, 19)).unwrap();
    assert_eq!(bindings.version, 1);
    assert!(bindings.key_bindings == app.key_bindings);
    let db = f.open();
    let stored_json: String = db
        .query_row(
            "SELECT settings_json FROM terminal_profiles WHERE id=?1",
            [text(raw, 20)],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        text(raw, 22) == stored_json,
        "完整 JSON 包含 whitespace/未知内容，不能重编码"
    );
    let stored_bindings: String = db
        .query_row(
            "SELECT key_bindings_json FROM app_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        text(raw, 19) == stored_bindings,
        "versioned app JSON 必须保持原始 opaque 字节"
    );
    if has_connection {
        let old = repository
            .load_catalog()
            .unwrap()
            .connections
            .remove(&ConnectionId(
                uuid::Uuid::parse_str(fixture::CONNECTION).unwrap(),
            ))
            .unwrap();
        let overrides: Overrides = serde_json::from_str(text(raw, 16)).unwrap();
        assert_eq!(overrides.version, 1);
        let integer = |tag| {
            &raw.fields
                .iter()
                .find(|(header, _)| header.tag == tag)
                .unwrap()
                .1
        };
        let decoded = ConnectionProfile {
            id: ConnectionId(uuid::Uuid::parse_str(text(raw, 1)).unwrap()),
            group_id: optional(raw, 2)
                .map(|s| rshell_core::GroupId(uuid::Uuid::parse_str(s).unwrap())),
            name: text(raw, 3).into(),
            host: text(raw, 4).into(),
            port: u16::from_le_bytes(integer(5).as_slice().try_into().unwrap()),
            username: text(raw, 6).into(),
            transport: serde_json::from_value(serde_json::Value::String(text(raw, 7).into()))
                .unwrap(),
            authentication: serde_json::from_value(serde_json::Value::String(text(raw, 8).into()))
                .unwrap(),
            credential_ref: optional(raw, 9).map(rshell_core::CredentialRef::from),
            identity_file: optional(raw, 10).map(std::path::PathBuf::from),
            host_key_policy: serde_json::from_value(serde_json::Value::String(
                text(raw, 11).into(),
            ))
            .unwrap(),
            remote_command: optional(raw, 12).map(str::to_owned),
            note: text(raw, 13).into(),
            position: i64::from_le_bytes(integer(14).as_slice().try_into().unwrap()),
            terminal_profile_id: optional(raw, 15)
                .map(|s| TerminalProfileId(uuid::Uuid::parse_str(s).unwrap())),
            terminal_overrides: overrides.options,
            tags: raw
                .fields
                .iter()
                .filter(|(header, _)| header.tag == 23)
                .map(|(_, bytes)| String::from_utf8(bytes.clone()).unwrap())
                .collect(),
        };
        assert!(decoded == old, "完整连接与旧 codec 不等价");
        assert!(
            decoded_profile
                .settings
                .resolve(&decoded.terminal_overrides)
                .with_app_key_bindings(&app.key_bindings)
                == old_profile
                    .settings
                    .resolve(&old.terminal_overrides)
                    .with_app_key_bindings(&app.key_bindings)
        );
        let stored_overrides: String = db
            .query_row(
                "SELECT terminal_overrides_json FROM connections WHERE id=?1",
                [text(raw, 1)],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            text(raw, 16) == stored_overrides,
            "versioned overrides 必须保持原始 opaque 字节"
        );
        let mut s = db
            .prepare("SELECT connection_id,tag FROM connection_tags ORDER BY tag")
            .unwrap();
        let tags: Vec<String> = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .filter(|(id, _)| uuid::Uuid::parse_str(id).unwrap() == decoded.id.0)
            .map(|(_, tag)| tag)
            .collect();
        let actual: Vec<_> = raw
            .fields
            .iter()
            .filter(|(h, _)| h.tag == 23)
            .map(|(_, bytes)| std::str::from_utf8(bytes).unwrap())
            .collect();
        assert!(actual == tags, "tags 必须保持 SQLite ORDER BY tag 顺序");
    }
}

#[test]
fn producer_full_fields_old_codec_oracle_and_readonly_matrix() {
    for page in [512, 4096, 32768, 65536] {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let f = Fixture::new(page, encoding);
            for saved in [true, false] {
                let fixture_reader = f.open();
                let _: i64 = fixture_reader
                    .query_row("SELECT revision FROM configuration_revision", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                let before = f.bytes();
                let sidecars = f.sidecars();
                let r = request(saved);
                let output = probe(&f, r, "");
                assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
                let raw = parse(&output.stdout, r, false).unwrap();
                assert!(raw.footer.is_none(), "隔离成功不是认证 LoadedRaw");
                assert!(raw.required_facts.is_none());
                assert_eq!(
                    raw.preamble.unwrap().group_reference,
                    wire::GroupReferenceFact::NoReference
                );
                assert_eq!(raw.fields.len(), if saved { 27 } else { 6 });
                assert_eq!(raw.stats.integer_bytes, if saved { 10 } else { 0 });
                assert!(raw.stats.text_bytes <= raw.preamble.unwrap().text_upper);
                assert!(f.bytes() == before, "helper 不得修改静止 fixture 主库");
                assert_eq!(f.sidecars(), sidecars);
                // 旧 repository oracle 自身按原契约设置 WAL，不归因于 helper。
                oracle(&f, &raw, saved);
                drop(fixture_reader);
            }
        }
    }
}

#[test]
fn producer_priority_missing_limits_and_no_bulk_materialization() {
    let f = Fixture::new(4096, "UTF-8");
    let mut r = request(true).limits();
    r.profile = Some(
        uuid::Uuid::parse_str(fixture::EXPLICIT)
            .unwrap()
            .into_bytes(),
    );
    let valid = r.validate().unwrap();
    let output = probe(&f, valid, "");
    let raw = parse(&output.stdout, valid, false).unwrap();
    assert_eq!(raw.preamble.unwrap().source, 1);
    assert!(text(&raw, 20) == fixture::EXPLICIT);
    r.profile = Some([255; 16]);
    let valid = r.validate().unwrap();
    let output = probe(&f, valid, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::MissingProfile);
    assert!(
        parse(&output.stdout, valid, true)
            .unwrap()
            .preamble
            .is_none()
    );
    r = request(true).limits();
    r.connection = Some([255; 16]);
    let output = probe(&f, r.validate().unwrap(), "");
    assert_eq!(
        probe_report(&output).0,
        protocol::Outcome::MissingConnection
    );
    r = request(true).limits();
    r.field_max = 16;
    let valid = r.validate().unwrap();
    let output = probe(&f, valid, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::SelectedLimit);
    assert_eq!(output.stdout.len(), 128);
    f.unrelated();
    let output = probe(&f, request(true), "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
    let raw = parse(&output.stdout, request(true), false).unwrap();
    assert!(text(&raw, 20) == fixture::REFERENCED);
    assert_eq!(raw.fields.len(), 27);
}

#[test]
fn producer_nullable_empty_and_exact_selected_limits() {
    let f = Fixture::new(4096, "UTF-8");
    f.open().execute_batch("INSERT INTO connection_groups VALUES('00000000-0000-0000-0000-000000000004',NULL,'分组',0); UPDATE connections SET group_id='00000000-0000-0000-0000-000000000004',credential_ref='',identity_file='',remote_command=NULL,terminal_profile_id=NULL").unwrap();
    let r = request(true);
    let raw = parse(&probe(&f, r, "").stdout, r, false).unwrap();
    assert_eq!(optional(&raw, 9), Some(""));
    assert_eq!(optional(&raw, 10), Some(""));
    assert_eq!(optional(&raw, 12), None);
    assert_eq!(optional(&raw, 15), None);
    assert_eq!(raw.preamble.unwrap().source, 3);
    assert_eq!(
        raw.preamble.unwrap().group_reference,
        wire::GroupReferenceFact::Exists
    );
    oracle(&f, &raw, true);
    let mut limited = r.limits();
    limited.field_max = raw
        .fields
        .iter()
        .filter(|(h, _)| h.kind == wire::Kind::Utf8)
        .map(|(h, _)| h.len)
        .max()
        .unwrap();
    limited.total_max = raw.preamble.unwrap().text_upper;
    limited.tags_max = 5;
    limited.frame_count_max = 27;
    limited.wire_max = wire::wire_upper(27, limited.total_max, 10).unwrap();
    let exact = limited.validate().unwrap();
    assert_eq!(
        probe_report(&probe(&f, exact, "")).0,
        protocol::Outcome::PreflightPassed
    );
    for decrease in [0, 1, 2] {
        let mut failed = limited;
        if decrease == 0 {
            failed.field_max -= 1;
        } else if decrease == 1 {
            failed.total_max -= 1;
        } else {
            failed.tags_max -= 1;
            failed.frame_count_max -= 1;
        }
        failed.wire_max = wire::wire_upper(failed.frame_count_max, failed.total_max, 10).unwrap();
        let failed = failed.validate().unwrap();
        let output = probe(&f, failed, "");
        assert_eq!(probe_report(&output).0, protocol::Outcome::SelectedLimit);
        assert_eq!(
            parse(&output.stdout, failed, true)
                .unwrap()
                .footer
                .unwrap()
                .stats
                .completed_fields,
            0
        );
    }
    f.open()
        .execute("UPDATE connections SET position=?1", [i64::MIN])
        .unwrap();
    let raw = parse(&probe(&f, r, "").stdout, r, false).unwrap();
    let position = &raw.fields.iter().find(|(h, _)| h.tag == 14).unwrap().1;
    assert_eq!(
        i64::from_le_bytes(position.as_slice().try_into().unwrap()),
        i64::MIN
    );
}

#[test]
fn producer_group_facts_preserve_missing_invalid_uuid_and_json_check_order() {
    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        let f = Fixture::new(4096, encoding);
        let r = request(true);
        let repository = rshell_storage::SqliteRepository::open(&f.path).unwrap();
        let mut old_core = repository.load_catalog().unwrap();
        let group = rshell_core::GroupId(uuid::Uuid::parse_str(fixture::GROUP).unwrap());
        old_core
            .connections
            .get_mut(&rshell_core::ConnectionId(
                uuid::Uuid::parse_str(fixture::CONNECTION).unwrap(),
            ))
            .unwrap()
            .group_id = Some(group);
        assert!(old_core.validate() == Err(rshell_core::DomainError::GroupNotFound(group)));
        let db = f.open();
        db.pragma_update(None, "foreign_keys", false).unwrap();
        db.execute("UPDATE connections SET group_id=?1", [fixture::GROUP])
            .unwrap();
        let output = probe(&f, r, "");
        assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
        let raw = parse(&output.stdout, r, false).unwrap();
        assert_eq!(
            raw.preamble.unwrap().group_reference,
            wire::GroupReferenceFact::Absent
        );
        assert!(optional(&raw, 2) == Some(fixture::GROUP));
        assert!(raw.footer.is_none() && raw.required_facts.is_none());
        assert!(matches!(
            repository.load_catalog(),
            Err(rshell_storage::StorageError::Corrupt)
        ));
        db.execute(
            "UPDATE connections SET terminal_overrides_json=?1",
            ["{invalid opaque JSON"],
        )
        .unwrap();
        let output = probe(&f, r, "");
        assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
        let raw = parse(&output.stdout, r, false).unwrap();
        assert_eq!(
            raw.preamble.unwrap().group_reference,
            wire::GroupReferenceFact::Absent
        );
        assert!(text(&raw, 16) == "{invalid opaque JSON");
        assert!(serde_json::from_str::<serde_json::Value>(text(&raw, 16)).is_err());
        assert!(matches!(
            repository.load_catalog(),
            Err(rshell_storage::StorageError::Corrupt)
        ));
        for reference in ["", "不是 UUID😀", "abcdefab\0cdefabcd"] {
            db.execute("UPDATE connections SET group_id=?1", [reference])
                .unwrap();
            let output = probe(&f, r, "");
            assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
            let raw = parse(&output.stdout, r, false).unwrap();
            assert_eq!(
                raw.preamble.unwrap().group_reference,
                wire::GroupReferenceFact::InvalidUuid
            );
            assert!(optional(&raw, 2) == Some(reference));
            assert!(text(&raw, 16) == "{invalid opaque JSON");
        }
    }
}

#[test]
fn producer_binary_uuid_aliases_match_old_catalog_without_rewriting_raw_fields() {
    use rusqlite::params;
    let forms = |id: &str| {
        let uuid = uuid::Uuid::parse_str(id).unwrap();
        [
            id.to_uppercase(),
            uuid.simple().to_string(),
            uuid.braced().to_string(),
            uuid.urn().to_string(),
        ]
    };
    for (index, page) in [512, 4096, 32768, 65536].into_iter().enumerate() {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let f = Fixture::new(page, encoding);
            let connection = &forms(fixture::CONNECTION)[index];
            let profile = &forms(fixture::REFERENCED)[(index + 1) % 4];
            let saved = &forms(fixture::REFERENCED)[(index + 2) % 4];
            let stored_group = &forms(fixture::GROUP)[(index + 3) % 4];
            let reference_group = &forms(fixture::GROUP)[index];
            f.group(stored_group, reference_group);
            let db = f.open();
            db.pragma_update(None, "foreign_keys", false).unwrap();
            db.execute(
                "UPDATE connections SET id=?1,terminal_profile_id=?2 WHERE id=?3",
                params![connection, saved, fixture::CONNECTION],
            )
            .unwrap();
            db.execute(
                "UPDATE terminal_profiles SET id=?1 WHERE id=?2",
                params![profile, fixture::REFERENCED],
            )
            .unwrap();
            let default: String = db
                .query_row(
                    "SELECT default_terminal_profile FROM app_settings",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let default_stored = &forms(&default)[(index + 2) % 4];
            let default_reference = &forms(&default)[(index + 3) % 4];
            db.execute(
                "UPDATE terminal_profiles SET id=?1 WHERE id=?2",
                params![default_stored, default],
            )
            .unwrap();
            db.execute(
                "UPDATE app_settings SET default_terminal_profile=?1",
                [default_reference],
            )
            .unwrap();
            for (ordinal, alias) in forms(fixture::CONNECTION).into_iter().enumerate() {
                db.execute(
                    "INSERT INTO connection_tags VALUES(?1,?2)",
                    params![alias, format!("别名标签{ordinal}")],
                )
                .unwrap();
            }
            let r = request(true);
            let output = probe(&f, r, "");
            assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
            let raw = parse(&output.stdout, r, false).unwrap();
            assert_eq!(
                raw.preamble.unwrap().group_reference,
                wire::GroupReferenceFact::Exists
            );
            assert!(text(&raw, 1) == connection);
            assert!(text(&raw, 15) == saved);
            assert!(text(&raw, 20) == profile);
            assert!(text(&raw, 17) == default_reference);
            assert!(optional(&raw, 2) == Some(reference_group));
            oracle(&f, &raw, true);
            // 显式 profile 的请求仍为二进制 UUID；文本 alias 不改变选择优先级。
            let mut explicit = r.limits();
            explicit.profile = Some(
                uuid::Uuid::parse_str(fixture::REFERENCED)
                    .unwrap()
                    .into_bytes(),
            );
            let explicit = explicit.validate().unwrap();
            let raw = parse(&probe(&f, explicit, "").stdout, explicit, false).unwrap();
            assert_eq!(raw.preamble.unwrap().source, 1);
            assert!(text(&raw, 20) == profile);
            let temporary = request(false);
            let raw = parse(&probe(&f, temporary, "").stdout, temporary, false).unwrap();
            assert_eq!(
                raw.preamble.unwrap().group_reference,
                wire::GroupReferenceFact::NoReference
            );
            assert!(text(&raw, 20) == default_stored);
            oracle(&f, &raw, false);
        }
    }
}

#[test]
fn producer_group_fact_uses_same_snapshot_before_preflight_and_materialization() {
    for (initially_exists, commit) in [(true, true), (false, true), (true, false)] {
        for barrier in ["raw-snapshot", "raw-preflight", "raw-materialize"] {
            let f = Fixture::new(4096, "UTF-8");
            let r = request(true);
            let db = f.open();
            db.pragma_update(None, "foreign_keys", false).unwrap();
            db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
            db.execute("UPDATE connections SET group_id=?1", [fixture::GROUP])
                .unwrap();
            if initially_exists {
                db.execute(
                    "INSERT INTO connection_groups VALUES(?1,NULL,'分组',0)",
                    [fixture::GROUP],
                )
                .unwrap();
            }
            let output = at_barrier(&f, r, barrier, || {
                db.execute_batch("BEGIN IMMEDIATE").unwrap();
                if initially_exists {
                    db.execute("DELETE FROM connection_groups", []).unwrap();
                } else {
                    db.execute(
                        "INSERT INTO connection_groups VALUES(?1,NULL,'新组',0)",
                        [fixture::GROUP],
                    )
                    .unwrap();
                }
                db.execute_batch("UPDATE configuration_revision SET revision=11")
                    .unwrap();
                db.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })
                    .unwrap();
            });
            assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
            let raw = parse(&output.stdout, r, false).unwrap();
            assert_eq!(raw.preamble.unwrap().revision, 7);
            assert_eq!(
                raw.preamble.unwrap().group_reference,
                if initially_exists {
                    wire::GroupReferenceFact::Exists
                } else {
                    wire::GroupReferenceFact::Absent
                }
            );
            assert!(optional(&raw, 2) == Some(fixture::GROUP));
            let raw = parse(&probe(&f, r, "").stdout, r, false).unwrap();
            let now_exists = if commit {
                !initially_exists
            } else {
                initially_exists
            };
            assert_eq!(
                raw.preamble.unwrap().group_reference,
                if now_exists {
                    wire::GroupReferenceFact::Exists
                } else {
                    wire::GroupReferenceFact::Absent
                }
            );
            assert_eq!(raw.preamble.unwrap().revision, if commit { 11 } else { 7 });
        }
    }
}

#[test]
fn producer_group_membership_does_not_materialize_unrelated_tree_or_large_records() {
    let f = Fixture::new(4096, "UTF-8");
    f.group(fixture::GROUP, fixture::GROUP);
    f.unrelated();
    let mut db = f.open();
    db.pragma_update(None, "foreign_keys", false).unwrap();
    let tx = db.transaction().unwrap();
    for id in 100..2100 {
        tx.execute(
            "INSERT INTO connection_groups VALUES(?1,NULL,'无关组',0)",
            [uuid::Uuid::from_u128(id).to_string()],
        )
        .unwrap();
    }
    tx.execute(
        "INSERT INTO connection_groups VALUES(?1,'无效的非 selected 树引用',?2,-1)",
        rusqlite::params![
            uuid::Uuid::from_u128(4096).to_string(),
            "x".repeat(17 * 1024 * 1024)
        ],
    )
    .unwrap();
    // 不匹配 selected UUID 的 id 也不能引入全 catalog validity。
    tx.execute_batch(
        "INSERT INTO connection_groups VALUES(CAST(x'80' AS TEXT),NULL,'非 selected',0)",
    )
    .unwrap();
    tx.commit().unwrap();
    drop(db);
    let r = request(true);
    let output = probe(&f, r, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
    let raw = parse(&output.stdout, r, false).unwrap();
    assert_eq!(
        raw.preamble.unwrap().group_reference,
        wire::GroupReferenceFact::Exists
    );
    assert_eq!(raw.fields.len(), 27);
    assert!(text(&raw, 20) == fixture::REFERENCED);
    let db = f.open();
    db.pragma_update(None, "foreign_keys", false).unwrap();
    db.execute(
        "UPDATE connections SET group_id=?1 WHERE id=?2",
        rusqlite::params!["abcdefab-cdef-abcd-efab-cdefabcdef05", fixture::CONNECTION],
    )
    .unwrap();
    let output = probe(&f, r, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
    let raw = parse(&output.stdout, r, false).unwrap();
    assert_eq!(
        raw.preamble.unwrap().group_reference,
        wire::GroupReferenceFact::Absent
    );
}

#[test]
fn producer_outer_success_quota_and_cleanup_are_fail_closed() {
    let f = Fixture::new(4096, "UTF-8");
    let r = request(true);
    for (fault, completed) in [("raw-convert-policy", 2), ("raw-cleanup-policy", 27)] {
        let output = probe(&f, r, fault);
        assert_eq!(probe_report(&output).0, protocol::Outcome::CBudgetExceeded);
        let raw = parse(&output.stdout, r, true).unwrap();
        let footer = raw.footer.unwrap();
        assert_eq!(footer.outcome, wire::Outcome::CBudgetExceeded);
        assert_eq!(footer.stats.completed_fields, completed);
        assert_eq!(
            footer.diagnostics.code, 0,
            "实际 C 成功收口，不能伪造 NOMEM"
        );
        assert_ne!(footer.flags & wire::QUOTA_PROVED, 0);
        assert_ne!(footer.diagnostics.first_quota_op, 0);
    }
    let output = probe(&f, r, "partial-payload");
    assert_eq!(probe_report(&output).0, protocol::Outcome::InternalFailure);
    assert_eq!(output.stdout.len(), 64 + 24 + 18);
    assert!(parse(&output.stdout, r, true).is_err());
    let output = probe(&f, r, "partial-footer");
    assert_eq!(probe_report(&output).0, protocol::Outcome::SelectedLimit);
    assert_eq!(output.stdout.len(), 64);
    assert!(parse(&output.stdout, r, true).is_err());
    f.open()
        .execute("UPDATE connections SET note=zeroblob(8)", [])
        .unwrap();
    let output = probe(&f, r, "raw-cleanup-policy");
    assert_eq!(probe_report(&output).0, protocol::Outcome::StorageFailure);
    let footer = parse(&output.stdout, r, true).unwrap().footer.unwrap();
    assert_eq!(
        footer.diagnostics.code, 2,
        "已确认 Corrupt 不得被 cleanup quota 覆盖"
    );
    assert_ne!(footer.flags & wire::QUOTA_PROVED, 0);
}

#[test]
fn producer_same_snapshot_concurrent_commit_and_rollback() {
    for barrier in ["raw-snapshot", "raw-preflight", "raw-materialize"] {
        let f = Fixture::new(4096, "UTF-16le");
        let db = f.open();
        db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        let old_json: String = db
            .query_row(
                "SELECT settings_json FROM terminal_profiles WHERE id=?1",
                [fixture::REFERENCED],
                |r| r.get(0),
            )
            .unwrap();
        let r = request(true);
        let output = at_barrier(&f, r, barrier, || {
            db.execute_batch("BEGIN IMMEDIATE; UPDATE configuration_revision SET revision=9; UPDATE connections SET name='新值',terminal_profile_id=NULL; DELETE FROM connection_tags; UPDATE terminal_profiles SET settings_json='新的 opaque JSON'; UPDATE app_settings SET color_scheme='dracula'; COMMIT").unwrap();
        });
        assert_eq!(probe_report(&output).0, protocol::Outcome::PreflightPassed);
        let raw = parse(&output.stdout, r, false).unwrap();
        assert_eq!(raw.preamble.unwrap().revision, 7);
        assert_eq!(raw.preamble.unwrap().source, 2);
        assert!(text(&raw, 3) == "示例\0尾");
        assert!(text(&raw, 20) == fixture::REFERENCED);
        assert!(text(&raw, 22) == old_json);
        assert!(text(&raw, 18) == "nord");
        assert_eq!(raw.fields.len(), 27);
    }
    let f = Fixture::new(4096, "UTF-8");
    let db = f.open();
    db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let r = request(true);
    let output = at_barrier(&f, r, "raw-preflight", || {
        db.execute_batch("BEGIN IMMEDIATE; UPDATE connections SET name='未提交'; UPDATE configuration_revision SET revision=99; ROLLBACK").unwrap();
    });
    let raw = parse(&output.stdout, r, false).unwrap();
    assert!(text(&raw, 3) == "示例\0尾");
    assert_eq!(raw.preamble.unwrap().revision, 7);
}

#[test]
fn producer_authorizer_survives_actual_auto_recompile() {
    let f = Fixture::new(4096, "UTF-8");
    let db = f.open();
    db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let r = request(true);
    let output = at_barrier(&f, r, "raw-prepared", || {
        db.execute_batch("ALTER TABLE connections ADD COLUMN future_extra TEXT")
            .unwrap();
    });
    let report = probe_report(&output);
    assert_eq!(report.0, protocol::Outcome::PreflightPassed);
    assert!(report.2 > 0, "真实 sqlite3_step 必须发生自动重编译");
    let output = at_barrier(&f, r, "raw-prepared", || {
        db.execute_batch("DROP TABLE configuration_revision; CREATE TABLE hidden_metadata(revision INTEGER,singleton INTEGER); INSERT INTO hidden_metadata VALUES(7,1); CREATE VIEW configuration_revision AS SELECT revision,singleton FROM hidden_metadata").unwrap();
    });
    assert_eq!(probe_report(&output).0, protocol::Outcome::StorageFailure);
    let footer = parse(&output.stdout, r, true).unwrap().footer.unwrap();
    assert_eq!(footer.diagnostics.code, 2);
    assert_eq!(footer.stats.completed_fields, 0);
}

#[test]
fn producer_actual_c_quota_and_selected_sql_types() {
    let f = Fixture::new(4096, "UTF-8");
    for sql in [
        "UPDATE connections SET note=zeroblob(8)",
        "UPDATE terminal_profiles SET name=zeroblob(8)",
    ] {
        let tx = f.open();
        tx.execute_batch("BEGIN").unwrap();
        tx.execute_batch(sql).unwrap();
        // 不提交的变化对 helper 不可见。
        assert_eq!(
            probe_report(&probe(&f, request(true), "")).0,
            protocol::Outcome::PreflightPassed
        );
        tx.execute_batch("ROLLBACK").unwrap();
    }
    f.open()
        .execute("UPDATE connections SET note=zeroblob(8)", [])
        .unwrap();
    assert_eq!(
        probe_report(&probe(&f, request(true), "")).0,
        protocol::Outcome::StorageFailure
    );
    f.open()
        .execute("UPDATE connections SET note='恢复'", [])
        .unwrap();
    let mut db = f.open();
    let tx = db.transaction().unwrap();
    for n in 0..400 {
        tx.execute_batch(&format!("CREATE TABLE extra_{n}(a TEXT,b TEXT,c TEXT,d TEXT,e TEXT,f TEXT,g TEXT,h TEXT,i TEXT,j TEXT,k TEXT,l TEXT);")).unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    let mut r = request(true).limits();
    r.c_max = 65536;
    let r = r.validate().unwrap();
    let output = probe(&f, r, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::CBudgetExceeded);
    let raw = parse(&output.stdout, r, true).unwrap();
    assert!(raw.preamble.is_none());
    assert_ne!(raw.footer.unwrap().flags & wire::QUOTA_PROVED, 0);
}

#[test]
fn producer_invalid_utf8_storage_failure_stays_at_complete_field_boundary() {
    let f = Fixture::new(4096, "UTF-8");
    let r = request(true);
    f.open()
        .execute_batch("UPDATE connections SET note=CAST(x'80' AS TEXT)")
        .unwrap();
    assert!(matches!(
        rshell_storage::SqliteRepository::open(&f.path)
            .unwrap()
            .load_catalog(),
        Err(rshell_storage::StorageError::Corrupt)
    ));
    let output = probe(&f, r, "");
    assert_eq!(probe_report(&output).0, protocol::Outcome::StorageFailure);
    let raw = parse(&output.stdout, r, true).unwrap();
    let footer = raw.footer.unwrap();
    assert_eq!(footer.outcome, wire::Outcome::StorageFailure);
    assert_eq!(footer.stats.completed_fields, 12);
    assert_eq!(footer.diagnostics.code, 2);
    assert_eq!(footer.flags & wire::QUOTA_PROVED, 0);
}

fn normal(f: &Fixture, mut r: wire::Request, grant: Option<u64>) -> Output {
    use helper::rust_budget::{FixedLimits, HelperLaunchShape, HelperRustCertificate, SqlRoute};
    let mut candidate = normal_candidate::Candidate::load();
    let executable = candidate.executable().as_os_str();
    let build = candidate.evidence().verify_artifact().unwrap();
    let certificate = HelperRustCertificate::calculate(
        build,
        HelperLaunchShape::from_paths(executable, f.path.as_os_str()).unwrap(),
        FixedLimits {
            c_max: r.c_max,
            field_max: r.field_max,
            total_max: r.total_max,
            tags_max: r.tags_max,
        },
        SqlRoute::FixedCStr,
    )
    .unwrap();
    r.helper_rust_max = grant.unwrap_or(certificate.rust_max() as u64);
    let request = r.validate().unwrap();
    let full = certificate.spawn_bytes().unwrap();
    let ledger = normal_candidate::Ledger::new(full);
    let reservation = ledger.reserve(full).unwrap();
    assert_eq!(ledger.held(), full);
    assert!(ledger.reserve(1).is_none());
    let mut command = Command::new(executable);
    command
        .arg(&f.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert!(
        command.get_envs().next().is_none(),
        "正常子进程必须完整继承环境"
    );
    let child = command.spawn().unwrap();
    assert!(child.stdin.is_some() && child.stdout.is_some() && child.stderr.is_some());
    let output = wait_reserved(
        child,
        &request.encode(),
        r.wire_max as usize,
        reservation,
        &ledger,
    );
    assert_eq!(ledger.held(), 0);
    candidate.verify_unchanged();
    output
}

struct ReservedChild {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
    reservation: Option<normal_candidate::Grant>,
}
impl Drop for ReservedChild {
    fn drop(&mut self) {
        // 成功和 unwind 都必须先收割、关闭／drain 两路 reader，最后才返 H+C。
        drop(self.child.stdin.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let exited = self.child.wait().is_ok();
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
        if !exited {
            std::mem::forget(self.reservation.take());
        }
    }
}
fn wait_reserved(
    child: Child,
    bytes: &[u8],
    cap: usize,
    reservation: normal_candidate::Grant,
    ledger: &normal_candidate::Ledger,
) -> Output {
    let mut owner = ReservedChild {
        child,
        stdout: None,
        stderr: None,
        reservation: Some(reservation),
    };
    let stdout = owner.child.stdout.take().unwrap();
    let stderr = owner.child.stderr.take().unwrap();
    owner.stdout = Some(thread::spawn(move || read_bounded(stdout, cap)));
    owner.stderr = Some(thread::spawn(move || read_bounded(stderr, 128)));
    owner.child.stdin.take().unwrap().write_all(bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = owner.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "真实候选超时，owned child 将 kill/wait/drain 后返额"
        );
        thread::sleep(Duration::from_millis(5));
    };
    let held = ledger.held();
    assert!(held > 0);
    let stdout = owner.stdout.take().unwrap().join();
    assert_eq!(ledger.held(), held);
    let stderr = owner.stderr.take().unwrap().join();
    assert_eq!(ledger.held(), held);
    let output = Output {
        stdout: stdout.unwrap(),
        stderr: stderr.unwrap(),
        status,
    };
    drop(owner);
    output
}

#[test]
fn normal_v2_full_loaded_raw_actual_subprocess() {
    for (index, page) in [512, 4096, 32768, 65536].into_iter().enumerate() {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let f = Fixture::new(page, encoding);
            let r = request(true);
            let before = f.bytes();
            let sidecars = f.sidecars();
            let output = normal(&f, r.limits(), None);
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            let raw = parse(&output.stdout, r, true).unwrap();
            assert!(f.bytes() == before);
            assert!(f.sidecars() == sidecars);
            assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
            assert_eq!(
                raw.required_facts.unwrap().group_reference(),
                wire::GroupReferenceFact::NoReference
            );
            oracle(&f, &raw, true);
            let temporary = request(false);
            let output = normal(&f, temporary.limits(), None);
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            let raw = parse(&output.stdout, temporary, true).unwrap();
            assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
            assert_eq!(
                raw.required_facts.unwrap().group_reference(),
                wire::GroupReferenceFact::NoReference
            );
            oracle(&f, &raw, false);
            let db = f.open();
            db.pragma_update(None, "foreign_keys", false).unwrap();
            let uuid = uuid::Uuid::parse_str(fixture::CONNECTION).unwrap();
            let connection_alias = [
                fixture::CONNECTION.to_uppercase(),
                uuid.simple().to_string(),
                uuid.braced().to_string(),
                uuid.urn().to_string(),
            ][index]
                .clone();
            let profile = uuid::Uuid::parse_str(fixture::REFERENCED).unwrap();
            let profile_alias = profile.braced().to_string();
            let saved_alias = profile.urn().to_string();
            db.execute(
                "UPDATE connections SET id=?1,terminal_profile_id=?2 WHERE id=?3",
                rusqlite::params![connection_alias, saved_alias, fixture::CONNECTION],
            )
            .unwrap();
            db.execute(
                "UPDATE terminal_profiles SET id=?1 WHERE id=?2",
                rusqlite::params![profile_alias, fixture::REFERENCED],
            )
            .unwrap();
            drop(db);
            let output = normal(&f, r.limits(), None);
            assert!(output.status.success() && output.stderr.is_empty());
            let raw = parse(&output.stdout, r, true).unwrap();
            assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
            assert!(
                text(&raw, 1) == connection_alias
                    && text(&raw, 15) == saved_alias
                    && text(&raw, 20) == profile_alias
            );
            oracle(&f, &raw, true);
            let selected_fields = raw.fields;
            f.unrelated();
            // 在既有 WAL/SHM reader 生存期内比较静止 fixture；该观察不证明 VFS 上界。
            let fixture_reader = f.open();
            let _: i64 = fixture_reader
                .query_row("SELECT revision FROM configuration_revision", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let before = f.bytes();
            let sidecars = f.sidecars();
            let output = normal(&f, r.limits(), None);
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            let raw = parse(&output.stdout, r, true).unwrap();
            assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
            assert!(
                raw.fields == selected_fields,
                "无关巨型记录不能改变完整 selected 字段流"
            );
            assert!(f.bytes() == before, "真实 helper 不得修改 canary 主库");
            assert!(
                f.sidecars() == sidecars,
                "真实 helper 的 WAL/SHM sidecar 集合变化"
            );
            drop(fixture_reader);
        }
    }
}

#[test]
fn normal_v2_insufficient_h_precedes_path_and_c_backing() {
    let f = Fixture::new(4096, "UTF-8");
    let r = request(true);
    let before = f.bytes();
    let output = normal(&f, r.limits(), Some(0));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.len(), 128);
    let raw = parse(&output.stdout, r, true).unwrap();
    let footer = raw.footer.unwrap();
    assert_eq!(footer.outcome, wire::Outcome::RustBudgetExceeded);
    assert_eq!(footer.diagnostics.phase, 1);
    assert!(footer.diagnostics.requested > 0);
    assert_eq!(footer.diagnostics.available, 0);
    assert_eq!(
        footer.flags & (wire::QUOTA_PROVED | wire::READONLY | wire::ENVELOPE_VERIFIED),
        0
    );
    assert!(f.bytes() == before);
}

#[test]
fn normal_v2_group_facts_loaded_raw_actual_subprocess() {
    for fact in [
        wire::GroupReferenceFact::Exists,
        wire::GroupReferenceFact::Absent,
        wire::GroupReferenceFact::InvalidUuid,
    ] {
        let f = Fixture::new(4096, "UTF-16be");
        if fact == wire::GroupReferenceFact::Exists {
            f.group(
                &uuid::Uuid::parse_str(fixture::GROUP)
                    .unwrap()
                    .urn()
                    .to_string(),
                fixture::GROUP,
            );
        } else {
            let db = f.open();
            db.pragma_update(None, "foreign_keys", false).unwrap();
            db.execute(
                "UPDATE connections SET group_id=?1,terminal_overrides_json='{invalid opaque JSON'",
                [if fact == wire::GroupReferenceFact::Absent {
                    fixture::GROUP
                } else {
                    "invalid UUID"
                }],
            )
            .unwrap();
        }
        let r = request(true);
        let output = normal(&f, r.limits(), None);
        assert!(output.status.success() && output.stderr.is_empty());
        let raw = parse(&output.stdout, r, true).unwrap();
        assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
        assert_eq!(raw.required_facts.unwrap().group_reference(), fact);
        assert_eq!(raw.fields.len(), 27);
        if fact == wire::GroupReferenceFact::Exists {
            oracle(&f, &raw, true);
        }
        if fact != wire::GroupReferenceFact::Exists {
            assert!(text(&raw, 16) == "{invalid opaque JSON");
        }
    }
}

#[cfg(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64"))]
#[test]
fn normal_v2_actual_candidate_allocation_closure_audit() {
    use helper::rust_budget::{FixedLimits, HelperLaunchShape, HelperRustCertificate, SqlRoute};
    for insufficient in [false, true] {
        let f = Fixture::new(4096, "UTF-16be");
        f.group(fixture::GROUP, fixture::GROUP);
        f.unrelated();
        let mut candidate = normal_candidate::Candidate::load();
        let mut r = request(true).limits();
        let certificate = HelperRustCertificate::calculate(
            candidate.evidence().verify_artifact().unwrap(),
            HelperLaunchShape::from_paths(candidate.executable().as_os_str(), f.path.as_os_str())
                .unwrap(),
            FixedLimits {
                c_max: r.c_max,
                field_max: r.field_max,
                total_max: r.total_max,
                tags_max: r.tags_max,
            },
            SqlRoute::FixedCStr,
        )
        .unwrap();
        r.helper_rust_max = if insufficient {
            0
        } else {
            certificate.rust_max() as u64
        };
        let r = r.validate().unwrap();
        let (output, audit) = normal_allocations::run(&mut candidate, &f.path, r, certificate);
        assert!(output.status.success() && output.stderr.is_empty());
        let raw = parse(&output.stdout, r, true).unwrap();
        if insufficient {
            assert_eq!(
                raw.footer.unwrap().outcome,
                wire::Outcome::RustBudgetExceeded
            );
            assert_eq!(
                audit.after_run, 0,
                "实际 run gate 后不可有 CString/C backing/producer allocation"
            );
            assert_eq!(audit.c_peak, 0);
        } else {
            assert_eq!(raw.footer.unwrap().outcome, wire::Outcome::LoadedRaw);
            assert_eq!(
                raw.required_facts.unwrap().group_reference(),
                wire::GroupReferenceFact::Exists
            );
            assert_eq!(
                audit.after_run, 2,
                "仅 path CString 和 C backing，producer 字段无 Rust allocation"
            );
            assert_eq!(audit.c_peak, certificate.c_backing().size());
            assert_eq!(raw.fields.len(), 27);
        }
        println!(
            "actual candidate record={} exe={} sources={} allocations={} RustPeak={} H={} CPeak={} afterRun={}",
            candidate.record_digest,
            candidate.executable_digest(),
            candidate.source_digest(),
            audit.allocations,
            audit.rust_peak,
            certificate.rust_max(),
            audit.c_peak,
            audit.after_run
        );
    }
}

#[test]
fn normal_v2_request_cancel_and_stdout_broken_reap_actual_child() {
    let f = Fixture::new(4096, "UTF-8");
    let mut candidate = normal_candidate::Candidate::load();
    let normal = candidate.executable();
    let r = request(true).limits();
    use helper::rust_budget::{FixedLimits, HelperLaunchShape, HelperRustCertificate, SqlRoute};
    let certificate = HelperRustCertificate::calculate(
        candidate.evidence().verify_artifact().unwrap(),
        HelperLaunchShape::from_paths(normal.as_os_str(), f.path.as_os_str()).unwrap(),
        FixedLimits {
            c_max: r.c_max,
            field_max: r.field_max,
            total_max: r.total_max,
            tags_max: r.tags_max,
        },
        SqlRoute::FixedCStr,
    )
    .unwrap();
    let full = certificate.spawn_bytes().unwrap();
    let frame = request(true).encode();
    let before = f.bytes();
    let ledger = normal_candidate::Ledger::new(full);
    let reservation = ledger.reserve(full).unwrap();
    let child = Command::new(normal)
        .arg(&f.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner = ReservedChild {
        child,
        stdout: None,
        stderr: None,
        reservation: Some(reservation),
    };
    let stdout = owner.child.stdout.take().unwrap();
    let stderr = owner.child.stderr.take().unwrap();
    let cap = frame.len();
    owner.stdout = Some(thread::spawn(move || read_bounded(stdout, cap)));
    owner.stderr = Some(thread::spawn(move || read_bounded(stderr, 128)));
    let mut input = owner.child.stdin.take().unwrap();
    input.write_all(&frame).unwrap();
    // request 后 EOF 尚未到达；只能由父取消，不能把 kill 或半帧冒充 Budget。
    assert!(owner.child.try_wait().unwrap().is_none());
    owner.child.kill().unwrap();
    let status = owner.child.wait().unwrap();
    drop(input);
    assert!(!status.success());
    let stdout = owner.stdout.take().unwrap().join().unwrap();
    let stderr = owner.stderr.take().unwrap().join().unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(ledger.held(), full);
    drop(owner);
    assert_eq!(ledger.held(), 0);
    let reservation = ledger.reserve(full).unwrap();
    let child = Command::new(normal)
        .arg(&f.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner = ReservedChild {
        child,
        stdout: None,
        stderr: None,
        reservation: Some(reservation),
    };
    drop(owner.child.stdout.take().unwrap());
    let stderr = owner.child.stderr.take().unwrap();
    owner.stderr = Some(thread::spawn(move || read_bounded(stderr, 128)));
    owner.child.stdin.take().unwrap().write_all(&frame).unwrap();
    assert_eq!(owner.child.wait().unwrap().code(), Some(2));
    assert!(owner.stderr.take().unwrap().join().unwrap().is_empty());
    assert_eq!(ledger.held(), full);
    drop(owner);
    assert_eq!(ledger.held(), 0);
    assert!(f.bytes() == before);
    candidate.verify_unchanged();
}

#[test]
fn normal_v2_missing_build_record_fails_without_database_access() {
    let r = request(true);
    let mut bytes = Vec::new();
    helper::normal_v2::run(
        std::ffi::OsStr::new(env!("CARGO_BIN_EXE_selected-read-helper")),
        std::ffi::OsStr::new("不存在的合成库"),
        r,
        None,
        &mut bytes,
    )
    .unwrap();
    let raw = parse(&bytes, r, true).unwrap();
    assert_eq!(
        raw.footer.unwrap().outcome,
        wire::Outcome::UnsupportedEnvelope
    );
    assert!(raw.preamble.is_none());
}

#[test]
fn normal_v2_actual_subprocess_admission_rejection_is_correlated() {
    let f = Fixture::new(4096, "UTF-8");
    let mut r = request(true).limits();
    r.helper_rust_max = 0;
    let r = r.validate().unwrap();
    let output = normal(&f, r.limits(), Some(0));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let raw = parse(&output.stdout, r, true).unwrap();
    let footer = raw.footer.unwrap();
    assert_eq!(footer.outcome, wire::Outcome::RustBudgetExceeded);
    assert_eq!(footer.nonce, r.limits().nonce);
    assert_eq!(footer.stats, wire::Statistics::default());
    assert!(raw.preamble.is_none());
}

struct Cut<W> {
    inner: W,
    remaining: usize,
    failed: bool,
}
impl<W: Write> Write for Cut<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(!self.failed, "写失败之后绝不能继续底层 write");
        if self.remaining == 0 {
            self.failed = true;
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = bytes.len().min(self.remaining);
        let wrote = self.inner.write(&bytes[..count])?;
        self.remaining -= wrote;
        Ok(wrote)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
#[ignore = "仅由专用 producer 测试以精确 child 入口运行"]
fn producer_child() {
    if std::env::var_os("SELECTED_RAW_PROBE_DB").is_none() {
        return;
    }
    // 独立 raw 通道避免 libtest 的输出进入 wire；正常 bin 仍只使用 stdout pipe。
    let stream =
        std::net::TcpStream::connect(std::env::var("SELECTED_RAW_PROBE_RESULT").unwrap()).unwrap();
    // 隔离 fixture 入口，不消费或伪造 HelperRustCertificate，不是 normal artifact。
    let request = wire::WireValidatedRequest::read(&mut io::stdin().lock()).unwrap();
    let path = helper::path_string(&std::env::var_os("SELECTED_RAW_PROBE_DB").unwrap()).unwrap();
    let mut arena = helper::envelope::Arena::new(request.limits().c_max as usize).unwrap();
    let partial_payload = helper::fault("partial-payload");
    let partial_footer = helper::fault("partial-footer");
    let mut cut = Cut {
        inner: stream,
        remaining: if partial_payload {
            106
        } else if partial_footer {
            64
        } else {
            usize::MAX
        },
        failed: false,
    };
    let mut writer = wire::FrameWriter::new(&mut cut, request);
    let initialized = helper::normal_v2::initialize(&mut arena, request.limits().c_max as usize);
    let result = if partial_footer {
        Ok(protocol::Report::new(protocol::Outcome::SelectedLimit))
    } else {
        match initialized {
            Ok(()) => helper::producer::run(&path, request, &mut arena, &mut writer),
            Err(report) => Ok(report),
        }
    };
    let report = match result {
        Ok(report) => report,
        Err(_) => protocol::Report::new(protocol::Outcome::InternalFailure),
    };
    let report = helper::normal_v2::shutdown(&mut arena, report);
    if report.outcome != protocol::Outcome::PreflightPassed && !writer.is_failed() {
        let (outcome, flags, diagnostics) = helper::normal_v2::completion(&arena, report);
        let _ = writer.finish(outcome, flags, diagnostics);
    }
    cut.inner.flush().unwrap();
    cut.inner.shutdown(std::net::Shutdown::Write).unwrap();
    drop(cut);
    report.write(&mut io::stderr().lock()).unwrap();
    drop(arena);
    std::process::exit(0);
}
