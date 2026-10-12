#![cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]

#[path = "support/selected_helper_fixture.rs"]
mod fixture;
#[path = "../src/bin/selected_read_helper/mod.rs"]
mod helper;
#[path = "support/selected_helper_process.rs"]
mod process;

use fixture::Fixture;
use helper::protocol::{Outcome, RESULT_LEN, Request};
use process::{End, Spec};
use std::{io::Write, sync::atomic::Ordering, time::Duration};

fn selected() -> Request {
    Request {
        connection: Some(
            uuid::Uuid::parse_str(fixture::CONNECTION)
                .unwrap()
                .into_bytes(),
        ),
        ..Request::default()
    }
}
fn word(frame: &[u8; RESULT_LEN], offset: usize) -> u64 {
    u64::from_le_bytes(frame[offset..offset + 8].try_into().unwrap())
}
fn outcome(frame: &[u8; RESULT_LEN]) -> u16 {
    u16::from_le_bytes([frame[10], frame[11]])
}
fn run(spec: Spec<'_>, expected: Outcome) -> [u8; RESULT_LEN] {
    let cap = spec.request.cap;
    let result = process::start(spec).finish();
    assert_eq!(result.end, End::Complete, "{result:?}");
    assert!(result.reaped && result.joined && result.status.unwrap().success());
    let frame = result.frame.unwrap();
    assert_eq!(outcome(&frame), expected as u16, "{frame:?}");
    assert!(word(&frame, 56) <= cap as u64);
    assert_eq!(word(&frame, 64), 0, "shutdown 后无悬挂块");
    frame
}

#[test]
fn normal_binary_selected_matrix_and_readonly() {
    for (page, encoding) in [
        (512, "UTF-8"),
        (4096, "UTF-8"),
        (65536, "UTF-16le"),
        (512, "UTF-16be"),
    ] {
        let f = Fixture::new(page, encoding);
        let before = f.bytes();
        let logical = f.logical();
        let sidecars = f.sidecars();
        let r = run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
        assert_eq!(word(&r, 32), 5);
        assert_eq!(word(&r, 48), 7);
        assert_eq!(word(&r, 40), if encoding == "UTF-8" { 208 } else { 564 });
        assert_eq!(u32::from_le_bytes(r[24..28].try_into().unwrap()), 2);
        assert_eq!(word(&r, 112) & 7, 3);
        assert_eq!(word(&r, 112) & 8, 8);
        assert!(word(&r, 104) & (1 << 8) != 0);
        assert_eq!(word(&r, 104) & 0x1ffe, 0x1ffe);
        assert!(word(&r, 56) > 0 && word(&r, 96) > 0);
        let temporary = run(
            Spec::normal(f.path(), Request::default()),
            Outcome::PreflightPassed,
        );
        assert_eq!(word(&temporary, 32), 3);
        assert_eq!(
            word(&temporary, 40),
            if encoding == "UTF-8" { 82 } else { 234 }
        );
        assert_eq!(f.bytes(), before);
        assert_eq!(f.logical(), logical);
        assert_eq!(f.sidecars(), sidecars);
        let escaped = r#"{"value":"\u0000"}"#;
        f.open()
            .execute(
                "UPDATE terminal_profiles SET settings_json=?1 WHERE id=?2",
                rusqlite::params![escaped, fixture::REFERENCED],
            )
            .unwrap();
        let r = run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
        assert_eq!(
            word(&r, 40),
            if encoding == "UTF-8" {
                208 + (escaped.len() as u64 - 2)
            } else {
                564 + 3 * (escaped.len() as u64 - 2)
            }
        );
    }
}

#[test]
fn priority_missing_types_and_selected_limits() {
    let f = Fixture::new(4096, "UTF-8");
    let mut request = selected();
    request.profile = Some(
        uuid::Uuid::parse_str(fixture::EXPLICIT)
            .unwrap()
            .into_bytes(),
    );
    let r = run(Spec::normal(f.path(), request), Outcome::PreflightPassed);
    assert_eq!(u32::from_le_bytes(r[24..28].try_into().unwrap()), 1);
    request.profile = Some([255; 16]);
    run(Spec::normal(f.path(), request), Outcome::MissingProfile);
    request = selected();
    request.connection = Some([255; 16]);
    run(Spec::normal(f.path(), request), Outcome::MissingConnection);
    {
        let db = f.open();
        db.execute_batch("PRAGMA foreign_keys=OFF; UPDATE connections SET terminal_profile_id='ffffffff-ffff-ffff-ffff-ffffffffffff'").unwrap();
    }
    run(Spec::normal(f.path(), selected()), Outcome::MissingProfile);
    f.open()
        .execute("UPDATE connections SET terminal_profile_id=NULL", [])
        .unwrap();
    let r = run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
    assert_eq!(u32::from_le_bytes(r[24..28].try_into().unwrap()), 3);
    let mut request = selected();
    request.field = 35;
    run(Spec::normal(f.path(), request), Outcome::SelectedLimit);
    request.field = 36;
    request.total = word(&r, 40);
    run(Spec::normal(f.path(), request), Outcome::PreflightPassed);
    request.total -= 1;
    run(Spec::normal(f.path(), request), Outcome::SelectedLimit);
    request = selected();
    request.tags = 0;
    run(Spec::normal(f.path(), request), Outcome::SelectedLimit);
    request.tags = 1;
    run(Spec::normal(f.path(), request), Outcome::PreflightPassed);
    f.open()
        .execute(
            "INSERT INTO connection_tags VALUES(?1,'second')",
            [fixture::CONNECTION],
        )
        .unwrap();
    run(Spec::normal(f.path(), request), Outcome::SelectedLimit);
    request.tags = 2;
    run(Spec::normal(f.path(), request), Outcome::PreflightPassed);
    f.open()
        .execute("UPDATE connections SET note=?1", ["x".repeat(65536)])
        .unwrap();
    run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
    f.open()
        .execute("UPDATE connections SET note=?1", ["x".repeat(65537)])
        .unwrap();
    let before = f.bytes();
    let r = run(Spec::normal(f.path(), selected()), Outcome::SelectedLimit);
    assert_eq!(word(&r, 112) & 3, 3);
    assert_eq!(f.bytes(), before);
    f.open()
        .execute("UPDATE connections SET note=CAST(x'80' AS TEXT)", [])
        .unwrap();
    let r = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 2);
    f.open()
        .execute("UPDATE connections SET note=x'6162'", [])
        .unwrap();
    let r = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 2);
    f.open().execute("DELETE FROM app_settings", []).unwrap();
    let r = run(
        Spec::normal(f.path(), Request::default()),
        Outcome::StorageFailure,
    );
    assert_eq!(r[12], 2);
}

#[test]
fn unrelated_large_rows_and_actual_tag_allocation() {
    for encoding in ["UTF-8", "UTF-16le"] {
        let f = Fixture::new(512, encoding);
        f.unrelated();
        run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
        f.giant_tag();
        let before = f.bytes();
        let r = run(Spec::normal(f.path(), selected()), Outcome::CBudgetExceeded);
        assert!(word(&r, 72) > 8 * 1024 * 1024);
        assert_eq!(r[20], 3);
        assert_eq!(word(&r, 112) & 3, 3);
        assert_eq!(f.bytes(), before);
    }
}

#[test]
fn cold_schema_and_small_budget() {
    let f = Fixture::new(4096, "UTF-8");
    f.large_schema(600);
    let mut request = selected();
    request.cap = 65536;
    let r = run(Spec::normal(f.path(), request), Outcome::CBudgetExceeded);
    assert_eq!(r[16], 5);
    assert!(word(&r, 72) > 0);
    run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
}

#[test]
fn native_small_realloc_growth_has_budget_causality() {
    let f = Fixture::new(4096, "UTF-8");
    let request = Request {
        cap: 65536,
        ..selected()
    };
    let mut spec = Spec::normal(f.path(), request);
    spec.fault = Some("native-small-growth");
    let r = run(spec, Outcome::CBudgetExceeded);
    assert_eq!(r[20], 4);
    assert_eq!(word(&r, 72), 64);
    assert_eq!(word(&r, 56), 65536);
}

#[test]
fn ffi_scopes_are_fresh_after_state_preparation_and_quota_injection() {
    let f = Fixture::new(4096, "UTF-8");
    let mut spec = Spec::normal(f.path(), selected());
    spec.fault = Some("ffi-scope");
    let frame = run(spec, Outcome::CBudgetExceeded);
    assert_eq!((frame[12], frame[16], frame[20]), (4, 8, 3));
}

#[test]
fn native_realloc_success_and_unknown_nomem_do_not_inherit_denial() {
    let f = Fixture::new(4096, "UTF-8");
    let request = Request {
        cap: 65536,
        ..selected()
    };
    let mut spec = Spec::normal(f.path(), request);
    spec.fault = Some("native-realloc-controls");
    let r = run(spec, Outcome::StorageFailure);
    assert_eq!(r[12], 4);
    assert_eq!(r[20], 0);
}

#[test]
fn native_malloc_after_size_query_still_requires_budget_attribution() {
    let f = Fixture::new(4096, "UTF-8");
    let request = Request {
        cap: 65536,
        ..selected()
    };
    let mut spec = Spec::normal(f.path(), request);
    spec.fault = Some("native-ambiguous-prefix");
    // 同 raw 8192 的 A 必须是 native quota；B 成功 reuse 后的 unknown 仍为 Io。
    // 子进程同时证明未知 NOMEM 对照未误报；两条路径都实际执行 SQLite 并完成 shutdown。
    let r = run(spec, Outcome::CBudgetExceeded);
    assert_eq!(r[20], 4);
}

#[test]
fn native_release_and_retry_keep_request_quota() {
    let f = Fixture::new(4096, "UTF-8");
    f.unrelated();
    let before = f.bytes();
    let mut spec = Spec::normal(f.path(), selected());
    spec.fault = Some("native-release-retry");
    spec.timeout = Duration::from_secs(30);
    let frame = run(spec, Outcome::CBudgetExceeded);
    assert_eq!((frame[12], frame[16], frame[20]), (0, 7, 1));
    assert_eq!(f.bytes(), before);
}

#[test]
fn native_fresh_allocation_recovery_keeps_request_quota() {
    let f = Fixture::new(4096, "UTF-8");
    let mut spec = Spec::normal(
        f.path(),
        Request {
            cap: 65536,
            ..selected()
        },
    );
    spec.fault = Some("native-fresh-recovery");
    let result = process::start(spec).finish();
    assert_eq!(result.end, End::Complete);
    assert!(result.reaped && result.joined && result.status.unwrap().success());
    let frame = result.frame.unwrap();
    assert_eq!(word(&frame, 64), 0, "真实 shutdown 后无悬挂块");
    assert_eq!(
        (outcome(&frame), frame[12], frame[20]),
        (Outcome::CBudgetExceeded as u16, 4, 4),
        "首次 actual quota 永久拒绝请求；诊断/恢复两条完整轨迹及相对地址对照保留。frame={frame:?}"
    );
}

#[test]
fn auto_recompile_schema_errors_match_cold_prepare() {
    for sql in [
        "DROP TABLE configuration_revision",
        "ALTER TABLE configuration_revision RENAME TO hidden_revision; CREATE VIEW configuration_revision AS SELECT revision,singleton FROM hidden_revision",
    ] {
        let f = Fixture::new(4096, "UTF-8");
        let listener = process::barrier_listener();
        let mut spec = Spec::normal(f.path(), selected());
        spec.barrier = Some(("prepared", &listener));
        let running = process::start(spec);
        let mut control = process::await_barrier(&listener);
        f.open().execute_batch(sql).unwrap();
        control.write_all(&[1]).unwrap();
        drop(control);
        let result = running.finish();
        assert_eq!(result.end, End::Complete);
        assert!(result.reaped && result.joined && result.status.unwrap().success());
        let warm = result.frame.unwrap();
        let cold = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
        assert_eq!(outcome(&warm), Outcome::StorageFailure as u16);
        assert_eq!(cold[12], 2);
        assert_eq!(
            warm[12], cold[12],
            "同一异常 schema 的 prepare/step 分类必须一致"
        );
        assert_eq!(word(&warm, 64), 0);
    }
}

#[test]
fn conversion_and_initialization_faults_are_real_subprocesses() {
    let f = Fixture::new(4096, "UTF-16le");
    f.open()
        .execute("UPDATE connections SET note=?1", ["汉".repeat(12000)])
        .unwrap();
    for (fault, expected, phase) in [
        ("init", Outcome::CBudgetExceeded, 2),
        ("open", Outcome::CBudgetExceeded, 4),
        ("backing", Outcome::SystemOom, 0),
        ("convert", Outcome::CBudgetExceeded, 8),
        ("convert-recovered", Outcome::CBudgetExceeded, 8),
        ("unknown-convert", Outcome::StorageFailure, 8),
        ("native", Outcome::CBudgetExceeded, 8),
        ("cleanup", Outcome::CBudgetExceeded, 10),
        ("cleanup-unknown", Outcome::StorageFailure, 10),
        ("benign", Outcome::CBudgetExceeded, 5),
    ] {
        let mut spec = Spec::normal(f.path(), selected());
        spec.fault = Some(fault);
        let r = run(spec, expected);
        assert_eq!(r[16], phase);
        if matches!(fault, "convert-recovered" | "cleanup" | "benign") {
            assert_eq!(r[12], 0, "成功 API 的请求策略拒绝不能伪造 NOMEM");
        }
        if fault == "native" {
            assert_eq!(r[20], 4);
        }
        if fault == "unknown-convert" {
            assert_eq!(r[12], 4);
            assert_eq!(r[20], 0);
        }
        if fault == "cleanup-unknown" {
            assert_eq!(r[12], 4);
            assert_eq!(word(&r, 112) & 4, 4);
        }
    }
    run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
    f.open()
        .execute("UPDATE connections SET note=x'80'", [])
        .unwrap();
    let mut early = Spec::normal(f.path(), selected());
    early.fault = Some("benign");
    let r = run(early, Outcome::CBudgetExceeded);
    assert_eq!(
        (r[12], r[16], r[20]),
        (0, 5, 3),
        "无需继续寻找 late Corrupt"
    );
    for fault in ["cleanup", "cleanup-unknown"] {
        let mut spec = Spec::normal(f.path(), selected());
        spec.fault = Some(fault);
        let r = run(spec, Outcome::StorageFailure);
        assert_eq!(r[12], 2);
        if fault == "cleanup-unknown" {
            assert_eq!(word(&r, 112) & 4, 4);
        }
    }
}

#[test]
fn request_policy_checks_success_before_consuming_results() {
    let f = Fixture::new(4096, "UTF-8");
    let before = f.bytes();
    for (fault, phase) in [
        ("prepare-policy", 5),
        ("bind-policy", 6),
        ("step-row-policy", 7),
        ("step-done-policy", 7),
        ("column-bytes-policy", 8),
    ] {
        let mut spec = Spec::normal(f.path(), selected());
        spec.fault = Some(fault);
        let r = run(spec, Outcome::CBudgetExceeded);
        assert_eq!((r[12], r[16], r[20]), (0, phase, 3));
        if fault == "prepare-policy" {
            assert_eq!(word(&r, 104) & (1 << 7), 0, "prepare 拒绝后不能再 step");
        }
    }
    assert_eq!(f.bytes(), before);
}

#[test]
fn request_policy_covers_init_and_isolates_only_calibration() {
    let f = Fixture::new(4096, "UTF-8");
    let mut init = Spec::normal(f.path(), selected());
    init.fault = Some("init-recovered");
    let r = run(init, Outcome::CBudgetExceeded);
    assert_eq!((r[12], r[16], r[20]), (0, 2, 1));
    assert_eq!(
        word(&r, 104) & (1 << 3),
        0,
        "真实 init 首证必须先收口，不能进入校准洗掉"
    );
    let mut calibration = Spec::normal(f.path(), selected());
    calibration.fault = Some("calibration-quota");
    let r = run(calibration, Outcome::PreflightPassed);
    assert_eq!(
        word(&r, 56),
        selected().cap as u64,
        "隔离校准也不得把成本移出 backing"
    );
    let mut unexpected = Spec::normal(f.path(), selected());
    unexpected.fault = Some("calibration-null");
    run(unexpected, Outcome::UnsupportedEnvelope);
    run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
}

#[test]
fn request_policy_keeps_confirmed_non_nomem_step_errors() {
    for busy in [false, true] {
        let f = Fixture::new(4096, "UTF-8");
        let listener = process::barrier_listener();
        let mut spec = Spec::normal(f.path(), selected());
        spec.fault = Some("step-error-priority");
        spec.barrier = Some(("prepared", &listener));
        let running = process::start(spec);
        let mut control = process::await_barrier(&listener);
        let writer = f.open();
        writer
            .execute_batch(if busy {
                "BEGIN EXCLUSIVE"
            } else {
                "DROP TABLE configuration_revision"
            })
            .unwrap();
        control.write_all(&[1]).unwrap();
        drop(control);
        let result = running.finish();
        if busy {
            writer.execute_batch("ROLLBACK").unwrap();
        }
        assert_eq!(result.end, End::Complete);
        assert!(result.reaped && result.joined && result.status.unwrap().success());
        let r = result.frame.unwrap();
        assert_eq!(outcome(&r), Outcome::StorageFailure as u16);
        assert_eq!(r[12], if busy { 1 } else { 2 });
        assert_eq!(r[20], 0);
        assert_eq!(word(&r, 64), 0);
    }
}

#[test]
fn overflow_scan_is_bounded_without_changing_normal_query() {
    let f = Fixture::new(512, "UTF-8");
    let db = f.open();
    db.execute("INSERT INTO connections(rowid,id,group_id,name,host,port,username,transport,authentication,credential_ref,identity_file,host_key_policy,remote_command,note,position,terminal_profile_id,terminal_overrides_json) SELECT -1,'00000000-0000-0000-0000-000000000009',group_id,name,host,port,username,transport,authentication,credential_ref,identity_file,host_key_policy,remote_command,?1,position,terminal_profile_id,terminal_overrides_json FROM connections WHERE id=?2",rusqlite::params!["x".repeat(32*1024*1024),fixture::CONNECTION]).unwrap();
    // 只用于合成反例：让合法 512 页的 local payload 回落到 39，ID 横跨 overflow。
    let payload: usize = db
        .query_row(
            "SELECT max(mx_payload) FROM dbstat WHERE name='connections'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let padding = (500 + 508 - payload % 508) % 508;
    db.execute(
        "UPDATE connections SET note=?1 WHERE rowid=-1",
        ["x".repeat(32 * 1024 * 1024 + padding)],
    )
    .unwrap();
    drop(db);
    let mut request = selected();
    request.cap = 128 * 1024;
    run(Spec::normal(f.path(), request), Outcome::PreflightPassed);
    let mut spec = Spec::normal(f.path(), request);
    spec.fault = Some("overflow");
    let r = run(spec, Outcome::CBudgetExceeded);
    assert_eq!(r[16], 7);
    assert!(word(&r, 72) > request.cap as u64);
}

#[test]
fn automatic_recompile_budget_is_not_a_new_prepare() {
    let f = Fixture::new(4096, "UTF-8");
    let listener = process::barrier_listener();
    let mut request = selected();
    request.cap = 256 * 1024;
    let mut spec = Spec::normal(f.path(), request);
    spec.barrier = Some(("prepared", &listener));
    spec.timeout = Duration::from_secs(30);
    let running = process::start(spec);
    let mut control = process::await_barrier(&listener);
    f.large_schema(600);
    control.write_all(&[1]).unwrap();
    drop(control);
    let result = running.finish();
    assert_eq!(result.end, End::Complete);
    let r = result.frame.unwrap();
    assert_eq!(outcome(&r), Outcome::CBudgetExceeded as u16);
    assert_eq!(r[16], 7);
    assert!(word(&r, 72) > 0);
    assert_eq!(word(&r, 64), 0);
}

#[test]
fn busy_corrupt_authorizer_and_uri_do_not_become_budget_errors() {
    let f = Fixture::new(4096, "UTF-8");
    let before = f.bytes();
    let db = f.open();
    db.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let r = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 1);
    db.execute_batch("ROLLBACK").unwrap();
    drop(db);
    assert_eq!(f.bytes(), before);
    let uri = std::path::PathBuf::from(format!("file:{}?mode=ro", f.path().to_str().unwrap()));
    let r = run(Spec::normal(&uri, selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 4);
    let db = f.open();
    db.execute_batch("ALTER TABLE app_settings RENAME TO original_settings; CREATE VIEW app_settings AS SELECT singleton,default_terminal_profile,color_scheme,key_bindings_json FROM original_settings;").unwrap();
    drop(db);
    let r = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
    assert_ne!(r[12], 0);
    let corrupt = f.dir.path().join("corrupt.sqlite");
    std::fs::write(&corrupt, b"not a SQLite database; synthetic").unwrap();
    let before = std::fs::read(&corrupt).unwrap();
    let r = run(Spec::normal(&corrupt, selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 2);
    assert_eq!(std::fs::read(&corrupt).unwrap(), before);
}

#[test]
fn schema_auto_recompile_and_snapshot() {
    let f = Fixture::new(4096, "UTF-8");
    let listener = process::barrier_listener();
    let mut spec = Spec::normal(f.path(), selected());
    spec.barrier = Some(("prepared", &listener));
    let running = process::start(spec);
    let mut control = process::await_barrier(&listener);
    f.open()
        .execute_batch("CREATE TABLE schema_change(x)")
        .unwrap();
    control.write_all(&[1]).unwrap();
    drop(control);
    let result = running.finish();
    assert_eq!(result.end, End::Complete);
    let r = result.frame.unwrap();
    assert_eq!(outcome(&r), 0);
    assert!(word(&r, 120) > 0);
    let writer = f.open();
    writer.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let listener = process::barrier_listener();
    let mut spec = Spec::normal(f.path(), selected());
    spec.barrier = Some(("snapshot", &listener));
    let running = process::start(spec);
    let mut control = process::await_barrier(&listener);
    writer.execute_batch("BEGIN; UPDATE configuration_revision SET revision=8; UPDATE connections SET note='changed'; UPDATE connection_tags SET tag='changed'; COMMIT;").unwrap();
    control.write_all(&[1]).unwrap();
    drop(control);
    let result = running.finish();
    assert_eq!(result.end, End::Complete);
    let r = result.frame.unwrap();
    assert_eq!(outcome(&r), 0);
    assert_eq!(word(&r, 48), 7);
    assert_eq!(
        word(&r, 40),
        208,
        "连接与 tag 必须和 revision 属于同一旧快照"
    );
    assert!(f.sidecars().iter().any(|s| s.ends_with("-wal")));
}

#[test]
fn cancellation_result_before_exit_and_isolation() {
    let f = Fixture::new(4096, "UTF-8");
    let parent = rusqlite::Connection::open_in_memory().unwrap();
    let parent_limit: i64 = parent
        .query_row("PRAGMA hard_heap_limit", [], |r| r.get(0))
        .unwrap();
    let before = f.bytes();
    let logical = f.logical();
    for phase in [
        "snapshot",
        "preflight",
        "materialize",
        "close",
        "shutdown",
        "result",
    ] {
        let listener = process::barrier_listener();
        let mut spec = Spec::normal(f.path(), selected());
        spec.barrier = Some((phase, &listener));
        let running = process::start(spec);
        let control = process::await_barrier(&listener);
        if phase == "result" {
            process::await_flag(&running.signals.buffered);
        }
        assert_eq!(
            running.signals.reserved.load(Ordering::SeqCst),
            selected().cap
        );
        running
            .signals
            .hold_after_kill
            .store(true, Ordering::SeqCst);
        assert!(running.signals.cancel());
        process::await_flag(&running.signals.killed);
        assert_eq!(
            running.signals.reserved.load(Ordering::SeqCst),
            selected().cap
        );
        run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
        running
            .signals
            .hold_after_kill
            .store(false, Ordering::SeqCst);
        drop(control);
        let signals = running.signals.clone();
        let result = running.finish();
        assert_eq!(result.end, End::Cancelled);
        assert!(result.reaped && result.joined);
        assert_eq!(signals.reserved.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        parent
            .query_row("PRAGMA hard_heap_limit", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        parent_limit
    );
    assert_eq!(
        parent
            .query_row("SELECT 42", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        42
    );
    assert_eq!(f.bytes(), before);
    assert_eq!(f.logical(), logical);
    let running = process::start(Spec::normal(f.path(), selected()));
    process::await_flag(&running.signals.buffered);
    let cancelled = running.signals.cancel();
    let result = running.finish();
    assert_eq!(
        result.end,
        if cancelled {
            End::Cancelled
        } else {
            End::Complete
        }
    );
    assert!(result.reaped && result.joined);
}

#[test]
fn bad_protocol_crash_timeout_receiver_drop_and_spawn_failure() {
    let f = Fixture::new(4096, "UTF-8");
    for fault in [
        "half",
        "over",
        "version",
        "crash",
        "hang",
        "half-hang",
        "flood",
    ] {
        let mut spec = Spec::normal(f.path(), selected());
        spec.fault = Some(fault);
        spec.timeout = Duration::from_millis(700);
        spec.read_after_exit = fault == "flood";
        let result = process::start(spec).finish();
        assert!(result.reaped && result.joined);
        assert_eq!(
            result.end,
            match fault {
                "crash" => End::ChildCrashed,
                "hang" | "half-hang" | "flood" => End::TimedOut,
                _ => End::ProtocolFailure,
            }
        );
    }
    let listener = process::barrier_listener();
    let mut spec = Spec::normal(f.path(), selected());
    spec.barrier = Some(("snapshot", &listener));
    let running = process::start(spec);
    let control = process::await_barrier(&listener);
    running.drop_receiver();
    drop(control);
    let mut spec = Spec::normal(f.path(), selected());
    spec.nonexistent = true;
    let running = process::start(spec);
    let signals = running.signals.clone();
    assert_eq!(running.finish().end, End::SpawnFailure);
    assert_eq!(signals.reserved.load(Ordering::SeqCst), 0);
    for kind in 0..3 {
        let mut wire = selected().encode().to_vec();
        match kind {
            0 => {
                wire.pop();
            }
            1 => wire.push(0),
            _ => wire[10] = 128,
        }
        let mut spec = Spec::normal(f.path(), selected());
        spec.wire = Some(wire);
        run(spec, Outcome::InvalidRequest);
    }
    let mut spec = Spec::normal(f.path(), selected());
    spec.read_after_exit = true;
    run(spec, Outcome::PreflightPassed);
}

#[test]
fn wal_sidecar_observations_are_not_a_vfs_bound() {
    let f = Fixture::new(4096, "UTF-8");
    let writer = f.open();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; UPDATE configuration_revision SET revision=9;")
        .unwrap();
    let wal = f.dir.path().join("synthetic.sqlite-wal");
    let before = f.bytes();
    let wal_before = std::fs::read(&wal).unwrap();
    let r = run(Spec::normal(f.path(), selected()), Outcome::PreflightPassed);
    assert_eq!(word(&r, 48), 9);
    assert_eq!(word(&r, 112) & 3, 3);
    assert_eq!(f.bytes(), before);
    assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
    // 复制静止的合成 main/WAL，不复制 SHM；无 writer 的副本用于观察 sidecar 行为。
    let copy = tempfile::tempdir().unwrap();
    let path = copy.path().join("copy.sqlite");
    let copy_wal = copy.path().join("copy.sqlite-wal");
    let shm = copy.path().join("copy.sqlite-shm");
    std::fs::write(&path, &before).unwrap();
    std::fs::write(&copy_wal, &wal_before).unwrap();
    assert!(!shm.exists());
    let r = run(Spec::normal(&path, selected()), Outcome::PreflightPassed);
    assert_eq!(word(&r, 48), 9);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&copy_wal).unwrap(), wal_before);
    assert!(shm.exists(), "本场景须实际观察到 SQLite 创建的 SHM");
    {
        let original = std::fs::metadata(&shm).unwrap().permissions();
        let mut readonly = original.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&shm, readonly).unwrap();
        let completion = process::start(Spec::normal(&path, selected())).finish();
        std::fs::set_permissions(&shm, original).unwrap();
        assert_eq!(completion.end, End::Complete);
        let r = completion.frame.unwrap();
        assert!(matches!(outcome(&r), 0 | 5));
        assert_eq!(word(&r, 64), 0);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read(&copy_wal).unwrap(), wal_before);
    }
    drop(writer);
}

#[test]
fn temporary_selection_does_not_read_directory_and_schema_corrupt_stays_corrupt() {
    let f = Fixture::new(4096, "UTF-8");
    f.open().execute_batch("ALTER TABLE connections RENAME TO hidden_connections; CREATE VIEW connections AS SELECT * FROM hidden_connections").unwrap();
    run(
        Spec::normal(f.path(), Request::default()),
        Outcome::PreflightPassed,
    );
    let r = run(Spec::normal(f.path(), selected()), Outcome::StorageFailure);
    assert_eq!(r[12], 2);
    f.open().execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql='CREATE TABLE invalid(' WHERE name='terminal_profiles'; PRAGMA schema_version=100;").unwrap();
    let before = f.bytes();
    let r = run(
        Spec::normal(f.path(), Request::default()),
        Outcome::StorageFailure,
    );
    assert_eq!(r[12], 2);
    assert_eq!(f.bytes(), before);
}

#[test]
#[ignore = "仅由父测试作为独立子进程精确启动"]
fn fault_child() {
    let _normal_entry: fn() = helper::main;
    let mut output =
        std::net::TcpStream::connect(std::env::var("SELECTED_TEST_RESULT").unwrap()).unwrap();
    let request = Request::read(&mut std::io::stdin().lock()).unwrap();
    if helper::fault("crash") {
        std::process::exit(17);
    }
    if helper::fault("hang") {
        std::thread::sleep(Duration::from_secs(60));
    }
    let path = std::env::var_os("SELECTED_TEST_PATH").unwrap();
    let report = helper::run(&path, request);
    let mut frame = report.encode();
    if helper::fault("flood") {
        for _ in 0..65536 {
            if output.write_all(&[0; 1024]).is_err() {
                return;
            }
        }
    } else if helper::fault("half-hang") {
        output.write_all(&frame[..64]).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    } else if helper::fault("half") {
        output.write_all(&frame[..64]).unwrap();
    } else if helper::fault("over") {
        output.write_all(&frame).unwrap();
        output.write_all(&[1]).unwrap();
    } else if helper::fault("version") {
        frame[8] = 2;
        output.write_all(&frame).unwrap();
    } else {
        report.write(&mut output).unwrap();
    }
    drop(output);
    helper::barrier("result");
}
