#[path = "../src/bin/selected_read_helper/production_protocol.rs"]
mod protocol;

use protocol::*;
use std::io::{self, Read, Write};

const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const REVISION: u64 = 0x0102030405060708;
const VERIFIED: u32 = READONLY | TOTAL_CHANGES_ZERO | ENVELOPE_VERIFIED;

// 独立逐字节 fixture，不调用 codec、长度公式或 footer builder 生成期望值。
const REQUEST_BYTES: &[u8] = b"SHSELREQ\x02\0\0\0\0\0\x01\0\0\0\0\0\
    \x40\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x02\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \x50\x03\0\0\0\0\0\0\x34\x12\0\0\0\0\0\0\x06\0\0\0\0\0\0\0\
    \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

// 无连接完整成功流：6 字段、actual text=15、upper=16、wire=351，footer 自含 header。
const SUCCESS_BYTES: &[u8] = b"SHSELHD2\x02\0\x01\0\x40\0\0\0\
    \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
    \x08\x07\x06\x05\x04\x03\x02\x01\x03\0\0\0\x06\0\0\0\
    \x10\0\0\0\0\0\0\0\x60\x01\0\0\0\0\0\0\
    SHSELFD2\x11\0\x01\0\0\0\0\0\x01\0\0\0\0\0\0\0a\
    SHSELFD2\x12\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
    SHSELFD2\x13\0\x01\0\0\0\0\0\x02\0\0\0\0\0\0\0{}\
    SHSELFD2\x14\0\x01\0\0\0\0\0\x01\0\0\0\0\0\0\0p\
    SHSELFD2\x15\0\x01\0\0\0\0\0\x03\0\0\0\0\0\0\0N\0X\
    SHSELFD2\x16\0\x01\0\0\0\0\0\x08\0\0\0\0\0\0\0SHSELFN2\
    SHSELFN2\x02\0\0\0\x5f\x01\0\0\
    \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
    \x08\x07\x06\x05\x04\x03\x02\x01\x03\0\0\0\x06\0\0\0\
    \x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdf\0\0\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

// 早期 actual quota、outer 成功收口的 code=0；各数字诊断覆盖精确 offset。
const EARLY_QUOTA_BYTES: &[u8] = b"SHSELFN2\x02\0\x04\0\xdc\0\0\0\
    \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    \0\0\x08\x03\x20\x10\0\0\x08\x07\x06\x05\x04\x03\x02\x01\
    \x09\0\0\0\0\0\0\0\x0a\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\0\
    \x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

fn request(connection: bool, profile: bool) -> WireValidatedRequest {
    Request {
        c_max: 65536,
        field_max: 64,
        total_max: 512,
        tags_max: 2,
        connection: connection.then_some([0x21; 16]),
        profile: profile.then_some([0x32; 16]),
        wire_max: if connection { 1290 } else { 848 },
        helper_rust_max: 0x1234,
        frame_count_max: if connection { 24 } else { 6 },
        nonce: NONCE,
    }
    .validate()
    .unwrap()
}

fn text(tag: u16, ordinal: u32, payload: &[u8]) -> FieldHeader {
    FieldHeader {
        tag,
        kind: Kind::Utf8,
        ordinal,
        len: u64::try_from(payload.len()).unwrap(),
    }
}

fn preamble(
    r: WireValidatedRequest,
    revision: u64,
    source: u32,
    fields: u32,
    upper: u64,
) -> Result<Preamble, ProtocolError> {
    Preamble::new(
        r,
        revision,
        source,
        fields,
        upper,
        GroupReferenceFact::NoReference,
    )
}

fn quota_diagnostics() -> Diagnostics {
    Diagnostics {
        code: 0,
        phase: 8,
        reason: 3,
        rounded: 0x1020,
        requested: REVISION,
        denied_occupied: 9,
        available: 10,
        largest: 11,
        first_quota_op: 12,
        occupied_after_shutdown: 0,
    }
}

// 有界真实 Write 实现；short write、Interrupted、WriteZero 与任意字节处错误可独立注入。
struct Sink {
    bytes: [u8; 4096],
    len: usize,
    step: usize,
    fail_at: usize,
    interrupted: bool,
    zero: bool,
    flush_error: bool,
    calls: usize,
}

impl Sink {
    fn new() -> Self {
        Self {
            bytes: [0; 4096],
            len: 0,
            step: 4096,
            fail_at: 4096,
            interrupted: false,
            zero: false,
            flush_error: false,
            calls: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.len >= self.fail_at {
            return if self.zero {
                Ok(0)
            } else {
                Err(io::ErrorKind::BrokenPipe.into())
            };
        }
        let len = bytes
            .len()
            .min(self.step)
            .min(self.fail_at - self.len)
            .min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + len].copy_from_slice(&bytes[..len]);
        self.len += len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_error {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    Truncated,
    Protocol(ProtocolError),
}

impl From<ProtocolError> for ParseError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], ParseError> {
    let end = offset.checked_add(len).ok_or(ProtocolError::Overflow)?;
    let slice = bytes.get(*offset..end).ok_or(ParseError::Truncated)?;
    *offset = end;
    Ok(slice)
}

// 仅测试 reader：在 field 边界分派 magic，先核验 header 再取 payload，footer 后必须 EOF。
// 最终 Guo 真实 pipe reader / raw owner 不在本波次内。
fn parse(bytes: &[u8], request: WireValidatedRequest) -> Result<Footer, ParseError> {
    parse_state(bytes, request).map(|(footer, _)| footer)
}

fn parse_state(
    bytes: &[u8],
    request: WireValidatedRequest,
) -> Result<(Footer, StreamState), ParseError> {
    let mut state = StreamState::new(request);
    let mut offset = 0;
    loop {
        let magic = take(bytes, &mut offset, 8)?;
        let start = offset - 8;
        match magic {
            b"SHSELHD2" => {
                take(bytes, &mut offset, PREAMBLE_LEN - 8)?;
                state.accept_preamble(Preamble::decode(&bytes[start..offset], request)?)?;
            }
            b"SHSELFD2" => {
                take(bytes, &mut offset, FIELD_HEADER_LEN - 8)?;
                let header = FieldHeader::decode(&bytes[start..offset])?;
                state.check_header(header)?;
                let payload = take(bytes, &mut offset, checked_size(header.len)?)?;
                state.accept_field(header, payload)?;
            }
            b"SHSELFN2" => {
                take(bytes, &mut offset, FOOTER_LEN - 8)?;
                let footer = Footer::decode(&bytes[start..offset])?;
                state.accept_footer(footer)?;
                if offset != bytes.len() {
                    return Err(ProtocolError::TrailingBytes.into());
                }
                return Ok((footer, state));
            }
            _ => return Err(ProtocolError::Magic.into()),
        }
    }
}

fn write_no_connection_fields(writer: &mut FrameWriter<&mut Sink>) {
    for (tag, payload) in [
        (17, &b"a"[..]),
        (18, &b""[..]),
        (19, &b"{}"[..]),
        (20, &b"p"[..]),
        (21, &b"N\0X"[..]),
        (22, &b"SHSELFN2"[..]),
    ] {
        writer.write_field(text(tag, 0, payload), payload).unwrap();
    }
}

fn write_success(sink: &mut Sink) {
    let r = request(false, false);
    let mut writer = FrameWriter::new(sink, r);
    writer
        .write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap())
        .unwrap();
    write_no_connection_fields(&mut writer);
    assert_eq!(writer.statistics().wire_before_footer, 223);
    writer
        .finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default())
        .unwrap();
    assert_eq!(
        writer.finish(Outcome::StorageFailure, 0, Diagnostics::default()),
        Err(WriteError::Protocol(ProtocolError::State))
    );
}

#[test]
fn request_matches_independent_fixed_bytes() {
    assert_eq!(REQUEST_BYTES.len(), REQUEST_LEN);
    let r = request(false, false);
    assert_eq!(r.encode(), REQUEST_BYTES);
    assert_eq!(Request::decode(REQUEST_BYTES).unwrap(), r);
    assert_eq!(
        WireValidatedRequest::read(&mut &REQUEST_BYTES[..]).unwrap(),
        r
    );
    for connection in [false, true] {
        for profile in [false, true] {
            let r = request(connection, profile);
            assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        }
    }
    // v1 允许已选 UUID 全零；这里只保留 shape，不做业务 UUID 校验。
    let mut r = request(true, true).limits();
    r.connection = Some([0; 16]);
    r.profile = Some([0; 16]);
    assert_eq!(
        Request::decode(&r.validate().unwrap().encode())
            .unwrap()
            .limits(),
        r
    );
}

#[test]
fn request_caps_checked_exact_and_no_rust_certificate() {
    let base = request(true, true).limits();
    for cap in [65536, 67108864] {
        assert_eq!(
            Request { c_max: cap, ..base }
                .validate()
                .unwrap()
                .limits()
                .c_max,
            cap
        );
    }
    for cap in [0, 65535, 65537, 67108880, u64::MAX] {
        assert_eq!(
            Request { c_max: cap, ..base }.validate(),
            Err(ProtocolError::Limit)
        );
    }
    for (field, total, tags) in [
        (0, 512, 2),
        (1048577, 2097152, 2),
        (64, 63, 2),
        (64, 4194305, 2),
        (64, 512, 4097),
    ] {
        assert_eq!(
            Request {
                field_max: field,
                total_max: total,
                tags_max: tags,
                ..base
            }
            .validate(),
            Err(ProtocolError::Limit)
        );
    }
    for delta in [-1i64, 1, 24, 128] {
        assert_eq!(
            Request {
                wire_max: base.wire_max.checked_add_signed(delta).unwrap(),
                ..base
            }
            .validate(),
            Err(ProtocolError::Limit)
        );
    }
    for frames in [0, 23, 25, u32::MAX] {
        assert_eq!(
            Request {
                frame_count_max: frames,
                ..base
            }
            .validate(),
            Err(ProtocolError::Limit)
        );
    }
    let maximum = Request {
        c_max: 67108864,
        field_max: 1048576,
        total_max: 4194304,
        tags_max: 4096,
        frame_count_max: 4118,
        wire_max: 4293338,
        ..base
    };
    assert!(maximum.validate().is_ok());
    assert!(
        Request {
            field_max: 1,
            total_max: 1,
            tags_max: 0,
            frame_count_max: 22,
            wire_max: 731,
            ..base
        }
        .validate()
        .is_ok()
    );
    assert!(
        Request {
            field_max: 1048576,
            total_max: 1048576,
            tags_max: 4096,
            wire_max: 1048912,
            ..request(false, false).limits()
        }
        .validate()
        .is_ok()
    );
    for helper_rust_max in [0, 1, u64::MAX] {
        assert_eq!(
            Request {
                helper_rust_max,
                ..base
            }
            .validate()
            .unwrap()
            .limits()
            .helper_rust_max,
            helper_rust_max
        );
    }
    assert_eq!(wire_upper(6, 512, 0), Ok(848));
    assert_eq!(wire_upper(24, 512, 10), Ok(1290));
    assert_eq!(
        wire_upper(u32::MAX, u64::MAX, 10),
        Err(ProtocolError::Overflow)
    );
    assert_eq!(wire_upper(0, 0, u64::MAX), Err(ProtocolError::Overflow));
    assert_eq!(checked_size(u64::MAX), Err(ProtocolError::Overflow));
    assert_eq!(
        checked_size(u64::try_from(isize::MAX).unwrap()),
        Ok(isize::MAX as usize)
    );
    assert_eq!(
        checked_size(u64::try_from(isize::MAX).unwrap() + 1),
        Err(ProtocolError::Overflow)
    );
}

#[test]
fn request_rejects_version_reserved_selection_truncation_and_tail() {
    for (offset, value, error) in [
        (0, 0, ProtocolError::Magic),
        (8, 1, ProtocolError::Version),
        (10, 4, ProtocolError::Reserved),
        (40, 1, ProtocolError::Selection),
        (56, 1, ProtocolError::Selection),
        (92, 1, ProtocolError::Reserved),
        (95, 1, ProtocolError::Reserved),
    ] {
        let mut bytes = request(false, false).encode();
        bytes[offset] = value;
        assert_eq!(Request::decode(&bytes), Err(error));
    }
    for len in 0..REQUEST_LEN {
        assert_eq!(
            Request::decode(&REQUEST_BYTES[..len]),
            Err(ProtocolError::Length)
        );
    }
    assert_eq!(
        WireValidatedRequest::read(&mut &REQUEST_BYTES[..111]),
        Err(RequestReadError::Io(io::ErrorKind::UnexpectedEof))
    );
    let mut extra = [0; 113];
    extra[..112].copy_from_slice(REQUEST_BYTES);
    assert_eq!(Request::decode(&extra), Err(ProtocolError::Length));
    assert_eq!(
        WireValidatedRequest::read(&mut &extra[..]),
        Err(RequestReadError::Protocol(ProtocolError::TrailingBytes))
    );
}

#[test]
fn request_reader_handles_interrupted_eof_and_real_io_error() {
    struct Reader<'a> {
        bytes: &'a [u8],
        interrupted: bool,
        fail: bool,
    }
    impl Read for Reader<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.bytes.is_empty() && self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.fail {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.read(out)
        }
    }
    assert_eq!(
        WireValidatedRequest::read(&mut Reader {
            bytes: REQUEST_BYTES,
            interrupted: true,
            fail: false
        })
        .unwrap(),
        request(false, false)
    );
    assert_eq!(
        WireValidatedRequest::read(&mut Reader {
            bytes: REQUEST_BYTES,
            interrupted: false,
            fail: true
        }),
        Err(RequestReadError::Io(io::ErrorKind::BrokenPipe))
    );
}

#[test]
fn complete_stream_matches_independent_bytes_including_unique_footer() {
    assert_eq!(SUCCESS_BYTES.len(), 351);
    let mut sink = Sink::new();
    sink.step = 3;
    sink.interrupted = true;
    write_success(&mut sink);
    assert_eq!(sink.bytes(), SUCCESS_BYTES);
    assert!(sink.calls > 100);
    let footer = parse(SUCCESS_BYTES, request(false, false)).unwrap();
    assert_eq!(footer.outcome, Outcome::LoadedRaw);
    assert_eq!(
        footer.stats,
        Statistics {
            completed_fields: 6,
            text_bytes: 15,
            integer_bytes: 0,
            wire_before_footer: 223
        }
    );
    assert_eq!(footer.nonce, NONCE);
    assert_eq!(footer.revision, REVISION);
    assert_eq!(footer.source, 3);
}

#[test]
fn all_three_frame_magics_inside_payload_are_only_utf8_bytes() {
    let r = request(false, false);
    let payload = b"SHSELHD2SHSELFD2SHSELFN2";
    let mut sink = Sink::new();
    let mut writer = FrameWriter::new(&mut sink, r);
    writer
        .write_preamble(preamble(r, 0, 3, 6, 24).unwrap())
        .unwrap();
    writer.write_field(text(17, 0, payload), payload).unwrap();
    for tag in 18..=22 {
        writer.write_field(text(tag, 0, b""), b"").unwrap();
    }
    writer
        .finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default())
        .unwrap();
    assert_eq!(&sink.bytes[88..112], payload);
    assert_eq!(sink.len, 360);
    let footer = parse(sink.bytes(), r).unwrap();
    assert_eq!(footer.outcome, Outcome::LoadedRaw);
    assert_eq!(footer.stats.text_bytes, 24);
}

#[test]
fn early_failure_matches_independent_numeric_footer_bytes() {
    assert_eq!(EARLY_QUOTA_BYTES.len(), FOOTER_LEN);
    let r = request(false, false);
    let mut sink = Sink::new();
    FrameWriter::new(&mut sink, r)
        .finish(
            Outcome::CBudgetExceeded,
            VERIFIED | QUOTA_PROVED,
            quota_diagnostics(),
        )
        .unwrap();
    assert_eq!(sink.bytes(), EARLY_QUOTA_BYTES);
    let footer = parse(EARLY_QUOTA_BYTES, r).unwrap();
    assert_eq!(footer.stats, Statistics::default());
    assert_eq!(footer.diagnostics, quota_diagnostics());
    assert_eq!(footer.flags & PREAMBLE_PRESENT, 0);
    assert_eq!(footer.flags & REVISION_VALID, 0);
    assert_eq!(footer.revision, 0);
    assert_eq!(footer.source, 0);
}

#[test]
fn preamble_checks_source_selection_nonce_and_exact_bounds() {
    for (connection, profile, sources) in [
        (false, false, [false, false, true]),
        (false, true, [true, false, false]),
        (true, false, [false, true, true]),
        (true, true, [true, false, false]),
    ] {
        let r = request(connection, profile);
        for source in 0..=4 {
            let result = preamble(r, 0, source, if connection { 22 } else { 6 }, 0);
            let expected = (1..=3).contains(&source) && sources[(source - 1) as usize];
            assert_eq!(result.is_ok(), expected);
        }
    }
    let r = request(false, false);
    let p = preamble(r, REVISION, 3, 6, 16).unwrap();
    assert_eq!(p.encode(r).unwrap(), SUCCESS_BYTES[..64]);
    assert_eq!(Preamble::decode(&SUCCESS_BYTES[..64], r).unwrap(), p);
    for fields in [0, 5, 7, u32::MAX] {
        assert_eq!(preamble(r, 0, 3, fields, 0), Err(ProtocolError::Limit));
    }
    assert_eq!(preamble(r, 0, 3, 6, 513), Err(ProtocolError::Limit));
    let mut bad = p;
    bad.nonce[0] = 0;
    assert_eq!(bad.validate(r), Err(ProtocolError::Nonce));
    for upper in [351, 353, u64::MAX] {
        assert_eq!(
            Preamble {
                wire_upper: upper,
                ..p
            }
            .validate(r),
            Err(ProtocolError::Limit)
        );
    }
    for (offset, value, error) in [
        (0, 0, ProtocolError::Magic),
        (8, 3, ProtocolError::Version),
        (10, 8, ProtocolError::Reserved),
        (12, 63, ProtocolError::Reserved),
        (16, 0, ProtocolError::Nonce),
        (40, 4, ProtocolError::Source),
    ] {
        let mut bytes = p.encode(r).unwrap();
        bytes[offset] = value;
        assert_eq!(Preamble::decode(&bytes, r), Err(error));
    }
    assert_eq!(
        Preamble::decode(&SUCCESS_BYTES[..63], r),
        Err(ProtocolError::Length)
    );
}

#[test]
fn field_kind_tag_nullable_and_ordinal_matrix() {
    for tag in 0..=24 {
        for kind in [Kind::Null, Kind::Utf8, Kind::U16, Kind::I64] {
            let len = match kind {
                Kind::Null | Kind::Utf8 => 0,
                Kind::U16 => 2,
                Kind::I64 => 8,
            };
            let header = FieldHeader {
                tag,
                kind,
                ordinal: u32::from(tag == 23),
                len,
            };
            let expected = match tag {
                5 => kind == Kind::U16,
                14 => kind == Kind::I64,
                2 | 9 | 10 | 12 | 15 => matches!(kind, Kind::Null | Kind::Utf8),
                1..=23 => kind == Kind::Utf8,
                _ => false,
            };
            assert_eq!(header.validate().is_ok(), expected);
            if expected {
                assert_eq!(
                    FieldHeader::decode(&header.encode().unwrap()).unwrap(),
                    header
                );
            }
        }
    }
    for header in [
        FieldHeader {
            tag: 2,
            kind: Kind::Null,
            ordinal: 0,
            len: 1,
        },
        FieldHeader {
            tag: 5,
            kind: Kind::U16,
            ordinal: 0,
            len: 1,
        },
        FieldHeader {
            tag: 14,
            kind: Kind::I64,
            ordinal: 0,
            len: 7,
        },
        text(17, 1, b""),
        text(23, 0, b""),
    ] {
        assert_eq!(header.validate(), Err(ProtocolError::Field));
    }
    let good = text(17, 0, b"a").encode().unwrap();
    assert_eq!(good, SUCCESS_BYTES[64..88]);
    for (offset, value, error) in [
        (0, 0, ProtocolError::Magic),
        (8, 24, ProtocolError::Field),
        (10, 4, ProtocolError::Field),
        (11, 1, ProtocolError::Reserved),
        (12, 1, ProtocolError::Field),
    ] {
        let mut bytes = good;
        bytes[offset] = value;
        assert_eq!(FieldHeader::decode(&bytes), Err(error));
    }
    assert_eq!(FieldHeader::decode(&good[..23]), Err(ProtocolError::Length));
    assert_eq!(
        FieldHeader {
            len: u64::MAX,
            ..text(17, 0, b"")
        }
        .validate(),
        Err(ProtocolError::Overflow)
    );
}

fn write_connection(writer: &mut FrameWriter<&mut Sink>, nulls: bool) {
    for tag in 1..=22 {
        let (kind, payload): (Kind, &[u8]) = match tag {
            5 => (Kind::U16, &[0x22, 0x11]),
            14 => (Kind::I64, &[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            2 | 9 | 10 | 12 | 15 if nulls => (Kind::Null, b""),
            _ => (Kind::Utf8, b""),
        };
        writer
            .write_field(
                FieldHeader {
                    tag,
                    kind,
                    ordinal: 0,
                    len: payload.len() as u64,
                },
                payload,
            )
            .unwrap();
    }
}

#[test]
fn connection_scalars_tags_null_and_empty_have_exact_wire_bytes() {
    let r = request(true, false);
    for nulls in [false, true] {
        let mut sink = Sink::new();
        let mut writer = FrameWriter::new(&mut sink, r);
        writer
            .write_preamble(
                Preamble::new(
                    r,
                    7,
                    2,
                    24,
                    4,
                    if nulls {
                        GroupReferenceFact::NoReference
                    } else {
                        GroupReferenceFact::InvalidUuid
                    },
                )
                .unwrap(),
            )
            .unwrap();
        write_connection(&mut writer, nulls);
        writer.write_field(text(23, 1, b"a\0"), b"a\0").unwrap();
        writer.write_field(text(23, 2, b"bb"), b"bb").unwrap();
        assert_eq!(
            writer.statistics(),
            Statistics {
                completed_fields: 24,
                text_bytes: 4,
                integer_bytes: 10,
                wire_before_footer: 654
            }
        );
        writer
            .finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default())
            .unwrap();
        assert_eq!(sink.len, 782);
        assert_eq!(
            &sink.bytes[160..186],
            b"SHSELFD2\x05\0\x02\0\0\0\0\0\x02\0\0\0\0\0\0\0\x22\x11"
        );
        assert_eq!(
            &sink.bytes[378..410],
            b"SHSELFD2\x0e\0\x03\0\0\0\0\0\x08\0\0\0\0\0\0\0\xfe\xff\xff\xff\xff\xff\xff\xff"
        );
        assert_eq!(
            &sink.bytes[602..628],
            b"SHSELFD2\x17\0\x01\0\x01\0\0\0\x02\0\0\0\0\0\0\0a\0"
        );
        assert_eq!(sink.bytes[98], if nulls { 0 } else { 1 });
        assert_eq!(parse(sink.bytes(), r).unwrap().outcome, Outcome::LoadedRaw);
    }
}

#[test]
fn field_order_limits_utf8_and_statistics_are_checked_before_commit() {
    let r = request(false, false);
    let mut state = StreamState::new(r);
    assert_eq!(
        state.accept_field(text(17, 0, b""), b""),
        Err(ProtocolError::State)
    );
    let p = preamble(r, 0, 3, 6, 2).unwrap();
    state.accept_preamble(p).unwrap();
    assert_eq!(state.accept_preamble(p), Err(ProtocolError::State));
    for header in [text(1, 0, b""), text(18, 0, b""), text(23, 1, b"")] {
        assert_eq!(state.check_header(header), Err(ProtocolError::Order));
    }
    assert_eq!(
        state.accept_field(text(17, 0, &[0xff]), &[0xff]),
        Err(ProtocolError::Utf8)
    );
    assert_eq!(
        state.accept_field(text(17, 0, b"a"), b""),
        Err(ProtocolError::Length)
    );
    assert_eq!(
        state.accept_field(text(17, 0, b"abc"), b"abc"),
        Err(ProtocolError::Limit)
    );
    assert_eq!(
        state.statistics(),
        Statistics {
            wire_before_footer: 64,
            ..Statistics::default()
        }
    );
    state.accept_field(text(17, 0, b"\0a"), b"\0a").unwrap();
    assert_eq!(
        state.accept_field(text(18, 0, b"b"), b"b"),
        Err(ProtocolError::Limit)
    );
    state.accept_field(text(18, 0, b""), b"").unwrap();
    assert_eq!(state.statistics().text_bytes, 2);
    let mut field_limited = StreamState::new(r);
    field_limited
        .accept_preamble(preamble(r, 0, 3, 6, 512).unwrap())
        .unwrap();
    assert_eq!(
        field_limited.check_header(text(17, 0, &[0; 65])),
        Err(ProtocolError::Limit)
    );
    assert!(field_limited.check_header(text(17, 0, &[0; 64])).is_ok());
}

#[test]
fn connection_tags_require_contiguous_ordinals_and_actual_count() {
    let r = request(true, false);
    let mut state = StreamState::new(r);
    state
        .accept_preamble(Preamble::new(r, 0, 3, 24, 2, GroupReferenceFact::InvalidUuid).unwrap())
        .unwrap();
    for tag in 1..=22 {
        let (kind, payload): (Kind, &[u8]) = match tag {
            5 => (Kind::U16, &[0, 0]),
            14 => (Kind::I64, &[0; 8]),
            _ => (Kind::Utf8, b""),
        };
        state
            .accept_field(
                FieldHeader {
                    tag,
                    kind,
                    ordinal: 0,
                    len: payload.len() as u64,
                },
                payload,
            )
            .unwrap();
    }
    assert_eq!(
        state.accept_field(text(23, 2, b"a"), b"a"),
        Err(ProtocolError::Order)
    );
    state.accept_field(text(23, 1, b"a"), b"a").unwrap();
    assert_eq!(
        state.accept_field(text(23, 1, b"b"), b"b"),
        Err(ProtocolError::Order)
    );
    state.accept_field(text(23, 2, b"b"), b"b").unwrap();
    assert_eq!(
        state.accept_field(text(23, 3, b""), b""),
        Err(ProtocolError::Order)
    );
    let footer = state
        .footer(Outcome::LoadedRaw, VERIFIED, Diagnostics::default())
        .unwrap();
    state.accept_footer(footer).unwrap();
    assert_eq!(state.accept_footer(footer), Err(ProtocolError::State));
    assert_eq!(
        state.accept_field(text(23, 3, b""), b""),
        Err(ProtocolError::State)
    );
}

#[test]
fn midstream_failure_at_complete_field_boundary_preserves_exact_counts() {
    let r = request(false, false);
    let mut sink = Sink::new();
    let mut writer = FrameWriter::new(&mut sink, r);
    writer
        .write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap())
        .unwrap();
    writer.write_field(text(17, 0, b"a"), b"a").unwrap();
    writer.write_field(text(18, 0, b""), b"").unwrap();
    assert_eq!(
        writer.finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default()),
        Err(WriteError::Protocol(ProtocolError::Counts))
    );
    writer
        .finish(
            Outcome::StorageFailure,
            VERIFIED,
            Diagnostics {
                code: 11,
                ..Diagnostics::default()
            },
        )
        .unwrap();
    assert_eq!(&sink.bytes[..113], &SUCCESS_BYTES[..113]);
    assert_eq!(sink.len, 241);
    let footer = parse(sink.bytes(), r).unwrap();
    assert_eq!(footer.outcome, Outcome::StorageFailure);
    assert_eq!(
        footer.stats,
        Statistics {
            completed_fields: 2,
            text_bytes: 1,
            integer_bytes: 0,
            wire_before_footer: 113
        }
    );
}

#[test]
fn all_raw_fields_then_cleanup_quota_is_failure_not_early_success() {
    let r = request(false, false);
    let mut sink = Sink::new();
    let mut writer = FrameWriter::new(&mut sink, r);
    writer
        .write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap())
        .unwrap();
    write_no_connection_fields(&mut writer);
    let diagnostics = Diagnostics {
        code: 4,
        phase: 12,
        occupied_after_shutdown: 16,
        ..quota_diagnostics()
    };
    assert!(
        writer
            .finish(
                Outcome::LoadedRaw,
                VERIFIED | QUOTA_PROVED | CLEANUP_FAILED,
                diagnostics
            )
            .is_err()
    );
    writer
        .finish(
            Outcome::CBudgetExceeded,
            VERIFIED | QUOTA_PROVED | CLEANUP_FAILED,
            diagnostics,
        )
        .unwrap();
    assert_eq!(&sink.bytes[..223], &SUCCESS_BYTES[..223]);
    let footer = parse(sink.bytes(), r).unwrap();
    assert_eq!(footer.outcome, Outcome::CBudgetExceeded);
    assert_eq!(footer.stats.completed_fields, 6);
    assert_eq!(footer.diagnostics.occupied_after_shutdown, 16);
}

#[test]
fn confirmed_primary_can_keep_quota_diagnostics_without_becoming_budget() {
    let r = request(false, false);
    let mut sink = Sink::new();
    FrameWriter::new(&mut sink, r)
        .finish(
            Outcome::StorageFailure,
            QUOTA_PROVED,
            Diagnostics {
                code: 11,
                ..quota_diagnostics()
            },
        )
        .unwrap();
    assert_eq!(
        parse(sink.bytes(), r).unwrap().outcome,
        Outcome::StorageFailure
    );
    let mut sink = Sink::new();
    FrameWriter::new(&mut sink, r)
        .finish(
            Outcome::StorageFailure,
            0,
            Diagnostics {
                code: 4,
                ..Diagnostics::default()
            },
        )
        .unwrap();
    assert_eq!(parse(sink.bytes(), r).unwrap().flags & QUOTA_PROVED, 0);
}

#[test]
fn footer_unbound_invalid_request_is_not_a_normal_correlated_reply() {
    let footer = Footer {
        outcome: Outcome::InvalidRequest,
        flags: 0,
        nonce: [0; 16],
        revision: 0,
        source: 0,
        stats: Statistics::default(),
        diagnostics: Diagnostics::default(),
    };
    assert_eq!(Footer::decode(&footer.encode().unwrap()).unwrap(), footer);
    assert_eq!(
        StreamState::new(request(false, false)).check_footer(footer),
        Err(ProtocolError::Nonce)
    );
    assert_eq!(
        Footer {
            outcome: Outcome::StorageFailure,
            ..footer
        }
        .validate(),
        Err(ProtocolError::Nonce)
    );
    assert_eq!(
        Footer {
            nonce: NONCE,
            ..footer
        }
        .validate(),
        Err(ProtocolError::Nonce)
    );
    assert_eq!(
        Footer {
            revision: 1,
            ..footer
        }
        .validate(),
        Err(ProtocolError::Revision)
    );
    assert_eq!(
        Footer {
            source: 1,
            ..footer
        }
        .validate(),
        Err(ProtocolError::Revision)
    );
}

#[test]
fn footer_numeric_outcomes_reserved_flags_proofs_and_cleanup_checks() {
    let r = request(false, false);
    for outcome in [
        Outcome::MissingConnection,
        Outcome::MissingProfile,
        Outcome::SelectedLimit,
        Outcome::StorageFailure,
        Outcome::InvalidRequest,
        Outcome::UnsupportedEnvelope,
        Outcome::SystemOom,
        Outcome::InternalFailure,
        Outcome::RustBudgetExceeded,
    ] {
        let mut sink = Sink::new();
        FrameWriter::new(&mut sink, r)
            .finish(outcome, 0, Diagnostics::default())
            .unwrap();
        assert_eq!(parse(sink.bytes(), r).unwrap().outcome, outcome);
    }
    let footer = Footer::decode(EARLY_QUOTA_BYTES).unwrap();
    for (offset, value, error) in [
        (0, 0, ProtocolError::Magic),
        (8, 1, ProtocolError::Version),
        (10, 11, ProtocolError::Outcome),
        (13, 8, ProtocolError::Reserved),
        (32, 1, ProtocolError::Revision),
        (40, 1, ProtocolError::Revision),
        (44, 1, ProtocolError::Counts),
    ] {
        let mut bytes = footer.encode().unwrap();
        bytes[offset] = value;
        assert_eq!(Footer::decode(&bytes), Err(error));
    }
    assert_eq!(
        Footer::decode(&EARLY_QUOTA_BYTES[..127]),
        Err(ProtocolError::Length)
    );
    assert_eq!(
        Footer {
            flags: footer.flags & !QUOTA_PROVED,
            ..footer
        }
        .validate(),
        Err(ProtocolError::Outcome)
    );
    assert_eq!(
        Footer {
            diagnostics: Diagnostics {
                first_quota_op: 0,
                ..footer.diagnostics
            },
            ..footer
        }
        .validate(),
        Err(ProtocolError::Outcome)
    );
    assert_eq!(
        Footer {
            diagnostics: Diagnostics {
                code: 11,
                ..footer.diagnostics
            },
            ..footer
        }
        .validate(),
        Err(ProtocolError::Outcome)
    );
    assert_eq!(
        Footer {
            diagnostics: Diagnostics {
                occupied_after_shutdown: 1,
                ..footer.diagnostics
            },
            ..footer
        }
        .validate(),
        Err(ProtocolError::Outcome)
    );
    let success = Footer::decode(&SUCCESS_BYTES[223..]).unwrap();
    for flag in [
        PREAMBLE_PRESENT,
        REVISION_VALID,
        NONCE_VALID,
        READONLY,
        TOTAL_CHANGES_ZERO,
        ENVELOPE_VERIFIED,
    ] {
        assert!(
            Footer {
                flags: success.flags & !flag,
                ..success
            }
            .validate()
            .is_err()
        );
    }
    for flag in [CLEANUP_FAILED, QUOTA_PROVED] {
        assert!(
            Footer {
                flags: success.flags | flag,
                ..success
            }
            .validate()
            .is_err()
        );
    }
    assert_eq!(
        Footer {
            diagnostics: Diagnostics {
                code: 4,
                ..Diagnostics::default()
            },
            ..success
        }
        .validate(),
        Err(ProtocolError::Outcome)
    );
}

#[test]
fn footer_identity_and_each_count_must_match_observed_stream() {
    let r = request(false, false);
    for (offset, value, error) in [
        (239, 0, ProtocolError::Nonce),
        (255, 0, ProtocolError::Revision),
        (263, 2, ProtocolError::Source),
        (267, 5, ProtocolError::Counts),
        (271, 14, ProtocolError::Counts),
        (279, 1, ProtocolError::Counts),
        (287, 222, ProtocolError::Counts),
    ] {
        let mut bytes = [0; 351];
        bytes.copy_from_slice(SUCCESS_BYTES);
        bytes[offset] = value;
        assert_eq!(parse(&bytes, r), Err(ParseError::Protocol(error)));
    }
    let mut early = [0; 128];
    early.copy_from_slice(EARLY_QUOTA_BYTES);
    early[16] = 0;
    assert_eq!(
        parse(&early, r),
        Err(ParseError::Protocol(ProtocolError::Nonce))
    );
}

#[test]
fn malformed_stream_boundaries_extra_frames_and_extra_bytes_are_rejected() {
    let r = request(false, false);
    for len in 0..SUCCESS_BYTES.len() {
        assert_eq!(parse(&SUCCESS_BYTES[..len], r), Err(ParseError::Truncated));
    }
    let mut extra = [0; 352];
    extra[..351].copy_from_slice(SUCCESS_BYTES);
    assert_eq!(
        parse(&extra, r),
        Err(ParseError::Protocol(ProtocolError::TrailingBytes))
    );
    let mut duplicate = [0; 415];
    duplicate[..64].copy_from_slice(&SUCCESS_BYTES[..64]);
    duplicate[64..128].copy_from_slice(&SUCCESS_BYTES[..64]);
    duplicate[128..].copy_from_slice(&SUCCESS_BYTES[64..]);
    assert_eq!(
        parse(&duplicate, r),
        Err(ParseError::Protocol(ProtocolError::State))
    );
    let mut unknown = [0; 351];
    unknown.copy_from_slice(SUCCESS_BYTES);
    unknown[64] = b'X';
    assert_eq!(
        parse(&unknown, r),
        Err(ParseError::Protocol(ProtocolError::Magic))
    );
    assert_eq!(
        parse(&SUCCESS_BYTES[64..], r),
        Err(ParseError::Protocol(ProtocolError::State))
    );
    let mut extra_field = [0; 375];
    extra_field[..223].copy_from_slice(&SUCCESS_BYTES[..223]);
    extra_field[223..247].copy_from_slice(&SUCCESS_BYTES[89..113]);
    extra_field[247..].copy_from_slice(&SUCCESS_BYTES[223..]);
    assert_eq!(
        parse(&extra_field, r),
        Err(ParseError::Protocol(ProtocolError::Order))
    );
    let mut oversized = [0; 88];
    oversized.copy_from_slice(&SUCCESS_BYTES[..88]);
    oversized[80..88].copy_from_slice(&65u64.to_le_bytes());
    assert_eq!(
        parse(&oversized, r),
        Err(ParseError::Protocol(ProtocolError::Limit))
    );
}

#[test]
fn partial_preamble_field_header_and_payload_poison_writer_without_footer() {
    let r = request(false, false);
    for fail_at in [0, 7, 63, 64, 70, 87, 88, 89, 90] {
        let mut sink = Sink::new();
        sink.fail_at = fail_at;
        sink.step = 2;
        let mut writer = FrameWriter::new(&mut sink, r);
        let result = writer.write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap());
        let result = result.and_then(|()| writer.write_field(text(17, 0, b"abc"), b"abc"));
        assert_eq!(result, Err(WriteError::Io(io::ErrorKind::BrokenPipe)));
        assert!(writer.is_failed());
        let before = writer.statistics();
        assert_eq!(before.completed_fields, 0);
        assert_eq!(before.text_bytes, 0);
        assert_eq!(
            writer.finish(Outcome::CBudgetExceeded, QUOTA_PROVED, quota_diagnostics()),
            Err(WriteError::Failed)
        );
        assert_eq!(
            writer.write_field(text(17, 0, b""), b""),
            Err(WriteError::Failed)
        );
        assert_eq!(
            writer.write_preamble(preamble(r, 0, 3, 6, 0).unwrap()),
            Err(WriteError::Failed)
        );
        assert_eq!(writer.statistics(), before);
        assert_eq!(sink.len, fail_at);
        assert!(parse(sink.bytes(), r).is_err());
    }
}

#[test]
fn partial_footer_and_write_zero_never_become_typed_budget() {
    let r = request(false, false);
    for fail_at in [0, 8, 72, 127] {
        for zero in [false, true] {
            let mut sink = Sink::new();
            sink.fail_at = fail_at;
            sink.zero = zero;
            let mut writer = FrameWriter::new(&mut sink, r);
            assert_eq!(
                writer.finish(
                    Outcome::CBudgetExceeded,
                    VERIFIED | QUOTA_PROVED,
                    quota_diagnostics()
                ),
                Err(WriteError::Io(if zero {
                    io::ErrorKind::WriteZero
                } else {
                    io::ErrorKind::BrokenPipe
                }))
            );
            assert!(writer.is_failed());
            assert_eq!(
                writer.finish(Outcome::CBudgetExceeded, QUOTA_PROVED, quota_diagnostics()),
                Err(WriteError::Failed)
            );
            assert_eq!(sink.bytes(), &EARLY_QUOTA_BYTES[..fail_at]);
            assert_eq!(parse(sink.bytes(), r), Err(ParseError::Truncated));
        }
    }
}

#[test]
fn completed_field_then_partial_next_field_retains_only_completed_statistics() {
    let r = request(false, false);
    let mut sink = Sink::new();
    sink.fail_at = 115;
    let mut writer = FrameWriter::new(&mut sink, r);
    writer
        .write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap())
        .unwrap();
    writer.write_field(text(17, 0, b"a"), b"a").unwrap();
    assert_eq!(
        writer.write_field(text(18, 0, b"abcdef"), b"abcdef"),
        Err(WriteError::Io(io::ErrorKind::BrokenPipe))
    );
    assert_eq!(
        writer.statistics(),
        Statistics {
            completed_fields: 1,
            text_bytes: 1,
            integer_bytes: 0,
            wire_before_footer: 89
        }
    );
    assert_eq!(
        writer.finish(Outcome::StorageFailure, 0, Diagnostics::default()),
        Err(WriteError::Failed)
    );
    assert_eq!(sink.len, 115);
    assert_eq!(parse(sink.bytes(), r), Err(ParseError::Truncated));
}

#[test]
fn flush_error_is_io_failure_and_blocks_later_writes() {
    let r = request(false, false);
    let mut sink = Sink::new();
    sink.flush_error = true;
    let mut writer = FrameWriter::new(&mut sink, r);
    assert_eq!(
        writer.finish(Outcome::MissingProfile, 0, Diagnostics::default()),
        Err(WriteError::Io(io::ErrorKind::BrokenPipe))
    );
    assert!(writer.is_failed());
    assert_eq!(
        writer.finish(Outcome::MissingProfile, 0, Diagnostics::default()),
        Err(WriteError::Failed)
    );
    assert_eq!(sink.len, 128);
}

#[test]
fn poisoned_writer_does_not_retry_even_when_underlying_io_recovers() {
    use std::cell::Cell;

    struct RecoveringSink<'a> {
        sink: &'a mut Sink,
        calls: &'a Cell<usize>,
    }
    impl Write for RecoveringSink<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls.set(self.calls.get() + 1);
            let result = self.sink.write(bytes);
            if result.is_err() {
                self.sink.fail_at = 4096;
            }
            result
        }

        fn flush(&mut self) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.sink.flush()
        }
    }

    let r = request(false, false);
    let mut sink = Sink::new();
    sink.fail_at = 89;
    let calls = Cell::new(0);
    let mut writer = FrameWriter::new(
        RecoveringSink {
            sink: &mut sink,
            calls: &calls,
        },
        r,
    );
    writer
        .write_preamble(preamble(r, 0, 3, 6, 16).unwrap())
        .unwrap();
    assert_eq!(
        writer.write_field(text(17, 0, b"abc"), b"abc"),
        Err(WriteError::Io(io::ErrorKind::BrokenPipe))
    );
    let failed_calls = calls.get();
    assert_eq!(
        writer.finish(Outcome::CBudgetExceeded, QUOTA_PROVED, quota_diagnostics()),
        Err(WriteError::Failed)
    );
    assert_eq!(
        writer.finish(Outcome::StorageFailure, 0, Diagnostics::default()),
        Err(WriteError::Failed)
    );
    assert_eq!(
        writer.write_field(text(17, 0, b""), b""),
        Err(WriteError::Failed)
    );
    assert_eq!(calls.get(), failed_calls);
    assert_eq!(sink.len, 89);
    assert_eq!(parse(sink.bytes(), r), Err(ParseError::Truncated));
}

#[test]
fn partial_footer_after_all_fields_is_still_truncation_and_poisoned() {
    let r = request(false, false);
    for fail_at in [223, 224, 230, 350] {
        let mut sink = Sink::new();
        sink.fail_at = fail_at;
        let mut writer = FrameWriter::new(&mut sink, r);
        writer
            .write_preamble(preamble(r, REVISION, 3, 6, 16).unwrap())
            .unwrap();
        write_no_connection_fields(&mut writer);
        let before = writer.statistics();
        assert_eq!(
            writer.finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default()),
            Err(WriteError::Io(io::ErrorKind::BrokenPipe))
        );
        assert_eq!(writer.statistics(), before);
        assert!(writer.is_failed());
        assert_eq!(
            writer.finish(Outcome::CBudgetExceeded, QUOTA_PROVED, quota_diagnostics()),
            Err(WriteError::Failed)
        );
        assert_eq!(sink.bytes(), &SUCCESS_BYTES[..fail_at]);
        assert_eq!(parse(sink.bytes(), r), Err(ParseError::Truncated));
    }
}

#[test]
fn early_footer_all_counts_and_revision_source_combinations_are_checked() {
    let r = request(false, false);
    let early = Footer::decode(EARLY_QUOTA_BYTES).unwrap();
    for offset in [44, 48, 56, 64] {
        let mut bytes = [0; FOOTER_LEN];
        bytes.copy_from_slice(EARLY_QUOTA_BYTES);
        bytes[offset] = 1;
        assert_eq!(Footer::decode(&bytes), Err(ProtocolError::Counts));
    }
    let with_revision = Footer {
        flags: early.flags | REVISION_VALID,
        revision: 0,
        source: 3,
        ..early
    };
    assert!(StreamState::new(r).check_footer(with_revision).is_ok());
    assert_eq!(
        StreamState::new(r).check_footer(Footer {
            source: 2,
            ..with_revision
        }),
        Err(ProtocolError::Source)
    );
    assert_eq!(
        Footer {
            source: 0,
            ..with_revision
        }
        .validate(),
        Err(ProtocolError::Source)
    );
    assert_eq!(
        Footer {
            flags: early.flags | PREAMBLE_PRESENT,
            ..early
        }
        .validate(),
        Err(ProtocolError::State)
    );
    let mut tail = [0; FOOTER_LEN * 2];
    tail[..FOOTER_LEN].copy_from_slice(EARLY_QUOTA_BYTES);
    tail[FOOTER_LEN..].copy_from_slice(EARLY_QUOTA_BYTES);
    assert_eq!(
        parse(&tail, r),
        Err(ParseError::Protocol(ProtocolError::TrailingBytes))
    );
}

#[test]
fn group_reference_facts_are_required_correlated_and_minted_only_after_loaded_stream() {
    let r = request(true, false);
    assert_eq!(
        StreamState::new(r).required_facts(),
        Err(ProtocolError::State)
    );
    for fact in [
        GroupReferenceFact::NoReference,
        GroupReferenceFact::Exists,
        GroupReferenceFact::Absent,
        GroupReferenceFact::InvalidUuid,
        GroupReferenceFact::Unproven,
    ] {
        let group: &[u8] = match fact {
            GroupReferenceFact::NoReference => b"",
            GroupReferenceFact::InvalidUuid => b"invalid",
            _ => b"00000000-0000-0000-0000-000000000004",
        };
        let p = Preamble::new(r, REVISION, 3, 22, group.len() as u64, fact).unwrap();
        let mut header_state = StreamState::new(r);
        header_state.accept_preamble(p).unwrap();
        header_state.accept_field(text(1, 0, b""), b"").unwrap();
        let incompatible = FieldHeader {
            tag: 2,
            kind: if fact == GroupReferenceFact::NoReference {
                Kind::Utf8
            } else {
                Kind::Null
            },
            ordinal: 0,
            len: 0,
        };
        assert_eq!(
            header_state.check_header(incompatible),
            Err(ProtocolError::Facts)
        );
        assert_eq!(header_state.required_facts(), Err(ProtocolError::State));
        let mut sink = Sink::new();
        let mut writer = FrameWriter::new(&mut sink, r);
        writer.write_preamble(p).unwrap();
        for tag in 1..=22 {
            let (kind, payload): (Kind, &[u8]) = match tag {
                5 => (Kind::U16, &[22, 0]),
                14 => (Kind::I64, &[0; 8]),
                2 if fact == GroupReferenceFact::NoReference => (Kind::Null, b""),
                2 => (Kind::Utf8, group),
                9 | 10 | 12 | 15 => (Kind::Null, b""),
                _ => (Kind::Utf8, b""),
            };
            writer
                .write_field(
                    FieldHeader {
                        tag,
                        kind,
                        ordinal: 0,
                        len: payload.len() as u64,
                    },
                    payload,
                )
                .unwrap();
        }
        writer
            .finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default())
            .unwrap();
        let (footer, state) = parse_state(sink.bytes(), r).unwrap();
        assert_eq!(state.required_facts().unwrap().group_reference(), fact);
        assert_eq!(footer.flags & GROUP_FACT_MASK, fact.footer_bits());
        for value in [0, 6, 7] {
            let mut bytes = sink.bytes().to_vec();
            bytes[10] = value;
            assert_eq!(
                parse(&bytes, r),
                Err(ParseError::Protocol(ProtocolError::Facts))
            );
            let mut bytes = sink.bytes().to_vec();
            let start = bytes.len() - FOOTER_LEN;
            bytes[start + 13] = value;
            assert_eq!(
                parse(&bytes, r),
                Err(ParseError::Protocol(ProtocolError::Facts))
            );
        }
        let mut bytes = sink.bytes().to_vec();
        let start = bytes.len() - FOOTER_LEN;
        bytes[start + 13] = if fact == GroupReferenceFact::Exists {
            3
        } else {
            2
        };
        assert_eq!(
            parse(&bytes, r),
            Err(ParseError::Protocol(ProtocolError::Facts))
        );
        let mut bytes = sink.bytes().to_vec();
        bytes[start + 10] = Outcome::StorageFailure as u8;
        let (_, state) = parse_state(&bytes, r).unwrap();
        assert_eq!(state.required_facts(), Err(ProtocolError::State));
        assert!(parse_state(&sink.bytes()[..sink.len - 1], r).is_err());
    }
    let mut sink = Sink::new();
    FrameWriter::new(&mut sink, r)
        .finish(Outcome::StorageFailure, 0, Diagnostics::default())
        .unwrap();
    assert_eq!(
        parse_state(sink.bytes(), r).unwrap().1.required_facts(),
        Err(ProtocolError::State)
    );
    assert_eq!(
        Preamble::new(
            request(false, false),
            0,
            3,
            6,
            0,
            GroupReferenceFact::Exists
        ),
        Err(ProtocolError::Facts)
    );
    let early = Footer {
        flags: NONCE_VALID | GroupReferenceFact::NoReference.footer_bits(),
        outcome: Outcome::StorageFailure,
        nonce: NONCE,
        revision: 0,
        source: 0,
        stats: Statistics::default(),
        diagnostics: Diagnostics::default(),
    };
    assert_eq!(early.validate(), Err(ProtocolError::Facts));
}

#[test]
fn invalid_writer_input_emits_no_bytes_and_keeps_boundary_recoverable() {
    let r = request(false, false);
    let mut sink = Sink::new();
    let mut writer = FrameWriter::new(&mut sink, r);
    assert_eq!(
        writer.finish(Outcome::LoadedRaw, VERIFIED, Diagnostics::default()),
        Err(WriteError::Protocol(ProtocolError::Outcome))
    );
    assert_eq!(writer.statistics(), Statistics::default());
    writer
        .write_preamble(preamble(r, 0, 3, 6, 1).unwrap())
        .unwrap();
    assert_eq!(
        writer.write_field(text(18, 0, b""), b""),
        Err(WriteError::Protocol(ProtocolError::Order))
    );
    assert!(!writer.is_failed());
    writer
        .finish(Outcome::SelectedLimit, 0, Diagnostics::default())
        .unwrap();
    assert_eq!(sink.len, 192);
    assert_eq!(parse(sink.bytes(), r).unwrap().stats.wire_before_footer, 64);
}
