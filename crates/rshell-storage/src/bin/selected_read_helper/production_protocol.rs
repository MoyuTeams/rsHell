//! 私有 v2 固定线格式及完整 raw/facts 校验；不读取 SQLite、不签发 Rust 预算证书。
//! 帧在栈上构造，字段仅借用；backing、准入与最终清理由 producer/进程 owner 持有。

use std::io::{self, Read, Write};

pub const REQUEST_LEN: usize = 112;
pub const PREAMBLE_LEN: usize = 64;
pub const FIELD_HEADER_LEN: usize = 24;
pub const FOOTER_LEN: usize = 128;
pub const PREAMBLE_PRESENT: u32 = 1;
pub const REVISION_VALID: u32 = 2;
pub const NONCE_VALID: u32 = 4;
pub const READONLY: u32 = 8;
pub const TOTAL_CHANGES_ZERO: u32 = 16;
pub const CLEANUP_FAILED: u32 = 32;
pub const ENVELOPE_VERIFIED: u32 = 64;
pub const QUOTA_PROVED: u32 = 128;
pub const GROUP_FACT_SHIFT: u32 = 8;
pub const GROUP_FACT_MASK: u32 = 7 << GROUP_FACT_SHIFT;
const SUCCESS_FLAGS: u32 = PREAMBLE_PRESENT
    | REVISION_VALID
    | NONCE_VALID
    | READONLY
    | TOTAL_CHANGES_ZERO
    | ENVELOPE_VERIFIED;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Length,
    Magic,
    Version,
    Reserved,
    Limit,
    Overflow,
    Selection,
    Source,
    Nonce,
    Revision,
    Field,
    Order,
    Utf8,
    Counts,
    Outcome,
    State,
    TrailingBytes,
    Facts,
}

/// 仅证明 selected 引用的 membership，不证明组树、positions 或全 catalog 有效性。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupReferenceFact {
    NoReference = 1,
    Exists = 2,
    Absent = 3,
    InvalidUuid = 4,
    Unproven = 5,
}

impl GroupReferenceFact {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::NoReference),
            2 => Ok(Self::Exists),
            3 => Ok(Self::Absent),
            4 => Ok(Self::InvalidUuid),
            5 => Ok(Self::Unproven),
            _ => Err(ProtocolError::Facts),
        }
    }

    pub fn footer_bits(self) -> u32 {
        (self as u32) << GROUP_FACT_SHIFT
    }
}

/// 只能由完整成功 stream 状态 mint；调用方仍须确认 EOF、可信产物和真实 wait/drain。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredFacts {
    group_reference: GroupReferenceFact,
}

impl RequiredFacts {
    pub fn group_reference(self) -> GroupReferenceFact {
        self.group_reference
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Outcome {
    LoadedRaw = 0,
    MissingConnection = 1,
    MissingProfile = 2,
    SelectedLimit = 3,
    CBudgetExceeded = 4,
    StorageFailure = 5,
    InvalidRequest = 6,
    UnsupportedEnvelope = 7,
    SystemOom = 8,
    InternalFailure = 9,
    RustBudgetExceeded = 10,
}

impl Outcome {
    fn decode(value: u16) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::LoadedRaw),
            1 => Ok(Self::MissingConnection),
            2 => Ok(Self::MissingProfile),
            3 => Ok(Self::SelectedLimit),
            4 => Ok(Self::CBudgetExceeded),
            5 => Ok(Self::StorageFailure),
            6 => Ok(Self::InvalidRequest),
            7 => Ok(Self::UnsupportedEnvelope),
            8 => Ok(Self::SystemOom),
            9 => Ok(Self::InternalFailure),
            10 => Ok(Self::RustBudgetExceeded),
            _ => Err(ProtocolError::Outcome),
        }
    }
}

pub fn checked_size(value: u64) -> Result<usize, ProtocolError> {
    let size = usize::try_from(value).map_err(|_| ProtocolError::Overflow)?;
    isize::try_from(size).map_err(|_| ProtocolError::Overflow)?;
    Ok(size)
}

pub fn wire_upper(fields: u32, text: u64, integers: u64) -> Result<u64, ProtocolError> {
    24u64
        .checked_mul(u64::from(fields))
        .and_then(|n| n.checked_add(64))
        .and_then(|n| n.checked_add(text))
        .and_then(|n| n.checked_add(integers))
        .and_then(|n| n.checked_add(128))
        .ok_or(ProtocolError::Overflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub c_max: u64,
    pub field_max: u64,
    pub total_max: u64,
    pub tags_max: u32,
    pub connection: Option<[u8; 16]>,
    pub profile: Option<[u8; 16]>,
    pub wire_max: u64,
    pub helper_rust_max: u64,
    pub frame_count_max: u32,
    pub nonce: [u8; 16],
}

/// 只证明线结构及 wire 限额；helper_rust_max 仍是待证书核验的原始额度。
/// 本类型不是 RustCertificate，也不提供生产批准或 backing 分配接口。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireValidatedRequest {
    request: Request,
}

impl Request {
    pub fn validate(self) -> Result<WireValidatedRequest, ProtocolError> {
        if !(65536..=67108864).contains(&self.c_max)
            || !self.c_max.is_multiple_of(16)
            || !(1..=1048576).contains(&self.field_max)
            || !(self.field_max..=4194304).contains(&self.total_max)
            || self.tags_max > 4096
        {
            return Err(ProtocolError::Limit);
        }
        let frames = if self.connection.is_some() {
            22u32
                .checked_add(self.tags_max)
                .ok_or(ProtocolError::Overflow)?
        } else {
            6
        };
        let integers = if self.connection.is_some() { 10 } else { 0 };
        if self.frame_count_max != frames
            || self.wire_max != wire_upper(frames, self.total_max, integers)?
        {
            return Err(ProtocolError::Limit);
        }
        for size in [self.c_max, self.field_max, self.total_max, self.wire_max] {
            checked_size(size)?;
        }
        checked_size(u64::from(frames))?;
        Ok(WireValidatedRequest { request: self })
    }

    pub fn decode(bytes: &[u8]) -> Result<WireValidatedRequest, ProtocolError> {
        if bytes.len() != REQUEST_LEN {
            return Err(ProtocolError::Length);
        }
        if &bytes[..8] != b"SHSELREQ" {
            return Err(ProtocolError::Magic);
        }
        if u16_at(bytes, 8) != 2 {
            return Err(ProtocolError::Version);
        }
        let flags = u16_at(bytes, 10);
        if flags & !3 != 0 || u32_at(bytes, 92) != 0 {
            return Err(ProtocolError::Reserved);
        }
        let connection = array_at(bytes, 40);
        let profile = array_at(bytes, 56);
        if (flags & 1 == 0 && connection != [0; 16]) || (flags & 2 == 0 && profile != [0; 16]) {
            return Err(ProtocolError::Selection);
        }
        Self {
            c_max: u64_at(bytes, 12),
            field_max: u64_at(bytes, 20),
            total_max: u64_at(bytes, 28),
            tags_max: u32_at(bytes, 36),
            connection: (flags & 1 != 0).then_some(connection),
            profile: (flags & 2 != 0).then_some(profile),
            wire_max: u64_at(bytes, 72),
            helper_rust_max: u64_at(bytes, 80),
            frame_count_max: u32_at(bytes, 88),
            nonce: array_at(bytes, 96),
        }
        .validate()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestReadError {
    Protocol(ProtocolError),
    Io(io::ErrorKind),
}

impl WireValidatedRequest {
    pub fn limits(self) -> Request {
        self.request
    }

    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let r = self.request;
        let mut bytes = [0; REQUEST_LEN];
        bytes[..8].copy_from_slice(b"SHSELREQ");
        put16(&mut bytes, 8, 2);
        put16(
            &mut bytes,
            10,
            u16::from(r.connection.is_some()) | (u16::from(r.profile.is_some()) << 1),
        );
        put64(&mut bytes, 12, r.c_max);
        put64(&mut bytes, 20, r.field_max);
        put64(&mut bytes, 28, r.total_max);
        put32(&mut bytes, 36, r.tags_max);
        bytes[40..56].copy_from_slice(&r.connection.unwrap_or([0; 16]));
        bytes[56..72].copy_from_slice(&r.profile.unwrap_or([0; 16]));
        put64(&mut bytes, 72, r.wire_max);
        put64(&mut bytes, 80, r.helper_rust_max);
        put32(&mut bytes, 88, r.frame_count_max);
        bytes[96..112].copy_from_slice(&r.nonce);
        bytes
    }

    pub fn read(reader: &mut impl Read) -> Result<Self, RequestReadError> {
        let mut bytes = [0; REQUEST_LEN];
        reader
            .read_exact(&mut bytes)
            .map_err(|e| RequestReadError::Io(e.kind()))?;
        let request = Request::decode(&bytes).map_err(RequestReadError::Protocol)?;
        let mut extra = [0];
        loop {
            match reader.read(&mut extra) {
                Ok(0) => return Ok(request),
                Ok(_) => {
                    return Err(RequestReadError::Protocol(ProtocolError::TrailingBytes));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(RequestReadError::Io(e.kind())),
            }
        }
    }
}

fn check_source(request: Request, source: u32) -> Result<(), ProtocolError> {
    if !(1..=3).contains(&source) {
        return Err(ProtocolError::Source);
    }
    let valid = if request.profile.is_some() {
        source == 1
    } else if request.connection.is_some() {
        source == 2 || source == 3
    } else {
        source == 3
    };
    if !valid {
        return Err(ProtocolError::Source);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preamble {
    pub nonce: [u8; 16],
    pub revision: u64,
    pub source: u32,
    pub fields: u32,
    pub text_upper: u64,
    pub wire_upper: u64,
    pub group_reference: GroupReferenceFact,
}

impl Preamble {
    pub fn new(
        request: WireValidatedRequest,
        revision: u64,
        source: u32,
        fields: u32,
        text_upper: u64,
        group_reference: GroupReferenceFact,
    ) -> Result<Self, ProtocolError> {
        let integers = if request.request.connection.is_some() {
            10
        } else {
            0
        };
        let value = Self {
            nonce: request.request.nonce,
            revision,
            source,
            fields,
            text_upper,
            wire_upper: wire_upper(fields, text_upper, integers)?,
            group_reference,
        };
        value.validate(request)?;
        Ok(value)
    }

    pub fn validate(self, request: WireValidatedRequest) -> Result<(), ProtocolError> {
        let r = request.request;
        if self.nonce != r.nonce {
            return Err(ProtocolError::Nonce);
        }
        check_source(r, self.source)?;
        if r.connection.is_none() && self.group_reference != GroupReferenceFact::NoReference {
            return Err(ProtocolError::Facts);
        }
        let integers = if r.connection.is_some() { 10 } else { 0 };
        if (r.connection.is_some() && !(22..=r.frame_count_max).contains(&self.fields))
            || (r.connection.is_none() && self.fields != 6)
            || self.text_upper > r.total_max
            || self.wire_upper != wire_upper(self.fields, self.text_upper, integers)?
            || self.wire_upper > r.wire_max
        {
            return Err(ProtocolError::Limit);
        }
        checked_size(self.text_upper)?;
        checked_size(self.wire_upper)?;
        Ok(())
    }

    pub fn encode(
        self,
        request: WireValidatedRequest,
    ) -> Result<[u8; PREAMBLE_LEN], ProtocolError> {
        self.validate(request)?;
        let mut bytes = [0; PREAMBLE_LEN];
        bytes[..8].copy_from_slice(b"SHSELHD2");
        put16(&mut bytes, 8, 2);
        put16(&mut bytes, 10, self.group_reference as u16);
        put32(&mut bytes, 12, 64);
        bytes[16..32].copy_from_slice(&self.nonce);
        put64(&mut bytes, 32, self.revision);
        put32(&mut bytes, 40, self.source);
        put32(&mut bytes, 44, self.fields);
        put64(&mut bytes, 48, self.text_upper);
        put64(&mut bytes, 56, self.wire_upper);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], request: WireValidatedRequest) -> Result<Self, ProtocolError> {
        if bytes.len() != PREAMBLE_LEN {
            return Err(ProtocolError::Length);
        }
        if &bytes[..8] != b"SHSELHD2" {
            return Err(ProtocolError::Magic);
        }
        if u16_at(bytes, 8) != 2 {
            return Err(ProtocolError::Version);
        }
        if u16_at(bytes, 10) & !7 != 0 || u32_at(bytes, 12) != 64 {
            return Err(ProtocolError::Reserved);
        }
        let value = Self {
            nonce: array_at(bytes, 16),
            revision: u64_at(bytes, 32),
            source: u32_at(bytes, 40),
            fields: u32_at(bytes, 44),
            text_upper: u64_at(bytes, 48),
            wire_upper: u64_at(bytes, 56),
            group_reference: GroupReferenceFact::decode(u16_at(bytes, 10) as u8)?,
        };
        value.validate(request)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Null = 0,
    Utf8 = 1,
    U16 = 2,
    I64 = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldHeader {
    pub tag: u16,
    pub kind: Kind,
    pub ordinal: u32,
    pub len: u64,
}

impl FieldHeader {
    pub fn validate(self) -> Result<(), ProtocolError> {
        let valid = match self.tag {
            5 => self.kind == Kind::U16 && self.len == 2,
            14 => self.kind == Kind::I64 && self.len == 8,
            2 | 9 | 10 | 12 | 15 => {
                self.kind == Kind::Utf8 || (self.kind == Kind::Null && self.len == 0)
            }
            1..=23 => self.kind == Kind::Utf8,
            _ => false,
        };
        if !valid || (self.tag == 23 && self.ordinal == 0) || (self.tag != 23 && self.ordinal != 0)
        {
            return Err(ProtocolError::Field);
        }
        checked_size(self.len)?;
        Ok(())
    }

    pub fn encode(self) -> Result<[u8; FIELD_HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut bytes = [0; FIELD_HEADER_LEN];
        bytes[..8].copy_from_slice(b"SHSELFD2");
        put16(&mut bytes, 8, self.tag);
        bytes[10] = self.kind as u8;
        put32(&mut bytes, 12, self.ordinal);
        put64(&mut bytes, 16, self.len);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != FIELD_HEADER_LEN {
            return Err(ProtocolError::Length);
        }
        if &bytes[..8] != b"SHSELFD2" {
            return Err(ProtocolError::Magic);
        }
        if bytes[11] != 0 {
            return Err(ProtocolError::Reserved);
        }
        let kind = match bytes[10] {
            0 => Kind::Null,
            1 => Kind::Utf8,
            2 => Kind::U16,
            3 => Kind::I64,
            _ => return Err(ProtocolError::Field),
        };
        let value = Self {
            tag: u16_at(bytes, 8),
            kind,
            ordinal: u32_at(bytes, 12),
            len: u64_at(bytes, 16),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub completed_fields: u32,
    pub text_bytes: u64,
    pub integer_bytes: u64,
    pub wire_before_footer: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub code: u16,
    pub phase: u8,
    pub reason: u8,
    pub rounded: u32,
    pub requested: u64,
    pub denied_occupied: u64,
    pub available: u64,
    pub largest: u64,
    pub first_quota_op: u64,
    pub occupied_after_shutdown: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Footer {
    pub outcome: Outcome,
    pub flags: u32,
    pub nonce: [u8; 16],
    pub revision: u64,
    pub source: u32,
    pub stats: Statistics,
    pub diagnostics: Diagnostics,
}

impl Footer {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.flags & !(255 | GROUP_FACT_MASK) != 0 {
            return Err(ProtocolError::Reserved);
        }
        if self.flags & NONCE_VALID == 0 && self.nonce != [0; 16] {
            return Err(ProtocolError::Nonce);
        }
        if self.flags & REVISION_VALID == 0 {
            if self.revision != 0 || self.source != 0 {
                return Err(ProtocolError::Revision);
            }
        } else if !(1..=3).contains(&self.source) {
            return Err(ProtocolError::Source);
        }
        if self.flags & PREAMBLE_PRESENT == 0 && self.stats != Statistics::default() {
            return Err(ProtocolError::Counts);
        }
        if self.flags & PREAMBLE_PRESENT != 0
            && self.flags & (NONCE_VALID | REVISION_VALID) != NONCE_VALID | REVISION_VALID
        {
            return Err(ProtocolError::State);
        }
        if self.flags & NONCE_VALID == 0
            && (self.outcome != Outcome::InvalidRequest
                || self.flags & (PREAMBLE_PRESENT | REVISION_VALID) != 0)
        {
            return Err(ProtocolError::Nonce);
        }
        if self.flags & PREAMBLE_PRESENT != 0 {
            GroupReferenceFact::decode(((self.flags & GROUP_FACT_MASK) >> GROUP_FACT_SHIFT) as u8)?;
        } else if self.flags & GROUP_FACT_MASK != 0 {
            return Err(ProtocolError::Facts);
        }
        let d = self.diagnostics;
        if self.flags & QUOTA_PROVED == 0 && d.first_quota_op != 0 {
            return Err(ProtocolError::Outcome);
        }
        if self.flags & QUOTA_PROVED != 0 && d.first_quota_op == 0 {
            return Err(ProtocolError::Outcome);
        }
        if d.occupied_after_shutdown != 0 && self.flags & CLEANUP_FAILED == 0 {
            return Err(ProtocolError::Outcome);
        }
        if self.outcome == Outcome::CBudgetExceeded
            && (self.flags & QUOTA_PROVED == 0 || !matches!(d.code, 0 | 4))
        {
            return Err(ProtocolError::Outcome);
        }
        if self.outcome == Outcome::LoadedRaw
            && (self.flags & !GROUP_FACT_MASK != SUCCESS_FLAGS
                || d.code != 0
                || d.occupied_after_shutdown != 0)
        {
            return Err(ProtocolError::Outcome);
        }
        Ok(())
    }

    pub fn encode(self) -> Result<[u8; FOOTER_LEN], ProtocolError> {
        self.validate()?;
        let mut bytes = [0; FOOTER_LEN];
        bytes[..8].copy_from_slice(b"SHSELFN2");
        put16(&mut bytes, 8, 2);
        put16(&mut bytes, 10, self.outcome as u16);
        put32(&mut bytes, 12, self.flags);
        bytes[16..32].copy_from_slice(&self.nonce);
        put64(&mut bytes, 32, self.revision);
        put32(&mut bytes, 40, self.source);
        put32(&mut bytes, 44, self.stats.completed_fields);
        put64(&mut bytes, 48, self.stats.text_bytes);
        put64(&mut bytes, 56, self.stats.integer_bytes);
        put64(&mut bytes, 64, self.stats.wire_before_footer);
        let d = self.diagnostics;
        put16(&mut bytes, 72, d.code);
        bytes[74] = d.phase;
        bytes[75] = d.reason;
        put32(&mut bytes, 76, d.rounded);
        for (offset, value) in [
            (80, d.requested),
            (88, d.denied_occupied),
            (96, d.available),
            (104, d.largest),
            (112, d.first_quota_op),
            (120, d.occupied_after_shutdown),
        ] {
            put64(&mut bytes, offset, value);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != FOOTER_LEN {
            return Err(ProtocolError::Length);
        }
        if &bytes[..8] != b"SHSELFN2" {
            return Err(ProtocolError::Magic);
        }
        if u16_at(bytes, 8) != 2 {
            return Err(ProtocolError::Version);
        }
        let value = Self {
            outcome: Outcome::decode(u16_at(bytes, 10))?,
            flags: u32_at(bytes, 12),
            nonce: array_at(bytes, 16),
            revision: u64_at(bytes, 32),
            source: u32_at(bytes, 40),
            stats: Statistics {
                completed_fields: u32_at(bytes, 44),
                text_bytes: u64_at(bytes, 48),
                integer_bytes: u64_at(bytes, 56),
                wire_before_footer: u64_at(bytes, 64),
            },
            diagnostics: Diagnostics {
                code: u16_at(bytes, 72),
                phase: bytes[74],
                reason: bytes[75],
                rounded: u32_at(bytes, 76),
                requested: u64_at(bytes, 80),
                denied_occupied: u64_at(bytes, 88),
                available: u64_at(bytes, 96),
                largest: u64_at(bytes, 104),
                first_quota_op: u64_at(bytes, 112),
                occupied_after_shutdown: u64_at(bytes, 120),
            },
        };
        value.validate()?;
        Ok(value)
    }
}

/// 只计已完成帧；不持有 payload、descriptor 或任何动态 backing。
#[derive(Clone, Copy, Debug)]
pub struct StreamState {
    request: WireValidatedRequest,
    preamble: Option<Preamble>,
    stats: Statistics,
    finished: bool,
    loaded: bool,
}

impl StreamState {
    pub fn new(request: WireValidatedRequest) -> Self {
        Self {
            request,
            preamble: None,
            stats: Statistics::default(),
            finished: false,
            loaded: false,
        }
    }

    pub fn statistics(self) -> Statistics {
        self.stats
    }

    pub fn required_facts(self) -> Result<RequiredFacts, ProtocolError> {
        if !self.finished || !self.loaded {
            return Err(ProtocolError::State);
        }
        Ok(RequiredFacts {
            group_reference: self.preamble.ok_or(ProtocolError::State)?.group_reference,
        })
    }

    pub fn accept_preamble(&mut self, preamble: Preamble) -> Result<(), ProtocolError> {
        if self.finished || self.preamble.is_some() {
            return Err(ProtocolError::State);
        }
        preamble.validate(self.request)?;
        self.preamble = Some(preamble);
        self.stats.wire_before_footer = 64;
        Ok(())
    }

    /// 在读取 payload 前核验长度、种类、顺序和剩余额度。
    pub fn check_header(self, header: FieldHeader) -> Result<Statistics, ProtocolError> {
        if self.finished {
            return Err(ProtocolError::State);
        }
        let preamble = self.preamble.ok_or(ProtocolError::State)?;
        header.validate()?;
        if header.tag == 2
            && (header.kind == Kind::Null)
                != (preamble.group_reference == GroupReferenceFact::NoReference)
        {
            return Err(ProtocolError::Facts);
        }
        let index = self.stats.completed_fields;
        if index >= preamble.fields {
            return Err(ProtocolError::Order);
        }
        let (tag, ordinal) = if self.request.request.connection.is_none() {
            (index.checked_add(17).ok_or(ProtocolError::Overflow)?, 0)
        } else if index < 22 {
            (index.checked_add(1).ok_or(ProtocolError::Overflow)?, 0)
        } else {
            (23, index.checked_sub(21).ok_or(ProtocolError::Overflow)?)
        };
        if u32::from(header.tag) != tag || header.ordinal != ordinal {
            return Err(ProtocolError::Order);
        }
        let mut next = self.stats;
        if header.kind == Kind::Utf8 {
            if header.len > self.request.request.field_max {
                return Err(ProtocolError::Limit);
            }
            next.text_bytes = next
                .text_bytes
                .checked_add(header.len)
                .ok_or(ProtocolError::Overflow)?;
            if next.text_bytes > preamble.text_upper {
                return Err(ProtocolError::Limit);
            }
        } else if matches!(header.kind, Kind::U16 | Kind::I64) {
            next.integer_bytes = next
                .integer_bytes
                .checked_add(header.len)
                .ok_or(ProtocolError::Overflow)?;
        }
        next.completed_fields = index.checked_add(1).ok_or(ProtocolError::Overflow)?;
        next.wire_before_footer = next
            .wire_before_footer
            .checked_add(24)
            .and_then(|n| n.checked_add(header.len))
            .ok_or(ProtocolError::Overflow)?;
        if next
            .wire_before_footer
            .checked_add(128)
            .ok_or(ProtocolError::Overflow)?
            > preamble.wire_upper
        {
            return Err(ProtocolError::Limit);
        }
        Ok(next)
    }

    pub fn accept_field(
        &mut self,
        header: FieldHeader,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let next = self.check_header(header)?;
        if payload.len() != checked_size(header.len)? {
            return Err(ProtocolError::Length);
        }
        if header.kind == Kind::Utf8 && std::str::from_utf8(payload).is_err() {
            return Err(ProtocolError::Utf8);
        }
        self.stats = next;
        Ok(())
    }

    pub fn footer(
        self,
        outcome: Outcome,
        flags: u32,
        diagnostics: Diagnostics,
    ) -> Result<Footer, ProtocolError> {
        let mut footer = Footer {
            outcome,
            flags: flags | NONCE_VALID,
            nonce: self.request.request.nonce,
            revision: 0,
            source: 0,
            stats: self.stats,
            diagnostics,
        };
        if let Some(preamble) = self.preamble {
            footer.flags |= PREAMBLE_PRESENT | REVISION_VALID;
            footer.revision = preamble.revision;
            footer.source = preamble.source;
            footer.flags |= preamble.group_reference.footer_bits();
        }
        self.check_footer(footer)?;
        Ok(footer)
    }

    pub fn check_footer(self, footer: Footer) -> Result<(), ProtocolError> {
        if self.finished {
            return Err(ProtocolError::State);
        }
        footer.validate()?;
        if footer.flags & NONCE_VALID == 0 || footer.nonce != self.request.request.nonce {
            return Err(ProtocolError::Nonce);
        }
        if footer.stats != self.stats {
            return Err(ProtocolError::Counts);
        }
        match self.preamble {
            Some(preamble) => {
                if footer.flags & PREAMBLE_PRESENT == 0 {
                    return Err(ProtocolError::State);
                }
                if footer.revision != preamble.revision {
                    return Err(ProtocolError::Revision);
                }
                if footer.source != preamble.source {
                    return Err(ProtocolError::Source);
                }
                if footer.flags & GROUP_FACT_MASK != preamble.group_reference.footer_bits() {
                    return Err(ProtocolError::Facts);
                }
                if footer.outcome == Outcome::LoadedRaw
                    && (self.stats.completed_fields != preamble.fields
                        || self.stats.integer_bytes
                            != if self.request.request.connection.is_some() {
                                10
                            } else {
                                0
                            })
                {
                    return Err(ProtocolError::Counts);
                }
            }
            None => {
                if footer.flags & PREAMBLE_PRESENT != 0 || footer.outcome == Outcome::LoadedRaw {
                    return Err(ProtocolError::State);
                }
                if footer.flags & REVISION_VALID != 0 {
                    check_source(self.request.request, footer.source)?;
                }
            }
        }
        Ok(())
    }

    pub fn accept_footer(&mut self, footer: Footer) -> Result<(), ProtocolError> {
        self.check_footer(footer)?;
        self.finished = true;
        self.loaded = footer.outcome == Outcome::LoadedRaw;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    Protocol(ProtocolError),
    Io(io::ErrorKind),
    Failed,
}

impl From<ProtocolError> for WriteError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// 同步 write_all 保持 payload 借用；不包装动态 BufWriter，不自行取得 permit。
/// success footer 仍必须由 producer 在真实 finalize/rollback/close/shutdown 后提供。
pub struct FrameWriter<W> {
    writer: W,
    state: StreamState,
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(writer: W, request: WireValidatedRequest) -> Self {
        Self {
            writer,
            state: StreamState::new(request),
            failed: false,
        }
    }

    pub fn statistics(&self) -> Statistics {
        self.state.statistics()
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    fn writable(&self) -> Result<(), WriteError> {
        if self.failed {
            Err(WriteError::Failed)
        } else if self.state.finished {
            Err(WriteError::Protocol(ProtocolError::State))
        } else {
            Ok(())
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        match self.writer.write_all(bytes) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.failed = true;
                Err(WriteError::Io(error.kind()))
            }
        }
    }

    pub fn write_preamble(&mut self, preamble: Preamble) -> Result<(), WriteError> {
        self.writable()?;
        let mut next = self.state;
        next.accept_preamble(preamble)?;
        let bytes = preamble.encode(self.state.request)?;
        self.write_all(&bytes)?;
        self.state = next;
        Ok(())
    }

    pub fn write_field(&mut self, header: FieldHeader, payload: &[u8]) -> Result<(), WriteError> {
        self.writable()?;
        let mut next = self.state;
        next.accept_field(header, payload)?;
        let bytes = header.encode()?;
        self.write_all(&bytes)?;
        self.write_all(payload)?;
        self.state = next;
        Ok(())
    }

    pub fn finish(
        &mut self,
        outcome: Outcome,
        flags: u32,
        diagnostics: Diagnostics,
    ) -> Result<(), WriteError> {
        self.writable()?;
        let footer = self.state.footer(outcome, flags, diagnostics)?;
        let bytes = footer.encode()?;
        self.write_all(&bytes)?;
        if let Err(error) = self.writer.flush() {
            self.failed = true;
            return Err(WriteError::Io(error.kind()));
        }
        self.state.accept_footer(footer)?;
        Ok(())
    }
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(array_at(bytes, offset))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(array_at(bytes, offset))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(array_at(bytes, offset))
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
