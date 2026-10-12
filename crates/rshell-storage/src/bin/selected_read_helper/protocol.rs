use std::io::{Read, Write};

pub const REQUEST_LEN: usize = 72;
pub const RESULT_LEN: usize = 128;
pub const DEFAULT_CAP: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Outcome {
    PreflightPassed = 0,
    MissingConnection = 1,
    MissingProfile = 2,
    SelectedLimit = 3,
    CBudgetExceeded = 4,
    StorageFailure = 5,
    InvalidRequest = 6,
    UnsupportedEnvelope = 7,
    SystemOom = 8,
    InternalFailure = 9,
}

#[derive(Clone, Copy)]
pub struct Request {
    pub cap: usize,
    pub field: u64,
    pub total: u64,
    pub tags: u32,
    pub connection: Option<[u8; 16]>,
    pub profile: Option<[u8; 16]>,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            cap: DEFAULT_CAP,
            field: 65536,
            total: 1048576,
            tags: 256,
            connection: None,
            profile: None,
        }
    }
}

impl Request {
    pub fn read(reader: &mut impl Read) -> Option<Self> {
        let mut b = [0; REQUEST_LEN];
        reader.read_exact(&mut b).ok()?;
        let mut extra = [0];
        if reader.read(&mut extra).ok()? != 0
            || &b[..8] != b"SHSELREQ"
            || b[8..10] != 1u16.to_le_bytes()
        {
            return None;
        }
        let flags = u16::from_le_bytes(b[10..12].try_into().ok()?);
        let cap = usize::try_from(u64::from_le_bytes(b[12..20].try_into().ok()?)).ok()?;
        let field = u64::from_le_bytes(b[20..28].try_into().ok()?);
        let total = u64::from_le_bytes(b[28..36].try_into().ok()?);
        let tags = u32::from_le_bytes(b[36..40].try_into().ok()?);
        if flags & !3 != 0
            || !(65536..=67108864).contains(&cap)
            || cap % 16 != 0
            || !(1..=1048576).contains(&field)
            || !(field..=4194304).contains(&total)
            || tags > 4096
        {
            return None;
        }
        let connection: [u8; 16] = b[40..56].try_into().ok()?;
        let profile: [u8; 16] = b[56..72].try_into().ok()?;
        if (flags & 1 == 0 && connection != [0; 16]) || (flags & 2 == 0 && profile != [0; 16]) {
            return None;
        }
        Some(Self {
            cap,
            field,
            total,
            tags,
            connection: (flags & 1 != 0).then_some(connection),
            profile: (flags & 2 != 0).then_some(profile),
        })
    }

    #[cfg(test)]
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut b = [0; REQUEST_LEN];
        b[..8].copy_from_slice(b"SHSELREQ");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(
            &(u16::from(self.connection.is_some()) | (u16::from(self.profile.is_some()) << 1))
                .to_le_bytes(),
        );
        b[12..20].copy_from_slice(&(self.cap as u64).to_le_bytes());
        b[20..28].copy_from_slice(&self.field.to_le_bytes());
        b[28..36].copy_from_slice(&self.total.to_le_bytes());
        b[36..40].copy_from_slice(&self.tags.to_le_bytes());
        b[40..56].copy_from_slice(&self.connection.unwrap_or([0; 16]));
        b[56..72].copy_from_slice(&self.profile.unwrap_or([0; 16]));
        b
    }
}

// 只有固定数字元信息；不承载路径、SQL 或所选字段。
// 帧：0 magic，8 version，10 outcome；12/16/20/24 为 code/phase/reason/source；
// 28 rounded；32 起为 rows/bytes/revision/peak/occupied/requested/available/largest；
// 96 operations，104 phase 位集（u32），108 拒绝时 occupied（u32），112 flags，120 reprepare。
// flags：1 readonly，2 total_changes=0，4 清理状态异常，8 构建与包络条件已核验。
// Budget 表示请求已被首次 actual quota 永久拒绝，不推断最终 NOMEM 的原因。
// code=0 表示收口 API 实际成功；code=4 表示实际 NOMEM。quota phase/reason/
// 尺寸来自首证；peak/occupied/operations 仍是实际完整生命周期的统计。
#[derive(Clone, Copy, Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub code: u16,
    pub phase: u8,
    pub reason: u8,
    pub source: u8,
    pub rows: u64,
    pub bytes: u64,
    pub revision: u64,
    pub peak: u64,
    pub occupied: u64,
    pub requested: u64,
    pub available: u64,
    pub largest: u64,
    pub operations: u64,
    pub phases: u64,
    pub flags: u64,
    pub reprepare: u64,
    pub denied_occupied: u32,
    pub rounded: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_boundaries_and_fixed_result() {
        let request = Request::default();
        assert_eq!(
            Request::read(&mut &request.encode()[..]).unwrap().cap,
            DEFAULT_CAP
        );
        for (offset, value) in [(0, 0), (8, 2), (10, 4), (40, 1), (56, 1)] {
            let mut b = request.encode();
            b[offset] = value;
            assert!(Request::read(&mut &b[..]).is_none());
        }
        for cap in [0, 65535, 65537, 67108880, usize::MAX] {
            let b = Request { cap, ..request }.encode();
            assert!(Request::read(&mut &b[..]).is_none());
        }
        for invalid in [
            Request {
                field: 0,
                ..request
            },
            Request {
                field: 1048577,
                ..request
            },
            Request {
                total: 4194305,
                ..request
            },
            Request {
                total: 1,
                ..request
            },
            Request {
                tags: 4097,
                ..request
            },
        ] {
            assert!(Request::read(&mut &invalid.encode()[..]).is_none());
        }
        for cap in [65536, 67108864] {
            assert_eq!(
                Request::read(&mut &Request { cap, ..request }.encode()[..])
                    .unwrap()
                    .cap,
                cap
            );
        }
        assert_eq!(Report::new(Outcome::CBudgetExceeded).encode().len(), 128);
    }
}

impl Report {
    pub fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            code: 0,
            phase: 0,
            reason: 0,
            source: 0,
            rows: 0,
            bytes: 0,
            revision: 0,
            peak: 0,
            occupied: 0,
            requested: 0,
            available: 0,
            largest: 0,
            operations: 0,
            phases: 0,
            flags: 0,
            reprepare: 0,
            denied_occupied: 0,
            rounded: 0,
        }
    }
    pub fn encode(self) -> [u8; RESULT_LEN] {
        let mut b = [0; RESULT_LEN];
        b[..8].copy_from_slice(b"SHSELRES");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&(self.outcome as u16).to_le_bytes());
        for (i, v) in [
            u32::from(self.code),
            u32::from(self.phase),
            u32::from(self.reason),
            u32::from(self.source),
        ]
        .into_iter()
        .enumerate()
        {
            b[12 + i * 4..16 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        for (i, v) in [
            self.rows,
            self.bytes,
            self.revision,
            self.peak,
            self.occupied,
            self.requested,
            self.available,
            self.largest,
            self.operations,
            self.phases,
            self.flags,
            self.reprepare,
        ]
        .into_iter()
        .enumerate()
        {
            b[32 + i * 8..40 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        b[28..32].copy_from_slice(&self.rounded.to_le_bytes());
        b[108..112].copy_from_slice(&self.denied_occupied.to_le_bytes());
        b
    }
    pub fn write(self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_all(&self.encode())?;
        writer.flush()
    }
}
