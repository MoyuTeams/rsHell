//! 同一只读事务的两遍 selected raw 读取；JSON 只作 opaque UTF-8 字节输出。
//! Bounds/Selection/Row/Failure 均在栈上；固定 CStr 直接传 SQLite，无 Rust SQL backing。
//! 列借用一直保留到同步 FrameWriter::write_field 返回，随后才 step/finalize。

use super::{
    envelope::Arena,
    preflight::{self, Db, Statement},
    production_protocol::{
        FieldHeader, FrameWriter, GroupReferenceFact, Kind, Preamble, WireValidatedRequest,
        WriteError,
    },
    protocol::{Outcome, Report, Request},
    rust_budget::source::FIXED_SQL,
};
use std::{ffi::CStr, io::Write};

const CONNECTION_TAGS: [u16; 14] = [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16];
const NULLABLE: [bool; 14] = [
    false, true, false, false, false, false, false, true, true, false, true, false, true, false,
];

struct Row {
    meta: &'static CStr,
    payload: &'static CStr,
    nullable: &'static [bool],
    missing: Outcome,
}

const CONNECTION: Row = Row {
    meta: FIXED_SQL[8],
    payload: FIXED_SQL[13],
    nullable: &NULLABLE,
    missing: Outcome::MissingConnection,
};
const SETTINGS: Row = Row {
    meta: FIXED_SQL[9],
    payload: FIXED_SQL[14],
    nullable: &[false; 3],
    missing: Outcome::StorageFailure,
};
const PROFILE: Row = Row {
    meta: FIXED_SQL[10],
    payload: FIXED_SQL[15],
    nullable: &[false; 3],
    missing: Outcome::MissingProfile,
};

#[derive(Clone, Copy)]
struct Selection {
    connection: Option<UuidKey>,
    profile: UuidKey,
    connection_bounds: [u64; 14],
    settings_bounds: [u64; 3],
    profile_bounds: [u64; 3],
    port: u16,
    position: i64,
    tags: u32,
    utf16: bool,
    summary: Report,
    group_reference: GroupReferenceFact,
}

/// 锁定 UUID parser 的四种合法 ASCII 文本形状，最长 urn:uuid: 为 45 bytes。
/// 仅保存真正匹配的原始 SQLite key；不改写 raw UUID 字段。
#[derive(Clone, Copy)]
struct UuidKey {
    bytes: [u8; 45],
    len: usize,
}

impl UuidKey {
    fn from_ascii(bytes: &[u8]) -> preflight::Result<Self> {
        if bytes.len() > 45 {
            return Err(Report::new(Outcome::InternalFailure));
        }
        let mut key = Self {
            bytes: [0; 45],
            len: bytes.len(),
        };
        key.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(key)
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy)]
enum UuidReference {
    None,
    Valid([u8; 16]),
    Invalid,
}

const TAG_META: &CStr = c"SELECT typeof(connection_id),octet_length(connection_id),connection_id,typeof(tag),octet_length(tag) FROM connection_tags WHERE typeof(connection_id)='text' AND replace(replace(replace(replace(lower(connection_id),'urn:uuid:',''),'{',''),'}',''),'-','')=replace(?1,'-','') ORDER BY tag";
const TAG_PAYLOAD: &CStr = c"SELECT typeof(connection_id),octet_length(connection_id),connection_id,typeof(tag),octet_length(tag),tag FROM connection_tags WHERE typeof(connection_id)='text' AND replace(replace(replace(replace(lower(connection_id),'urn:uuid:',''),'{',''),'}',''),'-','')=replace(?1,'-','') ORDER BY tag";

fn matches_uuid(s: &Statement<'_>, target: [u8; 16], utf16: bool) -> preflight::Result<bool> {
    let upper = preflight::metadata(s, 0, false, utf16)?;
    s.with_text_bytes(2, false, upper, |bytes| {
        Ok(bytes
            .and_then(|bytes| uuid::Uuid::try_parse_ascii(bytes).ok())
            .is_some_and(|id| id.into_bytes() == target))
    })
}

fn find_key(
    db: &Db,
    sql: &CStr,
    target: [u8; 16],
    utf16: bool,
    missing: Outcome,
) -> preflight::Result<UuidKey> {
    let s = db.prepare_fixed(sql)?;
    let mut found = None;
    while s.step()? {
        let upper = preflight::metadata(&s, 0, false, utf16)?;
        s.with_text_bytes(2, false, upper, |bytes| {
            let bytes = bytes.ok_or_else(preflight::corrupt_report)?;
            if uuid::Uuid::try_parse_ascii(bytes).is_ok_and(|id| id.into_bytes() == target) {
                if found.is_some() {
                    return preflight::corrupt();
                }
                found = Some(UuidKey::from_ascii(bytes)?);
            }
            Ok(())
        })?;
    }
    s.finish()?;
    found.ok_or_else(|| Report::new(missing))
}

fn group_fact(
    db: &Db,
    key: &UuidKey,
    upper: u64,
    utf16: bool,
) -> preflight::Result<GroupReferenceFact> {
    let reference = reference(
        db,
        c"SELECT group_id FROM connections WHERE id=?1",
        Some(key.as_bytes()),
        true,
        upper,
    )?;
    let target = match reference {
        UuidReference::None => return Ok(GroupReferenceFact::NoReference),
        UuidReference::Invalid => return Ok(GroupReferenceFact::InvalidUuid),
        UuidReference::Valid(target) => target,
    };
    // 只读取 id 与其类型/字节元信息；不读取组树、名称或 positions。
    let s = db.prepare_fixed(
        c"SELECT typeof(id),octet_length(id),id FROM connection_groups WHERE typeof(id)='text'",
    )?;
    while s.step()? {
        if matches_uuid(&s, target, utf16)? {
            s.finish()?;
            return Ok(GroupReferenceFact::Exists);
        }
    }
    s.finish()?;
    Ok(GroupReferenceFact::Absent)
}

enum Failure {
    Storage(Report),
    Write(WriteError),
}
impl From<Report> for Failure {
    fn from(report: Report) -> Self {
        Self::Storage(report)
    }
}
impl From<WriteError> for Failure {
    fn from(error: WriteError) -> Self {
        Self::Write(error)
    }
}

pub fn limits(wire: WireValidatedRequest) -> Request {
    let r = wire.limits();
    Request {
        cap: r.c_max as usize, // codec 已完成 usize/isize 与范围检查。
        field: r.field_max,
        total: r.total_max,
        tags: r.tags_max,
        connection: r.connection,
        profile: r.profile,
    }
}

/// 调用方已安装/初始化 arena；本函数结束全部 statement、transaction 和 Db，
/// 但不 shutdown、不写 footer。writer 出错仍执行清理，绝不续写或追加尾帧。
pub fn run<W: Write>(
    path: &CStr,
    wire: WireValidatedRequest,
    arena: &mut Arena,
    writer: &mut FrameWriter<W>,
) -> Result<Report, WriteError> {
    let (db, opened) = Db::open(path, arena);
    let result = (|| -> Result<Report, Failure> {
        opened?;
        let selection = preflight(&db, limits(wire))?;
        let fields = if selection.connection.is_some() {
            22 + selection.tags
        } else {
            6
        };
        let preamble = Preamble::new(
            wire,
            selection.summary.revision,
            u32::from(selection.summary.source),
            fields,
            selection.summary.bytes,
            selection.group_reference,
        )
        .map_err(WriteError::from)?;
        writer.write_preamble(preamble)?;
        #[cfg(test)]
        super::barrier("raw-preflight");
        materialize(&db, selection, limits(wire), writer)?;
        Ok(selection.summary)
    })();
    let (report, write_error) = match result {
        Ok(report) => (report, None),
        Err(Failure::Storage(report)) => (report, None),
        Err(Failure::Write(error)) => (Report::new(Outcome::InternalFailure), Some(error)),
    };
    #[cfg(test)]
    super::barrier("raw-close");
    #[cfg(test)]
    if super::fault("raw-cleanup-policy") {
        db.inject_quota(10);
    }
    let report = db.close(report);
    match write_error {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

fn row_bounds<const N: usize>(
    db: &Db,
    row: &Row,
    id: Option<&[u8]>,
    utf16: bool,
    request: Request,
    report: &mut Report,
) -> preflight::Result<[u64; N]> {
    let s = db.prepare_fixed(row.meta)?;
    if let Some(id) = id {
        s.bind_bytes(id)?;
    }
    if !s.step()? {
        return if row.missing == Outcome::StorageFailure {
            preflight::corrupt()
        } else {
            Err(Report::new(row.missing))
        };
    }
    let mut bounds = [0; N];
    for (i, bound) in bounds.iter_mut().enumerate() {
        *bound = preflight::metadata(&s, i as i32 * 2, row.nullable[i], utf16)?;
        preflight::account(request, *bound, report)?;
    }
    if s.step()? {
        return preflight::corrupt();
    }
    s.finish()?;
    report.rows += 1;
    Ok(bounds)
}

fn reference(
    db: &Db,
    sql: &CStr,
    id: Option<&[u8]>,
    nullable: bool,
    upper: u64,
) -> preflight::Result<UuidReference> {
    let s = db.prepare_fixed(sql)?;
    if let Some(id) = id {
        s.bind_bytes(id)?;
    }
    if !s.step()? {
        return preflight::corrupt();
    }
    let out = s.with_text(0, nullable, upper, |bytes| {
        Ok(match bytes {
            None => UuidReference::None,
            Some(bytes) => match uuid::Uuid::try_parse_ascii(bytes) {
                Ok(id) => UuidReference::Valid(id.into_bytes()),
                Err(_) => UuidReference::Invalid,
            },
        })
    })?;
    if s.step()? {
        return preflight::corrupt();
    }
    s.finish()?;
    Ok(out)
}

fn integers(db: &Db, id: &[u8]) -> preflight::Result<(u16, i64)> {
    let s = db.prepare_fixed(FIXED_SQL[7])?;
    s.bind_bytes(id)?;
    if !s.step()? {
        return preflight::corrupt();
    }
    // raw 层沿旧 mapping 的 u16 转换；port=0 的业务 predicate 属 bounded decoder。
    let port = u16::try_from(s.int(0)?).map_err(|_| preflight::corrupt_report())?;
    let position = s.int(1)?;
    if s.step()? {
        return preflight::corrupt();
    }
    s.finish()?;
    Ok((port, position))
}

fn preflight(db: &Db, request: Request) -> preflight::Result<Selection> {
    let utf16 = db.readonly_transaction()?;
    let s = db.prepare_fixed(FIXED_SQL[5])?;
    #[cfg(test)]
    super::barrier("raw-prepared");
    if !s.step()? || s.int(1)? != 1 {
        return preflight::corrupt();
    }
    let revision = u64::try_from(s.int(0)?).map_err(|_| preflight::corrupt_report())?;
    if s.step()? {
        return preflight::corrupt();
    }
    s.finish()?;
    #[cfg(test)]
    super::barrier("raw-snapshot");
    let mut summary = Report::new(Outcome::PreflightPassed);
    summary.revision = revision;
    summary.rows = 1;
    let s = db.prepare_fixed(FIXED_SQL[6])?;
    if !s.step()? || s.int(0)? != 1 {
        return preflight::corrupt();
    }
    if s.step()? {
        return preflight::corrupt();
    }
    s.finish()?;
    let settings_bounds = row_bounds(db, &SETTINGS, None, utf16, request, &mut summary)?;
    let default = reference(db, FIXED_SQL[12], None, false, settings_bounds[0])?;
    let connection =
        request
            .connection
            .map(|id| {
                find_key(db,
        c"SELECT typeof(id),octet_length(id),id FROM connections WHERE typeof(id)='text'",
        id, utf16, Outcome::MissingConnection)
            })
            .transpose()?;
    let mut connection_bounds = [0; 14];
    let mut referenced = UuidReference::None;
    let mut group_reference = GroupReferenceFact::NoReference;
    let mut port = 0;
    let mut position = 0;
    let mut tags = 0u32;
    if let Some(id) = &connection {
        connection_bounds = row_bounds(
            db,
            &CONNECTION,
            Some(id.as_bytes()),
            utf16,
            request,
            &mut summary,
        )?;
        referenced = reference(
            db,
            FIXED_SQL[11],
            Some(id.as_bytes()),
            true,
            connection_bounds[12],
        )?;
        (port, position) = integers(db, id.as_bytes())?;
        group_reference = group_fact(db, id, connection_bounds[1], utf16)?;
        let target = request.connection.ok_or_else(preflight::corrupt_report)?;
        let s = db.prepare_fixed(TAG_META)?;
        s.bind(&preflight::uuid_text(target))?;
        while s.step()? {
            if !matches_uuid(&s, target, utf16)? {
                continue;
            }
            if tags == request.tags {
                return Err(Report::new(Outcome::SelectedLimit));
            }
            preflight::account(
                request,
                preflight::metadata(&s, 3, false, utf16)?,
                &mut summary,
            )?;
            tags += 1;
        }
        s.finish()?;
        summary.rows += u64::from(tags);
    }
    let target = if let Some(id) = request.profile {
        summary.source = 1;
        id
    } else {
        match referenced {
            UuidReference::Valid(id) => {
                summary.source = 2;
                id
            }
            UuidReference::Invalid => return preflight::corrupt(),
            UuidReference::None => {
                summary.source = 3;
                match default {
                    UuidReference::Valid(id) => id,
                    _ => return preflight::corrupt(),
                }
            }
        }
    };
    let profile = find_key(
        db,
        c"SELECT typeof(id),octet_length(id),id FROM terminal_profiles WHERE typeof(id)='text'",
        target,
        utf16,
        Outcome::MissingProfile,
    )?;
    let profile_bounds = row_bounds(
        db,
        &PROFILE,
        Some(profile.as_bytes()),
        utf16,
        request,
        &mut summary,
    )?;
    Ok(Selection {
        connection,
        profile,
        connection_bounds,
        settings_bounds,
        profile_bounds,
        port,
        position,
        tags,
        utf16,
        summary,
        group_reference,
    })
}

fn text<W: Write>(
    s: &Statement<'_>,
    col: i32,
    tag: u16,
    ordinal: u32,
    nullable: bool,
    upper: u64,
    writer: &mut FrameWriter<W>,
) -> Result<(), Failure> {
    #[cfg(test)]
    if tag == 3 && super::fault("raw-convert-policy") {
        s.inject_quota();
    }
    s.with_text(col, nullable, upper, |bytes| {
        Ok(writer.write_field(
            FieldHeader {
                tag,
                kind: if bytes.is_some() {
                    Kind::Utf8
                } else {
                    Kind::Null
                },
                ordinal,
                len: bytes.map_or(0, |b| b.len() as u64),
            },
            bytes.unwrap_or(&[]),
        ))
    })??;
    Ok(())
}

fn materialize<W: Write>(
    db: &Db,
    selection: Selection,
    request: Request,
    writer: &mut FrameWriter<W>,
) -> Result<(), Failure> {
    if let Some(id) = &selection.connection {
        let s = db.prepare_fixed(CONNECTION.payload)?;
        s.bind_bytes(id.as_bytes())?;
        if !s.step()? {
            return Err(preflight::corrupt_report().into());
        }
        #[cfg(test)]
        super::barrier("raw-materialize");
        for (col, tag) in CONNECTION_TAGS.into_iter().enumerate() {
            text(
                &s,
                col as i32,
                tag,
                0,
                NULLABLE[col],
                selection.connection_bounds[col],
                writer,
            )?;
            if tag == 4 {
                writer.write_field(
                    FieldHeader {
                        tag: 5,
                        kind: Kind::U16,
                        ordinal: 0,
                        len: 2,
                    },
                    &selection.port.to_le_bytes(),
                )?;
            } else if tag == 13 {
                writer.write_field(
                    FieldHeader {
                        tag: 14,
                        kind: Kind::I64,
                        ordinal: 0,
                        len: 8,
                    },
                    &selection.position.to_le_bytes(),
                )?;
            }
        }
        if s.step()? {
            return Err(preflight::corrupt_report().into());
        }
        s.finish()?;
    }
    for (row, id, bounds, first_tag) in [
        (&SETTINGS, None, selection.settings_bounds, 17u16),
        (
            &PROFILE,
            Some(&selection.profile),
            selection.profile_bounds,
            20u16,
        ),
    ] {
        let s = db.prepare_fixed(row.payload)?;
        if let Some(id) = id {
            s.bind_bytes(id.as_bytes())?;
        }
        if !s.step()? {
            return Err(preflight::corrupt_report().into());
        }
        for (col, upper) in bounds.into_iter().enumerate() {
            text(
                &s,
                col as i32,
                first_tag + col as u16,
                0,
                false,
                upper,
                writer,
            )?;
        }
        if s.step()? {
            return Err(preflight::corrupt_report().into());
        }
        s.finish()?;
    }
    if selection.connection.is_some() {
        let target = request.connection.ok_or_else(preflight::corrupt_report)?;
        let s = db.prepare_fixed(TAG_PAYLOAD)?;
        s.bind(&preflight::uuid_text(target))?;
        let mut ordinal = 0u32;
        while s.step()? {
            if !matches_uuid(&s, target, selection.utf16)? {
                continue;
            }
            if ordinal == selection.tags {
                return Err(preflight::corrupt_report().into());
            }
            let upper = preflight::metadata(&s, 3, false, selection.utf16)?;
            if upper > request.field {
                return Err(preflight::corrupt_report().into());
            }
            ordinal += 1;
            text(&s, 5, 23, ordinal, false, upper, writer)?;
        }
        if ordinal != selection.tags {
            return Err(preflight::corrupt_report().into());
        }
        s.finish()?;
    }
    Ok(())
}
