use super::{
    envelope::Arena,
    protocol::{Outcome, Report, Request},
};
use rusqlite::ffi;
use std::{
    cell::Cell,
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr,
};

pub(super) type Result<T> = std::result::Result<T, Report>;
const CONNECTION: &[(&str, bool)] = &[
    ("id", false),
    ("group_id", true),
    ("name", false),
    ("host", false),
    ("username", false),
    ("transport", false),
    ("authentication", false),
    ("credential_ref", true),
    ("identity_file", true),
    ("host_key_policy", false),
    ("remote_command", true),
    ("note", false),
    ("terminal_profile_id", true),
    ("terminal_overrides_json", false),
];
const SETTINGS: &[(&str, bool)] = &[
    ("default_terminal_profile", false),
    ("color_scheme", false),
    ("key_bindings_json", false),
];
const PROFILE: &[(&str, bool)] = &[("id", false), ("name", false), ("settings_json", false)];
const TAG: &[(&str, bool)] = &[("tag", false)];
struct RowSpec {
    table: &'static str,
    predicate: &'static str,
    columns: &'static [(&'static str, bool)],
    missing: Outcome,
    capture: usize,
}
const CONNECTION_ROW: RowSpec = RowSpec {
    table: "connections",
    predicate: "id=?1",
    columns: CONNECTION,
    missing: Outcome::MissingConnection,
    capture: 12,
};
const SETTINGS_ROW: RowSpec = RowSpec {
    table: "app_settings",
    predicate: "singleton=1",
    columns: SETTINGS,
    missing: Outcome::StorageFailure,
    capture: 0,
};
const PROFILE_ROW: RowSpec = RowSpec {
    table: "terminal_profiles",
    predicate: "id=?1",
    columns: PROFILE,
    missing: Outcome::MissingProfile,
    capture: 0,
};
struct Selection<'a> {
    db: &'a Db,
    request: Request,
    utf16: bool,
    materialize: bool,
}

pub(super) struct Db {
    pub(super) raw: *mut ffi::sqlite3,
    // 来自 run 的独占参数；Db 存活时仅经此根指针访问 Arena，外部 owner 不再
    // 重借用它。该指针不发布到 TLS，也不传入任何 SQL callback userdata。
    arena: *mut Arena,
    cleanup_failed: Cell<bool>,
    reprepares: Cell<u64>,
    cleaning: Cell<bool>,
    cleanup_primary: Cell<Option<Report>>,
}
impl Db {
    pub(super) fn sqlite<T>(&self, call: impl FnOnce() -> T) -> T {
        // 每次从 Db 的有效根借用派生新的 FFI scope，返回后才做策略/状态处理。
        unsafe { (*self.arena).with_sqlite(call) }
    }
    pub(super) fn begin(&self, phase: u8) {
        let phase = if self.cleaning.get() && (5..=8).contains(&phase) {
            10
        } else {
            phase
        };
        unsafe {
            (*self.arena).begin(phase);
        }
    }
    fn error(&self, code: c_int) -> Report {
        unsafe { (*self.arena).failure(code) }
    }
    fn fixed_sql_error(&self, code: c_int) -> Report {
        let mut report = self.error(code);
        // 固定 SQL 的必要表缺失或异常 view，在首次 prepare 和 step 自动重编译
        // 中语义相同。其余码仍走原来的 Busy/NOMEM 因果及 I/O 映射。
        if matches!(code, ffi::SQLITE_AUTH | ffi::SQLITE_ERROR) {
            report.code = 2;
        }
        self.remember_cleanup(report);
        report
    }
    fn remember_cleanup(&self, report: Report) {
        if self.cleaning.get() && self.cleanup_primary.get().is_none() {
            self.cleanup_primary.set(Some(report));
        }
    }
    pub(super) fn check(&self, rc: c_int) -> Result<()> {
        let result = unsafe { (*self.arena).finish(rc) };
        if let Err(report) = result {
            self.remember_cleanup(report);
        }
        // 已失效请求仍须真正执行 rollback/finalize/close；这里只允许必要
        // cleanup 在真实成功码上继续，外层 cleanup 出口仍会按首证拒绝暂成功。
        if self.cleaning.get() && matches!(rc, ffi::SQLITE_OK | ffi::SQLITE_ROW | ffi::SQLITE_DONE)
        {
            return Ok(());
        }
        result
    }
    fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        let sql = CString::new(sql).map_err(|_| Report::new(Outcome::InternalFailure))?;
        self.prepare_fixed(&sql)
    }
    pub(super) fn prepare_fixed(&self, sql: &CStr) -> Result<Statement<'_>> {
        let mut raw = ptr::null_mut();
        self.begin(5);
        #[cfg(test)]
        if !self.cleaning.get() && super::fault("prepare-policy") {
            unsafe {
                (*self.arena).inject_quota();
            }
        }
        let rc = self.sqlite(|| unsafe {
            ffi::sqlite3_prepare_v2(self.raw, sql.as_ptr(), -1, &mut raw, ptr::null_mut())
        });
        let statement = Statement { raw, db: self };
        #[cfg(test)]
        if !self.cleaning.get() && super::fault("prepare-policy") {
            assert_eq!(rc, ffi::SQLITE_OK);
            assert!(
                !raw.is_null(),
                "真实 prepare 成功后仍由策略拒绝，局部 owner 须 finalize"
            );
        }
        if rc != ffi::SQLITE_OK {
            return Err(self.fixed_sql_error(rc));
        }
        self.check(rc)?;
        Ok(statement)
    }
    fn exec(&self, sql: &str) -> Result<()> {
        let s = self.prepare(sql)?;
        if s.step()? {
            return corrupt();
        }
        s.finish()
    }

    pub(super) fn exec_fixed(&self, sql: &CStr) -> Result<()> {
        let s = self.prepare_fixed(sql)?;
        if s.step()? {
            return corrupt();
        }
        s.finish()
    }

    #[cfg(test)]
    pub(super) fn inject_quota(&self, phase: u8) {
        self.begin(phase);
        unsafe { (*self.arena).inject_quota() };
    }

    pub(super) fn open(path: &CStr, arena: &mut Arena) -> (Self, Result<()>) {
        let mut raw = ptr::null_mut();
        arena.begin(4);
        let rc = arena.with_sqlite(|| unsafe {
            ffi::sqlite3_open_v2(
                path.as_ptr(),
                &mut raw,
                ffi::SQLITE_OPEN_READONLY
                    | ffi::SQLITE_OPEN_PRIVATECACHE
                    | ffi::SQLITE_OPEN_NOMUTEX,
                ptr::null(),
            )
        });
        let db = Self {
            raw,
            arena,
            cleanup_failed: Cell::new(false),
            reprepares: Cell::new(0),
            cleaning: Cell::new(false),
            cleanup_primary: Cell::new(None),
        };
        let result = db.check(rc);
        (db, result)
    }

    /// 固定 SQL 的 v2 路径；authorizer 一直保留到 rollback/close，覆盖自动重编译。
    pub(super) fn readonly_transaction(&self) -> Result<bool> {
        if self.sqlite(|| unsafe { ffi::sqlite3_db_readonly(self.raw, c"main".as_ptr()) }) != 1 {
            return Err(Report::new(Outcome::UnsupportedEnvelope));
        }
        self.begin(4);
        self.check(self.sqlite(|| unsafe { ffi::sqlite3_busy_timeout(self.raw, 100) }))?;
        self.exec_fixed(c"PRAGMA query_only=ON")?;
        let s = self.prepare_fixed(c"PRAGMA mmap_size=0")?;
        if !s.step()? || s.int(0)? != 0 {
            return Err(Report::new(Outcome::UnsupportedEnvelope));
        }
        if s.step()? {
            return corrupt();
        }
        s.finish()?;
        self.begin(4);
        self.check(self.sqlite(|| unsafe { ffi::sqlite3_enable_load_extension(self.raw, 0) }))?;
        let s = self.prepare_fixed(c"PRAGMA encoding")?;
        if !s.step()? {
            return corrupt();
        }
        let utf16 = s.with_text(0, false, 8, |bytes| match bytes {
            Some(b"UTF-8") => Ok(false),
            Some(b"UTF-16le" | b"UTF-16be") => Ok(true),
            _ => corrupt(),
        })?;
        if s.step()? {
            return corrupt();
        }
        s.finish()?;
        self.begin(4);
        self.check(self.sqlite(|| unsafe {
            ffi::sqlite3_set_authorizer(self.raw, Some(authorize_v2), ptr::null_mut())
        }))?;
        self.exec_fixed(c"BEGIN")?;
        Ok(utf16)
    }

    /// 最终 footer 之前真实结束事务与连接。这里只重借 Db 根，不长期发布 ACTIVE。
    pub(super) fn close(self, mut report: Report) -> Report {
        if !self.raw.is_null() {
            if self.sqlite(|| unsafe { ffi::sqlite3_db_readonly(self.raw, c"main".as_ptr()) }) == 1
            {
                report.flags |= 1;
            }
            if self.sqlite(|| unsafe { ffi::sqlite3_total_changes64(self.raw) }) == 0 {
                report.flags |= 2;
            }
            self.cleaning.set(true);
            self.begin(10);
            if self.sqlite(|| unsafe { ffi::sqlite3_get_autocommit(self.raw) }) == 0 {
                if let Err(cleanup) = self.exec_fixed(c"ROLLBACK") {
                    self.cleanup_failed.set(true);
                    if report.outcome == Outcome::PreflightPassed {
                        let flags = report.flags;
                        report = self.cleanup_primary.get().unwrap_or(cleanup);
                        report.flags |= flags;
                    }
                }
            }
            if report.outcome == Outcome::PreflightPassed {
                if let Some(cleanup) = self.cleanup_primary.get() {
                    let flags = report.flags;
                    report = cleanup;
                    report.flags |= flags;
                }
            }
            self.begin(11);
            let rc = self.sqlite(|| unsafe { ffi::sqlite3_close(self.raw) });
            if rc != ffi::SQLITE_OK {
                self.cleanup_failed.set(true);
            }
            if let Err(cleanup) = unsafe { (*self.arena).finish(rc) } {
                if report.outcome == Outcome::PreflightPassed {
                    let flags = report.flags;
                    report = cleanup;
                    report.flags |= flags;
                }
            }
        }
        if self.cleanup_failed.get() {
            report.flags |= 4;
        }
        report.reprepare = self.reprepares.get();
        report
    }
}
pub(super) struct Statement<'a> {
    raw: *mut ffi::sqlite3_stmt,
    db: &'a Db,
}
impl Statement<'_> {
    #[cfg(test)]
    pub(super) fn inject_quota(&self) {
        self.db.inject_quota(8);
    }
    pub(super) fn bind(&self, id: &[u8; 36]) -> Result<()> {
        self.bind_bytes(id)
    }
    pub(super) fn bind_bytes(&self, id: &[u8]) -> Result<()> {
        let len = c_int::try_from(id.len()).map_err(|_| Report::new(Outcome::InternalFailure))?;
        self.db.begin(6);
        #[cfg(test)]
        if super::fault("bind-policy") {
            unsafe {
                (*self.db.arena).inject_quota();
            }
        }
        let rc = self.db.sqlite(|| unsafe {
            ffi::sqlite3_bind_text(
                self.raw,
                1,
                id.as_ptr().cast(),
                len,
                ffi::SQLITE_TRANSIENT(),
            )
        });
        #[cfg(test)]
        if super::fault("bind-policy") {
            assert_eq!(rc, ffi::SQLITE_OK);
        }
        self.db.check(rc)
    }
    pub(super) fn step(&self) -> Result<bool> {
        self.db.begin(7);
        #[cfg(test)]
        let policy_step = !self.db.cleaning.get()
            && ((super::fault("step-row-policy")
                && self
                    .db
                    .sqlite(|| unsafe { ffi::sqlite3_column_count(self.raw) })
                    > 0)
                || (super::fault("step-done-policy")
                    && self
                        .db
                        .sqlite(|| unsafe { ffi::sqlite3_column_count(self.raw) })
                        == 0)
                || (super::fault("step-error-priority")
                    && self
                        .db
                        .sqlite(|| unsafe { ffi::sqlite3_column_count(self.raw) })
                        == 2));
        #[cfg(test)]
        if policy_step {
            unsafe {
                (*self.db.arena).inject_quota();
            }
        }
        let rc = self.db.sqlite(|| unsafe { ffi::sqlite3_step(self.raw) });
        #[cfg(test)]
        if policy_step {
            if super::fault("step-error-priority") {
                assert!(matches!(
                    rc,
                    ffi::SQLITE_ERROR | ffi::SQLITE_AUTH | ffi::SQLITE_BUSY | ffi::SQLITE_LOCKED
                ));
                assert_ne!(unsafe { (*self.db.arena).first_quota.reason }, 0);
            } else {
                assert_eq!(
                    rc,
                    if super::fault("step-row-policy") {
                        ffi::SQLITE_ROW
                    } else {
                        ffi::SQLITE_DONE
                    }
                );
            }
        }
        match rc {
            ffi::SQLITE_ROW | ffi::SQLITE_DONE => {
                self.db.check(rc)?;
                Ok(rc == ffi::SQLITE_ROW)
            }
            _ => Err(self.db.fixed_sql_error(rc)),
        }
    }
    pub(super) fn int(&self, col: c_int) -> Result<i64> {
        if self
            .db
            .sqlite(|| unsafe { ffi::sqlite3_column_type(self.raw, col) })
            != ffi::SQLITE_INTEGER
        {
            return corrupt();
        }
        self.db.check(ffi::SQLITE_OK)?;
        let value = self
            .db
            .sqlite(|| unsafe { ffi::sqlite3_column_int64(self.raw, col) });
        self.db.check(ffi::SQLITE_OK)?;
        Ok(value)
    }
    pub(super) fn text(
        &self,
        col: c_int,
        nullable: bool,
        upper: u64,
        capture: Option<&mut [u8; 36]>,
    ) -> Result<()> {
        self.with_text(col, nullable, upper, |bytes| {
            if let (Some(bytes), Some(out)) = (bytes, capture) {
                if bytes.len() != 36 || uuid::Uuid::try_parse_ascii(bytes).is_err() {
                    return corrupt();
                }
                out.copy_from_slice(bytes);
            }
            Ok(())
        })
    }
    pub(super) fn with_text<T>(
        &self,
        col: c_int,
        nullable: bool,
        upper: u64,
        consume: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        self.with_text_bytes(col, nullable, upper, |bytes| {
            if bytes.is_some_and(|bytes| std::str::from_utf8(bytes).is_err()) {
                return corrupt();
            }
            consume(bytes)
        })
    }
    /// UUID 候选只按 ASCII parser 比较；不把无关 id 的非 UTF-8 变成全目录校验。
    /// 转换、长度与请求策略仍在同一接缝完成，consume 之前绝不绕过 quota 收口。
    pub(super) fn with_text_bytes<T>(
        &self,
        col: c_int,
        nullable: bool,
        upper: u64,
        consume: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        let kind = self
            .db
            .sqlite(|| unsafe { ffi::sqlite3_column_type(self.raw, col) });
        if kind == ffi::SQLITE_NULL && nullable {
            self.db.check(ffi::SQLITE_OK)?;
            return consume(None);
        }
        if kind != ffi::SQLITE_TEXT {
            return corrupt();
        }
        self.db.begin(8);
        // column_text 可以分配。可疑指针后先取 errcode，绝不先 bytes/slice。
        let (p, text_rc) = self.db.sqlite(|| unsafe {
            let p = ffi::sqlite3_column_text(self.raw, col);
            // 在同一个借用 scope 中立即读取可疑指针的错误；中间没有其他 SQLite API。
            let rc = if p.is_null() {
                ffi::sqlite3_errcode(self.db.raw)
            } else {
                ffi::SQLITE_OK
            };
            (p, rc)
        });
        if p.is_null() {
            let rc = text_rc;
            if rc != ffi::SQLITE_OK && rc != ffi::SQLITE_ROW && rc != ffi::SQLITE_DONE {
                return Err(self.db.error(rc));
            }
        }
        #[cfg(test)]
        if (super::fault("convert-recovered") || super::fault("raw-convert-policy"))
            && unsafe { (*self.db.arena).first_quota.reason } != 0
        {
            assert!(!p.is_null(), "quota 后实际转换恢复成功，但请求仍须拒绝");
        }
        self.db.check(ffi::SQLITE_OK)?;
        self.db.begin(8);
        #[cfg(test)]
        if super::fault("column-bytes-policy") {
            unsafe {
                (*self.db.arena).inject_quota();
            }
        }
        let (n, rc) = self.db.sqlite(|| unsafe {
            let n = ffi::sqlite3_column_bytes(self.raw, col);
            (n, ffi::sqlite3_errcode(self.db.raw))
        });
        if !matches!(rc, ffi::SQLITE_OK | ffi::SQLITE_ROW | ffi::SQLITE_DONE) {
            return Err(self.db.error(rc));
        }
        self.db.check(ffi::SQLITE_OK)?;
        #[cfg(test)]
        assert_eq!(
            unsafe { (*self.db.arena).first_quota.reason },
            0,
            "策略拒绝必须早于 slice/consume"
        );
        if n < 0 || (p.is_null() && n != 0) || n as u64 > upper {
            return corrupt();
        }
        let bytes = if n == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p, n as usize) }
        };
        consume(Some(bytes))
    }
    pub(super) fn finish(mut self) -> Result<()> {
        self.db.reprepares.set(
            self.db.reprepares.get()
                + self.db.sqlite(|| unsafe {
                    ffi::sqlite3_stmt_status(self.raw, ffi::SQLITE_STMTSTATUS_REPREPARE, 0)
                }) as u64,
        );
        self.db.begin(9);
        let rc = self
            .db
            .sqlite(|| unsafe { ffi::sqlite3_finalize(self.raw) });
        self.raw = ptr::null_mut();
        self.db.check(rc)
    }
}
impl Drop for Statement<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            self.db.reprepares.set(
                self.db.reprepares.get()
                    + self.db.sqlite(|| unsafe {
                        ffi::sqlite3_stmt_status(self.raw, ffi::SQLITE_STMTSTATUS_REPREPARE, 0)
                    }) as u64,
            );
            self.db.begin(9);
            let rc = self
                .db
                .sqlite(|| unsafe { ffi::sqlite3_finalize(self.raw) });
            let _ = self.db.check(rc);
            if rc != ffi::SQLITE_OK {
                self.db.cleanup_failed.set(true);
            }
        }
    }
}
pub(super) fn corrupt<T>() -> Result<T> {
    Err(corrupt_report())
}
pub(super) fn corrupt_report() -> Report {
    let mut r = Report::new(Outcome::StorageFailure);
    r.code = 2;
    r
}

unsafe extern "C" fn authorize(
    _: *mut c_void,
    action: c_int,
    first: *const c_char,
    second: *const c_char,
    _: *const c_char,
    origin: *const c_char,
) -> c_int {
    if !origin.is_null() {
        return ffi::SQLITE_DENY;
    }
    let bytes = |p: *const c_char| {
        if p.is_null() {
            &[][..]
        } else {
            unsafe { CStr::from_ptr(p).to_bytes() }
        }
    };
    let allowed = match action {
        ffi::SQLITE_SELECT | ffi::SQLITE_TRANSACTION => true,
        ffi::SQLITE_READ => matches!(
            bytes(first),
            b"connections"
                | b"connection_tags"
                | b"terminal_profiles"
                | b"app_settings"
                | b"configuration_revision"
                | b"sqlite_master"
        ),
        ffi::SQLITE_FUNCTION => matches!(bytes(second), b"typeof" | b"octet_length"),
        _ => false,
    };
    if allowed {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_DENY
    }
}

unsafe extern "C" fn authorize_v2(
    data: *mut c_void,
    action: c_int,
    first: *const c_char,
    second: *const c_char,
    database: *const c_char,
    origin: *const c_char,
) -> c_int {
    let legacy = unsafe { authorize(data, action, first, second, database, origin) };
    if legacy == ffi::SQLITE_OK || !origin.is_null() {
        return legacy;
    }
    let allowed = match action {
        ffi::SQLITE_READ if !first.is_null() && !second.is_null() => unsafe {
            CStr::from_ptr(first).to_bytes() == b"connection_groups"
                && CStr::from_ptr(second).to_bytes() == b"id"
        },
        ffi::SQLITE_FUNCTION if !second.is_null() => unsafe {
            matches!(CStr::from_ptr(second).to_bytes(), b"lower" | b"replace")
        },
        _ => false,
    };
    if allowed {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_DENY
    }
}

pub(super) fn uuid_text(id: [u8; 16]) -> [u8; 36] {
    let mut out = [0; 36];
    uuid::Uuid::from_bytes(id)
        .hyphenated()
        .encode_lower(&mut out);
    out
}

pub fn run(path: &CStr, request: Request, arena: &mut Arena) -> Report {
    let mut raw = ptr::null_mut();
    #[cfg(test)]
    let held = if super::fault("open") {
        arena.occupy()
    } else {
        ptr::null_mut()
    };
    arena.begin(4);
    let rc = arena.with_sqlite(|| unsafe {
        ffi::sqlite3_open_v2(
            path.as_ptr(),
            &mut raw,
            ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_PRIVATECACHE | ffi::SQLITE_OPEN_NOMUTEX,
            ptr::null(),
        )
    });
    let db = Db {
        raw,
        arena,
        cleanup_failed: Cell::new(false),
        reprepares: Cell::new(0),
        cleaning: Cell::new(false),
        cleanup_primary: Cell::new(None),
    };
    let open_error = db.check(rc).err();
    #[cfg(test)]
    unsafe {
        (*db.arena).release(held);
    }
    let result = if let Some(error) = open_error {
        Err(error)
    } else {
        selected(&db, request)
    };
    let mut report = result.unwrap_or_else(|r| r);
    if !raw.is_null() {
        if db.sqlite(|| unsafe { ffi::sqlite3_db_readonly(raw, c"main".as_ptr()) }) == 1 {
            report.flags |= 1;
        }
        if db.sqlite(|| unsafe { ffi::sqlite3_total_changes64(raw) }) == 0 {
            report.flags |= 2;
        }
        #[cfg(test)]
        super::barrier("close");
        #[cfg(test)]
        if super::fault("cleanup") && report.outcome == Outcome::StorageFailure && report.code == 2
        {
            assert_eq!(
                unsafe { (*db.arena).first_quota.reason },
                0,
                "先确认 Corrupt，再注入 cleanup quota"
            );
        }
        db.cleaning.set(true);
        db.begin(10);
        #[cfg(test)]
        let held = if super::fault("cleanup") {
            unsafe { (*db.arena).occupy() }
        } else {
            ptr::null_mut()
        };
        #[cfg(test)]
        if super::fault("cleanup-unknown") {
            unsafe {
                (*db.arena).unclassified = true;
            }
        }
        // 即使主操作失败也结束事务；清理绝不替换主错误。
        if db.sqlite(|| unsafe { ffi::sqlite3_get_autocommit(raw) }) == 0 {
            if let Err(cleanup) = db.exec("ROLLBACK") {
                db.cleanup_failed.set(true);
                if report.outcome == Outcome::PreflightPassed {
                    let flags = report.flags;
                    report = db.cleanup_primary.get().unwrap_or(cleanup);
                    report.flags |= flags;
                }
            }
        }
        if report.outcome == Outcome::PreflightPassed {
            if let Some(cleanup) = db.cleanup_primary.get() {
                let flags = report.flags;
                report = cleanup;
                report.flags |= flags;
            }
        }
        #[cfg(test)]
        unsafe {
            (*db.arena).unclassified = false;
            (*db.arena).release(held);
        }
        db.begin(11);
        let close = db.sqlite(|| unsafe { ffi::sqlite3_close(raw) });
        if close != ffi::SQLITE_OK {
            db.cleanup_failed.set(true);
        }
        if let Err(cleanup) = unsafe { (*db.arena).finish(close) } {
            if report.outcome == Outcome::PreflightPassed {
                let flags = report.flags;
                report = cleanup;
                report.flags |= flags;
            }
        }
        #[cfg(test)]
        if super::fault("cleanup") && report.outcome == Outcome::StorageFailure && report.code == 2
        {
            assert_ne!(
                unsafe { (*db.arena).first_quota.reason },
                0,
                "必须实际观察到 Corrupt 之后的 cleanup quota"
            );
        }
    }
    if db.cleanup_failed.get() {
        report.flags |= 4;
    }
    report.reprepare = db.reprepares.get();
    report
}

fn selected(db: &Db, request: Request) -> Result<Report> {
    if db.sqlite(|| unsafe { ffi::sqlite3_db_readonly(db.raw, c"main".as_ptr()) }) != 1 {
        return Err(Report::new(Outcome::UnsupportedEnvelope));
    }
    db.begin(4);
    db.check(db.sqlite(|| unsafe { ffi::sqlite3_busy_timeout(db.raw, 100) }))?;
    db.exec("PRAGMA query_only=ON")?;
    {
        let s = db.prepare("PRAGMA mmap_size=0")?;
        if !s.step()? || s.int(0)? != 0 {
            return Err(Report::new(Outcome::UnsupportedEnvelope));
        }
        if s.step()? {
            return corrupt();
        }
        s.finish()?;
    }
    db.begin(4);
    db.check(db.sqlite(|| unsafe { ffi::sqlite3_enable_load_extension(db.raw, 0) }))?;
    let utf16 = {
        let s = db.prepare("PRAGMA encoding")?;
        if !s.step()? {
            return corrupt();
        }
        let utf16 = s.with_text(0, false, 8, |bytes| match bytes {
            Some(b"UTF-8") => Ok(false),
            Some(b"UTF-16le" | b"UTF-16be") => Ok(true),
            _ => corrupt(),
        })?;
        s.finish()?;
        utf16
    };
    db.begin(4);
    db.check(db.sqlite(|| unsafe {
        ffi::sqlite3_set_authorizer(db.raw, Some(authorize), ptr::null_mut())
    }))?;
    db.exec("BEGIN")?;
    let mut report = Report::new(Outcome::PreflightPassed);
    let revision =
        db.prepare("SELECT revision,singleton FROM configuration_revision WHERE singleton=1")?;
    #[cfg(test)]
    super::barrier("prepared");
    if !revision.step()? {
        return corrupt();
    }
    if revision.int(1)? != 1 {
        return corrupt();
    }
    report.revision = u64::try_from(revision.int(0)?).map_err(|_| {
        let mut r = Report::new(Outcome::StorageFailure);
        r.code = 2;
        r
    })?;
    if revision.step()? {
        return corrupt();
    }
    revision.finish()?;
    report.rows += 1;
    #[cfg(test)]
    super::barrier("snapshot");
    // 第一遍证明整个 selected 的累计上界。为解析 profile 优先级，仅提前借用
    // 已通过字段检查的 UUID 引用（固定 36 字节）；不 materialize 其余列。
    select_rows(
        &Selection {
            db,
            request,
            utf16,
            materialize: false,
        },
        &mut report,
    )?;
    #[cfg(test)]
    super::barrier("preflight");
    let mut actual = Report::new(Outcome::PreflightPassed);
    actual.rows = 1;
    actual.revision = report.revision;
    select_rows(
        &Selection {
            db,
            request,
            utf16,
            materialize: true,
        },
        &mut actual,
    )?;
    if actual.bytes != report.bytes || actual.rows != report.rows || actual.source != report.source
    {
        return corrupt();
    }
    Ok(report)
}

fn select_rows(selection: &Selection<'_>, report: &mut Report) -> Result<()> {
    let Selection { db, request, .. } = selection;
    let singleton = db.prepare("SELECT singleton FROM app_settings WHERE singleton=1")?;
    if !singleton.step()? || singleton.int(0)? != 1 {
        return corrupt();
    }
    singleton.finish()?;
    let mut default = [0; 36];
    row(selection, SETTINGS_ROW, None, Some(&mut default), report)?;
    let mut referenced = [0; 36];
    if let Some(id) = request.connection {
        let id = uuid_text(id);
        row(
            selection,
            CONNECTION_ROW,
            Some(&id),
            Some(&mut referenced),
            report,
        )?;
        let s = db.prepare("SELECT port,position FROM connections WHERE id=?1")?;
        s.bind(&id)?;
        if !s.step()? || !(1..=65535).contains(&s.int(0)?) {
            return corrupt();
        }
        s.int(1)?;
        s.finish()?;
        tags(selection, &id, report)?;
    }
    let profile = if let Some(id) = request.profile {
        report.source = 1;
        uuid_text(id)
    } else if referenced != [0; 36] {
        report.source = 2;
        referenced
    } else {
        report.source = 3;
        default
    };
    row(selection, PROFILE_ROW, Some(&profile), None, report)?;
    Ok(())
}

pub(super) fn upper(n: i64, utf16: bool) -> Result<u64> {
    let n = u64::try_from(n).map_err(|_| {
        let mut r = Report::new(Outcome::StorageFailure);
        r.code = 2;
        r
    })?;
    if utf16 {
        n.checked_add(1)
            .and_then(|v| (v / 2).checked_mul(3))
            .ok_or(Report::new(Outcome::SelectedLimit))
    } else {
        Ok(n)
    }
}
pub(super) fn account(request: Request, n: u64, report: &mut Report) -> Result<()> {
    if n > request.field {
        return Err(Report::new(Outcome::SelectedLimit));
    }
    report.bytes = report
        .bytes
        .checked_add(n)
        .filter(|v| *v <= request.total)
        .ok_or(Report::new(Outcome::SelectedLimit))?;
    Ok(())
}
// SQL 只由以下固定内部列集合生成，协议无法传入 SQL／表名。
fn row(
    selection: &Selection<'_>,
    spec: RowSpec,
    id: Option<&[u8; 36]>,
    mut capture: Option<&mut [u8; 36]>,
    report: &mut Report,
) -> Result<()> {
    let Selection {
        db,
        request,
        utf16,
        materialize,
    } = *selection;
    let RowSpec {
        table,
        predicate,
        columns,
        missing,
        capture: capture_index,
    } = spec;
    #[cfg(test)]
    let table = if super::fault("overflow") && table == "connections" {
        "connections NOT INDEXED"
    } else {
        table
    };
    let meta = columns
        .iter()
        .map(|(c, _)| format!("typeof({c}),octet_length({c})"))
        .collect::<Vec<_>>()
        .join(",");
    let s = db.prepare(&format!("SELECT {meta} FROM {table} WHERE {predicate}"))?;
    if let Some(id) = id {
        s.bind(id)?;
    }
    if !s.step()? {
        if missing == Outcome::StorageFailure {
            return corrupt();
        }
        return Err(Report::new(missing));
    }
    let mut bounds = [0u64; 14];
    for (i, (_, nullable)) in columns.iter().enumerate() {
        bounds[i] = metadata(&s, i as c_int * 2, *nullable, utf16)?;
        account(request, bounds[i], report)?;
    }
    if s.step()? {
        return corrupt();
    }
    s.finish()?;
    if !materialize {
        if let Some(out) = capture {
            let s = db.prepare(&format!(
                "SELECT {} FROM {table} WHERE {predicate}",
                columns[capture_index].0
            ))?;
            if let Some(id) = id {
                s.bind(id)?;
            }
            if !s.step()? {
                return corrupt();
            }
            s.text(
                0,
                columns[capture_index].1,
                bounds[capture_index],
                Some(out),
            )?;
            s.finish()?;
        }
        report.rows += 1;
        return Ok(());
    }
    let projection = columns
        .iter()
        .map(|(c, _)| *c)
        .collect::<Vec<_>>()
        .join(",");
    let s = db.prepare(&format!(
        "SELECT {projection} FROM {table} WHERE {predicate}"
    ))?;
    if let Some(id) = id {
        s.bind(id)?;
    }
    if !s.step()? {
        return corrupt();
    }
    #[cfg(test)]
    super::barrier("materialize");
    #[cfg(test)]
    let held = if super::fault("convert") && table == "connections" {
        unsafe { (*db.arena).occupy() }
    } else {
        ptr::null_mut()
    };
    #[cfg(test)]
    if super::fault("unknown-convert") && table == "connections" {
        unsafe {
            (*db.arena).unclassified = true;
        }
    }
    #[cfg(test)]
    if super::fault("convert-recovered") && table == "connections" {
        unsafe {
            (*db.arena).arm_retry_release();
        }
    }
    let materialized = (|| {
        for (i, (_, nullable)) in columns.iter().enumerate() {
            let out = capture.as_mut().and_then(|out| {
                if capture_index == i {
                    Some(&mut **out)
                } else {
                    None
                }
            });
            s.text(i as c_int, *nullable, bounds[i], out)?;
        }
        Ok(())
    })();
    #[cfg(test)]
    unsafe {
        (*db.arena).unclassified = false;
        (*db.arena).disarm_retry_release();
        (*db.arena).release(held);
    }
    materialized?;
    if s.step()? {
        return corrupt();
    }
    s.finish()?;
    report.rows += 1;
    Ok(())
}
pub(super) fn metadata(s: &Statement<'_>, col: c_int, nullable: bool, utf16: bool) -> Result<u64> {
    let is_text = s.with_text(col, false, 4, |kind| match kind {
        Some(b"null") if nullable => Ok(false),
        Some(b"text") => Ok(true),
        _ => corrupt(),
    })?;
    if is_text {
        upper(s.int(col + 1)?, utf16)
    } else {
        Ok(0)
    }
}
fn tags(selection: &Selection<'_>, id: &[u8; 36], report: &mut Report) -> Result<()> {
    let Selection {
        db,
        request,
        utf16,
        materialize,
    } = *selection;
    let meta = db.prepare("SELECT typeof(tag),octet_length(tag) FROM connection_tags WHERE connection_id=?1 ORDER BY tag")?;
    meta.bind(id)?;
    let mut count = 0;
    while meta.step()? {
        if count == request.tags {
            return Err(Report::new(Outcome::SelectedLimit));
        }
        account(request, metadata(&meta, 0, TAG[0].1, utf16)?, report)?;
        count += 1;
    }
    meta.finish()?;
    if !materialize {
        report.rows += u64::from(count);
        return Ok(());
    }
    let s = db.prepare("SELECT typeof(tag),octet_length(tag),tag FROM connection_tags WHERE connection_id=?1 ORDER BY tag")?;
    s.bind(id)?;
    let mut actual = 0;
    while s.step()? {
        let bound = metadata(&s, 0, false, utf16)?;
        s.text(2, false, bound, None)?;
        actual += 1;
        if actual > count {
            return corrupt();
        }
    }
    if actual != count {
        return corrupt();
    }
    s.finish()?;
    report.rows += u64::from(count);
    Ok(())
}
