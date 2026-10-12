//! 正常 v2 入口：父预约 bootstrap，读 request 后核验 H，再构造 path 与 C backing。
//! 构建记录只能由父持有的受信 build recipe 嵌入；不读取运行时环境、不自行签证。
//! FrameWriter、证书、Report、Diagnostics 均是栈值；无新增堆分配类。

use super::{
    envelope::Arena,
    producer,
    production_protocol::{self as wire, FrameWriter, WireValidatedRequest, WriteError},
    protocol::{Outcome, Report},
    rust_budget::{
        self, FixedLimits, HelperLaunchShape, HelperRustCertificate, SqlRoute,
        source::BuildEvidence,
    },
};
use rusqlite::ffi;
use std::{ffi::OsStr, io::Write};

/// 这些值必须来自实际产物的父构建记录，而非 W1 常量或请求提供的身份。
/// 未嵌入记录的候选仍可编译和运行 v1；不能签发 normal LoadedRaw。
pub fn embedded_build_evidence() -> Option<BuildEvidence<'static>> {
    Some(BuildEvidence {
        compiler_commit: option_env!("RSHELL_HELPER_BUILD_COMPILER_COMMIT")?,
        release: option_env!("RSHELL_HELPER_BUILD_COMPILER_RELEASE")?,
        target: option_env!("RSHELL_HELPER_BUILD_TARGET")?,
        sqlite_features: option_env!("RSHELL_HELPER_BUILD_RESOLVED_FEATURES")?,
        normal_helper_cfg: option_env!("RSHELL_HELPER_BUILD_CFG")? == "normal",
        inherited_environment: option_env!("RSHELL_HELPER_BUILD_ENVIRONMENT")? == "inherited",
        synchronous_pipe_handles: option_env!("RSHELL_HELPER_BUILD_STDIO")? == "synchronous-pipes",
    })
}

pub fn invalid_request(writer: &mut impl Write) -> Result<(), WriteError> {
    let footer = wire::Footer {
        outcome: wire::Outcome::InvalidRequest,
        flags: 0,
        nonce: [0; 16],
        revision: 0,
        source: 0,
        stats: wire::Statistics::default(),
        diagnostics: wire::Diagnostics::default(),
    };
    writer
        .write_all(&footer.encode()?)
        .map_err(|e| WriteError::Io(e.kind()))?;
    writer.flush().map_err(|e| WriteError::Io(e.kind()))
}

fn reject<W: Write>(
    writer: &mut FrameWriter<W>,
    reason: rust_budget::Reject,
    requested: u64,
    available: u64,
) -> Result<(), WriteError> {
    writer.finish(
        reason.outcome(),
        0,
        wire::Diagnostics {
            code: reason as u16,
            phase: 1,
            requested,
            available,
            ..wire::Diagnostics::default()
        },
    )
}

/// 私有整合接口。trusted_build 由父持有的产物记录提供；没有自填常量旁路。
/// 父已在 spawn 前按相同 launch/limits/certificate 预约 H+C；helper 不持父账本。
pub fn run<W: Write>(
    executable: &OsStr,
    database: &OsStr,
    request: WireValidatedRequest,
    trusted_build: Option<BuildEvidence<'_>>,
    writer: W,
) -> Result<(), WriteError> {
    let mut writer = FrameWriter::new(writer, request);
    let Some(evidence) = trusted_build else {
        return reject(&mut writer, rust_budget::Reject::SourceMismatch, 0, 0);
    };
    let build = match evidence.verify() {
        Ok(build) => build,
        Err(reason) => return reject(&mut writer, reason, 0, 0),
    };
    let launch = match HelperLaunchShape::from_paths(executable, database) {
        Ok(launch) => launch,
        Err(reason) => return reject(&mut writer, reason, 0, 0),
    };
    let r = request.limits();
    let certificate = match HelperRustCertificate::calculate(
        build,
        launch,
        FixedLimits {
            c_max: r.c_max,
            field_max: r.field_max,
            total_max: r.total_max,
            tags_max: r.tags_max,
        },
        SqlRoute::FixedCStr,
    ) {
        Ok(certificate) => certificate,
        Err(reason) => return reject(&mut writer, reason, 0, 0),
    };
    let admitted = match certificate.admit_request(request, r.nonce, build, launch) {
        Ok(admitted) => admitted,
        Err(reason) => {
            return reject(
                &mut writer,
                reason,
                certificate.rust_max() as u64,
                r.helper_rust_max,
            );
        }
    };
    let Some(path) = super::path_string(database) else {
        return reject(&mut writer, rust_budget::Reject::InvalidPath, 0, 0);
    };
    let Some(mut arena) = Arena::new(admitted.certificate().c_backing().size()) else {
        return writer.finish(wire::Outcome::SystemOom, 0, wire::Diagnostics::default());
    };
    let initialized = initialize(&mut arena, admitted.request().c_max as usize);
    let result = match initialized {
        Ok(()) => producer::run(&path, request, &mut arena, &mut writer),
        Err(report) => Ok(report),
    };
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            // 半帧/半 payload 或协议写失败后仅清理，不尝试尾帧。
            shutdown(&mut arena, Report::new(Outcome::InternalFailure));
            return Err(error);
        }
    };
    let mut report = shutdown(&mut arena, report);
    if initialized.is_ok() {
        report.flags |= 8;
    }
    if report.outcome == Outcome::PreflightPassed && report.flags & 15 != 11 {
        report.outcome = Outcome::InternalFailure;
    }
    let (outcome, flags, diagnostics) = completion(&arena, report);
    writer.finish(outcome, flags, diagnostics)
}

pub fn initialize(arena: &mut Arena, cap: usize) -> Result<(), Report> {
    if !arena.install() {
        return Err(Report::new(Outcome::UnsupportedEnvelope));
    }
    arena.start_request();
    arena.begin(2);
    let rc = arena.with_sqlite(|| unsafe { ffi::sqlite3_initialize() });
    arena.finish(rc)?;
    let initialized_accounting =
        arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) == arena.payload() as i64;
    arena.begin(3);
    arena.with_sqlite(|| unsafe { ffi::sqlite3_hard_heap_limit64(cap as i64) });
    arena.native_limit(cap);
    arena.finish(ffi::SQLITE_OK)?;
    arena.begin(3);
    arena.enter_calibration();
    let before = arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() });
    let probe = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(16) });
    let accounting = !probe.is_null()
        && arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) > before
        && arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) == arena.payload() as i64;
    arena.with_sqlite(|| unsafe { ffi::sqlite3_free(probe) });
    arena.leave_calibration();
    let conditions = unsafe {
        [
            ffi::sqlite3_libversion_number() == 3050002,
            arena.with_sqlite(|| ffi::sqlite3_hard_heap_limit64(-1)) == cap as i64,
            initialized_accounting
                && accounting
                && arena.with_sqlite(|| ffi::sqlite3_memory_used()) == before
                && arena.with_sqlite(|| ffi::sqlite3_memory_used()) == arena.payload() as i64,
            ffi::sqlite3_compileoption_used(c"ENABLE_MEMSYS3".as_ptr()) == 0,
            ffi::sqlite3_compileoption_used(c"ENABLE_MEMSYS5".as_ptr()) == 0,
            ffi::sqlite3_compileoption_used(c"OMIT_AUTOINIT".as_ptr()) == 0,
            ffi::sqlite3_compileoption_used(c"ENABLE_MEMORY_MANAGEMENT".as_ptr()) != 0,
            ffi::sqlite3_threadsafe() == 1,
        ]
    };
    arena.finish(ffi::SQLITE_OK)?;
    if conditions.iter().all(|condition| *condition) {
        Ok(())
    } else {
        let mut report = Report::new(Outcome::UnsupportedEnvelope);
        for (i, condition) in conditions.into_iter().enumerate() {
            if !condition {
                report.code |= 1 << i;
            }
        }
        Err(report)
    }
}

pub fn shutdown(arena: &mut Arena, mut report: Report) -> Report {
    arena.begin(12);
    let rc = arena.with_sqlite(|| unsafe { ffi::sqlite3_shutdown() });
    if let Err(cleanup) = arena.finish(rc) {
        if report.outcome == Outcome::PreflightPassed {
            let flags = report.flags;
            report = cleanup;
            report.flags |= flags;
        }
    }
    if rc != ffi::SQLITE_OK
        || arena.occupied != 0
        || arena.payload() != 0
        || arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) != 0
    {
        report.flags |= 4;
        if report.outcome == Outcome::PreflightPassed {
            report.outcome = Outcome::InternalFailure;
        }
    }
    arena.stats(&mut report);
    report
}

pub fn completion(arena: &Arena, report: Report) -> (wire::Outcome, u32, wire::Diagnostics) {
    let outcome = match report.outcome {
        Outcome::PreflightPassed => wire::Outcome::LoadedRaw,
        Outcome::MissingConnection => wire::Outcome::MissingConnection,
        Outcome::MissingProfile => wire::Outcome::MissingProfile,
        Outcome::SelectedLimit => wire::Outcome::SelectedLimit,
        Outcome::CBudgetExceeded => wire::Outcome::CBudgetExceeded,
        Outcome::StorageFailure => wire::Outcome::StorageFailure,
        Outcome::InvalidRequest => wire::Outcome::InvalidRequest,
        Outcome::UnsupportedEnvelope => wire::Outcome::UnsupportedEnvelope,
        Outcome::SystemOom => wire::Outcome::SystemOom,
        Outcome::InternalFailure => wire::Outcome::InternalFailure,
    };
    let mut flags = 0;
    for (old, new) in [
        (1, wire::READONLY),
        (2, wire::TOTAL_CHANGES_ZERO),
        (4, wire::CLEANUP_FAILED),
        (8, wire::ENVELOPE_VERIFIED),
    ] {
        if report.flags & old != 0 {
            flags |= new;
        }
    }
    let q = arena.first_quota;
    let mut diagnostics = wire::Diagnostics {
        code: report.code,
        phase: report.phase,
        occupied_after_shutdown: arena.occupied as u64,
        ..wire::Diagnostics::default()
    };
    if q.reason != 0 {
        flags |= wire::QUOTA_PROVED;
        diagnostics.phase = q.phase;
        diagnostics.reason = q.reason;
        diagnostics.rounded = q.rounded as u32;
        diagnostics.requested = q.requested as u64;
        diagnostics.denied_occupied = q.occupied as u64;
        diagnostics.available = q.available as u64;
        diagnostics.largest = q.largest as u64;
        diagnostics.first_quota_op = q.op;
    }
    (outcome, flags, diagnostics)
}
