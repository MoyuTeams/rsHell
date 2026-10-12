pub mod envelope;
pub mod normal_v2;
pub mod preflight;
pub mod producer;
pub mod production_protocol;
pub mod protocol;
pub mod rust_budget;

use envelope::Arena;
use protocol::{Outcome, Report, Request};
use rusqlite::ffi;
use std::{
    ffi::{CString, OsStr},
    io,
    io::Read,
};

pub fn main() {
    if !entry() {
        std::process::exit(2);
    }
}

fn entry() -> bool {
    let mut args = std::env::args_os();
    let executable = args.next();
    let path = args.next();
    let mut input = io::stdin().lock();
    let mut selector = [0u8; 10];
    let version = if input.read_exact(&mut selector).is_ok() && &selector[..8] == b"SHSELREQ" {
        u16::from_le_bytes([selector[8], selector[9]])
    } else {
        0
    };
    let result = if version == 2 {
        let request = production_protocol::WireValidatedRequest::read(
            &mut io::Cursor::new(selector).chain(&mut input),
        );
        match (executable, path, request, args.next()) {
            (Some(executable), Some(path), Ok(request), None) => normal_v2::run(
                &executable,
                &path,
                request,
                normal_v2::embedded_build_evidence(),
                &mut io::stdout().lock(),
            ),
            _ => normal_v2::invalid_request(&mut io::stdout().lock()),
        }
    } else {
        let request = if version == 1 {
            Request::read(&mut io::Cursor::new(selector).chain(&mut input))
        } else {
            None
        };
        let report = match (path, request, args.next()) {
            (Some(path), Some(request), None) => run(&path, request),
            _ => Report::new(Outcome::InvalidRequest),
        };
        report
            .write(&mut io::stdout().lock())
            .map_err(|error| production_protocol::WriteError::Io(error.kind()))
    };
    result.is_ok()
}

pub fn run(path: &OsStr, request: Request) -> Report {
    let Some(path) = path_string(path) else {
        return Report::new(Outcome::InvalidRequest);
    };
    let Some(mut arena) = Arena::new(request.cap) else {
        return Report::new(Outcome::SystemOom);
    };
    if !arena.install() {
        return Report::new(Outcome::UnsupportedEnvelope);
    }
    arena.start_request();
    #[cfg(test)]
    let held = if fault("init") {
        arena.occupy()
    } else {
        std::ptr::null_mut()
    };
    arena.begin(2);
    let init = arena.with_sqlite(|| unsafe { ffi::sqlite3_initialize() });
    #[cfg(test)]
    if fault("init-recovered") {
        assert_eq!(init, ffi::SQLITE_OK);
        assert!(arena.init_recovery_ok);
    }
    // 3.50.2 的版本/编译选项/threadsafe 只读常量或静态选项数组；其余运行期
    // 入口（包括 MEMSTAT getter）统一在当前有效借用的 scope 内调用。
    let initialized_accounting =
        arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) == arena.payload() as i64;
    let result = (|| -> Result<Report, Report> {
        arena.finish(init)?;
        arena.begin(3);
        arena.with_sqlite(|| unsafe {
            ffi::sqlite3_hard_heap_limit64(request.cap as i64);
        });
        arena.native_limit(request.cap);
        arena.finish(ffi::SQLITE_OK)?;
        arena.begin(3);
        arena.enter_calibration();
        #[cfg(test)]
        if fault("calibration-quota") {
            arena.arm_retry_release();
        }
        #[cfg(test)]
        let calibration_held = if fault("calibration-null") {
            arena.occupy()
        } else {
            std::ptr::null_mut()
        };
        // SINGLETHREAD 初始化可以不保留块；用受同一包络约束的一笔分配核验 MEMSTATUS。
        let before = arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() });
        let probe = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(16) });
        let accounting = !probe.is_null()
            && arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }) > before
            && arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() })
                == arena.payload() as i64;
        arena.with_sqlite(|| unsafe {
            ffi::sqlite3_free(probe);
        });
        #[cfg(test)]
        unsafe {
            arena.release(calibration_held);
        }
        arena.leave_calibration();
        let conditions = unsafe {
            [
                ffi::sqlite3_libversion_number() == 3050002,
                arena.with_sqlite(|| ffi::sqlite3_hard_heap_limit64(-1)) == request.cap as i64,
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
        if conditions.iter().all(|c| *c) {
            #[cfg(test)]
            if fault("native-small-growth")
                || fault("native-realloc-controls")
                || fault("native-ambiguous-prefix")
                || fault("native-release-retry")
                || fault("native-fresh-recovery")
                || fault("ffi-scope")
            {
                let report = if fault("ffi-scope") {
                    arena.scope_lifetime_regression()
                } else if fault("native-fresh-recovery") {
                    arena.fresh_allocation_recovery_regression()
                } else if fault("native-release-retry") {
                    arena.release_retry_regression(&path)
                } else if fault("native-ambiguous-prefix") {
                    arena.indistinguishable_native_prefix_regression()
                } else {
                    arena.native_small_growth_regression(fault("native-realloc-controls"))
                };
                return Ok(report);
            }
            #[cfg(test)]
            if fault("native") {
                arena.begin(8);
                let held =
                    arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc((request.cap / 8) as i32) });
                arena.begin(8);
                let maximum = arena.maximum_request() as i32;
                let refused = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(maximum) });
                assert!(refused.is_null());
                let report = arena.failure(ffi::SQLITE_NOMEM);
                arena.with_sqlite(|| unsafe {
                    ffi::sqlite3_free(held);
                });
                return Ok(report);
            }
            #[cfg(test)]
            if fault("benign") {
                arena.begin(5);
                let refused =
                    arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc((request.cap + 16) as i32) });
                assert!(refused.is_null());
            }
            let mut report = preflight::run(&path, request, &mut arena);
            report.flags |= 8;
            Ok(report)
        } else {
            let mut r = Report::new(Outcome::UnsupportedEnvelope);
            for (i, ok) in conditions.into_iter().enumerate() {
                if !ok {
                    r.code |= 1 << i;
                }
            }
            Ok(r)
        }
    })();
    let mut report = result.unwrap_or_else(|report| report);
    #[cfg(test)]
    {
        unsafe {
            arena.release(held);
        }
        arena.disarm_retry_release();
        barrier("shutdown");
    }
    arena.begin(12);
    let shutdown = arena.with_sqlite(|| unsafe { ffi::sqlite3_shutdown() });
    if let Err(cleanup) = arena.finish(shutdown) {
        if report.outcome == Outcome::PreflightPassed {
            report = cleanup;
        }
    }
    if shutdown != ffi::SQLITE_OK
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

pub fn path_string(path: &OsStr) -> Option<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_bytes()).ok()
    }
    #[cfg(windows)]
    {
        CString::new(path.to_str()?.as_bytes()).ok()
    }
}

#[cfg(test)]
pub fn fault(name: &str) -> bool {
    std::env::var("SELECTED_TEST_FAULT").is_ok_and(|v| v == name)
}

// 控制通道仅存在于独立测试 executable；正常 bin 不读取故障环境变量。
#[cfg(test)]
pub fn barrier(name: &str) {
    use std::io::{Read, Write};
    if std::env::var("SELECTED_TEST_BARRIER").is_ok_and(|v| v == name) {
        if let Ok(mut stream) =
            std::net::TcpStream::connect(std::env::var("SELECTED_TEST_CONTROL").unwrap())
        {
            stream.write_all(&[1]).unwrap();
            let mut b = [0];
            stream.read_exact(&mut b).unwrap();
        }
    }
}
