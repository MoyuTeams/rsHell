//! 隔离测试入口调用真实 selected_read_helper::run，从进程启动记录每笔 Rust Layout。
//! 本入口显式析构 database/arguments 并返回 ExitCode，记录包含 Rust runtime cleanup；
//! 数字审计在进程终止前的 CRT onExit 回调中输出，不在 CRT exit 之后。
//! 不调用或覆盖旧 main 的 process::exit(2) 失败出口；12288 留存断言仅适用于本入口。
//! 不以高水位生成额度，不向生产 binary 安装 allocator，不输出地址或字段内容。

#[path = "../../src/bin/selected_read_helper/production_protocol.rs"]
pub mod production_protocol;
#[path = "../../src/bin/selected_read_helper/rust_budget/mod.rs"]
pub mod rust_budget;
#[path = "../../src/bin/selected_read_helper/mod.rs"]
pub mod selected_read_helper;

use rust_budget::{FixedLimits, HelperLaunchShape, HelperRustCertificate, SqlRoute, source::*};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::UnsafeCell,
    ffi::c_void,
    io::{Read, Write},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const EVENTS: usize = 1024;
const LIVE: usize = 128;
const EMPTY_EVENT: [u64; 6] = [0; 6];

#[derive(Clone, Copy)]
struct Live {
    pointer: usize,
    size: usize,
    align: usize,
    class: u64,
}
const EMPTY_LIVE: Live = Live {
    pointer: 0,
    size: 0,
    align: 0,
    class: 0,
};

struct Journal {
    events: [[u64; 6]; EVENTS],
    event_count: usize,
    live: [Live; LIVE],
    rust_held: usize,
    c_held: usize,
    rust_peak: usize,
    c_peak: usize,
    errors: usize,
    class_held: [usize; 6],
    path_seen: bool,
}
struct Shared(UnsafeCell<Journal>);
// 只有下方 spin lock 的持有者访问 Journal；记录路径不分配、无外部回调。
unsafe impl Sync for Shared {}
static JOURNAL: Shared = Shared(UnsafeCell::new(Journal {
    events: [EMPTY_EVENT; EVENTS],
    event_count: 0,
    live: [EMPTY_LIVE; LIVE],
    rust_held: 0,
    c_held: 0,
    rust_peak: 0,
    c_peak: 0,
    errors: 0,
    class_held: [0; 6],
    path_seen: false,
}));
static LOCK: AtomicBool = AtomicBool::new(false);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static RUST_MAX: AtomicUsize = AtomicUsize::new(0);
static C_MAX: AtomicUsize = AtomicUsize::new(0);
static IDENTITY: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static AFTER_GATE: AtomicUsize = AtomicUsize::new(0);
static ARGV_MAX: AtomicUsize = AtomicUsize::new(0);
static PATH_MAX: AtomicUsize = AtomicUsize::new(0);
static SQL_MAX: AtomicUsize = AtomicUsize::new(0);

fn with_journal<T>(f: impl FnOnce(&mut Journal) -> T) -> T {
    while LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        std::hint::spin_loop();
    }
    let result = f(unsafe { &mut *JOURNAL.0.get() });
    LOCK.store(false, Ordering::Release);
    result
}

impl Journal {
    fn event(&mut self, kind: u64, size: usize, align: usize, class: u64) {
        if let Some(event) = self.events.get_mut(self.event_count) {
            *event = [
                kind,
                PHASE.load(Ordering::Relaxed) as u64,
                size as u64,
                align as u64,
                class,
                self.rust_held as u64,
            ];
            self.event_count += 1;
        } else {
            self.errors += 1;
        }
    }

    fn admit(&mut self, size: usize, align: usize) -> u64 {
        let phase = PHASE.load(Ordering::Relaxed);
        // 隔离入口调用顺序：args_os → stdin/stdout globals → run 首笔 path CString
        // → Arena backing → preflight SQL。仅测试标注，不改变生产分配。
        let class = match phase {
            1 => 1,
            2 | 4 | 6 => 2,
            3 if size == C_MAX.load(Ordering::Relaxed) && align == 16 => 5,
            3 if !self.path_seen => {
                self.path_seen = true;
                if size != PATH_MAX.load(Ordering::Relaxed) || align != 1 {
                    self.errors += 1;
                }
                3
            }
            3 => 4,
            _ => 0,
        };
        self.class_held[class as usize] += size;
        let cap = match class {
            1 => ARGV_MAX.load(Ordering::Relaxed),
            2 => 13312,
            3 => PATH_MAX.load(Ordering::Relaxed),
            4 => SQL_MAX.load(Ordering::Relaxed),
            5 => C_MAX.load(Ordering::Relaxed),
            _ => 0,
        };
        if self.class_held[class as usize] > cap {
            self.errors += 1;
        }
        if class == 5 {
            self.c_held += size;
            self.c_peak = self.c_peak.max(self.c_held);
            if self.c_held > C_MAX.load(Ordering::Relaxed) {
                self.errors += 1;
            }
        } else {
            self.rust_held += size;
            self.rust_peak = self.rust_peak.max(self.rust_held);
            if self.rust_held > RUST_MAX.load(Ordering::Relaxed) {
                self.errors += 1;
            }
        }
        if RESULT.load(Ordering::Relaxed) != 0 && phase == 3 {
            AFTER_GATE.fetch_add(1, Ordering::Relaxed);
        }
        self.event(1, size, align, class);
        class
    }

    fn allocated(&mut self, pointer: *mut u8, size: usize, align: usize, class: u64) {
        if pointer.is_null() {
            self.unhold(size, class);
        } else if let Some(slot) = self.live.iter_mut().find(|l| l.pointer == 0) {
            *slot = Live {
                pointer: pointer as usize,
                size,
                align,
                class,
            };
        } else {
            self.errors += 1;
        }
    }

    fn unhold(&mut self, size: usize, class: u64) {
        self.class_held[class as usize] -= size;
        if class == 5 {
            self.c_held -= size;
        } else {
            self.rust_held -= size;
        }
    }

    fn freed(&mut self, pointer: *mut u8, layout: Layout) {
        let Some(index) = self.live.iter().position(|l| l.pointer == pointer as usize) else {
            self.errors += 1;
            return;
        };
        let live = self.live[index];
        if live.size != layout.size() || live.align != layout.align() {
            self.errors += 1;
        }
        self.live[index] = EMPTY_LIVE;
        self.unhold(live.size, live.class);
        self.event(2, live.size, live.align, live.class);
    }
}

struct AuditAllocator;
#[global_allocator]
static ALLOCATOR: AuditAllocator = AuditAllocator;
unsafe impl GlobalAlloc for AuditAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let class = with_journal(|j| j.admit(layout.size(), layout.align()));
        let pointer = unsafe { System.alloc(layout) };
        with_journal(|j| j.allocated(pointer, layout.size(), layout.align(), class));
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let class = with_journal(|j| j.admit(layout.size(), layout.align()));
        let pointer = unsafe { System.alloc_zeroed(layout) };
        with_journal(|j| j.allocated(pointer, layout.size(), layout.align(), class));
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        with_journal(|j| j.freed(pointer, layout));
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // 新 backing 预约先于 System.realloc，旧 backing 直到成功返回仍计入。
        let class = with_journal(|j| j.admit(size, layout.align()));
        let next = unsafe { System.realloc(pointer, layout, size) };
        with_journal(|j| {
            if !next.is_null() {
                j.freed(pointer, layout);
            }
            j.allocated(next, size, layout.align(), class);
        });
        next
    }
}

// SDK 公共 ABI：GetCommandLineW 为系统持有的 NUL 字符串；WriteFile 为同步 stderr pipe。
// 官方文档：processenv/GetCommandLineW、fileapi/WriteFile；无 shell32 解析器。
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCommandLineW() -> *const u16;
    fn GetStdHandle(kind: u32) -> *mut c_void;
    fn WriteFile(
        handle: *mut c_void,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
unsafe extern "C" {
    fn atexit(callback: extern "C" fn()) -> i32;
}

fn raw_stderr(mut bytes: &[u8]) {
    let handle = unsafe { GetStdHandle((-12i32) as u32) };
    while !bytes.is_empty() {
        let mut written = 0;
        if unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || written == 0
        {
            return;
        }
        bytes = &bytes[written as usize..];
    }
}

// 本隔离入口完成局部析构与 Rust runtime cleanup 后，CRT onExit 回调记录剩余 Layout。
extern "C" fn exit_audit() {
    PHASE.store(6, Ordering::Relaxed);
    with_journal(|j| {
        let header = [
            IDENTITY.load(Ordering::Relaxed) as u64,
            RUST_MAX.load(Ordering::Relaxed) as u64,
            C_MAX.load(Ordering::Relaxed) as u64,
            j.rust_peak as u64,
            j.c_peak as u64,
            j.errors as u64,
            j.event_count as u64,
            j.rust_held as u64,
            j.c_held as u64,
            RESULT.load(Ordering::Relaxed) as u64,
            AFTER_GATE.load(Ordering::Relaxed) as u64,
        ];
        raw_stderr(b"SHRBAUD1");
        for value in header {
            raw_stderr(&value.to_le_bytes());
        }
        for event in &j.events[..j.event_count] {
            for value in event {
                raw_stderr(&value.to_le_bytes());
            }
        }
    });
}

fn main() -> std::process::ExitCode {
    if unsafe { atexit(exit_audit) } != 0 {
        std::process::exit(90);
    }
    let pointer = unsafe { GetCommandLineW() };
    let mut len = 0;
    while unsafe { *pointer.add(len) } != 0 {
        len += 1;
    }
    let command = unsafe { std::slice::from_raw_parts(pointer, len) };
    let shape = HelperLaunchShape::from_command_line(command).unwrap();
    let build = BuildEvidence {
        compiler_commit: COMPILER_COMMIT,
        release: COMPILER_RELEASE,
        target: TARGET,
        sqlite_features: SQLITE_FEATURES,
        normal_helper_cfg: true,
        inherited_environment: true,
        synchronous_pipe_handles: true,
    }
    .verify()
    .unwrap();
    let certificate = HelperRustCertificate::calculate(
        build,
        shape,
        FixedLimits::default(),
        SqlRoute::LegacyBuilder,
    )
    .unwrap();
    // 以父可计算的同形状 certificate 设审计界，不以 request 追授 bootstrap；
    // 测试自行填入构建常量不证明实际 artifact 身份或父 ledger 的 spawn 前 reservation。
    RUST_MAX.store(certificate.rust_max(), Ordering::Relaxed);
    C_MAX.store(certificate.c_backing().size(), Ordering::Relaxed);
    ARGV_MAX.store(certificate.costs().argv, Ordering::Relaxed);
    PATH_MAX.store(certificate.costs().path, Ordering::Relaxed);
    SQL_MAX.store(certificate.costs().sql_and_fields, Ordering::Relaxed);
    IDENTITY.store(shape.identity() as usize, Ordering::Relaxed);
    PHASE.store(1, Ordering::Relaxed);
    let mut arguments = std::env::args_os();
    let executable = arguments.next().unwrap();
    let database = arguments.next().unwrap();
    assert!(arguments.next().is_none());
    let std_shape = HelperLaunchShape::from_paths(&executable, &database).unwrap();
    certificate.verify_launch(std_shape).unwrap();
    assert_eq!(
        certificate.fingerprint(),
        HelperRustCertificate::calculate(
            build,
            std_shape,
            FixedLimits::default(),
            SqlRoute::LegacyBuilder
        )
        .unwrap()
        .fingerprint()
    );
    drop(executable);
    PHASE.store(2, Ordering::Relaxed);
    let mut frame = [0u8; 112];
    let mut input = std::io::stdin().lock();
    let request = input.read_exact(&mut frame).ok().and_then(|()| {
        let mut eof = [0u8; 1];
        (input.read(&mut eof).ok()? == 0).then_some(())?;
        production_protocol::Request::decode(&frame).ok()
    });
    drop(input);
    let nonce = request.map_or([0; 16], |request| request.limits().nonce);
    let admission = request
        .ok_or(rust_budget::Reject::InvalidRequest)
        .and_then(|r| certificate.admit_request(r, nonce, build, shape));
    let mut stdout = std::io::stdout().lock();
    let write_result = match admission {
        Ok(admitted) => {
            PHASE.store(3, Ordering::Relaxed);
            let r = admitted.request();
            let report = selected_read_helper::run(
                &database,
                selected_read_helper::protocol::Request {
                    cap: admitted.certificate().c_backing().size(),
                    field: r.field_max,
                    total: r.total_max,
                    tags: r.tags_max,
                    connection: r.connection,
                    profile: r.profile,
                },
            );
            PHASE.store(4, Ordering::Relaxed);
            // 真实 C selected 回归报告仍是 v1 PreflightPassed，绝不伪造 LoadedRaw。
            report.write(&mut stdout)
        }
        Err(reason) => {
            RESULT.store(reason as usize, Ordering::Relaxed);
            PHASE.store(4, Ordering::Relaxed);
            let footer = production_protocol::Footer {
                outcome: reason.outcome(),
                flags: if request.is_some() {
                    production_protocol::NONCE_VALID
                } else {
                    0
                },
                nonce,
                revision: 0,
                source: 0,
                stats: production_protocol::Statistics::default(),
                diagnostics: production_protocol::Diagnostics::default(),
            };
            stdout.write_all(&footer.encode().unwrap())
        }
    };
    let failed = write_result.and_then(|()| stdout.flush()).is_err();
    drop(stdout);
    PHASE.store(5, Ordering::Relaxed);
    drop(database);
    drop(arguments);
    if failed {
        RESULT.store(100, Ordering::Relaxed);
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}
