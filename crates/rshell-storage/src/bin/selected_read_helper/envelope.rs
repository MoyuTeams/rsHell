use super::protocol::{Outcome, Report};
use rusqlite::ffi;
use std::{
    alloc::{Layout, alloc, dealloc},
    cell::Cell,
    ffi::{c_int, c_void},
    ptr,
};

const ALIGN: usize = 16;
// phase：1 配置、2 初始化、3 原生限额/记账核验、4 open/连接配置、5 prepare、
// 6 bind、7 step（含自动 recompile）、8 取列、9 finalize、10 rollback、11 close、12 shutdown。
// reason：1 总容量、2 碎片、3 无法满足舍入、4 原生 hard limit（未进入分配回调）。
#[repr(C)]
struct Header {
    span: usize,
    used: usize,
}
const HEADER: usize = (size_of::<Header>() + ALIGN - 1) & !(ALIGN - 1);
// 请求类是 8 mod 16，实际 usable 是 0 mod 16。二者不相等并非虚假标签：
// 多出的 8 字节及未切尾部是真实可用空间，和 header 一起计入原 backing。
fn request_class(n: usize) -> Option<usize> {
    if n == 0 {
        return None;
    }
    n.checked_add(8)
        .and_then(|v| v.checked_add(ALIGN - 1))
        .map(|v| v & !(ALIGN - 1))
        .and_then(|v| v.checked_sub(8))
}
thread_local! { static ACTIVE: Cell<*mut Arena> = const { Cell::new(ptr::null_mut()) }; }

// guard 只管理 TLS 槽，不持有或重新借用 Arena。嵌套返回及 Rust unwind 均恢复
// 外层调用的指针；该外层指针只有在相应借用链重新恢复后才能被回调使用。
struct SqliteScope {
    previous: *mut Arena,
}

impl Drop for SqliteScope {
    fn drop(&mut self) {
        ACTIVE.with(|slot| slot.set(self.previous));
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Denial {
    pub op: u64,
    pub phase: u8,
    pub reason: u8,
    pub requested: usize,
    pub rounded: usize,
    pub occupied: usize,
    pub available: usize,
    pub largest: usize,
    pub payload: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CallbackEvent {
    kind: u8,
    size: usize,
}

// 固定测试仪器：1 malloc、2 free、3 realloc、4 size、5 roundup 返回类、
// 6 实际 arena 拒绝、7 测试 unknown NULL。
// 不采集地址或数据库内容，亦不替换真实 SQLite 调用。
#[cfg(test)]
struct CallbackTrace {
    events: [CallbackEvent; 256],
    offsets: [usize; 256],
    len: usize,
}

#[cfg(test)]
impl Default for CallbackTrace {
    fn default() -> Self {
        Self {
            events: [CallbackEvent::default(); 256],
            offsets: [usize::MAX; 256],
            len: 0,
        }
    }
}

#[cfg(test)]
impl CallbackTrace {
    // 只记录相对 backing 的偏移，不输出原生地址；用于比较真实回调参数。
    fn pointer(&mut self, base: *mut u8, pointer: *mut c_void) {
        if let Some(index) = self.len.checked_sub(1)
            && let Some(slot) = self.offsets.get_mut(index)
        {
            *slot = if pointer.is_null() {
                usize::MAX
            } else {
                (pointer as usize)
                    .checked_sub(base as usize)
                    .unwrap_or(usize::MAX)
            };
        }
    }
    fn record(&mut self, kind: u8, size: usize) {
        if let Some(slot) = self.events.get_mut(self.len) {
            *slot = CallbackEvent { kind, size };
        }
        self.len = self.len.saturating_add(1);
    }

    fn observed(&self) -> &[CallbackEvent] {
        assert!(
            self.len <= self.events.len(),
            "测试轨迹必须完整，不能截断证据"
        );
        &self.events[..self.len]
    }
}

#[cfg(test)]
#[derive(Default)]
// userdata 仅含独立观测输出，不保存 Arena。注册后直到 step 返回，Rust owner
// 不访问 probe；读出结果后只 finalize/close，且 xDestroy=None，不再执行此 callback。
struct PrefixProbe {
    unknown_after_success: bool,
    fresh_recovery: bool,
    setup_ok: bool,
    expected_returns: bool,
    occupied: usize,
    native_payload: usize,
    unchanged: bool,
    after_occupied: usize,
    after_payload: usize,
    trace: CallbackTrace,
}

// 仅测试注册的 SQL 函数：两条内层序列都由一次真实 sqlite3_step 承载，
// 外层都实际返回 SQLITE_NOMEM；不是把多个外层 API 错并为一个 operation。
#[cfg(test)]
unsafe extern "C" fn prefix_probe(
    context: *mut ffi::sqlite3_context,
    _: c_int,
    _: *mut *mut ffi::sqlite3_value,
) {
    // 锁定版 user_data 仅取 context 中的应用指针，不调用 allocator。
    let probe = unsafe { &mut *ffi::sqlite3_user_data(context).cast::<PrefixProbe>() };
    active((), |arena| {
        let small = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8192) });
        let mut chain = ptr::null_mut();
        let mut fresh = ptr::null_mut();
        let mut setup_ok = !small.is_null();
        while setup_ok {
            let largest = arena.free_space().1;
            if largest == 0 {
                break;
            }
            let block =
                arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc((largest - 8) as c_int) });
            if block.is_null() {
                setup_ok = false;
                break;
            }
            unsafe {
                block.cast::<*mut c_void>().write(chain);
            }
            chain = block;
        }
        if setup_ok {
            unsafe {
                small
                    .cast::<u8>()
                    .write_bytes(91, payload_size(small) as usize);
            }
            probe.occupied = arena.occupied;
            probe.native_payload = arena.native_payload;
            probe.setup_ok = probe.occupied == 65536 && probe.native_payload + 8192 >= 65536;
            arena.trace = CallbackTrace::default();
            probe.expected_returns = if probe.fresh_recovery {
                // 第一笔 raw8192 在满额 arena 中被 native hard gate 拒绝。
                let refused = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8192) });
                let native_refused = refused.is_null() && arena.native_pending.reason == 4;
                if !refused.is_null() {
                    arena.with_sqlite(|| unsafe {
                        ffi::sqlite3_free(refused);
                    });
                }
                // 只释放 filler，保留 small、连接和 statement；不另开 operation。
                while !chain.is_null() {
                    let next = unsafe { chain.cast::<*mut c_void>().read() };
                    arena.with_sqlite(|| unsafe {
                        ffi::sqlite3_free(chain);
                    });
                    chain = next;
                }
                fresh = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8192) });
                let mut returned_as_expected = native_refused && !fresh.is_null();
                if !fresh.is_null() {
                    unsafe {
                        fresh
                            .cast::<u8>()
                            .write_bytes(73, payload_size(fresh) as usize);
                    }
                    if probe.unknown_after_success {
                        // 这次成功申请恢复了原申请，最终 NOMEM 来自之后的库前置拒绝。
                        let before = arena.trace.len;
                        returned_as_expected &= arena
                            .with_sqlite(|| unsafe { ffi::sqlite3_realloc64(fresh, 0x7fffff00) })
                            .is_null();
                        returned_as_expected &= arena.trace.len == before;
                    }
                    // 对照分支：fresh 仅为无关诊断申请，仍报告第一笔未恢复的拒绝。
                    returned_as_expected &= unsafe {
                        std::slice::from_raw_parts(fresh.cast::<u8>(), payload_size(fresh) as usize)
                    }
                    .iter()
                    .all(|b| *b == 73);
                }
                returned_as_expected
            } else if probe.unknown_after_success {
                let same = arena.with_sqlite(|| unsafe { ffi::sqlite3_realloc(small, 8192) });
                let unknown =
                    arena.with_sqlite(|| unsafe { ffi::sqlite3_realloc64(small, 0x7fffff00) });
                same == small && unknown.is_null()
            } else {
                let size = arena.with_sqlite(|| unsafe { ffi::sqlite3_msize(small) });
                let refused = arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8192) });
                let refused_as_expected = refused.is_null();
                if !refused.is_null() {
                    arena.with_sqlite(|| unsafe {
                        ffi::sqlite3_free(refused);
                    });
                }
                size == 8208 && refused_as_expected
            };
            probe.trace.events = arena.trace.events;
            probe.trace.offsets = arena.trace.offsets;
            probe.trace.len = arena.trace.len;
            probe.after_occupied = arena.occupied;
            probe.after_payload = arena.native_payload;
            probe.unchanged = (if probe.fresh_recovery {
                probe.after_occupied < probe.occupied
                    && probe.after_payload < probe.native_payload
                    && arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() })
                        == probe.after_payload as i64
            } else {
                probe.after_occupied == probe.occupied
                    && probe.after_payload == probe.native_payload
            }) && unsafe {
                std::slice::from_raw_parts(small.cast::<u8>(), payload_size(small) as usize)
            }
            .iter()
            .all(|b| *b == 91);
        }
        while !chain.is_null() {
            let next = unsafe { chain.cast::<*mut c_void>().read() };
            arena.with_sqlite(|| unsafe {
                ffi::sqlite3_free(chain);
            });
            chain = next;
        }
        arena.with_sqlite(|| unsafe {
            ffi::sqlite3_free(fresh);
            ffi::sqlite3_free(small);
            ffi::sqlite3_result_error_nomem(context);
        });
    });
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryMode {
    AlarmMalloc,
    AlarmMallocSuccess,
    AlarmRealloc,
    RetryMalloc,
    RetryRealloc,
    UnknownMallocRetry,
    UnknownReallocRetry,
    RetrySuccess,
    RetryDone,
}

#[cfg(test)]
// 与 PrefixProbe 相同：Arena 必须从当前 ACTIVE 借用链获取，不从 userdata 恢复。
struct RecoveryProbe {
    mode: RecoveryMode,
    valid: bool,
    before_payload: usize,
    after_payload: usize,
    candidate_payload: usize,
    trace: CallbackTrace,
}

// 此测试函数在真实 step 内触发默认 pcache 的 alarm。直接占用的 fault 块
// 只计入 Coccupied，native 场景则全部经真实 sqlite3_malloc 记入 payload。
#[cfg(test)]
unsafe extern "C" fn recovery_probe(
    context: *mut ffi::sqlite3_context,
    _: c_int,
    _: *mut *mut ffi::sqlite3_value,
) {
    let probe = unsafe { &mut *ffi::sqlite3_user_data(context).cast::<RecoveryProbe>() };
    active((), |arena| {
        let native_fill = matches!(
            probe.mode,
            RecoveryMode::AlarmMalloc
                | RecoveryMode::AlarmMallocSuccess
                | RecoveryMode::AlarmRealloc
        );
        let is_realloc = matches!(
            probe.mode,
            RecoveryMode::AlarmRealloc
                | RecoveryMode::RetryRealloc
                | RecoveryMode::UnknownReallocRetry
        );
        let unknown_retry = matches!(
            probe.mode,
            RecoveryMode::UnknownMallocRetry | RecoveryMode::UnknownReallocRetry
        );
        let raw: c_int = if native_fill { 32768 } else { 64 };
        let mut old = if is_realloc {
            arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8) })
        } else {
            ptr::null_mut()
        };
        let mut valid = !is_realloc || !old.is_null();
        if !old.is_null() {
            unsafe {
                old.cast::<u8>().write_bytes(77, payload_size(old) as usize);
            }
        }
        let mut held = ptr::null_mut();
        if native_fill {
            while valid {
                let largest = arena.free_space().1;
                if largest == 0 {
                    break;
                }
                let block =
                    arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc((largest - 8) as c_int) });
                if block.is_null() {
                    valid = false;
                    break;
                }
                unsafe {
                    block.cast::<*mut c_void>().write(held);
                }
                held = block;
            }
        } else {
            held = arena.occupy();
        }
        valid &= arena.occupied == arena.layout.size();
        probe.before_payload = arena.native_payload;
        valid &= arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() })
            == probe.before_payload as i64;
        let class = request_class(raw as usize).unwrap_or(0);
        valid &= (probe.before_payload + class >= arena.native_limit) == native_fill;
        arena.trace = CallbackTrace::default();
        arena.unknown_on_free = unknown_retry;
        let allocated = if is_realloc {
            arena.with_sqlite(|| unsafe { ffi::sqlite3_realloc(old, raw) })
        } else {
            arena.with_sqlite(|| unsafe { ffi::sqlite3_malloc(raw) })
        };
        probe.after_payload = arena.native_payload;
        probe.candidate_payload = arena.native_pending.payload;
        valid &= arena.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() })
            == probe.after_payload as i64;
        let expected_null = unknown_retry || probe.mode == RecoveryMode::AlarmRealloc;
        valid &= allocated.is_null() == expected_null;
        if allocated.is_null() {
            if !old.is_null() {
                valid &= unsafe { std::slice::from_raw_parts(old.cast::<u8>(), 16) }
                    .iter()
                    .all(|b| *b == 77);
            }
        } else {
            if is_realloc {
                valid &= unsafe { std::slice::from_raw_parts(allocated.cast::<u8>(), 16) }
                    .iter()
                    .all(|b| *b == 77);
                old = ptr::null_mut();
            }
            // callback 成功只消费 candidate；实际 pool 拒绝的请求首证不可撤销。
            valid &= arena.native_pending.reason == 0;
            valid &= arena.first_quota.reason == if native_fill { 0 } else { 1 };
            if !matches!(
                probe.mode,
                RecoveryMode::RetrySuccess
                    | RecoveryMode::RetryDone
                    | RecoveryMode::AlarmMallocSuccess
            ) {
                let events_before = arena.trace.len;
                valid &= arena
                    .with_sqlite(|| unsafe { ffi::sqlite3_realloc64(allocated, 0x7fffff00) })
                    .is_null();
                valid &= arena.trace.len == events_before;
            }
        }
        probe.trace.events = arena.trace.events;
        probe.trace.len = arena.trace.len;
        probe.valid = valid;
        arena.unknown_on_free = false;
        arena.unclassified = false;
        arena.with_sqlite(|| unsafe {
            ffi::sqlite3_free(allocated);
            ffi::sqlite3_free(old);
        });
        if native_fill {
            while !held.is_null() {
                let next = unsafe { held.cast::<*mut c_void>().read() };
                arena.with_sqlite(|| unsafe {
                    ffi::sqlite3_free(held);
                });
                held = next;
            }
        } else {
            unsafe {
                arena.release(held);
            }
        }
        if matches!(
            probe.mode,
            RecoveryMode::RetrySuccess | RecoveryMode::RetryDone | RecoveryMode::AlarmMallocSuccess
        ) {
            arena.with_sqlite(|| unsafe {
                ffi::sqlite3_result_int(context, 1);
            });
        } else {
            arena.with_sqlite(|| unsafe {
                ffi::sqlite3_result_error_nomem(context);
            });
        }
    });
}

// 所有可变块元数据均位于 backing；此固定 owner 及系统分配元数据不属于 Cbacking。
pub struct Arena {
    base: *mut u8,
    layout: Layout,
    pub occupied: usize,
    pub peak: usize,
    pub op: u64,
    pub phase: u8,
    pub phases: u64,
    pub first_quota: Denial,
    request_active: bool,
    native_payload: usize,
    native_pending: Denial,
    native_limit: usize,
    #[cfg(test)]
    pub unclassified: bool,
    #[cfg(test)]
    unknown_on_free: bool,
    #[cfg(test)]
    release_on_denial: *mut c_void,
    #[cfg(test)]
    init_recovery: bool,
    #[cfg(test)]
    pub init_recovery_ok: bool,
    #[cfg(test)]
    trace: CallbackTrace,
}

impl Arena {
    pub fn new(cap: usize) -> Option<Self> {
        #[cfg(test)]
        if super::fault("backing") {
            return None;
        }
        let layout = Layout::from_size_align(cap, ALIGN).ok()?;
        if cap < HEADER + ALIGN || cap % ALIGN != 0 {
            return None;
        }
        // SAFETY: 唯一一次 fallible 系统分配，地址稳定至 shutdown 后。
        let base = unsafe { alloc(layout) };
        if base.is_null() {
            return None;
        }
        unsafe {
            base.cast::<Header>().write(Header { span: cap, used: 0 });
        }
        Some(Self {
            base,
            layout,
            occupied: 0,
            peak: 0,
            op: 0,
            phase: 0,
            phases: 0,
            first_quota: Denial::default(),
            request_active: false,
            native_payload: 0,
            native_pending: Denial::default(),
            native_limit: 0,
            #[cfg(test)]
            unclassified: false,
            #[cfg(test)]
            unknown_on_free: false,
            #[cfg(test)]
            release_on_denial: ptr::null_mut(),
            #[cfg(test)]
            init_recovery: super::fault("init-recovered"),
            #[cfg(test)]
            init_recovery_ok: false,
            #[cfg(test)]
            trace: CallbackTrace::default(),
        })
    }
    pub fn begin(&mut self, phase: u8) {
        // begin 只在真实 API 之间调用；不丢弃尚待收口的 native attempt。
        self.complete_pending();
        self.op += 1;
        self.phase = phase;
        self.phases |= 1u64 << phase;
    }
    /// 每次可能触发 allocator callback 的 FFI 调用都从当前借用发布新指针。
    /// closure 不接收 Arena；期间只有沿 ACTIVE 派生的同步 callback 可访问它。
    /// 状态准备和预算收口均在作用域外，不能重用 begin 或旧 owner 派生的指针。
    pub fn with_sqlite<T>(&mut self, call: impl FnOnce() -> T) -> T {
        let current = self as *mut Arena;
        let _scope = SqliteScope {
            previous: ACTIVE.with(|slot| slot.replace(current)),
        };
        call()
    }
    pub fn start_request(&mut self) {
        self.request_active = true;
    }
    pub fn enter_calibration(&mut self) {
        self.complete_pending();
        self.request_active = false;
    }
    pub fn leave_calibration(&mut self) {
        self.complete_pending();
        self.request_active = true;
    }
    fn latch(&mut self, proof: Denial) {
        if self.request_active && self.first_quota.reason == 0 {
            self.first_quota = proof;
        }
    }
    fn complete_pending(&mut self) {
        let candidate = std::mem::take(&mut self.native_pending);
        // 已锁定 P != R，默认 release 不嵌套分配；到下一 roundup 或 outer
        // return 仍未被回调消费，才确认 native refusal，不以预筛单独锁首证。
        if candidate.reason != 0
            && candidate.rounded > 0
            && candidate
                .payload
                .checked_add(candidate.rounded)
                .is_some_and(|used| used >= self.native_limit)
        {
            self.latch(candidate);
        }
    }
    #[cfg(test)]
    fn next_test_request(&mut self) {
        self.complete_pending();
        assert_eq!(
            self.occupied, 0,
            "独立 scenario 必须先释放上一请求的全部资源"
        );
        assert_eq!(self.native_payload, 0);
        self.first_quota = Denial::default();
        self.request_active = true;
    }
    fn free_space(&self) -> (usize, usize) {
        let (mut offset, mut total, mut largest) = (0, 0, 0);
        while offset < self.layout.size() {
            let h = unsafe { &*self.base.add(offset).cast::<Header>() };
            if h.used == 0 {
                total += h.span - HEADER;
                largest = largest.max(h.span - HEADER);
            }
            offset += h.span;
        }
        (total, largest)
    }
    fn deny(&mut self, n: usize, reason: u8) {
        #[cfg(test)]
        self.trace.record(6, n);
        let (available, largest) = self.free_space();
        self.latch(Denial {
            op: self.op,
            phase: self.phase,
            reason,
            requested: n,
            rounded: request_class(n).unwrap_or(0),
            occupied: self.occupied,
            available,
            largest,
            payload: self.native_payload,
        });
    }
    fn rounded(&mut self, n: c_int) -> c_int {
        if n <= 0 {
            return 0;
        }
        let class = request_class(n as usize);
        let need = class
            .and_then(|v| v.checked_add(8))
            .and_then(|v| v.checked_add(HEADER));
        match (class, need) {
            (Some(v), Some(need)) if need <= self.layout.size() && c_int::try_from(v).is_ok() => {
                v as c_int
            }
            _ => {
                self.deny(n as usize, 3);
                0
            }
        }
    }
    unsafe fn malloc(&mut self, n: c_int) -> *mut c_void {
        #[cfg(test)]
        if self.unclassified && matches!(self.phase, 7 | 8 | 10) {
            self.trace.record(7, n as usize);
            return ptr::null_mut();
        }
        let n = self.rounded(n);
        if n == 0 {
            return ptr::null_mut();
        }
        let Some(need) = (n as usize)
            .checked_add(8)
            .and_then(|v| v.checked_add(HEADER))
        else {
            self.deny(n as usize, 3);
            return ptr::null_mut();
        };
        let mut offset = 0;
        while offset < self.layout.size() {
            let h = unsafe { &mut *self.base.add(offset).cast::<Header>() };
            if h.used == 0 && h.span >= need {
                if h.span - need >= HEADER + ALIGN {
                    unsafe {
                        self.base.add(offset + need).cast::<Header>().write(Header {
                            span: h.span - need,
                            used: 0,
                        });
                    }
                    h.span = need;
                }
                h.used = 1;
                self.occupied += h.span;
                self.peak = self.peak.max(self.occupied);
                return unsafe { self.base.add(offset + HEADER).cast() };
            }
            offset += h.span;
        }
        let (total, _) = self.free_space();
        self.deny(n as usize, if total >= need - HEADER { 2 } else { 1 });
        ptr::null_mut()
    }
    unsafe fn free(&mut self, p: *mut c_void) {
        if p.is_null() {
            return;
        }
        let h = unsafe { &mut *p.cast::<u8>().sub(HEADER).cast::<Header>() };
        self.occupied -= h.span;
        h.used = 0;
        let mut offset = 0;
        while offset < self.layout.size() {
            let h = unsafe { &mut *self.base.add(offset).cast::<Header>() };
            while h.used == 0 && offset + h.span < self.layout.size() {
                let next = unsafe { &*self.base.add(offset + h.span).cast::<Header>() };
                if next.used != 0 {
                    break;
                }
                h.span += next.span;
            }
            offset += h.span;
        }
    }
    unsafe fn realloc(&mut self, p: *mut c_void, n: c_int) -> *mut c_void {
        if p.is_null() {
            return unsafe { self.malloc(n) };
        }
        // xRoundup 的零不是 sqlite3_realloc(p,0)，后者在 SQLite 上层处理。
        let n = self.rounded(n);
        if n == 0 {
            return ptr::null_mut();
        }
        let old = unsafe { payload_size(p) } as usize;
        if n as usize <= old {
            return p;
        }
        let next = unsafe { self.malloc(n) };
        if !next.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(p.cast::<u8>(), next.cast::<u8>(), old);
                self.free(p);
            }
        }
        next
    }
    pub fn finish(&mut self, rc: c_int) -> Result<(), Report> {
        self.complete_pending();
        let success = matches!(rc, ffi::SQLITE_OK | ffi::SQLITE_ROW | ffi::SQLITE_DONE);
        let mut report = Report::new(Outcome::StorageFailure);
        report.code = match rc & 255 {
            ffi::SQLITE_BUSY | ffi::SQLITE_LOCKED => 1,
            ffi::SQLITE_CORRUPT | ffi::SQLITE_NOTADB | ffi::SQLITE_MISMATCH => 2,
            ffi::SQLITE_CONSTRAINT => 3,
            _ => 4,
        };
        report.phase = self.phase;
        if !success && rc & 255 != ffi::SQLITE_NOMEM {
            return Err(report);
        }
        let event = self.first_quota;
        if self.request_active && event.reason != 0 {
            report.outcome = Outcome::CBudgetExceeded;
            report.code = if success { 0 } else { 4 };
            report.phase = event.phase;
            report.reason = event.reason;
            report.requested = event.requested as u64;
            report.available = event.available as u64;
            report.largest = event.largest as u64;
            report.denied_occupied = event.occupied as u32;
            report.rounded = event.rounded as u32;
            return Err(report);
        }
        if success { Ok(()) } else { Err(report) }
    }
    pub fn failure(&mut self, rc: c_int) -> Report {
        self.finish(rc)
            .err()
            .unwrap_or_else(|| Report::new(Outcome::InternalFailure))
    }
    pub fn stats(&self, r: &mut Report) {
        r.peak = self.peak as u64;
        r.occupied = self.occupied as u64;
        r.operations = self.op;
        r.phases = self.phases;
    }
    pub fn native_limit(&mut self, cap: usize) {
        self.native_limit = cap;
    }
    pub fn payload(&self) -> usize {
        self.native_payload
    }
    #[cfg(test)]
    pub fn maximum_request(&self) -> usize {
        self.layout.size() - HEADER - 8
    }
    #[cfg(test)]
    pub fn scope_lifetime_regression(&mut self) -> Report {
        assert!(!active(false, |_| true));
        self.begin(3);
        self.enter_calibration();
        self.trace = CallbackTrace::default();
        assert!(
            !active(false, |_| true),
            "begin 和状态准备不发布 callback context"
        );
        let p = self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(16) });
        assert!(!p.is_null());
        assert!(!active(false, |_| true), "实际 FFI 返回后必须撤销 context");
        assert_eq!(self.native_payload, 32);
        assert!(self.trace.observed().iter().any(|event| event.kind == 1));
        self.trace = CallbackTrace::default();
        self.with_sqlite(|| unsafe {
            ffi::sqlite3_free(p);
        });
        self.leave_calibration();
        self.finish(ffi::SQLITE_OK).unwrap();
        assert_eq!(self.occupied, 0);
        assert_eq!(
            self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
            0
        );

        self.begin(8);
        self.trace = CallbackTrace::default();
        self.inject_quota();
        assert!(!active(false, |_| true));
        let report = self.failure(ffi::SQLITE_NOMEM);
        assert_eq!(report.outcome, Outcome::CBudgetExceeded);
        assert_eq!(report.reason, 3);
        report
    }
    #[cfg(test)]
    pub fn arm_retry_release(&mut self) {
        assert!(self.release_on_denial.is_null());
        self.release_on_denial = self.occupy();
    }
    #[cfg(test)]
    pub fn disarm_retry_release(&mut self) {
        let held = std::mem::replace(&mut self.release_on_denial, ptr::null_mut());
        unsafe {
            self.release(held);
        }
    }
    #[cfg(test)]
    pub fn inject_quota(&mut self) {
        let size = (self.layout.size() + 16) as c_int;
        let refused = self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(size) });
        assert!(refused.is_null());
    }
    fn native_roundup(&mut self, n: c_int) -> c_int {
        self.complete_pending();
        let rounded = self.rounded(n);
        if rounded > 0
            && self.native_limit > 0
            && self
                .native_payload
                .checked_add(rounded as usize)
                .is_some_and(|used| used >= self.native_limit)
        {
            // 这是尚未消费的 candidate，不是拒绝。Pold mod16=0，R mod16=8，
            // 故锁定版的等尺寸直接成功分支不可达；成功、reuse、shrink 都进回调。
            // 默认 release 链只做 size/free，不覆盖 candidate；进入分配回调才消费。
            // 3.50.2：sqlite3PcacheReleaseMemory(57341) 经 pcache1MemSize、PinPage、
            // RemoveFromHash、FreePage、pcache1Free 到 sqlite3_free；无嵌套分配。
            // 必须保持默认 pcache / pPage=NULL；不能据当前回收后用量否定 realloc
            // 在 31283 使用 alarm 前 nUsed 所作的原生拒绝。
            let (available, largest) = self.free_space();
            self.native_pending = Denial {
                op: self.op,
                phase: self.phase,
                reason: 4,
                requested: n as usize,
                rounded: rounded as usize,
                occupied: self.occupied,
                available,
                largest,
                payload: self.native_payload,
            };
        }
        rounded
    }
    pub fn install(&mut self) -> bool {
        let methods = ffi::sqlite3_mem_methods {
            xMalloc: Some(xmalloc),
            xFree: Some(xfree),
            xRealloc: Some(xrealloc),
            xSize: Some(xsize),
            xRoundup: Some(xroundup),
            xInit: Some(xinit),
            xShutdown: Some(xshutdown),
            pAppData: ptr::null_mut(),
        };
        self.begin(1);
        self.with_sqlite(|| unsafe {
            ffi::sqlite3_config(ffi::SQLITE_CONFIG_SINGLETHREAD) == ffi::SQLITE_OK
                && ffi::sqlite3_config(ffi::SQLITE_CONFIG_MALLOC, &methods) == ffi::SQLITE_OK
                && ffi::sqlite3_config(ffi::SQLITE_CONFIG_MEMSTATUS, 1 as c_int) == ffi::SQLITE_OK
                && ffi::sqlite3_config(ffi::SQLITE_CONFIG_LOOKASIDE, 0 as c_int, 0 as c_int)
                    == ffi::SQLITE_OK
                && ffi::sqlite3_config(ffi::SQLITE_CONFIG_URI, 0 as c_int) == ffi::SQLITE_OK
                && ffi::sqlite3_config(
                    ffi::SQLITE_CONFIG_PAGECACHE,
                    ptr::null_mut::<c_void>(),
                    0 as c_int,
                    0 as c_int,
                ) == ffi::SQLITE_OK
        })
    }
    #[cfg(test)]
    pub fn occupy(&mut self) -> *mut c_void {
        let mut chain = ptr::null_mut();
        loop {
            let (_, largest) = self.free_space();
            if largest == 0 {
                return chain;
            }
            let p = unsafe { self.malloc((largest - 8) as c_int) };
            if p.is_null() {
                return chain;
            }
            // 测试预占链也完全放在同一 arena，不另建可增长元数据。
            unsafe {
                p.cast::<*mut c_void>().write(chain);
            }
            chain = p;
        }
    }
    #[cfg(test)]
    pub unsafe fn release(&mut self, mut p: *mut c_void) {
        while !p.is_null() {
            let next = unsafe { p.cast::<*mut c_void>().read() };
            unsafe {
                self.free(p);
            }
            p = next;
        }
    }

    #[cfg(test)]
    pub fn native_small_growth_regression(&mut self, controls: bool) -> Report {
        assert_eq!(self.layout.size(), 65536);
        assert_eq!(
            self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
            0
        );
        assert_eq!(HEADER, 16);
        let cases: &[&str] = if controls {
            &[
                "pool-malloc",
                "pool-grow",
                "round-zero",
                "api-zero",
                "same-raw",
                "shrink",
                "grow",
                "unknown",
            ]
        } else {
            &["native-grow"]
        };
        let mut report = Report::new(Outcome::InternalFailure);
        for case in cases {
            // 每个独立 scenario 都先完全释放前一场景，不用 begin 洗请求首证。
            self.next_test_request();
            self.begin(8);
            let large = self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(32760) });
            let mut small = self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8) });
            let mut rest = self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(32696) });
            assert!(!large.is_null() && !small.is_null() && !rest.is_null());
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_msize(large) }),
                32768
            );
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_msize(small) }),
                16
            );
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_msize(rest) }),
                32704
            );
            assert_eq!(self.occupied, 65536);
            assert_eq!(self.native_payload, 65488);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
                65488
            );
            self.finish(ffi::SQLITE_OK).unwrap();
            unsafe {
                large.cast::<u8>().write_bytes(55, 32768);
                small.cast::<u8>().write_bytes(91, 16);
            }
            self.begin(8);
            self.trace = CallbackTrace::default();
            let mut code = ffi::SQLITE_NOMEM;
            match *case {
                "native-grow" => {
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(small, 64) })
                            .is_null()
                    );
                    assert_eq!(
                        self.trace.observed(),
                        [
                            CallbackEvent { kind: 4, size: 16 },
                            CallbackEvent { kind: 5, size: 72 }
                        ]
                    );
                }
                "pool-malloc" | "pool-grow" => {
                    let kind = if *case == "pool-malloc" {
                        assert!(
                            self.with_sqlite(|| unsafe { ffi::sqlite3_malloc(8) })
                                .is_null()
                        );
                        1
                    } else {
                        assert!(
                            self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(small, 48) })
                                .is_null()
                        );
                        3
                    };
                    assert_eq!(
                        self.trace
                            .observed()
                            .iter()
                            .filter(|e| e.kind == kind)
                            .count(),
                        2
                    );
                    assert_eq!(
                        self.trace.observed().iter().filter(|e| e.kind == 5).count(),
                        1
                    );
                    assert_eq!(
                        self.trace.observed().iter().filter(|e| e.kind == 6).count(),
                        2
                    );
                    if kind == 3 {
                        assert!(
                            self.trace
                                .observed()
                                .iter()
                                .any(|e| *e == CallbackEvent { kind: 3, size: 56 })
                        );
                    }
                }
                "same-raw" | "shrink" => {
                    let raw = if *case == "same-raw" { 32760 } else { 64 };
                    let class = request_class(raw as usize).unwrap();
                    assert_eq!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(large, raw) }),
                        large
                    );
                    assert_eq!(
                        self.trace.observed(),
                        [
                            CallbackEvent {
                                kind: 4,
                                size: 32768
                            },
                            CallbackEvent {
                                kind: 5,
                                size: class
                            },
                            CallbackEvent {
                                kind: 3,
                                size: class
                            },
                            CallbackEvent {
                                kind: 4,
                                size: 32768
                            }
                        ]
                    );
                    self.finish(ffi::SQLITE_OK).unwrap();
                    let before = self.trace.len;
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc64(small, 0x7fffff00) })
                            .is_null()
                    );
                    assert_eq!(self.trace.len, before);
                }
                "grow" => {
                    self.with_sqlite(|| unsafe {
                        ffi::sqlite3_free(rest);
                    });
                    rest = ptr::null_mut();
                    self.trace = CallbackTrace::default();
                    let grown = self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(small, 64) });
                    assert!(!grown.is_null());
                    small = grown;
                    assert_eq!(
                        self.trace.observed(),
                        [
                            CallbackEvent { kind: 4, size: 16 },
                            CallbackEvent { kind: 5, size: 72 },
                            CallbackEvent { kind: 3, size: 72 },
                            CallbackEvent { kind: 4, size: 80 }
                        ]
                    );
                    self.finish(ffi::SQLITE_OK).unwrap();
                    assert_eq!(self.occupied, 32880);
                    assert_eq!(self.native_payload, 32848);
                    let before = self.trace.len;
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc64(small, 0x7fffff00) })
                            .is_null()
                    );
                    assert_eq!(self.trace.len, before);
                }
                "api-zero" => {
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(small, 0) })
                            .is_null()
                    );
                    small = ptr::null_mut();
                    assert!(
                        !self
                            .trace
                            .observed()
                            .iter()
                            .any(|e| matches!(e.kind, 3 | 5))
                    );
                    assert_eq!(self.occupied, 65504);
                    assert_eq!(self.native_payload, 65472);
                    code = ffi::SQLITE_OK;
                }
                "round-zero" => {
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc(large, 65536) })
                            .is_null()
                    );
                    assert!(
                        self.trace
                            .observed()
                            .iter()
                            .any(|e| *e == CallbackEvent { kind: 5, size: 0 })
                    );
                }
                "unknown" => {
                    assert!(
                        self.with_sqlite(|| unsafe { ffi::sqlite3_realloc64(small, 0x7fffff00) })
                            .is_null()
                    );
                    assert!(self.trace.observed().is_empty());
                }
                _ => unreachable!(),
            }
            if !matches!(*case, "grow" | "api-zero") {
                assert_eq!(self.occupied, 65536);
                assert_eq!(self.native_payload, 65488);
            }
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
                self.native_payload as i64
            );
            assert!(
                unsafe { std::slice::from_raw_parts(large.cast::<u8>(), 32768) }
                    .iter()
                    .all(|b| *b == 55)
            );
            if !small.is_null() {
                assert!(
                    unsafe { std::slice::from_raw_parts(small.cast::<u8>(), 16) }
                        .iter()
                        .all(|b| *b == 91)
                );
            }
            report = self
                .finish(code)
                .err()
                .unwrap_or_else(|| Report::new(Outcome::PreflightPassed));
            if matches!(
                *case,
                "native-grow" | "pool-malloc" | "pool-grow" | "round-zero"
            ) {
                assert_eq!(report.outcome, Outcome::CBudgetExceeded);
                assert_eq!(
                    report.reason,
                    if *case == "native-grow" {
                        4
                    } else if *case == "round-zero" {
                        3
                    } else {
                        1
                    }
                );
                let first = self.first_quota;
                self.begin(8);
                assert!(
                    self.with_sqlite(|| unsafe { ffi::sqlite3_realloc64(small, 0x7fffff00) })
                        .is_null()
                );
                assert_eq!(
                    self.failure(ffi::SQLITE_NOMEM).outcome,
                    Outcome::CBudgetExceeded
                );
                assert_eq!(
                    self.first_quota, first,
                    "新 operation 与 unknown 不得洗首证"
                );
                self.begin(10);
                self.inject_quota();
                let later = self.failure(ffi::SQLITE_NOMEM);
                assert_eq!(later.phase, first.phase);
                assert_eq!(later.reason, first.reason);
                assert_eq!(
                    self.first_quota, first,
                    "更晚的真实 rounding 拒绝也不能覆盖第一事件"
                );
            } else if code == ffi::SQLITE_NOMEM {
                assert_eq!(report.outcome, Outcome::StorageFailure);
                assert_eq!(report.code, 4);
                assert_eq!(report.reason, 0);
            }
            let first = self.first_quota;
            self.begin(9);
            self.with_sqlite(|| unsafe {
                ffi::sqlite3_free(rest);
                ffi::sqlite3_free(small);
                ffi::sqlite3_free(large);
            });
            let _ = self.finish(ffi::SQLITE_OK);
            assert_eq!(self.first_quota, first);
            assert_eq!(self.occupied, 0);
            assert_eq!(self.native_payload, 0);
        }
        report
    }

    #[cfg(test)]
    pub fn indistinguishable_native_prefix_regression(&mut self) -> Report {
        assert_eq!(self.layout.size(), 65536);
        assert_eq!(
            self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
            0
        );
        let mut native_failure = Report::new(Outcome::InternalFailure);
        let mut first_payload = 0;
        for unknown_after_success in [false, true] {
            self.next_test_request();
            let mut probe = PrefixProbe {
                unknown_after_success,
                ..PrefixProbe::default()
            };
            let mut db = ptr::null_mut();
            self.begin(4);
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_open_v2(
                        c":memory:".as_ptr(),
                        &mut db,
                        ffi::SQLITE_OPEN_READWRITE
                            | ffi::SQLITE_OPEN_CREATE
                            | ffi::SQLITE_OPEN_NOMUTEX,
                        ptr::null(),
                    )
                }),
                ffi::SQLITE_OK
            );
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_create_function_v2(
                        db,
                        c"native_prefix_probe".as_ptr(),
                        0,
                        ffi::SQLITE_UTF8,
                        (&mut probe as *mut PrefixProbe).cast(),
                        Some(prefix_probe),
                        None,
                        None,
                        None,
                    )
                }),
                ffi::SQLITE_OK
            );
            let mut statement = ptr::null_mut();
            self.begin(5);
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_prepare_v2(
                        db,
                        c"SELECT native_prefix_probe()".as_ptr(),
                        -1,
                        &mut statement,
                        ptr::null_mut(),
                    )
                }),
                ffi::SQLITE_OK
            );
            self.with_sqlite(|| unsafe {
                ffi::sqlite3_release_memory(c_int::MAX);
            });
            self.begin(7);
            let code = self.with_sqlite(|| unsafe { ffi::sqlite3_step(statement) });
            let failure = self.failure(code);
            assert_eq!(code, ffi::SQLITE_NOMEM);
            assert!(probe.setup_ok && probe.expected_returns && probe.unchanged);
            let prefix = [
                CallbackEvent {
                    kind: 4,
                    size: 8208,
                },
                CallbackEvent {
                    kind: 5,
                    size: 8200,
                },
            ];
            assert_eq!(&probe.trace.observed()[..2], &prefix);
            if unknown_after_success {
                assert_eq!(
                    &probe.trace.observed()[2..],
                    [
                        CallbackEvent {
                            kind: 3,
                            size: 8200
                        },
                        CallbackEvent {
                            kind: 4,
                            size: 8208
                        }
                    ]
                );
                assert_eq!(probe.native_payload, first_payload);
                assert_eq!(failure.outcome, Outcome::StorageFailure);
                assert_eq!(failure.code, 4);
            } else {
                assert_eq!(probe.trace.observed().len(), 2);
                first_payload = probe.native_payload;
                native_failure = failure;
            }
            self.begin(9);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_finalize(statement) }),
                ffi::SQLITE_NOMEM
            );
            self.begin(11);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_close(db) }),
                ffi::SQLITE_OK
            );
            assert_eq!(self.occupied, 0);
            assert_eq!(self.native_payload, 0);
        }
        native_failure
    }

    #[cfg(test)]
    pub fn release_retry_regression(&mut self, path: &std::ffi::CStr) -> Report {
        for mode in [
            RecoveryMode::AlarmMalloc,
            RecoveryMode::AlarmMallocSuccess,
            RecoveryMode::AlarmRealloc,
            RecoveryMode::RetryMalloc,
            RecoveryMode::RetryRealloc,
            RecoveryMode::UnknownMallocRetry,
            RecoveryMode::UnknownReallocRetry,
            RecoveryMode::RetrySuccess,
            RecoveryMode::RetryDone,
        ] {
            self.next_test_request();
            let mut probe = RecoveryProbe {
                mode,
                valid: false,
                before_payload: 0,
                after_payload: 0,
                candidate_payload: 0,
                trace: CallbackTrace::default(),
            };
            let mut db = ptr::null_mut();
            self.begin(4);
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_open_v2(
                        path.as_ptr(),
                        &mut db,
                        ffi::SQLITE_OPEN_READONLY
                            | ffi::SQLITE_OPEN_PRIVATECACHE
                            | ffi::SQLITE_OPEN_NOMUTEX,
                        ptr::null(),
                    )
                }),
                ffi::SQLITE_OK
            );
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_db_readonly(db, c"main".as_ptr()) }),
                1
            );
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_create_function_v2(
                        db,
                        c"recovery_probe".as_ptr(),
                        0,
                        ffi::SQLITE_UTF8,
                        (&mut probe as *mut RecoveryProbe).cast(),
                        Some(recovery_probe),
                        None,
                        None,
                        None,
                    )
                }),
                ffi::SQLITE_OK
            );
            self.begin(7);
            // 真实文件页进入默认 LRU；statement 结束后成为可回收 clean pages。
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_exec(
                        db,
                        c"PRAGMA mmap_size=0; SELECT id FROM connections".as_ptr(),
                        None,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                }),
                ffi::SQLITE_OK
            );
            let mut statement = ptr::null_mut();
            self.begin(5);
            let sql = if mode == RecoveryMode::RetryDone {
                c"SELECT 1 WHERE recovery_probe() IS NULL"
            } else {
                c"SELECT recovery_probe()"
            };
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut statement, ptr::null_mut())
                }),
                ffi::SQLITE_OK
            );
            self.begin(7);
            let code = self.with_sqlite(|| unsafe { ffi::sqlite3_step(statement) });
            let report = self
                .finish(code)
                .err()
                .unwrap_or_else(|| Report::new(Outcome::PreflightPassed));
            assert!(probe.valid, "{mode:?} 的真实返回、旧内容或记账不符");
            let events = probe.trace.observed();
            let first_free = events
                .iter()
                .position(|event| event.kind == 2)
                .expect("必须实际回收缓存页");
            let released: usize = events
                .iter()
                .filter(|event| event.kind == 2)
                .map(|event| event.size)
                .sum();
            assert!(released > 0);
            assert_eq!(
                events.iter().filter(|event| event.kind == 5).count(),
                1,
                "release 不得嵌套 roundup"
            );
            match mode {
                RecoveryMode::AlarmMalloc | RecoveryMode::AlarmMallocSuccess => {
                    assert!(events.iter().position(|event| event.kind == 1).unwrap() > first_free);
                    assert_eq!(events.iter().filter(|event| event.kind == 1).count(), 1);
                    assert_eq!(probe.after_payload, probe.before_payload - released + 32784);
                }
                RecoveryMode::AlarmRealloc => {
                    assert!(
                        !events
                            .iter()
                            .any(|event| matches!(event.kind, 1 | 3 | 6 | 7))
                    );
                    assert_eq!(probe.candidate_payload, probe.before_payload);
                    assert_eq!(probe.after_payload, probe.before_payload - released);
                    assert!(
                        probe.after_payload + (32776 - 16) < self.native_limit,
                        "回收后已低于阈值，但原生 realloc 按 alarm 前 nUsed 拒绝"
                    );
                }
                _ => {
                    let kind = if matches!(
                        mode,
                        RecoveryMode::RetryRealloc | RecoveryMode::UnknownReallocRetry
                    ) {
                        3
                    } else {
                        1
                    };
                    assert_eq!(
                        events.iter().filter(|event| event.kind == kind).count(),
                        2,
                        "第一次 NULL 后无新 roundup，真实 SQLite 必须重试同一回调"
                    );
                    assert!(events.iter().position(|event| event.kind == 6).unwrap() < first_free);
                    assert_eq!(events.iter().filter(|event| event.kind == 6).count(), 1);
                    let unknown = matches!(
                        mode,
                        RecoveryMode::UnknownMallocRetry | RecoveryMode::UnknownReallocRetry
                    );
                    assert_eq!(events.iter().any(|event| event.kind == 7), unknown);
                    let added = if unknown {
                        0
                    } else if kind == 3 {
                        64
                    } else {
                        80
                    };
                    assert_eq!(probe.after_payload, probe.before_payload - released + added);
                }
            }
            if mode == RecoveryMode::AlarmRealloc {
                assert_eq!(report.outcome, Outcome::CBudgetExceeded);
                assert_eq!(report.reason, 4);
            } else if mode == RecoveryMode::AlarmMallocSuccess {
                assert_eq!(code, ffi::SQLITE_ROW);
                assert_eq!(report.outcome, Outcome::PreflightPassed);
            } else if mode == RecoveryMode::AlarmMalloc {
                assert_eq!(code, ffi::SQLITE_NOMEM);
                assert_eq!(report.outcome, Outcome::StorageFailure);
                assert_eq!(report.code, 4);
                assert_eq!(report.reason, 0);
            } else {
                let success = matches!(mode, RecoveryMode::RetrySuccess | RecoveryMode::RetryDone);
                assert_eq!(
                    code,
                    if mode == RecoveryMode::RetryDone {
                        ffi::SQLITE_DONE
                    } else if success {
                        ffi::SQLITE_ROW
                    } else {
                        ffi::SQLITE_NOMEM
                    }
                );
                assert_eq!(report.outcome, Outcome::CBudgetExceeded);
                assert_eq!(report.code, if success { 0 } else { 4 });
                assert_eq!(report.reason, 1);
                assert_eq!(report.phase, 7);
            }
            self.begin(9);
            let finalized = self.with_sqlite(|| unsafe { ffi::sqlite3_finalize(statement) });
            assert_eq!(
                finalized,
                if matches!(code, ffi::SQLITE_ROW | ffi::SQLITE_DONE) {
                    ffi::SQLITE_OK
                } else {
                    ffi::SQLITE_NOMEM
                }
            );
            self.begin(11);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_close(db) }),
                ffi::SQLITE_OK
            );
            assert_eq!(self.occupied, 0);
            assert_eq!(self.native_payload, 0);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
                0
            );
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_hard_heap_limit64(-1) }),
                self.layout.size() as i64
            );
        }
        self.finish(ffi::SQLITE_OK)
            .expect_err("最后一个独立请求已因 pool 拒绝失效")
    }

    #[cfg(test)]
    pub fn fresh_allocation_recovery_regression(&mut self) -> Report {
        assert_eq!(self.layout.size(), 65536);
        let mut diagnostic_trace = CallbackTrace::default();
        let mut diagnostic_state = [0; 4];
        let mut recovered_report = Report::new(Outcome::InternalFailure);
        for unknown_after_success in [false, true] {
            self.next_test_request();
            let mut probe = PrefixProbe {
                fresh_recovery: true,
                unknown_after_success,
                ..PrefixProbe::default()
            };
            let mut db = ptr::null_mut();
            self.begin(4);
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_open_v2(
                        c":memory:".as_ptr(),
                        &mut db,
                        ffi::SQLITE_OPEN_READWRITE
                            | ffi::SQLITE_OPEN_CREATE
                            | ffi::SQLITE_OPEN_NOMUTEX,
                        ptr::null(),
                    )
                }),
                ffi::SQLITE_OK
            );
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_create_function_v2(
                        db,
                        c"native_prefix_probe".as_ptr(),
                        0,
                        ffi::SQLITE_UTF8,
                        (&mut probe as *mut PrefixProbe).cast(),
                        Some(prefix_probe),
                        None,
                        None,
                        None,
                    )
                }),
                ffi::SQLITE_OK
            );
            let mut statement = ptr::null_mut();
            self.begin(5);
            assert_eq!(
                self.with_sqlite(|| unsafe {
                    ffi::sqlite3_prepare_v2(
                        db,
                        c"SELECT native_prefix_probe()".as_ptr(),
                        -1,
                        &mut statement,
                        ptr::null_mut(),
                    )
                }),
                ffi::SQLITE_OK
            );
            self.with_sqlite(|| unsafe {
                ffi::sqlite3_release_memory(c_int::MAX);
            });
            self.begin(7);
            let operation = self.op;
            let code = self.with_sqlite(|| unsafe { ffi::sqlite3_step(statement) });
            assert_eq!(self.op, operation, "同一 step 内不能切换 operation");
            assert_eq!(code, ffi::SQLITE_NOMEM);
            let report = self.failure(code);
            assert!(probe.setup_ok && probe.expected_returns && probe.unchanged);
            let events = probe.trace.observed();
            assert_eq!(
                events[0],
                CallbackEvent {
                    kind: 5,
                    size: 8200
                }
            );
            let second_roundup = events
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, event)| event.kind == 5)
                .unwrap()
                .0;
            assert!(
                events[1..second_roundup]
                    .iter()
                    .all(|event| matches!(event.kind, 2 | 4))
            );
            assert!(
                events[1..second_roundup]
                    .iter()
                    .any(|event| event.kind == 2)
            );
            assert_eq!(
                &events[second_roundup..],
                [
                    CallbackEvent {
                        kind: 5,
                        size: 8200
                    },
                    CallbackEvent {
                        kind: 1,
                        size: 8200
                    },
                    CallbackEvent {
                        kind: 4,
                        size: 8208
                    },
                ]
            );
            for (event, offset) in events.iter().zip(&probe.trace.offsets) {
                if matches!(event.kind, 2 | 3 | 4) {
                    assert!(*offset < self.layout.size());
                }
            }
            let state = [
                probe.occupied,
                probe.native_payload,
                probe.after_occupied,
                probe.after_payload,
            ];
            if unknown_after_success {
                // 两路都发生了已证 native quota；请求策略不再区分最终 NOMEM 来历。
                assert_eq!(report.outcome, Outcome::CBudgetExceeded);
                assert_eq!((report.code, report.reason, report.phase), (4, 4, 7));
                assert_eq!(events, diagnostic_trace.observed());
                assert_eq!(
                    &probe.trace.offsets[..events.len()],
                    &diagnostic_trace.offsets[..events.len()]
                );
                assert_eq!(state, diagnostic_state);
                recovered_report = report;
            } else {
                assert_eq!(report.outcome, Outcome::CBudgetExceeded);
                assert_eq!(report.reason, 4);
                diagnostic_trace.events = probe.trace.events;
                diagnostic_trace.offsets = probe.trace.offsets;
                diagnostic_trace.len = probe.trace.len;
                diagnostic_state = state;
            }
            self.begin(9);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_finalize(statement) }),
                ffi::SQLITE_NOMEM
            );
            self.begin(11);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_close(db) }),
                ffi::SQLITE_OK
            );
            assert_eq!(self.occupied, 0);
            assert_eq!(self.native_payload, 0);
            assert_eq!(
                self.with_sqlite(|| unsafe { ffi::sqlite3_memory_used() }),
                0
            );
        }
        recovered_report
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // 调用方只有在 shutdown 成功且无存活块后才可释放；否则保留至进程退出。
        if self.occupied == 0 {
            unsafe {
                dealloc(self.base, self.layout);
            }
        }
    }
}

unsafe fn payload_size(p: *mut c_void) -> c_int {
    unsafe { ((*p.cast::<u8>().sub(HEADER).cast::<Header>()).span - HEADER) as c_int }
}
fn active<T>(fallback: T, f: impl FnOnce(&mut Arena) -> T) -> T {
    // 仅从当前 FFI scope 的指针派生临时借用。allocator callback 不递归
    // 调 SQLite；测试 SQL callback 如需嵌套调用，必须用此借用再开 with_sqlite。
    ACTIVE.with(|p| {
        let p = p.get();
        if p.is_null() {
            fallback
        } else {
            unsafe { f(&mut *p) }
        }
    })
}
unsafe extern "C" fn xmalloc(n: c_int) -> *mut c_void {
    active(ptr::null_mut(), |a| unsafe {
        #[cfg(test)]
        a.trace.record(1, n as usize);
        a.native_pending = Denial::default();
        let p = a.malloc(n);
        #[cfg(test)]
        if p.is_null() {
            a.disarm_retry_release();
        }
        if !p.is_null() {
            a.native_payload += payload_size(p) as usize;
        }
        p
    })
}
unsafe extern "C" fn xfree(p: *mut c_void) {
    active((), |a| unsafe {
        #[cfg(test)]
        a.trace.record(
            2,
            if p.is_null() {
                0
            } else {
                payload_size(p) as usize
            },
        );
        #[cfg(test)]
        a.trace.pointer(a.base, p);
        if !p.is_null() {
            a.native_payload -= payload_size(p) as usize;
        }
        a.free(p);
        #[cfg(test)]
        if a.unknown_on_free {
            a.unclassified = true;
        }
    });
}
unsafe extern "C" fn xrealloc(p: *mut c_void, n: c_int) -> *mut c_void {
    active(ptr::null_mut(), |a| unsafe {
        #[cfg(test)]
        a.trace.record(3, n as usize);
        #[cfg(test)]
        a.trace.pointer(a.base, p);
        a.native_pending = Denial::default();
        let old = if p.is_null() {
            0
        } else {
            payload_size(p) as usize
        };
        let next = a.realloc(p, n);
        #[cfg(test)]
        if next.is_null() {
            a.disarm_retry_release();
        }
        if !next.is_null() {
            a.native_payload = a.native_payload - old + payload_size(next) as usize;
        }
        next
    })
}
unsafe extern "C" fn xsize(p: *mut c_void) -> c_int {
    let size = if p.is_null() {
        0
    } else {
        unsafe { payload_size(p) }
    };
    #[cfg(test)]
    active((), |a| {
        a.trace.record(4, size as usize);
        a.trace.pointer(a.base, p);
    });
    size
}
unsafe extern "C" fn xroundup(n: c_int) -> c_int {
    active(0, |a| {
        let rounded = a.native_roundup(n);
        #[cfg(test)]
        a.trace.record(5, rounded as usize);
        rounded
    })
}
unsafe extern "C" fn xinit(_: *mut c_void) -> c_int {
    #[cfg(test)]
    active((), |a| {
        if a.init_recovery {
            // 真实 initialize 的 xInit 回调内作一次可恢复的 pool 申请。
            // 不调用 SQLite、不申请系统内存；首个真实拒绝必须留在请求域。
            let held = a.occupy();
            let first = unsafe { a.malloc(8) };
            unsafe {
                a.free(first);
                a.release(held);
            }
            let recovered = unsafe { a.malloc(8) };
            a.init_recovery_ok = first.is_null() && !recovered.is_null();
            unsafe {
                a.free(recovered);
            }
        }
    });
    ffi::SQLITE_OK
}
unsafe extern "C" fn xshutdown(_: *mut c_void) {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ffi_scope_restores_nested_context_and_unwinds_without_owner_access() {
        let mut arena = Arena::new(256).unwrap();
        arena.start_request();
        arena.begin(3);
        arena.enter_calibration();
        arena.trace = CallbackTrace::default();
        assert!(!active(false, |_| true));
        // 纯 Rust 回调测试不安装 SQLite 全局 allocator，亦不以地址相等证明标签有效。
        let p = arena.with_sqlite(|| unsafe { xmalloc(24) });
        assert!(!p.is_null());
        assert!(!active(false, |_| true));
        arena.with_sqlite(|| {
            active((), |current| {
                current.begin(8);
                current.trace = CallbackTrace::default();
                assert_eq!(current.with_sqlite(|| unsafe { xsize(p) }), 32);
                let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    current.with_sqlite(|| panic!("仅测试 Rust scope unwind"));
                }));
                assert!(unwound.is_err());
                // 此时外层借用仍存活，不能用恢复的祖先 raw 再借用；只观察槽，
                // 后续调用继续从 current 派生新 scope。
                assert!(ACTIVE.with(|slot| !slot.get().is_null()));
                current.with_sqlite(|| unsafe {
                    xfree(p);
                });
            });
            assert_eq!(active(usize::MAX, |current| current.occupied), 0);
            let mut other = Arena::new(512).unwrap();
            other.with_sqlite(|| assert_eq!(active(0, |current| current.layout.size()), 512));
            drop(other);
            assert_eq!(
                active(0, |current| current.layout.size()),
                256,
                "另一个 owner 的 Drop 不得清掉外层 scope"
            );
        });
        assert!(!active(false, |_| true));
        assert!(
            unsafe { xmalloc(8) }.is_null(),
            "scope 外不得沿旧 context 访问 Arena"
        );
        assert_eq!(arena.occupied, 0);
        assert_eq!(arena.native_payload, 0);
        arena.leave_calibration();
    }
    #[test]
    fn arena_layout_realloc_and_fragmentation() {
        let mut a = Arena::new(256).unwrap();
        a.start_request();
        a.begin(2);
        assert_eq!(request_class(0), None);
        assert_eq!(request_class(usize::MAX), None);
        assert_eq!(a.rounded(0), 0);
        assert_eq!(a.rounded(-1), 0);
        for raw in 1..=232 {
            let class = request_class(raw).unwrap();
            assert!(class >= raw && class - raw <= 15);
            assert!((8..=23).contains(&(class + 8 - raw)));
            assert_eq!(class % 16, 8);
            assert_eq!(request_class(class), Some(class));
            assert_eq!(a.rounded(raw as c_int) as usize, class);
        }
        assert_eq!(a.rounded(233), 0);
        unsafe {
            let p = a.malloc(33);
            let q = a.malloc(40);
            let r = a.malloc(40);
            assert_eq!(p as usize % 16, 0);
            p.cast::<u8>().write(91);
            assert!(a.realloc(p, 100).is_null());
            assert_eq!(p.cast::<u8>().read(), 91);
            a.free(q);
            assert!(a.malloc(88).is_null());
            // 本测试前面的边界申请已拒绝；first 不能被后续碎片拒绝覆盖。
            assert_eq!(a.first_quota.reason, 3);
            assert_eq!(a.rounded(c_int::MAX), 0);
            assert!(a.realloc(p, 0).is_null());
            assert_eq!(p.cast::<u8>().read(), 91);
            a.free(r);
            a.free(p);
            let p = a.malloc(201);
            assert_eq!(a.rounded(201), 216);
            assert_eq!(payload_size(p), 240, "不能隐藏不可切的 16 字节尾部");
            assert_eq!(a.occupied, 256);
            assert_eq!(a.realloc(p, 201), p);
            a.free(p);
            assert_eq!(a.occupied, 0);
            let p = a.malloc(232);
            assert!(!p.is_null());
            assert_eq!(payload_size(p), 240);
            a.free(p);
        }
        assert!(a.peak <= 256);
        drop(a);
        let mut fragmented = Arena::new(256).unwrap();
        fragmented.start_request();
        fragmented.begin(2);
        unsafe {
            let left = fragmented.malloc(33);
            let middle = fragmented.malloc(40);
            let right = fragmented.malloc(40);
            fragmented.free(middle);
            assert!(fragmented.malloc(88).is_null());
            assert_eq!(fragmented.first_quota.reason, 2);
            fragmented.free(left);
            fragmented.free(right);
        }
        assert_eq!(fragmented.occupied, 0);
    }

    #[test]
    fn every_live_block_and_realloc_copy_stays_inside_backing() {
        let mut a = Arena::new(4096).unwrap();
        let mut slots = [ptr::null_mut::<c_void>(); 32];
        let mut sizes = [0usize; 32];
        let mut state = 17u32;
        for _ in 0..2000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let index = (state as usize >> 8) % slots.len();
            let n = (state as usize % 511) + 1;
            unsafe {
                if slots[index].is_null() {
                    let p = a.malloc(n as c_int);
                    if !p.is_null() {
                        p.cast::<u8>().write_bytes(index as u8, n);
                        slots[index] = p;
                        sizes[index] = n;
                    }
                } else if state & 1 == 0 {
                    a.free(slots[index]);
                    slots[index] = ptr::null_mut();
                    sizes[index] = 0;
                } else {
                    let old = slots[index];
                    let next = a.realloc(old, n as c_int);
                    let (p, check) = if next.is_null() {
                        (old, sizes[index])
                    } else {
                        (next, sizes[index].min(n))
                    };
                    assert!(
                        std::slice::from_raw_parts(p.cast::<u8>(), check)
                            .iter()
                            .all(|b| *b == index as u8)
                    );
                    if !next.is_null() {
                        next.cast::<u8>().write_bytes(index as u8, n);
                        slots[index] = next;
                        sizes[index] = n;
                    }
                }
                let mut offset = 0;
                let mut occupied = 0;
                while offset < a.layout.size() {
                    let h = &*a.base.add(offset).cast::<Header>();
                    assert_eq!(h.span % 16, 0);
                    assert!(h.span >= HEADER + 16);
                    if h.used != 0 {
                        assert_eq!((h.span - HEADER) % 16, 0);
                    }
                    assert!(offset + h.span <= a.layout.size());
                    if h.used != 0 {
                        occupied += h.span;
                    }
                    offset += h.span;
                }
                assert_eq!(offset, a.layout.size());
                assert_eq!(occupied, a.occupied);
                for (i, p) in slots.iter().enumerate() {
                    if p.is_null() {
                        continue;
                    }
                    assert_eq!(*p as usize % 16, 0);
                    assert!(*p as usize >= a.base as usize + HEADER);
                    assert!(
                        *p as usize + payload_size(*p) as usize
                            <= a.base as usize + a.layout.size()
                    );
                    for other in &slots[i + 1..] {
                        if !other.is_null() {
                            assert!(
                                *p as usize + payload_size(*p) as usize <= *other as usize
                                    || *other as usize + payload_size(*other) as usize
                                        <= *p as usize
                            );
                        }
                    }
                }
            }
        }
        for p in slots {
            unsafe {
                a.free(p);
            }
        }
        assert_eq!(a.occupied, 0);
        assert!(a.peak <= 4096);
    }
}
