//! Windows x64 owned child 的 Rust allocator ABI 反证审计；不重编候选、不以峰值签证。
//! 断点仅改变被调试进程的内存；exe/source 的 SHA 在整个会话前后核验。

use crate::{
    Output, ReservedChild, helper::rust_budget::HelperRustCertificate, normal_candidate::Candidate,
    read_bounded,
};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    io::{Read, Write},
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type Handle = *mut c_void;
#[repr(C)]
struct DebugEvent {
    code: u32,
    process: u32,
    thread: u32,
    payload: [u64; 20],
}
#[repr(C, align(16))]
struct Context {
    bytes: [u8; 1232],
}
impl Context {
    fn read(thread: Handle) -> Self {
        let mut context = Self { bytes: [0; 1232] };
        context.bytes[48..52].copy_from_slice(&0x100003u32.to_le_bytes());
        checked(unsafe { GetThreadContext(thread, &mut context) });
        context
    }
    fn reg(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.bytes[offset..offset + 8].try_into().unwrap())
    }
    fn rip(&mut self, address: u64) {
        self.bytes[248..256].copy_from_slice(&address.to_le_bytes());
    }
    fn step(&mut self, enabled: bool) {
        let flags = u32::from_le_bytes(self.bytes[68..72].try_into().unwrap());
        self.bytes[68..72].copy_from_slice(
            &(if enabled {
                flags | 0x100
            } else {
                flags & !0x100
            })
            .to_le_bytes(),
        );
    }
    fn write(&self, thread: Handle) {
        checked(unsafe { SetThreadContext(thread, self) });
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WaitForDebugEvent(event: *mut DebugEvent, milliseconds: u32) -> i32;
    fn ContinueDebugEvent(process: u32, thread: u32, status: u32) -> i32;
    fn DebugActiveProcessStop(process: u32) -> i32;
    fn GetThreadContext(thread: Handle, context: *mut Context) -> i32;
    fn SetThreadContext(thread: Handle, context: *const Context) -> i32;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        process: Handle,
        address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn FlushInstructionCache(process: Handle, address: *const c_void, size: usize) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}
fn checked(result: i32) {
    assert!(
        result != 0,
        "owned debugger API failed: {:?}",
        std::io::Error::last_os_error().raw_os_error()
    );
}
fn memory<const N: usize>(process: Handle, address: u64) -> [u8; N] {
    let mut bytes = [0; N];
    let mut read = 0;
    checked(unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            N,
            &mut read,
        )
    });
    assert_eq!(read, N);
    bytes
}
fn byte(process: Handle, address: u64, value: u8) {
    let mut written = 0;
    checked(unsafe {
        WriteProcessMemory(
            process,
            address as *mut c_void,
            (&value as *const u8).cast(),
            1,
            &mut written,
        )
    });
    assert_eq!(written, 1);
    checked(unsafe { FlushInstructionCache(process, address as *const c_void, 1) });
}
fn close_file(handle: u64) {
    if handle != 0 {
        checked(unsafe { CloseHandle(handle as Handle) });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Alloc,
    Zeroed,
    Realloc,
    Free,
    Run,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Bootstrap,
    Path,
    C,
}
#[derive(Clone, Copy)]
struct Block {
    size: usize,
    align: usize,
    class: Class,
}
#[derive(Clone, Copy)]
struct Pending {
    operation: Operation,
    pointer: u64,
    block: Block,
}
struct Breakpoint {
    original: u8,
    operation: Option<Operation>,
    pending: Vec<(u32, Pending)>,
}

/// 地址来自同一 PE 的 section map 和匹配 GUID/Age 的 PDB，而非复制另一 build 的地址。
fn symbols(candidate: &Candidate) -> Vec<(u64, Operation)> {
    let exe = candidate.executable();
    let mut file = std::fs::File::open(exe).unwrap();
    let mut image = Vec::new();
    file.read_to_end(&mut image).unwrap();
    let u16_at =
        |offset| u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap()) as usize;
    let u32_at =
        |offset| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()) as usize;
    let pe = u32_at(0x3c);
    assert_eq!(&image[pe..pe + 4], b"PE\0\0");
    assert_eq!(u16_at(pe + 4), 0x8664);
    let section_table = pe + 24 + u16_at(pe + 20);
    let sections: Vec<_> = (0..u16_at(pe + 6))
        .map(|i| {
            let at = section_table + 40 * i;
            (u32_at(at + 12), u32_at(at + 16), u32_at(at + 20))
        })
        .collect();
    let rva_file = |rva: usize| {
        let (base, _, raw) = sections
            .iter()
            .find(|(base, size, _)| rva >= *base && rva < base + size)
            .unwrap();
        raw + rva - base
    };
    let optional = pe + 24;
    assert_eq!(u16_at(optional), 0x20b);
    let debug = rva_file(u32_at(optional + 112 + 8 * 6));
    let debug_size = u32_at(optional + 112 + 8 * 6 + 4);
    let entry = (0..debug_size / 28)
        .map(|i| debug + i * 28)
        .find(|at| u32_at(at + 12) == 2)
        .unwrap();
    let codeview = u32_at(entry + 24);
    assert_eq!(&image[codeview..codeview + 4], b"RSDS");
    let guid = uuid::Uuid::from_bytes_le(image[codeview + 4..codeview + 20].try_into().unwrap());
    let age = u32_at(codeview + 20);
    let name = &image[codeview + 24..codeview + u32_at(entry + 16)];
    let name = std::str::from_utf8(name.strip_suffix(&[0]).unwrap()).unwrap();
    assert!(std::path::Path::new(name).components().count() == 1);
    let pdb = exe.parent().unwrap().join(name);
    let summary = Command::new("llvm-pdbutil")
        .args(["dump", "--summary"])
        .arg(&pdb)
        .output()
        .unwrap();
    assert!(summary.status.success());
    let text = std::str::from_utf8(&summary.stdout).unwrap();
    let field = |prefix: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(prefix))
            .unwrap()
    };
    assert_eq!(uuid::Uuid::parse_str(field("GUID: ")).unwrap(), guid);
    assert_eq!(field("Age: ").parse::<usize>().unwrap(), age);
    let publics = Command::new("llvm-pdbutil")
        .args(["dump", "--publics"])
        .arg(&pdb)
        .output()
        .unwrap();
    assert!(publics.status.success());
    let text = std::str::from_utf8(&publics.stdout).unwrap();
    let mut result = Vec::new();
    let mut operation = None;
    for line in text.lines() {
        if line.contains("S_PUB32") {
            operation = if line.ends_with("12___rust_alloc`") {
                Some(Operation::Alloc)
            } else if line.ends_with("19___rust_alloc_zeroed`") {
                Some(Operation::Zeroed)
            } else if line.ends_with("14___rust_realloc`") {
                Some(Operation::Realloc)
            } else if line.ends_with("14___rust_dealloc`") {
                Some(Operation::Free)
            } else if line.contains("9normal_v23run") {
                Some(Operation::Run)
            } else {
                None
            };
        } else if let Some(op) = operation.take() {
            let address = line.split("addr = ").nth(1).unwrap();
            let (section, offset) = address.trim().split_once(':').unwrap();
            let section = section.parse::<usize>().unwrap();
            let offset = offset.parse::<u64>().unwrap();
            result.push((sections[section - 1].0 as u64 + offset, op));
        }
    }
    assert_eq!(
        result.len(),
        5,
        "必须覆盖同一候选的四个 allocator ABI 与 normal-v2 run"
    );
    result
}

pub struct Audit {
    pub allocations: usize,
    pub after_run: usize,
    pub rust_peak: usize,
    pub c_peak: usize,
    held: usize,
    c_held: usize,
    live: BTreeMap<u64, Block>,
    entered_run: bool,
    path_seen: bool,
    c_seen: bool,
    certificate: HelperRustCertificate,
}
impl Audit {
    fn reserve(&mut self, size: usize, align: usize) -> Block {
        self.allocations += 1;
        let class = if !self.entered_run {
            Class::Bootstrap
        } else if !self.path_seen && size == self.certificate.costs().path && align == 1 {
            self.path_seen = true;
            Class::Path
        } else if !self.c_seen
            && size == self.certificate.c_backing().size()
            && align == self.certificate.c_backing().align()
        {
            self.c_seen = true;
            Class::C
        } else {
            panic!("normal producer 出现无源界 Rust allocation: size={size} align={align}")
        };
        if self.entered_run {
            self.after_run += 1;
        }
        if class == Class::C {
            self.c_held += size;
            self.c_peak = self.c_peak.max(self.c_held);
            assert!(self.c_held <= self.certificate.c_backing().size());
        } else {
            self.held += size;
            self.rust_peak = self.rust_peak.max(self.held);
            assert!(self.held <= self.certificate.rust_max());
            if !self.entered_run {
                assert!(
                    self.held
                        <= self.certificate.costs().argv + self.certificate.costs().stdio_globals
                );
            }
        }
        Block { size, align, class }
    }
    fn unhold(&mut self, block: Block) {
        if block.class == Class::C {
            self.c_held -= block.size;
        } else {
            self.held -= block.size;
        }
    }
    fn complete(&mut self, pending: Pending, pointer: u64) {
        match pending.operation {
            Operation::Free => {
                let block = self.live.remove(&pending.pointer).unwrap();
                self.unhold(block);
            }
            Operation::Realloc => {
                if pointer != 0 {
                    let old = self.live.remove(&pending.pointer).unwrap();
                    self.unhold(old);
                }
                if pointer == 0 {
                    self.unhold(pending.block);
                } else {
                    assert!(self.live.insert(pointer, pending.block).is_none());
                }
            }
            Operation::Alloc | Operation::Zeroed => {
                if pointer == 0 {
                    self.unhold(pending.block);
                } else {
                    assert!(self.live.insert(pointer, pending.block).is_none());
                }
            }
            Operation::Run => unreachable!(),
        }
    }
}

struct DebugChild {
    owner: ReservedChild,
    attached: bool,
}
impl Drop for DebugChild {
    fn drop(&mut self) {
        if self.attached {
            let _ = self.owner.child.kill();
            unsafe {
                DebugActiveProcessStop(self.owner.child.id());
            }
        }
    }
}

pub fn run(
    candidate: &mut Candidate,
    database: &std::path::Path,
    request: crate::wire::WireValidatedRequest,
    certificate: HelperRustCertificate,
) -> (Output, Audit) {
    let symbols = symbols(candidate);
    let full = certificate.spawn_bytes().unwrap();
    let ledger = crate::normal_candidate::Ledger::new(full);
    let grant = ledger.reserve(full).unwrap();
    assert!(ledger.reserve(1).is_none());
    let mut command = Command::new(candidate.executable());
    command
        .creation_flags(2)
        .arg(database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert!(command.get_envs().next().is_none());
    let child = command.spawn().unwrap();
    let mut debug = DebugChild {
        owner: ReservedChild {
            child,
            stdout: None,
            stderr: None,
            reservation: Some(grant),
        },
        attached: true,
    };
    let stdout = debug.owner.child.stdout.take().unwrap();
    let stderr = debug.owner.child.stderr.take().unwrap();
    let cap = request.limits().wire_max as usize;
    debug.owner.stdout = Some(thread::spawn(move || read_bounded(stdout, cap)));
    debug.owner.stderr = Some(thread::spawn(move || read_bounded(stderr, 128)));
    debug
        .owner
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(&request.encode())
        .unwrap();
    let process = debug.owner.child.as_raw_handle();
    let mut threads = BTreeMap::new();
    let mut breakpoints: BTreeMap<u64, Breakpoint> = BTreeMap::new();
    let mut stepping = BTreeMap::new();
    let mut audit = Audit {
        allocations: 0,
        after_run: 0,
        rust_peak: 0,
        c_peak: 0,
        held: 0,
        c_held: 0,
        live: BTreeMap::new(),
        entered_run: false,
        path_seen: false,
        c_seen: false,
        certificate,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(Instant::now() < deadline, "owned allocation audit timeout");
        let mut event = DebugEvent {
            code: 0,
            process: 0,
            thread: 0,
            payload: [0; 20],
        };
        if unsafe { WaitForDebugEvent(&mut event, 1000) } == 0 {
            continue;
        }
        assert_eq!(event.process, debug.owner.child.id());
        let mut status = 0x10002;
        match event.code {
            3 => {
                threads.insert(event.thread, event.payload[2] as Handle);
                close_file(event.payload[0]);
                let base = event.payload[3];
                for (offset, operation) in &symbols {
                    let address = base + offset;
                    let original = memory::<1>(process, address)[0];
                    assert_ne!(original, 0xcc);
                    breakpoints.insert(
                        address,
                        Breakpoint {
                            original,
                            operation: Some(*operation),
                            pending: Vec::new(),
                        },
                    );
                    byte(process, address, 0xcc);
                }
            }
            2 => {
                threads.insert(event.thread, event.payload[0] as Handle);
            }
            4 => {
                threads.remove(&event.thread);
            }
            6 => close_file(event.payload[0]),
            1 => {
                let exception = event.payload[0] as u32;
                if exception == 0x80000004 && stepping.contains_key(&event.thread) {
                    let address = stepping.remove(&event.thread).unwrap();
                    let bp = breakpoints.get(&address).unwrap();
                    if bp.operation.is_some() || !bp.pending.is_empty() {
                        byte(process, address, 0xcc);
                    }
                    let thread = threads[&event.thread];
                    let mut context = Context::read(thread);
                    context.step(false);
                    context.write(thread);
                } else if exception == 0x80000003 {
                    let address = event.payload[2];
                    if let Some(bp) = breakpoints.get_mut(&address) {
                        let thread = threads[&event.thread];
                        let mut context = Context::read(thread);
                        byte(process, address, bp.original);
                        context.rip(address);
                        if let Some(index) =
                            bp.pending.iter().rposition(|(tid, _)| *tid == event.thread)
                        {
                            let (_, pending) = bp.pending.remove(index);
                            audit.complete(pending, context.reg(120));
                        } else if let Some(operation) = bp.operation {
                            if operation == Operation::Run {
                                audit.entered_run = true;
                                bp.operation = None;
                            } else {
                                let pending = if operation == Operation::Free {
                                    let pointer = context.reg(128);
                                    let block = *audit.live.get(&pointer).unwrap();
                                    assert_eq!(block.size, context.reg(136) as usize);
                                    assert_eq!(block.align, context.reg(184) as usize);
                                    Pending {
                                        operation,
                                        pointer,
                                        block,
                                    }
                                } else if operation == Operation::Realloc {
                                    let pointer = context.reg(128);
                                    let old = *audit.live.get(&pointer).unwrap();
                                    assert_eq!(old.size, context.reg(136) as usize);
                                    assert_eq!(old.align, context.reg(184) as usize);
                                    Pending {
                                        operation,
                                        pointer,
                                        block: audit.reserve(context.reg(192) as usize, old.align),
                                    }
                                } else {
                                    Pending {
                                        operation,
                                        pointer: 0,
                                        block: audit.reserve(
                                            context.reg(128) as usize,
                                            context.reg(136) as usize,
                                        ),
                                    }
                                };
                                let target =
                                    u64::from_le_bytes(memory::<8>(process, context.reg(152)));
                                let original = memory::<1>(process, target)[0];
                                let target_bp =
                                    breakpoints.entry(target).or_insert_with(|| Breakpoint {
                                        original,
                                        operation: None,
                                        pending: Vec::new(),
                                    });
                                target_bp.pending.push((event.thread, pending));
                                byte(process, target, 0xcc);
                            }
                        }
                        let bp = breakpoints.get(&address).unwrap();
                        if bp.operation.is_some() || !bp.pending.is_empty() {
                            stepping.insert(event.thread, address);
                            context.step(true);
                        }
                        context.write(thread);
                    }
                    // 初始 loader breakpoint 不属于 allocator；它没有用户 payload 或 owned grant 释放。
                } else {
                    status = 0x80010001;
                }
            }
            _ => {}
        }
        checked(unsafe { ContinueDebugEvent(event.process, event.thread, status) });
        if event.code == 5 {
            debug.attached = false;
            break;
        }
    }
    let status = debug.owner.child.wait().unwrap();
    assert_eq!(ledger.held(), full);
    let stdout = debug.owner.stdout.take().unwrap().join();
    let stderr = debug.owner.stderr.take().unwrap().join();
    assert_eq!(ledger.held(), full);
    let output = Output {
        stdout: stdout.unwrap(),
        stderr: stderr.unwrap(),
        status,
    };
    assert!(audit.entered_run);
    assert_eq!(audit.c_held, 0);
    assert!(
        audit
            .live
            .values()
            .all(|block| block.class == Class::Bootstrap)
    );
    assert_eq!(
        audit.held, 12288,
        "真正 process exit 前只保留进程寿命 stdin global"
    );
    candidate.verify_unchanged();
    drop(debug);
    assert_eq!(ledger.held(), 0);
    (output, audit)
}
