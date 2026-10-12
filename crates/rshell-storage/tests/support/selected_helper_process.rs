use crate::helper::protocol::{RESULT_LEN, Request};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub enum End {
    Complete,
    Cancelled,
    TimedOut,
    ChildCrashed,
    ProtocolFailure,
    SpawnFailure,
}
#[derive(Debug)]
pub struct Completion {
    pub end: End,
    pub frame: Option<[u8; RESULT_LEN]>,
    pub status: Option<ExitStatus>,
    pub reaped: bool,
    pub joined: bool,
}

pub struct Signals {
    pub reserved: AtomicUsize,
    result_state: AtomicUsize,
    pub buffered: AtomicBool,
    pub killed: AtomicBool,
    pub hold_after_kill: AtomicBool,
    pub reaped: AtomicBool,
}
impl Signals {
    fn new() -> Self {
        Self {
            reserved: AtomicUsize::new(0),
            result_state: AtomicUsize::new(0),
            buffered: AtomicBool::new(false),
            killed: AtomicBool::new(false),
            hold_after_kill: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
        }
    }
    // 与最终接纳结果共享一个线性化点；已取消的 owner 永远不能接纳迟到成功。
    pub fn cancel(&self) -> bool {
        self.result_state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn cancelled(&self) -> bool {
        self.result_state.load(Ordering::SeqCst) == 1
    }
}
pub struct Running {
    pub signals: Arc<Signals>,
    receive: Option<mpsc::Receiver<Completion>>,
    join: Option<JoinHandle<()>>,
}
impl Running {
    pub fn finish(mut self) -> Completion {
        let result = self
            .receive
            .take()
            .unwrap()
            .recv_timeout(Duration::from_secs(35))
            .unwrap();
        self.join.take().unwrap().join().unwrap();
        result
    }
    pub fn drop_receiver(mut self) {
        drop(self.receive.take());
        self.signals.cancel();
        self.join.take().unwrap().join().unwrap();
        assert_eq!(self.signals.reserved.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            self.signals.hold_after_kill.store(false, Ordering::SeqCst);
            self.signals.cancel();
            // 父断言失败也仍等待唯一监督者，不留下 Child 或管道任务。
            let joined = join.join();
            if !thread::panicking() {
                assert!(joined.is_ok(), "监督者失败，不能声明已释放预约");
            }
        }
    }
}

pub struct Spec<'a> {
    pub path: &'a Path,
    pub request: Request,
    pub fault: Option<&'a str>,
    pub barrier: Option<(&'a str, &'a TcpListener)>,
    pub timeout: Duration,
    pub wire: Option<Vec<u8>>,
    pub nonexistent: bool,
    pub read_after_exit: bool,
}
impl<'a> Spec<'a> {
    pub fn normal(path: &'a Path, request: Request) -> Self {
        Self {
            path,
            request,
            fault: None,
            barrier: None,
            timeout: Duration::from_secs(10),
            wire: None,
            nonexistent: false,
            read_after_exit: false,
        }
    }
}

pub fn start(spec: Spec<'_>) -> Running {
    let signals = Arc::new(Signals::new());
    let s = signals.clone();
    let (tx, receive) = mpsc::channel();
    let mut command;
    let result_listener;
    if spec.fault.is_some() || spec.barrier.is_some() {
        command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "fault_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        result_listener = Some(TcpListener::bind("127.0.0.1:0").unwrap());
        command.env(
            "SELECTED_TEST_RESULT",
            result_listener
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap()
                .to_string(),
        );
        command.env("SELECTED_TEST_PATH", spec.path);
        if let Some(fault) = spec.fault {
            command.env("SELECTED_TEST_FAULT", fault);
        }
        if let Some((name, listener)) = spec.barrier {
            command.env("SELECTED_TEST_BARRIER", name).env(
                "SELECTED_TEST_CONTROL",
                listener.local_addr().unwrap().to_string(),
            );
        }
        command.stdout(Stdio::null()).stderr(Stdio::null());
    } else {
        command = Command::new(if spec.nonexistent {
            "nonexistent-selected-helper-executable"
        } else {
            env!("CARGO_BIN_EXE_selected-read-helper")
        });
        command
            .arg(spec.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        result_listener = None;
    }
    command.stdin(Stdio::piped());
    let cap = spec.request.cap;
    let wire = spec.wire.unwrap_or_else(|| spec.request.encode().to_vec());
    assert!(wire.len() <= 73);
    let timeout = spec.timeout;
    let read_after_exit = spec.read_after_exit;
    let join = thread::spawn(move || {
        s.reserved.store(cap, Ordering::SeqCst);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                s.reserved.store(0, Ordering::SeqCst);
                let _ = tx.send(Completion {
                    end: End::SpawnFailure,
                    frame: None,
                    status: None,
                    reaped: false,
                    joined: true,
                });
                return;
            }
        };
        let deadline = Instant::now() + timeout;
        let mut input = child.stdin.take().unwrap();
        // 请求最大 73 字节，写端由独立任务持有；收割还必须 join 写任务。
        let writer = thread::spawn(move || {
            let _ = input.write_all(&wire);
        });
        let source: Option<Box<dyn Read + Send>> = if let Some(listener) = result_listener {
            listener.set_nonblocking(true).unwrap();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        break Some(Box::new(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline || s.cancelled() {
                            break None;
                        }
                        if child.try_wait().unwrap().is_some() {
                            break listener.accept().ok().map(|(stream, _)| {
                                stream.set_nonblocking(false).unwrap();
                                Box::new(stream) as Box<dyn Read + Send>
                            });
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break None,
                }
            }
        } else {
            Some(Box::new(child.stdout.take().unwrap()))
        };
        let bad = Arc::new(AtomicBool::new(false));
        let stderr = child.stderr.take().map(|mut source| {
            let bad = bad.clone();
            thread::spawn(move || {
                // 正常入口不输出自由文本；只需一个字节便可检测意外泄漏。
                let mut byte = [0];
                let empty = matches!(source.read(&mut byte), Ok(0));
                if !empty {
                    bad.store(true, Ordering::SeqCst);
                }
                empty
            })
        });
        let reader = source.map(|mut source| {
            let signal = s.clone();
            let bad = bad.clone();
            thread::spawn(move || {
                if read_after_exit {
                    while !signal.reaped.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(2));
                    }
                }
                let mut frame = [0; RESULT_LEN];
                if source.read_exact(&mut frame).is_err() {
                    return None;
                }
                if &frame[..8] != b"SHSELRES"
                    || frame[8..10] != 1u16.to_le_bytes()
                    || u16::from_le_bytes([frame[10], frame[11]]) > 9
                {
                    bad.store(true, Ordering::SeqCst);
                    return None;
                }
                signal.buffered.store(true, Ordering::SeqCst);
                let mut extra = [0];
                if !matches!(source.read(&mut extra), Ok(0)) {
                    bad.store(true, Ordering::SeqCst);
                    return None;
                }
                Some(frame)
            })
        });
        let (end, status) = supervise(&mut child, &s, &bad, deadline);
        s.reaped.store(true, Ordering::SeqCst);
        let frame = reader.and_then(|h| h.join().unwrap());
        let stderr_empty = stderr.is_none_or(|h| h.join().unwrap());
        writer.join().unwrap();
        // wait 成功及所有管道任务结束之前绝不释放预约。
        s.reserved.store(0, Ordering::SeqCst);
        let end = if s
            .result_state
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            End::Cancelled
        } else if end == End::Complete && (frame.is_none() || !stderr_empty) {
            End::ProtocolFailure
        } else {
            end
        };
        let _ = tx.send(Completion {
            end,
            frame,
            status: Some(status),
            reaped: true,
            joined: true,
        });
    });
    Running {
        signals,
        receive: Some(receive),
        join: Some(join),
    }
}

fn supervise(
    child: &mut Child,
    s: &Signals,
    bad: &AtomicBool,
    deadline: Instant,
) -> (End, ExitStatus) {
    loop {
        let reason = if s.cancelled() {
            Some(End::Cancelled)
        } else if Instant::now() >= deadline {
            Some(End::TimedOut)
        } else if bad.load(Ordering::SeqCst) {
            Some(End::ProtocolFailure)
        } else {
            None
        };
        if let Some(reason) = reason {
            if child.kill().is_err() {
                assert!(
                    child
                        .try_wait()
                        .expect("kill 竞态后仍须核验真实退出")
                        .is_some(),
                    "无法终止存活 Child，保持预约并停止验收"
                );
            }
            s.killed.store(true, Ordering::SeqCst);
            while s.hold_after_kill.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(2));
            }
            let status = child.wait().expect("实际 wait 失败时保持预约并使测试失败");
            return (reason, status);
        }
        if let Some(status) = child
            .try_wait()
            .expect("实际 wait 失败时保持预约并使测试失败")
        {
            return (
                if status.success() {
                    End::Complete
                } else {
                    End::ChildCrashed
                },
                status,
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
}
pub fn barrier_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}
pub fn await_barrier(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok((mut s, _)) = listener.accept() {
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut b = [0];
            s.read_exact(&mut b).unwrap();
            return s;
        }
        assert!(Instant::now() < deadline, "未到达真实子进程屏障");
        thread::sleep(Duration::from_millis(2));
    }
}
pub fn await_flag(flag: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !flag.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}
