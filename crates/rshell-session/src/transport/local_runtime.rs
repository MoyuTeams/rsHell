use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use portable_pty::{Child, MasterPty, PtySize};
use rshell_core::{ExitStatus, SessionFailure, TerminalSize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::{TransportError, TransportEvent};

use super::local_reader::ReaderEvent;

mod lifecycle;

pub(super) use lifecycle::join_reader_thread;

const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const FORCE_EXIT_GRACE: Duration = Duration::from_millis(250);
const READER_CLOSE_GRACE: Duration = Duration::from_millis(100);
const READER_DRAIN_LIMIT: usize = 32;
#[cfg(unix)]
const READER_JOIN_GRACE: Duration = Duration::from_millis(1_250);
#[cfg(windows)]
const READER_JOIN_GRACE: Duration = Duration::from_millis(600);
/// 已入队但尚未写入 PTY 的字节上限；队列满时 `write` 异步等待空间，而不是阻塞运行时线程。
pub(super) const WRITER_QUEUE_LIMIT: usize = 4 * 1024 * 1024;
/// 单次入队的分块大小；大于上限的写入按块入队，取消时只丢弃尚未入队的块。
const WRITE_CHUNK_SIZE: usize = 64 * 1024;

pub(super) struct LocalRuntime {
    master: Option<Box<dyn MasterPty>>,
    #[cfg(unix)]
    process_group: Option<i32>,
    #[cfg(windows)]
    process_job: Option<rshell_platform::WindowsProcessJob>,
    writer: Option<PtyWriter>,
    writer_thread: Option<JoinHandle<()>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    reader_rx: mpsc::Receiver<ReaderEvent>,
    reader_thread: Option<JoinHandle<()>>,
    pending_exit: Option<ExitStatus>,
    reader_eof: bool,
    exit_emitted: bool,
    shut_down: bool,
}

impl LocalRuntime {
    pub(super) fn new(
        master: Box<dyn MasterPty>,
        writer: PtyWriter,
        writer_thread: JoinHandle<()>,
        child: Box<dyn Child + Send + Sync>,
        reader_rx: mpsc::Receiver<ReaderEvent>,
        reader_thread: JoinHandle<()>,
        #[cfg(windows)] process_job: rshell_platform::WindowsProcessJob,
    ) -> Self {
        #[cfg(unix)]
        let process_group = master.process_group_leader();
        Self {
            master: Some(master),
            #[cfg(unix)]
            process_group,
            #[cfg(windows)]
            process_job: Some(process_job),
            writer: Some(writer),
            writer_thread: Some(writer_thread),
            child: Some(child),
            reader_rx,
            reader_thread: Some(reader_thread),
            pending_exit: None,
            reader_eof: false,
            exit_emitted: false,
            shut_down: false,
        }
    }

    pub(super) fn process_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|child| child.process_id())
    }

    #[cfg(windows)]
    pub(super) fn process_tree_contains(&self, process_id: u32) -> Result<bool, TransportError> {
        self.process_job
            .as_ref()
            .ok_or_else(pty_error)?
            .contains_process(process_id)
            .map_err(|_| pty_error())
    }

    pub(super) async fn next_event(&mut self) -> Result<TransportEvent, TransportError> {
        if self.exit_emitted || self.shut_down {
            return Err(pty_error());
        }
        loop {
            match self.reader_rx.try_recv() {
                Ok(event) => {
                    if let Some(event) = self.handle_reader_event(event)? {
                        return Ok(event);
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => self.reader_eof = true,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }

            self.poll_child()?;
            if self.reader_eof
                && let Some(status) = self.pending_exit.take()
            {
                self.join_reader()?;
                self.exit_emitted = true;
                return Ok(TransportEvent::Exit(status));
            }

            if self.reader_eof {
                tokio::time::sleep(CHILD_POLL_INTERVAL).await;
            } else {
                match tokio::time::timeout(CHILD_POLL_INTERVAL, self.reader_rx.recv()).await {
                    Ok(Some(event)) => {
                        if let Some(event) = self.handle_reader_event(event)? {
                            return Ok(event);
                        }
                    }
                    Ok(None) => self.reader_eof = true,
                    Err(_) => {}
                }
            }
        }
    }

    /// 把输入交给专用写线程；返回表示已入队，写线程的失败由之后的 `write` 报告。
    pub(super) async fn write(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.writer
            .as_ref()
            .ok_or_else(pty_error)?
            .write(bytes)
            .await
    }

    pub(super) fn resize(&mut self, size: TerminalSize) -> Result<(), TransportError> {
        let size = checked_pty_size(size)?;
        self.master
            .as_ref()
            .ok_or_else(pty_error)?
            .resize(size)
            .map_err(|_| pty_error())
    }

    fn handle_reader_event(
        &mut self,
        event: ReaderEvent,
    ) -> Result<Option<TransportEvent>, TransportError> {
        match event {
            ReaderEvent::Output(bytes) => Ok(Some(TransportEvent::Output(bytes))),
            ReaderEvent::Eof => {
                self.reader_eof = true;
                Ok(None)
            }
            ReaderEvent::Failure => Err(pty_error()),
        }
    }

    fn poll_child(&mut self) -> Result<(), TransportError> {
        if self.pending_exit.is_some() {
            return Ok(());
        }
        let Some(child) = self.child.as_mut() else {
            return Err(pty_error());
        };
        if let Some(status) = child.try_wait().map_err(|_| pty_error())? {
            self.pending_exit = Some(exit_status(status));
            self.writer.take();
            self.master.take();
        }
        Ok(())
    }
}

/// 待写入的块与其占用的字节额度；块写完（或被丢弃）时额度归还。
type WriteChunk = (Vec<u8>, OwnedSemaphorePermit);

struct WriterShared {
    /// 按字节计的队列额度，总量为 `WRITER_QUEUE_LIMIT`。
    budget: Arc<Semaphore>,
    failed: AtomicBool,
    closed: AtomicBool,
}

/// 本地 PTY 输入端：入队在调用方异步完成，实际写入只发生在专用写线程上。
pub(super) struct PtyWriter {
    sender: std_mpsc::Sender<WriteChunk>,
    shared: Arc<WriterShared>,
}

impl PtyWriter {
    /// 按块申请字节额度后入队。额度申请可被取消：已入队的块保持顺序写出，未入队的部分不写。
    pub(super) async fn write(&self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.shared.failed.load(Ordering::Acquire) {
            return Err(pty_error());
        }
        for chunk in bytes.chunks(WRITE_CHUNK_SIZE) {
            let permits = u32::try_from(chunk.len()).map_err(|_| pty_error())?;
            let permit = Arc::clone(&self.shared.budget)
                .acquire_many_owned(permits)
                .await
                .map_err(|_| pty_error())?;
            self.sender
                .send((chunk.to_vec(), permit))
                .map_err(|_| pty_error())?;
        }
        Ok(())
    }
}

impl Drop for PtyWriter {
    fn drop(&mut self) {
        // 关闭后写线程丢弃尚未写出的块；正在进行的那次写入由子进程退出或 PTY 关闭来打断。
        self.shared.closed.store(true, Ordering::Release);
    }
}

pub(super) fn spawn_writer(
    writer: Box<dyn Write + Send>,
) -> io::Result<(PtyWriter, JoinHandle<()>)> {
    let (sender, receiver) = std_mpsc::channel();
    let shared = Arc::new(WriterShared {
        budget: Arc::new(Semaphore::new(WRITER_QUEUE_LIMIT)),
        failed: AtomicBool::new(false),
        closed: AtomicBool::new(false),
    });
    let thread_shared = Arc::clone(&shared);
    let thread = thread::Builder::new()
        .name("rshell-local-pty-writer".to_owned())
        .spawn(move || write_loop(writer, &receiver, &thread_shared))?;
    Ok((PtyWriter { sender, shared }, thread))
}

fn write_loop(
    mut writer: Box<dyn Write + Send>,
    receiver: &std_mpsc::Receiver<WriteChunk>,
    shared: &WriterShared,
) {
    while let Ok((bytes, permit)) = receiver.recv() {
        if shared.closed.load(Ordering::Acquire) {
            continue;
        }
        let result = writer.write_all(&bytes).and_then(|()| writer.flush());
        drop(permit);
        if result.is_err() {
            shared.failed.store(true, Ordering::Release);
            // 唤醒等待额度的 `write`，让它立即返回错误。
            shared.budget.close();
            return;
        }
    }
}

pub(super) fn checked_pty_size(size: TerminalSize) -> Result<PtySize, TransportError> {
    if size.cols == 0 || size.rows == 0 {
        return Err(TransportError::new(SessionFailure::Validation));
    }
    #[cfg(windows)]
    if size.cols > i16::MAX as u16 || size.rows > i16::MAX as u16 {
        return Err(TransportError::new(SessionFailure::Validation));
    }
    Ok(PtySize {
        rows: size.rows,
        cols: size.cols,
        pixel_width: u16::try_from(size.pixel_width)
            .map_err(|_| TransportError::new(SessionFailure::Validation))?,
        pixel_height: u16::try_from(size.pixel_height)
            .map_err(|_| TransportError::new(SessionFailure::Validation))?,
    })
}

fn exit_status(status: portable_pty::ExitStatus) -> ExitStatus {
    ExitStatus {
        code: i32::try_from(status.exit_code()).ok(),
        success: status.success(),
    }
}

fn pty_error() -> TransportError {
    TransportError::new(SessionFailure::Pty)
}
