use std::{
    io::{self, Write},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use rshell_core::SessionFailure;
use tokio::sync::mpsc;

use super::{
    local_reader::ReaderEvent,
    local_runtime::{WRITER_QUEUE_LIMIT, join_reader_thread, spawn_writer},
};

/// 在闸门打开前阻塞每次写入的假 PTY 输入端，用来模拟不读 stdin 的子进程。
#[derive(Clone, Default)]
struct GatedWriter {
    gate: Arc<(Mutex<bool>, Condvar)>,
    written: Arc<Mutex<Vec<u8>>>,
    entered: Arc<AtomicBool>,
    fail: bool,
}

impl GatedWriter {
    fn open(&self) {
        let (open, wake) = &*self.gate;
        *open.lock().unwrap() = true;
        wake.notify_all();
    }

    fn written(&self) -> Vec<u8> {
        self.written.lock().unwrap().clone()
    }
}

impl Write for GatedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered.store(true, Ordering::Release);
        let (open, wake) = &*self.gate;
        let _open = wake
            .wait_while(open.lock().unwrap(), |open| !*open)
            .unwrap();
        if self.fail {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.written.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn wait_for_thread(thread: &JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !thread.is_finished() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("writer thread must exit in bounded time");
}

#[tokio::test(flavor = "current_thread")]
async fn full_writer_queue_awaits_without_blocking_and_cancels_cleanly() {
    let pty = GatedWriter::default();
    let (writer, thread) = spawn_writer(Box::new(pty.clone())).expect("spawn writer");
    let payload: Vec<u8> = (0..WRITER_QUEUE_LIMIT).map(|index| index as u8).collect();

    tokio::time::timeout(Duration::from_secs(1), writer.write(&payload))
        .await
        .expect("a queue-sized write must enqueue without waiting on the PTY")
        .expect("enqueue succeeds");
    tokio::time::timeout(Duration::from_millis(100), writer.write(b"cancelled"))
        .await
        .expect_err("a full queue must make the write wait instead of blocking the runtime");

    pty.open();
    writer
        .write(b"after")
        .await
        .expect("write after cancellation");
    let mut expected = payload;
    expected.extend_from_slice(b"after");
    tokio::time::timeout(Duration::from_secs(2), async {
        while pty.written().len() < expected.len() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("queued bytes drain once the PTY accepts input");
    drop(writer);
    wait_for_thread(&thread).await;
    thread.join().expect("writer thread");

    assert!(
        pty.written() == expected,
        "queued bytes must be written in order and the cancelled write must be dropped"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn closing_the_writer_discards_queued_bytes() {
    let pty = GatedWriter::default();
    let (writer, thread) = spawn_writer(Box::new(pty.clone())).expect("spawn writer");
    writer.write(b"first").await.expect("first chunk");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !pty.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("writer thread must start the first write");
    writer.write(b"queued").await.expect("queued chunk");
    drop(writer);
    pty.open();
    wait_for_thread(&thread).await;
    thread.join().expect("writer thread");
    assert_eq!(pty.written(), b"first");
}

#[tokio::test(flavor = "current_thread")]
async fn writer_failure_is_reported_by_the_next_write() {
    let pty = GatedWriter {
        fail: true,
        ..GatedWriter::default()
    };
    pty.open();
    let (writer, thread) = spawn_writer(Box::new(pty.clone())).expect("spawn writer");
    writer.write(b"lost").await.expect("enqueue before failure");
    wait_for_thread(&thread).await;
    let error = writer
        .write(b"next")
        .await
        .expect_err("a failed writer must reject later input");
    assert_eq!(error.failure(), SessionFailure::Pty);
    thread.join().expect("writer thread");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receiver_close_unblocks_a_sender_but_remains_a_pty_failure() {
    let (sender, mut receiver) = mpsc::channel(1);
    let (started_sender, started_receiver) = std_mpsc::channel();
    let thread = thread::spawn(move || {
        started_sender.send(()).unwrap();
        while sender.blocking_send(ReaderEvent::Output(vec![1])).is_ok() {}
    });
    started_receiver.recv().unwrap();

    let error = tokio::time::timeout(
        Duration::from_millis(500),
        join_reader_thread(&mut receiver, thread, Duration::from_millis(30)),
    )
    .await
    .expect("reader close cleanup must remain bounded")
    .expect_err("receiver-forced completion is not natural convergence");
    assert_eq!(error.failure(), SessionFailure::Pty);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn natural_reader_completion_before_the_deadline_succeeds() {
    let (sender, mut receiver) = mpsc::channel(1);
    let (started_sender, started_receiver) = std_mpsc::channel();
    let (release_sender, release_receiver) = std_mpsc::channel();
    let thread = thread::spawn(move || {
        started_sender.send(()).unwrap();
        release_receiver.recv().unwrap();
        drop(sender);
    });
    started_receiver.recv().unwrap();
    release_sender.send(()).unwrap();

    tokio::time::timeout(
        Duration::from_secs(2),
        join_reader_thread(&mut receiver, thread, Duration::from_millis(1_250)),
    )
    .await
    .expect("natural reader completion must remain bounded")
    .expect("natural reader completion must succeed");
}
