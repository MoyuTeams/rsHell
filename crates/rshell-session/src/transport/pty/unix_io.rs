//! Unix PTY master 的读写端。
//!
//! master 的打开文件描述设为非阻塞，读线程与写线程各持一份描述符副本，在 `read(2)`/`write(2)`
//! 返回 `EAGAIN` 时等待可读/可写，而不是阻塞在系统调用里。子进程不读 stdin 时，Linux 上阻塞在
//! master 上的 `write(2)` 在子进程退出后也不会返回（写端自身仍持有 master），因此写线程同时
//! 等待一条唤醒管道：输入端关闭时管道随之关闭，写入立即以错误结束。

use std::{
    fs::File,
    io::{self, PipeReader, PipeWriter, Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
};

/// 读、写两端与唤醒管道的写端；后者交给 `PtyWriter`，随输入端一起关闭。
pub(super) type MasterIo = (Box<dyn Read + Send>, Box<dyn Write + Send>, PipeWriter);

/// 把 master 设为非阻塞，并为读线程、写线程各复制一份描述符。
pub(super) fn split_master(master: RawFd) -> io::Result<MasterIo> {
    // SAFETY: `master` 属于调用方持有的 MasterPty，在本函数返回前一直有效。
    let master = unsafe { BorrowedFd::borrow_raw(master) };
    set_nonblocking(master)?;
    let output = File::from(master.try_clone_to_owned()?);
    let input = File::from(master.try_clone_to_owned()?);
    let (wake, closer) = io::pipe()?;
    Ok((
        Box::new(PtyOutput { file: output }),
        Box::new(PtyInput { file: input, wake }),
        closer,
    ))
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// PTY 输出端：暂无数据时等待可读。PTY 关闭后的 `EIO` 由读线程按 EOF 处理。
struct PtyOutput {
    file: File,
}

impl Read for PtyOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut hung_up = false;
        loop {
            match self.file.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if hung_up {
                        // 已报告挂断却仍无数据：按 PTY 关闭处理，避免空转。
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                    hung_up = wait(self.file.as_fd(), Interest::Read, None)? == Ready::HungUp;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
}

/// PTY 输入端：PTY 写满时等待可写；唤醒管道关闭（输入端关闭）时放弃当前写入。
struct PtyInput {
    file: File,
    wake: PipeReader,
}

impl Write for PtyInput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            match self.file.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    match wait(self.file.as_fd(), Interest::Write, Some(self.wake.as_fd()))? {
                        Ready::Io => {}
                        Ready::HungUp => return Err(io::Error::from_raw_os_error(libc::EIO)),
                        Ready::Woken => return Err(io::ErrorKind::BrokenPipe.into()),
                    }
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PtyInput {
    /// 关闭输入端时送出换行与 VEOF，让 shell 自行退出；PTY 已写满时直接放弃，不等待。
    fn drop(&mut self) {
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(self.file.as_raw_fd(), termios.as_mut_ptr()) } != 0 {
            return;
        }
        let eof = unsafe { termios.assume_init() }.c_cc[libc::VEOF];
        if eof != 0 {
            let _ = self.file.write(&[b'\n', eof]);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interest {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ready {
    /// 描述符就绪（或出现需要由下一次读写报告的状态）。
    Io,
    /// 描述符只报告了挂断或错误。
    #[cfg_attr(target_vendor = "apple", allow(dead_code))]
    HungUp,
    /// 唤醒管道已关闭。
    Woken,
}

fn wait(fd: BorrowedFd<'_>, interest: Interest, wake: Option<BorrowedFd<'_>>) -> io::Result<Ready> {
    loop {
        match wait_once(fd.as_raw_fd(), interest, wake.map(|wake| wake.as_raw_fd())) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

#[cfg(not(target_vendor = "apple"))]
fn wait_once(fd: RawFd, interest: Interest, wake: Option<RawFd>) -> io::Result<Ready> {
    let events = match interest {
        Interest::Read => libc::POLLIN,
        Interest::Write => libc::POLLOUT,
    };
    let mut fds = [
        libc::pollfd {
            fd,
            events,
            revents: 0,
        },
        // 负描述符的条目被 poll 忽略。
        libc::pollfd {
            fd: wake.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if fds[1].revents != 0 {
        return Ok(Ready::Woken);
    }
    let revents = fds[0].revents;
    if revents & events == 0 && revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Ok(Ready::HungUp);
    }
    Ok(Ready::Io)
}

/// macOS 的 poll(2) 不支持设备文件，PTY 改用 select(2) 等待；挂断与错误表现为就绪，
/// 由下一次读写报告。
#[cfg(target_vendor = "apple")]
fn wait_once(fd: RawFd, interest: Interest, wake: Option<RawFd>) -> io::Result<Ready> {
    let fits = |fd: RawFd| usize::try_from(fd).is_ok_and(|fd| fd < libc::FD_SETSIZE);
    if !fits(fd) || !wake.is_none_or(fits) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut readable: libc::fd_set = unsafe { std::mem::zeroed() };
    let mut writable: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut readable);
        libc::FD_ZERO(&mut writable);
        match interest {
            Interest::Read => libc::FD_SET(fd, &mut readable),
            Interest::Write => libc::FD_SET(fd, &mut writable),
        }
        if let Some(wake) = wake {
            libc::FD_SET(wake, &mut readable);
        }
    }
    let nfds = fd.max(wake.unwrap_or(fd)) + 1;
    let result = unsafe {
        libc::select(
            nfds,
            &mut readable,
            &mut writable,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if wake.is_some_and(|wake| unsafe { libc::FD_ISSET(wake, &readable) }) {
        return Ok(Ready::Woken);
    }
    Ok(Ready::Io)
}
