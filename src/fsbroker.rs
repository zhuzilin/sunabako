//! Landlock ABI 1 denies cross-directory rename, even within a writable rule.
//! A tiny helper performs only rename/link inside a real kernel chroot. Helpers
//! have the sandbox UID, no capabilities, no network and no host filesystem FDs.
//! They never service a read-only mapping. PRoot sends already translated paths.
use crate::linux;
use anyhow::{ensure, Result};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
};

pub fn spawn(base: &Path) -> Result<UnixStream> {
    let (client, server) = UnixStream::pair()?;
    let parent = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    linux::cv(pid, "fork filesystem helper")?;
    if pid != 0 {
        return Ok(client);
    }
    drop(client);
    let result = (|| -> Result<()> {
        unsafe {
            linux::cv(
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
                "guard filesystem helper",
            )?;
            ensure!(libc::getppid() == parent, "filesystem helper parent exited");
            // Keep only the request socket, with a known FD, before chroot.
            linux::cv(libc::dup2(server.as_raw_fd(), 3), "filesystem helper FD")?;
            linux::cv(
                libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) as i32,
                "close helper FDs",
            )?;
            for fd in 0..3 {
                libc::close(fd);
            }
            linux::cv(
                libc::unshare(libc::CLONE_NEWNET),
                "filesystem helper network isolation",
            )?;
            linux::cv(
                libc::chroot(linux::cstr(base)?.as_ptr()),
                "filesystem helper chroot",
            )?;
        }
        std::env::set_current_dir("/")?;
        linux::drop_privileges()?;
        linux::seccomp()?;
        unsafe {
            linux::cv(
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0),
                "protect filesystem helper",
            )?;
        }
        use std::os::fd::FromRawFd;
        serve(unsafe { UnixStream::from_raw_fd(3) })
    })();
    unsafe {
        libc::_exit(if result.is_ok() { 0 } else { 125 });
    }
}

fn serve(mut stream: UnixStream) -> Result<()> {
    loop {
        let mut header = [0u8; 16];
        if stream.read_exact(&mut header).is_err() {
            return Ok(());
        }
        let word = |i| u32::from_ne_bytes(header[i..i + 4].try_into().unwrap());
        let (operation, flags, old_len, new_len) = (word(0), word(4), word(8), word(12));
        ensure!(
            (1..=4096).contains(&old_len) && (1..=4096).contains(&new_len),
            "invalid helper request"
        );
        let mut old = vec![0; old_len as usize];
        let mut new = vec![0; new_len as usize];
        stream.read_exact(&mut old)?;
        stream.read_exact(&mut new)?;
        let result = (|| -> Result<()> {
            ensure!(
                old.first() == Some(&b'/') && new.first() == Some(&b'/'),
                "helper paths must be absolute"
            );
            let old = std::ffi::CString::new(old)?;
            let new = std::ffi::CString::new(new)?;
            let ret = unsafe {
                match operation {
                    1 => libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        old.as_ptr(),
                        libc::AT_FDCWD,
                        new.as_ptr(),
                        flags,
                    ) as i32,
                    2 if flags == 0 => libc::link(old.as_ptr(), new.as_ptr()),
                    _ => {
                        libc::close(3);
                        return Ok(());
                    }
                }
            };
            linux::cv(ret, "filesystem helper operation")
        })();
        let errno = match result {
            Ok(()) => 0i32,
            Err(e) => e
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                .unwrap_or(libc::EINVAL),
        };
        stream.write_all(&errno.to_ne_bytes())?;
    }
}
