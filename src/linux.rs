use crate::model::Record;
use anyhow::{bail, ensure, Context, Result};
use std::{
    ffi::CString,
    fs, io,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, io::AsRawFd, net::UnixStream},
    path::Path,
};

pub fn cv(ret: i32, action: &str) -> Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error()).context(action.to_string())
    } else {
        Ok(())
    }
}
pub fn cstr(p: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    Ok(CString::new(p.as_os_str().as_bytes())?)
}
pub fn start_time(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
pub fn live(pid: i32, start: u64) -> bool {
    pid > 1 && start > 0 && start_time(pid) == Some(start)
}

pub fn pidfd_signal(pid: i32, start: u64, sig: i32) -> Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    cv(fd, "pidfd_open")?;
    let valid = live(pid, start);
    let r = if valid {
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, sig, 0usize, 0) as i32 }
    } else {
        -1
    };
    unsafe {
        libc::close(fd);
    }
    ensure!(valid, "process identity changed");
    cv(r, "pidfd_send_signal")
}

pub fn processes(init_pid: i32) -> Vec<(i32, u64, u64, char)> {
    // Match the namespace, not process groups: double-fork/setsid cannot escape accounting.
    let Ok(ns) = fs::read_link(format!("/proc/{init_pid}/ns/pid")) else {
        return vec![];
    };
    let mut out = vec![];
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|v| v.parse::<i32>().ok()) else {
            continue;
        };
        if fs::read_link(e.path().join("ns/pid")).ok().as_ref() != Some(&ns) {
            continue;
        }
        if let Ok(s) = fs::read_to_string(e.path().join("stat")) {
            if let Some((_, tail)) = s.rsplit_once(") ") {
                let f: Vec<_> = tail.split_whitespace().collect();
                if f.len() > 21 {
                    let start = f[19].parse().unwrap_or(0);
                    let rss: u64 = f[21].parse().unwrap_or(0);
                    out.push((
                        pid,
                        start,
                        rss.saturating_mul(unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64),
                        f[0].chars().next().unwrap_or('?'),
                    ));
                }
            }
        }
    }
    out
}

pub fn tasks(init_pid: i32) -> Vec<(i32, i32, u64, char)> {
    let mut out = vec![];
    for (pid, _, _, _) in processes(init_pid) {
        let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for e in entries.flatten() {
            let Some(tid) = e.file_name().to_str().and_then(|s| s.parse().ok()) else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(e.path().join("stat")) else {
                continue;
            };
            let Some((_, tail)) = stat.rsplit_once(") ") else {
                continue;
            };
            let fields: Vec<_> = tail.split_whitespace().collect();
            if fields.len() > 19 {
                out.push((
                    pid,
                    tid,
                    fields[19].parse().unwrap_or(0),
                    fields[0].chars().next().unwrap_or('?'),
                ));
            }
        }
    }
    out
}

pub fn task_signal(pid: i32, tid: i32, start: u64, sig: i32) {
    // tgkill also checks the thread-group ID; a reused TID in another process
    // cannot receive this signal. The tracer is stopped while tasks are frozen.
    if start_time(tid) == Some(start) {
        unsafe {
            libc::syscall(libc::SYS_tgkill, pid, tid, sig);
        }
    }
}

pub fn map_uid_range(pid: i32, record: &Record) -> Result<()> {
    // Only the privileged supervisor writes this mapping, for its own blocked
    // child. No host UID 0 is mapped into the sandbox. Leaving setgroups allowed
    // is safe here because the supervisor has CAP_SETGID in the parent namespace.
    let mapping = format!("0 {} {}\n", record.uid, record.uid_range_size);
    fs::write(format!("/proc/{pid}/uid_map"), &mapping).context("map dedicated guest UIDs")?;
    fs::write(format!("/proc/{pid}/gid_map"), &mapping).context("map dedicated guest GIDs")?;
    Ok(())
}

pub fn enter_namespaces(record: &Record, mapping_ready: &mut UnixStream) -> Result<()> {
    if record.native_users() {
        // NVIDIA's container runtime overlays parts of /proc. Linux locks those
        // mounts when entering a less privileged user namespace, which prevents
        // mounting a fresh procfs for the sandbox PID namespace. Start with a
        // complete procfs in a PRIVATE bootstrap mount namespace, while still
        // outer root. This changes no mounts in the parent container.
        unsafe {
            cv(
                libc::unshare(libc::CLONE_NEWNS),
                "create bootstrap mount namespace",
            )?;
        }
        mount(
            Path::new("none"),
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
        )
        .context("native guest users require private mounts in the outer container")?;
        let mut overlays: Vec<_> = fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .filter(|path| path.starts_with("/proc/"))
            .map(|path| {
                path.replace("\\040", " ")
                    .replace("\\011", "\t")
                    .replace("\\012", "\n")
                    .replace("\\134", "\\")
            })
            .collect();
        overlays.sort_by_key(|path| std::cmp::Reverse(path.len()));
        for path in overlays {
            unsafe {
                cv(
                    libc::umount2(CString::new(path)?.as_ptr(), libc::MNT_DETACH),
                    "detach procfs overlay in private bootstrap namespace",
                )?;
            }
        }
    }
    unsafe {
        cv(
            libc::setgroups(0, std::ptr::null()),
            "drop supplementary groups",
        )?;
        cv(libc::setgid(record.uid), "set dedicated gid")?;
        cv(libc::setuid(record.uid), "set dedicated uid")?;
        cv(
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0),
            "allow writing own UID mapping",
        )?;
        cv(libc::unshare(libc::CLONE_NEWUSER), "create user namespace")?;
    }
    if record.native_users() {
        mapping_ready.write_all(b"U")?;
        let mut reply = [0];
        mapping_ready.read_exact(&mut reply)?;
        ensure!(
            reply == *b"M",
            "supervisor did not install UID/GID mappings"
        );
    } else {
        fs::write("/proc/self/setgroups", "deny")?;
        fs::write("/proc/self/uid_map", format!("0 {} 1\n", record.uid))?;
        fs::write("/proc/self/gid_map", format!("0 {} 1\n", record.uid))?;
    }
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    if record.spec.runtime == "native" {
        flags |= libc::CLONE_NEWPID;
    }
    if record.spec.network == "none" {
        flags |= libc::CLONE_NEWNET;
    }
    unsafe {
        cv(
            libc::unshare(flags),
            "create PID/mount/IPC/UTS/network namespaces",
        )?;
    }
    if record.spec.network == "none" {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            cv(fd, "loopback configuration socket")?;
            let mut req: libc::ifreq = std::mem::zeroed();
            req.ifr_name[0] = b'l' as i8;
            req.ifr_name[1] = b'o' as i8;
            let get = libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut req);
            if get >= 0 {
                req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
            }
            let set = if get >= 0 {
                libc::ioctl(fd, libc::SIOCSIFFLAGS, &req)
            } else {
                get
            };
            libc::close(fd);
            cv(set, "enable private loopback")?;
        }
    }
    let hostname = CString::new(record.spec.id.as_str())?;
    unsafe {
        cv(
            libc::sethostname(hostname.as_ptr(), record.spec.id.len()),
            "set hostname",
        )?;
    }
    Ok(())
}

fn mount(src: &Path, dst: &Path, kind: Option<&str>, flags: libc::c_ulong) -> Result<()> {
    let src = cstr(src)?;
    let dst = cstr(dst)?;
    let kind = kind.map(CString::new).transpose()?;
    unsafe {
        cv(
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                flags,
                std::ptr::null(),
            ),
            "mount",
        )
    }
}

pub fn setup_root(root: &Path, record: &Record) -> Result<bool> {
    // The outer container may deny mounts. chroot still provides a kernel filesystem boundary.
    if !record.spec.mounts.is_empty() {
        mount(Path::new("none"), Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE)
            .context("directory mounts require the platform to allow mount(2) in the user namespace; no mount was emulated")?;
    }
    for m in &record.spec.mounts {
        let dest = root.join(m.target.strip_prefix("/")?);
        ensure!(
            dest.canonicalize()?.starts_with(root),
            "mount target escapes rootfs"
        );
        mount(&m.source, &dest, None, libc::MS_BIND).with_context(|| {
            format!(
                "bind {} -> {} (outer AppArmor must permit bind mounts)",
                m.source.display(),
                m.target.display()
            )
        })?;
        let flags = libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | if m.readonly { libc::MS_RDONLY } else { 0 };
        mount(Path::new("none"), &dest, None, flags)?;
    }
    let proc_mounted = mount(
        Path::new("proc"),
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )
    .is_ok();
    let root_c = cstr(root)?;
    unsafe {
        cv(libc::chroot(root_c.as_ptr()), "chroot")?;
    }
    std::env::set_current_dir("/")?;
    Ok(proc_mounted)
}

// Scoped to the sandbox's user namespace: chown, DAC override, fowner,
// setgid and setuid let guest root prepare an ordinary unprivileged user.
pub const GUEST_ROOT_CAPS: u64 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 7);
// Only trusted init retains SETPCAP, so each fork can empty its bounding set.
pub const NATIVE_INIT_CAPS: u64 = GUEST_ROOT_CAPS | (1 << 5) | (1 << 8);

pub fn drop_privileges() -> Result<()> {
    restrict_privileges(0, false)
}

pub fn check_file_rpc(file: &fs::File) -> Result<()> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe {
        cv(
            libc::fstatfs(file.as_raw_fd(), &mut stat),
            "inspect file filesystem",
        )?;
    }
    // The file worker is a fork of trusted init, not an exec of guest code.
    // Its /proc/self would otherwise expose inherited supervisor memory/env.
    // Check the opened descriptor so symlinks cannot bypass this boundary.
    ensure!(
        stat.f_type != libc::PROC_SUPER_MAGIC,
        "file RPC cannot inspect procfs; use commands.run for guest process information"
    );
    Ok(())
}

pub fn restrict_privileges(keep: u64, ambient: bool) -> Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    unsafe {
        cv(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "no_new_privs",
        )?;
        // Prevent UID 0 from reacquiring namespace capabilities on exec.
        cv(
            libc::prctl(libc::PR_SET_SECUREBITS, 15, 0, 0, 0),
            "lock securebits",
        )?;
        for cap in 0..=40 {
            if keep & (1u64 << cap) == 0 && libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) > 0 {
                cv(
                    libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0),
                    "drop bounding capability",
                )?;
            }
        }
        cv(
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ),
            "clear ambient capabilities",
        )?;
        let h = Header {
            version: 0x20080522,
            pid: 0,
        };
        let d = [0, 32].map(|shift| Data {
            effective: (keep >> shift) as u32,
            permitted: (keep >> shift) as u32,
            inheritable: if ambient { (keep >> shift) as u32 } else { 0 },
        });
        cv(
            libc::syscall(libc::SYS_capset, &h, d.as_ptr()) as i32,
            "restrict capabilities",
        )?;
        if ambient {
            for cap in 0..=40 {
                if keep & (1u64 << cap) != 0 {
                    cv(
                        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, cap, 0, 0),
                        "set guest root ambient capability",
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub fn limits(pids: u64) -> Result<()> {
    for (resource, value) in [
        (libc::RLIMIT_NPROC, pids),
        (libc::RLIMIT_NOFILE, 1024),
        (libc::RLIMIT_CORE, 0),
    ] {
        let lim = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        unsafe {
            cv(libc::setrlimit(resource, &lim), "setrlimit")?;
        }
    }
    Ok(())
}

pub fn seccomp() -> Result<()> {
    seccomp_filter(false)
}
pub fn seccomp_filter(tracer: bool) -> Result<()> {
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x15,
            jt,
            jf,
            k,
        }
    }
    let deny = 0x00050000 | libc::EPERM as u32;
    let mut b = vec![
        stmt(0x20, 4),
        jump(0xc000003e, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
        jump(u32::MAX, 0, 1),
        stmt(0x06, 0x00050000 | libc::ENOSYS as u32),
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        stmt(0x06, 0x80000000),
    ];
    for n in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_mknod,
        libc::SYS_mknodat,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_pidfd_getfd,
        libc::SYS_acct,
        libc::SYS_quotactl,
    ] {
        if tracer
            && [
                libc::SYS_ptrace,
                libc::SYS_process_vm_readv,
                libc::SYS_process_vm_writev,
            ]
            .contains(&n)
        {
            continue;
        }
        b.push(jump(n as u32, 0, 1));
        b.push(stmt(0x06, deny));
    }
    // Landlock ABI 1 does not mediate pathname truncate. ftruncate still requires a writable FD.
    if tracer {
        b.push(jump(libc::SYS_truncate as u32, 0, 1));
        b.push(stmt(0x06, deny));
        b.push(jump(libc::SYS_openat2 as u32, 0, 1));
        b.push(stmt(0x06, 0x00050000 | libc::ENOSYS as u32));
        for (sys, arg) in [(libc::SYS_open, 24), (libc::SYS_openat, 32)] {
            b.push(jump(sys as u32, 0, 5));
            b.push(stmt(0x20, arg));
            b.push(libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 2,
                k: libc::O_TRUNC as u32,
            });
            b.push(libc::sock_filter {
                code: 0x45,
                jt: 1,
                jf: 0,
                k: libc::O_ACCMODE as u32,
            });
            b.push(stmt(0x06, deny));
            b.push(stmt(0x20, 0));
        }
    }
    b.push(jump(libc::SYS_clone3 as u32, 0, 1));
    b.push(stmt(0x06, 0x00050000 | libc::ENOSYS as u32));
    b.extend([
        jump(libc::SYS_clone as u32, 0, 3),
        stmt(0x20, 16),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: (libc::CLONE_NEWUSER
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWCGROUP
                | libc::CLONE_UNTRACED) as u32,
        },
        stmt(0x06, deny),
        stmt(0x06, 0x7fff0000),
    ]);
    let p = libc::sock_fprog {
        len: b.len() as u16,
        filter: b.as_mut_ptr(),
    };
    unsafe {
        cv(
            libc::prctl(libc::PR_SET_SECCOMP, 2, &p, 0, 0),
            "install seccomp",
        )
    }
}

/// Landlock guards actual kernel paths even when PRoot rewrites guest pathnames.
pub fn landlock(root: &Path, mounts: &[crate::model::Mount], proot: &Path) -> Result<()> {
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct Beneath {
        allowed_access: u64,
        parent_fd: i32,
    }
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, 1) };
    ensure!(
        abi >= 1,
        "PRoot backend requires Landlock; refusing an unconfined fallback"
    );
    // ABI 2 adds REFER (cross-directory rename/link), ABI 3 adds TRUNCATE.
    let handled = (1u64
        << if abi >= 3 {
            15
        } else if abi >= 2 {
            14
        } else {
            13
        })
        - 1;
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &Ruleset {
                handled_access_fs: handled,
            },
            std::mem::size_of::<Ruleset>(),
            0,
        )
    } as i32;
    cv(ruleset, "create Landlock ruleset")?;
    let result = (|| -> Result<()> {
        let read = (1 << 0) | (1 << 2) | (1 << 3);
        let mut paths = vec![
            (root.to_path_buf(), handled),
            (proot.to_path_buf(), read),
            (Path::new("/proc").to_path_buf(), read | (1 << 1)),
            (Path::new("/sys").to_path_buf(), read),
            (Path::new("/etc/ld.so.cache").to_path_buf(), read),
        ];
        // Dynamic loader and PRoot dependencies, each file individually; never expose host /usr.
        let libs = std::process::Command::new("ldd").arg(proot).output()?;
        for token in String::from_utf8_lossy(&libs.stdout).split_whitespace() {
            if token.starts_with('/') && Path::new(token).is_file() {
                paths.push((Path::new(token).to_path_buf(), read));
            }
        }
        for m in mounts {
            paths.push((m.source.clone(), if m.readonly { read } else { handled }));
        }
        for (path, mut access) in paths {
            if !path.is_dir() {
                access &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14);
            }
            let fd = unsafe { libc::open(cstr(&path)?.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            cv(fd, &format!("open Landlock path {}", path.display()))?;
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset,
                    1,
                    &Beneath {
                        allowed_access: access,
                        parent_fd: fd,
                    },
                    0,
                )
            } as i32;
            unsafe {
                libc::close(fd);
            }
            cv(r, "add Landlock path rule")?;
        }
        unsafe {
            cv(
                libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) as i32,
                "enforce Landlock",
            )?;
        }
        Ok(())
    })();
    unsafe {
        libc::close(ruleset);
    }
    result
}

pub fn copy_device(src: &Path, root: &Path) -> Result<()> {
    let md = fs::metadata(src)?;
    use std::os::unix::fs::FileTypeExt;
    ensure!(
        md.file_type().is_char_device(),
        "not a character device: {}",
        src.display()
    );
    let dst = root.join(src.strip_prefix("/")?);
    fs::create_dir_all(dst.parent().unwrap())?;
    if dst.exists() {
        fs::remove_file(&dst)?;
    }
    unsafe {
        cv(
            libc::mknod(cstr(&dst)?.as_ptr(), libc::S_IFCHR | 0o666, md.rdev()),
            "create sandbox device",
        )?;
        // mknod applies the caller's umask. Device access must also work for
        // mapped non-root guest users, independent of the supervisor's umask.
        cv(
            libc::chmod(cstr(&dst)?.as_ptr(), 0o666),
            "set sandbox device permissions",
        )?;
    }
    Ok(())
}

pub fn flock(file: &fs::File, exclusive: bool) -> Result<()> {
    unsafe {
        cv(
            libc::flock(
                file.as_raw_fd(),
                if exclusive {
                    libc::LOCK_EX
                } else {
                    libc::LOCK_SH
                },
            ),
            "flock",
        )
    }
}

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "sunabako node operations require root inside the outer container (not host privilege)"
        );
    }
    Ok(())
}
