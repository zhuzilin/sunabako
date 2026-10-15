use crate::model::Record;
use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    fs, io,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{fs::MetadataExt, io::AsRawFd, net::UnixStream},
    path::{Path, PathBuf},
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

pub fn terminate_preparation(pid: i32, start: u64) -> Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    struct Frozen(Vec<OwnedFd>);
    impl Drop for Frozen {
        fn drop(&mut self) {
            // If inspection fails before termination, do not leave the owned
            // preparations stopped. PIDfds cannot signal reused process IDs.
            for fd in &self.0 {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGCONT,
                        0usize,
                        0,
                    );
                }
            }
        }
    }
    fn open(pid: i32, start: u64) -> Result<OwnedFd> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        cv(raw, "open preparation pidfd")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        ensure!(live(pid, start), "preparation process identity changed");
        Ok(fd)
    }
    fn signal(fd: &OwnedFd, value: i32) -> Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                value,
                0usize,
                0,
            ) as i32
        };
        if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        cv(result, "signal preparation process")
    }

    let leader = open(pid, start)?;
    ensure!(
        unsafe { libc::getpgid(pid) } == pid && unsafe { libc::getsid(pid) } == pid,
        "creation does not own a dedicated preparation session"
    );
    let mut frozen = Frozen(vec![leader]);
    signal(&frozen.0[0], libc::SIGSTOP)?;
    // The pinned leader owns this session; launch is serialized with cancellation.
    // Stop members through pidfds too, so rollback can resume every task we stop.
    // Repeat the scan until stopped children can no longer add descendants.
    let until = Instant::now() + Duration::from_secs(5);
    let mut known = HashSet::from([(pid, start)]);
    loop {
        let mut stopped = true;
        let mut added = false;
        // Cancellation is exceptional; unlike hot-path sandbox accounting,
        // this also finds orphaned tools still in the dedicated process group.
        for entry in fs::read_dir("/proc")?.flatten() {
            let Some(member) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some((_, tail)) = stat.rsplit_once(") ") else {
                continue;
            };
            let fields: Vec<_> = tail.split_whitespace().collect();
            if fields.len() <= 19 || fields[2].parse::<i32>().ok() != Some(pid) {
                continue;
            }
            ensure!(
                fields[3].parse::<i32>().ok() == Some(pid),
                "preparation session changed"
            );
            let member_start: u64 = fields[19].parse()?;
            if !known.contains(&(member, member_start)) {
                let fd = match open(member, member_start) {
                    Ok(fd) => fd,
                    Err(_) if !live(member, member_start) => continue,
                    Err(error) => return Err(error),
                };
                signal(&fd, libc::SIGSTOP)?;
                frozen.0.push(fd);
                known.insert((member, member_start));
                added = true;
            }
            stopped &= matches!(fields[0], "T" | "t" | "Z" | "X");
        }
        if stopped && !added {
            break;
        }
        ensure!(Instant::now() < until, "preparation processes did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
    fn wait(fd: &OwnedFd, until: Instant) -> Result<()> {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = until.saturating_duration_since(Instant::now()).as_millis() as i32;
        let result = unsafe { libc::poll(&mut poll, 1, remaining) };
        cv(result, "wait for preparation process exit")?;
        ensure!(result > 0, "preparation process did not exit");
        Ok(())
    }
    // Keep the stopped leader alive until all tools exit. If a tool cannot exit,
    // rollback resumes the leader and preserves a verifiable owner for retry.
    for fd in frozen.0.iter().skip(1).rev() {
        signal(fd, libc::SIGKILL)?;
    }
    let until = Instant::now() + Duration::from_secs(10);
    for fd in frozen.0.iter().skip(1) {
        wait(fd, until)?;
    }
    signal(&frozen.0[0], libc::SIGKILL)?;
    wait(&frozen.0[0], until)?;
    Ok(())
}

pub fn processes(init_pid: i32) -> Vec<(i32, u64, u64, char)> {
    // Lifecycle snapshots may run alongside the persistent monitor, which
    // already owns its descriptor allowance. Keep one-off scans uncached.
    let mut monitor = ProcessMonitor::new(init_pid);
    monitor.max_files = 0;
    monitor.processes()
}

pub struct ProcessMonitor {
    init_pid: i32,
    namespace: Option<PathBuf>,
    files: HashMap<PathBuf, (fs::File, bool)>,
    max_files: usize,
}

impl ProcessMonitor {
    pub fn new(init_pid: i32) -> Self {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        let max_files = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            (limit.rlim_cur as usize).saturating_sub(64).min(1024)
        } else {
            0
        };
        Self {
            init_pid,
            namespace: fs::read_link(format!("/proc/{init_pid}/ns/pid")).ok(),
            files: HashMap::new(),
            max_files,
        }
    }

    fn read(&mut self, path: &Path) -> io::Result<String> {
        if !self.files.contains_key(path) && self.files.len() < self.max_files {
            self.files
                .insert(path.to_owned(), (fs::File::open(path)?, false));
        }
        let Some((file, used)) = self.files.get_mut(path) else {
            return fs::read_to_string(path);
        };
        // Rewinding regenerates procfs content. The open file remains tied to
        // the original process/thread rather than following a reused PID.
        let result = (|| {
            file.seek(SeekFrom::Start(0))?;
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            Ok(text)
        })();
        *used = result.is_ok();
        if result.is_err() {
            self.files.remove(path);
        }
        result
    }

    pub fn processes(&mut self) -> Vec<(i32, u64, u64, char)> {
        // PID-namespace init adopts orphaned descendants, including double forks
        // and setsid children. Walk every thread's children instead of scanning the
        // entire host /proc once per sandbox on every monitoring tick.
        let Some(ns) = self.namespace.clone() else {
            return vec![];
        };
        if fs::read_link(format!("/proc/{}/ns/pid", self.init_pid))
            .ok()
            .as_ref()
            != Some(&ns)
        {
            self.files.clear();
            return vec![];
        }
        for (_, used) in self.files.values_mut() {
            *used = false;
        }
        let mut out = vec![];
        let mut pending = vec![self.init_pid];
        let mut seen = HashSet::new();
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        while let Some(pid) = pending.pop() {
            if !seen.insert(pid) {
                continue;
            }
            let path = std::path::PathBuf::from(format!("/proc/{pid}"));
            if fs::read_link(path.join("ns/pid")).ok().as_ref() != Some(&ns) {
                continue;
            }
            if let Ok(threads) = fs::read_dir(path.join("task")) {
                for task in threads.flatten() {
                    if let Ok(children) = self.read(&task.path().join("children")) {
                        pending.extend(
                            children
                                .split_whitespace()
                                .filter_map(|p| p.parse::<i32>().ok()),
                        );
                    }
                }
            }
            if let Ok(s) = self.read(&path.join("stat")) {
                if let Some((_, tail)) = s.rsplit_once(") ") {
                    let f: Vec<_> = tail.split_whitespace().collect();
                    if f.len() > 21 {
                        let start = f[19].parse().unwrap_or(0);
                        let rss: u64 = f[21].parse().unwrap_or(0);
                        out.push((
                            pid,
                            start,
                            rss.saturating_mul(page_size),
                            f[0].chars().next().unwrap_or('?'),
                        ));
                    }
                }
            }
        }
        self.files.retain(|_, (_, used)| *used);
        out
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    #[test]
    fn cached_process_monitor_discovers_new_children_and_releases_exited_files() {
        let root = std::process::id() as i32;
        let mut monitor = ProcessMonitor::new(root);
        assert!(monitor.processes().iter().any(|p| p.0 == root));
        // The leader and this worker thread's children files are already open.
        // A later fork must still appear through those same descriptors.
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let found = monitor.processes().iter().any(|p| p.0 == pid);
        let child_path = PathBuf::from(format!("/proc/{pid}"));
        let cached = monitor.files.keys().any(|p| p.starts_with(&child_path));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(found);
        assert!(cached);
        assert!(!monitor.processes().iter().any(|p| p.0 == pid));
        assert!(!monitor.files.keys().any(|p| p.starts_with(&child_path)));
    }

    #[test]
    fn process_monitor_falls_back_when_descriptor_budget_is_exhausted() {
        let root = std::process::id() as i32;
        let mut monitor = ProcessMonitor::new(root);
        monitor.max_files = 1;
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let all = monitor.processes();
        let again = monitor.processes();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(monitor.files.len() <= 1);
        for processes in [all, again] {
            assert!(processes.iter().any(|p| p.0 == root));
            assert!(processes.iter().any(|p| p.0 == pid));
        }
    }

    #[test]
    fn process_accounting_follows_thread_children_and_new_sessions() {
        // Rust runs this test on a worker thread; its child is absent from the
        // process leader's children file. The child starts a separate session.
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let descendant: i32 = line.trim().parse().unwrap();
        let root = std::process::id() as i32;
        let all = processes(root);
        let subtree = processes(child.id() as i32);
        // Only the explicitly created session is signalled, independent of
        // the accounting function's output.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        child.wait().unwrap();
        for pid in [child.id() as i32, descendant] {
            assert!(all.iter().any(|p| p.0 == pid));
            assert!(subtree.iter().any(|p| p.0 == pid));
        }
        assert!(!subtree.iter().any(|p| p.0 == root));
    }
}
