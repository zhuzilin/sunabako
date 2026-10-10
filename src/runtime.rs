use crate::{
    linux,
    model::{NodeConfig, Record, Request, Status},
    store,
};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_REQUEST: u64 = 20 << 20;
const MAX_OUTPUT: usize = 2 << 20;

pub fn rpc(dir: &Path, request: &Request) -> Result<Value> {
    let mut stream =
        UnixStream::connect(dir.join("control.sock")).context("connect to sandbox init")?;
    let timeout = match request {
        Request::Exec { timeout, .. } => *timeout + 15,
        _ => 30,
    };
    stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_REQUEST)
        .read_line(&mut line)?;
    ensure!(
        !line.is_empty(),
        "sandbox closed the RPC (inspect status for OOM/timeout/exit)"
    );
    let value: Value = serde_json::from_str(&line)?;
    if let Some(error) = value.get("error") {
        bail!("sandbox: {error}");
    }
    Ok(value)
}

fn drain(reader: &mut impl Read, buf: &mut Vec<u8>, truncated: &mut bool) -> Result<()> {
    let mut block = [0u8; 8192];
    // Bound work per poll so continuous stdout cannot starve the timeout check.
    for _ in 0..32 {
        match reader.read(&mut block) {
            Ok(0) => break,
            Ok(n) => {
                let keep = n.min(MAX_OUTPUT.saturating_sub(buf.len()));
                buf.extend_from_slice(&block[..keep]);
                *truncated |= keep != n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct GuestUser {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    home: String,
}

fn guest_user(user: &str, record: &Record) -> Result<GuestUser> {
    ensure!(
        !user.is_empty()
            && user
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
        "invalid guest user"
    );
    if user == "root" {
        return Ok(GuestUser {
            uid: 0,
            gid: 0,
            groups: vec![],
            home: "/root".into(),
        });
    }
    ensure!(
        record.native_users(),
        "native guest users require node uid_range_size > 1 (normally 65536)"
    );
    // Resolve only the guest's local account databases, without loading NSS
    // modules or running guest code inside the trusted init process.
    let passwd = fs::read_to_string("/etc/passwd")?;
    let fields: Vec<_> = passwd
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() == 7 && fields[0] == user).then_some(fields)
        })
        .with_context(|| format!("unknown guest user {user}"))?;
    let uid: u32 = fields[2].parse()?;
    let gid: u32 = fields[3].parse()?;
    ensure!(
        uid > 0 && uid < record.uid_range_size && gid < record.uid_range_size,
        "guest UID/GID is outside the sandbox mapping"
    );
    let mut groups = vec![gid];
    for line in fs::read_to_string("/etc/group")?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() == 4 && fields[3].split(',').any(|name| name == user) {
            let group: u32 = fields[2].parse()?;
            ensure!(
                group < record.uid_range_size,
                "guest supplementary GID is outside the sandbox mapping"
            );
            groups.push(group);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(GuestUser {
        uid,
        gid,
        groups,
        home: fields[5].into(),
    })
}

fn set_guest_user(user: &GuestUser) -> Result<()> {
    unsafe {
        linux::cv(
            libc::setgroups(user.groups.len(), user.groups.as_ptr()),
            "set guest supplementary groups",
        )?;
        linux::cv(
            libc::setresgid(user.gid, user.gid, user.gid),
            "set guest gid",
        )?;
        linux::cv(
            libc::setresuid(user.uid, user.uid, user.uid),
            "set guest uid",
        )?;
    }
    // Securebits keep capabilities across the trusted UID transition only.
    // Clear them, including bounding/ambient sets, before any non-root code runs.
    linux::restrict_privileges(
        if user.uid == 0 {
            linux::GUEST_ROOT_CAPS
        } else {
            0
        },
        user.uid == 0,
    )
}

fn file_as_user(
    record: &Record,
    user: &str,
    action: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    if !record.native_users() {
        ensure!(
            user == "root" || record.spec.runtime == "proot",
            "native guest users require node uid_range_size > 1"
        );
        return action();
    }
    let user = guest_user(user, record)?;
    let (mut reader, mut writer) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_secs(30)))?;
    let pid = unsafe { libc::fork() };
    linux::cv(pid, "fork file operation")?;
    if pid == 0 {
        drop(reader);
        let result = (|| {
            set_guest_user(&user)?;
            linux::seccomp()?;
            action()
        })();
        let value = result.unwrap_or_else(|e| json!({"error":format!("{e:#}")}));
        let _ = serde_json::to_writer(&mut writer, &value);
        let _ = writer.write_all(b"\n");
        unsafe {
            libc::_exit(0);
        }
    }
    drop(writer);
    let mut line = String::new();
    let result = BufReader::new(&mut reader)
        .take(MAX_REQUEST)
        .read_line(&mut line);
    unsafe {
        if result.is_err() {
            libc::kill(pid, libc::SIGKILL);
        }
        loop {
            if libc::waitpid(pid, std::ptr::null_mut(), 0) >= 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
    result?;
    let value: Value =
        serde_json::from_str(&line).context("file operation exited without a response")?;
    if let Some(error) = value.get("error") {
        bail!("file operation: {error}");
    }
    Ok(value)
}

fn execute(request: Request, record: &Record) -> Result<(Value, bool)> {
    match request {
        Request::Ping => Ok((json!({"ok":true}), false)),
        Request::Write {
            path,
            data,
            append,
            user,
        } => {
            ensure!(path.starts_with('/'), "file path must be absolute");
            let data = STANDARD.decode(data)?;
            let value = file_as_user(record, &user, || {
                if let Some(p) = Path::new(&path).parent() {
                    fs::create_dir_all(p)?;
                }
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(append)
                    .truncate(!append && !record.native_users())
                    .open(path)?;
                if record.native_users() {
                    linux::check_file_rpc(&file)?;
                }
                if !append && record.native_users() {
                    file.set_len(0)?;
                }
                file.write_all(&data)?;
                Ok(json!({"ok":true}))
            })?;
            Ok((value, false))
        }
        Request::Read { path, user } => {
            ensure!(path.starts_with('/'), "file path must be absolute");
            let value = file_as_user(record, &user, || {
                let mut bytes = vec![];
                let f = fs::File::open(path)?;
                if record.native_users() {
                    linux::check_file_rpc(&f)?;
                }
                f.take(8 << 20).read_to_end(&mut bytes)?;
                ensure!(bytes.len() < 8 << 20, "file exceeds read RPC limit (8 MiB)");
                Ok(json!({"data":STANDARD.encode(bytes)}))
            })?;
            Ok((value, false))
        }
        Request::Exec {
            argv,
            env,
            cwd,
            timeout,
            user,
        } => {
            ensure!(
                !argv.is_empty() && timeout > 0 && timeout <= 86400,
                "exec needs argv and timeout 1..86400 seconds"
            );
            ensure!(cwd.starts_with('/'), "cwd must be absolute");
            ensure!(
                !user.is_empty()
                    && user
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
                "invalid guest user"
            );
            let identity = if record.native_users() {
                Some(guest_user(&user, record)?)
            } else {
                None
            };
            let mut cmd = if user == "root" || record.native_users() {
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            } else {
                ensure!(
                    record.spec.runtime == "proot",
                    "native guest users require node uid_range_size > 1 (normally 65536)"
                );
                let mut c = Command::new("runuser");
                c.args(["-u", &user, "--"]).args(&argv);
                c
            };
            cmd.current_dir(cwd);
            cmd.env_clear()
                .env(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                )
                .env("HOME", "/root")
                .env("LANG", "C.UTF-8")
                .env("TMPDIR", "/tmp")
                .envs(&record.spec.env);
            if let Some(identity) = &identity {
                cmd.env("HOME", &identity.home)
                    .env("USER", &user)
                    .env("LOGNAME", &user);
            }
            cmd.envs(env)
                .env("CUDA_VISIBLE_DEVICES", record.gpu_uuids.join(","))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if let Some(user) = &identity {
                        set_guest_user(user).map_err(std::io::Error::other)?;
                    }
                    linux::seccomp().map_err(std::io::Error::other)
                });
            }
            let mut child = cmd.spawn().context("exec in sandbox")?;
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
                unsafe {
                    linux::cv(
                        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK),
                        "nonblocking command output",
                    )?;
                }
            }
            let mut out = vec![];
            let mut err = vec![];
            let mut truncated = false;
            let start = Instant::now();
            loop {
                drain(&mut stdout, &mut out, &mut truncated)?;
                drain(&mut stderr, &mut err, &mut truncated)?;
                let result = child.try_wait()?;
                let timed_out = start.elapsed() > Duration::from_secs(timeout);
                if result.is_some() || timed_out {
                    drain(&mut stdout, &mut out, &mut truncated)?;
                    drain(&mut stderr, &mut err, &mut truncated)?;
                    use std::os::unix::process::ExitStatusExt;
                    let code = result
                        .map(|s| s.code().unwrap_or(128 + s.signal().unwrap_or(0)))
                        .unwrap_or(124);
                    return Ok((
                        json!({"exit_code":code,"stdout":String::from_utf8_lossy(&out),"stderr":String::from_utf8_lossy(&err),"truncated":truncated,"timed_out":timed_out}),
                        timed_out,
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn init(
    listener: UnixListener,
    mut ready: UnixStream,
    root: &Path,
    record: &Record,
    prepared: bool,
) -> Result<()> {
    let mounted = if !prepared {
        linux::setup_root(root, record)?
    } else {
        false
    };
    if !prepared {
        linux::limits(record.spec.pids_max)?;
        if record.native_users() {
            linux::restrict_privileges(linux::NATIVE_INIT_CAPS, false)?;
        } else {
            linux::drop_privileges()?;
        }
    }
    // Tracees cannot inspect the trusted PID 1 via procfs or ptrace.
    if !prepared {
        unsafe {
            linux::cv(
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0),
                "protect init",
            )?;
        }
    }
    serde_json::to_writer(&mut ready, &json!({"ready":true,"proc_mounted":mounted}))?;
    ready.write_all(b"\n")?;
    drop(ready);
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                let result = (|| -> Result<(Value, bool)> {
                    let mut line = String::new();
                    BufReader::new(&stream)
                        .take(MAX_REQUEST)
                        .read_line(&mut line)?;
                    execute(serde_json::from_str(&line)?, record)
                })();
                let (value, stop) = match result {
                    Ok(v) => v,
                    Err(e) => (json!({"error":format!("{e:#}")}), false),
                };
                let _ = serde_json::to_writer(&mut stream, &value);
                let _ = stream.write_all(b"\n");
                if stop {
                    unsafe {
                        libc::_exit(124);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e.into()),
        }
        // Reap detached grandchildren after each command; no concurrent waitpid races.
        unsafe { while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {} }
    }
}

pub fn serve_inside_proot(listener_fd: i32, ready_fd: i32) -> Result<()> {
    use std::os::fd::FromRawFd;
    let (record, _config): (Record, NodeConfig) =
        serde_json::from_str(&std::env::var("SUNABAKO_INIT")?)?;
    std::env::remove_var("SUNABAKO_INIT");
    std::env::remove_var("SUNABAKO_RENAME_HELPERS");
    if let Ok(fds) = std::env::var("SUNABAKO_HELPER_FDS") {
        for fd in fds.split(',') {
            if let Ok(fd) = fd.parse::<i32>() {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        std::env::remove_var("SUNABAKO_HELPER_FDS");
    }
    ensure!(unsafe { libc::getpid() } == 1, "private init must be PID 1");
    for fd in [listener_fd, ready_fd] {
        unsafe {
            linux::cv(
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC),
                "protect inherited control FD",
            )?;
        }
    }
    unsafe {
        linux::cv(
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
            "guard sandbox init",
        )?;
    }
    // PRoot surrounds this long-lived init, so detached commands remain in the same sandbox.
    init(
        unsafe { UnixListener::from_raw_fd(listener_fd) },
        unsafe { UnixStream::from_raw_fd(ready_fd) },
        Path::new("/"),
        &record,
        true,
    )
}

fn proot_init(
    listener: UnixListener,
    ready: UnixStream,
    root: &Path,
    record: &Record,
    config: &NodeConfig,
) -> Result<()> {
    let proot = config
        .proot_binary
        .as_ref()
        .context("proot_binary required")?;
    let binary = std::env::current_exe()?;
    let mut permissions = record.spec.mounts.clone();
    permissions.push(crate::model::Mount {
        source: binary.clone(),
        target: "/.sunabako-init".into(),
        readonly: true,
    });
    linux::limits(record.spec.pids_max)?;
    // ABI 1 has no REFER right. Confined helpers preserve atomic rename/link
    // semantics without relaxing the workload's Landlock rules.
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, 1) };
    let mut helpers = Vec::new();
    let mut helper_map = String::new();
    if abi == 1 {
        for base in std::iter::once(root.to_path_buf()).chain(
            record
                .spec
                .mounts
                .iter()
                .filter(|m| !m.readonly)
                .map(|m| m.source.clone()),
        ) {
            let base = base.canonicalize()?;
            ensure!(
                !base.to_string_lossy().contains(['\n', '\t']),
                "mapping path contains a control character"
            );
            let stream = crate::fsbroker::spawn(&base)?;
            helper_map.push_str(&format!("{}\t{}\n", stream.as_raw_fd(), base.display()));
            helpers.push(stream);
        }
    }
    // Install filesystem confinement before PRoot: its traced tasks inherit kernel enforcement.
    unsafe {
        linux::cv(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "no_new_privs",
        )?;
    }
    linux::landlock(root, &permissions, proot)?;
    // PRoot itself must use the PID namespace of the inherited /proc mount. Its FIRST child
    // enters the new namespace and becomes the persistent init. Do not fork between these.
    unsafe {
        linux::cv(
            libc::unshare(libc::CLONE_NEWPID),
            "create workload PID namespace",
        )?;
    }
    linux::drop_privileges()?;
    linux::seccomp_filter(true)?;
    let mut cmd = Command::new(proot);
    if let Ok(level) = std::env::var("SUNABAKO_PROOT_VERBOSE") {
        cmd.args(["-v", &level]);
    }
    cmd.arg("-0")
        .arg("-r")
        .arg(root)
        .args(["-w", "/", "-b", "/proc:/proc", "-b", "/sys:/sys"]);
    for m in &record.spec.mounts {
        cmd.arg("-b")
            .arg(format!("{}:{}!", m.source.display(), m.target.display()));
    }
    cmd.arg("-b")
        .arg(format!("{}:/.sunabako-init!", binary.display()));
    cmd.arg("/.sunabako-init")
        .arg("__serve")
        .arg(listener.as_raw_fd().to_string())
        .arg(ready.as_raw_fd().to_string());
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PROOT_TMP_DIR", root.join("tmp"))
        .env("PROOT_NO_SECCOMP", "1")
        .env("SUNABAKO_INIT", serde_json::to_string(&(record, config))?)
        .env("SUNABAKO_SINGLE_UID", "1")
        .env("SUNABAKO_RENAME_HELPERS", helper_map)
        .env(
            "SUNABAKO_HELPER_FDS",
            helpers
                .iter()
                .map(|h| h.as_raw_fd().to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    for stream in &helpers {
        unsafe {
            linux::cv(
                libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, 0),
                "pass filesystem helper FD",
            )?;
        }
    }
    for fd in [listener.as_raw_fd(), ready.as_raw_fd()] {
        unsafe {
            linux::cv(libc::fcntl(fd, libc::F_SETFD, 0), "pass init FD")?;
        }
    }
    Err(cmd.exec()).context("exec PRoot launcher")
}

fn child(
    listener: UnixListener,
    ready: UnixStream,
    mut mapping_ready: UnixStream,
    root: &Path,
    record: &Record,
    parent: i32,
    config: &NodeConfig,
) -> Result<()> {
    if let Some(cg) = store::cgroup_path(config, &record.spec.id) {
        fs::write(
            cg.join("cgroup.procs"),
            unsafe { libc::getpid() }.to_string(),
        )?;
    }
    linux::enter_namespaces(record, &mut mapping_ready)?;
    drop(mapping_ready);
    unsafe {
        linux::cv(
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
            "guard namespace launcher",
        )?;
    }
    ensure!(
        unsafe { libc::getppid() } == parent,
        "supervisor exited during setup"
    );
    if record.spec.runtime == "proot" {
        return proot_init(listener, ready, root, record, config);
    }
    let pid = unsafe { libc::fork() };
    linux::cv(pid, "fork namespace init")?;
    if pid == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        }
        return init(listener, ready, root, record, false);
    }
    let mut ready = ready;
    serde_json::to_writer(&mut ready, &json!({"init_pid":pid}))?;
    ready.write_all(b"\n")?;
    drop(ready);
    drop(listener);
    let mut status = 0;
    unsafe {
        while libc::waitpid(pid, &mut status, 0) < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        libc::_exit(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        });
    }
}

pub fn supervise(dir: &Path, config: &NodeConfig) -> Result<()> {
    let record: Record = store::read(&dir.join("record.json"))?;
    let root = dir.join("rootfs").canonicalize()?;
    let _ = fs::remove_file(dir.join("control.sock"));
    let listener = UnixListener::bind(dir.join("control.sock"))?;
    let (mut read, write) = UnixStream::pair()?;
    let (mut map_parent, map_child) = UnixStream::pair()?;
    map_parent.set_read_timeout(Some(Duration::from_secs(20)))?;
    map_child.set_read_timeout(Some(Duration::from_secs(20)))?;
    read.set_read_timeout(Some(Duration::from_secs(20)))?;
    let parent = unsafe { libc::getpid() };
    let launcher = unsafe { libc::fork() };
    linux::cv(launcher, "fork sandbox launcher")?;
    if launcher == 0 {
        drop(read);
        drop(map_parent);
        let mut notify = write.try_clone()?;
        if let Err(e) = child(listener, write, map_child, &root, &record, parent, config) {
            eprintln!("sandbox init: {e:#}");
            let _ = serde_json::to_writer(&mut notify, &json!({"error":format!("{e:#}")}));
            let _ = notify.write_all(b"\n");
        }
        unsafe {
            libc::_exit(125);
        }
    }
    drop(write);
    drop(map_child);
    drop(listener);
    let mut status = Status {
        state: "starting".into(),
        supervisor_pid: parent,
        supervisor_start: linux::start_time(parent).unwrap_or(0),
        ..Default::default()
    };
    let setup = (|| -> Result<()> {
        if record.native_users() {
            let mut request = [0];
            map_parent
                .read_exact(&mut request)
                .context("wait for user namespace")?;
            ensure!(request == *b"U", "invalid UID mapping handshake");
            linux::map_uid_range(launcher, &record)?;
            map_parent.write_all(b"M")?;
        }
        drop(map_parent);
        let mut reader = BufReader::new(&mut read);
        for _ in 0..if record.spec.runtime == "proot" { 1 } else { 2 } {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let msg: Value =
                serde_json::from_str(&line).context("sandbox setup failed; see supervisor.log")?;
            if let Some(error) = msg.get("error") {
                bail!("sandbox init: {error}");
            }
            if let Some(pid) = msg["init_pid"].as_i64() {
                status.init_pid = pid as i32;
                status.init_start = linux::start_time(pid as i32).unwrap_or(0);
            }
            if msg["ready"] == true {
                status.proc_mounted = msg["proc_mounted"] == true;
            }
        }
        if record.spec.runtime == "proot" {
            let children =
                fs::read_to_string(format!("/proc/{launcher}/task/{launcher}/children"))?;
            let parent_ns = fs::read_link(format!("/proc/{launcher}/ns/pid"))?;
            status.init_pid = children
                .split_whitespace()
                .filter_map(|p| p.parse::<i32>().ok())
                .find(|pid| {
                    fs::read_link(format!("/proc/{pid}/ns/pid")).is_ok_and(|ns| ns != parent_ns)
                })
                .context("PRoot init child missing")?;
            status.init_start = linux::start_time(status.init_pid).unwrap_or(0);
        }
        ensure!(
            linux::live(status.init_pid, status.init_start),
            "sandbox init exited during setup"
        );
        Ok(())
    })();
    if let Err(e) = setup {
        if linux::live(status.init_pid, status.init_start) {
            let _ = linux::pidfd_signal(status.init_pid, status.init_start, libc::SIGKILL);
        }
        unsafe {
            libc::kill(launcher, libc::SIGKILL);
            libc::waitpid(launcher, std::ptr::null_mut(), 0);
        }
        status.state = "failed".into();
        status.reason = Some(format!("{e:#}"));
        store::atomic(&dir.join("status.json"), &status)?;
        return Err(e);
    }
    status.state = "running".into();
    store::atomic(&dir.join("status.json"), &status)?;
    let cg = store::cgroup_path(config, &record.spec.id);
    let helper_pids: Vec<i32> =
        fs::read_to_string(format!("/proc/{launcher}/task/{launcher}/children"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .filter(|p| *p != status.init_pid)
            .collect();
    let helpers: Vec<_> = std::iter::once(launcher)
        .chain(helper_pids.iter().copied())
        .filter_map(|pid| linux::start_time(pid).map(|start| (pid, start)))
        .collect();
    let mut last_write = Instant::now();
    loop {
        let desired: String =
            store::read(&dir.join("desired.json")).unwrap_or_else(|_| "stopped".into());
        let procs = linux::processes(status.init_pid);
        status.process_count = procs.iter().filter(|p| p.3 != 'Z').count();
        status.memory_current = if record.spec.memory_mode == "cgroup" {
            cg.as_ref()
                .and_then(|p| fs::read_to_string(p.join("memory.current")).ok())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(u64::MAX)
        } else {
            let mut total: u64 = procs.iter().map(|p| p.2).sum();
            if record.spec.runtime == "proot" {
                for pid in std::iter::once(&launcher).chain(helper_pids.iter()) {
                    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/statm")) {
                        total += s
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0)
                            * 4096;
                    }
                }
            }
            total
        };
        status.memory_peak = status.memory_peak.max(status.memory_current);
        let oom = status.memory_current > record.spec.memory_bytes;
        let too_many = status.process_count as u64 > record.spec.pids_max;
        if desired == "stopped" || oom || too_many {
            if status.state == "paused" {
                for &(pid, start) in &helpers {
                    let _ = linux::pidfd_signal(pid, start, libc::SIGCONT);
                }
            }
            let _ = linux::pidfd_signal(status.init_pid, status.init_start, libc::SIGKILL);
            status.state = if oom || too_many { "failed" } else { "stopped" }.into();
            status.reason = if oom {
                Some("memory_limit_exceeded".into())
            } else if too_many {
                Some("process_limit_exceeded".into())
            } else {
                None
            };
            break;
        }
        let mut wait = 0;
        let ended = unsafe { libc::waitpid(launcher, &mut wait, libc::WNOHANG) };
        if ended == launcher || !linux::live(status.init_pid, status.init_start) {
            status.state = "failed".into();
            status.reason = Some(format!("sandbox init exited (wait status {wait})"));
            break;
        }
        if desired == "paused" && status.state != "paused" {
            if record.spec.runtime == "proot" {
                // Stop the tracer first: otherwise it can consume a tracee's
                // SIGSTOP and resume it while we are inspecting the tree.
                for &(pid, start) in &helpers {
                    linux::pidfd_signal(pid, start, libc::SIGSTOP)?;
                }
            }
            linux::pidfd_signal(status.init_pid, status.init_start, libc::SIGSTOP)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let tasks = linux::tasks(status.init_pid);
                if tasks.iter().all(|p| matches!(p.3, 'T' | 't' | 'Z')) {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "unable to freeze sandbox process tree"
                );
                for (pid, tid, start, _) in tasks {
                    linux::task_signal(pid, tid, start, libc::SIGSTOP);
                }
                thread::sleep(Duration::from_millis(2));
            }
            status.state = "paused".into();
            store::atomic(&dir.join("status.json"), &status)?;
        } else if desired == "running" && status.state == "paused" {
            for (pid, tid, start, _) in linux::tasks(status.init_pid) {
                linux::task_signal(pid, tid, start, libc::SIGCONT);
            }
            for &(pid, start, _, _) in &procs {
                let _ = linux::pidfd_signal(pid, start, libc::SIGCONT);
            }
            if record.spec.runtime == "proot" {
                for &(pid, start) in &helpers {
                    linux::pidfd_signal(pid, start, libc::SIGCONT)?;
                }
            }
            status.state = "running".into();
            store::atomic(&dir.join("status.json"), &status)?;
        }
        if last_write.elapsed() > Duration::from_millis(250) {
            store::atomic(&dir.join("status.json"), &status)?;
            last_write = Instant::now();
        }
        thread::sleep(Duration::from_millis(config.monitor_interval_ms));
    }
    // Reap the launcher, which reaps PID 1. Killing PID 1 tears down every descendant.
    // PRoot also waits for its non-traced filesystem helpers; end those first.
    for &(pid, start) in &helpers {
        if pid != launcher {
            let _ = linux::pidfd_signal(pid, start, libc::SIGKILL);
        }
    }
    unsafe {
        libc::waitpid(launcher, std::ptr::null_mut(), 0);
    }
    status.memory_current = 0;
    status.process_count = 0;
    store::atomic(&dir.join("status.json"), &status)?;
    Ok(())
}
