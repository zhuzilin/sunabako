use crate::{
    linux,
    model::{valid_id, NodeConfig, Record, Spec, Status},
};
use anyhow::{bail, ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn read<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(
        &fs::read(p).with_context(|| p.display().to_string())?,
    )?)
}
pub fn atomic<T: Serialize>(p: &Path, value: &T) -> Result<()> {
    let temp = p.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    fs::rename(temp, p)?;
    fs::File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}
pub fn lock(state: &Path) -> Result<fs::File> {
    fs::create_dir_all(state)?;
    fs::set_permissions(state, fs::Permissions::from_mode(0o711))?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join(".lock"))?;
    linux::flock(&f, true)?;
    Ok(f)
}
pub fn dir(state: &Path, id: &str) -> Result<PathBuf> {
    valid_id(id)?;
    Ok(state.join(id))
}
pub fn lifecycle_lock(d: &Path) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(d.join(".lifecycle.lock"))?;
    linux::flock(&file, true)?;
    Ok(file)
}

fn cancellation_path(state: &Path, token: &str) -> Result<PathBuf> {
    ensure!(
        token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid creation token"
    );
    Ok(state.join(".cancelled").join(token))
}

pub fn cancel_create(state: &Path, id: &str, token: &str) -> Result<Value> {
    let d = dir(state, id)?;
    let marker = cancellation_path(state, token)?;
    {
        // Serialize with admission, including requests that have not arrived
        // yet. Keep the marker after deletion so a late request cannot revive.
        let _lock = lock(state)?;
        if d.exists() {
            let owner: Value = read(&d.join("creation.json"))?;
            ensure!(
                owner["token"].as_str() == Some(token),
                "creation token does not own this sandbox"
            );
        }
        fs::create_dir_all(marker.parent().unwrap())?;
        atomic(&marker, &json!({"id": id, "token": token}))?;
        if !d.exists() {
            return Ok(json!({"cancelled":true,"deleted":true}));
        }
    }
    let _lifecycle = match lifecycle_lock(&d) {
        Ok(lock) => lock,
        Err(_error) if !d.exists() => return Ok(json!({"cancelled":true,"deleted":true})),
        Err(error) => return Err(error),
    };
    if !d.exists() {
        return Ok(json!({"cancelled":true,"deleted":true}));
    }
    let owner: Value = read(&d.join("creation.json"))?;
    ensure!(
        owner["token"].as_str() == Some(token),
        "creation ownership changed"
    );
    let current = status(&d)?;
    if current.state == "creating" {
        ensure!(
            owner["pid"].as_i64() == Some(current.supervisor_pid as i64)
                && owner["start"].as_u64() == Some(current.supervisor_start),
            "creation process identity changed"
        );
        linux::terminate_preparation(current.supervisor_pid, current.supervisor_start)?;
        atomic(
            &d.join("status.json"),
            &Status {
                state: "stopped".into(),
                reason: Some("creation cancelled".into()),
                ..Default::default()
            },
        )?;
    } else if active(&current) {
        transition(&d, "stopped")?;
    }
    let result = remove_stopped(state, &d, &config(state)?, true)?;
    Ok(json!({"cancelled":true,"deleted":true,"cleanup_pending":result["cleanup_pending"]}))
}
// The caller must hold this sandbox's lifecycle lock through detachment.
pub fn remove_stopped(state: &Path, d: &Path, cfg: &NodeConfig, deferred: bool) -> Result<Value> {
    let record: Record = read(&d.join("record.json"))?;
    let id = &record.spec.id;
    ensure!(!active(&status(d)?), "stop sandbox before delete");
    if let Some(cg) = cgroup_path(cfg, id) {
        if cg.exists() {
            fs::remove_dir(cg)?;
        }
    }
    // This stopped sandbox cannot restart while its lifecycle lock is
    // held. Atomic detachment releases its UID; admission scans tolerate
    // a stopped directory disappearing while they read it.
    use std::os::unix::fs::PermissionsExt;
    let trash = state.join(".trash");
    fs::create_dir_all(&trash)?;
    fs::set_permissions(&trash, fs::Permissions::from_mode(0o700))?;
    let deleted = trash.join(format!("{id}-{}", std::process::id()));
    fs::rename(d, &deleted)?;
    if deferred {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(state.join("cleanup.log"))?;
        let mut worker = Command::new(std::env::current_exe()?);
        worker
            .arg("--state")
            .arg(state)
            .arg("__gc")
            .arg(deleted.file_name().unwrap())
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        unsafe {
            worker.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        worker
            .spawn()
            .context("start deferred cleanup; use gc to retry")?;
        return Ok(json!({"deleted":id,"cleanup_pending":true}));
    }
    fs::remove_dir_all(deleted)?;
    Ok(json!({"deleted":id}))
}
pub fn config(state: &Path) -> Result<NodeConfig> {
    let c: NodeConfig = read(&state.join("node.json"))?;
    c.validate()?;
    Ok(c)
}
pub fn status(dir: &Path) -> Result<Status> {
    let mut s: Status = read(&dir.join("status.json"))?;
    if matches!(
        s.state.as_str(),
        "creating" | "starting" | "running" | "paused"
    ) && !linux::live(s.supervisor_pid, s.supervisor_start)
    {
        // Terminal state may have been published between the read and exit.
        s = read(&dir.join("status.json"))?;
        if !matches!(
            s.state.as_str(),
            "creating" | "starting" | "running" | "paused"
        ) {
            return Ok(s);
        }
        s.state = "failed".into();
        s.reason = Some("supervisor is not alive; inspect supervisor.log".into());
    }
    Ok(s)
}
pub fn records(state: &Path) -> Result<Vec<(PathBuf, Record, Status)>> {
    let mut out = vec![];
    for e in fs::read_dir(state)?.flatten() {
        let path = e.path();
        if path.join("record.json").is_file() {
            let entry: Result<(Record, Status)> =
                (|| Ok((read(&path.join("record.json"))?, status(&path)?)))();
            match entry {
                Ok((record, status)) => out.push((path, record, status)),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                        && fs::symlink_metadata(&path)
                            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
    }
    out.sort_by(|a, b| a.1.spec.id.cmp(&b.1.spec.id));
    Ok(out)
}
pub fn active(s: &Status) -> bool {
    matches!(
        s.state.as_str(),
        "creating" | "running" | "paused" | "starting"
    ) || linux::live(s.init_pid, s.init_start)
}
pub fn cgroup_path(c: &NodeConfig, id: &str) -> Option<PathBuf> {
    c.cgroup_parent
        .as_ref()
        .map(|p| p.join("sunabako").join(id))
}

pub fn pool(c: &NodeConfig) -> Result<Option<PathBuf>> {
    let Some(parent) = &c.cgroup_parent else {
        ensure!(c.allow_unbounded_memory_for_tests,
            "hard aggregate memory limit unavailable: configure cgroup_parent with a delegated writable memory+pids subtree. Production startup is refused. allow_unbounded_memory_for_tests is only for bounded functional tests, never safe oversubscription.");
        return Ok(None);
    };
    ensure!(parent.is_absolute(), "cgroup_parent must be absolute");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe {
        linux::cv(
            libc::statfs(linux::cstr(parent)?.as_ptr(), &mut stat),
            "inspect cgroup filesystem",
        )?;
    }
    ensure!(
        stat.f_type == 0x63677270,
        "cgroup_parent must be on a real cgroup-v2 filesystem"
    );
    let controllers = fs::read_to_string(parent.join("cgroup.controllers"))?;
    for v in ["memory", "pids"] {
        ensure!(
            controllers.split_whitespace().any(|s| s == v),
            "missing delegated {v} controller"
        );
    }
    fs::write(parent.join("cgroup.subtree_control"), "+memory +pids")
        .context("enable delegated controllers")?;
    let p = parent.join("sunabako");
    fs::create_dir_all(&p)?;
    fs::write(p.join("memory.max"), c.memory_capacity_bytes.to_string())?;
    fs::write(p.join("memory.swap.max"), "0")?;
    fs::write(p.join("memory.oom.group"), "1")?;
    fs::write(p.join("cgroup.subtree_control"), "+memory +pids")?;
    ensure!(
        fs::read_to_string(p.join("memory.max"))?.trim() == c.memory_capacity_bytes.to_string(),
        "pool memory.max verification failed"
    );
    Ok(Some(p))
}

fn admission(state: &Path, c: &NodeConfig, spec: &Spec) -> Result<()> {
    let list = records(state)?;
    let reserved: u128 = list
        .iter()
        .filter(|(_, r, s)| r.spec.id != spec.id && active(s))
        .map(|(_, r, _)| r.spec.memory_bytes as u128)
        .sum();
    let cap = (c.memory_capacity_bytes as f64 * c.memory_overcommit) as u128;
    ensure!(
        reserved + spec.memory_bytes as u128 <= cap,
        "node memory admission exhausted ({reserved} reserved, {} requested, {cap} schedulable)",
        spec.memory_bytes
    );
    for gpu in &spec.gpus {
        let users: Vec<_> = list
            .iter()
            .filter(|(_, r, s)| r.spec.id != spec.id && active(s) && r.spec.gpus.contains(gpu))
            .collect();
        ensure!(
            users.is_empty()
                || (spec.gpu_mode == "shared"
                    && users.iter().all(|(_, r, _)| r.spec.gpu_mode == "shared")),
            "GPU {gpu} has an exclusive reservation"
        );
        ensure!(
            users.len() < c.gpu_slots_per_device,
            "GPU {gpu} sharing slots exhausted"
        );
    }
    Ok(())
}

fn cp(src: &Path, dst: &Path, require_reflink: bool) -> Result<()> {
    let output = Command::new("cp")
        .args([
            "-a",
            if require_reflink {
                "--reflink=always"
            } else {
                "--reflink=auto"
            },
            "--",
        ])
        .arg(src)
        .arg(dst)
        .output()?;
    ensure!(
        output.status.success(),
        "copy rootfs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn checked_path(root: &Path, path: &Path) -> Result<()> {
    let mut parent = path;
    while fs::symlink_metadata(parent).is_err() {
        parent = parent.parent().context("invalid image path")?;
    }
    ensure!(
        parent.canonicalize()?.starts_with(root.canonicalize()?),
        "image path escapes rootfs: {}",
        path.display()
    );
    Ok(())
}
fn copy_library(src: &Path, root: &Path) -> Result<()> {
    let dest = root.join(src.strip_prefix("/")?);
    checked_path(root, &dest)?;
    fs::create_dir_all(dest.parent().unwrap())?;
    // Copy the referent under its requested SONAME; no host-facing symlinks.
    if !dest.exists() {
        fs::copy(src, &dest)?;
    }
    Ok(())
}
fn dependencies(binary: &Path, root: &Path) -> Result<()> {
    copy_library(binary, root)?;
    let output = Command::new("ldd").arg(binary).output()?;
    for token in String::from_utf8_lossy(&output.stdout).split_whitespace() {
        if token.starts_with('/') && Path::new(token).is_file() {
            copy_library(Path::new(token), root)?;
        }
    }
    Ok(())
}
fn gpu(spec: &Spec, root: &Path) -> Result<Vec<String>> {
    if spec.gpus.is_empty() {
        return Ok(vec![]);
    }
    let out = Command::new("nvidia-smi").args(["-q", "-x"]).output()?;
    ensure!(out.status.success(), "nvidia-smi discovery failed");
    let devices: String = String::from_utf8_lossy(&out.stdout).into();
    let blocks: Vec<_> = devices.split("<gpu id=").skip(1).collect();
    let field = |block: &str, name: &str| -> Result<String> {
        Ok(block
            .split_once(&format!("<{name}>"))
            .context("missing NVIDIA XML field")?
            .1
            .split_once(&format!("</{name}>"))
            .context("invalid NVIDIA XML field")?
            .0
            .trim()
            .to_string())
    };
    let mut uuids = vec![];
    for index in &spec.gpus {
        let block = blocks
            .get(*index as usize)
            .with_context(|| format!("GPU index {index} not available"))?;
        let minor = field(block, "minor_number")?;
        ensure!(
            minor.bytes().all(|b| b.is_ascii_digit()),
            "invalid device minor"
        );
        uuids.push(field(block, "uuid")?);
        linux::copy_device(Path::new(&format!("/dev/nvidia{minor}")), root)?;
    }
    for name in ["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"] {
        if Path::new(name).exists() {
            linux::copy_device(Path::new(name), root)?;
        }
    }
    dependencies(Path::new("/usr/bin/nvidia-smi"), root)?;
    for name in [
        "libcuda.so.1",
        "libnvidia-ml.so.1",
        "libnvidia-ptxjitcompiler.so.1",
        "libnvidia-nvvm.so.4",
    ] {
        let lib = Path::new("/usr/lib/x86_64-linux-gnu").join(name);
        if lib.exists() {
            dependencies(&lib, root)?;
        }
    }
    for entry in fs::read_dir("/usr/lib/x86_64-linux-gnu")?.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("libnvidia-gpucomp.so.")
        {
            dependencies(&entry.path(), root)?;
        }
    }
    Ok(uuids)
}

fn allocate_uid(c: &NodeConfig, existing: &[(u32, u32)]) -> Result<u32> {
    (0..c.max_sandboxes as u32)
        .map(|slot| c.uid_start + slot * c.uid_range_size)
        .find(|&uid| {
            // Also account for stopped sandboxes made with an older configuration.
            existing.iter().all(|&(start, size)| {
                u64::from(uid) + u64::from(c.uid_range_size) <= u64::from(start)
                    || u64::from(start) + u64::from(size) <= u64::from(uid)
            })
        })
        .context("UID range exhausted")
}

pub fn create(state: &Path, spec: Spec, creation_token: Option<&str>) -> Result<Value> {
    spec.validate()?;
    let c = config(state)?;
    let admission_lock = lock(state)?;
    if let Some(token) = creation_token {
        ensure!(
            !cancellation_path(state, token)?.exists(),
            "creation was cancelled"
        );
        let pid = std::process::id() as i32;
        ensure!(
            unsafe { libc::getpgrp() } == pid && unsafe { libc::getsid(0) } == pid,
            "owned creation requires a dedicated preparation session"
        );
    }
    let d = dir(state, &spec.id)?;
    ensure!(!d.exists(), "sandbox id already exists");
    if spec.runtime == "proot" {
        ensure!(
            c.proot_binary
                .as_ref()
                .is_some_and(|p| p.is_absolute() && p.is_file()),
            "configure an absolute patched proot_binary (scripts/build-proot.sh)"
        );
        let yama: u32 = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")?
            .trim()
            .parse()?;
        ensure!(yama>=1,"PRoot isolation requires Yama ptrace_scope >= 1 to protect the tracer from its tracees");
        let state_path = state.canonicalize()?;
        for m in &spec.mounts {
            let source = m.source.canonicalize()?;
            ensure!(
                !source.starts_with(&state_path) && !state_path.starts_with(&source),
                "mount source must not expose sunabako state"
            );
            for other in &spec.mounts {
                if m.readonly && !other.readonly {
                    let writable = other.source.canonicalize()?;
                    ensure!(
                        !source.starts_with(&writable) && !writable.starts_with(&source),
                        "read-only and writable mount sources must not overlap"
                    );
                }
            }
        }
    }
    let p = pool(&c)?;
    ensure!(
        spec.memory_mode != "cgroup" || p.is_some(),
        "per-sandbox cgroup memory mode requires cgroup_parent"
    );
    admission(state, &c, &spec)?;
    let existing = records(state)?;
    ensure!(
        existing.len() < c.max_sandboxes,
        "max_sandboxes reached (delete unused sandboxes)"
    );
    let uid = allocate_uid(
        &c,
        &existing
            .iter()
            .map(|(_, r, _)| (r.uid, r.uid_range_size))
            .collect::<Vec<_>>(),
    )?;
    let uid_range_size = if spec.runtime == "native" {
        c.uid_range_size
    } else {
        1
    };
    fs::create_dir(&d)?;
    fs::set_permissions(&d, fs::Permissions::from_mode(0o711))?;
    let reservation = (|| -> Result<()> {
        atomic(
            &d.join("status.json"),
            &Status {
                state: "creating".into(),
                supervisor_pid: std::process::id() as i32,
                supervisor_start: linux::start_time(std::process::id() as i32).unwrap_or(0),
                ..Default::default()
            },
        )?;
        atomic(
            &d.join("record.json"),
            &Record {
                spec: spec.clone(),
                uid,
                uid_range_size,
                created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                gpu_uuids: vec![],
            },
        )?;
        if let Some(token) = creation_token {
            atomic(
                &d.join("creation.json"),
                &json!({"token":token,"pid":std::process::id(),
                "start":linux::start_time(std::process::id() as i32).unwrap_or(0)}),
            )?;
        }
        Ok(())
    })();
    if let Err(error) = reservation {
        let _ = fs::remove_dir_all(&d);
        return Err(error);
    }
    // Admission and UID ranges stay reserved while independent clones proceed
    // concurrently. Lifecycle mutations reject the creating state.
    drop(admission_lock);
    let setup = (|| -> Result<()> {
        // Reserve cold preparations too, so cluster scheduling sees their
        // resource demand before the potentially long image import finishes.
        let image = crate::images::prepare(&spec.rootfs, state, &c)?;
        let _clone_slot =
            crate::images::preparation_slot(state, "clone", c.rootfs_clone_concurrency)?;
        cp(
            &image.rootfs,
            &d.join("rootfs"),
            crate::images::is_oci(&spec.rootfs),
        )?;
        let root = d.join("rootfs");
        // Images and filesystem snapshots must never grant devices implicitly.
        let dev = root.join("dev");
        if let Ok(md) = fs::symlink_metadata(&dev) {
            if md.is_dir() {
                fs::remove_dir_all(&dev)?;
            } else {
                fs::remove_file(&dev)?;
            }
        }
        for name in [
            "workspace",
            "root",
            "tmp",
            "proc",
            "sys",
            "dev",
            "dev/shm",
            "dev/pts",
        ] {
            checked_path(&root, &root.join(name))?;
            fs::create_dir_all(root.join(name))?;
        }
        for m in &spec.mounts {
            let dest = root.join(m.target.strip_prefix("/")?);
            checked_path(&root, &dest)?;
            fs::create_dir_all(&dest)?;
            ensure!(
                dest.canonicalize()?.starts_with(root.canonicalize()?),
                "mount target escapes rootfs"
            );
        }
        for dev in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"] {
            linux::copy_device(Path::new(dev), &root)?;
        }
        for (name, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            std::os::unix::fs::symlink(target, root.join("dev").join(name))?;
        }
        let gpu_uuids = gpu(&spec, &root)?;
        if Path::new("/etc/resolv.conf").exists() {
            checked_path(&root, &root.join("etc/resolv.conf"))?;
            fs::copy("/etc/resolv.conf", root.join("etc/resolv.conf"))?;
        }
        let out = Command::new("chown")
            .args(["-R", "-h", &format!("{uid}:{uid}"), "--"])
            .arg(&root)
            .output()?;
        ensure!(
            out.status.success(),
            "chown rootfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if uid_range_size > 1 {
            // Guest users must traverse '/', while the outer sandbox directory
            // keeps every other sandbox UID out of this rootfs and its metadata.
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(&d, fs::Permissions::from_mode(0o700))?;
            unsafe {
                linux::cv(
                    libc::chown(linux::cstr(&d)?.as_ptr(), uid, uid),
                    "own sandbox directory",
                )?;
            }
        } else {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let record = Record {
            spec,
            uid,
            uid_range_size,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            gpu_uuids,
        };
        atomic(&d.join("record.json"), &record)?;
        atomic(&d.join("desired.json"), &"stopped")?;
        Ok(())
    })();
    if let Err(error) = setup {
        let _lifecycle = lifecycle_lock(&d)?;
        atomic(
            &d.join("status.json"),
            &Status {
                state: "stopped".into(),
                reason: Some("creation failed".into()),
                ..Default::default()
            },
        )?;
        remove_stopped(state, &d, &c, false)?;
        return Err(error);
    }
    // The creating record already owns its admission and UID reservation.
    // Keep it active through startup instead of waiting behind new admissions
    // to release and reacquire those same resources under the node lock.
    let record: Record = read(&d.join("record.json"))?;
    // Cancellation must either stop the preparation worker or observe a
    // completed launch. It cannot race the change of supervisor identity.
    let _lifecycle = lifecycle_lock(&d)?;
    if let Some(token) = creation_token {
        ensure!(
            !cancellation_path(state, token)?.exists(),
            "creation was cancelled"
        );
    }
    launch_reserved(state, &d, &c, &record)?;
    inspect(&d)
}

pub fn start_locked(state: &Path, d: &Path, c: &NodeConfig) -> Result<()> {
    let record: Record = read(&d.join("record.json"))?;
    let s = status(d)?;
    ensure!(!active(&s), "sandbox is already active");
    admission(state, c, &record.spec)?;
    launch_reserved(state, d, c, &record)
}

fn launch_reserved(state: &Path, d: &Path, c: &NodeConfig, record: &Record) -> Result<()> {
    let pool = pool(c)?;
    if let Some(p) = pool {
        let cg = p.join(&record.spec.id);
        fs::create_dir_all(&cg)?;
        fs::write(
            cg.join("memory.max"),
            if record.spec.memory_mode == "cgroup" {
                record.spec.memory_bytes.to_string()
            } else {
                "max".into()
            },
        )?;
        fs::write(cg.join("memory.oom.group"), "1")?;
        fs::write(cg.join("pids.max"), record.spec.pids_max.to_string())?;
    }
    atomic(&d.join("desired.json"), &"running")?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.join("supervisor.log"))?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("--state")
        .arg(state)
        .arg("__supervise")
        .arg(&record.spec.id)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let initial = Status {
        state: "starting".into(),
        supervisor_pid: child.id() as i32,
        supervisor_start: linux::start_time(child.id() as i32).unwrap_or(0),
        ..Default::default()
    };
    atomic(&d.join("status.json"), &initial)?;
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let s = status(d)?;
        if s.state == "running" {
            return Ok(());
        }
        if s.state == "failed" || child.try_wait()?.is_some() {
            bail!(
                "sandbox startup failed: {}; log: {}",
                s.reason.unwrap_or_default(),
                d.join("supervisor.log").display()
            );
        }
        ensure!(
            Instant::now() < until,
            "sandbox startup timed out; inspect supervisor.log"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub fn inspect(d: &Path) -> Result<Value> {
    let r: Record = read(&d.join("record.json"))?;
    Ok(
        json!({"spec":r.spec,"uid":r.uid,"uid_range_size":r.uid_range_size,"status":status(d)?,"directory":d}),
    )
}
pub fn transition(d: &Path, desired: &str) -> Result<Value> {
    let s = status(d)?;
    if desired == "stopped" && !active(&s) {
        return inspect(d);
    }
    ensure!(active(&s), "sandbox is not active; use start");
    atomic(&d.join("desired.json"), &desired)?;
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let s = status(d)?;
        if s.state == desired {
            return inspect(d);
        }
        ensure!(s.state != "failed", "sandbox failed: {:?}", s.reason);
        ensure!(Instant::now() < end, "transition to {desired} timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_reserves_resources_before_waiting_for_an_image() {
        let base =
            std::env::temp_dir().join(format!("sunabako-cold-reservation-{}", std::process::id()));
        let state = base.join("state");
        let source = base.join("source");
        let cache = base.join("cache");
        for path in [&state, &source, &cache] {
            fs::create_dir_all(path).unwrap();
        }
        let hash = "a".repeat(64);
        fs::write(source.join("oci-layout"), "{}").unwrap();
        atomic(
            &source.join("index.json"),
            &json!({"manifests": [{"digest": format!("sha256:{hash}")}]}),
        )
        .unwrap();
        let c = NodeConfig {
            memory_capacity_bytes: 64 << 20,
            allow_unbounded_memory_for_tests: true,
            image_cache_dir: Some(cache.clone()),
            ..Default::default()
        };
        atomic(&state.join("node.json"), &c).unwrap();
        let pin = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(cache.join(format!("{hash}.lock")))
            .unwrap();
        linux::flock(&pin, true).unwrap();
        let spec: Spec = serde_json::from_value(json!({
            "id": "pending", "rootfs": source, "memory_bytes": 64 << 20, "memory_mode": "rss"
        }))
        .unwrap();
        let worker_state = state.clone();
        let worker_spec = spec.clone();
        let worker = std::thread::spawn(move || create(&worker_state, worker_spec, None));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !state.join("pending/record.json").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(status(&state.join("pending")).unwrap().state, "creating");
        let mut next = spec.clone();
        next.id = "next".into();
        assert!(admission(&state, &c, &next)
            .unwrap_err()
            .to_string()
            .contains("memory admission"));
        // Publish an intentionally incomplete fixture to make setup fail after
        // the lock is released, without invoking umoci or starting a sandbox.
        fs::create_dir(cache.join(&hash)).unwrap();
        atomic(
            &cache.join(&hash).join("cache.json"),
            &json!({"bytes": 0, "last_used": 0}),
        )
        .unwrap();
        drop(pin);
        assert!(worker.join().unwrap().is_err());
        assert!(!state.join("pending").exists());
        admission(&state, &c, &next).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn creating_sandboxes_reserve_resources_until_the_creator_exits() {
        let state =
            std::env::temp_dir().join(format!("sunabako-reservation-{}", std::process::id()));
        let d = state.join("pending");
        fs::create_dir_all(&d).unwrap();
        let c = NodeConfig {
            memory_capacity_bytes: 64 << 20,
            memory_overcommit: 1.0,
            ..Default::default()
        };
        let spec: Spec = serde_json::from_value(json!({
            "id": "pending", "rootfs": "/unused", "memory_bytes": 64 << 20,
            "gpus": [0], "gpu_mode": "exclusive"
        }))
        .unwrap();
        atomic(
            &d.join("record.json"),
            &Record {
                spec: spec.clone(),
                uid: 60000,
                uid_range_size: 1,
                created_at: 0,
                gpu_uuids: vec![],
            },
        )
        .unwrap();
        let mut s = Status {
            state: "creating".into(),
            supervisor_pid: std::process::id() as i32,
            supervisor_start: linux::start_time(std::process::id() as i32).unwrap(),
            ..Default::default()
        };
        atomic(&d.join("status.json"), &s).unwrap();
        let mut next = spec.clone();
        next.id = "next".into();
        assert!(admission(&state, &c, &next)
            .unwrap_err()
            .to_string()
            .contains("memory admission"));
        let larger = NodeConfig {
            memory_capacity_bytes: 128 << 20,
            ..c
        };
        assert!(admission(&state, &larger, &next)
            .unwrap_err()
            .to_string()
            .contains("exclusive reservation"));
        let list = records(&state).unwrap();
        let uids: Vec<_> = list
            .iter()
            .map(|(_, r, _)| (r.uid, r.uid_range_size))
            .collect();
        assert_ne!(allocate_uid(&larger, &uids).unwrap(), 60000);
        // A different process start time represents a dead creator even if its PID was reused.
        s.supervisor_start += 1;
        atomic(&d.join("status.json"), &s).unwrap();
        assert_eq!(status(&d).unwrap().state, "failed");
        admission(&state, &larger, &next).unwrap();
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn uid_allocation_checks_entire_existing_ranges_after_reconfiguration() {
        let c = NodeConfig {
            uid_start: 100000,
            uid_range_size: 65536,
            max_sandboxes: 3,
            ..Default::default()
        };
        assert_eq!(allocate_uid(&c, &[]).unwrap(), 100000);
        // A legacy single UID in the middle reserves the entire overlapping slot.
        assert_eq!(allocate_uid(&c, &[(100500, 1)]).unwrap(), 165536);
        // A range made with an older stride can overlap two new slots.
        assert_eq!(allocate_uid(&c, &[(130000, 65536)]).unwrap(), 231072);
        assert!(allocate_uid(&c, &[(100000, 3 * 65536)]).is_err());
    }
}
