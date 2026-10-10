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
pub fn config(state: &Path) -> Result<NodeConfig> {
    let c: NodeConfig = read(&state.join("node.json"))?;
    c.validate()?;
    Ok(c)
}
pub fn status(dir: &Path) -> Result<Status> {
    let mut s: Status = read(&dir.join("status.json"))?;
    if matches!(s.state.as_str(), "starting" | "running" | "paused")
        && !linux::live(s.supervisor_pid, s.supervisor_start)
    {
        // Terminal state may have been published between the read and exit.
        s = read(&dir.join("status.json"))?;
        if !matches!(s.state.as_str(), "starting" | "running" | "paused") {
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
        if e.path().join("record.json").is_file() {
            out.push((
                e.path(),
                read::<Record>(&e.path().join("record.json"))?,
                status(&e.path())?,
            ));
        }
    }
    out.sort_by(|a, b| a.1.spec.id.cmp(&b.1.spec.id));
    Ok(out)
}
pub fn active(s: &Status) -> bool {
    matches!(s.state.as_str(), "running" | "paused" | "starting")
        || linux::live(s.init_pid, s.init_start)
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

fn cp(src: &Path, dst: &Path) -> Result<()> {
    let output = Command::new("cp")
        .args(["-a", "--reflink=auto", "--"])
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

pub fn create(state: &Path, spec: Spec) -> Result<Value> {
    spec.validate()?;
    let _lock = lock(state)?;
    let c = config(state)?;
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
    let setup = (|| -> Result<()> {
        cp(&spec.rootfs.canonicalize()?, &d.join("rootfs"))?;
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
        atomic(
            &d.join("status.json"),
            &Status {
                state: "stopped".into(),
                ..Default::default()
            },
        )?;
        atomic(&d.join("desired.json"), &"stopped")?;
        Ok(())
    })();
    if let Err(e) = setup {
        let _ = fs::remove_dir_all(&d);
        return Err(e);
    }
    start_locked(state, &d, &c)?;
    inspect(&d)
}

pub fn start_locked(state: &Path, d: &Path, c: &NodeConfig) -> Result<()> {
    let record: Record = read(&d.join("record.json"))?;
    let s = status(d)?;
    ensure!(!active(&s), "sandbox is already active");
    let pool = pool(c)?;
    admission(state, c, &record.spec)?;
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
