//! Compressed OCI layouts may live on shared storage. Rootfs trees and writable
//! reflink clones stay on local disk; no mount or FUSE is required.
use crate::{linux, model::NodeConfig, store};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct Prepared {
    pub rootfs: PathBuf,
    // Pin until the caller finishes making its independent reflink clone.
    _pin: Option<File>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    bytes: u64,
    last_used: u64,
}

pub fn is_oci(path: &Path) -> bool {
    path.join("oci-layout").is_file() && path.join("index.json").is_file()
}

fn key(source: &Path) -> Result<String> {
    let index: Value = store::read(&source.join("index.json"))?;
    let digest = index["manifests"][0]["digest"]
        .as_str()
        .context("OCI manifest digest missing")?;
    let hash = digest
        .strip_prefix("sha256:")
        .context("OCI manifest must use sha256")?;
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid OCI manifest digest"
    );
    Ok(hash.to_owned())
}

fn cache_lock(cache: &Path, key: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cache.join(format!("{key}.lock")))?)
}

fn free_bytes(path: &Path) -> Result<u64> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    unsafe {
        linux::cv(
            libc::statvfs(linux::cstr(path)?.as_ptr(), &mut stat),
            "inspect image cache disk space",
        )?;
    }
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

fn local_disk(path: &Path) -> Result<()> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe {
        linux::cv(
            libc::statfs(linux::cstr(path)?.as_ptr(), &mut stat),
            "inspect image cache filesystem",
        )?;
    }
    ensure!(
        !matches!(stat.f_type, 0x6969 | 0x65735546 | 0x00c36400 | 0xff534d42),
        "OCI rootfs cache and sandbox state must be on local disk, not NFS/FUSE/Ceph/SMB"
    );
    Ok(())
}

fn prune(cache: &Path, config: &NodeConfig, incoming: u64) -> Result<File> {
    let lock = cache_lock(cache, "gc")?;
    linux::flock(&lock, true)?;
    let mut entries = Vec::new();
    for item in fs::read_dir(cache)? {
        let path = item?.path();
        if path.join("cache.json").is_file() {
            let entry: Entry = store::read(&path.join("cache.json"))?;
            entries.push((entry.last_used, path, entry.bytes));
        }
    }
    entries.sort_by_key(|entry| entry.0);
    let mut total: u64 = entries.iter().map(|entry| entry.2).sum();
    for (_, path, bytes) in entries {
        if total.saturating_add(incoming) <= config.image_cache_max_bytes
            && free_bytes(cache)? >= config.image_cache_min_free_bytes
        {
            break;
        }
        let pin = cache_lock(
            cache,
            path.file_name()
                .unwrap()
                .to_str()
                .context("invalid cache key")?,
        )?;
        if unsafe { libc::flock(pin.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                continue;
            }
            return Err(error.into());
        }
        fs::remove_dir_all(&path)?;
        total = total.saturating_sub(bytes);
    }
    ensure!(total.saturating_add(incoming) <= config.image_cache_max_bytes
        && free_bytes(cache)? >= config.image_cache_min_free_bytes,
        "image cache admission exhausted: active clones or pinned images prevent reclaiming local disk");
    Ok(lock)
}

pub fn preparation_slot(directory: &Path, kind: &str, concurrency: usize) -> Result<File> {
    // Let one waiter look for the next available slot. Other callers block in
    // the kernel instead of racing it with shorter retry delays on each arrival.
    // This lock is released as soon as a slot is acquired; it does not serialize
    // the import, clone, or deletion itself.
    let admission = cache_lock(directory, &format!("{kind}-admission"))?;
    linux::flock(&admission, true)?;
    loop {
        for slot in 0..concurrency {
            let lock = cache_lock(directory, &format!("{kind}-{slot}"))?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(lock);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(error.into());
            }
        }
        // Only this waiter polls. A short fixed delay avoids leaving a released
        // slot idle while everyone else sleeps on the admission lock.
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn prepare(source: &Path, state: &Path, config: &NodeConfig) -> Result<Prepared> {
    if !is_oci(source) {
        return Ok(Prepared {
            rootfs: source.canonicalize()?,
            _pin: None,
        });
    }
    let cache = config
        .image_cache_dir
        .as_ref()
        .context("configure image_cache_dir on local disk to use compressed OCI layouts")?;
    fs::create_dir_all(cache)?;
    fs::create_dir_all(state)?;
    local_disk(cache)?;
    local_disk(state)?;
    let hash = key(source)?;
    let bundle = cache.join(&hash);
    let pin = cache_lock(cache, &hash)?;
    // Warm clones share the pin. Only a cold importer needs exclusivity.
    linux::flock(&pin, false)?;
    if !bundle.join("cache.json").is_file() {
        linux::flock(&pin, true)?;
    }
    if !bundle.join("cache.json").is_file() {
        let _import_slot =
            preparation_slot(cache, "import", config.image_cache_import_concurrency)?;
        prune(cache, config, 0)?;
        let temporary = cache.join(format!(".{hash}.unpack"));
        if temporary.exists() {
            fs::remove_dir_all(&temporary)?;
        }
        fs::create_dir_all(&temporary)?;
        let log_path = cache.join(format!(".{hash}.unpack.log"));
        let log = File::create(&log_path)?;
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new("umoci");
        // The cache needs only a rootfs. Full bundle unpack also walks and
        // hashes the tree for a repack manifest that sandbox creation never uses.
        command
            .args(["raw", "unpack", "--rootless", "--image"])
            .arg(format!("{}:image", source.display()))
            .arg(temporary.join("rootfs"))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("image importer parent exited"));
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let unpack = (|| -> Result<()> {
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(
                        status.success(),
                        "unpack compressed OCI image on local disk: {}",
                        fs::read_to_string(&log_path).unwrap_or_default()
                    );
                    return Ok(());
                }
                ensure!(
                    free_bytes(cache)? >= config.image_cache_min_free_bytes,
                    "image cache admission exhausted: local disk reached reserve during unpack"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&log_path);
        if let Err(error) = unpack {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }
        let output = Command::new("du")
            .args(["-sb", "--"])
            .arg(&temporary)
            .output()?;
        ensure!(
            output.status.success(),
            "measure unpacked image size failed"
        );
        let bytes = String::from_utf8(output.stdout)?
            .split_whitespace()
            .next()
            .context("missing image size")?
            .parse::<u64>()?;
        if bytes > config.image_cache_max_bytes {
            fs::remove_dir_all(&temporary)?;
            bail!("image cache admission exhausted: image exceeds image_cache_max_bytes");
        }
        // Hold the capacity lock until publication so simultaneous imports
        // cannot each admit themselves against the same free cache budget.
        let _capacity_lock = match prune(cache, config, bytes) {
            Ok(lock) => lock,
            Err(error) => {
                fs::remove_dir_all(&temporary)?;
                return Err(error);
            }
        };
        store::atomic(
            &temporary.join("cache.json"),
            &Entry {
                bytes,
                last_used: 0,
            },
        )?;
        fs::rename(&temporary, &bundle)?;
    }
    let mut entry: Entry = store::read(&bundle.join("cache.json"))?;
    entry.last_used = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    store::atomic(&bundle.join("cache.json"), &entry)?;
    ensure!(
        bundle.join("rootfs/bin/sh").exists(),
        "cached OCI image must contain /bin/sh"
    );
    prune(cache, config, 0)?;
    unsafe {
        linux::cv(
            libc::flock(pin.as_raw_fd(), libc::LOCK_SH),
            "pin image cache",
        )?;
    }
    Ok(Prepared {
        rootfs: bundle.join("rootfs"),
        _pin: Some(pin),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_import_slots_bound_concurrency_and_release_waiters() {
        let path =
            std::env::temp_dir().join(format!("sunabako-import-slots-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let first = preparation_slot(&path, "import", 2).unwrap();
        let second = preparation_slot(&path, "import", 2).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let other_path = path.clone();
        let waiter = std::thread::spawn(move || {
            let slot = preparation_slot(&other_path, "import", 2).unwrap();
            tx.send(()).unwrap();
            slot
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(first);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(waiter.join().unwrap());
        drop(second);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn new_arrivals_do_not_overtake_the_waiter_for_a_busy_slot() {
        let path = std::env::temp_dir().join(format!("sunabako-slot-order-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let occupied = preparation_slot(&path, "clone", 1).unwrap();
        let probe = cache_lock(&path, "clone-admission").unwrap();
        // Concurrent process tests may briefly inherit the initial admission
        // descriptor before exec. Wait for that lock to clear so it cannot be
        // mistaken for the first waiter below. Explicit unlock also releases
        // any forked copy of this probe's open file description.
        linux::flock(&probe, true).unwrap();
        assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) }, 0);
        let (order_tx, order_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_path = path.clone();
        let first_tx = order_tx.clone();
        let first = std::thread::spawn(move || {
            let _slot = preparation_slot(&first_path, "clone", 1).unwrap();
            first_tx.send("waiting").unwrap();
            release_rx.recv().unwrap();
        });
        // Establish that the first request is waiting before the new arrival.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EWOULDBLOCK)
                );
                break;
            }
            assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) }, 0);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let second_path = path.clone();
        let second = std::thread::spawn(move || {
            let _slot = preparation_slot(&second_path, "clone", 1).unwrap();
            order_tx.send("new").unwrap();
        });
        drop(occupied);
        let first_result = order_rx.recv_timeout(Duration::from_secs(2));
        // Release before asserting so a failed check cannot strand the waiter.
        release_tx.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(first_result.unwrap(), "waiting");
        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "new"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn eviction_skips_pinned_image_and_reclaims_it_after_release() {
        let path = std::env::temp_dir().join(format!("sunabako-image-gc-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        for (key, last_used) in [("old", 1), ("recent", 2)] {
            let bundle = path.join(key);
            fs::create_dir_all(&bundle).unwrap();
            store::atomic(
                &bundle.join("cache.json"),
                &Entry {
                    bytes: 40,
                    last_used,
                },
            )
            .unwrap();
        }
        let pin = cache_lock(&path, "old").unwrap();
        unsafe {
            assert_eq!(libc::flock(pin.as_raw_fd(), libc::LOCK_SH), 0);
        }
        let mut config = NodeConfig {
            image_cache_max_bytes: 50,
            image_cache_min_free_bytes: 0,
            ..Default::default()
        };
        prune(&path, &config, 0).unwrap();
        assert!(path.join("old").exists());
        assert!(!path.join("recent").exists());
        config.image_cache_max_bytes = 1;
        assert!(prune(&path, &config, 0)
            .unwrap_err()
            .to_string()
            .contains("admission exhausted"));
        // Other tests spawn processes concurrently. Dropping only this fd
        // need not release a lock still inherited by a child before exec.
        assert_eq!(unsafe { libc::flock(pin.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(pin);
        prune(&path, &config, 0).unwrap();
        assert!(!path.join("old").exists());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn rejects_manifest_digest_that_escapes_cache() {
        let path = std::env::temp_dir().join(format!("sunabako-image-key-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(
            path.join("index.json"),
            r#"{"manifests":[{"digest":"sha256:../../escape"}]}"#,
        )
        .unwrap();
        assert!(key(&path).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
