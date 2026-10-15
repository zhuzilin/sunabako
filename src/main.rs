#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("sunabako currently supports Linux x86_64");
mod fsbroker;
mod images;
mod linux;
mod model;
mod runtime;
mod store;

use anyhow::{bail, ensure, Context, Result};
use model::{NodeConfig, Record, Request, Spec, Status};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn input<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    if path == "-" {
        let mut s = String::new();
        io::stdin().take(20 << 20).read_to_string(&mut s)?;
        Ok(serde_json::from_str(&s)?)
    } else {
        store::read(Path::new(path))
    }
}
fn command_request(args: &[String]) -> Request {
    let args = if args.first().map(String::as_str) == Some("--") {
        &args[1..]
    } else {
        args
    };
    Request::Exec {
        argv: args.to_vec(),
        env: BTreeMap::new(),
        cwd: "/workspace".into(),
        timeout: 120,
        user: "root".into(),
    }
}
fn usage() -> Value {
    json!({"usage":[
        "sunabako doctor",
        "sunabako --state DIR init-node CONFIG.json",
        "sunabako --state DIR set-proot /absolute/path/to/proot",
        "sunabako --state DIR create SPEC.json|-",
        "sunabako --state DIR create SPEC.json|- --token TOKEN",
        "sunabako --state DIR cancel-create ID TOKEN",
        "sunabako --state DIR list|capacity",
        "sunabako --state DIR inspect|pause|resume|stop|start|delete ID",
        "sunabako --state DIR delete ID --defer",
        "sunabako --state DIR gc",
        "sunabako --state DIR exec ID -- COMMAND [ARGS...]",
        "sunabako --state DIR rpc ID REQUEST.json|-",
        "sunabako --state DIR hibernate ID -- CHECKPOINT_COMMAND [ARGS...]",
        "sunabako --state DIR restore ID -- RESTORE_COMMAND [ARGS...]",
        "sunabako --state DIR snapshot ID DESTINATION"
    ]})
}
fn doctor() -> Result<Value> {
    let out = Command::new("unshare")
        .args(["-Urpf", "--mount", "--propagation", "unchanged", "true"])
        .output()?;
    Ok(
        json!({"uid":unsafe{libc::geteuid()},"namespaces_available":out.status.success(),"namespace_error":String::from_utf8_lossy(&out.stderr),
        "apparmor":fs::read_to_string("/proc/self/attr/current").unwrap_or_default().trim(),
        "cgroup_controllers":fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default().trim(),
        "outer_memory_max":fs::read_to_string("/sys/fs/cgroup/memory.max").unwrap_or_default().trim(),
        "landlock_abi":unsafe{libc::syscall(libc::SYS_landlock_create_ruleset,0usize,0usize,1)},
        "production_requirement":"A delegated writable cgroup subtree for the hard aggregate sandbox memory limit. Native directory binds also require mount permission."}),
    )
}
fn run() -> Result<Value> {
    let mut a: Vec<String> = std::env::args().skip(1).collect();
    let state = if a.first().map(String::as_str) == Some("--state") {
        ensure!(a.len() > 2, "--state requires DIR and command");
        let p = PathBuf::from(a.remove(1));
        a.remove(0);
        p
    } else {
        PathBuf::from("/var/lib/sunabako")
    };
    ensure!(state.is_absolute(), "state directory must be absolute");
    let cmd = a.first().map(String::as_str).unwrap_or("help");
    if cmd == "__serve" {
        runtime::serve_inside_proot(
            a.get(1).context("listener FD")?.parse()?,
            a.get(2).context("ready FD")?.parse()?,
        )?;
        return Ok(json!({"ok":true}));
    }
    if matches!(cmd, "help" | "--help" | "-h") {
        return Ok(usage());
    }
    if cmd == "doctor" {
        return doctor();
    }
    if cmd == "--version" {
        return Ok(json!({"version":env!("CARGO_PKG_VERSION")}));
    }
    linux::require_root()?;
    if cmd == "set-proot" {
        let binary = PathBuf::from(a.get(1).context("set-proot requires an executable path")?);
        ensure!(binary.is_absolute(), "PRoot path must be absolute");
        let binary = fs::canonicalize(binary)?;
        let metadata = fs::metadata(&binary)?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "PRoot path must be an executable file"
        );
        // Use an immutable versioned binary: active tracers keep their executable,
        // and new starts grant Landlock access to the same inode they execute.
        let _lock = store::lock(&state)?;
        let mut cfg = store::config(&state)?;
        cfg.proot_binary = Some(binary);
        store::atomic(&state.join("node.json"), &cfg)?;
        return Ok(json!({"config":cfg}));
    }
    if cmd == "init-node" {
        let cfg: NodeConfig = input(a.get(1).context("init-node requires CONFIG.json")?)?;
        cfg.validate()?;
        let _lock = store::lock(&state)?;
        ensure!(
            store::records(&state)?
                .iter()
                .all(|(_, _, s)| !store::active(s)),
            "stop existing sandboxes before changing node configuration"
        );
        store::pool(&cfg)?;
        store::atomic(&state.join("node.json"), &cfg)?;
        return Ok(json!({"config":cfg,"hard_aggregate_memory_limit":cfg.cgroup_parent.is_some()}));
    }
    let cfg = store::config(&state)?;
    if matches!(cmd, "gc" | "__gc") {
        let _slot = images::preparation_slot(&state, "delete", 4)?;
        let trash = state.join(".trash");
        let paths = if cmd == "__gc" {
            let name = a.get(1).context("cleanup requires trash entry")?;
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "invalid trash entry"
            );
            vec![trash.join(name)]
        } else if trash.exists() {
            fs::read_dir(trash)?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?
        } else {
            vec![]
        };
        for path in paths {
            if let Err(error) = fs::remove_dir_all(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.into());
                }
            }
        }
        return Ok(json!({"cleanup_complete":true}));
    }
    if cmd == "create" {
        let spec = input::<Spec>(a.get(1).context("create requires SPEC.json")?)?;
        if a.len() == 2 {
            return store::create(&state, spec, None);
        }
        ensure!(
            a.len() == 4 && a[2] == "--token",
            "create accepts only --token TOKEN"
        );
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--state")
            .arg(&state)
            .arg("__create")
            .arg(&a[3])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut worker = command.spawn()?;
        {
            let mut stdin = worker.stdin.take().context("preparation input pipe")?;
            serde_json::to_writer(&mut stdin, &spec)?;
            stdin.flush()?;
        }
        let result = worker.wait_with_output()?;
        ensure!(
            result.status.success(),
            "creation worker failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        return Ok(serde_json::from_slice(&result.stdout)?);
    }
    if cmd == "__create" {
        return store::create(
            &state,
            input::<Spec>("-")?,
            Some(a.get(1).context("creation token")?),
        );
    }
    if cmd == "cancel-create" {
        ensure!(a.len() == 3, "cancel-create requires ID TOKEN");
        return store::cancel_create(&state, &a[1], &a[2]);
    }
    if cmd == "list" {
        return Ok(Value::Array(
            store::records(&state)?
                .iter()
                .map(|(d, _, _)| store::inspect(d))
                .collect::<Result<_>>()?,
        ));
    }
    if cmd == "capacity" {
        let records = store::records(&state)?;
        let reserved: u64 = records
            .iter()
            .filter(|(_, _, s)| store::active(s))
            .map(|(_, r, _)| r.spec.memory_bytes)
            .sum();
        let current: u64 = records
            .iter()
            .filter(|(_, _, s)| store::active(s))
            .map(|(_, _, s)| s.memory_current)
            .sum();
        return Ok(
            json!({"config":cfg,"memory_reserved":reserved,"memory_observed":current,"sandboxes":records.len(),"active":records.iter().filter(|(_,_,s)|store::active(s)).count(),"hard_aggregate_memory_limit":cfg.cgroup_parent.is_some()}),
        );
    }
    let id = a.get(1).context("command requires sandbox ID")?;
    let d = store::dir(&state, id)?;
    if cmd == "__supervise" {
        // Parent publishes the launcher identity before this process touches status.json.
        for _ in 0..1000 {
            if store::read::<Status>(&d.join("status.json"))
                .map(|s| s.supervisor_pid == std::process::id() as i32)
                .unwrap_or(false)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        runtime::supervise(&d, &cfg)?;
        return Ok(json!({"ok":true}));
    }
    if cmd == "inspect" {
        return store::inspect(&d);
    }
    if matches!(cmd, "exec" | "rpc") {
        let request = if cmd == "rpc" {
            input(a.get(2).context("rpc requires REQUEST.json")?)?
        } else {
            command_request(&a[2..])
        };
        // Status is published atomically. The node lock cannot protect this
        // RPC from a later stop, and waiting for unrelated rootfs clones here
        // stalls tool calls in every live sandbox on the node.
        ensure!(
            store::status(&d)?.state == "running",
            "sandbox must be running"
        );
        return runtime::rpc(&d, &request);
    }
    // Lifecycle changes serialize with other operations on the same sandbox.
    // Only starting a stopped sandbox needs a new node admission reservation.
    let _lifecycle = store::lifecycle_lock(&d)?;
    ensure!(
        !matches!(store::status(&d)?.state.as_str(), "creating" | "starting"),
        "sandbox creation or startup is still in progress"
    );
    match cmd {
        "pause" => store::transition(&d, "paused"),
        "resume" => store::transition(&d, "running"),
        "stop" => store::transition(&d, "stopped"),
        "start" => {
            let _lock = store::lock(&state)?;
            store::start_locked(&state, &d, &cfg)?;
            store::inspect(&d)
        }
        "delete" => {
            let deferred = a.get(2).map(String::as_str) == Some("--defer");
            ensure!(
                a.len() == 2 || (a.len() == 3 && deferred),
                "delete accepts only --defer"
            );
            store::remove_stopped(&state, &d, &cfg, deferred)
        }
        "hibernate" => {
            ensure!(
                store::status(&d)?.state == "running",
                "hibernate requires a running sandbox"
            );
            let req = command_request(&a[2..]);
            let result = runtime::rpc(&d, &req)?;
            ensure!(
                result["exit_code"] == 0,
                "checkpoint command failed; inspect sandbox status: {result}"
            );
            // Freeze after a successful application checkpoint before flushing filesystem state.
            store::transition(&d, "paused")?;
            use std::os::fd::AsRawFd;
            let record: Record = store::read(&d.join("record.json"))?;
            let flushed = (|| -> Result<()> {
                for path in std::iter::once(d.join("rootfs")).chain(
                    record
                        .spec
                        .mounts
                        .iter()
                        .filter(|m| !m.readonly)
                        .map(|m| m.source.clone()),
                ) {
                    let f = fs::File::open(path)?;
                    unsafe {
                        linux::cv(libc::syncfs(f.as_raw_fd()), "flush checkpoint filesystem")?;
                    }
                }
                Ok(())
            })();
            if let Err(e) = flushed {
                store::transition(&d, "running")?;
                return Err(e);
            }
            store::transition(&d, "stopped")?;
            store::atomic(
                &d.join("checkpoint.json"),
                &json!({"kind":"application","command":req,"result":result}),
            )?;
            let mut s = store::status(&d)?;
            s.state = "hibernated".into();
            store::atomic(&d.join("status.json"), &s)?;
            store::inspect(&d)
        }
        "restore" => {
            ensure!(
                store::status(&d)?.state == "hibernated",
                "restore requires an application checkpoint"
            );
            {
                let _lock = store::lock(&state)?;
                store::start_locked(&state, &d, &cfg)?;
            }
            let result = runtime::rpc(&d, &command_request(&a[2..]))?;
            ensure!(result["exit_code"] == 0, "restore command failed: {result}");
            Ok(json!({"sandbox":store::inspect(&d)?,"restore":result}))
        }
        "snapshot" => {
            let dst = PathBuf::from(
                a.get(2)
                    .context("snapshot requires destination directory")?,
            );
            ensure!(
                dst.is_absolute() && !dst.exists(),
                "snapshot destination must be an unused absolute directory"
            );
            ensure!(
                !dst.parent()
                    .context("invalid snapshot destination")?
                    .canonicalize()?
                    .starts_with(state.canonicalize()?),
                "snapshot destination must be outside sunabako state"
            );
            let running = store::status(&d)?.state == "running";
            if running {
                store::transition(&d, "paused")?;
            }
            let result = (|| -> Result<Value> {
                fs::create_dir(&dst)?;
                let out = Command::new("cp")
                    .args(["-a", "--reflink=auto", "--"])
                    .arg(d.join("rootfs"))
                    .arg(dst.join("rootfs"))
                    .output()?;
                ensure!(
                    out.status.success(),
                    "snapshot copy failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let r: Record = store::read(&d.join("record.json"))?;
                store::atomic(&dst.join("record.json"), &r)?;
                store::atomic(
                    &dst.join("manifest.json"),
                    &json!({"format":1,"kind":"filesystem","process_memory":false,"external_mounts_included":false}),
                )?;
                Ok(json!({"snapshot":dst,"process_memory":false}))
            })();
            if running {
                store::transition(&d, "running")?;
            }
            if result.is_err() {
                let _ = fs::remove_dir_all(&dst);
            }
            result
        }
        _ => bail!("unknown command {cmd}; use sunabako help"),
    }
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
        Err(e) => {
            eprintln!("{}", json!({"error":format!("{e:#}")}));
            std::process::exit(1);
        }
    }
}
