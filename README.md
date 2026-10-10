# sunabako · 砂箱

[中文版](README_zh.md)

Linux sandboxes **inside an existing container**, without Docker-in-Docker. A
Rust runtime manages resource admission, isolation and lifecycle; a Python SDK
provides familiar `Sandbox.create()`, `commands.run()` and `files.read/write()`
interfaces. Add SSH nodes to distribute rollout sandboxes across an allocation.

This is an early implementation. The current four-machine environment provides
user namespaces and Landlock, but its cgroup mount is read-only and AppArmor
blocks mounts. The PRoot backend supports directory mappings in this environment.
**Production startup refuses to proceed without a hard aggregate cgroup memory
limit.** The explicitly named `allow_unbounded_memory_for_tests` option is for
bounded functional verification only; it is not protection against outer-container
OOM and must not be used to oversubscribe production workloads.

## Build and install

Linux x86-64 and Python 3.10+ are required. Native mode also works on Linux 5.4;
PRoot requires a Landlock-enabled kernel (the tested baseline is Linux 5.15). Building
from source needs Rust/Cargo; installing a built wheel needs neither Rust nor maturin.
Node operations run as root **inside the allocated outer container**; sandboxes
run under distinct outer UIDs. Non-root commands have all capabilities removed. User namespaces must
be enabled. PRoot mode additionally requires Landlock and Yama ptrace_scope >= 1.

```bash
python -m pip install 'maturin>=1.8,<2'
CARGO_TARGET_DIR=/tmp/sunabako-target maturin build --release --locked --out dist
python -m pip install dist/sunabako-*.whl
```

The wheel contains the statically linked Rust executable and the Python package.
Builds use a local target directory to avoid slow shared-filesystem compilation.
Release automation is in [`.github/workflows/wheels.yml`](.github/workflows/wheels.yml).
It builds one Linux x86-64 `py3-none` wheel, tests the installed package on Python
3.10–3.14, and rebuilds the source distribution in a clean build environment.
These checks exercise packaging, SDK imports and the Rust CLI without requiring
root, GPUs or delegated cgroups. The privileged runtime tests below remain
separate from these packaging checks.

For PyPI publishing, configure a Trusted Publisher for project `sunabako` with
your actual GitHub owner and repository, workflow filename `wheels.yml`, and
environment name `pypi`. Create that environment in the GitHub repository too.
For a first release, use a
[pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
The workflow uses [GitHub OIDC](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
so no PyPI API token needs to be stored in GitHub secrets.

Keep the versions in `Cargo.toml`, `Cargo.lock`, `pyproject.toml` and
`python/sunabako/__init__.py` aligned. After committing and pushing the release
files, push the matching version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Only a `v*` tag push publishes. Branch pushes, pull requests and manual runs
build and test without uploading to PyPI. The publishing job waits for all
checks, verifies the package versions against the tag, and uploads the same
wheel and sdist that passed verification. A mismatched tag or a failed check
blocks publication.

For the mount-free compatibility backend, build the pinned PRoot version with
the included PID-namespace compatibility patch:

```bash
apt-get install -y gcc make git pkg-config libtalloc-dev
bash scripts/build-proot.sh
```

PRoot remains a separate GPL-2.0-or-later executable. The Rust/Python project is
Apache-2.0. `patches/proot-pidns.patch` modifies PRoot and is GPL-2.0-or-later;
the script pins its upstream source and submodule revisions. PRoot is not
silently downloaded or executed on package import.

## Configure a node and an image

The platform must delegate an empty writable cgroup-v2 subtree with the memory
and pids controllers. Point `cgroup_parent` at that subtree. sunabako creates its
own child pool, sets `memory.max`, disables swap for the pool, and verifies the
limit before allowing sandbox startup. Choose its size to leave RAM for training
and the outer container's other processes. Limits cover sunabako workloads, not
unrelated processes outside that pool or GPU VRAM.

```bash
sunabako doctor
sunabako --state /var/lib/sunabako init-node configs/node.example.json
apt-get install -y skopeo umoci
python -m sunabako.images ubuntu:24.04 /var/lib/sunabako-images/ubuntu
```

Image import verifies registry layers with skopeo and unpacks with umoci. No Docker
daemon is needed. Import trusted images. OCI metadata is saved in `image.json`;
pass the image's environment through `envs` and its working directory through
`cwd` when a task requires them. Entry points are not automatically started.

## Relationship to the e2b Python API

sunabako implements a **subset of the e2b Python SDK's calling conventions** for
creating sandboxes, running commands and reading/writing files. It is an
independent package and runtime, not an e2b service endpoint or a complete SDK
replacement. Migrate the import, sandbox configuration and exception imports;
review the supported methods below. The implementation is in
[`python/sunabako/client.py`](python/sunabako/client.py).

| e2b-style call | sunabako support and migration details |
| --- | --- |
| `Sandbox.create(template=..., envs=...)` | Supported. `template` is an **unpacked rootfs path on the chosen node**, not an e2b template ID or an OCI image name. Import the image first. Select `node=` or `cluster=` and configure memory, mounts, GPU and network explicitly. |
| `AsyncSandbox.create(...)` | Async counterpart with the same options. Async operations delegate to the local/SSH client using worker threads. |
| `sb.commands.run(cmd, timeout=..., envs=..., cwd=..., user=...)` | Runs a shell string or argv list and returns `CommandResult` with `exit_code`, `stdout`, `stderr`, plus `timed_out` and `truncated`. Defaults are 120 seconds, `/workspace`, and guest `root`. |
| Handling nonzero command exits | Raises **sunabako's** `CommandExitException` by default. Import it from `sunabako`; e2b's exception class does not catch it. `check=False` returns the result instead. |
| `sb.files.write(path, data)` | Accepts `str`, `bytes`, or a host `Path`; returns `None`. No file-like object, batch-write or `WriteInfo` return support. |
| `sb.files.read(path, format="text")` | Returns `str`; `format="bytes"` returns `bytes`. No stream format or per-operation `user`/`request_timeout` options on `files`. |
| `Sandbox.connect(sandbox_id, ...)` | Requires `node=`. Reconnects to an existing sandbox without starting or resuming it. Save both the ID and node; call `resume()` or `start()` explicitly when needed. |
| `sb.sandbox_id`, `sb.get_info()`, `sb.kill()` | Available. `get_info()` returns a runtime `dict`, not e2b's `SandboxInfo`; `kill()` returns `None` and removes the local rootfs. External mounts and snapshots remain. |
| `with sb:` / `async with sb:` | Cleans up with `kill()` on exit. Use explicit lifecycle calls if the sandbox should survive the block. |

The names `pause` and `snapshot` need particular care when migrating.
[e2b persistence](https://docs.e2b.dev/sandbox/persistence) can preserve process
memory and resume through `connect()`. In sunabako, `pause()` freezes processes
**while retaining RAM and GPU allocations**, and `snapshot()` copies only the
rootfs and metadata. To release memory, use `stop()` or application-managed
`hibernate(checkpoint_command)`; `start()` starts fresh processes, while
`restore(restore_command)` explicitly restores application state.

sunabako has no sandbox-lifetime `create(timeout=...)` or `set_timeout()` API.
Its command deadline stops the whole sandbox, including detached children.
There is no automatic expiration or e2b-style resume-on-connect. Network access
defaults to `network="none"`; choose `network="host"` when required. Node
authentication uses the local environment or SSH, with no `E2B_API_KEY`.

Other e2b APIs are currently outside this subset: command streaming callbacks,
`background=True` handles, stdin/PTY, `files.list/remove/watch`, template build
services, public URLs / `get_host()`, and the code-interpreter `run_code()` API.
Shell commands can still start detached jobs with output redirected to files.
sunabako adds its own `Node`, `Cluster`, `Mount`, cgroup-pool and GPU controls.
For the upstream interfaces, see e2b's [commands](https://docs.e2b.dev/commands)
and [file read/write](https://docs.e2b.dev/filesystem/read-write) documentation.

A minimal migrated call site, after node configuration and image import:

```python
from sunabako import Sandbox, Node, CommandExitException

node = Node(rootfs="/var/lib/sunabako-images/ubuntu/rootfs")
with Sandbox.create(node=node, runtime="proot", memory_mb=2048) as sb:
    sb.files.write("/tmp/input.txt", "hello")
    try:
        result = sb.commands.run("cat /tmp/input.txt", timeout=30)
        print(result.stdout)
    except CommandExitException as error:
        print(error.exit_code, error.stderr)
```

In slime, `examples/coding_agent_rl/sunabako_sandbox.py` adapts this SDK to the
small shared `slime.agent.sandbox.Sandbox` protocol: async `exec()` returns
`(exit_code, stdout, stderr)`, alongside `write_file()`, `read_file()` and async
context management. The example's `sandbox.py` defaults to sunabako and selects
the same provider for both agents and graders. This protocol adaptation is
separate from full e2b SDK compatibility.

## Python

```python
from sunabako import Sandbox, Node, Mount

node = Node(rootfs="/var/lib/sunabako-images/ubuntu/rootfs")
with Sandbox.create(
    node=node, memory_mb=2048, runtime="proot",
    gpus=[0], gpu_mode="shared",
    mounts=[Mount("/data/rollouts/task-001", "/workspace")],
) as sb:
    sb.files.write("/workspace/input.txt", "hello")
    result = sb.commands.run("cat /workspace/input.txt; nvidia-smi -L")
    print(result.stdout)
    sb.pause()       # Freezes the process tree; retains RAM and GPU allocations.
    sb.resume()
    sb.stop()        # Releases processes/RAM/VRAM; preserves the writable rootfs.
    sb.start()       # Fresh processes using that existing filesystem.
```

A mapped directory must grant the sandbox's dedicated outer UID the intended
access (see `get_info()['uid']`). Use separate per-task directories or a deliberate
shared group/ACL. Do not recursively change ownership of existing user data.
`readonly=True` denies file-content writes using Landlock in PRoot mode. Sources
should be owned by a different UID to also protect metadata on older Landlock
kernels. Native mode uses kernel read-only bind mounts.

`commands.run()` returns `exit_code`, `stdout`, `stderr`, `timed_out`, and
`truncated`; nonzero exits raise `CommandExitException` unless `check=False`.
Output is capped at 2 MiB per stream and file reads at 8 MiB. Uploads stream in
4 MiB chunks, including large `Path` inputs. An interrupted upload can leave a
partial destination. A command timeout
terminates the whole sandbox so detached descendants cannot outlive its deadline;
the filesystem remains available for `start()` and inspection. PRoot supports
image users through `commands.run(..., user="agent")`; create that user in the
image first. All guest identities map to the sandbox's one unprivileged outer
UID, so they do not form security boundaries within a sandbox. Native mode defaults
to namespace root only. To enable real guest users, configure `uid_range_size=65536`
and reserve `max_sandboxes * uid_range_size` unused outer UIDs/GIDs starting at
`uid_start` (for example 100000). Keep the ranges of separate nodes disjoint.
This mode requires the outer container to permit private mounts and privileged
UID/GID mapping. It works with a privileged Docker container on Linux 5.4 and
does not require PRoot or Landlock. Node state must be reachable through searchable
parent directories, such as `/workspace`, rather than a mode-0700 `/root`.

```python
node.configure(uid_start=100000, uid_range_size=65536, max_sandboxes=2,
               cgroup_parent="/sys/fs/cgroup/delegated")
with Sandbox.create(node=node, runtime="native", memory_mb=512) as sb:
    sb.commands.run("useradd -m -s /bin/bash agent")
    sb.commands.run("id", user="agent")
    sb.files.write("/home/agent/example.txt", "hello", user="agent")
    assert sb.files.read("/home/agent/example.txt", user="agent") == "hello"
```

Native guest users are resolved from the image's `/etc/passwd` and `/etc/group`.
Guest root retains only namespace-scoped chown, DAC override, fowner, setuid and
setgid capabilities for user setup. Other users run with their real mapped IDs,
supplementary groups, empty capability sets and no-new-privileges. File operations
also enforce the selected user's permissions. Existing root-only records keep
their original mapping when a node configuration changes.
Use `commands.run()` to inspect procfs: native multi-user file RPCs reject procfs
descriptors so the trusted file worker's own process state is never exposed.

Shell background jobs persist within the sandbox;
redirect their standard streams to files before detaching them.

`network="none"` uses a private network namespace with loopback only. Explicit
`network="host"` allows network access through the outer container, sharing its
network namespace. No virtual bridge or port publishing is installed.

## Slime and multiple machines

```python
from sunabako import AsyncSandbox, Cluster

cluster = Cluster.from_file("configs/cluster.example.json")
sb = await AsyncSandbox.create(cluster=cluster, memory_mb=2048, runtime="proot")
async with sb:
    result = await sb.commands.run("echo rollout")
    code, stdout, stderr = await sb.exec("echo compatible with slime's Sandbox protocol")
```

The async adapter also supplies `write_file` and `read_file` for
`slime.agent.sandbox.Sandbox`. Install sunabako into Slime's Python environment;
the provider selection, dataset conversion and training launcher belong in
Slime's `examples/coding_agent_rl`, using `SWE_SANDBOX_PROVIDER=sunabako`.
Install the wheel, runtime dependency, image and
node configuration on each allocated machine; add nodes to the cluster file to
expand capacity. SSH uses existing authentication. A capacity-ranked scheduler
selects nodes; each node holds a lock during admission so concurrent clients
cannot over-reserve memory or GPU slots. A transport timeout never blindly
replays sandbox creation or command execution. Save `sandbox_id` and `node` to
reconnect from a restarted client.

`memory_overcommit=2` permits total requested memory of twice the pool size, while
the **kernel pool limit stays unchanged**. Paused sandboxes retain reservations.
Stopped/hibernated sandboxes release them. GPU sharing is ordinary CUDA sharing
of specifically exposed devices, with a configurable number of admission slots;
it does not partition compute or enforce per-sandbox VRAM quotas. Exclusive
reservations exclude other sunabako reservations, not unrelated host processes.

## Persistence and hibernation

```python
sb.hibernate("python /workspace/save_checkpoint.py")
# Processes are gone; an application checkpoint and the writable filesystem remain.
sb.restore("python /workspace/load_checkpoint.py")
sb.snapshot("/shared/snapshots/task-001")
```

The checkpoint command must quiesce its writers and durably save the application's
state, and must succeed before processes are terminated. `restore` runs an explicit
application restore command. This is not a transparent CRIU process-memory image.
GPU state must likewise be saved by the application before hibernation. A
checkpoint command returning nonzero leaves the sandbox running; the general
whole-sandbox timeout policy still applies. Writable volume filesystems are
flushed before stopping. `pause` freezes CPU threads and does not release memory
or cancel GPU kernels already submitted to the driver.

Filesystem snapshots briefly freeze running processes and copy the writable
rootfs plus metadata. They exclude external volume contents and process memory.
Create a new sandbox using `snapshot/rootfs` as its template; volume data lives at
the configured source directory. Put snapshots and volumes on shared persistent
storage to survive destruction of the outer container. `kill()` deletes the
sandbox's local rootfs; it leaves external volume sources and snapshots intact.

## Isolation and current scope

Native mode uses kernel chroot and user/PID/IPC/UTS/mount namespaces. Bind mounts
and a private procfs require the outer AppArmor policy to permit mount operations.
Without mount permission, use PRoot mode: a persistent trusted init runs inside a
private PID namespace; PRoot translates filesystem paths while Landlock limits
the actual kernel paths. Commands inherit a syscall filter, no-new-privileges,
PID limits, and a dedicated outer UID. Non-root native commands and PRoot commands
have zero capabilities; native guest root in multi-user mode has only the limited
capabilities described above. Only selected NVIDIA
device nodes and driver libraries are copied into the rootfs.

On Landlock ABI 1, small helpers preserve cross-directory rename and hard-link
semantics needed by package managers. Each helper is confined by kernel chroot
to exactly one writable mapping, uses the sandbox UID, and drops capabilities
and unrelated file descriptors. Read-only mappings have no helper. These
processes are charged to the same sandbox cgroup and included in RSS monitoring.

This shares the Linux kernel and (when requested) a GPU driver. It is not a VM,
and has not received a security audit for hostile multi-tenant use. Current
limitations include no interactive PTY API, no automatic overlay-layer sharing,
no transparent CRIU/CUDA process checkpoint, and no GPU memory quotas.

## Verification

The current container environment passed the real CUDA kernel probe on all four
allocated H100 nodes, writable-volume persistence, two sandboxes sharing one GPU,
pause/resume, application-checkpoint hibernation, filesystem snapshots, and
cross-sandbox filesystem checks. The integration suite also verifies that normal
node startup refuses a missing aggregate cgroup limit. Functional tests here use
explicit RSS test mode because the outer cgroup mount is read-only.

Terminal Bench 2.1's `cancel-async-tasks` image was tested using its official oracle
and unmodified verifier: **6/6 tests passed, reward 1**. This is one task's runtime
compatibility check, not a full benchmark result. Reproduce it after importing
`alexgshaw/cancel-async-tasks:20251031` and cloning the official task repository:

```bash
python tests/tb21.py \
  --repository /path/to/terminal-bench-2-1 \
  --rootfs /path/to/imported-bundle/rootfs \
  --state /tmp/sunabako-tb-new \
  --artifacts /persistent/tb-new \
  --binary /path/to/sunabako \
  --proot /path/to/patched-proot \
  --allow-test-memory
```

The test requires unused state/artifact paths, saves verifier output, and deletes
its sandbox after completion. On a delegated cgroup installation, replace
`--allow-test-memory` with `--cgroup-parent /path/to/delegated/cgroup`.

Kernel behavior references: [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[PRoot](https://proot-me.github.io/).
