# sunabako · 砂箱

[English](README.md)

**在现有容器内部运行 Linux 沙箱，无需 Docker-in-Docker。** Rust runtime 负责资源分配、隔离和生命周期，Python SDK 提供 `Sandbox.create()`、`commands.run()`、`files.read/write()` 等接口。通过 SSH 添加节点，可以将 rollout 沙箱分配到多台机器。

这是一个早期实现。当前四机环境支持 user namespace 和 Landlock，但 cgroup 挂载只读，AppArmor 也限制了 mount 操作；PRoot 后端在这种环境下支持目录映射。**生产模式要求内核强制执行沙箱池的内存总量上限，否则拒绝启动。** `allow_unbounded_memory_for_tests` 仅供有界功能测试，无法防止外层容器 OOM，不能用于生产环境超额分配内存。

## 构建与安装

当前支持 Linux x86-64、Python 3.10+；native 模式也可在 Linux 5.4 运行，PRoot 模式需要启用 Landlock 的内核（已测试的基线为 Linux 5.15）。从源码构建需要 Rust/Cargo；安装已构建的 wheel 无需 Rust 或 maturin。节点管理操作以**外层容器内的 root** 身份执行，各沙箱使用不同的外层 UID，非 root 命令移除全部 capabilities。环境必须启用 user namespace；PRoot 模式还要求 Landlock 和 `Yama ptrace_scope >= 1`。

```bash
python -m pip install 'maturin>=1.8,<2'
CARGO_TARGET_DIR=/tmp/sunabako-target maturin build --release --locked --out dist
python -m pip install dist/sunabako-*.whl
```

wheel 包含静态链接的 Rust 可执行文件和 Python SDK。使用本地 target 目录可以避免共享文件系统上的编译开销。

发布工作流见 [`.github/workflows/wheels.yml`](.github/workflows/wheels.yml)：构建一个 Linux x86-64 的 `py3-none` wheel，在 Python 3.10–3.14 上验证安装，并从源码包重新构建。CI 检查 SDK 导入、Rust CLI 和打包结果，无需 root、GPU 或可写 cgroup；需要这些环境条件的运行时验证见下文。

在 PyPI 中为项目 `sunabako` 配置 Trusted Publisher，填写实际 GitHub 用户或组织、仓库名、工作流文件名 `wheels.yml` 和环境名 `pypi`，并在 GitHub 仓库中创建该环境。首次发布可配置 [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)。工作流使用 [GitHub OIDC](https://docs.pypi.org/trusted-publishers/using-a-publisher/)，无需在 GitHub secrets 中保存 PyPI API token。

保持 `Cargo.toml`、`Cargo.lock`、`pyproject.toml` 和 `python/sunabako/__init__.py` 的版本一致。提交并推送发布内容后，推送对应的版本标签：

```bash
git tag v0.1.0
git push origin v0.1.0
```

只有 `v*` 标签的 push 会发布。分支 push、pull request 和手动运行只构建、测试。发布任务等待所有检查通过，再核对标签版本，上传已经验证的同一份 wheel 和源码包。

使用无需 mount 的兼容后端时，通过仓库中的脚本构建带 PID namespace 兼容补丁的 PRoot：

```bash
apt-get install -y gcc make git pkg-config libtalloc-dev
bash scripts/build-proot.sh
```

PRoot 是独立的 GPL-2.0-or-later 可执行程序，`patches/proot-pidns.patch` 采用相同许可证；构建脚本固定上游代码和子模块版本。sunabako 的 Rust/Python 代码采用 Apache-2.0。导入 Python 包时不会自动下载或执行 PRoot。

## 配置节点和镜像

平台需要委派一个空的、可写的 cgroup v2 子树，并开放 memory 和 pids 控制器。将 `cgroup_parent` 指向该目录。sunabako 在子树下创建自己的沙箱池，设置 `memory.max`、禁用池内 swap，并在允许沙箱启动前检查限制。设置内存池大小时，需要为训练和外层容器的其他进程预留空间；该限制覆盖 sunabako 沙箱池，不覆盖池外进程或 GPU 显存。

```bash
sunabako doctor
sunabako --state /var/lib/sunabako init-node configs/node.example.json
apt-get install -y skopeo umoci
python -m sunabako.images ubuntu:24.04 /var/lib/sunabako-images/ubuntu
```

镜像导入使用 skopeo 校验镜像层、umoci 解包，无需 Docker daemon。请使用可信镜像。OCI 元数据保存在 `image.json`；任务需要镜像中的环境变量或工作目录时，分别通过 `envs` 和 `cwd` 传入。镜像的 entrypoint 不会自动执行。

## 与 e2b Python API 的适配关系

sunabako 对齐 **e2b Python SDK 中创建沙箱、运行命令、读写文件等常用调用方式的一个子集**。它是独立的包和运行时，不是 e2b 服务端，也没有实现完整 SDK。迁移时需要调整 import、沙箱配置和异常类型，并检查下表中的接口范围。实现见 [`python/sunabako/client.py`](python/sunabako/client.py)。

| e2b 风格的调用 | sunabako 的支持范围与迁移方式 |
| --- | --- |
| `Sandbox.create(template=..., envs=...)` | 支持。`template` 是**所选节点上已经解包的 rootfs 路径**，不是 e2b template ID 或 OCI 镜像名。先导入镜像，再通过 `node=` 或 `cluster=` 选择节点，并配置内存、目录映射、GPU 和网络。 |
| `AsyncSandbox.create(...)` | 提供相同配置的异步接口，内部通过工作线程执行本地或 SSH 客户端操作。 |
| `sb.commands.run(cmd, timeout=..., envs=..., cwd=..., user=...)` | 支持 shell 字符串和 argv 列表，返回 `CommandResult`：包含 `exit_code`、`stdout`、`stderr`，以及 `timed_out`、`truncated`。默认超时 120 秒、目录 `/workspace`、沙箱内用户 `root`。 |
| 非零退出码处理 | 默认抛出 **sunabako 自己的** `CommandExitException`，需从 `sunabako` 导入；捕获 e2b 的同名异常不会生效。设置 `check=False` 则返回结果供调用方检查。 |
| `sb.files.write(path, data)` | 接受 `str`、`bytes` 或宿主侧 `Path`，返回 `None`。不接受 file-like 对象，不提供批量写入或 `WriteInfo` 返回值。 |
| `sb.files.read(path, format="text")` | 默认返回 `str`，`format="bytes"` 返回 `bytes`。不支持 stream 格式，也不支持文件操作级别的 `user`、`request_timeout` 参数。 |
| `Sandbox.connect(sandbox_id, ...)` | 必须传 `node=`。连接已有沙箱，不会自动启动或恢复。请同时保存 ID 和节点，需要时显式调用 `resume()` 或 `start()`。 |
| `sb.sandbox_id`、`sb.get_info()`、`sb.kill()` | 均提供。`get_info()` 返回运行时 `dict`，不是 e2b 的 `SandboxInfo`；`kill()` 返回 `None`，删除本地 rootfs，保留外部映射目录和快照。 |
| `with sb:` / `async with sb:` | 退出时调用 `kill()` 清理。需要保留沙箱时，使用显式生命周期调用。 |

迁移时尤其需要注意 `pause` 和 `snapshot` 的语义。[e2b 持久化](https://docs.e2b.dev/sandbox/persistence)可以保存进程内存并通过 `connect()` 恢复；sunabako 的 `pause()` 只冻结进程，**仍然占用内存并保留 GPU 分配**，`snapshot()` 只复制 rootfs 和元数据。需要释放内存时，使用 `stop()` 或应用自行保存状态的 `hibernate(checkpoint_command)`；`start()` 启动新进程，`restore(restore_command)` 则执行应用自己的恢复逻辑。

sunabako 没有沙箱生命周期级别的 `create(timeout=...)`、`set_timeout()` 或自动到期回收 API。命令超时会停止整个沙箱，包括脱离父进程的子进程；重连也不会自动恢复沙箱。网络默认 `network="none"`，需要访问外部网络时显式设置 `network="host"`。节点访问使用本地环境或 SSH 认证，不需要 `E2B_API_KEY`。

当前尚未覆盖的 e2b 接口包括：命令输出流回调、`background=True` 进程句柄、stdin/PTY、`files.list/remove/watch`、模板构建服务、公开访问 URL / `get_host()`，以及 code interpreter 的 `run_code()`。后台任务可以通过 shell 启动并将输出重定向到文件。sunabako 另外提供 `Node`、`Cluster`、`Mount`、cgroup 内存池和 GPU 配置。上游接口见 e2b 的[命令执行](https://docs.e2b.dev/commands)与[文件读写](https://docs.e2b.dev/filesystem/read-write)文档。

完成节点配置和镜像导入后，迁移后的最小调用示例：

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

在 slime 中，`examples/coding_agent_rl/sunabako_sandbox.py` 将 SDK 接到共享的 `slime.agent.sandbox.Sandbox` 小接口上：异步 `exec()` 返回 `(exit_code, stdout, stderr)`，并提供 `write_file()`、`read_file()` 和异步上下文管理。example 的 `sandbox.py` 默认选择 sunabako，agent 和 grader 使用同一 provider。这里适配的是 slime 的共享协议，并不意味着实现了完整 e2b SDK。

## Python 使用

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
    sb.pause()       # 冻结进程树，保留内存和 GPU 分配。
    sb.resume()
    sb.stop()        # 释放进程、内存和显存，保留可写 rootfs。
    sb.start()       # 在保留的文件系统上启动新进程。
```

映射目录需要给予沙箱专用外层 UID 对应的访问权限，UID 可通过 `get_info()['uid']` 查询。建议使用独立的任务目录，或明确配置共享用户组和 ACL，不要递归修改已有用户数据的所有者。PRoot 模式通过 Landlock 实现 `readonly=True` 的文件内容写保护；在较旧的 Landlock 内核上，源目录应属于不同 UID，以同时保护文件元数据。原生模式使用内核只读 bind mount。

`commands.run()` 返回 `exit_code`、`stdout`、`stderr`、`timed_out` 和 `truncated`。非零退出码会触发 `CommandExitException`，可用 `check=False` 改为检查返回值。每个输出流最多 2 MiB，单次读取文件最多 8 MiB；上传按 4 MiB 分块，支持大的 `Path` 输入，中断上传可能留下部分文件。

命令超时会终止整个沙箱，确保脱离父进程的子进程也无法继续运行；文件系统仍保留，可以用 `start()` 重启并检查。PRoot 支持 `commands.run(..., user="agent")`，需先在镜像中创建用户。PRoot 中的用户身份都映射到同一个无特权外层 UID，不构成沙箱内部的安全边界。

native 默认保留仅支持 namespace root 的行为。配置 `uid_range_size=65536` 后，可创建并使用真实的 guest 用户；从 `uid_start`（例如 100000）开始，需要为每个节点预留 `max_sandboxes * uid_range_size` 个空闲的外层 UID/GID，不同节点的范围不能重叠。外层容器须允许私有挂载和 UID/GID 映射，可使用 privileged Docker 在 Linux 5.4 上运行，无需 PRoot 或 Landlock。state 的父目录必须可遍历，例如 `/workspace`，不能放在权限为 0700 的 `/root` 下。

```python
node.configure(uid_start=100000, uid_range_size=65536, max_sandboxes=2,
               cgroup_parent="/sys/fs/cgroup/delegated")
with Sandbox.create(node=node, runtime="native", memory_mb=512) as sb:
    sb.commands.run("useradd -m -s /bin/bash agent")
    sb.commands.run("id", user="agent")
    sb.files.write("/home/agent/example.txt", "hello", user="agent")
    assert sb.files.read("/home/agent/example.txt", user="agent") == "hello"
```

native 从镜像的 `/etc/passwd`、`/etc/group` 解析用户和附加组。guest root 仅保留用户 namespace 内用于用户初始化的 chown、DAC override、fowner、setuid、setgid capabilities；其他用户以真实映射后的 UID/GID 运行，清空全部 capabilities 并启用 no-new-privileges。文件 API 同样按所选用户检查权限。修改节点配置不会改变已有沙箱的 UID 映射。多用户模式的文件 RPC 拒绝 procfs 文件描述符，避免泄漏可信文件工作进程自身的状态；查看 procfs 请使用 `commands.run()`。后台 shell 任务可以在沙箱内持续运行，脱离前应将输出流重定向到文件。

`network="none"` 使用只含 loopback 的独立网络 namespace。显式设置 `network="host"` 时共享外层容器的网络 namespace。当前不会创建虚拟网桥或配置端口映射。

## 与 slime 集成及多机使用

```python
from sunabako import AsyncSandbox, Cluster

cluster = Cluster.from_file("configs/cluster.example.json")
sb = await AsyncSandbox.create(cluster=cluster, memory_mb=2048, runtime="proot")
async with sb:
    result = await sb.commands.run("echo rollout")
    code, stdout, stderr = await sb.exec("echo compatible with slime's Sandbox protocol")
```

异步接口还提供 `write_file` 和 `read_file`，兼容 `slime.agent.sandbox.Sandbox` 协议。将 sunabako 安装到 slime 的 Python 环境中；数据转换、沙箱 provider 和训练启动脚本位于 slime 的 `examples/coding_agent_rl`，通过 `SWE_SANDBOX_PROVIDER=sunabako` 选择后端。

在沙箱节点上部署 wheel、运行时依赖、镜像和节点配置，将节点加入 cluster 文件即可扩容。SSH 复用已有认证配置。调度器按可用容量选择节点，节点在准入检查期间持锁，防止并发客户端重复预留内存或 GPU 槽位。传输超时不会自动重放创建或执行操作；保留 `sandbox_id` 和 `node`，便于客户端重启后重连。

`memory_overcommit=2` 允许申请的内存总量达到池大小的两倍，但**内核内存池上限保持不变**。暂停的沙箱保留资源预留；停止或休眠后释放预留。GPU 共享是对指定设备的普通 CUDA 共享，可以配置准入槽位数，不划分算力，也不限制单个沙箱的显存用量。独占预留只排斥其他 sunabako 预留，不约束无关的宿主进程。

## 持久化与休眠

```python
sb.hibernate("python /workspace/save_checkpoint.py")
# 进程已释放，应用 checkpoint 和可写文件系统保留。
sb.restore("python /workspace/load_checkpoint.py")
sb.snapshot("/shared/snapshots/task-001")
```

保存命令需要协调应用的写入，并持久化应用状态；只有命令成功后才会终止进程。`restore` 执行显式的应用恢复命令。这不是透明的 CRIU 进程内存快照，GPU 状态也需要由应用自行保存。保存命令返回非零退出码时，沙箱继续运行；命令超时则仍遵循终止整个沙箱的规则。停止之前会刷写可写 volume。`pause` 只冻结 CPU 线程，不释放内存，也不取消已经提交到 GPU 驱动的 kernel。

文件系统快照会短暂冻结运行中的进程，复制可写 rootfs 和元数据，不包含外部 volume 内容或进程内存。可以用 `snapshot/rootfs` 作为模板创建新沙箱；volume 数据仍保存在配置的源目录。要在外层容器销毁后保留数据，请将快照和 volume 放到共享持久化存储。`kill()` 删除沙箱本地 rootfs，保留外部 volume 源目录和快照。

## 隔离机制与当前范围

原生模式使用内核 chroot，以及 user、PID、IPC、UTS、mount namespace。bind mount 和独立 procfs 需要外层 AppArmor 策略允许 mount。PRoot 模式通过可信 init 维持独立 PID namespace，由 PRoot 转换文件系统路径，再由 Landlock 约束真实内核路径。命令继承 syscall filter、no-new-privileges、PID 限制和专用外层 UID。native 非 root 命令及 PRoot 命令的 capabilities 为空；native 多用户模式的 guest root 只保留前述少量 capabilities。rootfs 只包含选定的 NVIDIA 设备节点和驱动库。

Landlock ABI 1 上使用小型 helper 保持包管理器所需的跨目录 rename 和 hard-link 语义。每个 helper 都通过内核 chroot 限制在一个可写映射中，使用沙箱 UID，移除 capabilities 和无关文件描述符。只读映射不启动 helper。这些进程计入同一沙箱 cgroup，也纳入 RSS 监测。

沙箱共享 Linux 内核，启用 GPU 时也共享 GPU 驱动；它不是虚拟机，尚未通过针对不可信多租户使用的安全审计。目前还没有交互式 PTY API、自动 overlay 镜像层共享、透明 CRIU/CUDA 进程 checkpoint 或 GPU 显存配额。

## 验证

当前环境已经在四台 H100 节点上通过真实 CUDA kernel 检查，并验证可写 volume 持久化、两个沙箱共享 GPU、暂停与恢复、应用 checkpoint 休眠、文件系统快照和跨沙箱文件系统隔离。集成测试也检查生产模式在缺少内存池硬上限时拒绝启动。由于外层 cgroup 只读，这里的功能测试使用显式 RSS 测试模式。

Terminal Bench 2.1 的 `cancel-async-tasks` 镜像使用官方 oracle 和未修改的 verifier 验证，**6/6 测试通过，reward 为 1**。这是单个任务的运行时兼容性检查，不代表完整 benchmark 成绩。导入 `alexgshaw/cancel-async-tasks:20251031` 并克隆官方任务仓库后，可运行：

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

测试要求使用尚不存在的 state 和 artifacts 路径，保存 verifier 输出，并在结束后删除沙箱。已委派 cgroup 的环境应将 `--allow-test-memory` 替换为 `--cgroup-parent /path/to/delegated/cgroup`。

内核机制参考：[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)、[user namespace](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)、[Landlock](https://docs.kernel.org/userspace-api/landlock.html)、[PRoot](https://proot-me.github.io/)。

## 许可证

sunabako：[Apache-2.0](LICENSE)。独立 PRoot 程序及其补丁使用 GPL-2.0-or-later。
