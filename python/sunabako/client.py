from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import logging
import math
import os
import io
import re
import random
import shlex
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any


class SandboxError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


class CommandExitException(SandboxError):
    def __init__(self, result: CommandResult):
        self.result = result
        self.exit_code = result.exit_code
        self.stdout = result.stdout
        self.stderr = result.stderr
        super().__init__(f"Command exited {result.exit_code}: {result.stderr[-1000:]}")


@dataclasses.dataclass(frozen=True)
class Mount:
    source: str
    target: str
    readonly: bool = False


@dataclasses.dataclass(frozen=True)
class Node:
    """SSH is authenticated by the existing SSH configuration; no exposed root HTTP endpoint."""
    name: str = "local"
    host: str | None = None
    port: int = 22
    state_dir: str = "/var/lib/sunabako"
    binary: str = "sunabako"
    rootfs: str = ""

    def _command(self, args: tuple[str, ...]) -> list[str]:
        argv = [self.binary, "--state", self.state_dir, *args]
        if self.host:
            if self.host.startswith("-") or not 1 <= self.port <= 65535:
                raise ValueError("Invalid SSH node")
            argv = ["ssh", "-p", str(self.port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.host, shlex.join(argv)]
        elif self.binary == "sunabako":
            argv[0] = os.environ.get("SUNABAKO_BINARY") or shutil.which("sunabako") or "sunabako"
        return argv

    @staticmethod
    def _response(returncode: int, stdout: str, stderr: str) -> Any:
        if returncode:
            raise SandboxError(stderr.strip() or stdout.strip())
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            raise SandboxError(f"Invalid node response: {stdout[:500]}") from e

    def call(self, *args: str, data: Any = None, timeout: float | None = 150) -> Any:
        try:
            p = subprocess.run(self._command(args), input=json.dumps(data) if data is not None else None, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise SandboxError("Transport timed out; do not replay mutations blindly. Inspect the sandbox ID before retrying.") from e
        return self._response(p.returncode, p.stdout, p.stderr)

    async def call_async(self, *args: str, data: Any = None, timeout: float | None = 150) -> Any:
        process = await asyncio.create_subprocess_exec(
            *self._command(args), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(json.dumps(data).encode() if data is not None else None), timeout,
            )
        except BaseException as error:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            # A multiplexing SSH master can retain stderr after this client
            # exits. Close this RPC's pipes instead of waiting for its EOF;
            # killing a process group could disrupt unrelated SSH channels.
            # asyncio.Process exposes no public close() for its pipe transport.
            process._transport.close()
            await process.wait()
            if isinstance(error, asyncio.TimeoutError):
                raise SandboxError("Transport timed out; do not replay mutations blindly. Inspect the sandbox ID before retrying.") from error
            raise
        return self._response(process.returncode, stdout.decode(), stderr.decode())

    def configure(self, **config: Any) -> dict:
        return self.call("init-node", "-", data=config)


class Cluster:
    def __init__(self, nodes: list[Node]):
        if not nodes or len({n.name for n in nodes}) != len(nodes):
            raise ValueError("Cluster requires distinct node names")
        self.nodes = nodes

    @classmethod
    def from_file(cls, path: str | Path) -> Cluster:
        return cls([Node(**n) for n in json.loads(Path(path).read_text())["nodes"]])

    def candidates(self) -> list[Node]:
        ranked = []
        failures = []
        for n in self.nodes:
            try:
                c = n.call("capacity", timeout=20)
                available = max(1, c["config"]["memory_capacity_bytes"] * c["config"].get("memory_overcommit", 1) - c["memory_reserved"])
                ranked.append((random.expovariate(available), n.name, n))
            except (SandboxError, OSError) as e:
                failures.append(f"{n.name}: {e}")
        if not ranked:
            raise SandboxError("No reachable nodes: " + "; ".join(failures))
        return [n for _, _, n in sorted(ranked, key=lambda v: v[:2])]


class Commands:
    def __init__(self, sandbox: Sandbox):
        self._sandbox = sandbox

    def run(self, command: str | list[str], *, timeout: int = 120, envs: dict[str, str] | None = None,
            cwd: str = "/workspace", user: str = "root", check: bool = True) -> CommandResult:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        argv = ["/bin/sh", "-lc", command] if isinstance(command, str) else command
        raw = self._sandbox._rpc({"op": "exec", "argv": argv, "env": envs or {}, "cwd": cwd, "timeout": timeout, "user": user}, timeout=timeout + 30)
        result = CommandResult(**raw)
        if check and result.exit_code:
            raise CommandExitException(result)
        return result


class Files:
    def __init__(self, sandbox: Sandbox):
        self._sandbox = sandbox

    def write(self, path: str, data: str | bytes | Path, *, user: str = "root") -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        source = data.open("rb") if isinstance(data, Path) else io.BytesIO(data.encode() if isinstance(data, str) else data)
        with source:
            append = False
            while True:
                content = source.read(4 << 20)
                if not content and append:
                    break
                self._sandbox._rpc({"op": "write", "path": path, "data": base64.b64encode(content).decode(), "append": append, "user": user})
                append = True
                if not content:
                    break

    def read(self, path: str, *, format: str = "text", user: str = "root") -> str | bytes:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        if format not in ("text", "bytes"):
            raise ValueError("format must be text or bytes")
        value = self._sandbox._rpc({"op": "read", "path": path, "user": user})
        data = base64.b64decode(value["data"])
        return data.decode() if format == "text" else data


class Sandbox:
    """E2B-style API with explicit local resource and lifecycle semantics."""
    def __init__(self, sandbox_id: str, *, node: Node):
        self.sandbox_id = sandbox_id
        self.node = node
        self.commands = Commands(self)
        self.files = Files(self)

    @classmethod
    def create(cls, template: str | None = None, *, node: Node | None = None, cluster: Cluster | None = None,
               memory_mb: int = 512, memory_mode: str = "cgroup", runtime: str = "native",
               gpus: list[int] | None = None, gpu_mode: str = "shared", mounts: list[Mount] | None = None,
               network: str = "none", envs: dict[str, str] | None = None, pids_max: int = 256,
               sandbox_id: str | None = None, create_timeout: float | None = 600) -> Sandbox:
        if create_timeout is not None and (not math.isfinite(create_timeout) or create_timeout <= 0):
            raise ValueError("create_timeout must be positive and finite, or None")
        if node and cluster:
            raise ValueError("Specify node or cluster")
        if not isinstance(memory_mb, int) or memory_mb < 16:
            raise ValueError("memory_mb must be an integer >= 16")
        sid = sandbox_id or "s-" + uuid.uuid4().hex
        candidates = cluster.candidates() if cluster else [node or Node()]
        errors = []
        for candidate in candidates:
            token = uuid.uuid4().hex
            spec = {"id": sid, "rootfs": template or candidate.rootfs or os.environ.get("SUNABAKO_ROOTFS", ""),
                    "memory_bytes": memory_mb << 20, "memory_mode": memory_mode, "runtime": runtime,
                    "gpus": gpus or [], "gpu_mode": gpu_mode, "mounts": [dataclasses.asdict(m) for m in mounts or []],
                    "network": network, "env": envs or {}, "pids_max": pids_max}
            try:
                candidate.call("create", "-", "--token", token, data=spec, timeout=create_timeout)
                return cls(sid, node=candidate)
            except (SandboxError, KeyboardInterrupt) as e:
                try:
                    cleanup = candidate.call("cancel-create", sid, token, timeout=60)
                    if not isinstance(cleanup, dict) or cleanup.get("cancelled") is not True or cleanup.get("deleted") is not True:
                        raise SandboxError("Node did not acknowledge creation cancellation")
                except Exception as cleanup_error:
                    if isinstance(e, KeyboardInterrupt):
                        logging.getLogger(__name__).warning("Could not confirm cancelled creation cleanup for %s: %s", sid, cleanup_error)
                        raise e
                    raise SandboxError(f"{e}; could not confirm creation cleanup for {sid}: {cleanup_error}") from e
                if isinstance(e, KeyboardInterrupt):
                    raise
                # Only capacity rejection is known to occur before any sandbox is launched.
                if not any(s in str(e) for s in ("admission exhausted", "sharing slots exhausted", "exclusive reservation", "max_sandboxes reached")):
                    raise
                errors.append(f"{candidate.name}: {e}")
        raise SandboxError("Cluster capacity exhausted: " + "; ".join(errors))

    @classmethod
    def connect(cls, sandbox_id: str, *, node: Node) -> Sandbox:
        node.call("inspect", sandbox_id)
        return cls(sandbox_id, node=node)

    def _rpc(self, data: dict, *, timeout: int = 150):
        return self.node.call("rpc", self.sandbox_id, "-", data=data, timeout=timeout)

    def get_info(self) -> dict:
        return self.node.call("inspect", self.sandbox_id)

    def pause(self) -> dict:
        return self.node.call("pause", self.sandbox_id)

    def resume(self) -> dict:
        return self.node.call("resume", self.sandbox_id)

    def stop(self) -> dict:
        return self.node.call("stop", self.sandbox_id)

    def start(self) -> dict:
        return self.node.call("start", self.sandbox_id)

    def kill(self, *, defer_cleanup: bool = False) -> None:
        self.stop()
        self.node.call("delete", self.sandbox_id, *(["--defer"] if defer_cleanup else []))

    def snapshot(self, destination: str) -> dict:
        return self.node.call("snapshot", self.sandbox_id, destination, timeout=600)

    def hibernate(self, checkpoint_command: str) -> dict:
        return self.node.call("hibernate", self.sandbox_id, "--", "/bin/sh", "-lc", checkpoint_command)

    def restore(self, restore_command: str) -> dict:
        return self.node.call("restore", self.sandbox_id, "--", "/bin/sh", "-lc", restore_command)

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *_exc) -> None:
        self.kill()


class AsyncCommands:
    def __init__(self, commands: Commands):
        self._commands = commands

    async def run(self, command: str | list[str], *, timeout: int = 120,
                  envs: dict[str, str] | None = None, cwd: str = "/workspace",
                  user: str = "root", check: bool = True) -> CommandResult:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        sandbox = self._commands._sandbox
        argv = ["/bin/sh", "-lc", command] if isinstance(command, str) else command
        raw = await sandbox.node.call_async("rpc", sandbox.sandbox_id, "-", data={
            "op": "exec", "argv": argv, "env": envs or {}, "cwd": cwd,
            "timeout": timeout, "user": user,
        }, timeout=timeout + 30)
        result = CommandResult(**raw)
        if check and result.exit_code:
            raise CommandExitException(result)
        return result


class AsyncFiles:
    def __init__(self, files: Files):
        self._files = files

    async def write(self, path: str, data: str | bytes | Path, *, user: str = "root") -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        sandbox = self._files._sandbox
        source = data.open("rb") if isinstance(data, Path) else io.BytesIO(data.encode() if isinstance(data, str) else data)
        with source:
            append = False
            while True:
                content = source.read(4 << 20)
                if not content and append:
                    break
                await sandbox.node.call_async("rpc", sandbox.sandbox_id, "-", data={
                    "op": "write", "path": path, "data": base64.b64encode(content).decode(),
                    "append": append, "user": user,
                })
                append = True
                if not content:
                    break

    async def read(self, path: str, *, format: str = "text", user: str = "root") -> str | bytes:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
            raise ValueError("Invalid guest user")
        if format not in ("text", "bytes"):
            raise ValueError("format must be text or bytes")
        sandbox = self._files._sandbox
        value = await sandbox.node.call_async("rpc", sandbox.sandbox_id, "-", data={"op": "read", "path": path, "user": user})
        data = base64.b64decode(value["data"])
        return data.decode() if format == "text" else data


class AsyncSandbox:
    def __init__(self, sandbox: Sandbox):
        self._sandbox = sandbox
        self.sandbox_id = sandbox.sandbox_id
        self.node = sandbox.node
        self.commands = AsyncCommands(sandbox.commands)
        self.files = AsyncFiles(sandbox.files)

    @classmethod
    async def create(cls, template: str | None = None, *, node: Node | None = None, cluster: Cluster | None = None,
                     memory_mb: int = 512, memory_mode: str = "cgroup", runtime: str = "native",
                     gpus: list[int] | None = None, gpu_mode: str = "shared", mounts: list[Mount] | None = None,
                     network: str = "none", envs: dict[str, str] | None = None, pids_max: int = 256,
                     sandbox_id: str | None = None, create_timeout: float | None = 600) -> AsyncSandbox:
        if create_timeout is not None and (not math.isfinite(create_timeout) or create_timeout <= 0):
            raise ValueError("create_timeout must be positive and finite, or None")
        if node and cluster:
            raise ValueError("Specify node or cluster")
        if not isinstance(memory_mb, int) or memory_mb < 16:
            raise ValueError("memory_mb must be an integer >= 16")
        sid = sandbox_id or "s-" + uuid.uuid4().hex
        candidates = [node or Node()]
        if cluster:
            capacities = await asyncio.gather(
                *(n.call_async("capacity", timeout=20) for n in cluster.nodes), return_exceptions=True,
            )
            ranked = []
            for n, c in zip(cluster.nodes, capacities):
                if isinstance(c, BaseException):
                    continue
                available = max(1, c["config"]["memory_capacity_bytes"] * c["config"].get("memory_overcommit", 1) - c["memory_reserved"])
                ranked.append((random.expovariate(available), n.name, n))
            if not ranked:
                raise SandboxError("No reachable nodes: " + "; ".join(str(c) for c in capacities))
            # Sample without replacement, weighted by available memory. A
            # slightly stale least-loaded snapshot otherwise sends an entire
            # concurrent burst to one node. Runtime admission stays authoritative.
            candidates = [n for _, _, n in sorted(ranked, key=lambda v: v[0])]
        errors = []
        for candidate in candidates:
            token = uuid.uuid4().hex
            spec = {"id": sid, "rootfs": template or candidate.rootfs or os.environ.get("SUNABAKO_ROOTFS", ""),
                    "memory_bytes": memory_mb << 20, "memory_mode": memory_mode, "runtime": runtime,
                    "gpus": gpus or [], "gpu_mode": gpu_mode, "mounts": [dataclasses.asdict(m) for m in mounts or []],
                    "network": network, "env": envs or {}, "pids_max": pids_max}
            try:
                await candidate.call_async("create", "-", "--token", token, data=spec, timeout=create_timeout)
                return cls(Sandbox(sid, node=candidate))
            except (SandboxError, asyncio.CancelledError) as error:
                # Close the transport, then cancel only this request's remote
                # mutation. The token also rejects requests arriving after cancel.
                cancelled = isinstance(error, asyncio.CancelledError)
                cleanup = asyncio.create_task(candidate.call_async("cancel-create", sid, token, timeout=60))
                while not cleanup.done():
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError:
                        cancelled = True
                    except Exception:
                        break
                try:
                    result = cleanup.result()
                    if not isinstance(result, dict) or result.get("cancelled") is not True or result.get("deleted") is not True:
                        raise SandboxError("Node did not acknowledge creation cancellation")
                except Exception as cleanup_error:
                    if cancelled:
                        logging.getLogger(__name__).warning("Could not confirm cancelled creation cleanup for %s: %s", sid, cleanup_error)
                    else:
                        raise SandboxError(f"{error}; could not confirm creation cleanup for {sid}: {cleanup_error}") from error
                if cancelled:
                    raise asyncio.CancelledError from error
                if not any(s in str(error) for s in ("admission exhausted", "sharing slots exhausted", "exclusive reservation", "max_sandboxes reached")):
                    raise
                errors.append(f"{candidate.name}: {error}")
        raise SandboxError("Cluster capacity exhausted: " + "; ".join(errors))

    @classmethod
    async def connect(cls, sandbox_id: str, *, node: Node) -> AsyncSandbox:
        await node.call_async("inspect", sandbox_id)
        return cls(Sandbox(sandbox_id, node=node))

    async def get_info(self): return await self.node.call_async("inspect", self.sandbox_id)
    async def pause(self): return await self.node.call_async("pause", self.sandbox_id)
    async def resume(self): return await self.node.call_async("resume", self.sandbox_id)
    async def stop(self): return await self.node.call_async("stop", self.sandbox_id)
    async def start(self): return await self.node.call_async("start", self.sandbox_id)
    async def kill(self, *, defer_cleanup: bool = False):
        await self.stop()
        await self.node.call_async("delete", self.sandbox_id, *(["--defer"] if defer_cleanup else []))
    async def snapshot(self, destination: str):
        return await self.node.call_async("snapshot", self.sandbox_id, destination, timeout=600)
    async def hibernate(self, checkpoint_command: str):
        return await self.node.call_async("hibernate", self.sandbox_id, "--", "/bin/sh", "-lc", checkpoint_command)
    async def restore(self, restore_command: str):
        return await self.node.call_async("restore", self.sandbox_id, "--", "/bin/sh", "-lc", restore_command)

    # Slime's slime.agent.sandbox.Sandbox protocol.
    async def exec(self, cmd: str, *, user: str = "root", env: dict[str, str] | None = None,
                   timeout: int = 120, check: bool = False, idempotent: bool = False) -> tuple[int, str, str]:
        result = await self.commands.run(cmd, user=user, envs=env, timeout=timeout, check=check)
        return result.exit_code, result.stdout, result.stderr

    async def write_file(self, sandbox_path: str, content: str | bytes | Path, *, user: str = "root") -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user): raise ValueError("Invalid guest user")
        await self.files.write(sandbox_path, content, user=user)

    async def read_file(self, sandbox_path: str, *, user: str = "root") -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", user): raise ValueError("Invalid guest user")
        return await self.files.read(sandbox_path, user=user)

    async def __aenter__(self) -> AsyncSandbox: return self
    async def __aexit__(self, *_exc) -> None: await self.kill()
