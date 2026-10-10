"""Real native UID/GID, file-permission and isolation checks (run as outer root).

Requires an Ubuntu rootfs, user namespaces and permission to bind mount.
Use a fresh state directory outside /root so dedicated sandbox UIDs can traverse it.
"""

import argparse
import asyncio
import json
import subprocess
from pathlib import Path

from sunabako import AsyncSandbox, Mount, Node, SandboxError


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    state = Path(args.state)
    assert not state.exists(), "Use a fresh state directory"
    artifacts = state.with_name(state.name + "-artifacts")
    artifacts.mkdir()
    readonly = artifacts / "readonly"
    readonly.mkdir()
    (readonly / "canary").write_text("unchanged")
    node = Node(state_dir=str(state), binary=args.binary, rootfs=args.rootfs)
    node.configure(uid_start=1000000, uid_range_size=65536, max_sandboxes=3,
                   memory_capacity_bytes=3 << 30, allow_unbounded_memory_for_tests=True)
    report = {"checks": [], "passed": False}
    sandboxes = []

    def passed(name):
        report["checks"].append(name)
        print("PASS", name, flush=True)

    async def denied(operation):
        try:
            await operation
        except SandboxError:
            return
        raise AssertionError("Unprivileged file operation unexpectedly succeeded")

    try:
        sb = await AsyncSandbox.create(node=node, sandbox_id="users", runtime="native",
                                       memory_mb=1024, memory_mode="rss",
                                       envs={"HOME": "/root"},
                                       mounts=[Mount(str(readonly), "/readonly", True)])
        sandboxes.append(sb)
        await sb.commands.run("useradd -u 1234 -m -s /bin/bash agent && "
                              "groupadd -g 1235 extra && usermod -aG extra agent")
        result = await sb.commands.run("id -u; id -g; id -G; printf '%s\\n' \"$HOME\"", user="agent")
        assert result.stdout.splitlines() == ["1234", "1234", "1234 1235", "/home/agent"], result
        status = (await sb.commands.run("cat /proc/self/status", user="agent")).stdout
        for line in status.splitlines():
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")):
                assert int(line.split()[1], 16) == 0, line
        assert "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status, status
        passed("agent_has_real_uid_groups_and_zero_capabilities")

        payload = "native-user-file\n" * 280000  # crosses the 4 MiB upload boundary
        await sb.write_file("/home/agent/owned", payload, user="agent")
        assert await sb.read_file("/home/agent/owned", user="agent") == payload
        info = await sb.get_info()
        owned = state / "users/rootfs/home/agent/owned"
        assert owned.stat().st_uid == info["uid"] + 1234
        assert owned.stat().st_gid == info["uid"] + 1234
        passed("chunked_async_files_use_agent_ownership")

        await sb.write_file("/root/private", "root-only")
        await sb.commands.run("chmod 600 /root/private")
        await denied(sb.read_file("/root/private", user="agent"))
        await denied(sb.write_file("/root/private", "overwritten", user="agent"))
        await denied(sb.read_file("/proc/self/environ", user="agent"))
        await sb.commands.run("ln -s /proc/self/environ /home/agent/worker-env")
        await denied(sb.read_file("/home/agent/worker-env", user="agent"))
        await denied(sb.write_file("/readonly/canary", "overwritten", user="root"))
        assert (readonly / "canary").read_text() == "unchanged"
        assert await sb.read_file("/root/private") == "root-only"
        escalation = await sb.commands.run("python3 -c 'import os; os.setuid(0)'", user="agent", check=False)
        assert escalation.exit_code != 0 and "Operation not permitted" in escalation.stderr, escalation
        assert (await sb.commands.run("unshare -Ur true", check=False)).exit_code != 0
        assert (await sb.commands.run("chown 65536:65536 /home/agent/owned", check=False)).exit_code != 0
        passed("file_permissions_readonly_mount_and_privilege_escalation_enforced")

        peer = await AsyncSandbox.create(node=node, sandbox_id="peer", runtime="native",
                                         memory_mb=512, memory_mode="rss")
        sandboxes.append(peer)
        peer_info = await peer.get_info()
        assert peer_info["uid"] >= info["uid"] + info["uid_range_size"]
        peer_file = state / "peer/rootfs/etc/passwd"
        for uid in [info["uid"], info["uid"] + 1234]:
            read = subprocess.run(["setpriv", "--reuid", str(uid), "--regid", str(uid),
                                   "--clear-groups", "cat", str(peer_file)], capture_output=True)
            assert read.returncode != 0 and b"Permission denied" in read.stderr, read
        passed("guest_root_and_agent_cannot_read_peer_rootfs_from_outer_namespace")

        await sb.stop()
        await sb.start()
        assert await sb.read_file("/home/agent/owned", user="agent") == payload
        assert (await sb.commands.run("id -u", user="agent")).stdout.strip() == "1234"
        passed("user_mapping_and_files_survive_restart")

        # Existing nodes still default to a single unprivileged outer UID.
        legacy = Node(state_dir=str(artifacts / "legacy"), binary=args.binary, rootfs=args.rootfs)
        legacy.configure(uid_start=2000000, max_sandboxes=1, allow_unbounded_memory_for_tests=True)
        old = await AsyncSandbox.create(node=legacy, sandbox_id="root-only", runtime="native",
                                        memory_mb=512, memory_mode="rss", envs={"HOME": "/tmp"})
        sandboxes.append(old)
        assert (await old.commands.run("id -u")).stdout.strip() == "0"
        assert (await old.commands.run("printf %s \"$HOME\"")).stdout == "/tmp"
        await denied(old.commands.run("id", user="agent"))
        passed("legacy_root_only_nodes_remain_compatible")
        report["passed"] = True
    finally:
        for sb in reversed(sandboxes):
            log = Path(sb.node.state_dir) / sb.sandbox_id / "supervisor.log"
            if log.exists():
                (artifacts / f"{sb.sandbox_id}-supervisor.log").write_text(log.read_text())
            await sb.kill()
        (artifacts / "result.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
