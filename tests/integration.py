"""Bounded real-kernel integration tests. Never use test-mode nodes for production.

Run with an unused --state and --artifacts directory and an Ubuntu rootfs.
Requires the compiled verification/runtime_probe and verification/gpu_compute.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

from sunabako import Mount, Node, Sandbox, SandboxError


def until(check, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError("condition did not become true")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("state", "artifacts", "rootfs", "binary", "proot", "probe", "cuda"):
        p.add_argument("--" + key, required=True)
    a = p.parse_args()
    state = Path(a.state)
    artifacts = Path(a.artifacts)
    if state.exists() or artifacts.exists():
        raise ValueError("Use unused test directories")
    artifacts.mkdir(parents=True)
    readonly = artifacts / "readonly"
    readonly.mkdir(mode=0o755)
    (readonly / "canary").write_text("unaltered")
    node = Node(state_dir=str(state), binary=a.binary)
    report = {"hard_aggregate_memory_limit": False, "checks": {}}
    sandboxes = []

    def passed(name, result=True):
        report["checks"][name] = result
        print(name, json.dumps(result), flush=True)
        (artifacts / "result.json").write_text(json.dumps(report, indent=2))

    def create(name, **kw):
        s = Sandbox.create(a.rootfs, node=node, sandbox_id=name, runtime="proot", memory_mode="rss", **kw)
        sandboxes.append(s)
        return s

    def upload(s, file, target):
        s.files.write(target, Path(file))
        s.commands.run(["chmod", "+x", target])

    def devices():
        raw = subprocess.check_output(["nvidia-smi", "--query-compute-apps=pid,gpu_uuid,used_gpu_memory", "--format=csv,noheader,nounits"], text=True)
        return [line.split(", ") for line in raw.splitlines() if line.strip()]

    try:
        try:
            node.configure(memory_capacity_bytes=1 << 30)
        except SandboxError as e:
            assert "hard aggregate memory limit unavailable" in str(e), e
        else:
            raise AssertionError("production startup accepted missing cgroups")
        passed("production_refuses_missing_hard_cap")
        node.configure(memory_capacity_bytes=1 << 30, memory_overcommit=2, max_sandboxes=16,
                       uid_start=63000, gpu_slots_per_device=2, proot_binary=a.proot,
                       allow_unbounded_memory_for_tests=True)
        baseline={int(r[0]) for r in devices()}
        volumes = []
        for name in ("a", "b"):
            volume = artifacts / name
            volume.mkdir(mode=0o777)
            volume.chmod(0o777)
            volumes.append(volume)
            s = create(name, memory_mb=512, gpus=[0], mounts=[Mount(str(volume), "/workspace"), Mount(str(readonly), "/readonly", True)])
            upload(s, a.cuda, "/workspace/cuda-probe")
            upload(s, a.probe, "/workspace/runtime-probe")
            s.files.write("/workspace/secret", name)
            s.commands.run("/workspace/cuda-probe 120 >/workspace/cuda.log 2>&1 </dev/null &")
        x, y = sandboxes[:2]
        for volume in volumes:
            until(lambda: "CUDA kernel PASS" in (volume / "cuda.log").read_text())
        # NVML reports physical-host PIDs, which need not equal /proc PIDs
        # inside the allocated outer container. Track the new driver entries.
        rows = until(lambda: [r for r in devices() if int(r[0]) not in baseline])
        pids = {int(r[0]) for r in rows}
        assert len(rows) == 2 and rows[0][1] == rows[1][1] and all(int(r[2]) > 0 for r in rows), rows
        passed("two_sandboxes_share_one_gpu", rows)
        x.commands.run("unset CUDA_VISIBLE_DEVICES; /workspace/cuda-probe")
        passed("unassigned_gpu_devices_inaccessible_after_unsetting_env")
        x.commands.run(["/workspace/runtime-probe", "readonly", "/readonly/canary"])
        assert (readonly / "canary").read_text() == "unaltered"
        passed("readonly_mapping_blocks_write_and_truncate")
        x.commands.run(["/workspace/runtime-probe", "network"])
        passed("private_network_with_loopback")
        peer = y.get_info()["status"]["init_pid"]
        r = x.commands.run(["cat", f"/proc/{peer}/root{volumes[1]}/secret"], check=False)
        assert r.exit_code != 0, r
        passed("peer_rootfs_access_denied")
        x.commands.run("(i=0; while :; do i=$((i+1)); echo $i >/workspace/counter; sleep .05; done) >/workspace/ticker.log 2>&1 </dev/null &")
        until(lambda: (volumes[0] / "counter").exists())
        x.pause()
        before = (volumes[0] / "counter").read_text()
        time.sleep(.5)
        assert before == (volumes[0] / "counter").read_text()
        x.resume()
        until(lambda: (volumes[0] / "counter").read_text() != before)
        passed("pause_freezes_detached_processes_and_resume_continues")
        x.hibernate("cp /workspace/counter /workspace/checkpoint")
        assert x.get_info()["status"]["state"] == "hibernated"
        until(lambda: len([r for r in devices() if int(r[0]) in pids]) == 1)
        x.restore("cp /workspace/checkpoint /workspace/restored")
        assert x.files.read("/workspace/checkpoint") == x.files.read("/workspace/restored")
        passed("hibernate_releases_gpu_and_restores_application_checkpoint")
        y.pause()
        y.stop()
        until(lambda: not [r for r in devices() if int(r[0]) in pids])
        passed("stop_from_paused_releases_gpu")
        x.files.write("/root/persisted", "snapshot-data")
        snapshot = artifacts / "snapshot"
        x.snapshot(str(snapshot))
        z = Sandbox.create(str(snapshot / "rootfs"), node=node, sandbox_id="snapshot-clone", runtime="proot", memory_mode="rss", memory_mb=128)
        sandboxes.append(z)
        assert z.files.read("/root/persisted") == "snapshot-data"
        assert z.commands.run("test ! -e /dev/nvidia0").exit_code == 0
        passed("snapshot_restores_files_without_inheriting_gpu_grant")
        z.stop()
        x.stop()
        x.start()
        assert x.files.read("/workspace/secret") == "a"
        passed("mounted_volume_survives_restart")
        memory = create("memory", memory_mb=64)
        upload(memory, a.probe, "/workspace/runtime-probe")
        memory.commands.run(["/workspace/runtime-probe", "memory"])
        until(lambda: memory.get_info()["status"]["state"] == "failed")
        assert memory.get_info()["status"]["reason"] == "memory_limit_exceeded"
        passed("rss_watchdog_accounts_for_double_fork_sets_id")
        x.stop()
        big = create("overcommit-a", memory_mb=1100)
        try:
            create("overcommit-b", memory_mb=1100)
        except SandboxError as e:
            assert "admission exhausted" in str(e), e
        else:
            raise AssertionError("admission exceeded 2x configured capacity")
        passed("overcommit_admission_uses_requested_memory")
        big.kill(); sandboxes.remove(big)
        report["passed"] = True
    finally:
        errors = []
        if not report.get("passed"):
            report["failure_state"] = node.call("list")
            for s in sandboxes:
                log=state/s.sandbox_id/"supervisor.log"
                if log.exists(): (artifacts/f"{s.sandbox_id}-supervisor.log").write_text(log.read_text())
        for s in reversed(sandboxes):
            try: s.kill()
            except Exception as e: errors.append(str(e))
        report["cleanup_errors"] = errors
        (artifacts / "result.json").write_text(json.dumps(report, indent=2))
        if errors: raise AssertionError(errors)


if __name__ == "__main__":
    main()
