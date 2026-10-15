"""Verify PRoot PID/TID translation on an isolated test-mode node.

Build verification/proc_lookup.c with gcc -O2 -pthread -static. Supply an
unused state directory, a rootfs with /bin/sh, and a dedicated UID range.
An optional baseline binary records the old behavior without requiring it
to pass the regression checks. Runtime confinement remains enabled.
"""
import argparse
import json
import shutil
import statistics
from pathlib import Path

from sunabako import Mount, Node, Sandbox, SandboxError


def main(args):
    if args.state.exists() or args.report.exists():
        raise ValueError("Use unused state and report paths")
    probe_dir = args.state / "probe"
    probe_dir.mkdir(parents=True)
    shutil.copy2(args.probe, probe_dir / "proc-lookup-probe")
    variants = [("candidate", args.proot)]
    if args.baseline_proot:
        variants.insert(0, ("baseline", args.baseline_proot))
    report = {}
    for index, (name, proot) in enumerate(variants):
        node = Node(state_dir=str(args.state / name), binary=str(args.binary))
        node.configure(
            memory_capacity_bytes=512 << 20, max_sandboxes=4,
            uid_start=args.uid_start + index * 4, rootfs_clone_concurrency=1,
            allow_unbounded_memory_for_tests=True, proot_binary=str(proot),
        )
        sandbox = Sandbox.create(
            str(args.rootfs), node=node, runtime="proot", memory_mode="rss",
            memory_mb=128,
            mounts=[Mount(str(probe_dir), "/probe", True)],
        )
        result = {"measurements": []}
        try:
            for _ in range(3):
                value = sandbox.commands.run(
                    ["/probe/proc-lookup-probe", str(args.iterations), "bench", str(args.workers)], timeout=120,
                )
                result["measurements"].append(json.loads(value.stdout))
            value = sandbox.commands.run(
                ["/probe/proc-lookup-probe", "1", "check"], timeout=120, check=False,
            )
            result.update(
                check_exit_code=value.exit_code,
                check_stdout=value.stdout, check_stderr=value.stderr,
                median_seconds=statistics.median(
                    row["seconds"] for row in result["measurements"]
                ),
            )
            sandbox.pause()
            assert sandbox.get_info()["status"]["state"] == "paused"
            sandbox.resume()
            sandbox.commands.run(["/bin/sh", "-c", ":"])
        finally:
            sandbox.kill()
            result["remaining"] = len(node.call("list"))
            report[name] = result
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(name, json.dumps(result), flush=True)
    assert report["candidate"]["check_exit_code"] == 0, report["candidate"]
    assert all(row["remaining"] == 0 for row in report.values()), report
    if args.baseline_proot:
        node = Node(state_dir=str(args.state / "upgrade"), binary=str(args.binary))
        node.configure(
            memory_capacity_bytes=512 << 20, max_sandboxes=4,
            uid_start=args.uid_start + 8, rootfs_clone_concurrency=1,
            allow_unbounded_memory_for_tests=True, proot_binary=str(args.baseline_proot),
        )
        sandboxes = []
        try:
            old = Sandbox.create(
                str(args.rootfs), node=node, runtime="proot", memory_mode="rss", memory_mb=128,
                mounts=[Mount(str(probe_dir), "/probe", True)],
            )
            sandboxes.append(old)
            old_pid = old.get_info()["status"]["init_pid"]
            config = node.call("capacity")["config"]
            expected = dict(config, proot_binary=str(args.proot))
            assert node.call("set-proot", str(args.proot))["config"] == expected
            for invalid in ("relative-path", str(args.state), str(args.state / "missing")):
                try:
                    node.call("set-proot", invalid)
                except SandboxError:
                    pass
                else:
                    raise AssertionError(f"Accepted invalid executable: {invalid}")
            assert node.call("capacity")["config"] == expected
            try:
                node.configure(**dict(expected, max_sandboxes=5))
            except SandboxError:
                pass
            else:
                raise AssertionError("General reconfiguration accepted with live sandboxes")
            new = Sandbox.create(
                str(args.rootfs), node=node, runtime="proot", memory_mode="rss", memory_mb=128,
                mounts=[Mount(str(probe_dir), "/probe", True)],
            )
            sandboxes.append(new)
            new.commands.run(["/probe/proc-lookup-probe", "1", "check"])
            assert old.get_info()["status"]["init_pid"] == old_pid
            old.commands.run(["/probe/proc-lookup-probe", "1"])
            report["upgrade"] = {"existing_init_preserved": True, "new_process_checks_passed": True}
        finally:
            for sandbox in reversed(sandboxes):
                sandbox.kill()
            remaining = len(node.call("list"))
            report.setdefault("upgrade", {})["remaining"] = remaining
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        assert remaining == 0
        print("upgrade", json.dumps(report["upgrade"]), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state", "report", "rootfs", "binary", "proot", "probe"):
        parser.add_argument("--" + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--baseline-proot", type=lambda value: Path(value).resolve())
    parser.add_argument("--uid-start", type=int, required=True)
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument("--workers", type=int, choices=range(129), metavar="N", default=0,
                        help="Idle threads present during each lookup benchmark (0–128)")
    main(parser.parse_args())
