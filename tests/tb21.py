"""Run Terminal Bench 2.1's cancel-async-tasks oracle and unmodified verifier.

Import alexgshaw/cancel-async-tasks:20251031 first and provide its rootfs.
This is a bounded functional test; --allow-test-memory explicitly opts into RSS
monitoring when a writable delegated cgroup hierarchy is unavailable.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

from sunabako import Mount, Node, Sandbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "rootfs", "state", "artifacts", "binary", "proot"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--allow-test-memory", action="store_true")
    parser.add_argument("--cgroup-parent")
    args = parser.parse_args()
    state, artifacts = Path(args.state).resolve(), Path(args.artifacts).resolve()
    if state.exists() or artifacts.exists():
        raise ValueError("Use new state and artifact directories")
    repository = Path(args.repository).resolve()
    task = repository / "tasks/cancel-async-tasks"
    for script in (task / "solution/solve.sh", task / "tests/test.sh"):
        if not script.is_file():
            raise ValueError(f"Missing official script: {script}")
    logs = artifacts / "logs"
    (logs / "verifier").mkdir(parents=True, mode=0o777)
    logs.chmod(0o777)
    (logs / "verifier").chmod(0o777)
    node = Node(state_dir=str(state), binary=args.binary)
    config = dict(
        memory_capacity_bytes=4 << 30,
        uid_start=66000,
        proot_binary=args.proot,
        allow_unbounded_memory_for_tests=args.allow_test_memory,
    )
    if args.cgroup_parent:
        config["cgroup_parent"] = args.cgroup_parent
    node.configure(**config)
    env = {
        name: os.environ[name]
        for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY")
        if name in os.environ
    }
    report = {
        "task": "cancel-async-tasks",
        "repository": "https://github.com/harbor-framework/terminal-bench-2-1",
        "commit": subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip(),
        "rootfs": args.rootfs,
        "memory_mode": "rss" if args.allow_test_memory else "cgroup",
        "hard_aggregate_memory_limit": not args.allow_test_memory,
    }
    try:
        with Sandbox.create(
            args.rootfs,
            node=node,
            runtime="proot",
            network="host",
            memory_mb=2048,
            memory_mode=report["memory_mode"],
            envs=env,
            mounts=[
                Mount(str(task / "solution"), "/solution", True),
                Mount(str(task / "tests"), "/tests", True),
                Mount(str(logs), "/logs"),
            ],
        ) as sandbox:
            for name, command in (("oracle", "/solution/solve.sh"), ("verifier", "/tests/test.sh")):
                result = sandbox.commands.run(["bash", command], cwd="/app", timeout=900, check=False)
                (artifacts / f"{name}.log").write_text(result.stdout + "\n" + result.stderr)
                report[f"{name}_exit_code"] = result.exit_code
                if result.exit_code:
                    raise RuntimeError(f"{name} failed: inspect {artifacts / (name + '.log')}")
            report["reward"] = float(sandbox.files.read("/logs/verifier/reward.txt").strip())
            report["tests"] = json.loads(sandbox.files.read("/logs/verifier/ctrf.json"))
            if report["reward"] != 1.0:
                raise RuntimeError("Official TB verifier returned reward != 1")
    finally:
        report["remaining_sandboxes"] = node.call("list")
        (artifacts / "result.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
