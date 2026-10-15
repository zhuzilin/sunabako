"""Real-node OCI cache, reflink isolation, eviction and cleanup verification.

Run explicitly with two downloaded OCI layouts on a node with local reflink
storage. Choose a cache budget fitting either image, but not both together.
"""
import argparse
from contextlib import ExitStack
import fcntl
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from sunabako import Node, Sandbox


def verify_reserved_startup(node, image, memory_mode, *, defer_cleanup=False):
    """Creation and lifecycle changes proceed while another client holds admission.

    Run on the node itself, with rootfs_clone_concurrency=1 and an isolated
    state directory. The clone slot makes the lock ordering deterministic.
    """
    state = Path(node.state_dir)
    sandbox_id = "reserved-startup"
    sandbox = Sandbox(sandbox_id, node=node)
    creator = None
    with (state / "clone-0.lock").open("a+") as clone_slot:
        fcntl.flock(clone_slot, fcntl.LOCK_EX)
        try:
            creator = subprocess.Popen(
                [node.binary, "--state", node.state_dir, "create", "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True,
            )
            json.dump({"id": sandbox_id, "rootfs": str(image), "memory_bytes": 512 << 20,
                       "memory_mode": memory_mode, "runtime": "proot"}, creator.stdin)
            creator.stdin.close()
            creator.stdin = None
            deadline = time.monotonic() + 10
            while not (state / sandbox_id / "record.json").exists():
                assert creator.poll() is None, "creator exited before reserving resources"
                assert time.monotonic() < deadline, "creation did not reserve resources"
                time.sleep(0.01)
            with (state / ".lock").open("r+") as admission:
                fcntl.flock(admission, fcntl.LOCK_EX)
                started = time.monotonic()
                fcntl.flock(clone_slot, fcntl.LOCK_UN)
                stdout, stderr = creator.communicate(timeout=60)
                assert creator.returncode == 0, stderr
                assert json.loads(stdout)["status"]["state"] == "running"
                startup_seconds = time.monotonic() - started
                lifecycle_started = time.monotonic()
                sandbox.pause()
                sandbox.resume()
                sandbox.stop()
                if defer_cleanup:
                    with ExitStack() as cleanup_slots:
                        for i in range(4):
                            slot = cleanup_slots.enter_context((state / f"delete-{i}.lock").open("a+"))
                            fcntl.flock(slot, fcntl.LOCK_EX)
                        result = node.call("delete", sandbox_id, "--defer", timeout=10)
                        assert result["cleanup_pending"] is True
                        assert not (state / sandbox_id).exists()
                        assert list((state / ".trash").glob(sandbox_id + "-*"))
                    deadline = time.monotonic() + 30
                    while list((state / ".trash").glob(sandbox_id + "-*")):
                        assert time.monotonic() < deadline, "deferred cleanup did not finish"
                        time.sleep(.05)
                else:
                    sandbox.kill()
                return {"startup_seconds": startup_seconds,
                        "pause_resume_stop_delete_seconds": time.monotonic() - lifecycle_started}
        finally:
            fcntl.flock(clone_slot, fcntl.LOCK_UN)
            if creator is not None:
                if creator.poll() is None:
                    try:
                        creator.communicate(timeout=60)
                    except subprocess.TimeoutExpired:
                        # This isolated test owns the creator's process group,
                        # including a copy/import that outlives the failed probe.
                        try:
                            os.killpg(creator.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        creator.communicate()
                if (state / sandbox_id / "record.json").exists():
                    sandbox.kill()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image-a", "image-b", "state", "cache", "binary", "proot", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cache-budget-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, default=8 << 30)
    parser.add_argument("--allow-test-memory", action="store_true")
    parser.add_argument("--cgroup-parent")
    args = parser.parse_args()
    if args.state.exists() or args.cache.exists():
        raise ValueError("Use fresh local state and cache paths")
    node = Node(state_dir=str(args.state.resolve()), binary=str(args.binary.resolve()))
    config = dict(memory_capacity_bytes=4 << 30, memory_overcommit=1, max_sandboxes=8,
                  uid_start=75000, proot_binary=str(args.proot.resolve()),
                  image_cache_dir=str(args.cache.resolve()),
                  image_cache_max_bytes=args.cache_budget_bytes,
                  image_cache_min_free_bytes=args.reserve_bytes,
                  rootfs_clone_concurrency=1,
                  allow_unbounded_memory_for_tests=args.allow_test_memory)
    if args.cgroup_parent:
        config["cgroup_parent"] = args.cgroup_parent
    node.configure(**config)
    result = {}
    sandboxes = []

    def create(image, name):
        start = time.monotonic()
        sandbox = Sandbox.create(str(image.resolve()), node=node, sandbox_id=name,
                                 memory_mb=512, runtime="proot",
                                 memory_mode="rss" if args.allow_test_memory else "cgroup")
        sandboxes.append(sandbox)
        result[name + "_seconds"] = time.monotonic() - start
        return sandbox

    try:
        a = create(args.image_a, "cold")
        b = create(args.image_a, "warm")
        a.files.write("/tmp/cache-isolation", "only-a")
        b.commands.run("test ! -e /tmp/cache-isolation")
        # Other admissions must not prevent live sandboxes from executing tools.
        with (args.state / ".lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            reply = node.call("rpc", b.sandbox_id, "-", timeout=3, data={
                "op": "exec", "argv": ["/bin/true"], "env": {},
                "cwd": "/tmp", "timeout": 1, "user": "root",
            })
            assert reply["exit_code"] == 0
            result["rpc_during_node_lock_seconds"] = time.monotonic() - started
        result["lifecycle_during_node_lock"] = verify_reserved_startup(
            node, args.image_a.resolve(), "rss" if args.allow_test_memory else "cgroup"
        )
        result["deferred_cleanup_during_node_lock"] = verify_reserved_startup(
            node, args.image_a.resolve(), "rss" if args.allow_test_memory else "cgroup", defer_cleanup=True
        )
        first_key = json.loads((args.image_a / "index.json").read_text())["manifests"][0]["digest"].split(":")[1]
        assert (args.cache / first_key).is_dir()
        c = create(args.image_b, "evict")
        assert not (args.cache / first_key).exists(), "Choose a budget that forces eviction"
        assert a.files.read("/tmp/cache-isolation") == "only-a"
        b.commands.run("test ! -e /tmp/cache-isolation")
        c.commands.run("test -x /bin/sh")
        assert not (args.image_a / "rootfs").exists()
        assert not (args.image_b / "rootfs").exists()
        result["isolation_and_eviction"] = True
    finally:
        for sandbox in reversed(sandboxes):
            sandbox.kill()
        result["remaining_sandboxes"] = node.call("list")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
