"""Real-node request-owned creation cancellation, using an isolated RSS test node.

Supply an unused local state directory, a small rootfs with /bin/sh, a PRoot
binary, and a dedicated UID range. No production node configuration is used.
"""
import argparse
import asyncio
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from sunabako import AsyncSandbox, Node, Sandbox
from sunabako.client import SandboxError


def live(pid, start):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19]) == start and fields[0] not in ("Z", "X")
    except (OSError, ValueError, IndexError):
        return False


async def until(condition, timeout=15):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("Timed out waiting for isolated test condition")
        await asyncio.sleep(.02)


async def main(args):
    assert not args.state.exists() and not args.report.exists(), "Use unused state and report paths"
    args.state.mkdir(parents=True)
    fixtures = args.state / ".fixtures"
    fixtures.mkdir()
    cache = fixtures / "cache"
    cache.mkdir()
    node = Node(binary=str(args.binary), state_dir=str(args.state))
    node.configure(memory_capacity_bytes=512 << 20, max_sandboxes=4, uid_start=args.uid_start,
                   allow_unbounded_memory_for_tests=True, rootfs_clone_concurrency=1,
                   image_cache_dir=str(cache), image_cache_max_bytes=1 << 30,
                   image_cache_min_free_bytes=0, proot_binary=str(args.proot))
    report = {"checks": {}}
    creators = []
    def record(name, **details):
        report["checks"][name] = {"passed": True, **details}
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(name, json.dumps(details), flush=True)
    def spec(sid, rootfs=None):
        return {"id": sid, "rootfs": str(rootfs or args.rootfs), "runtime": "proot",
                "memory_bytes": 64 << 20, "memory_mode": "rss"}
    def spawn(sid, token, *, rootfs=None, env=None):
        process = subprocess.Popen(node._command(("create", "-", "--token", token)),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True, env=env)
        json.dump(spec(sid, rootfs), process.stdin)
        process.stdin.close()
        process.stdin = None
        creators.append(process)
        return process
    def reject(*command, data=None):
        try:
            node.call(*command, data=data, timeout=20)
        except SandboxError:
            return
        raise AssertionError(f"Unexpectedly accepted {command[0]}")
    def cancel(sid, token):
        started = time.monotonic()
        result = node.call("cancel-create", sid, token, timeout=30)
        assert result["cancelled"] and result["deleted"] and not (args.state / sid).exists()
        return time.monotonic() - started
    sentinel = None
    try:
        sentinel = Sandbox.create(str(args.rootfs), node=node, sandbox_id="sentinel", runtime="proot",
                                  memory_mode="rss", memory_mb=64)
        sentinel_status = sentinel.get_info()["status"]
        legacy = node.call("create", "-", data=spec("legacy"))
        reject("cancel-create", "legacy", uuid.uuid4().hex)
        assert node.call("inspect", "legacy")["status"]["init_pid"] == legacy["status"]["init_pid"]
        Sandbox("legacy", node=node).kill()
        record("legacy_creation_remains_usable_and_unowned")
        token = uuid.uuid4().hex
        cancel("late", token)
        reject("create", "-", "--token", token, data=spec("late"))
        reject("cancel-create", "late", "../invalid")
        record("cancellation_before_arrival_blocks_late_create")

        reject("cancel-create", "sentinel", uuid.uuid4().hex)
        assert sentinel.get_info()["status"]["init_pid"] == sentinel_status["init_pid"]
        sentinel.commands.run(["/bin/sh", "-c", ":"])
        record("wrong_token_preserves_live_sandbox")

        sid, token = "admission-race", uuid.uuid4().hex
        with (args.state / ".lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = spawn(sid, token)
            children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
            await until(lambda: children.exists() and bool(children.read_text().strip()))
            cancellation = asyncio.create_task(node.call_async("cancel-create", sid, token, timeout=30))
            await asyncio.sleep(.1)
            assert not cancellation.done()
            fcntl.flock(lock, fcntl.LOCK_UN)
        assert (await cancellation)["deleted"]
        process.communicate(timeout=10)
        assert not (args.state / sid).exists()
        record("cancellation_races_admission_without_late_instance")

        sid, token = "launch-race", uuid.uuid4().hex
        with (args.state / "clone-0.lock").open("a+") as clone:
            fcntl.flock(clone, fcntl.LOCK_EX)
            process = spawn(sid, token)
            await until(lambda: (args.state / sid / "creation.json").exists())
            with (args.state / sid / ".lifecycle.lock").open("a+") as lifecycle:
                fcntl.flock(lifecycle, fcntl.LOCK_EX)
                fcntl.flock(clone, fcntl.LOCK_UN)
                cancellation = asyncio.create_task(node.call_async("cancel-create", sid, token, timeout=30))
                await until(lambda: (args.state / ".cancelled" / token).exists())
                assert not cancellation.done()
                fcntl.flock(lifecycle, fcntl.LOCK_UN)
        assert (await cancellation)["deleted"]
        process.communicate(timeout=10)
        assert process.returncode != 0 and not (args.state / sid).exists()
        record("cancellation_serializes_with_launch_publication")

        for kind in ("clone", "image"):
            sid, token = f"blocked-{kind}", uuid.uuid4().hex
            rootfs = args.rootfs
            lock_path = args.state / "clone-0.lock"
            if kind == "image":
                rootfs = fixtures / "oci"
                rootfs.mkdir()
                digest = "a" * 64
                (rootfs / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
                (rootfs / "index.json").write_text(json.dumps({"manifests": [{"digest": "sha256:" + digest}]}))
                lock_path = cache / f"{digest}.lock"
            with lock_path.open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = spawn(sid, token, rootfs=rootfs)
                await until(lambda: (args.state / sid / "creation.json").exists())
                owner = json.loads((args.state / sid / "creation.json").read_text())
                elapsed = cancel(sid, token)
                process.communicate(timeout=10)
                assert process.returncode != 0 and not live(owner["pid"], owner["start"])
                assert node.call("capacity")["active"] == 1
            record(f"cancel_while_waiting_for_{kind}", cancellation_seconds=elapsed)

        # Trusted preparation tools inherit only this request's dedicated session.
        tools = fixtures / "tools"
        tools.mkdir()
        cp = tools / "cp"
        cp.write_text(f"#!{sys.executable}\n" + """import json,os,subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
rows=[]
for pid in (os.getpid(),child.pid):
 fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
 rows.append({'pid':pid,'start':int(fields[19])})
Path(os.environ['SUNABAKO_TEST_PREPARATION']).write_text(json.dumps(rows))
child.wait()
""")
        cp.chmod(0o755)
        marker = fixtures / "preparation.json"
        sid, token = "active-copy", uuid.uuid4().hex
        process = spawn(sid, token, env=dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
                                             SUNABAKO_TEST_PREPARATION=str(marker)))
        await until(marker.exists)
        children = json.loads(marker.read_text())
        elapsed = cancel(sid, token)
        process.communicate(timeout=10)
        assert all(not live(row["pid"], row["start"]) for row in children)
        sentinel.commands.run(["/bin/sh", "-c", ":"])
        record("cancel_active_copy_and_descendant_preserves_other_sandbox", cancellation_seconds=elapsed)

        sid, token = "completed", uuid.uuid4().hex
        node.call("create", "-", "--token", token, data=spec(sid))
        assert node.call("inspect", sid)["status"]["state"] == "running"
        cancel(sid, token)
        cancel(sid, token)
        reject("create", "-", "--token", token, data=spec(sid))
        replacement_token = uuid.uuid4().hex
        replacement = node.call("create", "-", "--token", replacement_token, data=spec(sid))
        reject("cancel-create", sid, token)
        assert node.call("inspect", sid)["status"]["init_pid"] == replacement["status"]["init_pid"]
        cancel(sid, replacement_token)
        record("completed_creation_and_id_reuse_have_distinct_ownership")

        for asynchronous in (False, True):
            sid = "sdk-timeout-async" if asynchronous else "sdk-timeout-sync"
            with (args.state / "clone-0.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                started = time.monotonic()
                kwargs = dict(node=node, sandbox_id=sid, runtime="proot", memory_mode="rss",
                              memory_mb=64, create_timeout=.5)
                try:
                    if asynchronous:
                        await AsyncSandbox.create(str(args.rootfs), **kwargs)
                    else:
                        Sandbox.create(str(args.rootfs), **kwargs)
                except SandboxError as error:
                    assert "Transport timed out" in str(error) and "could not confirm" not in str(error)
                else:
                    raise AssertionError("Creation did not time out")
                assert not (args.state / sid).exists()
                assert node.call("capacity")["active"] == 1
            record(sid, elapsed_seconds=time.monotonic() - started)

        with (args.state / "clone-0.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            task = asyncio.create_task(AsyncSandbox.create(str(args.rootfs), node=node, sandbox_id="sdk-cancel",
                                       runtime="proot", memory_mode="rss", memory_mb=64, create_timeout=None))
            await until(lambda: (args.state / "sdk-cancel/creation.json").exists())
            task.cancel()
            try:
                await asyncio.wait_for(task, 30)
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Creation cancellation was lost")
            assert not (args.state / "sdk-cancel").exists()
        record("sdk_cancellation_stops_remote_preparation")

        # Keep the successful reply in a transport shim until the client times out.
        lost = fixtures / "lost-reply"
        lost_marker = fixtures / "reply-created"
        lost.write_text(f"#!{sys.executable}\n" + f"""import os,subprocess,sys,time
from pathlib import Path
binary={str(args.binary)!r}
if sys.argv[3]=='create':
 result=subprocess.run([binary,*sys.argv[1:]],input=sys.stdin.buffer.read(),capture_output=True)
 if result.returncode==0:
  Path({str(lost_marker)!r}).write_text('created')
  time.sleep(120)
 sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr);sys.exit(result.returncode)
os.execv(binary,[binary,*sys.argv[1:]])
""")
        lost.chmod(0o755)
        lost_node = Node(binary=str(lost), state_dir=str(args.state))
        try:
            await AsyncSandbox.create(str(args.rootfs), node=lost_node, sandbox_id="lost-reply",
                                      runtime="proot", memory_mode="rss", memory_mb=64, create_timeout=10)
        except SandboxError as error:
            assert "Transport timed out" in str(error) and "could not confirm" not in str(error)
        else:
            raise AssertionError("Lost reply did not time out")
        assert lost_marker.exists() and not (args.state / "lost-reply").exists()
        record("sdk_lost_success_reply_cleans_running_instance")

        current = sentinel.get_info()["status"]
        assert (current["init_pid"], current["init_start"]) == (sentinel_status["init_pid"], sentinel_status["init_start"])
        sentinel.commands.run(["/bin/sh", "-c", ":"])
        record("unrelated_sandbox_survives_all_cancellations")
        report["passed"] = True
    finally:
        for row in node.call("list"):
            sid = row["spec"]["id"]
            owner = json.loads((args.state / sid / "creation.json").read_text())
            cancel(sid, owner["token"])
        for process in creators:
            process.communicate(timeout=10)
        report["remaining"] = len(node.call("list"))
        await until(lambda: not any((args.state / ".trash").glob("*")))
        report["pending_cleanup_directories"] = 0
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    assert report["remaining"] == 0
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state", "report", "rootfs", "binary", "proot"):
        parser.add_argument("--" + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--uid-start", type=int, required=True)
    asyncio.run(main(parser.parse_args()))
