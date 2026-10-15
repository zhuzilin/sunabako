"""Check RSS accounting of detached processes using a dedicated test-mode node."""
import argparse
import asyncio
import dataclasses
import json
import shlex
import time
from pathlib import Path

from sunabako import AsyncSandbox, Cluster


async def main(args):
    node = Cluster.from_file(args.cluster).nodes[0]
    if args.binary:
        node = dataclasses.replace(node, binary=args.binary)
    sandbox = await AsyncSandbox.create(
        args.image, node=node, runtime="proot", memory_mode="rss", memory_mb=192,
    )
    report = {}
    try:
        # A worker thread spawns a new session and exits. Its orphaned child
        # must remain visible to namespace accounting and pause/resume.
        child = "import time; from pathlib import Path\np=Path('/tmp/accounting-ticks')\nwhile True:\n p.write_text(str(time.monotonic()))\n time.sleep(.05)"
        launcher = (
            "import subprocess,threading\n"
            "def launch():\n"
            f" subprocess.Popen(['python','-c',{child!r}],start_new_session=True,"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "t=threading.Thread(target=launch);t.start();t.join()"
        )
        await sandbox.commands.run("python -c " + shlex.quote(launcher))
        await asyncio.sleep(.3)
        await sandbox.pause()
        before = (await sandbox.get_info())["status"]
        assert before["state"] == "paused" and before["process_count"] >= 2, before
        await sandbox.resume()
        first = await sandbox.files.read("/tmp/accounting-ticks")
        await asyncio.sleep(.3)
        assert await sandbox.files.read("/tmp/accounting-ticks") != first
        report["detached_thread_child_survives_and_resumes"] = True
        hog = "import time; data=bytearray(256<<20); time.sleep(60)"
        launcher = launcher.replace(repr(child), repr(hog))
        await sandbox.commands.run("python -c " + shlex.quote(launcher))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status = (await sandbox.get_info())["status"]
            if status["state"] == "failed":
                assert status["reason"] == "memory_limit_exceeded", status
                report["orphan_memory_limit_enforced"] = True
                break
            await asyncio.sleep(.1)
        else:
            raise AssertionError("Detached child escaped RSS accounting")
    finally:
        await sandbox.kill()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", type=Path, required=True)
    parser.add_argument("--image", required=True, help="Warm image containing python and /bin/sh")
    parser.add_argument("--binary", help="Override the node runtime binary")
    parser.add_argument("--report", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
