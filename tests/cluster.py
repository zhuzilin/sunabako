"""Exercise installed wheels and real CUDA kernels on the four allocated nodes."""
import asyncio
import json
from pathlib import Path
from sunabako import AsyncSandbox, Cluster, Mount, Node

HOSTS = ["100.113.71.45", "100.113.72.44", "100.113.73.47", "100.113.74.64"]
NODES = [Node(name=f"node{i}", host=host, port=2222, state_dir="/tmp/sunabako-cluster-test",
              binary="/tmp/sunabako-node-runtime/bin/sunabako", rootfs="/tmp/sunabako-images/ubuntu")
         for i, host in enumerate(HOSTS)]
ARTIFACTS = Path("/mnt/o1_checkpoints/zzl/tmp/sunabako-cluster-results")


async def check_node(node):
    volume = ARTIFACTS / node.name
    volume.mkdir(parents=True, exist_ok=True)
    volume.chmod(0o777)
    sb = await AsyncSandbox.create(node=node, runtime="proot", memory_mb=512, memory_mode="rss",
                                   gpus=[0], mounts=[Mount(str(volume), "/workspace")])
    async with sb:
        await sb.files.write("/workspace/cuda", Path("/tmp/sunabako-gpu-compute"))
        await sb.commands.run(["chmod", "+x", "/workspace/cuda"])
        result = await sb.commands.run(["/workspace/cuda"], timeout=90)
        assert "CUDA kernel PASS" in result.stdout
        await sb.files.write("/workspace/persistent.txt", node.name)
        await sb.pause()
        assert (await sb.get_info())["status"]["state"] == "paused"
        await sb.resume()
        await sb.stop()
        await sb.start()
        assert await sb.files.read("/workspace/persistent.txt") == node.name
        return {"node": node.name, "host": node.host, "cuda": result.stdout.strip(), "persistent_volume": True}


async def main():
    ARTIFACTS.mkdir(exist_ok=True)
    results = await asyncio.gather(*(check_node(n) for n in NODES))
    for result in results:
        print(json.dumps(result), flush=True)
    # These are the two sandbox machines selected for the later SWE run.
    cluster = Cluster(NODES[2:])
    allocated = []
    try:
        for _ in range(2):
            allocated.append(await AsyncSandbox.create(cluster=cluster, runtime="proot", memory_mb=128, memory_mode="rss"))
        assert {s.node.name for s in allocated} == {"node2", "node3"}
    finally:
        await asyncio.gather(*(s.kill() for s in allocated))
    report = {"nodes": results, "scheduler_distributed_across_two_sandbox_nodes": True,
              "hard_aggregate_memory_limit": False}
    (ARTIFACTS / "result.json").write_text(json.dumps(report, indent=2))
    Path("configs/cluster.test.json").write_text(json.dumps({"nodes": [n.__dict__ for n in NODES[2:]]}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
