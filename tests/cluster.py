"""Exercise installed wheels and CUDA kernels on an explicitly configured cluster."""
import argparse
import asyncio
import json
from pathlib import Path
from sunabako import AsyncSandbox, Cluster, Mount


async def check_node(node, artifacts, cuda_binary):
    volume = artifacts / node.name
    volume.mkdir(parents=True, exist_ok=True)
    volume.chmod(0o777)
    sb = await AsyncSandbox.create(node=node, runtime="proot", memory_mb=512, memory_mode="rss",
                                   gpus=[0], mounts=[Mount(str(volume), "/workspace")])
    async with sb:
        await sb.files.write("/workspace/cuda", cuda_binary)
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


async def main(args):
    nodes = Cluster.from_file(args.cluster).nodes
    if len(nodes) < 2:
        raise ValueError("The cluster probe requires at least two nodes")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    results = await asyncio.gather(*(check_node(n, artifacts, args.cuda_binary) for n in nodes))
    for result in results:
        print(json.dumps(result), flush=True)
    cluster = Cluster(nodes[-2:])
    allocated = []
    try:
        for _ in range(2):
            allocated.append(await AsyncSandbox.create(cluster=cluster, runtime="proot", memory_mb=128, memory_mode="rss"))
        # Placement is weighted random; two requests may legitimately choose
        # the same node. check_node above exercises every configured node.
        placements = [s.node.name for s in allocated]
        assert set(placements) <= {n.name for n in cluster.nodes}
        for sandbox in allocated:
            assert (await sandbox.commands.run(["/bin/true"])).exit_code == 0
    finally:
        await asyncio.gather(*(s.kill() for s in allocated))
    report = {"nodes": results, "cluster_allocation_nodes": placements,
              "hard_aggregate_memory_limit": False}
    (artifacts / "result.json").write_text(json.dumps(report, indent=2))
    (artifacts / "cluster.json").write_text(json.dumps({"nodes": [n.__dict__ for n in cluster.nodes]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", type=Path, required=True, help="Private cluster configuration")
    parser.add_argument("--artifacts", type=Path, required=True, help="Shared directory outside the source checkout")
    parser.add_argument("--cuda-binary", type=Path, required=True, help="Built verification/gpu_compute.c executable")
    asyncio.run(main(parser.parse_args()))
