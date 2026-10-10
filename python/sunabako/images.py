"""Fetch OCI images without running a Docker daemon.

Usage: python -m sunabako.images IMAGE DESTINATION
Requires skopeo and umoci; their verified layer handling avoids ad-hoc tar extraction.
"""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def pull(image: str, destination: str | Path) -> Path:
    destination = Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(destination)
    for name in ("skopeo", "umoci"):
        if not shutil.which(name):
            raise RuntimeError(f"Install {name} (Ubuntu: apt install skopeo umoci)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sunabako-image-", dir=destination.parent) as temporary:
        tmp = Path(temporary)
        layout = tmp / "oci"
        subprocess.run(["skopeo", "copy", "--override-os", "linux", "--override-arch", "amd64",
                        f"docker://{image}", f"oci:{layout}:image"], check=True)
        bundle = tmp / "bundle"
        subprocess.run(["umoci", "unpack", "--rootless", "--image", f"{layout}:image", str(bundle)], check=True)
        index = json.loads((layout / "index.json").read_text())
        manifest = index["manifests"][0]["digest"]
        config = json.loads((bundle / "config.json").read_text())["process"]
        (bundle / "image.json").write_text(json.dumps({"image": image, "manifest_digest": manifest,
            "env": dict(v.split("=", 1) for v in config.get("env", [])),
            "cwd": config.get("cwd", "/"), "command": config.get("args", [])}, indent=2))
        bundle.rename(destination)
    return destination / "rootfs"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image")
    p.add_argument("destination")
    args = p.parse_args()
    print(pull(args.image, args.destination))


if __name__ == "__main__":
    main()
