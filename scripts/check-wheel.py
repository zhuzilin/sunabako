"""Check a wheel in a fresh environment without source imports or build tools."""

import argparse
import email
import hashlib
import json
import os
import subprocess
import tempfile
import venv
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        forbidden = {"__pycache__", "target", ".git", "slime", "examples"}
        assert not any(forbidden.intersection(Path(name).parts) for name in names)
        binaries = [name for name in names if name.endswith(".data/scripts/sunabako")]
        assert len(binaries) == 1, binaries
        assert archive.read(binaries[0]).startswith(b"\x7fELF")
        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        assert len(metadata_names) == 1
        metadata = email.message_from_bytes(archive.read(metadata_names[0]))
        assert metadata["Name"] == "sunabako"
        assert not metadata.get_all(
            "Requires-Dist"
        ), "The SDK has no runtime Python dependencies"
        assert "-py3-none-" in wheel.name and wheel.name.endswith(
            "x86_64.whl"
        ), wheel.name
        for name in names:
            if ".dist-info/" in name and name.endswith(".json"):
                assert b"path+file://" not in archive.read(name), name

    with tempfile.TemporaryDirectory(prefix="sunabako-wheel-check-") as directory:
        root = Path(directory)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / "bin/python"
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH", "PYTHONHOME"}
        }
        env["PATH"] = str(environment / "bin")
        subprocess.run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--only-binary=:all:",
                str(wheel),
            ],
            env=env,
            cwd=root,
            check=True,
            timeout=120,
        )
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                """
import importlib.metadata
import json
import pathlib
import shutil
import subprocess
import sys
import sunabako
from sunabako import AsyncSandbox, Cluster, Mount, Node, Sandbox

assert pathlib.Path(sunabako.__file__).is_relative_to(sys.prefix), sunabako.__file__
assert all(shutil.which(name) is None for name in ('rustc', 'cargo', 'maturin', 'proot'))
version = importlib.metadata.version('sunabako')
assert sunabako.__version__ == version
binary = pathlib.Path(sys.prefix) / 'bin/sunabako'
reported = json.loads(subprocess.check_output([str(binary), '--version'], text=True))
assert reported['version'] == version, reported
node = Node(binary=str(binary), state_dir=str(pathlib.Path.cwd() / 'state'))
assert node.call('help')['usage']
print(json.dumps({'version': version, 'sdk': sunabako.__file__, 'cli': str(binary)}))
""",
            ],
            env=env,
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
        )
        installed = json.loads(result.stdout)

    report = {
        "wheel": wheel.name,
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "version": installed["version"],
        "passed": True,
        "checks": [
            "binary-only install",
            "isolated SDK import",
            "no build tools on PATH",
            "SDK/CLI version agreement",
            "real SDK-to-CLI invocation",
        ],
        "privileged_sandbox_tests": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
