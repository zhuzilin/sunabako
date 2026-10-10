"""Reject a release unless the tested wheel and sdist match its version tag."""

import argparse
import email
import tarfile
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    assert args.tag.startswith("v"), "Release tags must start with v"
    version = args.tag[1:]
    wheels = sorted(args.dist.glob("*.whl"))
    sdists = sorted(args.dist.glob("*.tar.gz"))
    assert (
        len(wheels) == len(sdists) == 1
    ), "Expected one py3-none Linux wheel and one sdist"
    assert "-py3-none-manylinux" in wheels[0].name and wheels[0].name.endswith(
        "x86_64.whl"
    )
    for path in wheels + sdists:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                entries = [
                    name
                    for name in archive.namelist()
                    if name.endswith(".dist-info/METADATA")
                ]
                assert len(entries) == 1
                data = archive.read(entries[0])
        else:
            with tarfile.open(path) as archive:
                member = archive.extractfile(f"sunabako-{version}/PKG-INFO")
                assert member is not None
                data = member.read()
        metadata = email.message_from_bytes(data)
        assert metadata["Name"] == "sunabako", path
        assert (
            metadata["Version"] == version
        ), f"{path.name}: version does not match tag {args.tag}"
        print(f"Verified {path.name}")


if __name__ == "__main__":
    main()
