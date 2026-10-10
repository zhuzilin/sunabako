#!/usr/bin/env bash
set -euo pipefail
# PRoot is a separate GPL-2.0-or-later executable. This patch keeps inherited
# procfs usable for tasks in a child PID namespace, including CUDA thread names.
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${1:-/tmp/sunabako-proot-build}
destination=${2:-/usr/local/libexec/sunabako/proot}
revision=25dc6a3134891f98a79f57ce1c2c1b23ff15cad1
if [[ ! -d "$build_dir/.git" ]]; then
    git clone https://github.com/proot-me/proot "$build_dir"
fi
git -C "$build_dir" checkout --detach "$revision"
git -C "$build_dir" submodule update --init
if git -C "$build_dir" apply --check "$project_dir/patches/proot-pidns.patch"; then
    git -C "$build_dir" apply "$project_dir/patches/proot-pidns.patch"
else
    git -C "$build_dir" apply --reverse --check "$project_dir/patches/proot-pidns.patch"
fi
# Dependencies on Ubuntu: gcc make git pkg-config libtalloc-dev.
make -C "$build_dir/src" -j "${SUNABAKO_BUILD_JOBS:-4}" WITHOUT_PYTHON=1 LDFLAGS='-static -ltalloc'
install -D -m 0755 "$build_dir/src/proot" "$destination"
sha256sum "$destination"
