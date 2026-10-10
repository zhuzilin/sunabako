#!/usr/bin/env bash
# Explicit functional-test setup for the current container allocation.
# This configuration does NOT provide a hard aggregate memory cap.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
stage=${1:?usage: provision-test-node.sh STAGED_ARTIFACTS_DIRECTORY}
runtime_dir=/tmp/sunabako-node-runtime
image_dir=/tmp/sunabako-images/ubuntu
python -m venv "$runtime_dir"
"$runtime_dir/bin/python" -m pip install --no-index --no-deps --force-reinstall "$project_dir"/dist/sunabako-*.whl
install -D -m 0755 "$stage/proot" /tmp/sunabako-tools/proot
if [[ ! -d "$image_dir/bin" ]]; then
    mkdir -p "$image_dir"
    tar -xzf "$stage/ubuntu.tar.gz" -C "$image_dir"
fi
"$runtime_dir/bin/python" - <<'PY'
from sunabako import Node
n=Node(binary='/tmp/sunabako-node-runtime/bin/sunabako', state_dir='/tmp/sunabako-cluster-test')
print(n.configure(memory_capacity_bytes=4<<30, memory_overcommit=2, max_sandboxes=16,
                  uid_start=65000, gpu_slots_per_device=2, proot_binary='/tmp/sunabako-tools/proot',
                  allow_unbounded_memory_for_tests=True))
PY
"$runtime_dir/bin/sunabako" doctor
