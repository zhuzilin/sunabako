# Release notes

## 0.1.2

- Add native asyncio RPCs, configurable creation timeouts, request-owned cancellation, and weighted node placement.
- Cache compressed OCI images on local disk with bounded imports, eviction, and parallel reflink clones.
- Remove node-wide lifecycle bottlenecks and support deferred rootfs cleanup.
- Reduce process-monitoring and PRoot PID-lookup overhead; enable PRoot seccomp acceleration and fix non-leader thread exec.
- Exercise async transport and cancellation regressions against installed wheels.

Upgrade the Python SDK and node runtime together. Rebuild the separately installed
PRoot binary with the updated patch to use its fixes.
