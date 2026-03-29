# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current tree implements a capability-first kernel/service architecture with task-scoped authority, restartable native services, a content-addressed object store, local-first sync primitives, immutable-base state, measured-boot records, and task-first UX scaffolding.

## Spec Target

The repository now treats the Zigos v0.1 clean-slate OS spec as its explicit conformance target. The design goals, non-goals, implementation map, and example manifest now live in [SPEC.md](SPEC.md).

Repo-level conformance is checked through the thin root [`src/zigos_spec_test.zig`](src/zigos_spec_test.zig), which delegates to the suites under `src/tests/spec/`; the section-to-test contract is enforced by [`spec/coverage.json`](spec/coverage.json) and [`tools/check_spec_coverage.py`](tools/check_spec_coverage.py). Deeper subsystem coverage lives beside each native module under `src/native/`.

The native kernel surface is intentionally small:

- scheduling
- virtual memory
- IPC transport
- capability enforcement
- interrupts and timekeeping
- secure-boot handoff hooks
- IOMMU and DMA isolation hooks

Everything above that layer is modeled as a native service boundary under `src/native/`.

## Build And Test

```bash
# Build the native kernel
./scripts/zig.sh build kernel

# Run the native kernel in QEMU
./scripts/zig.sh build run

# Run native host-side tests
./scripts/zig.sh build host-tests

# Run the explicit spec coverage and conformance gate
./scripts/zig.sh build spec-conformance

# Run the native cold-reboot smoke test
./scripts/zig.sh build zigos-native-smoke-test

# Build a bootable ISO
./scripts/zig.sh build iso
```

`./scripts/zig.sh` is the repo entrypoint for the pinned Zig `0.15.2` toolchain. It prefers a matching active `zig`, then `mise`, then `ZIG_BIN`, and finally a repo-local fallback if one exists.

`./scripts/zig.sh build run` and `./scripts/zig.sh build run-zigos-native` attach `build/native-store.img` as the native storage image. `./scripts/zig.sh build zigos-native-smoke-test` uses `build/native-store-smoke.img` and validates the native bootstrap markers across two QEMU boots.

## Requirements

- Zig 0.15.2
- NASM
- QEMU
- For ISO builds: GRUB `mkrescue`, `xorriso`, and `mtools`

`build.zig` rejects any Zig version other than `0.15.2`, and the repo now includes both `.tool-versions` and `mise.toml` pins for local toolchain managers. Use `./scripts/zig.sh` for repo commands so the pinned toolchain resolution stays consistent across local shells, scripts, and CI.

Host-side native tests enter through `src/native_host_test.zig` and delegate to `src/tests/host/`. Deeper subsystem coverage lives beside each native module under `src/native/`.

## Repository Map

- `src/main.zig`: thin kernel entry and export surface
- `src/kernel/boot/profiles/zigos_native.zig`: only supported boot profile
- `src/native/`: native principals, capabilities, runtime, mediation, services, storage, sync, recovery, and UX
- `src/tests/`: organized host and spec test suites, with thin root entrypoints kept at `src/*.zig`
- `src/tools/`: Zig helper binaries that need to share the `src/` module root
- `src/kernel/net/`: low-level networking and device transport
- `build.zig`: native-only build graph
- `scripts/`: repo entrypoints for setup, build, run, and verification
- `tools/`: host-side support utilities such as spec coverage checks

## Status

The repository no longer builds or ships the old POSIX-like shell, POSIX-style syscall ABI, or VFS/userland rootfs pipeline. Legacy support is modeled as explicit portal-mediated compatibility environments rather than host-integrated compatibility boot profiles. The freestanding kernel surface is the native typed syscall entry plus the native-only verification targets below:

- `./scripts/zig.sh build kernel`
- `./scripts/zig.sh build spec-conformance`
- `./scripts/zig.sh build host-tests`
- `./scripts/zig.sh build zigos-native-smoke-test`

Storage-volume persistence remains covered by host-side native tests through `src/native/storage/storage_volume.zig`.
