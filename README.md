# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current tree implements a capability-first kernel/service architecture with task-scoped authority, restartable native services, a content-addressed object store, local-first sync primitives, immutable-base state, measured-boot records, and task-first UX scaffolding.

## Spec Target

The repository now treats the Zigos v0.1 clean-slate OS spec as its explicit conformance target. The design goals, non-goals, implementation map, and example manifest now live in [SPEC.md](/home/cameronl/zigos/SPEC.md).

Repo-level conformance is checked in [src/zigos_spec_test.zig](/home/cameronl/zigos/src/zigos_spec_test.zig), with the section-to-test contract enforced by [spec/coverage.json](/home/cameronl/zigos/spec/coverage.json) and [tools/check_spec_coverage.py](/home/cameronl/zigos/tools/check_spec_coverage.py). Deeper subsystem coverage lives beside each native module under `src/kernel/process/native/`.

The native kernel surface is intentionally small:

- scheduling
- virtual memory
- IPC transport
- capability enforcement
- interrupts and timekeeping
- secure-boot handoff hooks
- IOMMU and DMA isolation hooks

Everything above that layer is modeled as a native service boundary under `src/kernel/process/native/`.

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

## Native Subsystems

- `src/kernel/process/native/abi.zig`: native task, capability, IPC, and service ABI
- `src/kernel/process/native/native_kernel.zig`: kernel-native task/capability/IPC/service operations
- `src/kernel/process/native/syscall_surface.zig`: freestanding typed syscall dispatch into the native kernel port
- `src/kernel/process/native/task_runtime_service.zig`: restartable task-runtime checkpoint and recovery wrapper
- `src/kernel/process/native/policy_mediation.zig`: zero-authority launch mediation and grants
- `src/kernel/process/native/object_store.zig`: content-addressed immutable object versions
- `src/kernel/process/native/workspace.zig`: transactional workspaces, snapshots, restore, export/import
- `src/kernel/process/native/sync_service.zig`: device graph, sync policy, and replication semantics
- `src/kernel/process/native/immutable_base.zig`: signed base-image state and rollback metadata
- `src/kernel/process/native/measured_boot.zig`: measured boot coverage records
- `src/kernel/process/native/recovery_environment.zig`: recovery flows for restore, repair, revoke, and rotate
- `src/kernel/process/native/compatibility_environment.zig`: explicit VM, container, emulation, and remote-session environments mediated through portals
- `src/kernel/process/native/native_ux.zig`: task-first UX flows

## Status

The repository no longer builds or ships the old POSIX-like shell, POSIX-style syscall ABI, or VFS/userland rootfs pipeline. Legacy support is modeled as explicit portal-mediated compatibility environments rather than host-integrated compatibility boot profiles. The freestanding kernel surface is the native typed syscall entry plus the native-only verification targets below:

- `./scripts/zig.sh build kernel`
- `./scripts/zig.sh build spec-conformance`
- `./scripts/zig.sh build host-tests`
- `./scripts/zig.sh build zigos-native-smoke-test`

Storage-volume persistence remains covered by host-side native tests through `src/kernel/process/native/storage_volume.zig`.
