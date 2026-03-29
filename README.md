# Zigos

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Zigos is a native-only operating system prototype written in Zig. The current tree implements a capability-first kernel/service architecture with task-scoped authority, restartable native services, a content-addressed object store, local-first sync primitives, immutable-base state, measured-boot records, and task-first UX scaffolding.

## Spec Target

The repository now treats the Zigos v0.1 clean-slate OS spec as its explicit conformance target. The design goals, non-goals, implementation map, and example manifest now live in [SPEC.md](/home/cameronl/zigos/SPEC.md).

Repo-level conformance is checked in [src/zigos_spec_test.zig](/home/cameronl/zigos/src/zigos_spec_test.zig), with deeper subsystem coverage living beside each native module under `src/kernel/process/native/`.

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
zig build kernel

# Run the native kernel in QEMU
zig build run

# Run native host-side tests
zig build host-tests

# Run the native cold-reboot smoke test
zig build zigos-native-smoke-test

# Build a bootable ISO
zig build iso
```

`zig build run` and `zig build run-zigos-native` attach `build/native-store.img` as the native storage image. `zig build zigos-native-smoke-test` uses `build/native-store-smoke.img` and validates the native bootstrap markers across two QEMU boots.

## Requirements

- Zig compiler
- NASM
- QEMU
- For ISO builds: GRUB `mkrescue`, `xorriso`, and `mtools`

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

- `zig build kernel`
- `zig build host-tests`
- `zig build zigos-native-smoke-test`

Storage-volume persistence remains covered by host-side native tests through `src/kernel/process/native/storage_volume.zig`.
