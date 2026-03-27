# Architecture

Zigos is organized around a native-only kernel/service split.

## Core Layout

- `src/main.zig`: thin kernel entry/export surface
- `src/kernel/boot/entry.zig`: native boot sequencing
- `src/kernel/boot/profiles/zigos_native.zig`: only boot profile
- `src/kernel/process/native/`: native principals, capabilities, task runtime, mediation, services, storage, sync, recovery, and UX
- `src/kernel/net/link_port.zig`: low-level packet/device transport kept below higher-level native networking policy
- `build.zig`: native-only build graph
- `scripts/run-zigos-native-smoke.sh`: native cold-reboot smoke harness

## Native Boundaries

- Kernel TCB: scheduling, virtual memory, IPC transport, capability enforcement, interrupts/timekeeping, secure-boot handoff hooks, IOMMU/DMA isolation hooks
- Native task runtime: task ownership, component attachment, budgets, audit trail, zero-ambient-authority launch state
- Native mediation: manifest validation, permission review, policy grants, denials, lease enforcement
- Native services: network policy, storage/object authority, package/update, compositor/session, indexing/search, sync/replication, media/print helpers
- Native data model: immutable object versions plus transactional workspaces, snapshots, restore, delete recovery, export/import

## Key Modules

- `src/kernel/process/native/contract.zig`: kernel/service boundary catalog
- `src/kernel/process/native/service_contract.zig`: ordered native service contracts
- `src/kernel/process/native/native_kernel.zig`: task/capability/endpoint/shared-memory/service operations
- `src/kernel/process/native/component_port.zig`: typed component bridge used during bootstrap
- `src/kernel/process/native/storage_service.zig`: authoritative object/workspace service
- `src/kernel/process/native/file_bridge.zig`: derived, non-authoritative file-style view over workspace state
- `src/kernel/process/native/device_graph.zig`: user/device trust graph
- `src/kernel/process/native/network_policy.zig`: explicit egress policy objects
- `src/kernel/process/native/supervisor.zig`: crash/restart tracking for restartable services

## Verification

- `zig build kernel`: native kernel builds
- `zig build host-tests`: native subsystem tests pass
- `zig build zigos-native-smoke-test`: native bootstrap reaches the expected boot markers across two QEMU boots

The repository no longer treats shell-first execution, POSIX-like syscalls, VFS-rooted userland, or compatibility environments as part of the supported platform.
