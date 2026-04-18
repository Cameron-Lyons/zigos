# Architecture

Zigos is organized around a native-only kernel/service split.

The repository-level contract for that split is the Zigos v0.1 clean-slate spec described in [SPEC.md](/home/cameronl/zigos/SPEC.md). This file focuses on how that spec maps onto the current code layout.

## Core Layout

- `src/main.zig`: thin kernel entry/export surface
- `src/kernel/boot/entry.zig`: native boot sequencing
- `src/kernel/boot/profiles/zigos_native.zig`: only boot profile
- `src/native/`: native principals, capabilities, task runtime, mediation, services, storage, sync, recovery, and UX
- `src/native/demo/`: seeded bundle manifests plus explicit scenario-world/demo flows used to exercise spec stories
- `src/native/kernel_api/syscall_surface.zig`: typed freestanding syscall entry for native kernel operations
- `src/kernel/net/link_port.zig`: low-level packet/device transport kept below higher-level native networking policy
- `build.zig`: native-only build graph
- `scripts/run-zigos-native-smoke.sh`: native cold-reboot smoke harness

## Native Boundaries

- Kernel TCB: scheduling, virtual memory, IPC transport, capability enforcement, interrupts/timekeeping, secure-boot handoff hooks, IOMMU/DMA isolation hooks
- Native task runtime service: task ownership, component attachment, budgets, audit trail, zero-ambient-authority launch state, and checkpointed restart recovery
- Native syscall entry: typed `int 0x80` dispatch into the native kernel port, with explicit request buffers and typed responses
- Native mediation: manifest validation, permission review, policy grants, denials, lease enforcement
- Native services: network policy, storage/object authority, package/update, compositor/session, indexing/search, sync/replication, media/print helpers, compatibility portals
- Native data model: immutable object versions plus transactional workspaces, snapshots, restore, delete recovery, export/import

## Spec Mapping

- Principals, capabilities, objects, workspaces, and tasks live under `src/native/` as first-class types rather than POSIX-like process and path abstractions.
- Zero-ambient-authority launch and permission mediation are enforced by `task_runtime.zig`, `capability.zig`, `manifest.zig`, `permission_review*.zig`, and `policy_mediation.zig`.
- Immutable base images, measured boot, attestation, and rollback are modeled by `immutable_base.zig`, `measured_boot.zig`, `attestation_service.zig`, and `recovery_environment.zig`.
- Local-first multi-device sync and explicit networking are modeled by `device_graph.zig`, `sync_service.zig`, and `network_policy.zig`.
- Explainable denials, structured notifications, and privacy-preserving diagnostics are modeled by `denial_explanation.zig`, `notification_center.zig`, `event_ledger.zig`, and `supervisor.zig`.
- Native compatibility is explicit and isolated through `compatibility_environment.zig`; the repo does not treat legacy APIs as part of the native platform.

## Key Modules

- `src/native/session/contract.zig`: kernel/service boundary catalog
- `src/native/session/service_contract.zig`: ordered native service contracts
- `src/native/kernel_api/native_kernel.zig`: task/capability/endpoint/shared-memory/service operations
- `src/native/kernel_api/component_port.zig`: typed component bridge used during bootstrap
- `src/native/task/task_runtime_service.zig`: restartable wrapper around the native task catalog
- `src/native/storage/storage_service.zig`: authoritative object/workspace service
- `src/native/storage/file_bridge.zig`: derived, non-authoritative file-style view over workspace state
- `src/native/sync/device_graph.zig`: user/device trust graph
- `src/native/sync/network_policy.zig`: explicit egress policy objects
- `src/native/services/compatibility_environment.zig`: isolated VM/container/emulation/remote-session environments with portal-only host access
- `src/native/session/supervisor.zig`: crash/restart tracking for restartable services
- `src/native/demo/scenario_world.zig`: explicit scenario-world/demo orchestration kept outside the core session manager

## Verification

- `./scripts/zig.sh build spec-tests`: the `SPEC.md` heading set, section claims, and mapped host-side test anchors remain in sync
- `./scripts/zig.sh build spec-conformance`: `spec-tests` plus freestanding smoke verification
- `./scripts/zig.sh build kernel`: native kernel builds
- `./scripts/zig.sh build host-tests`: the explicit `src/native_host_test.zig` root delegates to the host suites under `src/tests/host/` without rediscovering files at runtime
- `./scripts/zig.sh build zigos-native-smoke-test`: native bootstrap reaches the expected boot markers across two QEMU boots
- `./scripts/zig.sh build benchmark`: native spec-aligned service-path benchmarks stay rebuildable and gated in QEMU

The repository no longer treats shell-first execution, POSIX-like syscalls, or VFS-rooted userland as part of the supported platform. Legacy support is modeled explicitly through isolated compatibility environments with portal-mediated host access. The remaining freestanding entry surface is the native typed syscall dispatcher.
