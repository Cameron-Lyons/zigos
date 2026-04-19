# Architecture

Zigos is a native-only operating system prototype organized as a small freestanding kernel plus a restartable native service stack. The repository-level contract for that split is the Zigos v0.1 clean-slate spec in [SPEC.md](SPEC.md). This document maps that contract onto the current source tree and build/boot pipeline.

## Layered System

- `src/main.zig`: thin export surface that exposes `kernel_main` and the typed syscall handler
- `src/kernel/`: freestanding boot, memory, interrupt, timer, device, and low-level networking code
- `src/native/kernel_api/`: typed kernel boundary for tasks, capabilities, endpoints, services, shared memory, and device access
- `src/native/session/`: principal assignment, supervisor state, session manager boot flow, and ordered service bootstrap
- `src/native/task/`: task/runtime model plus userspace image registry, loader, launch, scheduler, and bootstrap mailbox support
- `src/userspace/`: shared freestanding runtime and linker script used by every embedded userspace image
- `src/native/policy/`, `src/native/platform/`, `src/native/services/`, `src/native/storage/`, `src/native/sync/`, `src/native/drivers/`: the native service and platform layers above the kernel boundary
- `src/native/demo/`: seeded packages, scenario-world orchestration, permission flows, and transport demos used by spec-aligned stories
- `src/tests/host/` and `src/tests/spec/`: host-side native tests plus spec-conformance suites
- `build_support/`: build helpers for kernel and userspace artifacts
- `tools/`: host-side support utilities such as spec coverage checks

## Build and Boot Path

1. `build_support/userspace.zig` compiles every image declared in `src/native/task/userspace_registry.zig`, generates a `userspace_archive` module, and feeds that archive into the kernel build.
2. `src/kernel/boot/entry.zig` performs freestanding bring-up and enters the selected boot profile:
   - `src/kernel/boot/profiles/zigos_native.zig` for the main native system
   - `src/kernel/boot/profiles/benchmark.zig` for benchmark runs
3. `src/native/session/session_bootstrap.zig` assigns the built-in principals, preloads the userspace catalog through `src/native/task/userspace_boot_registry.zig`, initializes the userspace scheduler, and registers the core service records with the supervisor.
4. `src/native/session/session_manager_boot_flow.zig` constructs the long-lived system state: capability table, endpoint table, task runtime, service registry, shared memory table, driver directory/runtime, event ledger, background dispatch, storage checkpoint state, and sync resident state.
5. `src/native/session/phase3_bootstrap.zig` launches the ordered contract services declared in `src/native/session/service_contract.zig`, binds their interfaces into `src/native/kernel_api/service_registry.zig`, and attaches driver authority for device-backed services.
6. `src/userspace/runtime.zig` is the common runtime for every userspace image: it validates the embedded descriptor, reads the bootstrap mailbox, performs initial typed queries, publishes heartbeat or fault state, and then enters steady-state execution.

## Kernel Boundary

The freestanding kernel remains intentionally small. Its trusted computing base is modeled by `src/native/session/contract.zig` and centers on:

- scheduling
- virtual memory
- IPC transport
- capability table enforcement
- interrupts and timekeeping
- secure-boot handoff hooks
- IOMMU and DMA isolation hooks

Everything above that layer is mediated through typed native interfaces:

- `src/native/kernel_api/native_kernel.zig`: authoritative implementation of task, capability, endpoint, shared-memory, service, and device operations
- `src/native/kernel_api/component_port.zig`: in-process typed request/response boundary used by bootstrap code and host tests
- `src/native/kernel_api/syscall_surface.zig`: freestanding syscall dispatcher that validates the request header, subject task, ABI version, and response sizing before calling the same kernel API
- `src/main.zig`: wires the architecture trap handler into `syscall_surface.dispatch`, so freestanding userspace goes through the same typed authority checks as in-process callers

The repository no longer treats POSIX-style syscalls, shell-first execution, or a VFS-rooted userland as part of the native platform.

## Native Service Model

- `src/native/session/contract.zig`: service classes, boundaries, restart policy, and isolation profiles
- `src/native/session/supervisor.zig`: service registration, isolation-domain tracking, crash diagnostics, restart requests, and contract/driver binding events
- `src/native/task/task_runtime.zig` and `src/native/task/task_runtime_service.zig`: task ownership, explicit resource budgets, attached components, checkpoints, and restart recovery
- `src/native/task/userspace_loader.zig`, `src/native/task/userspace_launch.zig`, and `src/native/task/userspace_manifest_signing.zig`: signed bundle registration, embedded ELF metadata, and zero-ambient-authority launch state
- `src/native/drivers/driver_service.zig`: device-class-scoped driver authority, IOMMU-backed DMA ranges, and restart-generation tracking
- `src/native/policy/manifest.zig`, `src/native/policy/policy_mediation.zig`, `src/native/policy/permission_review*.zig`, and `src/native/policy/denial_explanation.zig`: manifest validation, mediation, permission review, and explainable denials
- `src/native/storage/`: content-addressed object versions, transactional workspaces, snapshots, export/import, delete recovery, persistent volume state, and the non-authoritative file bridge
- `src/native/sync/`: device graph, sync state, replication service state, and explicit network policy objects
- `src/native/platform/`: immutable base state, measured boot, attestation, update health, secure secret storage, event ledger, compositor session, and native UX control
- `src/native/services/`: package install/update, indexing/search, notifications, compatibility portal, and media/print helper services

## Userspace Image Model

Userspace images are declared statically in `src/native/task/userspace_registry.zig`. That registry currently covers:

- system bundles such as the session manager, permission review surface, policy mediation, network, storage, package, compositor, indexing, sync, media/print, and compatibility services
- driver-facing bundles such as the storage driver artifact
- demo or app-facing bundles such as `app.viewer`, `app.notes`, `app.sync`, and `app.capture`

Each image carries typed metadata: bundle id, publisher, initial component, role tag, heartbeat increment, contract flags, provided and consumed interfaces, and signature state. `src/native/task/userspace_boot_registry.zig` loads those definitions into the runtime catalog, while `src/userspace/runtime.zig` gives every embedded image the same bootstrap mailbox and syscall/query conventions.

## Verification

The repository keeps architecture and spec claims tied to explicit verification entrypoints:

- `./scripts/zig.sh build kernel`: build the main native kernel
- `./scripts/zig.sh build kernel-zigos-native`: build the primary native bootstrap kernel
- `./scripts/zig.sh build kernel-benchmark`: build the benchmark kernel profile
- `./scripts/zig.sh build host-tests`: run the thin `src/native_host_test.zig` root over `src/tests/host/`
- `./scripts/zig.sh build spec-tests`: run `spec/coverage.json`, `tools/check_spec_coverage.py`, and the thin `src/zigos_spec_test.zig` root over `src/tests/spec/`
- `./scripts/zig.sh build spec-conformance`: `spec-tests` plus the freestanding native smoke path
- `./scripts/zig.sh build zigos-native-smoke-test`: two-boot QEMU smoke verification through `scripts/run-zigos-native-smoke.sh`
- `./scripts/zig.sh build benchmark`: spec-aligned benchmark execution through `scripts/run-kernel-benchmark.sh`
- `./scripts/zig.sh build iso`: bootable ISO generation through `scripts/build-grub-iso.sh`

Architecture claims in this repository should map back either to a concrete implementation boundary in the files above or to a spec requirement covered by the `spec-tests` and `spec-conformance` gates.
