# Zigos Spec Target

This repository treats the "Hypothetical clean-slate operating system spec, v0.1" as its native platform contract.

The tree is still a prototype, but the implementation and test suite are organized around the same constraints:

- secure by default
- no ambient authority
- local-first, multi-device operation
- atomic, reversible system updates
- strong app isolation
- memory-safe implementation wherever possible
- first-class support for modern accelerators
- data-centric permissions and sharing
- explainable behavior and recoverability
- no backward-compatibility constraints in the native platform

## Non-Goals

The native platform intentionally does not target:

- POSIX compatibility
- unrestricted root or admin execution
- global writable system state
- arbitrary third-party kernel extensions
- app installation via opaque scripts
- files and paths as the only user-facing storage model

## Native Model

The repository models the v0.1 primitives directly:

- `Principal`: `src/kernel/process/native/principal.zig`, `src/kernel/process/native/device_graph.zig`
- `Capability`: `src/kernel/process/native/capability.zig`
- `Object`: `src/kernel/process/native/object_store.zig`
- `Workspace`: `src/kernel/process/native/workspace.zig`
- `Task`: `src/kernel/process/native/task_runtime.zig`

The kernel-side trusted computing base stays limited to scheduling, virtual memory, IPC transport, capability enforcement, interrupts and timekeeping, secure-boot handoff, and IOMMU or DMA isolation hooks. Everything else is modeled as a restartable typed native service.

## Spec-To-Code Map

| Spec area | Primary modules | Primary verification |
| --- | --- | --- |
| Zero ambient authority and explicit grants | `policy_mediation.zig`, `capability.zig`, `task_runtime.zig` | `src/zigos_spec_test.zig`, `policy_mediation.zig` tests |
| Immutable base, measured boot, rollback | `immutable_base.zig`, `measured_boot.zig`, `attestation_service.zig` | `src/zigos_spec_test.zig`, module tests |
| Typed userspace services and minimal kernel ABI | `contract.zig`, `native_kernel.zig`, `component_port.zig`, `syscall_surface.zig`, `userspace_loader.zig` | `src/zigos_spec_test.zig`, module tests |
| Versioned object storage and derived file bridge | `object_store.zig`, `workspace.zig`, `storage_service.zig`, `file_bridge.zig` | `src/zigos_spec_test.zig`, module tests |
| Local-first sync and trusted device graph | `sync_service.zig`, `device_graph.zig`, `network_policy.zig` | `src/zigos_spec_test.zig`, module tests |
| Recovery, explainability, and diagnostics | `recovery_environment.zig`, `denial_explanation.zig`, `event_ledger.zig`, `supervisor.zig` | `src/zigos_spec_test.zig`, module tests |
| Task-first UX and structured notifications | `native_ux.zig`, `notification_center.zig`, `media_print_service.zig` | `src/zigos_spec_test.zig`, module tests |
| Declarative packages and scoped policy | `manifest.zig`, `package_service.zig`, `policy_object.zig` | `src/zigos_spec_test.zig`, module tests |
| Modern accelerator scheduling and shared memory | `accelerator_scheduler.zig`, `shared_memory.zig` | `src/zigos_spec_test.zig`, module tests |
| Isolated legacy compatibility environments | `compatibility_environment.zig` | `src/zigos_spec_test.zig`, module tests |

## Verification

The repo-level conformance target is captured in `src/zigos_spec_test.zig`. The broader native subsystem checks live beside each module under `src/kernel/process/native/`.

Useful verification commands:

```bash
zig build kernel
zig build host-tests
zig build zigos-native-smoke-test
```

## Example Manifest

The v0.1 application model is intentionally declarative:

```yaml
app:
  id: com.example.writer
  version: 1.4.0
  publisher: Example Software

interfaces:
  provides:
    - writer.edit/v1
  consumes:
    - documents.open/v1
    - export.pdf/v1

permissions:
  workspace:
    - id: workspace://report-alpha
      access: read-write

  network:
    - service: sync.example.com
      access: outbound
      purpose: document-sync

  devices:
    microphone: none
    camera: none
    location: none

  background:
    - trigger: sync-complete
      max_duration_seconds: 30
```

The native platform deliberately avoids the older model of ambient installer authority, global folder access, and unrestricted socket access.
