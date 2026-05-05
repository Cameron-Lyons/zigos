# Zigos Spec Gap Matrix

Generated baseline: 2026-04-29

This matrix tracks how the implementation maps to the v0.1 requirements in
`SPEC.md`. It is not a replacement for `spec/coverage.json`; that file remains
the executable coverage manifest. This document is the engineering backlog view:
what is implemented, what is model-only, and where the next hardening work should
land.

## Verification Baseline

Current baseline commands:

```sh
./scripts/zig.sh build host-tests
./scripts/zig.sh build spec-conformance
./scripts/zig.sh build zigos-native-smoke-test
```

Result on 2026-04-29:

- `host-tests`: passed
- `spec-conformance`: passed, including spec coverage and cold-reboot smoke
- `zigos-native-smoke-test`: passed across cold reboot

`spec-tests` reports 77 headings, 61 requirements, 20 section groups, and 104
test references.

## Status Legend

- **Enforced**: the invariant is implemented in native code and exercised by
  focused tests or adversarial tests.
- **Modeled**: first-class implementation exists, but part of the requirement is
  still represented by prototype state, synthetic hardware, or scenario-level
  tests.
- **Scenario**: behavior is primarily demonstrated through scenario flows or
  rendered UX/control-plane records.
- **Deferred**: the requirement is mostly a design claim or future integration
  point.

## Requirement Matrix

| Requirement | Status | Implementation anchors | Next hardening move |
| --- | --- | --- | --- |
| `REQ-DESIGN-GOALS-AND-NON-GOALS` | Enforced | `tools/check_spec_coverage.py`, `src/native/policy/policy_mediation.zig`, `src/native/platform/immutable_base.zig`, `src/native/sync/sync_service_impl.zig`, `src/native/services/compatibility_environment.zig` | The coverage checker keeps broad design goals dependent on concrete enforced subsystem requirements. |
| `REQ-ZERO-AMBIENT-AUTHORITY` | Enforced | `src/native/task/task_runtime.zig`, `src/native/policy/policy_mediation.zig`, `src/native/kernel_api/native_kernel.zig` | Add more negative tests for newly added service operations. |
| `REQ-IMMUTABLE-BASE-SYSTEM` | Enforced | `src/native/platform/immutable_base.zig`, `src/native/platform/update_health.zig` | Wire real bootloader/kernel artifact digests into staged image callers and QEMU smoke verification. |
| `REQ-USERSPACE-SERVICES-BY-DEFAULT` | Enforced | `src/native/session/service_catalog.zig`, `src/native/session/contract.zig`, `src/native/drivers/driver_service.zig`, `src/kernel/net/ethernet.zig`, `src/kernel/net/link_port.zig`, `src/kernel/drivers/ata.zig`, `src/kernel/boot/init/devices.zig` | Kernel device/network code is marked as bootstrap shims and guarded against full service logic below typed contracts. |
| `REQ-DATA-IS-VERSIONED` | Enforced | `src/native/storage/object_store.zig`, `src/native/storage/workspace.zig`, `src/native/storage/storage_service.zig` | Expand corruption/replay tests around workspace history and snapshot import. |
| `REQ-PLATFORM-APIS-OVER-SYSTEM-INTERNALS` | Enforced | `src/native/core/abi.zig`, `src/native/kernel_api/syscall_surface.zig`, `src/native/services/service_registry.zig` | Keep expanding typed contracts as new platform services are added; reject new internal or unversioned bypass surfaces. |
| `REQ-PRINCIPAL-MODEL` | Enforced | `src/native/core/principal.zig`, `src/native/core/signing.zig`, `src/native/sync/device_graph.zig` | Add policy conflict tests across user, device, app, service, and organization principals. |
| `REQ-CAPABILITY-MODEL` | Enforced | `src/native/kernel_api/capability.zig`, `src/native/kernel_api/native_kernel.zig` | Continue adding operation-specific denial tests as syscall/service surface grows. |
| `REQ-OBJECT-MODEL` | Enforced | `src/native/storage/object_store.zig` | Add larger object/chunk replication tests once transport grows beyond the in-memory model. |
| `REQ-WORKSPACE-MODEL` | Enforced | `src/native/storage/workspace.zig`, `src/native/storage/storage_service.zig` | Add branch/merge conflict tests beyond restore and sharing. |
| `REQ-TASK-MODEL` | Enforced | `src/native/task/task_runtime_model.zig`, `src/native/task/task_runtime_service.zig` | Tie task audit trails into more service operations by default. |
| `REQ-KERNEL-TYPE-AND-BOUNDARY` | Enforced | `src/native/session/contract.zig`, `src/native/kernel_api/native_kernel.zig`, `src/native/kernel_api/syscall_surface.zig`, `src/native/session/service_catalog.zig`, `src/kernel/net/ethernet.zig`, `src/kernel/net/link_port.zig`, `src/kernel/drivers/ata.zig`, `src/kernel/boot/init/devices.zig` | Keep the static bootstrap-shim gate current as low-level hardware plumbing grows. |
| `REQ-KERNEL-REQUIREMENTS` | Enforced | `src/native/kernel_api/syscall_surface.zig`, `src/native/kernel_api/endpoint.zig`, `src/native/kernel_api/shared_memory.zig`, `src/native/kernel_api/native_kernel.zig` | Add more QEMU-backed MMU fault evidence around the enforced syscall and shared-memory contracts. |
| `REQ-PRIVILEGE-MODEL` | Enforced | `src/native/policy/policy_object.zig`, `src/native/platform/recovery_environment.zig`, `src/native/platform/event_ledger.zig` | Bind more privileged service operations to policy-object decisions and event-ledger audit records. |
| `REQ-BOOT-CHAIN` | Enforced | `src/native/platform/measured_boot.zig`, `src/native/session/session_manager_boot_flow.zig`, `scripts/run-zigos-native-smoke.sh` | Native smoke hashes bootloader, kernel, userspace service artifacts, policy set, base image, and driver set, then compares measured roots across cold reboot. |
| `REQ-MEASURED-STATE` | Enforced | `src/native/platform/measured_boot.zig`, `src/native/platform/attestation_service.zig` | Wire persisted measurement comparison into the QEMU cold-reboot smoke markers. |
| `REQ-RECOVERY-MODE` | Enforced | `src/native/platform/recovery_environment.zig` | Wire the recovery entry profile into the native boot selector and QEMU smoke markers. |
| `REQ-APP-PACKAGING` | Enforced | `src/native/policy/manifest.zig`, `src/native/services/package_service.zig`, `src/native/task/userspace_manifest_signing.zig` | Add package repository trust rotation and revoked publisher tests. |
| `REQ-APP-EXECUTION` | Enforced | `src/native/task/task_runtime.zig`, `src/native/task/userspace_launch.zig`, `src/native/task/userspace_executor.zig`, `src/native/session/runtime_negative_proofs.zig` | Keep host and freestanding MMU/syscall bypass proofs in the native smoke path. |
| `REQ-COMPONENT-MODEL` | Enforced | `src/native/task/userspace_descriptor.zig`, `src/native/task/userspace_contract_registry.zig`, `src/native/services/service_registry.zig`, `src/native/services/typed_component_abi.zig` | Keep versioned request/response contracts under the component ABI backlog gate. |
| `REQ-BACKGROUND-EXECUTION` | Enforced | `src/native/policy/manifest.zig`, `src/native/task/background_dispatch.zig` | Add expiration and abuse tests that cross task restart boundaries. |
| `REQ-CAPABILITY-BASED-ACCESS-CONTROL` | Enforced | `src/native/kernel_api/capability.zig`, `src/native/kernel_api/native_kernel_access.zig` | Require new protected services to accept capability ids, not raw names. |
| `REQ-PERMISSION-GRANTS` | Enforced | `src/native/policy/permission_review.zig`, `src/native/policy/permission_review_service.zig`, `src/native/policy/policy_mediation.zig`, `src/native/platform/event_ledger.zig` | Add cross-device revocation propagation tests once sync transport leaves the deterministic queue. |
| `REQ-DATA-EGRESS-CONTROL` | Enforced | `src/native/sync/network_policy.zig`, `src/native/sync/sync_service_impl.zig` | Route real packet transmit paths through the egress broker. |
| `REQ-PROCESS-ISOLATION` | Enforced | `src/native/task/task_runtime_model.zig`, `src/native/task/userspace_executor.zig`, `src/native/kernel_api/syscall_surface.zig`, `src/native/session/runtime_negative_proofs.zig` | Keep cross-memory, subject-spoofing, and raw-network bypass proofs under the isolation backlog gate. |
| `REQ-SECRETS` | Enforced | `src/native/platform/secure_secret_store.zig` | Bind the hardware seal provider to platform-specific secure-enclave hooks on targets that expose them. |
| `REQ-OBJECT-STORE` | Enforced | `src/native/storage/object_store.zig`, `src/native/storage/storage_volume.zig` | Increase persistence tests for dedup, integrity, and partial-write recovery. |
| `REQ-MUTABLE-STATE` | Enforced | `src/native/storage/workspace.zig`, `src/native/storage/storage_service.zig`, `src/native/sync/sync_adapters.zig` | Persist document operation logs and vector-clock metadata beyond the deterministic adapter harness. |
| `REQ-FILE-BRIDGE` | Enforced | `src/native/storage/file_bridge.zig` | Add end-to-end tests from app capability to file-view export/import. |
| `REQ-SNAPSHOTS-AND-RECOVERY` | Enforced | `src/native/storage/workspace.zig`, `src/native/platform/recovery_environment.zig` | Add signed snapshot replay/downgrade adversarial tests. |
| `REQ-DEVICE-GRAPH` | Enforced | `src/native/sync/device_graph.zig` | Add multi-user/team trust graph conflict tests. |
| `REQ-LOCAL-FIRST-REPLICATION` | Enforced | `src/native/sync/sync_service_impl.zig`, `src/native/sync/sync_state_store.zig`, `src/native/sync/sync_adapters.zig`, `src/native/sync/sync_transport_harness.zig` | Encrypted relay delivery now carries operation-log frames through the transport harness; keep production sync sends moving toward that path. |
| `REQ-SYNC-SEMANTICS` | Enforced | `src/native/sync/sync_state_support.zig`, `src/native/sync/sync_service_impl.zig`, `src/native/sync/sync_adapters.zig` | Mergeable documents now use idempotent operation logs with vector-clock summaries under the sync adapter depth gate. |
| `REQ-SHARING` | Enforced | `src/native/storage/workspace.zig`, `src/tests/spec/experience_and_policy_edges.zig` | Add sharing audit persistence and revocation propagation tests. |
| `REQ-IDENTITY-FIRST-NETWORKING` | Enforced | `src/native/sync/network_policy.zig`, `src/native/platform/attestation_service.zig`, `src/native/sync/sync_transport_harness.zig` | Expand pinned identity coverage across relay and private-service overlay connection paths. |
| `REQ-NETWORK-PERMISSIONS` | Enforced | `src/native/sync/network_policy.zig`, `src/native/sync/sync_service_impl.zig` | Add denial tests at every network-facing service boundary. |
| `REQ-PRIVATE-OVERLAY` | Enforced | `src/native/sync/sync_service_impl.zig`, `src/native/sync/sync_transport_harness.zig`, `src/native/sync/network_policy.zig` | Keep broker-approved encrypted relay transport and destination mismatch rejection under the network transport gate. |
| `REQ-TASK-FIRST-UX` | Enforced | `src/native/platform/native_ux.zig`, `src/native/platform/compositor_session.zig`, `src/native/platform/event_ledger.zig` | Keep durable task timelines and redacted permission decisions under the UX rendering backlog gate. |
| `REQ-WINDOWS-AND-VIEWS` | Enforced | `src/native/platform/compositor_session.zig` | Keep deterministic compositor review/window output under the UX rendering backlog gate. |
| `REQ-PERMISSION-UX` | Enforced | `src/native/policy/permission_review.zig`, `src/native/policy/permission_review_service.zig`, `src/native/platform/compositor_session.zig`, `src/native/platform/event_ledger.zig` | Connect the persisted permission timeline to a deterministic renderer once the compositor grows beyond records. |
| `REQ-NOTIFICATIONS` | Enforced | `src/native/services/notification_center.zig` | Add spam/suppression tests under repeated app abuse. |
| `REQ-UNIFIED-RESOURCE-SCHEDULER` | Enforced | `src/native/task/accelerator_scheduler.zig`, `src/native/task/userspace_scheduler.zig`, `src/native/task/task_runtime_model.zig` | Feed real CPU accounting and hardware availability signals into the existing policy controller. |
| `REQ-SHARED-MEMORY-OBJECTS` | Enforced | `src/native/kernel_api/shared_memory.zig`, `src/native/task/accelerator_scheduler.zig` | Add revocation tests while accelerator claims are active. |
| `REQ-THERMAL-AND-POWER-POLICY` | Enforced | `src/native/task/accelerator_scheduler.zig`, `src/native/task/task_runtime_model.zig` | Bind thermal and battery degradation decisions to live platform telemetry. |
| `REQ-USERSPACE-DRIVERS` | Enforced | `src/native/drivers/driver_service.zig`, `src/native/drivers/driver_runtime.zig`, `src/native/session/session_service_bootstrap.zig`, `src/native/drivers/bootstrap_driver_port.zig`, `src/kernel/net/ethernet.zig`, `src/kernel/net/link_port.zig`, `src/kernel/drivers/ata.zig`, `src/kernel/boot/init/devices.zig` | Kernel-published transport exceptions are constrained by driver-boundary and bootstrap-shim gates. |
| `REQ-DRIVER-PERMISSIONS` | Enforced | `src/native/drivers/driver_service.zig` | Keep IOMMU-scoped DMA and authority rejection under the driver boundary backlog gate. |
| `REQ-DRIVER-HOT-SWAP-AND-FAILURE-RECOVERY` | Enforced | `src/native/session/supervisor.zig`, `src/native/drivers/driver_service.zig`, `src/native/platform/event_ledger.zig` | Add device hot-unplug/replug scenarios across reboot. |
| `REQ-BASE-OS-UPDATES` | Enforced | `src/native/platform/immutable_base.zig`, `src/native/platform/update_health.zig`, `src/native/platform/measured_boot.zig`, `src/native/session/session_manager_boot_flow.zig` | Tie staged images to real kernel/base-image artifacts. |
| `REQ-HEALTH-CHECKS` | Enforced | `src/native/platform/update_health.zig`, `src/tests/spec/boot_recovery.zig` | Add post-rollback persistence checks across the QEMU smoke path. |
| `REQ-APP-UPDATES` | Enforced | `src/native/services/package_service.zig` | Add data migration failure rollback and compatibility-matrix tests. |
| `REQ-STRUCTURED-EVENT-LEDGER` | Enforced | `src/native/platform/event_ledger.zig` | Expand event schemas for new services before adding free-form logs. |
| `REQ-EXPLAINABLE-DENIALS` | Enforced | `src/native/policy/denial_explanation.zig`, `src/native/platform/event_ledger.zig` | Require every new denial enum to render policy, missing capability, approval, and retry fields. |
| `REQ-PRIVACY-PRESERVING-DIAGNOSTICS` | Enforced | `src/native/platform/event_ledger.zig` | Require redaction and remote-share opt-in assertions for every new diagnostic event kind. |
| `REQ-POLICY-OBJECTS` | Enforced | `src/native/policy/policy_object.zig` | Wire composite policy decisions into more service enforcement paths. |
| `REQ-POLICY-EXAMPLES` | Enforced | `src/native/policy/policy_object.zig`, `src/tests/spec/ux_and_lifecycle.zig` | Add removable-storage and screen-capture denial flows at service boundaries. |
| `REQ-ENTERPRISE-SUPPORT` | Enforced | `src/native/policy/policy_object.zig` | Add persistence/import tests for organization policy updates and stale-generation rejection. |
| `REQ-NATIVE-PLATFORM` | Enforced | `src/native/services/compatibility_environment.zig`, `src/native/services/service_registry.zig` | Keep POSIX-like affordances isolated to explicit compatibility environments and reject native API registrations that look like legacy internals. |
| `REQ-LEGACY-SUPPORT` | Enforced | `src/native/services/compatibility_environment.zig` | Add portal-specific capability mediation tests for VM/container/emulation modes. |
| `REQ-EXAMPLE-APPLICATION-MANIFEST` | Enforced | `src/native/policy/manifest.zig`, `src/native/demo/bootstrap_packages.zig` | Add parser/import tests if external manifest files become supported. |
| `REQ-ZIGOS-USER-EXPERIENCE` | Enforced | `src/native/demo/scenario_world.zig`, `src/native/demo/permission_flows.zig`, `src/native/platform/native_ux.zig` | Keep scenario expectations backed by durable renderer and ledger gates. |
| `REQ-ONE-SENTENCE-SUMMARY` | Enforced | `tools/check_spec_coverage.py`, `src/native/kernel_api/capability.zig`, `src/native/sync/sync_service_impl.zig`, `src/native/platform/immutable_base.zig`, `src/native/task/task_runtime_model.zig`, `src/native/task/accelerator_scheduler.zig` | The summary is now a meta-contract over the concrete enforced requirements it compresses. |

## Executable Backlog Gates

| Priority | Gate | Enforcement |
| --- | --- | --- |
| Hardware-backed boot trust | Backlog | Keep modeled until backed by target hardware or QEMU root-of-trust evidence. |
| Isolation proof depth | `backlog gate enforces isolation proof depth` | `src/tests/spec/backlog_gates.zig` runs freestanding negative proofs for cross-memory, syscall spoofing, and raw-network bypasses. |
| Network transport hardening | `backlog gate enforces network transport hardening` | `src/tests/spec/backlog_gates.zig` requires broker-approved encrypted relay transport and rejects destination mismatch. |
| Component ABI depth | `backlog gate enforces component ABI depth` | `src/native/services/typed_component_abi.zig` and `src/tests/spec/backlog_gates.zig` enforce versioned request/response contracts and reject zero-subject or malformed messages. |
| Sync adapter depth | `backlog gate enforces sync adapter depth` | Idempotent document operation logs, vector-clock summaries, and deterministic replay are enforced in `src/tests/spec/backlog_gates.zig`. |
| Driver boundary audit | `backlog gate enforces driver boundary audit`, `backlog gate enforces kernel bootstrap shim boundary` | `src/tests/spec/backlog_gates.zig` checks IOMMU-scoped DMA, rejects kernel-published data-plane transport outside supported bootstrap contracts, and statically guards kernel net/storage shims against service logic. |
| Policy persistence | Backlog | Add import/update tests for organization policy generations and stale policy rejection. |
| UX rendering | `backlog gate enforces UX rendering` | `src/tests/spec/backlog_gates.zig` connects compositor review rendering to redacted durable ledger records. |

## Maintenance Rules

- When `SPEC.md` gains or changes a `REQ-*`, update `spec/coverage.json` and
  this file in the same change.
- New protected operations must start denied by default and require a capability
  or signed policy object at the service boundary.
- Scenario tests are useful for product shape, but invariants belong in the
  subsystem that enforces them and should have focused host/adversarial tests.
- Claims about hardware roots, accelerators, and network transport should stay
  marked **Modeled** until backed by real boot, device, or QEMU evidence.
