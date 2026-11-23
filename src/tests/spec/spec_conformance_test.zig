const std = @import("std");
const adversarial_security = @import("adversarial_security.zig");
const architecture_security = @import("architecture_security.zig");
const backlog_gates = @import("backlog_gates.zig");
const boot_recovery = @import("boot_recovery.zig");
const drivers_storage_sync = @import("drivers_storage_sync.zig");
const experience_and_policy_edges = @import("experience_and_policy_edges.zig");
const platform_services = @import("platform_services.zig");
const runtime_negative_proofs = @import("../../native/session/proofs/runtime_negative_proofs.zig");
const service_path_proofs = @import("../../native/session/proofs/service_path_proofs.zig");
const sync_service_test = @import("../../native/sync/sync_service_test.zig");
const ux_and_lifecycle = @import("ux_and_lifecycle.zig");

comptime {
    _ = sync_service_test;
}

test "spec 1 keeps installs declarative privilege explicit and app components typed" {
    try architecture_security.designGoalsKeepInstallsDeclarativeAndAuthorityExplicit();
}

test "spec 2.1 6.2 and 7 explicit grants are required before a task gains authority" {
    try architecture_security.explicitGrantsRequireAuthority();
}

test "spec 4 and 7 preserve capability lattice security invariants" {
    try architecture_security.capabilityLatticePreservesSecurityInvariants();
}

test "spec 4 6.3 and 13 keep the kernel typed minimal and native-only" {
    try architecture_security.kernelRemainsTypedAndNativeOnly();
}

test "spec 4 and 6.3 require kernel-mediated launches and typed services to carry userspace image provenance" {
    try architecture_security.kernelMediatedLaunchesCarryUserspaceProvenance();
}

test "spec 4 6.3 and 7 harden modeled kernel isolation and component abi claims" {
    try architecture_security.modeledKernelClaimsHaveHardEnforcementProofs();
}

test "spec 4 and 13 activate published nic and storage transports through scoped driver services" {
    try drivers_storage_sync.publishedDriversActivateScopedTransports();
}

test "spec 8 storage stays versioned recoverable signed and addressed by object id" {
    try drivers_storage_sync.storageStaysVersionedRecoverableSignedAndDerived();
}

test "spec 9 and 10 use a trusted device graph selective sync and policy-gated networking" {
    try drivers_storage_sync.trustedDeviceGraphSelectiveSyncAndPolicyNetworking();
}

test "spec 5 and 14 keep the base image signed measured atomic and rollback-capable" {
    try boot_recovery.baseImageStaysSignedMeasuredAtomicAndRollbackCapable();
}

test "spec 14.2 validates boot core storage network and ui health before finalizing an update" {
    try boot_recovery.baseOsHealthChecksValidateBootCoreStorageNetworkAndUi();
}

test "spec 5.3 recovery mode can reinstall restore repair rotate and revoke" {
    try boot_recovery.recoveryModeCanReinstallRestoreRepairRotateAndRevoke();
}

test "spec 6.4 only runs declared background work with explicit triggers budgets and throttling" {
    try ux_and_lifecycle.backgroundWorkStaysDeclaredTriggeredBudgetedAndThrottled();
}

test "spec 11 task-first UX records structured task workspace permission and pairing flows" {
    try ux_and_lifecycle.taskFirstUxRecordsStructuredFlows();
}

test "spec 7.2 9.4 and 11.3 keep grants inspectable, scoped, and user-visible" {
    try experience_and_policy_edges.permissionReviewsAndSharingStayScopedAndInspectable();
}

test "spec 11.2 keeps task views and native app components explicit" {
    try experience_and_policy_edges.taskViewsAndNativeComponentsStayExplicit();
}

test "spec 6.1 14.3 and 16 keep package lifecycle declarative signed and policy scoped" {
    try ux_and_lifecycle.packageLifecycleStaysDeclarativeSignedAndPolicyScoped();
}

test "spec 2.3 11.4 12 and 15 keep indexing notifications media helpers and diagnostics structured" {
    try ux_and_lifecycle.structuredServicesAndDiagnosticsStayRedacted();
}

test "spec 5.2 7.5 and 12 keep attestation secrets and accelerator policy explicit" {
    try platform_services.attestationSecretsAndAcceleratorPolicyStayExplicit();
}

test "spec 12.3 and 14.3 preserve responsiveness while native app updates stay explicit and reversible" {
    try experience_and_policy_edges.thermalPowerAndAppUpdatesStayExplicit();
}

test "spec 3 4.3 and 16 keep principal identity signed and administrative scope split" {
    try architecture_security.principalIdentityAndAdministrativeScopeStaySplit();
}

test "spec 13.3 15.2 and 15.3 keep failures explainable restartable and redacted" {
    try platform_services.failuresStayExplainableRestartableAndRedacted();
}

test "spec 19 user journeys keep installs sync permissions updates and recovery cohesive" {
    try ux_and_lifecycle.userJourneyKeepsInstallSyncPermissionUpdateAndRecoveryCohesive();
}

test "spec 7.2 11.3 and 16 keep agent sessions bounded audited and revocable" {
    try experience_and_policy_edges.agentSessionsStayBoundedAuditedAndRevocable();
}

test "adversarial spec rejects revoked capabilities during ipc" {
    try adversarial_security.revokedCapabilitiesFailDuringIpc();
}

test "adversarial spec rejects expired leases at kernel service boundaries" {
    try adversarial_security.expiredLeasesFailAtKernelServiceBoundaries();
}

test "adversarial spec rejects malformed manifests" {
    try adversarial_security.malformedManifestsStayRejected();
}

test "adversarial spec refuses corrupted storage logs" {
    try adversarial_security.corruptedStorageLogsDoNotReplay();
}

test "adversarial spec records service crash loops without losing restart state" {
    try adversarial_security.serviceCrashLoopsRemainDiagnosableAndBounded();
}

test "adversarial spec treats downgrade and rollback metadata replay as invalid" {
    try adversarial_security.downgradeAndRollbackAttacksNeedFreshSignedMetadata();
}

test "adversarial freestanding runtime proofs reject modeled bypasses" {
    try std.testing.expect(runtime_negative_proofs.processIsolationBlocksForeignSharedMemory());
    try std.testing.expect(runtime_negative_proofs.syscallSubjectSpoofingIsRejected());
    try std.testing.expect(runtime_negative_proofs.rawNetworkSendBypassIsDenied());
    try std.testing.expect(runtime_negative_proofs.driverAuthorityEscapeIsRejected());
    try std.testing.expect(runtime_negative_proofs.checkpointAuthorityIsNotReplayed());
}

test "backlog gate enforces isolation proof depth" {
    try backlog_gates.isolationProofDepthGate();
}

test "backlog gate enforces network transport hardening" {
    try backlog_gates.networkTransportHardeningGate();
}

test "backlog gate enforces sync adapter depth" {
    try backlog_gates.syncAdapterDepthGate();
}

test "backlog gate enforces sync private overlay end-to-end" {
    try backlog_gates.syncPrivateOverlayEndToEndGate();
}

test "backlog gate enforces component ABI depth" {
    try backlog_gates.componentAbiDepthGate();
}

test "backlog gate enforces indexed hot-path tables" {
    try backlog_gates.indexedHotPathTablesGate();
}

test "backlog gate pins the first real hardware target" {
    try backlog_gates.firstHardwareTargetGate();
}

test "backlog gate enforces driver boundary audit" {
    try backlog_gates.driverBoundaryAuditGate();
}

test "backlog gate enforces kernel bootstrap shim boundary" {
    try backlog_gates.kernelBootstrapShimBoundaryGate();
}

test "backlog gate enforces UX rendering" {
    try backlog_gates.uxRenderingGate();
}
