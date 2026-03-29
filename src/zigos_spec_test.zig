const architecture_security = @import("spec_tests/architecture_security.zig");
const boot_recovery = @import("spec_tests/boot_recovery.zig");
const drivers_storage_sync = @import("spec_tests/drivers_storage_sync.zig");
const platform_services = @import("spec_tests/platform_services.zig");
const ux_and_lifecycle = @import("spec_tests/ux_and_lifecycle.zig");

test "spec 2.1 6.2 and 7 explicit grants are required before a task gains authority" {
    try architecture_security.explicitGrantsRequireAuthority();
}

test "spec 4 6.3 13 and 17 keep the kernel typed minimal and route legacy support through isolated portals" {
    try architecture_security.kernelRemainsTypedAndIsolatesLegacy();
}

test "spec 4 and 6.3 require kernel-mediated launches and typed services to carry userspace image provenance" {
    try architecture_security.kernelMediatedLaunchesCarryUserspaceProvenance();
}

test "spec 4 and 13 activate published nic and storage transports through scoped driver services" {
    try drivers_storage_sync.publishedDriversActivateScopedTransports();
}

test "spec 8 storage stays versioned recoverable signed and exposed through a derived file bridge" {
    try drivers_storage_sync.storageStaysVersionedRecoverableSignedAndDerived();
}

test "spec 9 and 10 use a trusted device graph selective sync and policy-gated networking" {
    try drivers_storage_sync.trustedDeviceGraphSelectiveSyncAndPolicyNetworking();
}

test "spec 5 and 14 keep the base image signed measured atomic and rollback-capable" {
    try boot_recovery.baseImageStaysSignedMeasuredAtomicAndRollbackCapable();
}

test "spec 5.3 recovery mode can reinstall restore repair rotate and revoke" {
    try boot_recovery.recoveryModeCanReinstallRestoreRepairRotateAndRevoke();
}

test "spec 11 task-first UX records structured task workspace permission and pairing flows" {
    try ux_and_lifecycle.taskFirstUxRecordsStructuredFlows();
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

test "spec 3 4.3 and 16 keep principal identity signed and administrative scope split" {
    try architecture_security.principalIdentityAndAdministrativeScopeStaySplit();
}

test "spec 13.3 15.2 and 15.3 keep failures explainable restartable and redacted" {
    try platform_services.failuresStayExplainableRestartableAndRedacted();
}
