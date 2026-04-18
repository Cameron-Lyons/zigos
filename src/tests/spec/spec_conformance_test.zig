const architecture_security = @import("architecture_security.zig");
const boot_recovery = @import("boot_recovery.zig");
const drivers_storage_sync = @import("drivers_storage_sync.zig");
const experience_and_policy_edges = @import("experience_and_policy_edges.zig");
const platform_services = @import("platform_services.zig");
const ux_and_lifecycle = @import("ux_and_lifecycle.zig");

const SpecCase = struct {
    run: *const fn () anyerror!void,
};

const spec_cases = [_]SpecCase{
    .{ .run = architecture_security.explicitGrantsRequireAuthority },
    .{ .run = architecture_security.kernelRemainsTypedAndIsolatesLegacy },
    .{ .run = architecture_security.kernelMediatedLaunchesCarryUserspaceProvenance },
    .{ .run = drivers_storage_sync.publishedDriversActivateScopedTransports },
    .{ .run = drivers_storage_sync.storageStaysVersionedRecoverableSignedAndDerived },
    .{ .run = drivers_storage_sync.trustedDeviceGraphSelectiveSyncAndPolicyNetworking },
    .{ .run = boot_recovery.baseImageStaysSignedMeasuredAtomicAndRollbackCapable },
    .{ .run = boot_recovery.baseOsHealthChecksValidateBootCoreStorageNetworkAndUi },
    .{ .run = boot_recovery.recoveryModeCanReinstallRestoreRepairRotateAndRevoke },
    .{ .run = ux_and_lifecycle.backgroundWorkStaysDeclaredTriggeredBudgetedAndThrottled },
    .{ .run = ux_and_lifecycle.taskFirstUxRecordsStructuredFlows },
    .{ .run = experience_and_policy_edges.permissionReviewsAndSharingStayScopedAndInspectable },
    .{ .run = experience_and_policy_edges.taskViewsAndCompatibilityEnvironmentsStayExplicit },
    .{ .run = ux_and_lifecycle.packageLifecycleStaysDeclarativeSignedAndPolicyScoped },
    .{ .run = ux_and_lifecycle.structuredServicesAndDiagnosticsStayRedacted },
    .{ .run = platform_services.attestationSecretsAndAcceleratorPolicyStayExplicit },
    .{ .run = experience_and_policy_edges.thermalPowerAndAppUpdatesStayCompatibilityAware },
    .{ .run = architecture_security.principalIdentityAndAdministrativeScopeStaySplit },
    .{ .run = platform_services.failuresStayExplainableRestartableAndRedacted },
};

fn runSpecCase(index: usize) !void {
    try spec_cases[index].run();
}

test "spec 2.1 6.2 and 7 explicit grants are required before a task gains authority" {
    try runSpecCase(0);
}

test "spec 4 6.3 13 and 17 keep the kernel typed minimal and route legacy support through isolated portals" {
    try runSpecCase(1);
}

test "spec 4 and 6.3 require kernel-mediated launches and typed services to carry userspace image provenance" {
    try runSpecCase(2);
}

test "spec 4 and 13 activate published nic and storage transports through scoped driver services" {
    try runSpecCase(3);
}

test "spec 8 storage stays versioned recoverable signed and exposed through a derived file bridge" {
    try runSpecCase(4);
}

test "spec 9 and 10 use a trusted device graph selective sync and policy-gated networking" {
    try runSpecCase(5);
}

test "spec 5 and 14 keep the base image signed measured atomic and rollback-capable" {
    try runSpecCase(6);
}

test "spec 14.2 validates boot core storage network and ui health before finalizing an update" {
    try runSpecCase(7);
}

test "spec 5.3 recovery mode can reinstall restore repair rotate and revoke" {
    try runSpecCase(8);
}

test "spec 6.4 only runs declared background work with explicit triggers budgets and throttling" {
    try runSpecCase(9);
}

test "spec 11 task-first UX records structured task workspace permission and pairing flows" {
    try runSpecCase(10);
}

test "spec 7.2 9.4 and 11.3 keep grants inspectable, scoped, and user-visible" {
    try runSpecCase(11);
}

test "spec 11.2 and 17.2 keep task views and compatibility environments explicit" {
    try runSpecCase(12);
}

test "spec 6.1 14.3 and 16 keep package lifecycle declarative signed and policy scoped" {
    try runSpecCase(13);
}

test "spec 2.3 11.4 12 and 15 keep indexing notifications media helpers and diagnostics structured" {
    try runSpecCase(14);
}

test "spec 5.2 7.5 and 12 keep attestation secrets and accelerator policy explicit" {
    try runSpecCase(15);
}

test "spec 12.3 and 14.3 preserve responsiveness while app updates stay explicit and reversible" {
    try runSpecCase(16);
}

test "spec 3 4.3 and 16 keep principal identity signed and administrative scope split" {
    try runSpecCase(17);
}

test "spec 13.3 15.2 and 15.3 keep failures explainable restartable and redacted" {
    try runSpecCase(18);
}
