const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const network_policy = @import("../sync/network_policy.zig");
const package_service = @import("../services/package_service.zig");
const policy_mediation = @import("policy_mediation.zig");
const policy_object = @import("policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const Error = package_service.AuthorityError || package_service.Error || network_policy.Error || policy_mediation.Error || event_ledger.Error || error{
    PolicyDenied,
};

pub fn installPackage(
    port: *package_service.PackagePort,
    authority: package_service.AuthorityContext,
    request: package_service.InstallRequest,
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
) Error!package_service.InstallResult {
    const decision = policies.installSourceDecision(subjects, request.source_identity);
    if (!decision.allowed) return error.InstallSourceDenied;
    return port.install(authority, request, null);
}

pub fn connectNetwork(
    broker: *network_policy.EgressBroker,
    request: network_policy.EgressConnectionRequest,
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
    destination: []const u8,
) Error!network_policy.EgressDecision {
    const decision = policies.networkEgressDecision(subjects, destination);
    if (!decision.allowed) {
        return .{
            .allowed = false,
            .reason = .policy_denied,
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .policy_decision = .{
                .allowed = false,
                .reason = .policy_denied,
            },
        };
    }
    return broker.connect(request);
}

pub fn authorizeSyncDestination(
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
    destination: []const u8,
) policy_object.PolicyDecision {
    return policies.syncDestinationDecision(subjects, destination);
}

pub fn authorizeRemovableStorage(
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
) policy_object.PolicyDecision {
    return policies.removableStorageDecision(subjects);
}

pub fn authorizePermission(
    mediator: *policy_mediation.PolicyMediator,
    task_id: u64,
    request: manifest.PermissionRequest,
    grants: []const policy_mediation.UserGrant,
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
    now_ticks: u64,
) Error!policy_mediation.PermissionDecision {
    if (request.kind == .screen_capture) {
        const policy_decision = policies.screenCaptureDecision(subjects);
        if (!policy_decision.allowed) {
            const task = mediator.runtime.find(task_id) orelse return error.TaskNotFound;
            return mediator.commitDeniedDecision(.{
                .request = request,
                .task_id = task.id,
                .owner = task.owner,
                .allowed = false,
                .reason = .policy_denied,
            }, now_ticks);
        }
    }
    return mediator.authorizeRequest(task_id, request, grants, now_ticks);
}

pub fn exportAuditHistory(
    ledger: *const event_ledger.Ledger,
    buffer: []u8,
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
    request: policy_object.RetentionAuditRequest,
    options: event_ledger.ExportOptions,
) Error![]const u8 {
    const decision = policies.retentionAuditDecision(subjects, request);
    if (!decision.allowed) return error.PolicyDenied;
    return ledger.exportText(buffer, options);
}

fn serviceAuthority(
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .capability_mint = true,
        } },
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
}

fn networkCapability(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    policy_id: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = policy_id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{
            .task_id = task_id,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
}

fn trustPublisher(
    port: *package_service.PackagePort,
    authority: package_service.AuthorityContext,
    identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    _ = try port.trustPolicyAuthorityRoot(authority, issuer, [_]u8{0x51} ** 32);
    _ = try port.trustPublisher(
        authority,
        .{ .kind = .app, .serial = std.hash.Wyhash.hash(0x5A47_504F_4C45, publisher) },
        issuer,
        publisher,
        try signing.publicKey(identity),
    );
}

test "policy examples route package network removable and sync denials through subsystem gates" {
    var policies = policy_object.Directory.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 88 };
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 88,
        .issuer = .{ .kind = .policy_authority, .serial = 88 },
        .label = "example-policy-controls",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &.{"api.corp.example"},
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .retention_days = 30,
        .audit_export_required = true,
    }, .{
        .label = "example-policy-key",
        .seed = [_]u8{0x88} ** 32,
    });

    var package_capabilities = capability.CapabilityTable.init();
    var packages = package_service.Service.init();
    packages.bind(8_800, .{ .kind = .service, .serial = 8_800 });
    var package_port = package_service.PackagePort.init(&packages, &package_capabilities);
    const package_actor = principal.PrincipalId{ .kind = .service, .serial = 8_801 };
    const package_authority_capability = try serviceAuthority(&package_capabilities, packages.service_id, package_actor, 8_802);
    const package_authority = package_service.AuthorityContext{
        .task_id = 8_802,
        .principal = package_actor,
        .capability_id = package_authority_capability.id,
        .now_ticks = 1,
    };
    const package_signer = signing.SignerIdentity{
        .label = "example-package-signer",
        .seed = [_]u8{0x89} ** 32,
    };
    try trustPublisher(&package_port, package_authority, package_signer, "zigos.dev");
    var bundle = manifest_fixtures.notesBundle();
    bundle.signature = try signing.signWithDefaultRegistry(.ed25519, package_signer, &package_service.digestBundle(bundle));

    try std.testing.expectError(error.InstallSourceDenied, installPackage(&package_port, package_authority, .{
        .bundle = bundle,
        .source_identity = "repo:personal",
        .data_schema_version = 1,
    }, &policies, subjects));
    const installed = try installPackage(&package_port, package_authority, .{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, &policies, subjects);
    try std.testing.expect(installed.installed_new);

    var network_policies = network_policy.Directory.init();
    const egress_policy = try network_policies.create(.{
        .owner = .{ .kind = .app, .serial = 8_810 },
        .label = "corp-api",
        .mode = .named_domain,
        .target = "api.corp.example",
    });
    var network_capabilities = capability.CapabilityTable.init();
    const network_actor = principal.PrincipalId{ .kind = .app, .serial = 8_810 };
    const network_authority = try networkCapability(&network_capabilities, network_actor, 8_811, egress_policy.id);
    var broker = network_policy.EgressBroker.init(&network_policies, &network_capabilities);

    const policy_denied = try connectNetwork(&broker, .{
        .task_id = 8_811,
        .principal_id = network_actor,
        .capability_id = network_authority.id,
        .policy_id = egress_policy.id,
        .evidence = .{ .destination = .{ .domain = "api.corp.example" } },
        .now_ticks = 2,
    }, &policies, subjects, "api.personal.example");
    try std.testing.expect(!policy_denied.allowed);
    try std.testing.expectEqual(network_policy.EgressDecisionReason.policy_denied, policy_denied.reason);

    const broker_denied = try connectNetwork(&broker, .{
        .task_id = 8_811,
        .principal_id = network_actor,
        .capability_id = network_authority.id,
        .policy_id = egress_policy.id,
        .evidence = .{ .destination = .{ .domain = "api.other.example" } },
        .now_ticks = 2,
    }, &policies, subjects, "api.corp.example");
    try std.testing.expect(!broker_denied.allowed);
    try std.testing.expectEqual(network_policy.EgressDecisionReason.destination_mismatch, broker_denied.reason);

    const allowed_network = try connectNetwork(&broker, .{
        .task_id = 8_811,
        .principal_id = network_actor,
        .capability_id = network_authority.id,
        .policy_id = egress_policy.id,
        .evidence = .{ .destination = .{ .domain = "api.corp.example" } },
        .now_ticks = 2,
    }, &policies, subjects, "api.corp.example");
    try std.testing.expect(allowed_network.allowed);

    const removable = authorizeRemovableStorage(&policies, subjects);
    try std.testing.expect(!removable.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.removable_storage_denied, removable.reason);

    const sync = authorizeSyncDestination(&policies, subjects, "relay.personal.example");
    try std.testing.expect(!sync.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.sync_destination_denied, sync.reason);
}

test "policy examples deny screen capture grants and enforce retention audit requirements" {
    var policies = policy_object.Directory.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 90 };
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 90,
        .issuer = .{ .kind = .policy_authority, .serial = 90 },
        .label = "capture-and-audit",
        .screen_capture_allowed = false,
        .retention_days = 30,
        .audit_export_required = true,
    }, .{
        .label = "capture-policy-key",
        .seed = [_]u8{0x90} ** 32,
    });

    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 9_001 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 2048,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    var mediator = policy_mediation.PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 91 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 92,
            .compositor_service_id = 93,
            .policy_service_id = 94,
            .service_registry_id = 95,
        },
    );
    const capture_request = manifest.PermissionRequest{
        .kind = .screen_capture,
        .resource = "display:main",
        .rights = .{ .device = .{ .screen_capture = true } },
        .required = false,
    };
    const grants = [_]policy_mediation.UserGrant{
        .{ .kind = .screen_capture, .resource = "display:main", .expires_at_ticks = 50 },
    };
    const denied_capture = try authorizePermission(
        &mediator,
        task.id,
        capture_request,
        &grants,
        &policies,
        subjects,
        10,
    );
    try std.testing.expect(!denied_capture.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, denied_capture.reason);
    try std.testing.expectEqual(@as(?u64, null), denied_capture.capability_id);

    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(
        task.owner,
        task.id,
        .screen_capture,
        false,
        .policy_denied,
        11,
        "screen capture blocked by organization policy",
        true,
    );
    var export_buffer: [1024]u8 = undefined;

    const retention_denied = policies.retentionAuditDecision(subjects, .{
        .retention_days = 90,
        .audit_export_present = true,
    });
    try std.testing.expect(!retention_denied.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.retention_denied, retention_denied.reason);
    try std.testing.expectError(error.PolicyDenied, exportAuditHistory(
        &ledger,
        &export_buffer,
        &policies,
        subjects,
        .{ .retention_days = 90, .audit_export_present = true },
        .{},
    ));

    const audit_denied = policies.retentionAuditDecision(subjects, .{
        .retention_days = 30,
        .audit_export_present = false,
    });
    try std.testing.expect(!audit_denied.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.audit_export_required, audit_denied.reason);
    try std.testing.expectError(error.PolicyDenied, exportAuditHistory(
        &ledger,
        &export_buffer,
        &policies,
        subjects,
        .{ .retention_days = 30, .audit_export_present = false },
        .{},
    ));

    const exported = try exportAuditHistory(
        &ledger,
        &export_buffer,
        &policies,
        subjects,
        .{ .retention_days = 30, .audit_export_present = true },
        .{},
    );
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=permission_decision") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=redacted") != null);
}
