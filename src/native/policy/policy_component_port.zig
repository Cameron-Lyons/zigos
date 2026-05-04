const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const policy_mediation = @import("policy_mediation.zig");
const request_header = @import("../core/request_header.zig");

pub const Error = policy_mediation.Error || error{
    SubjectTaskRequired,
    SubjectTaskMismatch,
    UnexpectedOperation,
    UnsupportedAbiVersion,
};

pub const AuthorizeRequest = struct {
    header: abi.RequestHeader,
    task_id: u64,
    request: manifest.PermissionRequest,
    grants: []const policy_mediation.UserGrant,
};

pub const ApplyManifestRequest = struct {
    header: abi.RequestHeader,
    task_id: u64,
    bundle: manifest.BundleManifest,
    grants: []const policy_mediation.UserGrant,
};

pub const Port = struct {
    mediator: *policy_mediation.PolicyMediator,

    pub fn init(mediator: *policy_mediation.PolicyMediator) Port {
        return .{ .mediator = mediator };
    }

    pub fn authorizeRequest(
        self: *Port,
        request: AuthorizeRequest,
        now_ticks: u64,
    ) Error!policy_mediation.PermissionDecision {
        try validateHeader(request.header, .authorize_request);
        try validateSubjectTask(request.header, request.task_id);
        return self.mediator.authorizeRequest(request.task_id, request.request, request.grants, now_ticks);
    }

    pub fn applyManifest(
        self: *Port,
        request: ApplyManifestRequest,
        now_ticks: u64,
    ) Error!policy_mediation.ActivationSummary {
        try validateHeader(request.header, .apply_manifest);
        try validateSubjectTask(request.header, request.task_id);
        return self.mediator.applyManifest(request.task_id, request.bundle, request.grants, now_ticks);
    }
};

pub fn makeHeader(operation: abi.PolicyOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return request_header.makeHeader(abi.policyOpcode(operation), correlation_id, subject_task_id);
}

fn validateHeader(header: abi.RequestHeader, expected: abi.PolicyOperation) Error!void {
    try request_header.validateHeader(header, abi.policyOpcode(expected));
}

fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) Error!void {
    try request_header.validateSubjectTask(header, task_id);
}

test "policy port validates headers and forwards apply manifest requests" {
    var capability_table = @import("../kernel_api/capability.zig").CapabilityTable.init();
    var runtime = @import("../task/task_runtime.zig").Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    var mediator = policy_mediation.PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 11,
            .compositor_service_id = 12,
            .policy_service_id = 13,
            .service_registry_id = 14,
        },
    );
    var port = Port.init(&mediator);
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .local_only = true,
            .max_lease_ticks = 20,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
    const grants = [_]policy_mediation.UserGrant{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .allow = true,
            .local_only = true,
            .expires_at_ticks = 15,
        },
    };

    const summary = try port.applyManifest(.{
        .header = makeHeader(.apply_manifest, 1, task.id),
        .task_id = task.id,
        .bundle = bundle,
        .grants = &grants,
    }, 10);
    try std.testing.expectEqual(@as(usize, 1), summary.granted_count);
    try std.testing.expect(summary.decisionForKind(.object_access).?.allowed);

    try std.testing.expectError(error.UnexpectedOperation, port.applyManifest(.{
        .header = makeHeader(.authorize_request, 2, task.id),
        .task_id = task.id,
        .bundle = bundle,
        .grants = &grants,
    }, 10));
}

test "policy port rejects invalid manifests before mediation" {
    var capability_table = @import("../kernel_api/capability.zig").CapabilityTable.init();
    var runtime = @import("../task/task_runtime.zig").Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    var mediator = policy_mediation.PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 21,
            .compositor_service_id = 22,
            .policy_service_id = 23,
            .service_registry_id = 24,
        },
    );
    var port = Port.init(&mediator);
    var bundle = manifest_fixtures.syncPushBundle();
    bundle.requested_permissions = &.{};

    try std.testing.expectError(error.MissingBackgroundPermission, port.applyManifest(.{
        .header = makeHeader(.apply_manifest, 3, task.id),
        .task_id = task.id,
        .bundle = bundle,
        .grants = &.{},
    }, 10));
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
}
