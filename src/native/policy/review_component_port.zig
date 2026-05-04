const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const permission_review_service = @import("permission_review_service.zig");
const policy_mediation = @import("policy_mediation.zig");
const request_header = @import("../core/request_header.zig");

pub const Error = error{
    SubjectTaskRequired,
    SubjectTaskMismatch,
    UnexpectedOperation,
    UnsupportedAbiVersion,
} || permission_review_service.Error;

pub const ReviewBundleRequest = struct {
    header: abi.RequestHeader,
    app_task_id: u64,
    bundle: manifest.BundleManifest,
    output: *[permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
};

pub const Port = struct {
    service: *permission_review_service.Service,

    pub fn init(service: *permission_review_service.Service) Port {
        return .{ .service = service };
    }

    pub fn reviewBundle(
        self: *Port,
        request: ReviewBundleRequest,
        now_ticks: u64,
    ) Error![]const policy_mediation.UserGrant {
        try validateHeader(request.header, .review_bundle);
        try validateSubjectTask(request.header, request.app_task_id);
        return self.service.reviewBundle(request.app_task_id, request.bundle, now_ticks, request.output);
    }
};

pub fn makeHeader(operation: abi.ReviewOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return request_header.makeHeader(abi.reviewOpcode(operation), correlation_id, subject_task_id);
}

fn validateHeader(header: abi.RequestHeader, expected: abi.ReviewOperation) Error!void {
    try request_header.validateHeader(header, abi.reviewOpcode(expected));
}

fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) Error!void {
    try request_header.validateSubjectTask(header, task_id);
}

test "review port validates headers and returns reviewed grants" {
    var runtime = @import("../task/task_runtime.zig").Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    const scripted_inputs = [_][]const u8{"allow local lease=25"};
    var service = permission_review_service.Service.init(5, 6, &runtime, &scripted_inputs);
    var port = Port.init(&service);
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .local_only = true,
            .max_lease_ticks = 50,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
    var grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try port.reviewBundle(.{
        .header = makeHeader(.review_bundle, 1, task.id),
        .app_task_id = task.id,
        .bundle = bundle,
        .output = &grants_buffer,
    }, 10);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expect(grants[0].allow);
    try std.testing.expect(grants[0].local_only);

    try std.testing.expectError(error.UnexpectedOperation, port.reviewBundle(.{
        .header = .{
            .operation = abi.policyOpcode(.apply_manifest),
            .correlation_id = 2,
            .subject_task_id = task.id,
        },
        .app_task_id = task.id,
        .bundle = bundle,
        .output = &grants_buffer,
    }, 10));
}

test "review port rejects invalid manifests before entering the review loop" {
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
    const scripted_inputs = [_][]const u8{"allow"};
    var service = permission_review_service.Service.init(5, 6, &runtime, &scripted_inputs);
    var port = Port.init(&service);
    var bundle = manifest_fixtures.syncPushBundle();
    bundle.requested_permissions = &.{};
    var grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.MissingBackgroundPermission, port.reviewBundle(.{
        .header = makeHeader(.review_bundle, 2, task.id),
        .app_task_id = task.id,
        .bundle = bundle,
        .output = &grants_buffer,
    }, 10));
}
