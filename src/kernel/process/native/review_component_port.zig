const std = @import("std");
const abi = @import("abi.zig");
const manifest = @import("manifest.zig");
const permission_review_service = @import("permission_review_service.zig");
const policy_mediation = @import("policy_mediation.zig");

pub const Error = error{
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
    return .{
        .operation = abi.reviewOpcode(operation),
        .correlation_id = correlation_id,
        .subject_task_id = subject_task_id,
    };
}

fn validateHeader(header: abi.RequestHeader, expected: abi.ReviewOperation) Error!void {
    if (header.version != abi.ABI_VERSION) return error.UnsupportedAbiVersion;
    if (header.operation != abi.reviewOpcode(expected)) return error.UnexpectedOperation;
}

fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) Error!void {
    if (header.subject_task_id != 0 and header.subject_task_id != task_id) {
        return error.SubjectTaskMismatch;
    }
}

test "review port validates headers and returns reviewed grants" {
    var runtime = @import("task_runtime.zig").Runtime.init();
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
            .rights = .{ .object_read = true },
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
    var runtime = @import("task_runtime.zig").Runtime.init();
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
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .background_triggers = &.{.scheduled_sync},
    };
    var grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.MissingBackgroundPermission, port.reviewBundle(.{
        .header = makeHeader(.review_bundle, 2, task.id),
        .app_task_id = task.id,
        .bundle = bundle,
        .output = &grants_buffer,
    }, 10));
}
