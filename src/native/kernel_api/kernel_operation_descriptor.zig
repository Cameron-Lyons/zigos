const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const operation_metadata = @import("operation_metadata.zig");

pub const TargetKindRule = operation_metadata.TargetKindRule;
pub const ScopeRule = operation_metadata.ScopeRule;
pub const AutoGrantKind = operation_metadata.AutoGrantKind;
pub const AutoGrantLocality = operation_metadata.AutoGrantLocality;
pub const AutoGrant = operation_metadata.AutoGrant;
pub const Descriptor = operation_metadata.Descriptor;
pub const endpoint_owner_auto_grant = operation_metadata.endpoint_owner_auto_grant;
pub const shared_memory_owner_auto_grant = operation_metadata.shared_memory_owner_auto_grant;
pub const operations = operation_metadata.operations;
pub const declarationFor = operation_metadata.declarationFor;
pub const autoGrantFor = operation_metadata.autoGrantFor;

test "kernel operation descriptors are projected from shared native operation metadata" {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, operations.len);
    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const declaration = declarationFor(operation);
        const metadata = operation_metadata.declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expectEqual(metadata.required_right, declaration.required_right);
    }

    try std.testing.expectEqual(capability.CapabilityRight.task_create, declarationFor(.task_create).required_right);
    try std.testing.expectEqual(capability.CapabilityRight.device_use, declarationFor(.device_describe).required_right);
    try std.testing.expect(switch (declarationFor(.endpoint_send).target_kind) {
        .fixed => |kind| kind == .endpoint,
        else => false,
    });
    try std.testing.expect(switch (declarationFor(.capability_query).target_kind) {
        .same_as_target_capability => true,
        else => false,
    });
    try std.testing.expect(declarationFor(.endpoint_create).scope_rule.task_scope_matches_request_task);
    try std.testing.expectEqual(@as(usize, 1), declarationFor(.endpoint_create).auto_grants.len);
    try std.testing.expectEqual(AutoGrantKind.created_endpoint_owner, autoGrantFor(.endpoint_create, .created_endpoint_owner).kind);
}
