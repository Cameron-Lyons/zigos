const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const debug_contract = @import("../security/debug_contract.zig");
const principal = @import("../core/principal.zig");
const std = @import("std");

pub const Context = struct {
    task_id: u64,
    principal: principal.PrincipalId,
    capability_id: u64,
    now_ticks: u64,
    operation: []const u8 = "service-call",
    trace: ?*debug_contract.ProvenanceRecord = null,
};

pub const Error = error{
    CapabilityRequired,
    CapabilityNotFound,
    CapabilityRevoked,
    PermissionDenied,
};

pub fn requireServiceAuthority(
    capability_table: *const capability.CapabilityTable,
    service_id: u64,
    authority_context: Context,
    required_right: capability.CapabilityRight,
) Error!*const capability.Capability {
    const authority = capability_table.requireUsable(authority_context.capability_id, authority_context.now_ticks) catch |err| switch (err) {
        error.CapabilityNotFound => {
            writeTrace(authority_context, service_id, required_right, .denied, .capability_missing);
            return error.CapabilityNotFound;
        },
        error.CapabilityRevoked => {
            writeTrace(authority_context, service_id, required_right, .denied, .capability_revoked);
            return error.CapabilityRevoked;
        },
    };

    if (!authority.holder.eql(authority_context.principal)) {
        writeTrace(authority_context, service_id, required_right, .denied, .policy_denied);
        return error.PermissionDenied;
    }
    if (authority.scope.task_id) |scoped_task_id| {
        if (scoped_task_id != authority_context.task_id) {
            writeTrace(authority_context, service_id, required_right, .denied, .scope_violation);
            return error.PermissionDenied;
        }
    }
    if (authority.target.kind != .service or authority.target.id != service_id) {
        writeTrace(authority_context, service_id, required_right, .denied, .invalid_target);
        return error.CapabilityRequired;
    }
    if (!authority.rights.has(required_right)) {
        writeTrace(authority_context, service_id, required_right, .denied, .policy_denied);
        return error.PermissionDenied;
    }
    writeTrace(authority_context, service_id, required_right, .allowed, .none);
    return authority;
}

fn writeTrace(
    authority_context: Context,
    service_id: u64,
    required_right: capability.CapabilityRight,
    decision: debug_contract.Decision,
    reason: abi.DenialReason,
) void {
    if (authority_context.trace) |trace| {
        trace.* = debug_contract.serviceCallProvenance(
            decision,
            authority_context.now_ticks,
            authority_context.task_id,
            service_id,
            authority_context.capability_id,
            required_right,
            reason,
            authority_context.operation,
        );
    }
}

test "service authority writes allow and denial provenance" {
    var table = capability.CapabilityTable.init();
    const service_id: u64 = 77;
    const owner = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const authority = try table.mintBootRoot(.{
        .holder = owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service_id },
        .rights = .{ .service = .{ .object_read = true } },
        .scope = .{ .task_id = 9, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });

    var allow_trace = debug_contract.ProvenanceRecord{};
    _ = try requireServiceAuthority(&table, service_id, .{
        .task_id = 9,
        .principal = owner,
        .capability_id = authority.id,
        .now_ticks = 10,
        .operation = "open-object",
        .trace = &allow_trace,
    }, .object_read);
    try std.testing.expectEqual(debug_contract.Decision.allowed, allow_trace.decision);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.service_call, allow_trace.kind);
    try std.testing.expect(allow_trace.trace_id != 0);

    var denied_trace = debug_contract.ProvenanceRecord{};
    try std.testing.expectError(error.PermissionDenied, requireServiceAuthority(&table, service_id, .{
        .task_id = 10,
        .principal = owner,
        .capability_id = authority.id,
        .now_ticks = 10,
        .operation = "open-object",
        .trace = &denied_trace,
    }, .object_read));
    try std.testing.expectEqual(debug_contract.Decision.denied, denied_trace.decision);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, denied_trace.denial.reason);
    try std.testing.expect(denied_trace.denial.fingerprint != 0);
}
