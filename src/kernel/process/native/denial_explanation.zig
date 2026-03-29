const std = @import("std");
const abi = @import("abi.zig");
const manifest = @import("manifest.zig");
const native_util = @import("util.zig");
const copyText = native_util.copyText;

pub const MAX_LABEL_BYTES: usize = 48;

pub const Explanation = struct {
    reason: abi.DenialReason = .none,
    policy_len: usize = 0,
    policy: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    missing_capability_len: usize = 0,
    missing_capability: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,

    pub fn policySlice(self: *const Explanation) []const u8 {
        return self.policy[0..self.policy_len];
    }

    pub fn missingCapabilitySlice(self: *const Explanation) []const u8 {
        return self.missing_capability[0..self.missing_capability_len];
    }
};

pub const RenderError = error{NoSpaceLeft};

pub fn none() Explanation {
    return .{};
}

pub fn forPermissionDecision(kind: manifest.PermissionKind, reason: abi.DenialReason) Explanation {
    var explanation = Explanation{
        .reason = reason,
    };
    explanation.policy_len = copyText(&explanation.policy, policyLabel(reason, kind));
    explanation.missing_capability_len = copyText(&explanation.missing_capability, capabilityLabel(kind));
    explanation.user_approval_can_resolve = approvalCanResolve(reason);
    explanation.retry_safe = retrySafe(reason);
    return explanation;
}

pub fn renderToBuffer(buffer: []u8, explanation: Explanation) RenderError![]const u8 {
    return std.fmt.bufPrint(buffer, "reason={s} policy={s} missing={s} approval={s} retry_safe={s}", .{
        @tagName(explanation.reason),
        explanation.policySlice(),
        explanation.missingCapabilitySlice(),
        yesNo(explanation.user_approval_can_resolve),
        yesNo(explanation.retry_safe),
    }) catch error.NoSpaceLeft;
}

fn capabilityLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "object-access-capability",
        .network_egress => "network-egress-capability",
        .device_access => "device-access-capability",
        .clipboard => "clipboard-capability",
        .camera => "camera-capability",
        .mic => "mic-capability",
        .sensor => "sensor-capability",
        .location => "location-capability",
        .contacts => "contacts-capability",
        .screen_capture => "screen-capture-capability",
        .notification_post => "notification-capability",
        .background_execution => "background-execution-capability",
        .peer_ipc => "peer-ipc-capability",
    };
}

fn policyLabel(reason: abi.DenialReason, kind: manifest.PermissionKind) []const u8 {
    _ = kind;
    return switch (reason) {
        .none => "none",
        .invalid_target => "target-routing-policy",
        .capability_missing => "capability-broker-policy",
        .capability_revoked => "capability-revocation-policy",
        .capability_expired => "capability-lease-policy",
        .scope_violation => "task-scope-policy",
        .policy_denied => "user-grant-policy",
        .budget_exhausted => "resource-budget-policy",
        .interface_not_found => "service-registry-policy",
        .unsupported_operation => "abi-surface-policy",
    };
}

fn approvalCanResolve(reason: abi.DenialReason) bool {
    return switch (reason) {
        .capability_missing,
        .capability_revoked,
        .capability_expired,
        .scope_violation,
        .policy_denied,
        => true,
        else => false,
    };
}

fn retrySafe(reason: abi.DenialReason) bool {
    return switch (reason) {
        .budget_exhausted, .interface_not_found => true,
        else => false,
    };
}


fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

test "permission denials explain blocking policy capability approval and retry hints" {
    const denied = forPermissionDecision(.network_egress, .policy_denied);
    try std.testing.expectEqualStrings("user-grant-policy", denied.policySlice());
    try std.testing.expectEqualStrings("network-egress-capability", denied.missingCapabilitySlice());
    try std.testing.expect(denied.user_approval_can_resolve);
    try std.testing.expect(!denied.retry_safe);

    const throttled = forPermissionDecision(.background_execution, .budget_exhausted);
    try std.testing.expectEqualStrings("resource-budget-policy", throttled.policySlice());
    try std.testing.expectEqualStrings("background-execution-capability", throttled.missingCapabilitySlice());
    try std.testing.expect(!throttled.user_approval_can_resolve);
    try std.testing.expect(throttled.retry_safe);
}
