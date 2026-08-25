const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const yesNo = native_util.yesNo;

pub const MAX_LABEL_BYTES: usize = 48;
const USER_HELP_BUFFER_BYTES: usize = 256;

pub const Explanation = struct {
    reason: abi.DenialReason = .none,
    policy: []const u8 = "",
    missing_capability: []const u8 = "",
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,

    pub fn policySlice(self: *const Explanation) []const u8 {
        return self.policy;
    }

    pub fn missingCapabilitySlice(self: *const Explanation) []const u8 {
        return self.missing_capability;
    }
};

pub const RenderError = error{NoSpaceLeft};

pub fn none() Explanation {
    return .{};
}

pub fn forPermissionDecision(kind: manifest.PermissionKind, reason: abi.DenialReason) Explanation {
    return .{
        .reason = reason,
        .policy = policyLabel(reason),
        .missing_capability = capabilityLabel(kind),
        .user_approval_can_resolve = approvalCanResolve(reason),
        .retry_safe = retrySafe(reason),
    };
}

pub fn renderToBuffer(buffer: []u8, explanation: Explanation) RenderError![]const u8 {
    var used: usize = 0;
    try appendText(buffer, &used, "reason=");
    try appendText(buffer, &used, @tagName(explanation.reason));
    try appendText(buffer, &used, " policy=");
    try appendText(buffer, &used, explanation.policySlice());
    try appendText(buffer, &used, " missing=");
    try appendText(buffer, &used, explanation.missingCapabilitySlice());
    try appendText(buffer, &used, " approval=");
    try appendText(buffer, &used, yesNo(explanation.user_approval_can_resolve));
    try appendText(buffer, &used, " retry_safe=");
    try appendText(buffer, &used, yesNo(explanation.retry_safe));
    return buffer[0..used];
}

pub fn renderUserHelpToBuffer(
    buffer: []u8,
    display_name: []const u8,
    kind: manifest.PermissionKind,
    resource: []const u8,
    explanation: Explanation,
) RenderError![]const u8 {
    var used: usize = 0;
    const action = actionLabel(kind);
    const reason = plainReason(explanation.reason);
    const missing = humanCapabilityLabel(kind);
    const resolution = resolutionHint(explanation);
    if (resource.len != 0) {
        try appendTextParts(buffer, &used, .{
            "Blocked: ",   display_name,
            " could not ", action,
            " for ",       resource,
            " because ",   reason,
            ". Missing: ", missing,
            ". ",          resolution,
        });
    } else {
        try appendTextParts(buffer, &used, .{
            "Blocked: ",   display_name,
            " could not ", action,
            " because ",   reason,
            ". Missing: ", missing,
            ". ",          resolution,
        });
    }
    return buffer[0..used];
}

fn resolutionHint(explanation: Explanation) []const u8 {
    if (explanation.user_approval_can_resolve) {
        return "Open Permission Review to grant a narrower scope or keep it blocked.";
    }
    if (explanation.retry_safe) {
        return "It is safe to try again after activity quiets down.";
    }
    return "This needs a different app route or administrator policy change.";
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

fn humanCapabilityLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "object access",
        .network_egress => "data egress",
        .device_access => "device access",
        .clipboard => "clipboard access",
        .camera => "camera access",
        .mic => "microphone access",
        .sensor => "sensor access",
        .location => "location access",
        .contacts => "contacts access",
        .screen_capture => "screen capture",
        .notification_post => "notification access",
        .background_execution => "background activity",
        .peer_ipc => "peer task connection",
    };
}

pub fn policyLabel(reason: abi.DenialReason) []const u8 {
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

fn actionLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "open or change the object",
        .network_egress => "send data through the approved route",
        .device_access => "use the device",
        .clipboard => "use the clipboard",
        .camera => "use the camera",
        .mic => "use the microphone",
        .sensor => "read the sensor",
        .location => "read location",
        .contacts => "read contacts",
        .screen_capture => "capture the screen",
        .notification_post => "post notifications",
        .background_execution => "run in the background",
        .peer_ipc => "connect to another task",
    };
}

fn plainReason(reason: abi.DenialReason) []const u8 {
    return switch (reason) {
        .none => "nothing was blocked",
        .invalid_target => "the target did not match the approved route",
        .capability_missing => "no permission grant was found",
        .capability_revoked => "the permission was revoked",
        .capability_expired => "the permission expired",
        .scope_violation => "the request was outside the approved scope",
        .policy_denied => "the permission was not granted",
        .budget_exhausted => "the background budget is exhausted",
        .interface_not_found => "the requested service is not available",
        .unsupported_operation => "this operation is not supported here",
    };
}

pub fn approvalCanResolve(reason: abi.DenialReason) bool {
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

pub fn retrySafe(reason: abi.DenialReason) bool {
    return switch (reason) {
        .budget_exhausted, .interface_not_found => true,
        else => false,
    };
}

fn appendText(buffer: []u8, used: *usize, text: []const u8) RenderError!void {
    if (used.* + text.len > buffer.len) return error.NoSpaceLeft;
    @memcpy(buffer[used.*..][0..text.len], text);
    used.* += text.len;
}

fn appendTextParts(buffer: []u8, used: *usize, parts: anytype) RenderError!void {
    var total_len: usize = 0;
    inline for (parts) |part| total_len += part.len;
    if (total_len > buffer.len -| used.*) return error.NoSpaceLeft;

    inline for (parts) |part| {
        @memcpy(buffer[used.*..][0..part.len], part);
        used.* += part.len;
    }
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

test "permission denial rendering respects exact buffer bounds" {
    const denied = forPermissionDecision(.network_egress, .policy_denied);
    const expected = "reason=policy_denied policy=user-grant-policy missing=network-egress-capability approval=yes retry_safe=no";

    var exact_buffer: [expected.len]u8 = undefined;
    try std.testing.expectEqualStrings(
        expected,
        try renderToBuffer(&exact_buffer, denied),
    );

    var undersized_backing = [_]u8{0xa5} ** expected.len;
    try std.testing.expectError(
        error.NoSpaceLeft,
        renderToBuffer(undersized_backing[0 .. expected.len - 1], denied),
    );
    try std.testing.expectEqual(
        @as(u8, 0xa5),
        undersized_backing[expected.len - 1],
    );
}

test "permission denials render a user readable blocked explanation" {
    const denied = forPermissionDecision(.network_egress, .policy_denied);
    const expected =
        "Blocked: Notes could not send data through the approved route for relay.zigos.dev" ++
        " because the permission was not granted. Missing: data egress." ++
        " Open Permission Review to grant a narrower scope or keep it blocked.";
    try std.testing.expect(expected.len <= USER_HELP_BUFFER_BYTES);

    var exact_buffer: [expected.len]u8 = undefined;
    const rendered = try renderUserHelpToBuffer(&exact_buffer, "Notes", .network_egress, "relay.zigos.dev", denied);
    try std.testing.expectEqualStrings(expected, rendered);

    var short_buffer: [expected.len - 1]u8 = undefined;
    try std.testing.expectError(
        error.NoSpaceLeft,
        renderUserHelpToBuffer(&short_buffer, "Notes", .network_egress, "relay.zigos.dev", denied),
    );
}
