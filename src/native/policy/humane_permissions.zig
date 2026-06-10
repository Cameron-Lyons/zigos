const std = @import("std");
const abi = @import("../core/abi.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const capability = @import("../kernel_api/capability.zig");
const denial_explanation = @import("denial_explanation.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const workspace = @import("../storage/workspace.zig");

pub const RenderError = error{NoSpaceLeft};

pub const GrantScope = struct {
    resource: []const u8 = "",
    local_only: bool = false,
    expires_at_ticks: ?u64 = null,
};

pub fn renderRequestScopeToBuffer(
    buffer: []u8,
    request: manifest.PermissionRequest,
) RenderError![]const u8 {
    var used: usize = 0;
    try appendFmt(buffer, &used, "Scope: {s}; rights: ", .{scopeSummaryLabel(request.kind, request.local_only)});
    try appendRights(buffer, &used, request.rights);
    try appendText(buffer, &used, "; lease: ");
    try appendRequestedLease(buffer, &used, request.max_lease_ticks);
    try appendFmt(buffer, &used, "; revoke: {s}", .{revocationHint(request.kind)});
    return buffer[0..used];
}

pub fn renderGrantScopeToBuffer(
    buffer: []u8,
    request: manifest.PermissionRequest,
    grant: GrantScope,
    now_ticks: u64,
) RenderError![]const u8 {
    const local_only = request.local_only or grant.local_only;
    var used: usize = 0;
    try appendFmt(buffer, &used, "Grant: {s} for {s}; scope: {s}; rights: ", .{
        permissionLabel(request.kind),
        if (grant.resource.len != 0) grant.resource else request.resource,
        scopeSummaryLabel(request.kind, local_only),
    });
    try appendRights(buffer, &used, request.rights);
    try appendText(buffer, &used, "; expiry: ");
    try appendExpiry(buffer, &used, grant.expires_at_ticks, now_ticks);
    try appendFmt(buffer, &used, "; revoke: {s}", .{revocationHint(request.kind)});
    return buffer[0..used];
}

pub fn renderBlockedExplanationToBuffer(
    buffer: []u8,
    display_name: []const u8,
    request: manifest.PermissionRequest,
    explanation: denial_explanation.Explanation,
) RenderError![]const u8 {
    return denial_explanation.renderUserHelpToBuffer(
        buffer,
        display_name,
        request.kind,
        request.resource,
        explanation,
    );
}

pub fn renderShareSheetToBuffer(
    buffer: []u8,
    workspace_id: u64,
    grant: workspace.ShareGrant,
    now_ticks: u64,
) RenderError![]const u8 {
    var used: usize = 0;
    try appendFmt(buffer, &used, "Share sheet: workspace={d}; recipient=", .{workspace_id});
    try appendPrincipal(buffer, &used, grant.principal_id);
    try appendText(buffer, &used, "; scope: ");
    if (grant.isObjectScoped()) {
        if (grant.scopePathSlice().len != 0) {
            try appendFmt(buffer, &used, "one object ({s})", .{grant.scopePathSlice()});
        } else {
            try appendFmt(buffer, &used, "one object ({d})", .{grant.scope_object_id.raw()});
        }
    } else {
        try appendText(buffer, &used, "whole workspace");
    }
    try appendText(buffer, &used, "; access: ");
    try appendShareRights(buffer, &used, grant);
    try appendFmt(buffer, &used, "; network: {s}; expires: ", .{shareNetworkLabel(grant.network_scope)});
    try appendShareExpiry(buffer, &used, grant.expires_at_ticks, now_ticks);
    try appendFmt(buffer, &used, "; reshare: {s}; activity: {s}", .{
        reshareLabel(grant.reshare_policy),
        auditVisibilityLabel(grant.audit_visibility),
    });
    return buffer[0..used];
}

pub fn renderBackgroundActivityToBuffer(
    buffer: []u8,
    record: background_dispatch.DispatchRecord,
) RenderError![]const u8 {
    var used: usize = 0;
    try appendFmt(buffer, &used, "Background activity: task={d}; job={s}; state={s}; trigger={s}; visible={s}; network={s}; expected={d}s; budget=cpu:{d} memory:{d} shared_memory:{d}; tick={d}", .{
        record.task_id,
        record.backgroundTaskIdSlice(),
        backgroundStateLabel(record.state),
        backgroundTriggerLabel(record.trigger),
        backgroundVisibilityLabel(record.visibility),
        backgroundNetworkLabel(record.network),
        record.expected_duration_seconds,
        record.budget.cpu_time_ticks,
        record.budget.memory_bytes,
        record.budget.shared_memory_bytes,
        record.tick,
    });
    return buffer[0..used];
}

pub fn renderRevocationReceiptToBuffer(
    buffer: []u8,
    capability_id: u64,
    permission_kind: ?manifest.PermissionKind,
    resource: []const u8,
    tick: u64,
    detail: []const u8,
) RenderError![]const u8 {
    var used: usize = 0;
    try appendFmt(buffer, &used, "Revoked: {s}", .{
        if (permission_kind) |kind| permissionLabel(kind) else "Permission",
    });
    if (resource.len != 0) {
        try appendFmt(buffer, &used, " for {s}", .{resource});
    }
    try appendFmt(buffer, &used, " is off now; capability={d}; tick={d}", .{
        capability_id,
        tick,
    });
    if (detail.len != 0) {
        try appendFmt(buffer, &used, "; detail: {s}", .{detail});
    }
    try appendText(buffer, &used, "; restore: approve a new permission review");
    return buffer[0..used];
}

pub fn scopeSummaryLabel(kind: manifest.PermissionKind, local_only: bool) []const u8 {
    return switch (kind) {
        .object_access => if (local_only) "this object on this device" else "this object wherever the workspace is shared",
        .contacts => if (local_only) "selected contacts on this device" else "selected contacts wherever the workspace is shared",
        .network_egress => if (local_only) "local network path only" else "named network path only",
        .device_access => "selected hardware device only",
        .clipboard => "clipboard for this task",
        .camera => "selected camera only",
        .mic => "selected microphone only",
        .sensor => "selected sensor only",
        .location => "current location only",
        .screen_capture => "visible screen for this task",
        .notification_post => "notifications from this task",
        .background_execution => "declared background job only",
        .peer_ipc => "named local peer task only",
    };
}

pub fn requestedLeaseLabel(buffer: []u8, max_lease_ticks: u64) RenderError![]const u8 {
    var used: usize = 0;
    try appendRequestedLease(buffer, &used, max_lease_ticks);
    return buffer[0..used];
}

pub fn expiryLabel(buffer: []u8, expires_at_ticks: ?u64, now_ticks: u64) RenderError![]const u8 {
    var used: usize = 0;
    try appendExpiry(buffer, &used, expires_at_ticks, now_ticks);
    return buffer[0..used];
}

pub fn revocationHint(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access, .contacts => "remove this app from the object's share sheet",
        .network_egress => "turn off the network grant in Permission Review",
        .device_access, .camera, .mic, .sensor, .location, .screen_capture => "turn off the device grant in Permission Review",
        .clipboard => "turn off clipboard access in Permission Review",
        .notification_post => "mute or revoke notifications in Permission Review",
        .background_execution => "stop the background job from Activity",
        .peer_ipc => "disconnect the peer task in Permission Review",
    };
}

fn appendRights(buffer: []u8, used: *usize, rights: capability.CapabilityRights) RenderError!void {
    var first = true;
    try appendRight(buffer, used, &first, rights.has(.object_read) or rights.has(.contacts_read), "read");
    try appendRight(buffer, used, &first, rights.has(.object_write), "write");
    try appendRight(buffer, used, &first, rights.has(.device_use), "use device");
    try appendRight(buffer, used, &first, rights.has(.clipboard_read), "read clipboard");
    try appendRight(buffer, used, &first, rights.has(.clipboard_write), "write clipboard");
    try appendRight(buffer, used, &first, rights.has(.sensor_read), "read sensor");
    try appendRight(buffer, used, &first, rights.has(.background_run), "run in background");
    try appendRight(buffer, used, &first, rights.has(.network_local), "local network");
    try appendRight(buffer, used, &first, rights.has(.network_remote), "remote network");
    try appendRight(buffer, used, &first, rights.has(.ipc_peer), "peer task");
    try appendRight(buffer, used, &first, rights.has(.location_read), "read location");
    try appendRight(buffer, used, &first, rights.has(.screen_capture), "capture screen");
    try appendRight(buffer, used, &first, rights.has(.notification_post), "post notifications");
    if (first) try appendText(buffer, used, "none");
}

fn appendShareRights(buffer: []u8, used: *usize, grant: workspace.ShareGrant) RenderError!void {
    var first = true;
    try appendRight(buffer, used, &first, grant.can_read, "read");
    try appendRight(buffer, used, &first, grant.can_write, "write");
    try appendRight(buffer, used, &first, grant.can_admin, "manage");
    try appendRight(buffer, used, &first, grant.can_export, "export");
    if (first) try appendText(buffer, used, "none");
}

fn appendRight(
    buffer: []u8,
    used: *usize,
    first: *bool,
    enabled: bool,
    label: []const u8,
) RenderError!void {
    if (!enabled) return;
    if (!first.*) try appendText(buffer, used, ", ");
    try appendText(buffer, used, label);
    first.* = false;
}

fn appendRequestedLease(buffer: []u8, used: *usize, max_lease_ticks: u64) RenderError!void {
    if (max_lease_ticks == 0) {
        try appendText(buffer, used, "until revoked");
    } else {
        try appendFmt(buffer, used, "up to {d} ticks", .{max_lease_ticks});
    }
}

fn appendExpiry(buffer: []u8, used: *usize, expires_at_ticks: ?u64, now_ticks: u64) RenderError!void {
    const expiry = expires_at_ticks orelse {
        try appendText(buffer, used, "until revoked");
        return;
    };
    try appendShareExpiry(buffer, used, expiry, now_ticks);
}

fn appendShareExpiry(buffer: []u8, used: *usize, expires_at_ticks: u64, now_ticks: u64) RenderError!void {
    if (expires_at_ticks == 0) {
        try appendText(buffer, used, "until revoked");
    } else if (now_ticks > expires_at_ticks) {
        try appendFmt(buffer, used, "expired at tick {d}", .{expires_at_ticks});
    } else {
        try appendFmt(buffer, used, "tick {d} ({d} ticks left)", .{
            expires_at_ticks,
            expires_at_ticks - now_ticks,
        });
    }
}

fn appendPrincipal(buffer: []u8, used: *usize, id: principal.PrincipalId) RenderError!void {
    try appendFmt(buffer, used, "{s}:{d}", .{ principalKindLabel(id.kind), id.serial });
}

fn permissionLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "Object access",
        .network_egress => "Network access",
        .device_access => "Device access",
        .clipboard => "Clipboard access",
        .camera => "Camera access",
        .mic => "Microphone access",
        .sensor => "Sensor access",
        .location => "Location access",
        .contacts => "Contacts access",
        .screen_capture => "Screen capture",
        .notification_post => "Notifications",
        .background_execution => "Background activity",
        .peer_ipc => "Peer connection",
    };
}

fn principalKindLabel(kind: principal.PrincipalKind) []const u8 {
    return switch (kind) {
        .user => "user",
        .device => "device",
        .app => "app",
        .service => "service",
        .policy_authority => "policy",
        .team => "team",
    };
}

fn shareNetworkLabel(scope: workspace.ShareNetworkScope) []const u8 {
    return switch (scope) {
        .local_only => "this device only",
        .trusted_overlay => "trusted devices",
        .relay_assisted => "trusted relay",
        .unrestricted => "internet allowed",
    };
}

fn reshareLabel(policy: workspace.ResharePolicy) []const u8 {
    return switch (policy) {
        .owner_only => "recipient cannot reshare",
        .admin_only => "workspace admins can reshare",
        .grantee_allowed => "recipient can reshare",
    };
}

fn auditVisibilityLabel(visibility: workspace.AuditVisibility) []const u8 {
    return switch (visibility) {
        .owner_only => "visible to owner",
        .shared_participants => "visible to shared participants",
        .organization_policy => "visible to organization policy",
    };
}

fn backgroundStateLabel(state: background_dispatch.RecordState) []const u8 {
    return switch (state) {
        .running => "running",
        .delayed => "waiting",
        .denied => "blocked",
        .completed => "completed",
    };
}

fn backgroundTriggerLabel(trigger: manifest.BackgroundTrigger) []const u8 {
    return switch (trigger) {
        .user_approved_scheduled_job => "approved schedule",
        .push_event => "push event",
        .local_object_change => "local object change",
        .device_proximity => "nearby device",
        .sensor_rule => "sensor rule",
        .sync_completion => "sync completion",
        .media_export_completion => "media export completion",
        .organization_policy_task => "organization policy",
    };
}

fn backgroundNetworkLabel(mode: manifest.BackgroundNetworkMode) []const u8 {
    return switch (mode) {
        .unspecified => "not declared",
        .none => "no network",
        .local_network_only => "local network only",
        .named_service_identities => "named services only",
        .named_domains => "named domains only",
        .unrestricted_internet => "internet allowed",
    };
}

fn backgroundVisibilityLabel(visibility: manifest.BackgroundVisibility) []const u8 {
    return switch (visibility) {
        .unspecified => "not declared",
        .hidden => "hidden",
        .status_only => "status only",
        .user_visible => "visible",
        .audit_only => "audit only",
    };
}

fn appendText(buffer: []u8, used: *usize, text: []const u8) RenderError!void {
    if (used.* + text.len > buffer.len) return error.NoSpaceLeft;
    @memcpy(buffer[used.*..][0..text.len], text);
    used.* += text.len;
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) RenderError!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

test "humane grant scopes explain scope expiry and revocation" {
    const request = manifest.PermissionRequest{
        .kind = .network_egress,
        .resource = "relay.zigos.dev",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .required = false,
        .max_lease_ticks = 80,
    };
    const grant = GrantScope{
        .resource = "relay.zigos.dev",
        .expires_at_ticks = 120,
    };
    var buffer: [320]u8 = undefined;
    const rendered = try renderGrantScopeToBuffer(&buffer, request, grant, 100);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "named network path only") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "remote network") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "20 ticks left") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "turn off the network grant") != null);
}

test "humane share sheets describe object scoped grants" {
    const grant = try (workspace.ShareGrant{
        .principal_id = .{ .kind = .team, .serial = 7 },
        .can_read = true,
        .can_write = false,
        .expires_at_ticks = 80,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    }).withObjectScope(@import("../core/ids.zig").object(55), "documents/shared.md");
    var buffer: [360]u8 = undefined;
    const rendered = try renderShareSheetToBuffer(&buffer, 12, grant, 40);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "one object (documents/shared.md)") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "team:7") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "read") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "trusted devices") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "visible to shared participants") != null);
}

test "humane background activity and revocation receipts are user readable" {
    const record = background_dispatch.DispatchRecord{
        .id = 1,
        .task_id = 44,
        .background_task_id_len = 4,
        .background_task_id = [_]u8{ 's', 'y', 'n', 'c' } ++ [_]u8{0} ** (background_dispatch.MAX_TASK_ID_BYTES - 4),
        .trigger = .sync_completion,
        .expected_duration_seconds = 40,
        .budget = .{ .cpu_time_ticks = 1100, .memory_bytes = 96 * 1024 },
        .network = .local_network_only,
        .visibility = .status_only,
        .state = .running,
        .tick = 50,
    };
    var activity_buffer: [360]u8 = undefined;
    const activity = try renderBackgroundActivityToBuffer(&activity_buffer, record);
    try std.testing.expect(std.mem.indexOf(u8, activity, "job=sync") != null);
    try std.testing.expect(std.mem.indexOf(u8, activity, "visible=status only") != null);
    try std.testing.expect(std.mem.indexOf(u8, activity, "local network only") != null);

    var revoked_buffer: [240]u8 = undefined;
    const revoked = try renderRevocationReceiptToBuffer(&revoked_buffer, 9, .network_egress, "relay.zigos.dev", 77, "network grant revoked");
    try std.testing.expect(std.mem.indexOf(u8, revoked, "is off now") != null);
    try std.testing.expect(std.mem.indexOf(u8, revoked, "approve a new permission review") != null);
}

test "humane blocked explanations say what happened next" {
    const request = manifest.PermissionRequest{
        .kind = .camera,
        .resource = "camera.front",
        .rights = .{ .device = .{ .device_use = true } },
    };
    const explanation = denial_explanation.forPermissionDecision(.camera, abi.DenialReason.policy_denied);
    var buffer: [300]u8 = undefined;
    const rendered = try renderBlockedExplanationToBuffer(&buffer, "Camera Notes", request, explanation);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Blocked: Camera Notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "not granted") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Permission Review") != null);
}
