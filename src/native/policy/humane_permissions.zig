const std = @import("std");
const abi = @import("../core/abi.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const capability = @import("../kernel_api/capability.zig");
const denial_explanation = @import("denial_explanation.zig");
const manifest = @import("manifest.zig");
const principal = @import("../core/principal.zig");
const units = @import("../core/units.zig");
const workspace = @import("../storage/workspace.zig");

pub const RenderError = error{NoSpaceLeft};
const GRANT_SCOPE_RENDER_BUFFER_BYTES: usize = 320;
const PERMISSION_RECEIPT_BUFFER_BYTES: usize = 512;
const SHARE_SHEET_RENDER_BUFFER_BYTES: usize = 360;
const BACKGROUND_ACTIVITY_BUFFER_BYTES: usize = 360;
const REVOCATION_RECEIPT_BUFFER_BYTES: usize = 240;
const BLOCKED_EXPLANATION_BUFFER_BYTES: usize = 300;

pub const GrantScope = struct {
    resource: []const u8 = "",
    local_only: bool = false,
    expires_at_ticks: ?u64 = null,
};

pub const PermissionReceipt = struct {
    task_id: u64 = 0,
    bundle_id: []const u8 = "",
    display_name: []const u8 = "",
    capability_id: u64 = 0,
    request: manifest.PermissionRequest,
    local_only: bool = false,
    expires_at_ticks: ?u64 = null,
    why: []const u8 = "",
};

pub fn renderRequestScopeToBuffer(
    buffer: []u8,
    request: manifest.PermissionRequest,
) RenderError![]const u8 {
    var used: usize = 0;
    try appendText(buffer, &used, "Scope: ");
    try appendText(buffer, &used, scopeSummaryLabel(request.kind, request.local_only));
    if (request.kind == .network_egress and request.egress_intent.declared()) {
        try appendText(buffer, &used, "; intent: ");
        try appendDataEgressIntent(buffer, &used, request.egress_intent);
    }
    try appendText(buffer, &used, "; rights: ");
    try appendRights(buffer, &used, request.rights);
    try appendText(buffer, &used, "; lease: ");
    try appendRequestedLease(buffer, &used, request.max_lease_ticks);
    try appendText(buffer, &used, "; data leaves: ");
    try appendDataLeaving(buffer, &used, request);
    try appendText(buffer, &used, "; revoke: ");
    try appendText(buffer, &used, revocationHint(request.kind));
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

pub fn renderPermissionReceiptToBuffer(
    buffer: []u8,
    receipt: PermissionReceipt,
    now_ticks: u64,
) RenderError![]const u8 {
    var used: usize = 0;
    const app_label = if (receipt.display_name.len != 0) receipt.display_name else if (receipt.bundle_id.len != 0) receipt.bundle_id else "app";
    const local_only = receipt.request.local_only or receipt.local_only;
    try appendFmt(buffer, &used, "Permission receipt: app={s}", .{app_label});
    if (receipt.bundle_id.len != 0) {
        try appendFmt(buffer, &used, " bundle={s}", .{receipt.bundle_id});
    }
    if (receipt.task_id != 0) {
        try appendFmt(buffer, &used, " task={d}", .{receipt.task_id});
    }
    if (receipt.capability_id != 0) {
        try appendFmt(buffer, &used, " capability={d}", .{receipt.capability_id});
    }
    try appendFmt(buffer, &used, "; granted: {s} for {s}; rights: ", .{
        permissionLabel(receipt.request.kind),
        receipt.request.resource,
    });
    try appendRights(buffer, &used, receipt.request.rights);
    try appendText(buffer, &used, "; why: ");
    if (receipt.why.len != 0) {
        try appendText(buffer, &used, receipt.why);
    } else {
        try appendPermissionReason(buffer, &used, app_label, receipt.request);
    }
    try appendText(buffer, &used, "; duration: ");
    try appendExpiry(buffer, &used, receipt.expires_at_ticks, now_ticks);
    try appendFmt(buffer, &used, "; scope: {s}; data leaves: ", .{
        scopeSummaryLabel(receipt.request.kind, local_only),
    });
    try appendDataLeaving(buffer, &used, receipt.request);
    try appendFmt(buffer, &used, "; revoke: {s}", .{revocationHint(receipt.request.kind)});
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
        .network_egress => if (local_only) "local data route only" else "named data route only",
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

pub fn revocationHint(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access, .contacts => "remove this app from the object's share sheet",
        .network_egress => "turn off the data route grant in Permission Review",
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
        try appendText(buffer, used, "up to ");
        try appendUnsigned(buffer, used, max_lease_ticks);
        try appendText(buffer, used, " ticks");
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
        .network_egress => "Data egress",
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
        .expired => "expired",
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

fn appendDataEgressIntent(buffer: []u8, used: *usize, intent: manifest.DataEgressIntent) RenderError!void {
    switch (intent.kind) {
        .unspecified => try appendText(buffer, used, "unspecified data egress"),
        .sync_object => try appendFmt(buffer, used, "sync object {s} with {s}", .{
            intent.object,
            intent.principal,
        }),
        .call_service => try appendFmt(buffer, used, "call service {s}", .{intent.service}),
        .publish_event => try appendFmt(buffer, used, "publish event {s}", .{intent.event_type}),
    }
}

fn appendDataLeaving(buffer: []u8, used: *usize, request: manifest.PermissionRequest) RenderError!void {
    if (request.kind == .network_egress) {
        if (request.egress_intent.declared()) {
            try appendDataEgressIntent(buffer, used, request.egress_intent);
        } else {
            try appendText(buffer, used, "network route ");
            try appendText(buffer, used, request.resource);
        }
        return;
    }

    try appendText(buffer, used, "none");
}

fn appendPermissionReason(
    buffer: []u8,
    used: *usize,
    display_name: []const u8,
    request: manifest.PermissionRequest,
) RenderError!void {
    switch (request.kind) {
        .object_access => try appendFmt(buffer, used, "{s} can read or write this object in the current task", .{display_name}),
        .network_egress => if (request.egress_intent.declared())
            try appendDataEgressIntent(buffer, used, request.egress_intent)
        else
            try appendFmt(buffer, used, "{s} can use this approved data route", .{display_name}),
        .device_access => try appendFmt(buffer, used, "{s} can use the selected hardware device", .{display_name}),
        .clipboard => try appendFmt(buffer, used, "{s} can use clipboard content in this task", .{display_name}),
        .camera => try appendFmt(buffer, used, "{s} can use the selected camera", .{display_name}),
        .mic => try appendFmt(buffer, used, "{s} can use the selected microphone", .{display_name}),
        .sensor => try appendFmt(buffer, used, "{s} can read the selected sensor", .{display_name}),
        .location => try appendFmt(buffer, used, "{s} can read the current location", .{display_name}),
        .contacts => try appendFmt(buffer, used, "{s} can read selected contacts", .{display_name}),
        .screen_capture => try appendFmt(buffer, used, "{s} can capture the visible screen", .{display_name}),
        .notification_post => try appendFmt(buffer, used, "{s} can post task notifications", .{display_name}),
        .background_execution => try appendFmt(buffer, used, "{s} can run the declared background job", .{display_name}),
        .peer_ipc => try appendFmt(buffer, used, "{s} can connect to the named peer task", .{display_name}),
    }
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

fn appendUnsigned(buffer: []u8, used: *usize, value: u64) RenderError!void {
    var number_buffer: [20]u8 = undefined;
    const number_len = std.fmt.printInt(&number_buffer, value, 10, .lower, .{});
    try appendText(buffer, used, number_buffer[0..number_len]);
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) RenderError!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

test "humane permission rendering handles maximum unsigned values" {
    const expected = "18446744073709551615";
    const maximum: u64 = std.math.maxInt(u64);
    var exact_buffer: [expected.len]u8 = undefined;
    var used: usize = 0;

    try appendUnsigned(&exact_buffer, &used, maximum);
    try std.testing.expectEqual(expected.len, used);
    try std.testing.expectEqualStrings(expected, exact_buffer[0..used]);

    var undersized_backing = [_]u8{0xa5} ** expected.len;
    used = 0;
    try std.testing.expectError(
        error.NoSpaceLeft,
        appendUnsigned(undersized_backing[0 .. expected.len - 1], &used, maximum),
    );
    try std.testing.expectEqual(@as(u8, 0xa5), undersized_backing[expected.len - 1]);
}

test "humane grant scopes explain scope expiry and revocation" {
    const request = manifest.PermissionRequest{
        .kind = .network_egress,
        .resource = "relay.zigos.dev",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .required = false,
        .max_lease_ticks = 80,
        .egress_intent = .{
            .kind = .call_service,
            .service = "relay.zigos.dev",
        },
    };
    const grant = GrantScope{
        .resource = "relay.zigos.dev",
        .expires_at_ticks = 120,
    };
    var buffer: [GRANT_SCOPE_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderGrantScopeToBuffer(&buffer, request, grant, 100);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "named data route only") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "remote network") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "20 ticks left") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "turn off the data route grant") != null);
}

test "humane permission receipts include grant reason duration egress and revocation" {
    const request = manifest.PermissionRequest{
        .kind = .network_egress,
        .resource = "relay.zigos.dev",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .max_lease_ticks = 80,
        .egress_intent = .{
            .kind = .sync_object,
            .object = "workspace://trip/documents/plan.md",
            .principal = "trusted-devices",
        },
    };
    var buffer: [PERMISSION_RECEIPT_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderPermissionReceiptToBuffer(&buffer, .{
        .task_id = 42,
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .capability_id = 99,
        .request = request,
        .expires_at_ticks = 180,
        .why = "user approved Permission Review",
    }, 100);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "granted: Data egress") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "why: user approved Permission Review") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "80 ticks left") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data leaves: sync object workspace://trip/documents/plan.md with trusted-devices") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "revoke: turn off the data route grant") != null);
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
    var buffer: [SHARE_SHEET_RENDER_BUFFER_BYTES]u8 = undefined;
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
        .budget = .{ .cpu_time_ticks = 1100, .memory_bytes = units.kibibytes(96) },
        .network = .local_network_only,
        .visibility = .status_only,
        .state = .running,
        .tick = 50,
    };
    var activity_buffer: [BACKGROUND_ACTIVITY_BUFFER_BYTES]u8 = undefined;
    const activity = try renderBackgroundActivityToBuffer(&activity_buffer, record);
    try std.testing.expect(std.mem.indexOf(u8, activity, "job=sync") != null);
    try std.testing.expect(std.mem.indexOf(u8, activity, "visible=status only") != null);
    try std.testing.expect(std.mem.indexOf(u8, activity, "local network only") != null);

    var revoked_buffer: [REVOCATION_RECEIPT_BUFFER_BYTES]u8 = undefined;
    const revoked = try renderRevocationReceiptToBuffer(&revoked_buffer, 9, .network_egress, "relay.zigos.dev", 77, "data route grant revoked");
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
    var buffer: [BLOCKED_EXPLANATION_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderBlockedExplanationToBuffer(&buffer, "Camera Notes", request, explanation);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Blocked: Camera Notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "not granted") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Permission Review") != null);
}
