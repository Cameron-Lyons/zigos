const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const humane_permissions = @import("humane_permissions.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const native_util = @import("../core/util.zig");
const policy_mediation = @import("policy_mediation.zig");

const yesNo = native_util.yesNo;

pub const MAX_REVIEW_DECISIONS: usize = policy_mediation.MAX_PERMISSION_DECISIONS;

pub const ReviewDecision = struct {
    kind: manifest.PermissionKind,
    resource: []const u8,
    allow: bool,
    local_only: bool = false,
    lease_ticks: ?u64 = null,
};

pub const ReviewCommand = struct {
    allow: bool,
    local_only: bool = false,
    lease_ticks: ?u64 = null,
};

pub const CommandError = error{
    EmptyCommand,
    InvalidCommand,
    InvalidLeaseTicks,
    InvalidRequestIndex,
};

pub const RenderError = CommandError || error{NoSpaceLeft};

pub const ReviewSession = struct {
    task_id: u64,
    bundle_id: []const u8,
    display_name: []const u8,
    decision_count: usize,
    decisions: [MAX_REVIEW_DECISIONS]ReviewDecision,
};

pub fn initSession(task_id: u64, bundle: *const manifest.BundleManifest, decisions: []const ReviewDecision) ReviewSession {
    var session = ReviewSession{
        .task_id = task_id,
        .bundle_id = bundle.bundle_id,
        .display_name = bundle.display_name,
        .decision_count = @min(decisions.len, MAX_REVIEW_DECISIONS),
        .decisions = [_]ReviewDecision{emptyDecision()} ** MAX_REVIEW_DECISIONS,
    };

    for (decisions[0..session.decision_count], 0..) |decision, index| {
        session.decisions[index] = decision;
    }
    return session;
}

pub fn renderToBuffer(
    buffer: []u8,
    session: *const ReviewSession,
    bundle: *const manifest.BundleManifest,
) ![]const u8 {
    var used: usize = 0;

    try appendFmt(buffer, &used, "Permission review for {s} [{s}] task={d}\n", .{
        session.display_name,
        session.bundle_id,
        session.task_id,
    });

    for (bundle.requested_permissions, 0..) |request, index| {
        try appendRequest(buffer, &used, session, bundle, request, index);
    }

    return buffer[0..used];
}

pub fn renderRequestToBuffer(
    buffer: []u8,
    session: *const ReviewSession,
    bundle: *const manifest.BundleManifest,
    request_index: usize,
) RenderError![]const u8 {
    if (request_index >= bundle.requested_permissions.len) {
        return error.InvalidRequestIndex;
    }

    var used: usize = 0;
    try appendRequest(buffer, &used, session, bundle, bundle.requested_permissions[request_index], request_index);
    return buffer[0..used];
}

pub fn decisionsToGrants(
    bundle: *const manifest.BundleManifest,
    decisions: []const ReviewDecision,
    now_ticks: u64,
    output: *[MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
) []const policy_mediation.UserGrant {
    var count: usize = 0;

    for (bundle.requested_permissions) |request| {
        const decision = findDecision(decisions, request.kind, request.resource) orelse continue;
        if (!decision.allow) continue;
        if (count >= output.len) break;

        output[count] = .{
            .kind = request.kind,
            .resource = request.resource,
            .allow = true,
            .local_only = request.local_only or decision.local_only,
            .expires_at_ticks = resolveDecisionExpiry(decision, request, now_ticks),
        };
        count += 1;
    }

    return output[0..count];
}

pub fn decisionFromCommand(request: manifest.PermissionRequest, command: ReviewCommand) ReviewDecision {
    return .{
        .kind = request.kind,
        .resource = request.resource,
        .allow = command.allow,
        .local_only = command.local_only,
        .lease_ticks = command.lease_ticks,
    };
}

pub fn parseCommand(line: []const u8) CommandError!ReviewCommand {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyCommand;

    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
    const verb = tokens.next() orelse return error.EmptyCommand;
    if (std.mem.eql(u8, verb, "deny")) {
        if (tokens.next() != null) return error.InvalidCommand;
        return .{ .allow = false };
    }
    if (!std.mem.eql(u8, verb, "allow")) {
        return error.InvalidCommand;
    }

    var command = ReviewCommand{ .allow = true };
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, "local") or std.mem.eql(u8, token, "local_only")) {
            command.local_only = true;
            continue;
        }
        if (std.mem.startsWith(u8, token, "lease=")) {
            const raw_ticks = token["lease=".len..];
            command.lease_ticks = std.fmt.parseInt(u64, raw_ticks, 10) catch return error.InvalidLeaseTicks;
            continue;
        }
        return error.InvalidCommand;
    }

    return command;
}

fn resolveDecisionExpiry(
    decision: ReviewDecision,
    request: manifest.PermissionRequest,
    now_ticks: u64,
) ?u64 {
    const requested_lease = decision.lease_ticks orelse {
        if (request.max_lease_ticks == 0) return null;
        return now_ticks + request.max_lease_ticks;
    };

    const clamped_lease = if (request.max_lease_ticks != 0)
        @min(requested_lease, request.max_lease_ticks)
    else
        requested_lease;
    return now_ticks + clamped_lease;
}

fn findDecision(
    decisions: []const ReviewDecision,
    kind: manifest.PermissionKind,
    resource: []const u8,
) ?ReviewDecision {
    for (decisions) |decision| {
        if (decision.kind != kind) continue;
        if (!std.mem.eql(u8, decision.resource, resource)) continue;
        return decision;
    }
    return null;
}

fn appendRequest(
    buffer: []u8,
    used: *usize,
    session: *const ReviewSession,
    bundle: *const manifest.BundleManifest,
    request: manifest.PermissionRequest,
    index: usize,
) !void {
    try appendFmt(buffer, used, "  [{d}/{d}] {s}: {s}\n", .{
        index + 1,
        bundle.requested_permissions.len,
        permissionLabel(request.kind),
        request.resource,
    });

    var rights_buffer: [160]u8 = undefined;
    try appendFmt(buffer, used, "    rights: {s}\n", .{rightsSummary(request.rights, &rights_buffer)});
    var scope_buffer: [320]u8 = undefined;
    const scope_summary = humane_permissions.renderRequestScopeToBuffer(&scope_buffer, request) catch "Scope: unavailable";
    try appendFmt(buffer, used, "    {s}\n", .{scope_summary});
    try appendFmt(buffer, used, "    required: {s} local_only: {s}\n", .{
        yesNo(request.required),
        yesNo(request.local_only),
    });
    if (request.kind == .background_execution) {
        if (manifest.findBackgroundTask(bundle.*, request.resource)) |task| {
            try appendFmt(buffer, used, "    trigger: {s}\n", .{backgroundTriggerLabel(task.trigger)});
            try appendFmt(buffer, used, "    expected duration: {d} seconds\n", .{task.expected_duration_seconds});
            try appendFmt(buffer, used, "    budget: cpu={d} memory={d} shared_memory={d}\n", .{
                task.budget.cpu_time_ticks,
                task.budget.memory_bytes,
                task.budget.shared_memory_bytes,
            });
            try appendFmt(buffer, used, "    network: {s} visibility: {s}\n", .{
                backgroundNetworkLabel(task.network),
                backgroundVisibilityLabel(task.visibility),
            });
        }
    }
    if (request.max_lease_ticks != 0) {
        try appendFmt(buffer, used, "    requested lease: {d} ticks\n", .{request.max_lease_ticks});
    }

    if (findDecision(session.decisions[0..session.decision_count], request.kind, request.resource)) |decision| {
        if (!decision.allow) {
            try appendText(buffer, used, "    decision: deny\n");
        } else if (decision.lease_ticks) |lease_ticks| {
            var expiry_buffer: [96]u8 = undefined;
            const expiry = humane_permissions.requestedLeaseLabel(&expiry_buffer, lease_ticks) catch "custom lease";
            try appendFmt(buffer, used, "    decision: allow local_only={s} lease={d} ticks\n", .{
                yesNo(decision.local_only),
                lease_ticks,
            });
            try appendFmt(buffer, used, "    decision lease summary: {s}\n", .{expiry});
        } else {
            try appendFmt(buffer, used, "    decision: allow local_only={s}\n", .{yesNo(decision.local_only)});
        }
    } else {
        try appendText(buffer, used, "    decision: pending\n");
    }
}

fn permissionLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "Object access",
        .network_egress => "Network egress",
        .device_access => "Device access",
        .clipboard => "Clipboard",
        .camera => "Camera",
        .mic => "Microphone",
        .sensor => "Sensor",
        .location => "Location",
        .contacts => "Contacts",
        .screen_capture => "Screen capture",
        .notification_post => "Notification posting",
        .background_execution => "Background execution",
        .peer_ipc => "Peer IPC",
    };
}

fn backgroundTriggerLabel(trigger: manifest.BackgroundTrigger) []const u8 {
    return switch (trigger) {
        .user_approved_scheduled_job => "user-approved scheduled job",
        .push_event => "push event",
        .local_object_change => "local object change",
        .device_proximity => "device proximity",
        .sensor_rule => "sensor rule",
        .sync_completion => "sync completion",
        .media_export_completion => "media/export completion",
        .organization_policy_task => "organization policy task",
    };
}

fn backgroundNetworkLabel(mode: manifest.BackgroundNetworkMode) []const u8 {
    return switch (mode) {
        .unspecified => "unspecified",
        .none => "none",
        .local_network_only => "local-network-only",
        .named_service_identities => "named-service-identities",
        .named_domains => "named-domains",
        .unrestricted_internet => "unrestricted-internet",
    };
}

fn backgroundVisibilityLabel(visibility: manifest.BackgroundVisibility) []const u8 {
    return switch (visibility) {
        .unspecified => "unspecified",
        .hidden => "hidden",
        .status_only => "status-only",
        .user_visible => "user-visible",
        .audit_only => "audit-only",
    };
}

fn rightsSummary(rights: capability.CapabilityRights, buffer: *[160]u8) []const u8 {
    var used: usize = 0;
    var first = true;

    appendRight(buffer, &used, &first, rights.has(.object_read), "object_read") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.object_write), "object_write") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.device_use), "device_use") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.clipboard_read), "clipboard_read") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.clipboard_write), "clipboard_write") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.sensor_read), "sensor_read") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.background_run), "background_run") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.network_local), "network_local") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.network_remote), "network_remote") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.ipc_peer), "ipc_peer") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.location_read), "location_read") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.contacts_read), "contacts_read") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.screen_capture), "screen_capture") catch return "rights_error";
    appendRight(buffer, &used, &first, rights.has(.notification_post), "notification_post") catch return "rights_error";

    if (first) {
        return "none";
    }
    return buffer[0..used];
}

fn appendRight(buffer: *[160]u8, used: *usize, first: *bool, enabled: bool, label: []const u8) !void {
    if (!enabled) return;
    if (!first.*) try appendText(buffer, used, ", ");
    try appendText(buffer, used, label);
    first.* = false;
}

fn appendText(buffer: []u8, used: *usize, text: []const u8) !void {
    if (used.* + text.len > buffer.len) return error.NoSpaceLeft;
    @memcpy(buffer[used.*..][0..text.len], text);
    used.* += text.len;
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
}

fn emptyDecision() ReviewDecision {
    return .{
        .kind = .object_access,
        .resource = "",
        .allow = false,
    };
}

test "decisionsToGrants clamps lease duration to the manifest request" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
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
    const decisions = [_]ReviewDecision{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .allow = true,
            .local_only = true,
            .lease_ticks = 200,
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = decisionsToGrants(&bundle, &decisions, 10, &grants_buffer);

    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 60), grants[0].expires_at_ticks);
}

test "renderToBuffer includes bundle name, permission labels, and decisions" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
    const decisions = [_]ReviewDecision{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .allow = true,
            .local_only = true,
            .lease_ticks = 400,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .allow = false,
        },
    };
    const session = initSession(3, &bundle, &decisions);

    var buffer: [2048]u8 = undefined;
    const rendered = try renderToBuffer(&buffer, &session, &bundle);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Permission review for Notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Object access") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision: allow") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision: deny") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Scope: this object on this device") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "revoke: remove this app from the object's share sheet") != null);
}

test "permission review does not grant hidden device access for the example writer manifest" {
    const bundle = manifest_fixtures.exampleWriterBundle();
    try manifest.validate(bundle);
    try manifest.validateApplicationPackaging(bundle);

    const decisions = [_]ReviewDecision{
        decisionFromCommand(bundle.requested_permissions[0], try parseCommand("allow local")),
        decisionFromCommand(bundle.requested_permissions[1], try parseCommand("deny")),
        decisionFromCommand(bundle.requested_permissions[2], try parseCommand("allow lease=30")),
        .{
            .kind = .camera,
            .resource = "camera.front",
            .allow = true,
            .local_only = true,
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = decisionsToGrants(&bundle, &decisions, 20, &grants_buffer);

    try std.testing.expectEqual(@as(usize, 2), grants.len);
    for (grants) |grant| {
        try std.testing.expect(grant.kind != .camera);
        try std.testing.expect(grant.kind != .mic);
        try std.testing.expect(grant.kind != .location);
    }

    const session = initSession(9, &bundle, &decisions);
    var buffer: [2048]u8 = undefined;
    const rendered = try renderToBuffer(&buffer, &session, &bundle);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Permission review for Writer") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Background execution") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "sync-complete") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "expected duration: 30 seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "network: none") != null);
}

test "parseCommand accepts allow local leases and deny commands" {
    const allow = try parseCommand("allow local lease=45");
    try std.testing.expect(allow.allow);
    try std.testing.expect(allow.local_only);
    try std.testing.expectEqual(@as(?u64, 45), allow.lease_ticks);

    const deny = try parseCommand("deny");
    try std.testing.expect(!deny.allow);
    try std.testing.expect(!deny.local_only);
    try std.testing.expectEqual(@as(?u64, null), deny.lease_ticks);
}

test "renderRequestToBuffer marks undecided requests as pending" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
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
    const session = initSession(4, &bundle, &.{});

    var buffer: [512]u8 = undefined;
    const rendered = try renderRequestToBuffer(&buffer, &session, &bundle, 0);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Network egress") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision: pending") != null);
}

test "renderToBuffer labels expanded location contacts screen capture and notification rights" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .location,
            .resource = "location.current",
            .rights = .{ .device = .{ .location_read = true } },
            .required = false,
        },
        .{
            .kind = .contacts,
            .resource = "contacts://personal",
            .rights = .{ .object = .{ .contacts_read = true } },
        },
        .{
            .kind = .screen_capture,
            .resource = "display:main",
            .rights = .{ .device = .{ .screen_capture = true } },
            .required = false,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .task = .{ .notification_post = true } },
            .required = false,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.organizer",
        .display_name = "Organizer",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
    const decisions = [_]ReviewDecision{
        .{ .kind = .location, .resource = "location.current", .allow = true },
    };
    const session = initSession(44, &bundle, &decisions);
    var buffer: [2048]u8 = undefined;
    const rendered = try renderToBuffer(&buffer, &session, &bundle);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Location") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Contacts") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Screen capture") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Notification posting") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "location_read") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "contacts_read") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "screen_capture") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "notification_post") != null);
}
