const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const humane_permissions = @import("humane_permissions.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const native_util = @import("../core/util.zig");
const policy_mediation = @import("policy_mediation.zig");
const units = @import("../core/units.zig");

const yesNo = native_util.yesNo;
const RIGHTS_SUMMARY_BUFFER_BYTES: usize = 160;
const SCOPE_SUMMARY_BUFFER_BYTES: usize = 320;
const EGRESS_INTENT_BUFFER_BYTES: usize = 180;
const LEASE_SUMMARY_BUFFER_BYTES: usize = 96;
const REVIEW_RENDER_BUFFER_BYTES: usize = units.kibibytes(2);
const REVIEW_REQUEST_BUFFER_BYTES: usize = 512;

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

pub const SessionError = error{
    TooManyRequests,
    TooManyDecisions,
    DecisionOrderMismatch,
};

pub const ReviewSession = struct {
    task_id: u64,
    bundle: *const manifest.BundleManifest,
    decision_count: usize,
    decisions: [MAX_REVIEW_DECISIONS]ReviewCommand,

    pub fn decisionAt(self: *const ReviewSession, request_index: usize) ?ReviewCommand {
        if (request_index >= self.decision_count) return null;
        return self.decisions[request_index];
    }
};

pub fn initSession(
    task_id: u64,
    bundle: *const manifest.BundleManifest,
    decisions: []const ReviewDecision,
) SessionError!ReviewSession {
    if (bundle.requested_permissions.len > MAX_REVIEW_DECISIONS) return error.TooManyRequests;
    if (decisions.len > bundle.requested_permissions.len) return error.TooManyDecisions;

    var session = ReviewSession{
        .task_id = task_id,
        .bundle = bundle,
        .decision_count = decisions.len,
        .decisions = undefined,
    };

    for (decisions, 0..) |decision, index| {
        const request = bundle.requested_permissions[index];
        if (decision.kind != request.kind or !std.mem.eql(u8, decision.resource, request.resource)) {
            return error.DecisionOrderMismatch;
        }
        session.decisions[index] = .{
            .allow = decision.allow,
            .local_only = decision.local_only,
            .lease_ticks = decision.lease_ticks,
        };
    }
    return session;
}

pub fn renderToBuffer(
    buffer: []u8,
    session: *const ReviewSession,
) ![]const u8 {
    var used: usize = 0;

    try appendText(buffer, &used, "Permission review for ");
    try appendText(buffer, &used, session.bundle.display_name);
    try appendText(buffer, &used, " [");
    try appendText(buffer, &used, session.bundle.bundle_id);
    try appendText(buffer, &used, "] task=");
    try appendUnsigned(buffer, &used, session.task_id);
    try appendText(buffer, &used, "\n");

    for (session.bundle.requested_permissions, 0..) |request, index| {
        try appendRequest(buffer, &used, session, request, index);
    }

    return buffer[0..used];
}

pub fn renderRequestToBuffer(
    buffer: []u8,
    session: *const ReviewSession,
    request_index: usize,
) RenderError![]const u8 {
    if (request_index >= session.bundle.requested_permissions.len) {
        return error.InvalidRequestIndex;
    }

    var used: usize = 0;
    try appendRequest(buffer, &used, session, session.bundle.requested_permissions[request_index], request_index);
    return buffer[0..used];
}

pub fn decisionsToGrants(
    session: *const ReviewSession,
    now_ticks: u64,
    output: *[MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
) []const policy_mediation.UserGrant {
    var count: usize = 0;

    for (session.bundle.requested_permissions, 0..) |request, index| {
        const decision = session.decisionAt(index) orelse continue;
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
    decision: ReviewCommand,
    request: manifest.PermissionRequest,
    now_ticks: u64,
) ?u64 {
    const requested_lease = decision.lease_ticks orelse {
        if (request.max_lease_ticks == 0) return null;
        return leaseEndFromTicks(now_ticks, request.max_lease_ticks);
    };

    const clamped_lease = if (request.max_lease_ticks != 0)
        @min(requested_lease, request.max_lease_ticks)
    else
        requested_lease;
    return leaseEndFromTicks(now_ticks, clamped_lease);
}

fn leaseEndFromTicks(now_ticks: u64, lease_ticks: u64) u64 {
    return std.math.add(u64, now_ticks, lease_ticks) catch std.math.maxInt(u64);
}

fn appendRequest(
    buffer: []u8,
    used: *usize,
    session: *const ReviewSession,
    request: manifest.PermissionRequest,
    index: usize,
) !void {
    const bundle = session.bundle;
    try appendText(buffer, used, "  [");
    try appendUnsigned(buffer, used, @intCast(index + 1));
    try appendText(buffer, used, "/");
    try appendUnsigned(buffer, used, @intCast(bundle.requested_permissions.len));
    try appendText(buffer, used, "] ");
    try appendText(buffer, used, manifest.permissionDisplayLabel(request.kind));
    try appendText(buffer, used, ": ");
    try appendText(buffer, used, request.resource);
    try appendText(buffer, used, "\n");

    var rights_buffer: [RIGHTS_SUMMARY_BUFFER_BYTES]u8 = undefined;
    try appendText(buffer, used, "    rights: ");
    try appendText(buffer, used, rightsSummary(request.rights, &rights_buffer));
    try appendText(buffer, used, "\n");
    var scope_buffer: [SCOPE_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const scope_summary = humane_permissions.renderRequestScopeToBuffer(&scope_buffer, request) catch "Scope: unavailable";
    try appendText(buffer, used, "    ");
    try appendText(buffer, used, scope_summary);
    try appendText(buffer, used, "\n");
    if (request.kind == .network_egress and request.egress_intent.declared()) {
        var intent_buffer: [EGRESS_INTENT_BUFFER_BYTES]u8 = undefined;
        try appendFmt(buffer, used, "    data egress intent: {s}\n", .{dataEgressIntentSummary(request.egress_intent, &intent_buffer)});
    }
    try appendText(buffer, used, "    required: ");
    try appendText(buffer, used, yesNo(request.required));
    try appendText(buffer, used, " local_only: ");
    try appendText(buffer, used, yesNo(request.local_only));
    try appendText(buffer, used, "\n");
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
        try appendText(buffer, used, "    requested lease: ");
        try appendUnsigned(buffer, used, request.max_lease_ticks);
        try appendText(buffer, used, " ticks\n");
    }

    if (session.decisionAt(index)) |decision| {
        if (!decision.allow) {
            try appendText(buffer, used, "    decision: deny\n");
        } else if (decision.lease_ticks) |lease_ticks| {
            var expiry_buffer: [LEASE_SUMMARY_BUFFER_BYTES]u8 = undefined;
            const expiry = humane_permissions.requestedLeaseLabel(&expiry_buffer, lease_ticks) catch "custom lease";
            try appendText(buffer, used, "    decision: allow local_only=");
            try appendText(buffer, used, yesNo(decision.local_only));
            try appendText(buffer, used, " lease=");
            try appendUnsigned(buffer, used, lease_ticks);
            try appendText(buffer, used, " ticks\n    decision lease summary: ");
            try appendText(buffer, used, expiry);
            try appendText(buffer, used, "\n");
        } else {
            try appendFmt(buffer, used, "    decision: allow local_only={s}\n", .{yesNo(decision.local_only)});
        }
        if (decision.allow) {
            try appendCompactReceipt(buffer, used, request, decision);
        }
    } else {
        try appendText(buffer, used, "    decision: pending\n");
    }
}

fn appendCompactReceipt(
    buffer: []u8,
    used: *usize,
    request: manifest.PermissionRequest,
    decision: ReviewCommand,
) !void {
    try appendText(buffer, used, "    receipt: granted=");
    try appendText(buffer, used, manifest.permissionDisplayLabel(request.kind));
    try appendText(buffer, used, " duration=");
    if (decision.lease_ticks) |lease_ticks| {
        try appendUnsigned(buffer, used, lease_ticks);
        try appendText(buffer, used, " ticks");
    } else if (request.max_lease_ticks != 0) {
        try appendText(buffer, used, "up to ");
        try appendUnsigned(buffer, used, request.max_lease_ticks);
        try appendText(buffer, used, " ticks");
    } else {
        try appendText(buffer, used, "until revoked");
    }
    try appendText(buffer, used, " data_leaves=");
    if (request.kind == .network_egress) {
        var intent_buffer: [EGRESS_INTENT_BUFFER_BYTES]u8 = undefined;
        try appendText(buffer, used, dataEgressIntentSummary(request.egress_intent, &intent_buffer));
    } else {
        try appendText(buffer, used, "none");
    }
    try appendText(buffer, used, " revoke=Permission Review\n");
}

fn dataEgressIntentSummary(intent: manifest.DataEgressIntent, buffer: *[EGRESS_INTENT_BUFFER_BYTES]u8) []const u8 {
    return switch (intent.kind) {
        .unspecified => "unspecified data egress",
        .sync_object => std.fmt.bufPrint(buffer, "sync object {s} with {s}", .{
            intent.object,
            intent.principal,
        }) catch "sync object",
        .call_service => std.fmt.bufPrint(buffer, "call service {s}", .{intent.service}) catch "call service",
        .publish_event => std.fmt.bufPrint(buffer, "publish event {s}", .{intent.event_type}) catch "publish event",
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

fn rightsSummary(rights: capability.CapabilityRights, buffer: *[RIGHTS_SUMMARY_BUFFER_BYTES]u8) []const u8 {
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

fn appendRight(buffer: *[RIGHTS_SUMMARY_BUFFER_BYTES]u8, used: *usize, first: *bool, enabled: bool, label: []const u8) !void {
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

fn appendUnsigned(buffer: []u8, used: *usize, value: u64) !void {
    var number_buffer: [20]u8 = undefined;
    const number_len = std.fmt.printInt(&number_buffer, value, 10, .lower, .{});
    try appendText(buffer, used, number_buffer[0..number_len]);
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
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
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
                .principal = "trusted-devices",
            },
        },
    };
    const bundle = manifest_fixtures.basicNotesBundle(&permissions);
    const decisions = [_]ReviewDecision{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .allow = true,
            .local_only = true,
            .lease_ticks = 200,
        },
    };
    const session = try initSession(1, &bundle, &decisions);
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = decisionsToGrants(&session, 10, &grants_buffer);

    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 60), grants[0].expires_at_ticks);
}

test "decisionsToGrants saturates lease expiry instead of wrapping" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
            .local_only = true,
        },
    };
    const bundle = manifest_fixtures.basicNotesBundle(&permissions);
    const decisions = [_]ReviewDecision{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .allow = true,
            .local_only = true,
            .lease_ticks = 20,
        },
    };
    const session = try initSession(1, &bundle, &decisions);
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = decisionsToGrants(&session, std.math.maxInt(u64) - 5, &grants_buffer);

    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), grants[0].expires_at_ticks);
}

test "renderToBuffer preserves the exact permission review text" {
    const expected =
        \\Permission review for Notes [app.notes] task=3
        \\  [1/2] Object access: workspace:notes
        \\    rights: object_read, object_write
        \\    Scope: this object on this device; rights: read, write; lease: until revoked; data leaves: none; revoke: remove this app from the object's share sheet
        \\    required: yes local_only: yes
        \\    decision: allow local_only=yes lease=400 ticks
        \\    decision lease summary: up to 400 ticks
        \\    receipt: granted=Object access duration=400 ticks data_leaves=none revoke=Permission Review
        \\  [2/2] Clipboard: clipboard
        \\    rights: clipboard_read
        \\    Scope: clipboard for this task; rights: read clipboard; lease: until revoked; data leaves: none; revoke: turn off clipboard access in Permission Review
        \\    required: no local_only: no
        \\    decision: deny
        \\
    ;
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
    const bundle = manifest_fixtures.basicNotesBundle(&permissions);
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
    const session = try initSession(3, &bundle, &decisions);

    var exact_buffer: [expected.len]u8 = undefined;
    try std.testing.expectEqualStrings(expected, try renderToBuffer(&exact_buffer, &session));

    var undersized_backing = [_]u8{0xa5} ** expected.len;
    try std.testing.expectError(
        error.NoSpaceLeft,
        renderToBuffer(undersized_backing[0 .. expected.len - 1], &session),
    );
    try std.testing.expectEqual(@as(u8, 0xa5), undersized_backing[expected.len - 1]);
}

test "permission review renders maximum unsigned values in exact buffers" {
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
    try std.testing.expectError(error.TooManyDecisions, initSession(9, &bundle, &decisions));

    const session = try initSession(9, &bundle, decisions[0..bundle.requested_permissions.len]);
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = decisionsToGrants(&session, 20, &grants_buffer);

    try std.testing.expectEqual(@as(usize, 2), grants.len);
    for (grants) |grant| {
        try std.testing.expect(grant.kind != .camera);
        try std.testing.expect(grant.kind != .mic);
        try std.testing.expect(grant.kind != .location);
    }

    var buffer: [REVIEW_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderToBuffer(&buffer, &session);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Permission review for Writer") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Background execution") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "sync-complete") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "expected duration: 30 seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "network: none") != null);
}

test "review sessions reject decisions that do not follow manifest order" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    const bundle = manifest_fixtures.basicNotesBundle(&permissions);
    const decisions = [_]ReviewDecision{
        decisionFromCommand(permissions[1], .{ .allow = true }),
    };

    try std.testing.expectError(error.DecisionOrderMismatch, initSession(12, &bundle, &decisions));
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
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
                .principal = "trusted-devices",
            },
        },
    };
    const bundle = manifest_fixtures.basicNotesBundle(&permissions);
    const session = try initSession(4, &bundle, &.{});

    var buffer: [REVIEW_REQUEST_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderRequestToBuffer(&buffer, &session, 0);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Data egress") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "sync object workspace:notes with trusted-devices") != null);
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
    const session = try initSession(44, &bundle, &decisions);
    var buffer: [REVIEW_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderToBuffer(&buffer, &session);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Location") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Contacts") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Screen capture") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Notification posting") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "location_read") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "contacts_read") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "screen_capture") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "notification_post") != null);
}
