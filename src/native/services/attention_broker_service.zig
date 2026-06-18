const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const notification_center = @import("notification_center.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");

pub const Error = notification_center.Error || event_ledger.Error || error{
    MissingTaskBinding,
    NotificationTaskMismatch,
    PolicyDenied,
    SourceMismatch,
};

pub const PostRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    reason: notification_center.Reason,
    urgency: notification_center.Urgency,
    notification_task_id: ?u64 = null,
    detail: []const u8,
    expires_at_ticks: u64 = 0,
    suppression_policy: notification_center.SuppressionPolicy = .allow_repeat,
    now_ticks: u64,
};

pub const DismissRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    notification_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const QueryRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const QueryResult = struct {
    latest: ?notification_center.Notification = null,
    active_visible: u16 = 0,
    active_interruptions: u16 = 0,
};

pub const Service = struct {
    center: notification_center.Center = notification_center.Center.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn post(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: PostRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*notification_center.Notification {
        const notification_task_id = request.notification_task_id orelse request.task_id;
        if (request.task_id == 0 or notification_task_id == 0) {
            try recordAttention(ledger, request.subject, request.task_id, false, false, self.activeVisible(request.now_ticks), self.activeInterruptions(request.now_ticks), request.now_ticks, request.detail);
            return error.MissingTaskBinding;
        }
        const visible = self.activeVisible(request.now_ticks);
        const interruptions = self.activeInterruptions(request.now_ticks);
        const interruptive = notification_center.isInterruptive(request.urgency);
        const decision = policies.attentionDecision(subjects, .{
            .now_tick = request.now_ticks,
            .visible_notifications = visible,
            .interruptive_notifications = interruptions,
            .requests_interruption = interruptive,
            .critical = request.urgency == .critical,
        });
        try recordAttention(ledger, request.subject, request.task_id, decision.allowed, interruptive, visible, interruptions, request.now_ticks, request.detail);
        if (!decision.allowed) return error.PolicyDenied;

        const notification = try self.center.post(.{
            .source = request.subject,
            .reason = request.reason,
            .urgency = request.urgency,
            .task_id = notification_task_id,
            .detail = request.detail,
            .expires_at_ticks = request.expires_at_ticks,
            .suppression_policy = request.suppression_policy,
        });
        try recordNotification(ledger, notification.*, request.now_ticks);
        return notification;
    }

    pub fn dismiss(
        self: *Service,
        request: DismissRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*notification_center.Notification {
        const visible = self.activeVisible(request.now_ticks);
        const interruptions = self.activeInterruptions(request.now_ticks);
        const notification = self.center.find(request.notification_id) orelse {
            try recordAttention(ledger, request.subject, request.task_id, false, false, visible, interruptions, request.now_ticks, request.detail);
            return error.NotificationNotFound;
        };
        if (!notification.source.eql(request.subject)) {
            try recordAttention(ledger, request.subject, request.task_id, false, false, visible, interruptions, request.now_ticks, request.detail);
            return error.SourceMismatch;
        }
        if (notification.task_id) |task_id| {
            if (task_id != request.task_id) {
                try recordAttention(ledger, request.subject, request.task_id, false, false, visible, interruptions, request.now_ticks, request.detail);
                return error.NotificationTaskMismatch;
            }
        }

        const dismissed = try self.center.dismiss(request.notification_id);
        try recordAttention(ledger, request.subject, request.task_id, true, false, visible, interruptions, request.now_ticks, request.detail);
        try recordNotification(ledger, dismissed.*, request.now_ticks);
        return dismissed;
    }

    pub fn query(self: *const Service, request: QueryRequest, ledger: ?*event_ledger.Ledger) event_ledger.Error!QueryResult {
        const visible = self.activeVisible(request.now_ticks);
        const interruptions = self.activeInterruptions(request.now_ticks);
        try recordAttention(ledger, request.subject, request.task_id, true, false, visible, interruptions, request.now_ticks, request.detail);
        return .{
            .latest = self.center.latestVisible(request.now_ticks),
            .active_visible = visible,
            .active_interruptions = interruptions,
        };
    }

    pub fn activeVisible(self: *const Service, now_ticks: u64) u16 {
        return boundedU16(self.center.activeCount(now_ticks));
    }

    pub fn activeInterruptions(self: *const Service, now_ticks: u64) u16 {
        return boundedU16(self.center.activeInterruptionCount(now_ticks));
    }
};

fn recordAttention(
    ledger: ?*event_ledger.Ledger,
    subject: principal.PrincipalId,
    task_id: u64,
    allowed: bool,
    interruptive: bool,
    active_visible: u16,
    active_interruptions: u16,
    tick: u64,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordAttentionDecision(
            subject,
            task_id,
            allowed,
            interruptive,
            active_visible,
            active_interruptions,
            tick,
            detail,
        );
    }
}

fn recordNotification(
    ledger: ?*event_ledger.Ledger,
    notification: notification_center.Notification,
    tick: u64,
) event_ledger.Error!void {
    if (ledger) |active| try active.recordNotification(notification, tick);
}

fn boundedU16(value: usize) u16 {
    return @intCast(@min(value, @as(usize, std.math.maxInt(u16))));
}

test "attention broker gates posts dismisses notifications and redacts policy details" {
    const signing = @import("../core/signing.zig");

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 720 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 721 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "attention policy",
        .quiet_until_tick = 50,
        .max_visible_notifications = 2,
        .max_interruptive_notifications = 1,
        .allow_critical_interruption = false,
    }, signing.SignerIdentity{
        .label = "attention-broker-policy",
        .seed = signing.seedFromByte(0x74),
    });

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    var ledger = event_ledger.Ledger.init();

    try std.testing.expectError(error.MissingTaskBinding, service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 0,
        .reason = .policy_notice,
        .urgency = .passive,
        .detail = "private missing task binding detail",
        .now_ticks = 9,
    }, &ledger));

    const passive = try service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 900,
        .reason = .policy_notice,
        .urgency = .passive,
        .detail = "private passive detail",
        .now_ticks = 10,
    }, &ledger);
    try std.testing.expectEqual(@as(u64, 1), passive.id);
    try std.testing.expectEqual(@as(u64, 900), passive.task_id.?);
    try std.testing.expectEqual(@as(u16, 1), service.activeVisible(10));

    try std.testing.expectError(error.PolicyDenied, service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 900,
        .reason = .driver_restart,
        .urgency = .critical,
        .detail = "private critical denial detail",
        .now_ticks = 11,
    }, &ledger));

    const high = try service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 900,
        .reason = .sync_conflict,
        .urgency = .high,
        .notification_task_id = 77,
        .detail = "private conflict detail",
        .now_ticks = 60,
        .suppression_policy = .replace_same_source_reason_task,
    }, &ledger);
    try std.testing.expectEqual(@as(u16, 2), service.activeVisible(60));
    try std.testing.expectEqual(@as(u16, 1), service.activeInterruptions(60));

    try std.testing.expectError(error.PolicyDenied, service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 900,
        .reason = .update_ready,
        .urgency = .high,
        .detail = "private interruption budget denial",
        .now_ticks = 61,
    }, &ledger));

    const query = try service.query(.{
        .subject = user,
        .task_id = 901,
        .now_ticks = 62,
        .detail = "query latest visible",
    }, &ledger);
    try std.testing.expectEqual(high.id, query.latest.?.id);
    try std.testing.expectEqual(@as(u16, 2), query.active_visible);

    try std.testing.expectError(error.NotificationTaskMismatch, service.dismiss(.{
        .subject = app,
        .task_id = 900,
        .notification_id = high.id,
        .now_ticks = 63,
        .detail = "wrong task dismiss conflict",
    }, &ledger));

    const dismissed = try service.dismiss(.{
        .subject = app,
        .task_id = 77,
        .notification_id = high.id,
        .now_ticks = 64,
        .detail = "dismiss conflict",
    }, &ledger);
    try std.testing.expect(dismissed.suppressed);
    try std.testing.expectEqual(passive.id, service.center.latestVisible(65).?.id);

    try std.testing.expectError(error.SourceMismatch, service.dismiss(.{
        .subject = user,
        .task_id = 901,
        .notification_id = passive.id,
        .now_ticks = 66,
        .detail = "wrong source dismiss denied",
    }, &ledger));
    try std.testing.expectError(error.NotificationTaskMismatch, service.dismiss(.{
        .subject = app,
        .task_id = 901,
        .notification_id = passive.id,
        .now_ticks = 67,
        .detail = "wrong default task dismiss denied",
    }, &ledger));
    const passive_dismissed = try service.dismiss(.{
        .subject = app,
        .task_id = 900,
        .notification_id = passive.id,
        .now_ticks = 68,
        .detail = "dismiss default-bound passive",
    }, &ledger);
    try std.testing.expect(passive_dismissed.suppressed);
    try std.testing.expectEqual(@as(u16, 0), service.activeVisible(68));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.attention_policy_events >= 7);
    try std.testing.expect(summary.attention_interruptions_denied >= 2);
    try std.testing.expect(summary.protected_details_redacted >= summary.attention_policy_events);

    var buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private critical denial detail") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=attention_policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=notification") != null);
}
