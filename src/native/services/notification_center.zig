const std = @import("std");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const copyText = native_util.copyText;

pub const MAX_NOTIFICATIONS: usize = 32;
pub const MAX_DETAIL_BYTES: usize = 96;

pub const Reason = enum(u8) {
    permission_request,
    sync_conflict,
    driver_restart,
    update_ready,
    media_export_complete,
    print_complete,
    policy_notice,
};

pub const Urgency = enum(u8) {
    passive,
    normal,
    high,
    critical,
};

pub const SuppressionPolicy = enum(u8) {
    allow_repeat,
    replace_same_source_reason,
    replace_same_source_reason_task,
};

pub const AttentionDecisionReason = enum(u8) {
    allowed,
    quiet_mode,
    visible_budget_exhausted,
    interruption_budget_exhausted,
    critical_interruption_denied,
};

pub const AttentionPolicy = struct {
    quiet_until_ticks: u64 = 0,
    max_visible_notifications: usize = 0,
    max_interruptions_per_window: u16 = 0,
    allow_critical_interruptions: bool = true,
};

pub const AttentionDecision = struct {
    allowed: bool,
    reason: AttentionDecisionReason = .allowed,
    active_visible: usize = 0,
    active_interruptions: usize = 0,
};

const AttentionCounts = struct {
    active_visible: usize = 0,
    active_interruptions: usize = 0,
};

pub const AttentionPostResult = struct {
    decision: AttentionDecision,
    notification: ?*Notification = null,
};

pub const PostRequest = struct {
    source: principal.PrincipalId,
    reason: Reason,
    urgency: Urgency,
    task_id: ?u64 = null,
    detail: []const u8,
    expires_at_ticks: u64 = 0,
    suppression_policy: SuppressionPolicy = .allow_repeat,
};

pub const Notification = struct {
    id: u64,
    reason: Reason,
    urgency: Urgency,
    source: principal.PrincipalId,
    task_id: ?u64,
    expires_at_ticks: u64,
    suppression_policy: SuppressionPolicy,
    suppressed: bool,
    detail_len: usize,
    detail: [MAX_DETAIL_BYTES]u8,

    pub fn detailSlice(self: *const Notification) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn isActive(self: *const Notification, now_ticks: u64) bool {
        if (self.suppressed) return false;
        return self.expires_at_ticks == 0 or now_ticks < self.expires_at_ticks;
    }
};

pub const Error = error{
    NotificationTableFull,
    NotificationNotFound,
};

const NotificationSlot = struct {
    in_use: bool = false,
    notification: Notification = zeroNotification(),
};

pub const Center = struct {
    next_notification_id: u64 = 1,
    notifications: [MAX_NOTIFICATIONS]NotificationSlot = [_]NotificationSlot{NotificationSlot{}} ** MAX_NOTIFICATIONS,

    pub fn init() Center {
        return .{};
    }

    pub fn post(self: *Center, request: PostRequest) Error!*Notification {
        self.applySuppressionPolicy(request);
        for (&self.notifications) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.notification = zeroNotification();
            slot.notification.id = self.next_notification_id;
            self.next_notification_id += 1;
            slot.notification.reason = request.reason;
            slot.notification.urgency = request.urgency;
            slot.notification.source = request.source;
            slot.notification.task_id = request.task_id;
            slot.notification.expires_at_ticks = request.expires_at_ticks;
            slot.notification.suppression_policy = request.suppression_policy;
            slot.notification.detail_len = copyText(&slot.notification.detail, request.detail);
            return &slot.notification;
        }
        return error.NotificationTableFull;
    }

    pub fn postWithAttentionPolicy(
        self: *Center,
        request: PostRequest,
        policy: AttentionPolicy,
        now_ticks: u64,
    ) Error!AttentionPostResult {
        const decision = self.attentionDecision(request, policy, now_ticks);
        if (!decision.allowed) {
            return .{ .decision = decision };
        }
        return .{
            .decision = decision,
            .notification = try self.post(request),
        };
    }

    pub fn attentionDecision(
        self: *const Center,
        request: PostRequest,
        policy: AttentionPolicy,
        now_ticks: u64,
    ) AttentionDecision {
        const counts = self.activeAttentionCounts(now_ticks);
        if (request.urgency == .critical and !policy.allow_critical_interruptions) {
            return deny(.critical_interruption_denied, counts);
        }
        if (isInterruptive(request.urgency) and
            request.urgency != .critical and
            policy.quiet_until_ticks != 0 and
            now_ticks < policy.quiet_until_ticks)
        {
            return deny(.quiet_mode, counts);
        }
        if (policy.max_visible_notifications != 0 and counts.active_visible >= policy.max_visible_notifications) {
            return deny(.visible_budget_exhausted, counts);
        }
        if (isInterruptive(request.urgency) and
            policy.max_interruptions_per_window != 0 and
            counts.active_interruptions >= policy.max_interruptions_per_window)
        {
            return deny(.interruption_budget_exhausted, counts);
        }
        return .{
            .allowed = true,
            .active_visible = counts.active_visible,
            .active_interruptions = counts.active_interruptions,
        };
    }

    pub fn suppressBySourceReason(self: *Center, source: principal.PrincipalId, reason: Reason) usize {
        var count: usize = 0;
        for (&self.notifications) |*slot| {
            if (!slot.in_use) continue;
            if (!slot.notification.source.eql(source) or slot.notification.reason != reason) continue;
            if (!slot.notification.suppressed) {
                slot.notification.suppressed = true;
                count += 1;
            }
        }
        return count;
    }

    pub fn find(self: *Center, notification_id: u64) ?*Notification {
        for (&self.notifications) |*slot| {
            if (!slot.in_use) continue;
            if (slot.notification.id == notification_id) return &slot.notification;
        }
        return null;
    }

    pub fn dismiss(self: *Center, notification_id: u64) Error!*Notification {
        const notification = self.find(notification_id) orelse return error.NotificationNotFound;
        notification.suppressed = true;
        return notification;
    }

    pub fn activeInterruptionCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_interruptions;
    }

    pub fn activeCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_visible;
    }

    fn activeAttentionCounts(self: *const Center, now_ticks: u64) AttentionCounts {
        var counts = AttentionCounts{};
        for (self.notifications) |slot| {
            if (!slot.in_use) continue;
            if (!slot.notification.isActive(now_ticks)) continue;
            counts.active_visible += 1;
            if (isInterruptive(slot.notification.urgency)) counts.active_interruptions += 1;
        }
        return counts;
    }

    pub fn latestVisible(self: *const Center, now_ticks: u64) ?Notification {
        var index = self.notifications.len;
        while (index > 0) {
            index -= 1;
            const slot = self.notifications[index];
            if (!slot.in_use) continue;
            if (slot.notification.isActive(now_ticks)) return slot.notification;
        }
        return null;
    }

    fn applySuppressionPolicy(self: *Center, request: PostRequest) void {
        switch (request.suppression_policy) {
            .allow_repeat => {},
            .replace_same_source_reason => {
                _ = self.suppressBySourceReason(request.source, request.reason);
            },
            .replace_same_source_reason_task => {
                for (&self.notifications) |*slot| {
                    if (!slot.in_use) continue;
                    if (!slot.notification.source.eql(request.source)) continue;
                    if (slot.notification.reason != request.reason) continue;
                    if (slot.notification.task_id != request.task_id) continue;
                    slot.notification.suppressed = true;
                }
            },
        }
    }
};

fn deny(
    reason: AttentionDecisionReason,
    counts: AttentionCounts,
) AttentionDecision {
    return .{
        .allowed = false,
        .reason = reason,
        .active_visible = counts.active_visible,
        .active_interruptions = counts.active_interruptions,
    };
}

pub fn isInterruptive(urgency: Urgency) bool {
    return switch (urgency) {
        .passive, .normal => false,
        .high, .critical => true,
    };
}

fn zeroNotification() Notification {
    return .{
        .id = 0,
        .reason = .permission_request,
        .urgency = .normal,
        .source = .{ .kind = .service, .serial = 0 },
        .task_id = null,
        .expires_at_ticks = 0,
        .suppression_policy = .allow_repeat,
        .suppressed = false,
        .detail_len = 0,
        .detail = [_]u8{0} ** MAX_DETAIL_BYTES,
    };
}

test "notification center keeps structured objects task links expiry and suppression" {
    var center = Center.init();
    const sync_source = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const update_source = principal.PrincipalId{ .kind = .service, .serial = 8 };

    _ = try center.post(.{
        .source = sync_source,
        .reason = .sync_conflict,
        .urgency = .high,
        .task_id = 44,
        .detail = "workspace conflict",
        .expires_at_ticks = 50,
    });
    const update_notification = try center.post(.{
        .source = update_source,
        .reason = .update_ready,
        .urgency = .normal,
        .detail = "notes update ready",
    });
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(20));
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(49));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(50));
    try std.testing.expectEqualStrings("notes update ready", update_notification.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.allow_repeat, update_notification.suppression_policy);

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(sync_source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(20));
    try std.testing.expectEqual(update_notification.id, center.latestVisible(60).?.id);

    const dismissed = try center.dismiss(update_notification.id);
    try std.testing.expect(dismissed.suppressed);
    try std.testing.expect(center.latestVisible(60) == null);
    try std.testing.expectError(error.NotificationNotFound, center.dismiss(update_notification.id + 100));
}

test "notification center applies structured suppression policies before posting replacements" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .service, .serial = 9 };

    _ = try center.post(.{
        .source = source,
        .reason = .driver_restart,
        .urgency = .high,
        .detail = "graphics reset 1",
        .suppression_policy = .replace_same_source_reason,
    });
    const replacement = try center.post(.{
        .source = source,
        .reason = .driver_restart,
        .urgency = .high,
        .detail = "graphics reset 2",
        .suppression_policy = .replace_same_source_reason,
    });
    _ = try center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .passive,
        .task_id = 41,
        .detail = "task notice 1",
        .suppression_policy = .replace_same_source_reason_task,
    });
    const task_replacement = try center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .passive,
        .task_id = 41,
        .detail = "task notice 2",
        .suppression_policy = .replace_same_source_reason_task,
    });
    _ = try center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .passive,
        .task_id = 42,
        .detail = "other task survives",
        .suppression_policy = .replace_same_source_reason_task,
    });

    try std.testing.expectEqual(@as(usize, 3), center.activeCount(1));
    try std.testing.expect(center.notifications[0].notification.suppressed);
    try std.testing.expect(center.notifications[2].notification.suppressed);
    try std.testing.expectEqualStrings("other task survives", center.latestVisible(1).?.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason, replacement.suppression_policy);
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason_task, task_replacement.suppression_policy);
}

test "notification center enforces quiet mode and interruption budgets" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 26 };
    const quiet_policy = AttentionPolicy{
        .quiet_until_ticks = 100,
        .max_visible_notifications = 3,
        .max_interruptions_per_window = 1,
    };

    const quiet_denied = try center.postWithAttentionPolicy(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .high,
        .detail = "background agent wants attention",
    }, quiet_policy, 40);
    try std.testing.expect(!quiet_denied.decision.allowed);
    try std.testing.expectEqual(AttentionDecisionReason.quiet_mode, quiet_denied.decision.reason);
    try std.testing.expectEqual(@as(usize, 0), center.activeCount(40));

    const critical = try center.postWithAttentionPolicy(.{
        .source = source,
        .reason = .driver_restart,
        .urgency = .critical,
        .detail = "storage path needs recovery",
    }, quiet_policy, 40);
    try std.testing.expect(critical.decision.allowed);
    try std.testing.expect(critical.notification != null);
    try std.testing.expectEqual(@as(usize, 1), center.activeInterruptionCount(40));

    const budget_denied = try center.postWithAttentionPolicy(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "second interruptive notice",
    }, .{
        .max_interruptions_per_window = 1,
    }, 120);
    try std.testing.expect(!budget_denied.decision.allowed);
    try std.testing.expectEqual(AttentionDecisionReason.interruption_budget_exhausted, budget_denied.decision.reason);
}
