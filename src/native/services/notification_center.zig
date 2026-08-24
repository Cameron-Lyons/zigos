const std = @import("std");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const copyText = native_util.copyText;

pub const MAX_NOTIFICATIONS: usize = 32;
pub const MAX_DETAIL_BYTES: usize = 96;
pub const BOUNDED_NOTIFICATION_SCAN = true;
pub const RECLAIMS_SUPPRESSED_NOTIFICATIONS = true;
pub const COMPACT_NOTIFICATION_METADATA = true;
pub const ATTENTION_DECISION_SIZE_CEILING_BYTES: usize = 4;
pub const ATTENTION_COUNTS_SIZE_CEILING_BYTES: usize = 2;
pub const ATTENTION_POST_RESULT_SIZE_CEILING_BYTES: usize = 16;
pub const CENTER_SIZE_CEILING_BYTES: usize = 4_624;

comptime {
    if (MAX_NOTIFICATIONS > std.math.maxInt(u8)) {
        @compileError("notification capacity exceeds compact attention counts");
    }
}

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
    active_visible: u8 = 0,
    active_interruptions: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > ATTENTION_DECISION_SIZE_CEILING_BYTES) {
            @compileError("notification attention decision exceeds its compact size ceiling");
        }
    }
};

pub const AttentionCounts = struct {
    active_visible: u8 = 0,
    active_interruptions: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > ATTENTION_COUNTS_SIZE_CEILING_BYTES) {
            @compileError("notification attention counts exceed their compact size ceiling");
        }
    }
};

pub const AttentionPostResult = struct {
    decision: AttentionDecision,
    notification: ?*Notification = null,

    comptime {
        if (@sizeOf(@This()) > ATTENTION_POST_RESULT_SIZE_CEILING_BYTES) {
            @compileError("notification attention post result exceeds its compact size ceiling");
        }
    }
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
    id: u64 = 0,
    reason: Reason = .permission_request,
    urgency: Urgency = .normal,
    source: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    task_id: u64 = 0,
    expires_at_ticks: u64 = 0,
    suppression_policy: SuppressionPolicy = .allow_repeat,
    suppressed: bool = false,
    detail_len: u8 = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const Notification) []const u8 {
        return self.detail[0..@as(usize, self.detail_len)];
    }

    pub fn taskId(self: *const Notification) ?u64 {
        return if (self.task_id == 0) null else self.task_id;
    }

    pub fn isActive(self: *const Notification, now_ticks: u64) bool {
        if (self.suppressed) return false;
        return self.expires_at_ticks == 0 or now_ticks < self.expires_at_ticks;
    }
};

pub const Error = error{
    NotificationIdExhausted,
    NotificationTableFull,
    NotificationNotFound,
};

pub const Center = struct {
    next_notification_id: u64 = 1,
    notifications: [MAX_NOTIFICATIONS]Notification = [_]Notification{.{}} ** MAX_NOTIFICATIONS,
    permanent_attention_counts: AttentionCounts = .{},
    notification_count: u8 = 0,
    visible_notification_count: u8 = 0,
    next_reusable_notification: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > CENTER_SIZE_CEILING_BYTES) {
            @compileError("notification center exceeds its fixed-state size ceiling");
        }
    }

    pub fn init() Center {
        return .{};
    }

    pub fn post(self: *Center, request: PostRequest) Error!*Notification {
        const notification_id = self.next_notification_id;
        if (notification_id == 0) return error.NotificationIdExhausted;
        if (self.notificationSlotIndex(notification_id) != null) return error.NotificationIdExhausted;
        var notification = Notification{};
        notification.id = notification_id;
        notification.reason = request.reason;
        notification.urgency = request.urgency;
        notification.source = request.source;
        notification.task_id = request.task_id orelse 0;
        notification.expires_at_ticks = request.expires_at_ticks;
        notification.suppression_policy = request.suppression_policy;
        notification.detail_len = @intCast(copyText(&notification.detail, request.detail));

        const slot_index = if (self.reserveNotificationSlotIndex()) |reserved_index| reserved: {
            self.applySuppressionPolicy(request);
            break :reserved reserved_index;
        } else replacement: {
            const retired_index = self.suppressionReplacementSlotIndex(request) orelse return error.NotificationTableFull;
            self.applySuppressionPolicy(request);
            break :replacement self.reuseSuppressedNotificationSlotIndex(retired_index);
        };
        if (slot_index == self.countNotifications()) self.notification_count += 1;
        const slot = &self.notifications[slot_index];
        slot.* = notification;
        self.accountPostedAttention(slot);
        self.next_notification_id +%= 1;
        return slot;
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
        if (policy.max_visible_notifications != 0 and @as(usize, counts.active_visible) >= policy.max_visible_notifications) {
            return deny(.visible_budget_exhausted, counts);
        }
        if (isInterruptive(request.urgency) and
            policy.max_interruptions_per_window != 0 and
            @as(u16, counts.active_interruptions) >= policy.max_interruptions_per_window)
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
        for (self.notifications[0..self.countNotifications()], 0..) |*notification, slot_index| {
            if (!notification.source.eql(source) or notification.reason != reason) continue;
            if (self.suppressNotificationSlot(slot_index)) count += 1;
        }
        return count;
    }

    pub fn find(self: *Center, notification_id: u64) ?*Notification {
        const slot_index = self.notificationSlotIndex(notification_id) orelse return null;
        return &self.notifications[slot_index];
    }

    pub fn dismiss(self: *Center, notification_id: u64) Error!*Notification {
        const slot_index = self.notificationSlotIndex(notification_id) orelse return error.NotificationNotFound;
        _ = self.suppressNotificationSlot(slot_index);
        return &self.notifications[slot_index];
    }

    pub fn activeInterruptionCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_interruptions;
    }

    pub fn activeCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_visible;
    }

    pub fn activeAttentionCounts(self: *const Center, now_ticks: u64) AttentionCounts {
        var counts = self.permanent_attention_counts;
        for (self.notifications[0..self.countNotifications()]) |*notification| {
            if (notification.suppressed or notification.expires_at_ticks == 0) continue;
            if (!notification.isActive(now_ticks)) continue;
            counts.active_visible += 1;
            if (isInterruptive(notification.urgency)) counts.active_interruptions += 1;
        }
        return counts;
    }

    /// The returned notification remains valid only until the center is mutated.
    pub fn latestVisible(self: *const Center, now_ticks: u64) ?*const Notification {
        var latest: ?*const Notification = null;
        for (self.notifications[0..self.countNotifications()]) |*notification| {
            if (!notification.isActive(now_ticks)) continue;
            if (latest == null or notification.id > latest.?.id) latest = notification;
        }
        return latest;
    }

    fn reserveNotificationSlotIndex(self: *Center) ?usize {
        const count = self.countNotifications();
        if (count < MAX_NOTIFICATIONS) return count;
        const retired_index = self.suppressedNotificationSlot() orelse return null;
        return self.reuseSuppressedNotificationSlotIndex(retired_index);
    }

    fn reuseSuppressedNotificationSlotIndex(self: *Center, retired_index: usize) usize {
        const retired = &self.notifications[retired_index];
        if (retired.id == 0 or !retired.suppressed) {
            native_util.impossibleByInvariant("notification replacement slot must be suppressed");
        }
        self.next_reusable_notification = @intCast((retired_index + 1) % MAX_NOTIFICATIONS);
        return retired_index;
    }

    fn suppressionReplacementSlotIndex(self: *const Center, request: PostRequest) ?usize {
        if (request.suppression_policy == .allow_repeat) return null;
        const request_task_id = request.task_id orelse 0;
        for (self.notifications[0..self.countNotifications()], 0..) |*notification, slot_index| {
            if (notification.suppressed) continue;
            if (!notification.source.eql(request.source) or notification.reason != request.reason) continue;
            if (request.suppression_policy == .replace_same_source_reason_task and
                notification.task_id != request_task_id) continue;
            return slot_index;
        }
        return null;
    }

    fn countNotifications(self: *const Center) usize {
        return @intCast(self.notification_count);
    }

    fn applySuppressionPolicy(self: *Center, request: PostRequest) void {
        switch (request.suppression_policy) {
            .allow_repeat => {},
            .replace_same_source_reason => {
                _ = self.suppressBySourceReason(request.source, request.reason);
            },
            .replace_same_source_reason_task => {
                const request_task_id = request.task_id orelse 0;
                for (self.notifications[0..self.countNotifications()], 0..) |*notification, slot_index| {
                    if (!notification.source.eql(request.source)) continue;
                    if (notification.reason != request.reason) continue;
                    if (notification.task_id != request_task_id) continue;
                    _ = self.suppressNotificationSlot(slot_index);
                }
            },
        }
    }

    fn suppressNotificationSlot(self: *Center, slot_index: usize) bool {
        if (slot_index >= self.countNotifications()) native_util.impossibleByInvariant("notification suppression points outside live slots");
        const notification = &self.notifications[slot_index];
        if (notification.id == 0) native_util.impossibleByInvariant("notification suppression points at a free slot");
        if (notification.suppressed) return false;
        self.unaccountSuppressedAttention(notification);
        notification.suppressed = true;
        return true;
    }

    fn accountPostedAttention(self: *Center, notification: *const Notification) void {
        if (notification.suppressed) return;
        self.visible_notification_count += 1;
        if (notification.expires_at_ticks == 0) {
            self.permanent_attention_counts.active_visible += 1;
            if (isInterruptive(notification.urgency)) self.permanent_attention_counts.active_interruptions += 1;
        }
    }

    fn unaccountSuppressedAttention(self: *Center, notification: *const Notification) void {
        if (notification.suppressed) return;
        if (self.visible_notification_count == 0) native_util.impossibleByInvariant("visible notification count underflow");
        self.visible_notification_count -= 1;
        if (notification.expires_at_ticks == 0) {
            if (self.permanent_attention_counts.active_visible == 0) native_util.impossibleByInvariant("permanent notification count underflow");
            self.permanent_attention_counts.active_visible -= 1;
            if (isInterruptive(notification.urgency)) {
                if (self.permanent_attention_counts.active_interruptions == 0) native_util.impossibleByInvariant("permanent interruption count underflow");
                self.permanent_attention_counts.active_interruptions -= 1;
            }
        }
    }

    fn notificationSlotIndex(self: *const Center, notification_id: u64) ?usize {
        if (notification_id == 0) return null;
        for (self.notifications[0..self.countNotifications()], 0..) |notification, slot_index| {
            if (notification.id == notification_id) return slot_index;
        }
        return null;
    }

    fn suppressedNotificationSlot(self: *const Center) ?usize {
        const count = self.countNotifications();
        if (count == 0) return null;
        const start = @as(usize, self.next_reusable_notification) % count;
        for (0..count) |offset| {
            const slot_index = (start + offset) % count;
            if (self.notifications[slot_index].suppressed) return slot_index;
        }
        return null;
    }

    fn suppressedNotificationCount(self: *const Center) usize {
        var count: usize = 0;
        for (self.notifications[0..self.countNotifications()]) |notification| {
            if (notification.suppressed) count += 1;
        }
        return count;
    }

    fn sourceReasonCount(self: *const Center, source: principal.PrincipalId, reason: Reason) usize {
        var count: usize = 0;
        for (self.notifications[0..self.countNotifications()]) |notification| {
            if (notification.source.eql(source) and notification.reason == reason) count += 1;
        }
        return count;
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

test "notification center keeps structured objects task links expiry and suppression" {
    try std.testing.expect(COMPACT_NOTIFICATION_METADATA);
    try std.testing.expectEqual(u8, @FieldType(AttentionDecision, "active_visible"));
    try std.testing.expectEqual(u8, @FieldType(AttentionDecision, "active_interruptions"));
    try std.testing.expectEqual(u8, @FieldType(AttentionCounts, "active_visible"));
    try std.testing.expectEqual(u8, @FieldType(AttentionCounts, "active_interruptions"));
    try std.testing.expect(@sizeOf(AttentionDecision) <= ATTENTION_DECISION_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(AttentionCounts) <= ATTENTION_COUNTS_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(AttentionPostResult) <= ATTENTION_POST_RESULT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Center) <= CENTER_SIZE_CEILING_BYTES);
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
    try std.testing.expectEqual(@as(u8, 2), center.visible_notification_count);
    try std.testing.expect(update_notification == center.latestVisible(20).?);
    try std.testing.expectEqual(update_notification.id, center.latestVisible(20).?.id);
    try std.testing.expectEqualStrings("notes update ready", update_notification.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.allow_repeat, update_notification.suppression_policy);

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(sync_source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(20));
    try std.testing.expectEqual(@as(u8, 1), center.visible_notification_count);
    try std.testing.expectEqual(update_notification.id, center.latestVisible(60).?.id);

    const dismissed = try center.dismiss(update_notification.id);
    try std.testing.expect(dismissed.suppressed);
    try std.testing.expectEqual(@as(usize, 2), center.suppressedNotificationCount());
    _ = try center.dismiss(update_notification.id);
    try std.testing.expectEqual(@as(usize, 2), center.suppressedNotificationCount());
    try std.testing.expectEqual(@as(u8, 0), center.visible_notification_count);
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
    try std.testing.expect(center.notifications[0].suppressed);
    try std.testing.expect(center.notifications[2].suppressed);
    try std.testing.expectEqual(@as(usize, 2), center.suppressedNotificationCount());
    try std.testing.expectEqual(@as(u8, 3), center.visible_notification_count);
    try std.testing.expectEqualStrings("other task survives", center.latestVisible(1).?.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason, replacement.suppression_policy);
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason_task, task_replacement.suppression_policy);
}

test "notification center commits new slots after suppression scans" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .service, .serial = 0 };

    const first = try center.post(.{
        .source = source,
        .reason = .permission_request,
        .urgency = .normal,
        .detail = "first default-shaped notification",
        .suppression_policy = .replace_same_source_reason,
    });
    try std.testing.expect(!first.suppressed);

    const replacement = try center.post(.{
        .source = source,
        .reason = .permission_request,
        .urgency = .normal,
        .detail = "replacement default-shaped notification",
        .suppression_policy = .replace_same_source_reason,
    });
    try std.testing.expect(center.find(first.id).?.suppressed);
    try std.testing.expect(!replacement.suppressed);
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(1));
}

test "notification center stops at id exhaustion and full posts require matching replacement" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .service, .serial = 10 };

    center.next_notification_id = std.math.maxInt(u64);
    const max_notification = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "max id notification",
    });
    try std.testing.expectEqual(std.math.maxInt(u64), max_notification.id);
    try std.testing.expectEqual(@as(u64, 0), center.next_notification_id);
    try std.testing.expect(center.find(0) == null);

    try std.testing.expectError(error.NotificationIdExhausted, center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "exhausted id notification",
        .suppression_policy = .replace_same_source_reason,
    }));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(1));
    try std.testing.expect(!max_notification.suppressed);

    var full_center = Center.init();
    for (0..MAX_NOTIFICATIONS) |index| {
        _ = try full_center.post(.{
            .source = source,
            .reason = .policy_notice,
            .urgency = .normal,
            .task_id = @intCast(index + 1),
            .detail = "full table notification",
        });
    }
    try std.testing.expectEqual(MAX_NOTIFICATIONS, full_center.activeCount(1));
    const replacement = try full_center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .normal,
        .task_id = 1,
        .detail = "matching replacement at capacity",
        .suppression_policy = .replace_same_source_reason_task,
    });
    try std.testing.expect(full_center.find(1) == null);
    try std.testing.expectEqualStrings("matching replacement at capacity", replacement.detailSlice());
    try std.testing.expectEqual(MAX_NOTIFICATIONS, full_center.activeCount(1));

    const next_before_unmatched = full_center.next_notification_id;
    try std.testing.expectError(error.NotificationTableFull, full_center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .normal,
        .task_id = MAX_NOTIFICATIONS + 1,
        .detail = "unmatched replacement without capacity",
        .suppression_policy = .replace_same_source_reason_task,
    }));
    try std.testing.expectEqual(next_before_unmatched, full_center.next_notification_id);
    try std.testing.expectEqual(MAX_NOTIFICATIONS, full_center.activeCount(1));
}

test "notification center reclaims suppressed slots when the table is full" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .service, .serial = 11 };

    for (0..MAX_NOTIFICATIONS) |index| {
        _ = try center.post(.{
            .source = source,
            .reason = .policy_notice,
            .urgency = .normal,
            .task_id = @intCast(index + 1),
            .detail = "table filler",
        });
    }
    const first_dismissed_slot = center.notificationSlotIndex(3).?;
    const second_dismissed_slot = center.notificationSlotIndex(5).?;
    try std.testing.expect((try center.dismiss(3)).suppressed);
    try std.testing.expect((try center.dismiss(5)).suppressed);
    try std.testing.expectEqual(first_dismissed_slot, center.suppressedNotificationSlot().?);

    const first_replacement = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "first reclaimed slot notification",
    });
    try std.testing.expect(center.find(3) == null);
    try std.testing.expect(center.find(5) != null);
    try std.testing.expectEqual(second_dismissed_slot, center.suppressedNotificationSlot().?);

    const second_replacement = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "second reclaimed slot notification",
    });
    try std.testing.expectEqual(MAX_NOTIFICATIONS, center.activeCount(1));
    try std.testing.expect(center.find(5) == null);
    try std.testing.expectEqualStrings("first reclaimed slot notification", first_replacement.detailSlice());
    try std.testing.expectEqualStrings("second reclaimed slot notification", second_replacement.detailSlice());
    try std.testing.expectEqual(MAX_NOTIFICATIONS - 2, center.sourceReasonCount(source, .policy_notice));
    try std.testing.expectEqual(@as(usize, 2), center.sourceReasonCount(source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 0), center.suppressedNotificationCount());

    try std.testing.expectError(error.NotificationTableFull, center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .normal,
        .detail = "no capacity left",
    }));
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

test "notification center counts permanent attention separately from expiring notices" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 27 };

    const permanent_interrupt = try center.post(.{
        .source = source,
        .reason = .driver_restart,
        .urgency = .high,
        .detail = "driver recovered",
    });
    _ = try center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .passive,
        .detail = "passive state",
    });
    _ = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "temporary conflict",
        .expires_at_ticks = 10,
    });

    try std.testing.expectEqual(@as(u8, 2), center.permanent_attention_counts.active_visible);
    try std.testing.expectEqual(@as(u8, 1), center.permanent_attention_counts.active_interruptions);
    try std.testing.expectEqual(@as(usize, 3), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 2), center.activeInterruptionCount(5));
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(10));
    try std.testing.expectEqual(@as(usize, 1), center.activeInterruptionCount(10));

    _ = try center.dismiss(permanent_interrupt.id);
    try std.testing.expectEqual(@as(u8, 1), center.permanent_attention_counts.active_visible);
    try std.testing.expectEqual(@as(u8, 0), center.permanent_attention_counts.active_interruptions);
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 1), center.activeInterruptionCount(5));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(10));

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 0), center.activeInterruptionCount(5));
}

test "notification center finds latest visible with a bounded scan" {
    var center = Center.init();
    const source = principal.PrincipalId{ .kind = .service, .serial = 31 };

    const permanent = try center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .normal,
        .detail = "persistent notice",
    });
    const temporary = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "temporary notice",
        .expires_at_ticks = 20,
    });

    try std.testing.expectEqual(@as(u8, 2), center.visible_notification_count);
    try std.testing.expectEqual(temporary.id, center.latestVisible(19).?.id);
    try std.testing.expectEqual(permanent.id, center.latestVisible(20).?.id);

    _ = try center.dismiss(permanent.id);
    try std.testing.expectEqual(@as(u8, 1), center.visible_notification_count);
    try std.testing.expect(center.latestVisible(20) == null);
}
