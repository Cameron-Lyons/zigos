const std = @import("std");
const indexed_arena = @import("../core/indexed_arena.zig");
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

fn notificationSlotId(slot: *const NotificationSlot) u64 {
    return slot.notification.id;
}

fn sourceReasonKey(source: principal.PrincipalId, reason: Reason) u64 {
    const source_bytes = source.keyBytes();
    var hash = native_util.fnv1a64(&source_bytes);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(reason));
    return indexed_arena.nonZeroKey(hash);
}

const NotificationArena = indexed_arena.IndexedArenaWithKey(u64, NotificationSlot, MAX_NOTIFICATIONS, MAX_NOTIFICATIONS * 2, notificationSlotId);
const SourceReasonIndex = indexed_arena.MultimapIndex(MAX_NOTIFICATIONS, MAX_NOTIFICATIONS, MAX_NOTIFICATIONS * 2);
const ExpiringAttentionIndex = indexed_arena.MultimapIndex(MAX_NOTIFICATIONS, 1, 2);
const EXPIRING_ATTENTION_KEY: u64 = 1;
const NO_VISIBLE_SLOT = indexed_arena.no_index;

pub const Center = struct {
    next_notification_id: u64 = 1,
    notifications: NotificationArena = NotificationArena.init(),
    source_reason_index: SourceReasonIndex = SourceReasonIndex.init(),
    permanent_attention_counts: AttentionCounts = .{},
    expiring_attention_index: ExpiringAttentionIndex = ExpiringAttentionIndex.init(),
    visible_head_slot: usize = NO_VISIBLE_SLOT,
    visible_tail_slot: usize = NO_VISIBLE_SLOT,
    visible_prev_by_slot: [MAX_NOTIFICATIONS]usize = [_]usize{NO_VISIBLE_SLOT} ** MAX_NOTIFICATIONS,
    visible_next_by_slot: [MAX_NOTIFICATIONS]usize = [_]usize{NO_VISIBLE_SLOT} ** MAX_NOTIFICATIONS,
    visible_notification_count: usize = 0,

    pub fn init() Center {
        return .{};
    }

    pub fn post(self: *Center, request: PostRequest) Error!*Notification {
        const notification_id = self.nextReservableNotificationId() orelse return error.NotificationTableFull;
        var notification = zeroNotification();
        notification.id = notification_id;
        notification.reason = request.reason;
        notification.urgency = request.urgency;
        notification.source = request.source;
        notification.task_id = request.task_id;
        notification.expires_at_ticks = request.expires_at_ticks;
        notification.suppression_policy = request.suppression_policy;
        notification.detail_len = copyText(&notification.detail, request.detail);

        self.applySuppressionPolicy(request);
        const slot_index = self.notifications.reserveIndex(notification_id) orelse return error.NotificationTableFull;
        const slot = &self.notifications.slots[slot_index];
        slot.notification = notification;
        if (!self.source_reason_index.append(sourceReasonKey(request.source, request.reason), slot_index)) {
            native_util.impossibleByInvariant("notification source/reason index covers notification slots");
        }
        self.accountPostedAttention(slot_index, &slot.notification);
        self.notifications.clearDirty();
        self.advanceNextNotificationIdFrom(notification_id);
        return &slot.notification;
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
        var slot_index = self.source_reason_index.head(sourceReasonKey(source, reason));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.source_reason_index.next(slot_index)) {
            const slot = &self.notifications.slots[slot_index];
            if (!slot.notification.source.eql(source) or slot.notification.reason != reason) continue;
            if (!slot.notification.suppressed) {
                self.unaccountSuppressedAttention(slot_index, &slot.notification);
                slot.notification.suppressed = true;
                self.notifications.markDirty(slot.notification.id);
                count += 1;
            }
        }
        return count;
    }

    pub fn find(self: *Center, notification_id: u64) ?*Notification {
        const slot = self.notifications.get(notification_id) orelse return null;
        return &slot.notification;
    }

    pub fn dismiss(self: *Center, notification_id: u64) Error!*Notification {
        const notification = self.find(notification_id) orelse return error.NotificationNotFound;
        if (!notification.suppressed) {
            const slot_index = self.notifications.slotIndexOf(notification_id).?;
            self.unaccountSuppressedAttention(slot_index, notification);
            notification.suppressed = true;
            self.notifications.markDirty(notification.id);
        }
        return notification;
    }

    pub fn activeInterruptionCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_interruptions;
    }

    pub fn activeCount(self: *const Center, now_ticks: u64) usize {
        return self.activeAttentionCounts(now_ticks).active_visible;
    }

    fn activeAttentionCounts(self: *const Center, now_ticks: u64) AttentionCounts {
        var counts = self.permanent_attention_counts;
        var slot_index = self.expiring_attention_index.head(EXPIRING_ATTENTION_KEY);
        while (slot_index != indexed_arena.no_index) : (slot_index = self.expiring_attention_index.next(slot_index)) {
            if (slot_index >= MAX_NOTIFICATIONS) native_util.impossibleByInvariant("expiring notification index points outside slots");
            const slot = &self.notifications.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("expiring notification index points at a free slot");
            if (slot.notification.suppressed) native_util.impossibleByInvariant("expiring notification index points at a suppressed slot");
            if (!slot.notification.isActive(now_ticks)) continue;
            counts.active_visible += 1;
            if (isInterruptive(slot.notification.urgency)) counts.active_interruptions += 1;
        }
        return counts;
    }

    pub fn latestVisible(self: *const Center, now_ticks: u64) ?Notification {
        var slot_index = self.visible_tail_slot;
        while (slot_index != NO_VISIBLE_SLOT) : (slot_index = self.visible_prev_by_slot[slot_index]) {
            const slot = self.visibleNotificationSlotAt(slot_index);
            if (slot.notification.isActive(now_ticks)) return slot.notification;
        }
        return null;
    }

    fn nextReservableNotificationId(self: *Center) ?u64 {
        if (self.countNotifications() >= MAX_NOTIFICATIONS) return null;

        var notification_id = normalizeNotificationId(self.next_notification_id);
        var attempts: usize = 0;
        while (attempts <= MAX_NOTIFICATIONS) : (attempts += 1) {
            if (self.find(notification_id) == null) return notification_id;
            notification_id = nextNotificationIdAfter(notification_id);
        }
        return null;
    }

    fn advanceNextNotificationIdFrom(self: *Center, notification_id: u64) void {
        self.next_notification_id = nextNotificationIdAfter(notification_id);
    }

    fn countNotifications(self: *const Center) usize {
        return self.notifications.countInUse();
    }

    fn applySuppressionPolicy(self: *Center, request: PostRequest) void {
        switch (request.suppression_policy) {
            .allow_repeat => {},
            .replace_same_source_reason => {
                _ = self.suppressBySourceReason(request.source, request.reason);
            },
            .replace_same_source_reason_task => {
                var slot_index = self.source_reason_index.head(sourceReasonKey(request.source, request.reason));
                while (slot_index != indexed_arena.no_index) : (slot_index = self.source_reason_index.next(slot_index)) {
                    const slot = &self.notifications.slots[slot_index];
                    if (!slot.notification.source.eql(request.source)) continue;
                    if (slot.notification.reason != request.reason) continue;
                    if (slot.notification.task_id != request.task_id) continue;
                    if (!slot.notification.suppressed) {
                        self.unaccountSuppressedAttention(slot_index, &slot.notification);
                        slot.notification.suppressed = true;
                        self.notifications.markDirty(slot.notification.id);
                    }
                }
            },
        }
    }

    fn accountPostedAttention(self: *Center, slot_index: usize, notification: *const Notification) void {
        if (notification.suppressed) return;
        self.linkVisibleNotification(slot_index);
        if (notification.expires_at_ticks == 0) {
            self.permanent_attention_counts.active_visible += 1;
            if (isInterruptive(notification.urgency)) self.permanent_attention_counts.active_interruptions += 1;
            return;
        }
        if (!self.expiring_attention_index.append(EXPIRING_ATTENTION_KEY, slot_index)) {
            native_util.impossibleByInvariant("expiring notification index covers notification slots");
        }
    }

    fn unaccountSuppressedAttention(self: *Center, slot_index: usize, notification: *const Notification) void {
        if (notification.suppressed) return;
        self.unlinkVisibleNotification(slot_index);
        if (notification.expires_at_ticks == 0) {
            if (self.permanent_attention_counts.active_visible == 0) native_util.impossibleByInvariant("permanent notification count underflow");
            self.permanent_attention_counts.active_visible -= 1;
            if (isInterruptive(notification.urgency)) {
                if (self.permanent_attention_counts.active_interruptions == 0) native_util.impossibleByInvariant("permanent interruption count underflow");
                self.permanent_attention_counts.active_interruptions -= 1;
            }
            return;
        }
        if (!self.expiring_attention_index.remove(EXPIRING_ATTENTION_KEY, slot_index)) {
            native_util.impossibleByInvariant("expiring notification index missing live notification");
        }
    }

    fn linkVisibleNotification(self: *Center, slot_index: usize) void {
        const slot = self.visibleNotificationSlotAt(slot_index);
        if (slot.notification.suppressed) native_util.impossibleByInvariant("suppressed notification cannot be linked as visible");
        if (self.visible_prev_by_slot[slot_index] != NO_VISIBLE_SLOT or
            self.visible_next_by_slot[slot_index] != NO_VISIBLE_SLOT or
            self.visible_head_slot == slot_index or
            self.visible_tail_slot == slot_index)
        {
            native_util.impossibleByInvariant("notification linked into visible chain more than once");
        }

        if (self.visible_tail_slot == NO_VISIBLE_SLOT) {
            if (self.visible_head_slot != NO_VISIBLE_SLOT or self.visible_notification_count != 0) {
                native_util.impossibleByInvariant("empty visible notification chain has stale head");
            }
            self.visible_head_slot = slot_index;
            self.visible_tail_slot = slot_index;
        } else {
            const old_tail = self.visible_tail_slot;
            if (old_tail >= MAX_NOTIFICATIONS) native_util.impossibleByInvariant("visible notification tail points outside slots");
            self.visible_next_by_slot[old_tail] = slot_index;
            self.visible_prev_by_slot[slot_index] = old_tail;
            self.visible_tail_slot = slot_index;
        }
        self.visible_notification_count += 1;
    }

    fn unlinkVisibleNotification(self: *Center, slot_index: usize) void {
        _ = self.visibleNotificationSlotAt(slot_index);
        if (self.visible_notification_count == 0) native_util.impossibleByInvariant("visible notification count underflow");
        const previous = self.visible_prev_by_slot[slot_index];
        const next = self.visible_next_by_slot[slot_index];
        const linked_as_singleton = self.visible_head_slot == slot_index and self.visible_tail_slot == slot_index;
        const linked_in_chain = previous != NO_VISIBLE_SLOT or next != NO_VISIBLE_SLOT or linked_as_singleton;
        if (!linked_in_chain) native_util.impossibleByInvariant("visible notification chain missing live notification");

        if (previous == NO_VISIBLE_SLOT) {
            if (self.visible_head_slot != slot_index) native_util.impossibleByInvariant("visible notification chain head mismatch");
            self.visible_head_slot = next;
        } else {
            if (previous >= MAX_NOTIFICATIONS) native_util.impossibleByInvariant("visible notification previous pointer outside slots");
            self.visible_next_by_slot[previous] = next;
        }

        if (next == NO_VISIBLE_SLOT) {
            if (self.visible_tail_slot != slot_index) native_util.impossibleByInvariant("visible notification chain tail mismatch");
            self.visible_tail_slot = previous;
        } else {
            if (next >= MAX_NOTIFICATIONS) native_util.impossibleByInvariant("visible notification next pointer outside slots");
            self.visible_prev_by_slot[next] = previous;
        }

        self.visible_prev_by_slot[slot_index] = NO_VISIBLE_SLOT;
        self.visible_next_by_slot[slot_index] = NO_VISIBLE_SLOT;
        self.visible_notification_count -= 1;
        if (self.visible_notification_count == 0 and
            (self.visible_head_slot != NO_VISIBLE_SLOT or self.visible_tail_slot != NO_VISIBLE_SLOT))
        {
            native_util.impossibleByInvariant("empty visible notification chain retained endpoints");
        }
    }

    fn visibleNotificationSlotAt(self: *const Center, slot_index: usize) *const NotificationSlot {
        if (slot_index >= MAX_NOTIFICATIONS) native_util.impossibleByInvariant("visible notification index points outside slots");
        const slot = &self.notifications.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("visible notification index points at a free slot");
        return slot;
    }
};

fn normalizeNotificationId(notification_id: u64) u64 {
    return if (notification_id == 0) 1 else notification_id;
}

fn nextNotificationIdAfter(notification_id: u64) u64 {
    const next = notification_id +% 1;
    return normalizeNotificationId(next);
}

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
    try std.testing.expectEqual(@as(usize, 2), center.visible_notification_count);
    try std.testing.expectEqual(update_notification.id, center.latestVisible(20).?.id);
    try std.testing.expectEqualStrings("notes update ready", update_notification.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.allow_repeat, update_notification.suppression_policy);

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(sync_source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(20));
    try std.testing.expectEqual(@as(usize, 1), center.visible_notification_count);
    try std.testing.expectEqual(update_notification.id, center.latestVisible(60).?.id);

    const dismissed = try center.dismiss(update_notification.id);
    try std.testing.expect(dismissed.suppressed);
    try std.testing.expectEqual(@as(usize, 0), center.visible_notification_count);
    try std.testing.expectEqual(NO_VISIBLE_SLOT, center.visible_tail_slot);
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
    try std.testing.expect(center.notifications.slots[0].notification.suppressed);
    try std.testing.expect(center.notifications.slots[2].notification.suppressed);
    try std.testing.expectEqual(@as(usize, 3), center.visible_notification_count);
    try std.testing.expectEqualStrings("other task survives", center.latestVisible(1).?.detailSlice());
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason, replacement.suppression_policy);
    try std.testing.expectEqual(SuppressionPolicy.replace_same_source_reason_task, task_replacement.suppression_policy);
}

test "notification center ids wrap without zero and full posts do not suppress" {
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
    try std.testing.expectEqual(@as(u64, 1), center.next_notification_id);
    try std.testing.expect(center.find(0) == null);

    const wrapped_notification = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "wrapped id notification",
    });
    try std.testing.expectEqual(@as(u64, 1), wrapped_notification.id);
    try std.testing.expectEqual(@as(u64, 2), center.next_notification_id);
    try std.testing.expect(center.find(0) == null);

    center.next_notification_id = 1;
    const skipped_notification = try center.post(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "skipped id notification",
    });
    try std.testing.expectEqual(@as(u64, 2), skipped_notification.id);
    try std.testing.expectEqual(@as(u64, 3), center.next_notification_id);
    try std.testing.expect(center.find(0) == null);

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
    const next_before_full = full_center.next_notification_id;
    try std.testing.expectEqual(MAX_NOTIFICATIONS, full_center.activeCount(1));
    try std.testing.expectError(error.NotificationTableFull, full_center.post(.{
        .source = source,
        .reason = .policy_notice,
        .urgency = .normal,
        .task_id = 1,
        .detail = "replacement without capacity",
        .suppression_policy = .replace_same_source_reason_task,
    }));
    try std.testing.expectEqual(next_before_full, full_center.next_notification_id);
    try std.testing.expectEqual(MAX_NOTIFICATIONS, full_center.activeCount(1));
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

    try std.testing.expectEqual(@as(usize, 2), center.permanent_attention_counts.active_visible);
    try std.testing.expectEqual(@as(usize, 1), center.permanent_attention_counts.active_interruptions);
    try std.testing.expect(center.expiring_attention_index.head(EXPIRING_ATTENTION_KEY) != indexed_arena.no_index);
    try std.testing.expectEqual(@as(usize, 3), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 2), center.activeInterruptionCount(5));
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(10));
    try std.testing.expectEqual(@as(usize, 1), center.activeInterruptionCount(10));

    _ = try center.dismiss(permanent_interrupt.id);
    try std.testing.expectEqual(@as(usize, 1), center.permanent_attention_counts.active_visible);
    try std.testing.expectEqual(@as(usize, 0), center.permanent_attention_counts.active_interruptions);
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 1), center.activeInterruptionCount(5));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(10));

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(source, .sync_conflict));
    try std.testing.expectEqual(indexed_arena.no_index, center.expiring_attention_index.head(EXPIRING_ATTENTION_KEY));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(5));
    try std.testing.expectEqual(@as(usize, 0), center.activeInterruptionCount(5));
}

test "notification center reads latest visible from maintained visible chain" {
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

    try std.testing.expectEqual(@as(usize, 2), center.visible_notification_count);
    try std.testing.expectEqual(temporary.id, center.latestVisible(19).?.id);
    try std.testing.expectEqual(permanent.id, center.latestVisible(20).?.id);
    try std.testing.expectEqual(temporary.id, center.notifications.slots[center.visible_tail_slot].notification.id);

    _ = try center.dismiss(permanent.id);
    try std.testing.expectEqual(@as(usize, 1), center.visible_notification_count);
    try std.testing.expect(center.latestVisible(20) == null);
}
