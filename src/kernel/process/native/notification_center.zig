const std = @import("std");
const principal = @import("principal.zig");

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

pub const Notification = struct {
    id: u64,
    reason: Reason,
    urgency: Urgency,
    source: principal.PrincipalId,
    task_id: ?u64,
    expires_at_ticks: u64,
    suppressed: bool,
    detail_len: usize,
    detail: [MAX_DETAIL_BYTES]u8,

    pub fn detailSlice(self: *const Notification) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn isActive(self: *const Notification, now_ticks: u64) bool {
        if (self.suppressed) return false;
        return self.expires_at_ticks == 0 or now_ticks <= self.expires_at_ticks;
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

    pub fn post(
        self: *Center,
        source: principal.PrincipalId,
        reason: Reason,
        urgency: Urgency,
        task_id: ?u64,
        detail: []const u8,
        expires_at_ticks: u64,
    ) Error!*Notification {
        for (&self.notifications) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.notification = zeroNotification();
            slot.notification.id = self.next_notification_id;
            self.next_notification_id += 1;
            slot.notification.reason = reason;
            slot.notification.urgency = urgency;
            slot.notification.source = source;
            slot.notification.task_id = task_id;
            slot.notification.expires_at_ticks = expires_at_ticks;
            slot.notification.detail_len = copyText(&slot.notification.detail, detail);
            return &slot.notification;
        }
        return error.NotificationTableFull;
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

    pub fn activeCount(self: *const Center, now_ticks: u64) usize {
        var count: usize = 0;
        for (self.notifications) |slot| {
            if (!slot.in_use) continue;
            if (slot.notification.isActive(now_ticks)) count += 1;
        }
        return count;
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
};

fn zeroNotification() Notification {
    return .{
        .id = 0,
        .reason = .permission_request,
        .urgency = .normal,
        .source = .{ .kind = .service, .serial = 0 },
        .task_id = null,
        .expires_at_ticks = 0,
        .suppressed = false,
        .detail_len = 0,
        .detail = [_]u8{0} ** MAX_DETAIL_BYTES,
    };
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

test "notification center keeps structured objects task links expiry and suppression" {
    var center = Center.init();
    const sync_source = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const update_source = principal.PrincipalId{ .kind = .service, .serial = 8 };

    _ = try center.post(sync_source, .sync_conflict, .high, 44, "workspace conflict", 50);
    const update_notification = try center.post(update_source, .update_ready, .normal, null, "notes update ready", 0);
    try std.testing.expectEqual(@as(usize, 2), center.activeCount(20));
    try std.testing.expectEqualStrings("notes update ready", update_notification.detailSlice());

    try std.testing.expectEqual(@as(usize, 1), center.suppressBySourceReason(sync_source, .sync_conflict));
    try std.testing.expectEqual(@as(usize, 1), center.activeCount(20));
    try std.testing.expectEqual(update_notification.id, center.latestVisible(60).?.id);
}
