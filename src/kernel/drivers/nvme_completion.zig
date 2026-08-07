const std = @import("std");

pub const Completion = struct {
    submission_head: u16,
    submission_queue_id: u16,
    command_id: u16,
    phase: u1,
    status: u15,

    pub fn belongsTo(
        self: Completion,
        expected_queue_id: u16,
        expected_command_id: u16,
        queue_entries: u32,
    ) bool {
        return self.submission_queue_id == expected_queue_id and
            self.command_id == expected_command_id and
            @as(u32, self.submission_head) < queue_entries;
    }

    pub fn succeeded(self: Completion) bool {
        return self.status == 0;
    }
};

pub fn decode(submission: u32, status: u32) Completion {
    return .{
        .submission_head = @truncate(submission),
        .submission_queue_id = @truncate(submission >> 16),
        .command_id = @truncate(status),
        .phase = @truncate(status >> 16),
        .status = @truncate(status >> 17),
    };
}

pub fn phase(status: u32) u1 {
    return @truncate(status >> 16);
}

test "NVMe completion binds queue command phase and success" {
    const completion = decode(
        (@as(u32, 1) << 16) | 7,
        (@as(u32, 0x1234)) | (@as(u32, 1) << 16),
    );
    try std.testing.expectEqual(@as(u16, 7), completion.submission_head);
    try std.testing.expectEqual(@as(u16, 1), completion.submission_queue_id);
    try std.testing.expectEqual(@as(u16, 0x1234), completion.command_id);
    try std.testing.expectEqual(@as(u1, 1), completion.phase);
    try std.testing.expectEqual(@as(u1, 1), phase((@as(u32, 1) << 16)));
    try std.testing.expect(completion.succeeded());
    try std.testing.expect(completion.belongsTo(1, 0x1234, 32));
}

test "NVMe completion rejects stale or malformed ownership" {
    const completion = decode(
        (@as(u32, 1) << 16) | 32,
        (@as(u32, 9)) | (@as(u32, 1) << 16) | (@as(u32, 0x81) << 17),
    );
    try std.testing.expect(!completion.succeeded());
    try std.testing.expect(!completion.belongsTo(1, 9, 32));
    try std.testing.expect(!completion.belongsTo(2, 9, 64));
    try std.testing.expect(!completion.belongsTo(1, 8, 64));
}
