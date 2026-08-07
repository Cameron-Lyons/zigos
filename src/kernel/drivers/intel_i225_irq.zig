const std = @import("std");

pub const INTERRUPT_VECTOR: u8 = 65;
pub const TRANSMIT_COMPLETE_CAUSE: u32 = 1 << 0;
pub const RECEIVE_DESCRIPTOR_CAUSE: u32 = 1 << 4;
pub const RECEIVE_TIMER_CAUSE: u32 = 1 << 7;
pub const ASSERTED_CAUSE: u32 = 1 << 31;
pub const RECEIVE_CAUSES: u32 = RECEIVE_DESCRIPTOR_CAUSE | RECEIVE_TIMER_CAUSE;
pub const QUEUE_CAUSES: u32 = TRANSMIT_COMPLETE_CAUSE | RECEIVE_CAUSES;
pub const MAX_TX_COMPLETIONS_PER_SERVICE: u32 = 63;
pub const MAX_RX_FRAMES_PER_SERVICE: u32 = 1;
pub const EMPTY_INTERRUPT_LIMIT: u8 = 8;

pub const Cause = enum {
    none,
    queue,
    invalid,
};

pub fn classify(raw_cause: u32) Cause {
    if (raw_cause == 0) return .none;
    if ((raw_cause & ASSERTED_CAUSE) != 0 and (raw_cause & QUEUE_CAUSES) != 0) return .queue;
    return .invalid;
}

pub fn nextEmptyStreak(current: u8, made_progress: bool) u8 {
    if (made_progress) return 0;
    return current +| 1;
}

pub fn shouldContain(empty_streak: u8) bool {
    return empty_streak >= EMPTY_INTERRUPT_LIMIT;
}

test "I225 interrupt causes require an asserted enabled queue cause" {
    try std.testing.expectEqual(Cause.none, classify(0));
    try std.testing.expectEqual(
        Cause.queue,
        classify(ASSERTED_CAUSE | TRANSMIT_COMPLETE_CAUSE),
    );
    try std.testing.expectEqual(
        Cause.queue,
        classify(ASSERTED_CAUSE | RECEIVE_TIMER_CAUSE | (1 << 2)),
    );
    try std.testing.expectEqual(Cause.invalid, classify(TRANSMIT_COMPLETE_CAUSE));
    try std.testing.expectEqual(Cause.invalid, classify(ASSERTED_CAUSE));
}

test "I225 empty interrupt accounting resets on bounded queue progress" {
    var streak: u8 = 0;
    for (0..EMPTY_INTERRUPT_LIMIT - 1) |_| {
        streak = nextEmptyStreak(streak, false);
        try std.testing.expect(!shouldContain(streak));
    }
    streak = nextEmptyStreak(streak, true);
    try std.testing.expectEqual(@as(u8, 0), streak);
    for (0..EMPTY_INTERRUPT_LIMIT) |_| streak = nextEmptyStreak(streak, false);
    try std.testing.expect(shouldContain(streak));
    try std.testing.expectEqual(@as(u32, 63), MAX_TX_COMPLETIONS_PER_SERVICE);
    try std.testing.expectEqual(@as(u32, 1), MAX_RX_FRAMES_PER_SERVICE);
}
