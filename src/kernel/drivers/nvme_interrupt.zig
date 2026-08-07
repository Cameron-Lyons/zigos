const std = @import("std");

pub const INTERRUPT_VECTOR: u8 = 0x42;
pub const SINGLE_MESSAGE_VECTOR: u16 = 0;

const CQ_PHYSICALLY_CONTIGUOUS: u32 = 1 << 0;
const CQ_INTERRUPTS_ENABLED: u32 = 1 << 1;

pub fn createCompletionQueueControl() u32 {
    return (@as(u32, SINGLE_MESSAGE_VECTOR) << 16) |
        CQ_INTERRUPTS_ENABLED |
        CQ_PHYSICALLY_CONTIGUOUS;
}

pub fn mayIdleWait(queue_id: u16, interrupt_route_active: bool, in_interrupt_context: bool) bool {
    return queue_id != 0 and interrupt_route_active and !in_interrupt_context;
}

test "single-message I/O completion queue enables vector zero interrupts" {
    const control = createCompletionQueueControl();
    try std.testing.expectEqual(@as(u32, 0), control >> 16);
    try std.testing.expect((control & CQ_INTERRUPTS_ENABLED) != 0);
    try std.testing.expect((control & CQ_PHYSICALLY_CONTIGUOUS) != 0);
}

test "interrupt-backed idle wait is restricted to routed I/O queues" {
    try std.testing.expect(mayIdleWait(1, true, false));
    try std.testing.expect(!mayIdleWait(0, true, false));
    try std.testing.expect(!mayIdleWait(1, false, false));
    try std.testing.expect(!mayIdleWait(1, true, true));
}
