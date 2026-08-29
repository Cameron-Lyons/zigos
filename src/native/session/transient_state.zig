const builtin = @import("builtin");
const std = @import("std");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};

pub const HEAP_BACKED_ON_FREESTANDING = true;
pub const HANDLE_SIZE_CEILING_BYTES: usize = 8;

pub fn ScopedState(comptime State: type) type {
    const heap_backed = builtin.target.os.tag == .freestanding and HEAP_BACKED_ON_FREESTANDING;
    const Backing = if (heap_backed) ?*State else State;

    return struct {
        const Self = @This();

        backing: Backing = if (heap_backed) null else undefined,

        pub inline fn begin(self: *Self) error{NoSpaceLeft}!*State {
            if (comptime heap_backed) {
                self.deinit();
                const allocation = kernel_memory.kmalloc(@sizeOf(State)) orelse return error.NoSpaceLeft;
                const state: *State = @ptrCast(@alignCast(allocation));
                self.backing = state;
                return state;
            }
            return &self.backing;
        }

        pub fn deinit(self: *Self) void {
            if (comptime heap_backed) {
                if (self.backing) |state| {
                    @memset(std.mem.asBytes(state), 0);
                    kernel_memory.kfree(@ptrCast(state));
                    self.backing = null;
                }
            } else {
                self.* = undefined;
            }
        }

        pub fn ptr(self: *Self) *State {
            if (comptime heap_backed) return self.backing.?;
            return &self.backing;
        }
    };
}

pub fn freestandingHandleSize(comptime State: type) usize {
    return if (HEAP_BACKED_ON_FREESTANDING) @sizeOf(?*State) else @sizeOf(State);
}

test "host scoped transient state retains value storage" {
    if (builtin.target.os.tag == .freestanding) return;
    const State = struct {
        bytes: [32]u8,
        ready: bool,
    };
    const Instance = ScopedState(State);
    try std.testing.expectEqual(@sizeOf(State), @sizeOf(Instance));

    var instance: Instance = .{};
    const state = try instance.begin();
    state.* = .{ .bytes = [_]u8{0x5a} ** 32, .ready = true };
    defer instance.deinit();
    try std.testing.expect(instance.ptr().ready);
    try std.testing.expectEqual(@as(u8, 0x5a), instance.ptr().bytes[31]);
}
