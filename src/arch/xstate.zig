const std = @import("std");

// The native baseline deliberately enables XCR0=x87|SSE, IA32_XSS=0.
// Future enabled components must change this bounded layout and assembly mask.
pub const enabled_mask: u64 = 3;
pub const image_bytes: usize = 576;
pub const alignment: usize = 64;
pub const State = extern struct {
    image: [image_bytes]u8 = @splat(0),
    pkru: u32 = 0,
    reserved: u32 = 0,

    pub fn initialize(self: *State) void {
        self.* = .{};
        // Init-state XRSTORS loads the architectural initial x87/SSE state.
        std.mem.writeInt(u64, self.image[520..528], (1 << 63) | enabled_mask, .little);
        // Retain the architectural MXCSR value in the initialized image too.
        std.mem.writeInt(u32, self.image[24..28], 0x1f80, .little);
    }
};

// kmalloc guarantees 32-byte granules, so retain the allocation base and align
// the actual image within it instead of requesting an unsupported alignment.
pub const Storage = struct {
    bytes: [@sizeOf(State) + alignment - 1]u8 = @splat(0),

    pub fn state(self: *Storage) *align(alignment) State {
        const address = std.mem.alignForward(usize, @intFromPtr(&self.bytes), alignment);
        return @ptrFromInt(address);
    }

    pub fn erase(self: *Storage) void {
        std.crypto.secureZero(u8, &self.bytes);
    }

    pub fn initialize(self: *Storage) void {
        self.state().initialize();
    }
};

comptime {
    if (@sizeOf(State) != 584 or @offsetOf(State, "pkru") != 576)
        @compileError("xstate layout must match xstate64.inc");
}

test "xstate storage retains aligned complete baseline image and private initial state" {
    var arena: [@sizeOf(Storage) + 64]u8 = undefined;
    for (0..64) |offset| {
        const storage: *Storage = @ptrCast(&arena[offset]);
        storage.initialize();
        const state = storage.state();
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(state) % alignment);
        try std.testing.expect(@intFromPtr(state) + @sizeOf(State) <= @intFromPtr(storage) + @sizeOf(Storage));
        try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, state.image[512..520], .little));
        try std.testing.expectEqual((@as(u64, 1) << 63) | enabled_mask, std.mem.readInt(u64, state.image[520..528], .little));
        try std.testing.expectEqual(@as(u32, 0x1f80), std.mem.readInt(u32, state.image[24..28], .little));
        try std.testing.expectEqual(@as(u32, 0), state.pkru);
        @memset(&state.image, 0xa5);
        state.pkru = 0x5a5a5a5a;
        storage.erase();
        for (storage.bytes) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
