const std = @import("std");
const xstate = @import("xstate.zig");

// Shared by the hosted fixture and the freestanding QEMU proof. Production
// entry code never imports these seeded register images.
pub const Image = extern struct { state: xstate.State align(xstate.alignment) };

comptime {
    if (@sizeOf(Image) != 896 or @alignOf(Image) != xstate.alignment)
        @compileError("roundtrip image stride must match XSTATE_ALIGNED_BYTES");
}

pub fn initializeCanary(image: *Image) void {
    @memset(std.mem.asBytes(image), 0xa5);
    image.state.initialize();
}

pub fn initialize(image: *Image, owner: usize) void {
    initializeCanary(image);
    const bytes = &image.state.image;
    // The fixture uses the standard format. All owned components are live.
    std.mem.writeInt(u64, bytes[512..520], xstate.enabled_mask, .little);
    std.mem.writeInt(u64, bytes[520..528], 0, .little);
    std.mem.writeInt(u16, bytes[0..2], 0x037f | (@as(u16, @intCast(owner + 1)) << 10), .little);
    bytes[4] = 0xff;
    std.mem.writeInt(u32, bytes[24..28], 0x1f80 | (@as(u32, @intCast(owner + 1)) << 13), .little);
    for (0..8) |register| {
        const offset = 32 + register * 16;
        std.mem.writeInt(u64, bytes[offset..][0..8], 0x8000_0000_0000_0000 | (owner << 16) | register, .little);
        std.mem.writeInt(u16, bytes[offset + 8 ..][0..2], 0x3fff + @as(u16, @intCast(register)), .little);
    }
    for (0..16) |register| {
        const offset = 160 + register * 16;
        std.mem.writeInt(u64, bytes[offset..][0..8], 0x1357_2468_0000_0000 | (owner << 16) | register, .little);
        std.mem.writeInt(u64, bytes[offset + 8 ..][0..8], 0xfedc_ba98_0000_0000 | (owner << 16) | register, .little);
        const high = 576 + register * 16;
        std.mem.writeInt(u64, bytes[high..][0..8], 0x2468_1357_0000_0000 | (owner << 16) | register, .little);
        std.mem.writeInt(u64, bytes[high + 8 ..][0..8], 0xba98_fedc_0000_0000 | (owner << 16) | register, .little);
    }
}

pub fn verify(inputs: *const [3]Image, outputs: *const [3]Image) bool {
    for (inputs, outputs) |*input, *output| {
        const before = &input.state.image;
        const after = &output.state.image;
        if (!std.mem.eql(u8, before[0..5], after[0..5]) or
            !std.mem.eql(u8, before[24..28], after[24..28])) return false;
        for (0..8) |register| {
            const offset = 32 + register * 16;
            if (!std.mem.eql(u8, before[offset..][0..10], after[offset..][0..10])) return false;
        }
        if (!std.mem.eql(u8, before[160..416], after[160..416]) or
            !std.mem.eql(u8, before[576..832], after[576..832]) or
            std.mem.readInt(u64, after[512..520], .little) != xstate.enabled_mask or
            std.mem.readInt(u64, after[520..528], .little) != 0 or
            !std.mem.eql(u8, before[528..576], after[528..576])) return false;
        for (std.mem.asBytes(output)[@sizeOf(xstate.State)..]) |byte| {
            if (byte != 0xa5) return false;
        }
        if (output.state.pkru != 0 or output.state.reserved != 0) return false;
    }
    return true;
}
