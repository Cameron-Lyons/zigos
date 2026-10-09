const std = @import("std");
const xstate = @import("../xstate.zig");
const seeds = @import("../xstate_roundtrip_model.zig");

pub const Image = seeds.Image;
pub const Result = extern struct { initial: Image, restored: Image };
pub const UnsupportedReason = enum { CPUID, XSAVE, AVX, XSAVES, YMM_LAYOUT };
pub const Capabilities = struct {
    maximum_leaf: u32,
    leaf1_ecx: u32,
    state_mask: u32,
    state_features: u32,
    ymm_bytes: u32,
    ymm_offset: u32,
    ymm_flags: u32,

    pub fn unsupported(self: @This()) ?UnsupportedReason {
        if (self.maximum_leaf < 0xD) return .CPUID;
        if (self.leaf1_ecx & (1 << 26) == 0) return .XSAVE;
        if (self.leaf1_ecx & (1 << 28) == 0) return .AVX;
        if (self.state_features & (1 << 3) == 0) return .XSAVES;
        if (self.state_mask & 7 != 7 or self.ymm_bytes != 256 or self.ymm_offset != 576 or self.ymm_flags & 1 != 0)
            return .YMM_LAYOUT;
        return null;
    }
};

pub fn initialize(image: *Image, owner: usize) void {
    seeds.initialize(image, owner);
}

pub fn initializeResult(result: *Result) void {
    seeds.initializeCanary(&result.initial);
    seeds.initializeCanary(&result.restored);
}

fn guardsIntact(image: *const Image) bool {
    if (image.state.pkru != 0 or image.state.reserved != 0) return false;
    for (std.mem.asBytes(image)[@sizeOf(xstate.State)..]) |byte| if (byte != 0xa5) return false;
    for (image.state.image[528..576]) |byte| if (byte != 0) return false;
    return true;
}

pub fn initialIntact(image: *const Image) bool {
    const bytes = &image.state.image;
    // Empty x87 register payloads are undefined; inspect only architectural
    // controls and component presence for the real BV=0 init restore.
    for (bytes[160..416]) |byte| if (byte != 0) return false;
    for (bytes[576..832]) |byte| if (byte != 0) return false;
    return guardsIntact(image) and std.mem.readInt(u16, bytes[0..2], .little) == 0x037f and
        std.mem.readInt(u16, bytes[2..4], .little) == 0 and bytes[4] == 0 and
        std.mem.readInt(u32, bytes[24..28], .little) == 0x1f80 and
        std.mem.readInt(u64, bytes[512..520], .little) & ~@as(u64, 7) == 0 and
        std.mem.readInt(u64, bytes[520..528], .little) == 0;
}

pub fn restoredIntact(expected: *const Image, actual: *const Image) bool {
    const before = &expected.state.image;
    const after = &actual.state.image;
    if (!guardsIntact(actual) or !std.mem.eql(u8, before[0..5], after[0..5]) or
        !std.mem.eql(u8, before[24..28], after[24..28]) or
        !std.mem.eql(u8, before[160..416], after[160..416]) or
        !std.mem.eql(u8, before[576..832], after[576..832]) or
        std.mem.readInt(u64, after[512..520], .little) != 7 or
        std.mem.readInt(u64, after[520..528], .little) != 0) return false;
    for (0..8) |register| {
        const offset = 32 + register * 16;
        if (!std.mem.eql(u8, before[offset..][0..10], after[offset..][0..10])) return false;
    }
    return true;
}

pub fn compactedIntact(state: *const xstate.State) bool {
    if (state.pkru != 0 or state.reserved != 0 or
        std.mem.readInt(u64, state.image[512..520], .little) != 7 or
        std.mem.readInt(u64, state.image[520..528], .little) != (@as(u64, 1) << 63 | 7)) return false;
    for (state.image[528..576]) |byte| if (byte != 0) return false;
    return true;
}

test "Mapping compact admission rejects raw missing capabilities and incompatible YMM layout" {
    const admitted: Capabilities = .{ .maximum_leaf = 0xD, .leaf1_ecx = (1 << 26) | (1 << 28), .state_mask = 7, .state_features = 8, .ymm_bytes = 256, .ymm_offset = 576, .ymm_flags = 2 };
    try std.testing.expect(admitted.unsupported() == null);
    inline for (.{ "maximum_leaf", "leaf1_ecx", "state_mask", "state_features", "ymm_bytes", "ymm_offset", "ymm_flags" }) |field| {
        var bad = admitted;
        @field(bad, field) = if (std.mem.eql(u8, field, "ymm_flags")) 1 else 0;
        try std.testing.expect(bad.unsupported() != null);
    }
    var no_avx = admitted;
    no_avx.leaf1_ecx &= ~@as(u32, 1 << 28);
    try std.testing.expectEqual(UnsupportedReason.AVX, no_avx.unsupported().?);
}

test "Mapping standard oracle observes every x87 and full YMM owner value plus headers and canaries" {
    var expected: Image = undefined;
    initialize(&expected, 0);
    var actual = expected;
    try std.testing.expect(restoredIntact(&expected, &actual));
    const offsets = [_]usize{ 0, 2, 4, 24, 512, 520, 528, 832, 836, 840, 895 };
    for (offsets) |offset| {
        actual = expected;
        std.mem.asBytes(&actual)[offset] ^= 1;
        try std.testing.expect(!restoredIntact(&expected, &actual));
    }
    for (0..8) |register| {
        actual = expected;
        actual.state.image[32 + register * 16 + 9] ^= 1;
        try std.testing.expect(!restoredIntact(&expected, &actual));
    }
    for (0..16) |register| {
        for ([_]usize{ 160, 576 }) |base| {
            actual = expected;
            actual.state.image[base + register * 16 + 15] ^= 1;
            try std.testing.expect(!restoredIntact(&expected, &actual));
        }
    }
    initialize(&actual, 1);
    try std.testing.expect(!restoredIntact(&expected, &actual));
}

test "Mapping init and compact oracles distinguish standard initialized and resident formats" {
    var initial: Image = undefined;
    seeds.initializeCanary(&initial);
    std.mem.writeInt(u16, initial.state.image[0..2], 0x037f, .little);
    std.mem.writeInt(u64, initial.state.image[520..528], 0, .little);
    try std.testing.expect(initialIntact(&initial));
    for (0..8) |tracked| {
        std.mem.writeInt(u64, initial.state.image[512..520], tracked, .little);
        try std.testing.expect(initialIntact(&initial));
    }
    initial.state.image[160] = 1;
    try std.testing.expect(!initialIntact(&initial));
    initial.state.image[160] = 0;
    initial.state.image[831] = 1;
    try std.testing.expect(!initialIntact(&initial));
    initial.state.image[831] = 0;
    initial.state.image[4] = 1;
    try std.testing.expect(!initialIntact(&initial));
    var compact: Image = undefined;
    initialize(&compact, 1);
    try std.testing.expect(!compactedIntact(&compact.state));
    std.mem.writeInt(u64, compact.state.image[520..528], (@as(u64, 1) << 63) | 7, .little);
    try std.testing.expect(compactedIntact(&compact.state));
    compact.state.image[575] = 1;
    try std.testing.expect(!compactedIntact(&compact.state));
}
