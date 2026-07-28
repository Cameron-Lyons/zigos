const std = @import("std");

const leaf1_edx_sse2: u32 = 1 << 26;
const leaf7_ebx_smep: u32 = 1 << 7;
const leaf7_ebx_smap: u32 = 1 << 20;
const leaf7_ecx_umip: u32 = 1 << 2;
const extended1_edx_nx: u32 = 1 << 20;
const extended1_edx_long_mode: u32 = 1 << 29;

pub const Registers = struct {
    cpuid_available: bool = false,
    max_basic_leaf: u32 = 0,
    leaf1_edx: u32 = 0,
    leaf7_ebx: u32 = 0,
    leaf7_ecx: u32 = 0,
    max_extended_leaf: u32 = 0,
    extended1_edx: u32 = 0,
};

pub const Features = struct {
    cpuid: bool = false,
    sse2: bool = false,
    long_mode: bool = false,
    nx: bool = false,
    smep: bool = false,
    smap: bool = false,
    umip: bool = false,
};

pub const MissingFeature = enum {
    cpuid,
    sse2,
    long_mode,
    nx,
    smep,
    smap,
    umip,
};

pub fn decode(registers: Registers) Features {
    if (!registers.cpuid_available) return .{};

    var features = Features{ .cpuid = true };
    if (registers.max_basic_leaf >= 1) {
        features.sse2 = (registers.leaf1_edx & leaf1_edx_sse2) != 0;
    }
    if (registers.max_basic_leaf >= 7) {
        features.smep = (registers.leaf7_ebx & leaf7_ebx_smep) != 0;
        features.smap = (registers.leaf7_ebx & leaf7_ebx_smap) != 0;
        features.umip = (registers.leaf7_ecx & leaf7_ecx_umip) != 0;
    }
    if (registers.max_extended_leaf >= 0x8000_0001) {
        features.nx = (registers.extended1_edx & extended1_edx_nx) != 0;
        features.long_mode = (registers.extended1_edx & extended1_edx_long_mode) != 0;
    }
    return features;
}

pub fn firstMissing(features: Features) ?MissingFeature {
    if (!features.cpuid) return .cpuid;
    if (!features.sse2) return .sse2;
    if (!features.long_mode) return .long_mode;
    if (!features.nx) return .nx;
    if (!features.smep) return .smep;
    if (!features.smap) return .smap;
    if (!features.umip) return .umip;
    return null;
}

pub fn isSupported(features: Features) bool {
    return firstMissing(features) == null;
}

test "decode recognizes the modern x86-64-capable baseline" {
    const features = decode(.{
        .cpuid_available = true,
        .max_basic_leaf = 7,
        .leaf1_edx = leaf1_edx_sse2,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_smap,
        .leaf7_ecx = leaf7_ecx_umip,
        .max_extended_leaf = 0x8000_0001,
        .extended1_edx = extended1_edx_nx | extended1_edx_long_mode,
    });

    try std.testing.expect(isSupported(features));
    try std.testing.expectEqual(@as(?MissingFeature, null), firstMissing(features));
}

test "decode ignores registers outside advertised CPUID ranges" {
    const features = decode(.{
        .cpuid_available = true,
        .leaf1_edx = leaf1_edx_sse2,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_smap,
        .leaf7_ecx = leaf7_ecx_umip,
        .extended1_edx = extended1_edx_nx | extended1_edx_long_mode,
    });

    try std.testing.expect(features.cpuid);
    try std.testing.expect(!features.sse2);
    try std.testing.expect(!features.long_mode);
    try std.testing.expect(!features.nx);
    try std.testing.expect(!features.smep);
    try std.testing.expect(!features.smap);
    try std.testing.expect(!features.umip);
}

test "baseline rejects every missing required feature" {
    const complete = Features{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .nx = true,
        .smep = true,
        .smap = true,
        .umip = true,
    };
    try std.testing.expectEqual(MissingFeature.cpuid, firstMissing(.{}).?);
    try std.testing.expectEqual(MissingFeature.sse2, firstMissing(.{
        .cpuid = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.long_mode, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.nx, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.smep, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .nx = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.smap, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .nx = true,
        .smep = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.umip, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .nx = true,
        .smep = true,
        .smap = true,
    }).?);
    try std.testing.expect(isSupported(complete));
}
