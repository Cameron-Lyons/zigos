const std = @import("std");

const leaf1_ecx_pcid: u32 = 1 << 17;
const leaf1_edx_pge: u32 = 1 << 13;
const leaf1_edx_sse2: u32 = 1 << 26;
const leaf1_ecx_x2apic: u32 = 1 << 21;
const leaf1_ecx_tsc_deadline: u32 = 1 << 24;
const leaf7_ebx_smep: u32 = 1 << 7;
const leaf7_ebx_invpcid: u32 = 1 << 10;
const leaf7_ebx_smap: u32 = 1 << 20;
const leaf7_ecx_umip: u32 = 1 << 2;
const extended1_edx_syscall: u32 = 1 << 11;
const extended1_edx_nx: u32 = 1 << 20;
const extended1_edx_long_mode: u32 = 1 << 29;
const extended7_edx_invariant_tsc: u32 = 1 << 8;
const hertz_per_megahertz: u64 = 1_000_000;

pub const Registers = struct {
    cpuid_available: bool = false,
    max_basic_leaf: u32 = 0,
    leaf1_ecx: u32 = 0,
    leaf1_edx: u32 = 0,
    leaf15_eax: u32 = 0,
    leaf15_ebx: u32 = 0,
    leaf15_ecx: u32 = 0,
    leaf16_eax: u32 = 0,
    leaf7_ebx: u32 = 0,
    leaf7_ecx: u32 = 0,
    max_extended_leaf: u32 = 0,
    extended1_edx: u32 = 0,
    extended7_edx: u32 = 0,
};

pub const Features = struct {
    cpuid: bool = false,
    sse2: bool = false,
    long_mode: bool = false,
    syscall: bool = false,
    nx: bool = false,
    smep: bool = false,
    smap: bool = false,
    umip: bool = false,
    pge: bool = false,
    pcid: bool = false,
    invpcid: bool = false,
    x2apic: bool = false,
    tsc_deadline: bool = false,
    invariant_tsc: bool = false,
    tsc_frequency_hz: u64 = 0,
};

pub const MissingFeature = enum {
    cpuid,
    sse2,
    long_mode,
    syscall,
    nx,
    smep,
    smap,
    umip,
    pge,
    pcid,
    invpcid,
    x2apic,
    tsc_frequency,
};

pub fn decode(registers: Registers) Features {
    if (!registers.cpuid_available) return .{};

    var features = Features{ .cpuid = true };
    if (registers.max_basic_leaf >= 1) {
        features.sse2 = (registers.leaf1_edx & leaf1_edx_sse2) != 0;
        features.pge = (registers.leaf1_edx & leaf1_edx_pge) != 0;
        features.pcid = (registers.leaf1_ecx & leaf1_ecx_pcid) != 0;
        features.x2apic = (registers.leaf1_ecx & leaf1_ecx_x2apic) != 0;
        features.tsc_deadline = (registers.leaf1_ecx & leaf1_ecx_tsc_deadline) != 0;
    }
    if (registers.max_basic_leaf >= 7) {
        features.smep = (registers.leaf7_ebx & leaf7_ebx_smep) != 0;
        features.invpcid = (registers.leaf7_ebx & leaf7_ebx_invpcid) != 0;
        features.smap = (registers.leaf7_ebx & leaf7_ebx_smap) != 0;
        features.umip = (registers.leaf7_ecx & leaf7_ecx_umip) != 0;
    }
    if (registers.max_extended_leaf >= 0x8000_0001) {
        features.syscall = (registers.extended1_edx & extended1_edx_syscall) != 0;
        features.nx = (registers.extended1_edx & extended1_edx_nx) != 0;
        features.long_mode = (registers.extended1_edx & extended1_edx_long_mode) != 0;
    }
    if (registers.max_extended_leaf >= 0x8000_0007) {
        features.invariant_tsc = (registers.extended7_edx & extended7_edx_invariant_tsc) != 0;
    }
    features.tsc_frequency_hz = decodeTscFrequency(registers);
    return features;
}

fn decodeTscFrequency(registers: Registers) u64 {
    if (registers.max_basic_leaf >= 0x15 and
        registers.leaf15_eax != 0 and
        registers.leaf15_ebx != 0 and
        registers.leaf15_ecx != 0)
    {
        const scaled = std.math.mul(u64, registers.leaf15_ecx, registers.leaf15_ebx) catch return 0;
        return scaled / registers.leaf15_eax;
    }
    if (registers.max_basic_leaf >= 0x16 and registers.leaf16_eax != 0) {
        return std.math.mul(u64, registers.leaf16_eax, hertz_per_megahertz) catch 0;
    }
    return 0;
}

pub fn firstMissing(features: Features) ?MissingFeature {
    if (!features.cpuid) return .cpuid;
    if (!features.sse2) return .sse2;
    if (!features.long_mode) return .long_mode;
    if (!features.syscall) return .syscall;
    if (!features.nx) return .nx;
    if (!features.smep) return .smep;
    if (!features.smap) return .smap;
    if (!features.umip) return .umip;
    if (!features.pge) return .pge;
    if (!features.pcid) return .pcid;
    if (!features.invpcid) return .invpcid;
    if (!features.x2apic) return .x2apic;
    if (features.tsc_frequency_hz == 0) return .tsc_frequency;
    return null;
}

pub fn isSupported(features: Features) bool {
    return firstMissing(features) == null;
}

test "decode recognizes the modern x86-64-capable baseline" {
    const features = decode(.{
        .cpuid_available = true,
        .max_basic_leaf = 0x16,
        .leaf1_ecx = leaf1_ecx_pcid | leaf1_ecx_x2apic | leaf1_ecx_tsc_deadline,
        .leaf1_edx = leaf1_edx_sse2 | leaf1_edx_pge,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_invpcid | leaf7_ebx_smap,
        .leaf7_ecx = leaf7_ecx_umip,
        .max_extended_leaf = 0x8000_0007,
        .extended1_edx = extended1_edx_syscall | extended1_edx_nx | extended1_edx_long_mode,
        .extended7_edx = extended7_edx_invariant_tsc,
    });

    try std.testing.expect(isSupported(features));
    try std.testing.expect(features.pcid);
    try std.testing.expect(features.invpcid);
    try std.testing.expect(features.pge);
    try std.testing.expect(features.syscall);
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
    try std.testing.expect(!features.syscall);
    try std.testing.expect(!features.nx);
    try std.testing.expect(!features.smep);
    try std.testing.expect(!features.smap);
    try std.testing.expect(!features.umip);
    try std.testing.expect(!features.pge);
    try std.testing.expect(!features.pcid);
    try std.testing.expect(!features.invpcid);
    try std.testing.expect(!features.x2apic);
    try std.testing.expect(!features.tsc_deadline);
    try std.testing.expect(!features.invariant_tsc);
    try std.testing.expectEqual(@as(u64, 0), features.tsc_frequency_hz);
}

test "baseline rejects every missing required feature" {
    const complete = Features{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
        .smap = true,
        .umip = true,
        .pge = true,
        .pcid = true,
        .invpcid = true,
        .x2apic = true,
        .tsc_deadline = true,
        .invariant_tsc = true,
        .tsc_frequency_hz = 2_400_000_000,
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
        .syscall = true,
    }).?);
    var missing_syscall = complete;
    missing_syscall.syscall = false;
    try std.testing.expectEqual(MissingFeature.syscall, firstMissing(missing_syscall).?);
    try std.testing.expectEqual(MissingFeature.smep, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.smap, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.umip, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
        .smap = true,
    }).?);
    var missing_pcid = complete;
    missing_pcid.pcid = false;
    try std.testing.expectEqual(MissingFeature.pcid, firstMissing(missing_pcid).?);
    var missing_invpcid = complete;
    missing_invpcid.invpcid = false;
    try std.testing.expectEqual(MissingFeature.invpcid, firstMissing(missing_invpcid).?);
    var missing_pge = complete;
    missing_pge.pge = false;
    try std.testing.expectEqual(MissingFeature.pge, firstMissing(missing_pge).?);
    try std.testing.expectEqual(MissingFeature.x2apic, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
        .smap = true,
        .umip = true,
        .pge = true,
        .pcid = true,
        .invpcid = true,
    }).?);
    try std.testing.expectEqual(MissingFeature.tsc_frequency, firstMissing(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
        .smap = true,
        .umip = true,
        .pge = true,
        .pcid = true,
        .invpcid = true,
        .x2apic = true,
    }).?);
    try std.testing.expect(isSupported(complete));
    try std.testing.expect(isSupported(.{
        .cpuid = true,
        .sse2 = true,
        .long_mode = true,
        .syscall = true,
        .nx = true,
        .smep = true,
        .smap = true,
        .umip = true,
        .pge = true,
        .pcid = true,
        .invpcid = true,
        .x2apic = true,
        .tsc_frequency_hz = 2_400_000_000,
    }));
}

test "TSC frequency prefers CPUID ratio and falls back to base MHz" {
    try std.testing.expectEqual(@as(u64, 2_400_000_000), decodeTscFrequency(.{
        .max_basic_leaf = 0x16,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
        .leaf16_eax = 1_800,
    }));
    try std.testing.expectEqual(@as(u64, 1_800_000_000), decodeTscFrequency(.{
        .max_basic_leaf = 0x16,
        .leaf16_eax = 1_800,
    }));
}
