const std = @import("std");

const leaf1_ecx_pcid: u32 = 1 << 17;
const leaf1_ecx_x2apic: u32 = 1 << 21;
const leaf1_ecx_tsc_deadline: u32 = 1 << 24;
const leaf1_ecx_xsave: u32 = 1 << 26;
const leaf1_edx_pge: u32 = 1 << 13;
const leaf1_edx_sse2: u32 = 1 << 26;
const leaf13_1_eax_xsaves: u32 = 1 << 3;
const leaf7_ebx_smep: u32 = 1 << 7;
const leaf7_ebx_invpcid: u32 = 1 << 10;
const leaf7_ebx_smap: u32 = 1 << 20;
const leaf7_ecx_pku: u32 = 1 << 3;
const leaf7_ecx_umip: u32 = 1 << 2;
const leaf7_ecx_cet_ss: u32 = 1 << 7;
const leaf7_edx_cet_ibt: u32 = 1 << 20;
const leaf7_1_eax_lass: u32 = 1 << 6;
const leaf7_1_eax_fred: u32 = 1 << 17;
const leaf7_1_eax_lkgs: u32 = 1 << 18;
const extended1_edx_syscall: u32 = 1 << 11;
const extended1_edx_nx: u32 = 1 << 20;
const extended1_edx_pages_1g: u32 = 1 << 26;
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
    leaf7_eax: u32 = 0,
    leaf7_ebx: u32 = 0,
    leaf7_ecx: u32 = 0,
    leaf7_edx: u32 = 0,
    leaf7_1_eax: u32 = 0,
    leaf13_1_eax: u32 = 0,
    max_extended_leaf: u32 = 0,
    extended1_edx: u32 = 0,
    extended7_edx: u32 = 0,
};

pub const REQUIRES_XSAVES = true;
pub const REQUIRES_CET = true;
pub const REQUIRES_PKU = true;
pub const REQUIRES_LASS = true;
pub const REQUIRES_FRED = true;

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
    xsave: bool = false,
    xsaves: bool = false,
    cet_ibt: bool = false,
    cet_ss: bool = false,
    pku: bool = false,
    lass: bool = false,
    fred: bool = false,
    lkgs: bool = false,
    pages_1g: bool = false,
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
    xsave,
    xsaves,
    cet_ibt,
    cet_ss,
    pku,
    lass,
    fred,
    lkgs,
    pages_1g,
    tsc,
};

pub fn decode(registers: Registers) Features {
    if (!registers.cpuid_available) return .{};

    var features = Features{ .cpuid = true };
    if (registers.max_basic_leaf >= 1) {
        features.sse2 = (registers.leaf1_edx & leaf1_edx_sse2) != 0;
        features.pge = (registers.leaf1_edx & leaf1_edx_pge) != 0;
        features.pcid = (registers.leaf1_ecx & leaf1_ecx_pcid) != 0;
        features.x2apic = (registers.leaf1_ecx & leaf1_ecx_x2apic) != 0;
        features.xsave = (registers.leaf1_ecx & leaf1_ecx_xsave) != 0;
        features.tsc_deadline = (registers.leaf1_ecx & leaf1_ecx_tsc_deadline) != 0;
    }
    if (registers.max_basic_leaf >= 7) {
        features.smep = (registers.leaf7_ebx & leaf7_ebx_smep) != 0;
        features.invpcid = (registers.leaf7_ebx & leaf7_ebx_invpcid) != 0;
        features.smap = (registers.leaf7_ebx & leaf7_ebx_smap) != 0;
        features.umip = (registers.leaf7_ecx & leaf7_ecx_umip) != 0;
        features.pku = (registers.leaf7_ecx & leaf7_ecx_pku) != 0;
        features.cet_ss = (registers.leaf7_ecx & leaf7_ecx_cet_ss) != 0;
        features.cet_ibt = (registers.leaf7_edx & leaf7_edx_cet_ibt) != 0;
        if (registers.leaf7_eax >= 1) {
            features.lass = (registers.leaf7_1_eax & leaf7_1_eax_lass) != 0;
            features.fred = (registers.leaf7_1_eax & leaf7_1_eax_fred) != 0;
            features.lkgs = (registers.leaf7_1_eax & leaf7_1_eax_lkgs) != 0;
        }
    }
    if (registers.max_basic_leaf >= 0xD) {
        features.xsaves = (registers.leaf13_1_eax & leaf13_1_eax_xsaves) != 0;
    }
    if (registers.max_extended_leaf >= 0x8000_0001) {
        features.syscall = (registers.extended1_edx & extended1_edx_syscall) != 0;
        features.nx = (registers.extended1_edx & extended1_edx_nx) != 0;
        features.pages_1g = (registers.extended1_edx & extended1_edx_pages_1g) != 0;
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
    if (!features.xsave) return .xsave;
    if (!features.xsaves) return .xsaves;
    if (!features.cet_ibt) return .cet_ibt;
    if (!features.cet_ss) return .cet_ss;
    if (!features.pku) return .pku;
    if (!features.lass) return .lass;
    if (!features.fred) return .fred;
    if (!features.lkgs) return .lkgs;
    if (!features.pages_1g) return .pages_1g;
    if (!features.tsc_deadline or !features.invariant_tsc or features.tsc_frequency_hz == 0) return .tsc;
    return null;
}

pub fn isSupported(features: Features) bool {
    return firstMissing(features) == null;
}

pub fn completeFeatures() Features {
    return .{
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
        .xsave = true,
        .xsaves = true,
        .cet_ibt = true,
        .cet_ss = true,
        .pku = true,
        .lass = true,
        .fred = true,
        .lkgs = true,
        .pages_1g = true,
        .tsc_deadline = true,
        .invariant_tsc = true,
        .tsc_frequency_hz = 2_400_000_000,
    };
}

fn modernRegisters() Registers {
    return .{
        .cpuid_available = true,
        .max_basic_leaf = 0x16,
        .leaf1_ecx = leaf1_ecx_pcid | leaf1_ecx_x2apic | leaf1_ecx_xsave | leaf1_ecx_tsc_deadline,
        .leaf13_1_eax = leaf13_1_eax_xsaves,
        .leaf1_edx = leaf1_edx_sse2 | leaf1_edx_pge,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
        .leaf7_eax = 1,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_invpcid | leaf7_ebx_smap,
        .leaf7_ecx = leaf7_ecx_umip | leaf7_ecx_cet_ss | leaf7_ecx_pku,
        .leaf7_edx = leaf7_edx_cet_ibt,
        .leaf7_1_eax = leaf7_1_eax_lass | leaf7_1_eax_fred | leaf7_1_eax_lkgs,
        .max_extended_leaf = 0x8000_0007,
        .extended1_edx = extended1_edx_syscall | extended1_edx_nx | extended1_edx_pages_1g | extended1_edx_long_mode,
        .extended7_edx = extended7_edx_invariant_tsc,
    };
}

test "decode recognizes the 2026 x86-64 baseline" {
    const features = decode(modernRegisters());
    try std.testing.expect(isSupported(features));
    try std.testing.expect(features.pcid);
    try std.testing.expect(features.invpcid);
    try std.testing.expect(features.pku);
    try std.testing.expect(features.lass);
    try std.testing.expect(features.fred);
    try std.testing.expect(features.lkgs);
    try std.testing.expect(features.cet_ibt);
    try std.testing.expect(features.cet_ss);
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
    try std.testing.expect(!features.xsave);
    try std.testing.expect(!features.xsaves);
    try std.testing.expect(!features.cet_ibt);
    try std.testing.expect(!features.cet_ss);
    try std.testing.expect(!features.pku);
    try std.testing.expect(!features.lass);
    try std.testing.expect(!features.fred);
    try std.testing.expect(!features.pages_1g);
    try std.testing.expect(!features.tsc_deadline);
    try std.testing.expect(!features.invariant_tsc);
    try std.testing.expectEqual(@as(u64, 0), features.tsc_frequency_hz);
}

test "baseline rejects every missing required feature" {
    try std.testing.expectEqual(MissingFeature.cpuid, firstMissing(.{}).?);
    try std.testing.expectEqual(MissingFeature.sse2, firstMissing(.{ .cpuid = true }).?);
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
    var missing_syscall = completeFeatures();
    missing_syscall.syscall = false;
    try std.testing.expectEqual(MissingFeature.syscall, firstMissing(missing_syscall).?);
    var missing_pcid = completeFeatures();
    missing_pcid.pcid = false;
    try std.testing.expectEqual(MissingFeature.pcid, firstMissing(missing_pcid).?);
    var missing_pku = completeFeatures();
    missing_pku.pku = false;
    try std.testing.expectEqual(MissingFeature.pku, firstMissing(missing_pku).?);
    var missing_lass = completeFeatures();
    missing_lass.lass = false;
    try std.testing.expectEqual(MissingFeature.lass, firstMissing(missing_lass).?);
    var missing_fred = completeFeatures();
    missing_fred.fred = false;
    try std.testing.expectEqual(MissingFeature.fred, firstMissing(missing_fred).?);
    var missing_lkgs = completeFeatures();
    missing_lkgs.lkgs = false;
    try std.testing.expectEqual(MissingFeature.lkgs, firstMissing(missing_lkgs).?);
    var missing_cet = completeFeatures();
    missing_cet.cet_ibt = false;
    try std.testing.expectEqual(MissingFeature.cet_ibt, firstMissing(missing_cet).?);
    try std.testing.expect(isSupported(completeFeatures()));
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
