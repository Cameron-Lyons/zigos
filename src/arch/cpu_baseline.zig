const std = @import("std");

const leaf1_ecx_sse3: u32 = 1 << 0;
const leaf1_ecx_ssse3: u32 = 1 << 9;
const leaf1_ecx_cx16: u32 = 1 << 13;
const leaf1_ecx_sse4_1: u32 = 1 << 19;
const leaf1_ecx_sse4_2: u32 = 1 << 20;
const leaf1_ecx_popcnt: u32 = 1 << 23;
const leaf1_ecx_pclmul: u32 = 1 << 1;
const leaf1_ecx_fma: u32 = 1 << 12;
const leaf1_ecx_movbe: u32 = 1 << 22;
const leaf1_ecx_aes: u32 = 1 << 25;
const leaf1_ecx_avx: u32 = 1 << 28;
const leaf1_ecx_f16c: u32 = 1 << 29;
const leaf1_ecx_pcid: u32 = 1 << 17;
const leaf1_ecx_x2apic: u32 = 1 << 21;
const leaf1_ecx_tsc_deadline: u32 = 1 << 24;
const leaf1_ecx_xsave: u32 = 1 << 26;
const leaf1_edx_pge: u32 = 1 << 13;
const leaf1_edx_sse2: u32 = 1 << 26;
const leaf13_1_eax_xsaves: u32 = 1 << 3;
const leaf7_ebx_smep: u32 = 1 << 7;
const leaf7_ebx_bmi1: u32 = 1 << 3;
const leaf7_ebx_avx2: u32 = 1 << 5;
const leaf7_ebx_bmi2: u32 = 1 << 8;
const leaf7_ebx_sha: u32 = 1 << 29;
const leaf7_ebx_invpcid: u32 = 1 << 10;
const leaf7_ebx_rdseed: u32 = 1 << 18;
const leaf7_ebx_smap: u32 = 1 << 20;
const leaf7_ecx_pku: u32 = 1 << 3;
const leaf7_ecx_rdpid: u32 = 1 << 22;
const leaf7_ecx_umip: u32 = 1 << 2;
const leaf7_ecx_cet_ss: u32 = 1 << 7;
const leaf7_edx_cet_ibt: u32 = 1 << 20;
const leaf7_1_eax_lass: u32 = 1 << 6;
const leaf7_1_eax_fred: u32 = 1 << 17;
const leaf7_1_eax_lkgs: u32 = 1 << 18;
const extended1_edx_syscall: u32 = 1 << 11;
const extended1_ecx_lahf_sahf: u32 = 1 << 0;
const extended1_ecx_lzcnt: u32 = 1 << 5;
const extended1_edx_nx: u32 = 1 << 20;
const extended1_edx_pages_1g: u32 = 1 << 26;
const extended1_edx_long_mode: u32 = 1 << 29;
const extended7_edx_invariant_tsc: u32 = 1 << 8;

pub const Registers = struct {
    cpuid_available: bool = false,
    max_basic_leaf: u32 = 0,
    leaf1_ecx: u32 = 0,
    leaf1_edx: u32 = 0,
    leaf15_eax: u32 = 0,
    leaf15_ebx: u32 = 0,
    leaf15_ecx: u32 = 0,
    leaf7_eax: u32 = 0,
    leaf7_ebx: u32 = 0,
    leaf7_ecx: u32 = 0,
    leaf7_edx: u32 = 0,
    leaf7_1_eax: u32 = 0,
    leaf13_1_eax: u32 = 0,
    leaf13_0_eax: u32 = 0,
    leaf13_2_eax: u32 = 0,
    leaf13_2_ebx: u32 = 0,
    leaf13_2_ecx: u32 = 0,
    max_extended_leaf: u32 = 0,
    extended1_ecx: u32 = 0,
    extended1_edx: u32 = 0,
    extended7_edx: u32 = 0,
};

pub const REQUIRES_XSAVES = true;
pub const REQUIRES_RDPID = true;
pub const REQUIRES_CET = true;
pub const REQUIRES_PKU = false;
pub const REQUIRES_LASS = true;
pub const REQUIRES_FRED = true;
pub const PRODUCTION_REQUIRES_HARDWARE_FRED = true;
pub const FRED_ONLY_TRAPS = true;

pub const KernelAddressPartition = struct {
    instruction: usize,
    stack: usize,
    kernel_data: usize,
    gdt: DescriptorTableAddress,
    idt: DescriptorTableAddress,
};

pub const DescriptorTableAddress = struct {
    base: usize,
    limit: u16,
};

pub inline fn isCanonicalUpperHalf(address: usize) bool {
    // The kernel uses four-level paging. LASS also requires bit 63 to be set
    // for supervisor instruction fetches and ordinary supervisor data access.
    return address >= 0xFFFF_8000_0000_0000;
}

pub inline fn lassAddressPartitionSupported(addresses: KernelAddressPartition) bool {
    return isCanonicalUpperHalf(addresses.instruction) and
        isCanonicalUpperHalf(addresses.stack) and
        isCanonicalUpperHalf(addresses.kernel_data) and
        descriptorTableUpperHalf(addresses.gdt) and
        descriptorTableUpperHalf(addresses.idt);
}

inline fn descriptorTableUpperHalf(table: DescriptorTableAddress) bool {
    return table.limit != 0 and isCanonicalUpperHalf(table.base) and
        table.base <= std.math.maxInt(usize) - @as(usize, table.limit);
}

test "LASS admission requires upper-half code stack data and descriptor tables together" {
    const admitted = KernelAddressPartition{
        .instruction = 0xFFFF_FFFF_8200_0000,
        .stack = 0xFFFF_C000_4001_0000,
        .kernel_data = 0xFFFF_FFFF_8240_0000,
        .gdt = .{ .base = 0xFFFF_FFFF_8241_0000, .limit = 63 },
        .idt = .{ .base = 0xFFFF_FFFF_8242_0000, .limit = 4095 },
    };
    try std.testing.expect(lassAddressPartitionSupported(admitted));
    inline for (.{ "instruction", "stack", "kernel_data" }) |field| {
        var mixed = admitted;
        @field(mixed, field) = 32 * 1024 * 1024;
        try std.testing.expect(!lassAddressPartitionSupported(mixed));
        @field(mixed, field) = 0x8000_0000_0000_0000;
        try std.testing.expect(!lassAddressPartitionSupported(mixed));
    }
    inline for (.{ "gdt", "idt" }) |field| {
        var mixed = admitted;
        @field(mixed, field).base = 32 * 1024 * 1024;
        try std.testing.expect(!lassAddressPartitionSupported(mixed));
        @field(mixed, field).base = 0x8000_0000_0000_0000;
        try std.testing.expect(!lassAddressPartitionSupported(mixed));
    }
}

test "LASS descriptor admission checks complete nonempty canonical extents" {
    try std.testing.expect(descriptorTableUpperHalf(.{ .base = 0xFFFF_8000_0000_0000, .limit = 4095 }));
    try std.testing.expect(descriptorTableUpperHalf(.{ .base = 0xFFFF_FFFF_FFFF_F000, .limit = 4095 }));
    try std.testing.expect(!descriptorTableUpperHalf(.{ .base = 0xFFFF_FFFF_FFFF_F001, .limit = 4095 }));
    try std.testing.expect(!descriptorTableUpperHalf(.{ .base = 0xFFFF_7FFF_FFFF_FFFF, .limit = 4095 }));
    try std.testing.expect(!descriptorTableUpperHalf(.{ .base = 0xFFFF_8000_0000_0000, .limit = 0 }));
}

test "LASS admission rejects the four-level canonical hole and lower half" {
    try std.testing.expect(!isCanonicalUpperHalf(0));
    try std.testing.expect(!isCanonicalUpperHalf(0x0000_7FFF_FFFF_FFFF));
    try std.testing.expect(!isCanonicalUpperHalf(0x0000_8000_0000_0000));
    try std.testing.expect(!isCanonicalUpperHalf(0xFFFF_7FFF_FFFF_FFFF));
    try std.testing.expect(isCanonicalUpperHalf(0xFFFF_8000_0000_0000));
    try std.testing.expect(isCanonicalUpperHalf(0xFFFF_FFFF_FFFF_FFFF));
}

pub const Features = struct {
    cpuid: bool = false,
    sse2: bool = false,
    sse3: bool = false,
    ssse3: bool = false,
    sse4_1: bool = false,
    sse4_2: bool = false,
    popcnt: bool = false,
    cx16: bool = false,
    lahf_sahf: bool = false,
    avx: bool = false,
    avx2: bool = false,
    f16c: bool = false,
    fma: bool = false,
    movbe: bool = false,
    bmi1: bool = false,
    bmi2: bool = false,
    lzcnt: bool = false,
    aes: bool = false,
    pclmul: bool = false,
    sha: bool = false,
    ymm_state: bool = false,
    long_mode: bool = false,
    syscall: bool = false,
    nx: bool = false,
    smep: bool = false,
    smap: bool = false,
    umip: bool = false,
    pge: bool = false,
    pcid: bool = false,
    invpcid: bool = false,
    rdseed: bool = false,
    rdpid: bool = false,
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
    sse3,
    ssse3,
    sse4_1,
    sse4_2,
    popcnt,
    cx16,
    lahf_sahf,
    avx,
    avx2,
    f16c,
    fma,
    movbe,
    bmi1,
    bmi2,
    lzcnt,
    aes,
    pclmul,
    sha,
    ymm_state,
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
    rdseed,
    rdpid,
};

pub fn decode(registers: Registers) Features {
    if (!registers.cpuid_available) return .{};

    var features = Features{ .cpuid = true };
    if (registers.max_basic_leaf >= 1) {
        features.sse2 = (registers.leaf1_edx & leaf1_edx_sse2) != 0;
        features.sse3 = (registers.leaf1_ecx & leaf1_ecx_sse3) != 0;
        features.ssse3 = (registers.leaf1_ecx & leaf1_ecx_ssse3) != 0;
        features.sse4_1 = (registers.leaf1_ecx & leaf1_ecx_sse4_1) != 0;
        features.sse4_2 = (registers.leaf1_ecx & leaf1_ecx_sse4_2) != 0;
        features.popcnt = (registers.leaf1_ecx & leaf1_ecx_popcnt) != 0;
        features.cx16 = (registers.leaf1_ecx & leaf1_ecx_cx16) != 0;
        features.avx = (registers.leaf1_ecx & leaf1_ecx_avx) != 0;
        features.f16c = (registers.leaf1_ecx & leaf1_ecx_f16c) != 0;
        features.fma = (registers.leaf1_ecx & leaf1_ecx_fma) != 0;
        features.movbe = (registers.leaf1_ecx & leaf1_ecx_movbe) != 0;
        features.aes = (registers.leaf1_ecx & leaf1_ecx_aes) != 0;
        features.pclmul = (registers.leaf1_ecx & leaf1_ecx_pclmul) != 0;
        features.pge = (registers.leaf1_edx & leaf1_edx_pge) != 0;
        features.pcid = (registers.leaf1_ecx & leaf1_ecx_pcid) != 0;
        features.x2apic = (registers.leaf1_ecx & leaf1_ecx_x2apic) != 0;
        features.xsave = (registers.leaf1_ecx & leaf1_ecx_xsave) != 0;
        features.tsc_deadline = (registers.leaf1_ecx & leaf1_ecx_tsc_deadline) != 0;
    }
    if (registers.max_basic_leaf >= 7) {
        features.avx2 = (registers.leaf7_ebx & leaf7_ebx_avx2) != 0;
        features.bmi1 = (registers.leaf7_ebx & leaf7_ebx_bmi1) != 0;
        features.bmi2 = (registers.leaf7_ebx & leaf7_ebx_bmi2) != 0;
        features.sha = (registers.leaf7_ebx & leaf7_ebx_sha) != 0;
        features.rdseed = (registers.leaf7_ebx & leaf7_ebx_rdseed) != 0;
        features.smep = (registers.leaf7_ebx & leaf7_ebx_smep) != 0;
        features.invpcid = (registers.leaf7_ebx & leaf7_ebx_invpcid) != 0;
        features.smap = (registers.leaf7_ebx & leaf7_ebx_smap) != 0;
        features.umip = (registers.leaf7_ecx & leaf7_ecx_umip) != 0;
        features.pku = (registers.leaf7_ecx & leaf7_ecx_pku) != 0;
        features.rdpid = (registers.leaf7_ecx & leaf7_ecx_rdpid) != 0;
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
        // Standard and compacted x87/SSE/YMM images fit exactly 832 bytes.
        // YMM is user state; 64-byte compact alignment adds no padding at 576.
        features.ymm_state = features.xsave and registers.leaf13_0_eax & 7 == 7 and
            registers.leaf13_2_eax == 256 and registers.leaf13_2_ebx == 576 and
            registers.leaf13_2_ecx & 1 == 0;
    }
    if (registers.max_extended_leaf >= 0x8000_0001) {
        features.lahf_sahf = (registers.extended1_ecx & extended1_ecx_lahf_sahf) != 0;
        features.lzcnt = (registers.extended1_ecx & extended1_ecx_lzcnt) != 0;
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
    // CPUID.15H reports the TSC/core-crystal ratio and nominal crystal rate.
    // CPUID.16H is display information, not an architectural counter rate.
    if (registers.max_basic_leaf >= 0x15 and
        registers.leaf15_eax != 0 and
        registers.leaf15_ebx != 0 and
        registers.leaf15_ecx != 0)
    {
        const scaled = std.math.mul(u64, registers.leaf15_ecx, registers.leaf15_ebx) catch return 0;
        return scaled / registers.leaf15_eax;
    }
    return 0;
}

// This subset runs in baseline-compiled firmware code before generated native
// instructions. It is also part of the kernel gate and is never modeled away.
pub fn firstMissingCodegen(features: Features) ?MissingFeature {
    if (!features.cpuid) return .cpuid;
    if (!features.sse2) return .sse2;
    if (!features.long_mode) return .long_mode;
    if (!features.sse3) return .sse3;
    if (!features.ssse3) return .ssse3;
    if (!features.sse4_1) return .sse4_1;
    if (!features.sse4_2) return .sse4_2;
    if (!features.popcnt) return .popcnt;
    if (!features.cx16) return .cx16;
    if (!features.lahf_sahf) return .lahf_sahf;
    if (!features.avx) return .avx;
    if (!features.avx2) return .avx2;
    if (!features.f16c) return .f16c;
    if (!features.fma) return .fma;
    if (!features.movbe) return .movbe;
    if (!features.bmi1) return .bmi1;
    if (!features.bmi2) return .bmi2;
    if (!features.lzcnt) return .lzcnt;
    if (!features.aes) return .aes;
    if (!features.pclmul) return .pclmul;
    if (!features.sha) return .sha;
    if (!features.xsave) return .xsave;
    if (!features.ymm_state) return .ymm_state;
    return null;
}

pub fn firstMissing(features: Features) ?MissingFeature {
    if (firstMissingCodegen(features)) |missing| return missing;
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
    if (!features.lass) return .lass;
    if (!features.fred) return .fred;
    if (!features.lkgs) return .lkgs;
    if (!features.pages_1g) return .pages_1g;
    if (!features.tsc_deadline or !features.invariant_tsc or features.tsc_frequency_hz == 0) return .tsc;
    if (!features.rdseed) return .rdseed;
    if (!features.rdpid) return .rdpid;
    return null;
}

pub fn isSupported(features: Features) bool {
    return firstMissing(features) == null;
}

pub fn completeFeatures() Features {
    return .{
        .rdseed = true,
        .rdpid = true,
        .cpuid = true,
        .sse2 = true,
        .sse3 = true,
        .ssse3 = true,
        .sse4_1 = true,
        .sse4_2 = true,
        .popcnt = true,
        .cx16 = true,
        .lahf_sahf = true,
        .avx = true,
        .avx2 = true,
        .f16c = true,
        .fma = true,
        .movbe = true,
        .bmi1 = true,
        .bmi2 = true,
        .lzcnt = true,
        .aes = true,
        .pclmul = true,
        .sha = true,
        .ymm_state = true,
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
        .leaf1_ecx = leaf1_ecx_pcid | leaf1_ecx_x2apic | leaf1_ecx_xsave | leaf1_ecx_tsc_deadline |
            leaf1_ecx_sse3 | leaf1_ecx_ssse3 | leaf1_ecx_sse4_1 | leaf1_ecx_sse4_2 | leaf1_ecx_popcnt | leaf1_ecx_cx16 |
            leaf1_ecx_avx | leaf1_ecx_f16c | leaf1_ecx_fma | leaf1_ecx_movbe | leaf1_ecx_aes | leaf1_ecx_pclmul,
        .leaf13_1_eax = leaf13_1_eax_xsaves,
        .leaf13_0_eax = 7,
        .leaf13_2_eax = 256,
        .leaf13_2_ebx = 576,
        .leaf1_edx = leaf1_edx_sse2 | leaf1_edx_pge,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
        .leaf7_eax = 1,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_invpcid | leaf7_ebx_smap | leaf7_ebx_rdseed |
            leaf7_ebx_avx2 | leaf7_ebx_bmi1 | leaf7_ebx_bmi2 | leaf7_ebx_sha,
        .leaf7_ecx = leaf7_ecx_umip | leaf7_ecx_cet_ss | leaf7_ecx_pku | leaf7_ecx_rdpid,
        .leaf7_edx = leaf7_edx_cet_ibt,
        .leaf7_1_eax = leaf7_1_eax_lass | leaf7_1_eax_fred | leaf7_1_eax_lkgs,
        .max_extended_leaf = 0x8000_0007,
        .extended1_ecx = extended1_ecx_lahf_sahf | extended1_ecx_lzcnt,
        .extended1_edx = extended1_edx_syscall | extended1_edx_nx | extended1_edx_pages_1g | extended1_edx_long_mode,
        .extended7_edx = extended7_edx_invariant_tsc,
    };
}

test "decode recognizes the 2026 x86-64 baseline" {
    const features = decode(modernRegisters());
    try std.testing.expect(isSupported(features));
    try std.testing.expect(features.rdseed);
    try std.testing.expect(features.rdpid);
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

test "codegen gate requires every real v3 crypto instruction and state feature" {
    inline for (.{ .sse3, .ssse3, .sse4_1, .sse4_2, .popcnt, .cx16, .lahf_sahf, .avx, .avx2, .f16c, .fma, .movbe, .bmi1, .bmi2, .lzcnt, .aes, .pclmul, .sha, .xsave, .ymm_state }) |required| {
        var missing = completeFeatures();
        @field(missing, @tagName(required)) = false;
        try std.testing.expectEqual(@as(?MissingFeature, required), firstMissingCodegen(missing));
        try std.testing.expectEqual(@as(?MissingFeature, required), firstMissing(missing));
    }
    // Firmware admission checks codegen only; the kernel still checks security,
    // timer and task-state features before enabling privileged controls.
    var firmware_floor = completeFeatures();
    firmware_floor.fred = false;
    try std.testing.expect(firstMissingCodegen(firmware_floor) == null);
    try std.testing.expectEqual(@as(?MissingFeature, .fred), firstMissing(firmware_floor));
}

test "YMM admission rejects unsupported masks and incompatible save geometry" {
    const invalid = [_]struct { mask: u32 = 7, size: u32 = 256, offset: u32 = 576, flags: u32 = 0 }{
        .{ .mask = 3 },   .{ .mask = 6 },     .{ .mask = 5 },
        .{ .size = 0 },   .{ .size = 255 },   .{ .size = 512 },
        .{ .offset = 0 }, .{ .offset = 512 }, .{ .offset = 832 },
        .{ .flags = 1 },  .{ .flags = 3 },
    };
    for (invalid) |geometry| {
        var registers = modernRegisters();
        registers.leaf13_0_eax = geometry.mask;
        registers.leaf13_2_eax = geometry.size;
        registers.leaf13_2_ebx = geometry.offset;
        registers.leaf13_2_ecx = geometry.flags;
        const result = decode(registers);
        try std.testing.expect(!result.ymm_state);
        try std.testing.expectEqual(@as(?MissingFeature, .ymm_state), firstMissingCodegen(result));
    }
    var registers = modernRegisters();
    registers.leaf13_2_ecx = 2;
    try std.testing.expect(decode(registers).ymm_state);
    registers.max_basic_leaf = 0xC;
    try std.testing.expect(!decode(registers).ymm_state);
    registers = modernRegisters();
    registers.leaf1_ecx &= ~leaf1_ecx_xsave;
    try std.testing.expect(!decode(registers).ymm_state);
}

test "v3 crypto decode requires exact bits in their advertised CPUID leaves" {
    inline for (.{
        .{ "avx", "leaf1_ecx", leaf1_ecx_avx, 1 },
        .{ "f16c", "leaf1_ecx", leaf1_ecx_f16c, 1 },
        .{ "fma", "leaf1_ecx", leaf1_ecx_fma, 1 },
        .{ "movbe", "leaf1_ecx", leaf1_ecx_movbe, 1 },
        .{ "aes", "leaf1_ecx", leaf1_ecx_aes, 1 },
        .{ "pclmul", "leaf1_ecx", leaf1_ecx_pclmul, 1 },
        .{ "avx2", "leaf7_ebx", leaf7_ebx_avx2, 7 },
        .{ "bmi1", "leaf7_ebx", leaf7_ebx_bmi1, 7 },
        .{ "bmi2", "leaf7_ebx", leaf7_ebx_bmi2, 7 },
        .{ "sha", "leaf7_ebx", leaf7_ebx_sha, 7 },
    }) |field| {
        var registers = modernRegisters();
        @field(registers, field[1]) &= ~field[2];
        try std.testing.expect(!@field(decode(registers), field[0]));
        @field(registers, field[1]) = field[2];
        try std.testing.expect(@field(decode(registers), field[0]));
        registers.max_basic_leaf = field[3] - 1;
        try std.testing.expect(!@field(decode(registers), field[0]));
    }
    var registers = modernRegisters();
    registers.extended1_ecx = 0;
    try std.testing.expect(!decode(registers).lzcnt);
    registers.extended1_ecx = extended1_ecx_lzcnt;
    try std.testing.expect(decode(registers).lzcnt);
    registers.max_extended_leaf = 0x8000_0000;
    try std.testing.expect(!decode(registers).lzcnt);
}

test "v2 decode respects advertised CPUID leaves and distinct feature bits" {
    inline for (.{
        .{ "sse3", leaf1_ecx_sse3 },
        .{ "ssse3", leaf1_ecx_ssse3 },
        .{ "sse4_1", leaf1_ecx_sse4_1 },
        .{ "sse4_2", leaf1_ecx_sse4_2 },
        .{ "popcnt", leaf1_ecx_popcnt },
        .{ "cx16", leaf1_ecx_cx16 },
    }) |field| {
        var registers = modernRegisters();
        registers.leaf1_ecx &= ~field[1];
        try std.testing.expect(!@field(decode(registers), field[0]));
        registers.leaf1_ecx = field[1];
        try std.testing.expect(@field(decode(registers), field[0]));
        registers.max_basic_leaf = 0;
        try std.testing.expect(!@field(decode(registers), field[0]));
    }
    var registers = modernRegisters();
    registers.extended1_ecx = 0;
    try std.testing.expect(!decode(registers).lahf_sahf);
    registers.extended1_ecx = extended1_ecx_lahf_sahf;
    try std.testing.expect(decode(registers).lahf_sahf);
    registers.max_extended_leaf = 0x8000_0000;
    try std.testing.expect(!decode(registers).lahf_sahf);
}

test "RDPID decoding requires advertised CPUID leaf 7 and exactly ECX bit 22" {
    for ([_]u32{ 0, 1, 6 }) |max_basic_leaf| {
        try std.testing.expect(!decode(.{
            .cpuid_available = true,
            .max_basic_leaf = max_basic_leaf,
            .leaf7_ecx = 0x0040_0000,
        }).rdpid);
    }
    try std.testing.expect(!decode(.{
        .max_basic_leaf = 7,
        .leaf7_ecx = 0x0040_0000,
    }).rdpid);
    // Leaf 7 subleaf zero advertises RDPID even without subleaf one.
    try std.testing.expect(decode(.{
        .cpuid_available = true,
        .max_basic_leaf = 7,
        .leaf7_ecx = 0x0040_0000,
    }).rdpid);
    for ([_]u32{ 0x0020_0000, 0x0080_0000, 0x00a0_0000, 0xffbf_ffff }) |ecx| {
        try std.testing.expect(!decode(.{
            .cpuid_available = true,
            .max_basic_leaf = 7,
            .leaf7_ebx = 0x0040_0000,
            .leaf7_ecx = ecx,
            .leaf7_edx = 0x0040_0000,
        }).rdpid);
    }
}

test "decode ignores registers outside advertised CPUID ranges" {
    const features = decode(.{
        .cpuid_available = true,
        .leaf1_edx = leaf1_edx_sse2,
        .leaf7_ebx = leaf7_ebx_smep | leaf7_ebx_smap | leaf7_ebx_rdseed,
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
    try std.testing.expect(!features.rdseed);
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
    var missing_nx = completeFeatures();
    missing_nx.nx = false;
    try std.testing.expectEqual(MissingFeature.nx, firstMissing(missing_nx).?);
    var missing_rdseed = completeFeatures();
    missing_rdseed.rdseed = false;
    try std.testing.expectEqual(MissingFeature.rdseed, firstMissing(missing_rdseed).?);
    var missing_rdpid = completeFeatures();
    missing_rdpid.rdpid = false;
    try std.testing.expectEqual(MissingFeature.rdpid, firstMissing(missing_rdpid).?);
    var missing_syscall = completeFeatures();
    missing_syscall.syscall = false;
    try std.testing.expectEqual(MissingFeature.syscall, firstMissing(missing_syscall).?);
    var missing_pcid = completeFeatures();
    missing_pcid.pcid = false;
    try std.testing.expectEqual(MissingFeature.pcid, firstMissing(missing_pcid).?);
    var missing_pku = completeFeatures();
    missing_pku.pku = false;
    try std.testing.expect(firstMissing(missing_pku) == null);
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

test "TSC frequency requires an advertised complete CPUID crystal ratio" {
    try std.testing.expectEqual(@as(u64, 2_400_000_000), decodeTscFrequency(.{
        .max_basic_leaf = 0x16,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
    }));
    try std.testing.expectEqual(@as(u64, 0), decodeTscFrequency(.{
        .max_basic_leaf = 0x14,
        .leaf15_eax = 2,
        .leaf15_ebx = 200,
        .leaf15_ecx = 24_000_000,
    }));
}

test "TSC rejects a leaf16 only processor base frequency" {
    var registers = modernRegisters();
    registers.leaf15_eax = 0;
    registers.leaf15_ebx = 0;
    registers.leaf15_ecx = 0;
    // Later CPUID leaves cannot supply a replacement counter frequency.
    try std.testing.expect(!@hasField(Registers, "leaf16_eax"));
    const features = decode(registers);
    try std.testing.expectEqual(@as(u64, 0), features.tsc_frequency_hz);
    try std.testing.expectEqual(MissingFeature.tsc, firstMissing(features).?);
}

test "TSC rejects each incomplete architectural frequency field" {
    for (0..3) |missing_field| {
        var registers = modernRegisters();
        switch (missing_field) {
            0 => registers.leaf15_eax = 0,
            1 => registers.leaf15_ebx = 0,
            2 => registers.leaf15_ecx = 0,
            else => unreachable,
        }
        const features = decode(registers);
        try std.testing.expectEqual(@as(u64, 0), features.tsc_frequency_hz);
        try std.testing.expectEqual(MissingFeature.tsc, firstMissing(features).?);
    }
}

test "TSC rejects a complete ratio that does not produce a usable frequency" {
    var registers = modernRegisters();
    registers.leaf15_eax = std.math.maxInt(u32);
    registers.leaf15_ebx = 1;
    registers.leaf15_ecx = 1;
    const features = decode(registers);
    try std.testing.expectEqual(@as(u64, 0), features.tsc_frequency_hz);
    try std.testing.expectEqual(MissingFeature.tsc, firstMissing(features).?);
}

test "a valid clock never relaxes the mandatory XSAVES floor" {
    var features = completeFeatures();
    features.xsaves = false;
    try std.testing.expectEqual(MissingFeature.xsaves, firstMissing(features).?);
}
