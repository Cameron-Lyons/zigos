const x86 = @import("x86.zig");
pub const baseline = @import("cpu_baseline.zig");
pub const cache_policy = @import("cache_policy.zig");

pub inline fn validateBootstrapCache() cache_policy.AdmissionError!void {
    try cache_policy.validateBootstrap(x86.readBootstrapCacheState());
}

pub const CacheAdmissionError = cache_policy.CacheAdmissionError;

pub inline fn initializeNativeCachePolicy() CacheAdmissionError!void {
    try validateBootstrapCache();
    var state: cache_policy.MtrrState = undefined;
    try x86.readMtrrStateInto(&state);
    try cache_policy.initializeBsp(&state);
}

pub inline fn admitApplicationProcessorCache() CacheAdmissionError!void {
    try validateBootstrapCache();
    var state: cache_policy.MtrrState = undefined;
    try x86.readMtrrStateInto(&state);
    try cache_policy.admitApplicationProcessor(&state);
}

const cpuid = x86.cpuid;

pub fn clflushLineBytes() ?usize {
    const leaf = cpuid(1, 0);
    return decodeClflushLineBytes(leaf.ebx, leaf.edx);
}

fn decodeClflushLineBytes(ebx: u32, edx: u32) ?usize {
    if (edx & (1 << 19) == 0) return null;
    const bytes: usize = ((ebx >> 8) & 0xFF) * 8;
    if (bytes == 0 or bytes > 4096 or !@import("std").math.isPowerOfTwo(bytes)) return null;
    return bytes;
}

test "VT-d cache maintenance requires a valid advertised CLFLUSH line" {
    const std = @import("std");
    try std.testing.expectEqual(@as(?usize, 64), decodeClflushLineBytes(8 << 8, 1 << 19));
    try std.testing.expectEqual(@as(?usize, null), decodeClflushLineBytes(8 << 8, 0));
    try std.testing.expectEqual(@as(?usize, null), decodeClflushLineBytes(0, 1 << 19));
    try std.testing.expectEqual(@as(?usize, null), decodeClflushLineBytes(3 << 8, 1 << 19));
}

pub fn detect() baseline.Features {
    var registers = baseline.Registers{};
    registers.max_basic_leaf = cpuid(0, 0).eax;
    if (registers.max_basic_leaf >= 1) {
        const leaf1 = cpuid(1, 0);
        registers.leaf1_ecx = leaf1.ecx;
        registers.leaf1_edx = leaf1.edx;
    }
    if (registers.max_basic_leaf >= 0x15) {
        const leaf15 = cpuid(0x15, 0);
        registers.leaf15_eax = leaf15.eax;
        registers.leaf15_ebx = leaf15.ebx;
        registers.leaf15_ecx = leaf15.ecx;
    }
    if (registers.max_basic_leaf >= 7) {
        const leaf7 = cpuid(7, 0);
        registers.leaf7_eax = leaf7.eax;
        registers.leaf7_ebx = leaf7.ebx;
        registers.leaf7_ecx = leaf7.ecx;
        registers.leaf7_edx = leaf7.edx;
        if (leaf7.eax >= 1) {
            registers.leaf7_1_eax = cpuid(7, 1).eax;
        }
    }
    if (registers.max_basic_leaf >= 0xD) {
        const leaf13 = cpuid(0xD, 0);
        registers.leaf13_0_eax = leaf13.eax;
        registers.leaf13_1_eax = cpuid(0xD, 1).eax;
        if (leaf13.eax & (1 << 2) != 0) {
            const ymm = cpuid(0xD, 2);
            registers.leaf13_2_eax = ymm.eax;
            registers.leaf13_2_ebx = ymm.ebx;
            registers.leaf13_2_ecx = ymm.ecx;
        }
    }

    registers.max_extended_leaf = cpuid(0x8000_0000, 0).eax;
    if (registers.max_extended_leaf >= 0x8000_0001) {
        const extended1 = cpuid(0x8000_0001, 0);
        registers.extended1_ecx = extended1.ecx;
        registers.extended1_edx = extended1.edx;
    }
    if (registers.max_extended_leaf >= 0x8000_0007) {
        registers.extended7_edx = cpuid(0x8000_0007, 0).edx;
    }
    return baseline.decode(registers);
}

pub const ProcessContextMode = enum {
    hardware_pcid,
    software_flush,
};

pub const CetMode = enum {
    hardware,
    deferred,
};

// Admission (cpu_policy.AdmissionPolicy.firstMissing) has already accepted
// these features and modes for this CPU. Every guard and control readback
// below still halts instead of becoming an optimizer assumption.
pub fn enableModernFeatures(
    features: baseline.Features,
    process_context_mode: ProcessContextMode,
    cet_mode: CetMode,
) void {
    x86.enableNoExecute();
    if (!x86.noExecuteEnabled()) x86.haltFatal();
    var cr4 = x86.readCr4();
    cr4 |= x86.CR4_PGE;
    cr4 |= x86.CR4_SMEP;
    cr4 |= x86.CR4_SMAP;
    cr4 |= x86.CR4_UMIP;
    x86.writeCr4(cr4);
    // UEFI specifies DF, but leaves AC undefined. Close inherited user-memory
    // access before treating SMAP or later LASS activation as enforced.
    x86.forbidSupervisorUserMemory();
    if (!x86.globalPagesEnabled()) x86.haltFatal();
    if (!x86.supervisorAccessPreventionEnabled()) x86.haltFatal();
    if (process_context_mode == .hardware_pcid) {
        if (!features.pcid or !features.invpcid) x86.haltFatal();
        x86.enableProcessContextIdentifiers();
        if (!x86.processContextIdentifiersEnabled()) x86.haltFatal();
    }
    if (!features.xsave or !features.xsaves) x86.haltFatal();
    x86.enableXsaves();
    if (!x86.xsavesEnabled()) x86.haltFatal();
    if (cet_mode == .hardware) {
        if (!features.cet_ibt or !features.cet_ss) x86.haltFatal();
        x86.enableCet();
        if (!x86.cetEnabled()) x86.haltFatal();
    }
    if (features.pku) {
        x86.enablePku();
        if (!x86.pkuEnabled()) x86.haltFatal();
    }
    // LASS still belongs to the mandatory hardware admission floor. Its CR4
    // activation waits until this CPU owns upper-half descriptor/native entry
    // state; inherited firmware GDTR/IDTR addresses may remain in the low half.
}
