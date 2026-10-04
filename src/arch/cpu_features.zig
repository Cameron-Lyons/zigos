const x86 = @import("x86.zig");
pub const baseline = @import("cpu_baseline.zig");

const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

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
    var registers = baseline.Registers{ .cpuid_available = true };
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
        registers.leaf13_1_eax = cpuid(0xD, 1).eax;
    }

    registers.max_extended_leaf = cpuid(0x8000_0000, 0).eax;
    if (registers.max_extended_leaf >= 0x8000_0001) {
        registers.extended1_edx = cpuid(0x8000_0001, 0).edx;
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

pub const FeatureMode = enum {
    hardware,
    explicit_model,
};

pub fn firstMissingForEnablement(
    features: baseline.Features,
    process_context_mode: ProcessContextMode,
    cet_mode: CetMode,
    feature_mode: FeatureMode,
) ?baseline.MissingFeature {
    var required_features = features;
    switch (feature_mode) {
        .hardware => {
            if (process_context_mode != .hardware_pcid) return .pcid;
            if (cet_mode != .hardware) return .cet_ibt;
        },
        .explicit_model => {
            if (process_context_mode == .software_flush) {
                required_features.pcid = true;
                required_features.invpcid = true;
            }
            if (cet_mode == .deferred) {
                required_features.cet_ibt = true;
                required_features.cet_ss = true;
            }
            required_features.lass = true;
            required_features.fred = true;
            required_features.lkgs = true;
            required_features.tsc_deadline = true;
            required_features.invariant_tsc = true;
        },
    }
    return baseline.firstMissing(required_features);
}

pub fn enableModernFeatures(
    features: baseline.Features,
    process_context_mode: ProcessContextMode,
    cet_mode: CetMode,
    feature_mode: FeatureMode,
) void {
    if (firstMissingForEnablement(features, process_context_mode, cet_mode, feature_mode) != null) unreachable;
    x86.enableNoExecute();
    if (!x86.noExecuteEnabled()) unreachable;
    var cr4 = x86.readCr4();
    cr4 |= x86.CR4_PGE;
    cr4 |= x86.CR4_SMEP;
    cr4 |= x86.CR4_SMAP;
    cr4 |= x86.CR4_UMIP;
    x86.writeCr4(cr4);
    if (!x86.globalPagesEnabled()) unreachable;
    if (!x86.supervisorAccessPreventionEnabled()) unreachable;
    if (process_context_mode == .hardware_pcid) {
        if (!features.pcid or !features.invpcid) unreachable;
        x86.enableProcessContextIdentifiers();
        if (!x86.processContextIdentifiersEnabled()) unreachable;
    }
    if (!features.xsave or !features.xsaves) unreachable;
    x86.enableXsaves();
    if (!x86.xsavesEnabled()) unreachable;
    if (cet_mode == .hardware) {
        if (!features.cet_ibt or !features.cet_ss) unreachable;
        x86.enableCet();
        if (!x86.cetEnabled()) unreachable;
    }
    if (features.pku) {
        x86.enablePku();
        if (!x86.pkuEnabled()) unreachable;
    }
    if (features.lass) {
        x86.enableLass();
        if (!x86.lassEnabled()) unreachable;
    }
}

test "explicit model enablement accepts only its selected software controls" {
    var features = baseline.completeFeatures();
    features.pcid = false;
    features.invpcid = false;
    features.cet_ibt = false;
    features.cet_ss = false;
    features.lass = false;
    features.fred = false;
    features.lkgs = false;
    features.tsc_deadline = false;
    features.invariant_tsc = false;
    try @import("std").testing.expectEqual(@as(?baseline.MissingFeature, null), firstMissingForEnablement(features, .software_flush, .deferred, .explicit_model));
    try @import("std").testing.expectEqual(@as(?baseline.MissingFeature, .pcid), firstMissingForEnablement(features, .hardware_pcid, .deferred, .explicit_model));
    features.pcid = true;
    features.invpcid = true;
    try @import("std").testing.expectEqual(@as(?baseline.MissingFeature, .cet_ibt), firstMissingForEnablement(features, .hardware_pcid, .hardware, .explicit_model));
}

test "hardware enablement rejects missing mandatory controls and software policy" {
    const std = @import("std");
    var features = baseline.completeFeatures();
    try std.testing.expectEqual(@as(?baseline.MissingFeature, null), firstMissingForEnablement(features, .hardware_pcid, .hardware, .hardware));
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .pcid), firstMissingForEnablement(features, .software_flush, .hardware, .hardware));
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .cet_ibt), firstMissingForEnablement(features, .hardware_pcid, .deferred, .hardware));
    features.lass = false;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .lass), firstMissingForEnablement(features, .hardware_pcid, .hardware, .hardware));
    features.lass = true;
    features.fred = false;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .fred), firstMissingForEnablement(features, .hardware_pcid, .hardware, .hardware));
    features.fred = true;
    features.tsc_deadline = false;
    try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), firstMissingForEnablement(features, .hardware_pcid, .hardware, .hardware));
}

test "every enablement mode requires real XSAVES and a selected clock" {
    const std = @import("std");
    for ([_]FeatureMode{ .hardware, .explicit_model }) |mode| {
        inline for ([_]baseline.MissingFeature{ .cpuid, .sse2, .long_mode, .syscall, .nx, .smep, .smap, .umip, .pge, .x2apic, .xsave, .xsaves, .pages_1g, .rdseed, .rdpid }) |required| {
            var missing = baseline.completeFeatures();
            @field(missing, @tagName(required)) = false;
            try std.testing.expectEqual(@as(?baseline.MissingFeature, required), firstMissingForEnablement(missing, .hardware_pcid, .hardware, mode));
        }
        var features = baseline.completeFeatures();
        features.tsc_frequency_hz = 0;
        try std.testing.expectEqual(@as(?baseline.MissingFeature, .tsc), firstMissingForEnablement(features, .hardware_pcid, .hardware, mode));
    }
}
