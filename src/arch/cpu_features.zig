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
    if (registers.max_basic_leaf >= 0x16) {
        registers.leaf16_eax = cpuid(0x16, 0).eax;
    }
    if (registers.max_basic_leaf >= 7) {
        const leaf7 = cpuid(7, 0);
        registers.leaf7_ebx = leaf7.ebx;
        registers.leaf7_ecx = leaf7.ecx;
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

pub fn enableModernFeatures(features: baseline.Features, process_context_mode: ProcessContextMode) void {
    var required_features = features;
    if (process_context_mode == .software_flush) {
        required_features.pcid = true;
        required_features.invpcid = true;
    }
    if (!baseline.isSupported(required_features)) unreachable;
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
}
