//! Hardware CPUID collection and supervisor-protection enablement for the
//! mandatory modern CPU baseline.

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
    // CPUID predates the mandatory x86-64 baseline by a decade. Unsupported
    // pre-Pentium processors are deliberately outside the platform contract.
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

/// Turn on the hardware protections that are safe with the current memory
/// access model. NX enforces execute-disable page-table entries, SMEP blocks
/// ring-0 execution from user pages, and UMIP hides descriptor-table state from
/// ring 3. SMAP is required by the baseline but is enabled with the controlled
/// user-copy primitives in the paging migration.
pub fn enableSupervisorProtections(features: baseline.Features) void {
    if (!baseline.isSupported(features)) unreachable;
    x86.enableNoExecute();
    if (!x86.noExecuteEnabled()) unreachable;
    var cr4 = x86.readCr4();
    cr4 |= x86.CR4_SMEP;
    cr4 |= x86.CR4_UMIP;
    x86.writeCr4(cr4);
}
