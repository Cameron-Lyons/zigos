//! CPUID-based detection of supervisor-mode hardening features and the
//! CR4 writes that enable them. Detection is dynamic so the same kernel
//! image hardens itself on capable hardware and still boots on CPUs that
//! predate these features.

const x86 = @import("x86.zig");

pub const Features = struct {
    smep: bool = false,
    umip: bool = false,
};

const eflags_id: u32 = 1 << 21;
const leaf7_ebx_smep: u32 = 1 << 7;
const leaf7_ecx_umip: u32 = 1 << 2;

const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuidSupported() bool {
    const toggled = asm volatile (
        \\pushfl
        \\popl %[flags]
        \\movl %[flags], %%ecx
        \\xorl $0x200000, %[flags]
        \\pushl %[flags]
        \\popfl
        \\pushfl
        \\popl %[flags]
        \\xorl %%ecx, %[flags]
        \\pushl %%ecx
        \\popfl
        : [flags] "=&r" (-> u32),
        :
        : .{ .ecx = true, .cc = true });
    return (toggled & eflags_id) != 0;
}

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

pub fn detect() Features {
    if (!cpuidSupported()) return .{};
    if (cpuid(0, 0).eax < 7) return .{};
    const leaf7 = cpuid(7, 0);
    return .{
        .smep = (leaf7.ebx & leaf7_ebx_smep) != 0,
        .umip = (leaf7.ecx & leaf7_ecx_umip) != 0,
    };
}

/// Turn on every supported supervisor protection. SMEP makes the CPU fault
/// on any ring-0 instruction fetch from a user-accessible page; UMIP stops
/// ring 3 from reading descriptor-table addresses via sgdt/sidt/sldt/str/smsw.
pub fn enable(features: Features) void {
    var cr4 = x86.readCr4();
    if (features.smep) cr4 |= x86.CR4_SMEP;
    if (features.umip) cr4 |= x86.CR4_UMIP;
    x86.writeCr4(cr4);
}
