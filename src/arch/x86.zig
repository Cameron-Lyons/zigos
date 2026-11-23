const cache_policy = @import("cache_policy.zig");

pub inline fn hlt() void {
    asm volatile ("hlt");
}

pub inline fn cli() void {
    asm volatile ("cli" ::: .{ .memory = true });
}

pub inline fn sti() void {
    asm volatile ("sti" ::: .{ .memory = true });
}

pub inline fn stiHlt() void {
    asm volatile ("sti; hlt" ::: .{ .memory = true });
}

// Fail closed on a violated privileged-control invariant. Unlike
// `unreachable`, this survives ReleaseFast and never becomes an assumption.
pub fn haltFatal() noreturn {
    @branchHint(.cold);
    cli();
    while (true) hlt();
}

pub inline fn interruptsEnabled() bool {
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    return (flags & (1 << 9)) != 0;
}

pub inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn rdtsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | low;
}

pub inline fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

pub inline fn writeMsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(value))),
          [high] "{edx}" (@as(u32, @truncate(value >> 32))),
        : .{ .memory = true });
}

pub inline fn stackPointer() usize {
    return asm volatile ("mov %%rsp, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn readCr2() usize {
    return asm volatile ("mov %%cr2, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn invalidatePage(address: usize) void {
    asm volatile ("invlpg (%%rax)"
        :
        : [address] "{rax}" (address),
        : .{ .memory = true });
}

pub inline fn loadIdt(descriptor: *const anyopaque) void {
    asm volatile ("lidtq (%%rax)"
        :
        : [descriptor] "{rax}" (descriptor),
        : .{ .memory = true });
}

pub const CR0_EM: usize = 1 << 2;
pub const CR0_MP: usize = 1 << 1;
pub const CR0_TS: usize = 1 << 3;
pub const CR0_WP: usize = 1 << 16;
pub const CR0_PG: usize = 1 << 31;
pub const CR0_CD = cache_policy.CR0_CD;
pub const CR0_NW = cache_policy.CR0_NW;

pub const CR4_PGE: usize = 1 << 7;
pub const CR4_OSFXSR: usize = 1 << 9;
pub const CR4_OSXMMEXCPT: usize = 1 << 10;
pub const CR4_UMIP: usize = 1 << 11;
pub const CR4_PCIDE: usize = 1 << 17;
pub const CR4_OSXSAVE: usize = 1 << 18;
pub const CR4_SMEP: usize = 1 << 20;
pub const CR4_SMAP: usize = 1 << 21;
pub const CR4_PKE: usize = 1 << 22;
pub const CR4_CET: usize = 1 << 23;
pub const CR4_LASS: usize = 1 << 27;
pub const CR4_FRED: usize = 1 << 32;

pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_YMM: u64 = 1 << 2;

pub const CR3_PCID_MASK: usize = 0x0FFF;
pub const CR3_ADDRESS_MASK: usize = 0x000F_FFFF_FFFF_F000;
pub const CR3_NO_FLUSH: usize = 1 << 63;

const InvpcidDescriptor = extern struct {
    pcid: u64,
    linear_address: u64,
};

extern fn x86_invalidate_pcid(descriptor: *const InvpcidDescriptor) callconv(.c) void;
extern fn x86_invalidate_all(descriptor: *const InvpcidDescriptor) callconv(.c) void;

pub const EFER_MSR: u32 = 0xC000_0080;
pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_NXE: u64 = 1 << 11;
pub const IA32_STAR_MSR: u32 = 0xC000_0081;
pub const IA32_LSTAR_MSR: u32 = 0xC000_0082;
pub const IA32_FMASK_MSR: u32 = 0xC000_0084;
pub const IA32_GS_BASE_MSR: u32 = 0xC000_0101;
pub const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC000_0102;
pub const IA32_TSC_AUX_MSR: u32 = 0xC000_0103;
pub const IA32_XSS_MSR: u32 = 0xDA0;
pub const IA32_PAT_MSR = cache_policy.PAT_MSR;
pub const IA32_MTRR_CAP_MSR: u32 = 0xFE;
pub const IA32_MTRR_DEFAULT_TYPE_MSR: u32 = 0x2FF;
pub const IA32_U_CET_MSR: u32 = 0x6A0;
pub const IA32_S_CET_MSR: u32 = 0x6A2;
pub const CET_SH_STK_EN: u64 = 1 << 0;
pub const CET_ENDBR_EN: u64 = 1 << 2;
pub const IA32_FRED_RSP0_MSR: u32 = 0x1CC;
pub const IA32_FRED_RSP1_MSR: u32 = 0x1CD;
pub const IA32_FRED_RSP2_MSR: u32 = 0x1CE;
pub const IA32_FRED_RSP3_MSR: u32 = 0x1CF;
pub const IA32_FRED_STKLVLS_MSR: u32 = 0x1D0;
pub const IA32_FRED_CONFIG_MSR: u32 = 0x1D4;
pub const FRED_STACK_ALIGNMENT: usize = 64;
const FRED_DOUBLE_FAULT_STACK_LEVELS: u64 = @as(u64, 3) << (2 * 8);

// CPUID.7.0:ECX[22] gates RDPID and IA32_TSC_AUX. It reads the kernel's
// logical CPU signature without reading mutable GS state or using RDMSR.
pub inline fn readProcessorId() u32 {
    const signature = asm volatile ("rdpid %[out]"
        : [out] "=r" (-> usize),
    );
    return @truncate(signature);
}

pub inline fn enableNoExecute() void {
    writeMsr(EFER_MSR, readMsr(EFER_MSR) | EFER_NXE);
}

pub inline fn noExecuteEnabled() bool {
    return (readMsr(EFER_MSR) & EFER_NXE) != 0;
}

pub inline fn syscallExtensionEnabled() bool {
    return (readMsr(EFER_MSR) & EFER_SCE) != 0;
}

pub inline fn readCr0() usize {
    return asm volatile ("mov %%cr0, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

pub inline fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
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

pub inline fn readPat() ?u64 {
    if (cpuid(1, 0).edx & cache_policy.CPUID_PAT == 0) return null;
    return readMsr(IA32_PAT_MSR);
}

pub inline fn readBootstrapCacheState() cache_policy.BootstrapState {
    const pat = readPat();
    return .{ .pat_supported = pat != null, .cr0 = readCr0(), .pat = pat orelse 0 };
}

// MTRR interpretation remains separate from PAT selection. These gated reads
// expose firmware state without changing package-shared cache configuration.
pub inline fn readMtrrCapabilities() ?u64 {
    if (cpuid(1, 0).edx & (1 << 12) == 0) return null;
    return readMsr(IA32_MTRR_CAP_MSR);
}

// Fill caller-owned bounded storage. No large error-union snapshot is copied
// on rejection; the caller may publish or query it only after success.
pub inline fn readMtrrStateInto(state: *cache_policy.MtrrState) cache_policy.MtrrError!void {
    const capabilities = readMtrrCapabilities() orelse return error.MtrrUnsupported;
    const count: usize = @as(u8, @truncate(capabilities));
    // Reject before any unimplemented pair is addressed. Future variable
    // counts need an explicit bounded contract rather than partial admission.
    if (count > cache_policy.MAX_VARIABLE_MTRRS) return error.UnsupportedVariableMtrrCount;
    if (cpuid(0x8000_0000, 0).eax < 0x8000_0008) return error.UnsupportedPhysicalAddressWidth;
    const physical_bits: u8 = @truncate(cpuid(0x8000_0008, 0).eax);
    if (physical_bits < 32 or physical_bits > 52) return error.UnsupportedPhysicalAddressWidth;
    @memset(@import("std").mem.asBytes(state), 0);
    state.physical_bits = physical_bits;
    state.capabilities = capabilities;
    state.default_type = readMsr(IA32_MTRR_DEFAULT_TYPE_MSR);
    if (capabilities & cache_policy.MTRR_FIXED_SUPPORTED != 0) {
        inline for (cache_policy.FIXED_MTRR_MSRS, 0..) |msr, index| state.fixed[index] = readMsr(msr);
    }
    for (state.variable[0..count], 0..) |*pair, index| {
        const msr = cache_policy.MTRR_VARIABLE_BASE_MSR + @as(u32, @intCast(index)) * 2;
        pair.* = .{ .base = readMsr(msr), .mask = readMsr(msr + 1) };
    }
    try state.validate();
}

pub inline fn writeBackInvalidateCaches() void {
    asm volatile ("wbinvd" ::: .{ .memory = true });
}

pub inline fn flushCacheLine(address: usize) void {
    asm volatile ("clflush (%[address])"
        :
        : [address] "r" (address),
        : .{ .memory = true });
}

pub inline fn writeCr0(value: usize) void {
    asm volatile ("mov %[value], %%cr0"
        :
        : [value] "r" (value),
        : .{ .memory = true });
}

pub inline fn taskSwitched() bool {
    return (readCr0() & CR0_TS) != 0;
}

pub inline fn clearTaskSwitched() void {
    writeCr0(readCr0() & ~CR0_TS);
}

pub inline fn readCr3() usize {
    return asm volatile ("mov %%cr3, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn writeCr3(value: usize) void {
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (value),
        : .{ .memory = true });
}

pub fn pcidCr3Value(page_table_root: usize, pcid: u16, preserve_translations: bool) ?usize {
    if ((page_table_root & ~CR3_ADDRESS_MASK) != 0) return null;
    if (@as(usize, pcid) > CR3_PCID_MASK) return null;
    return page_table_root |
        @as(usize, pcid) |
        (if (preserve_translations) CR3_NO_FLUSH else 0);
}

pub inline fn invalidatePcid(pcid: u16) void {
    const descriptor = InvpcidDescriptor{
        .pcid = pcid,
        .linear_address = 0,
    };
    x86_invalidate_pcid(&descriptor);
}

pub inline fn invalidateAllTranslations() void {
    if (processContextIdentifiersEnabled()) {
        const descriptor = InvpcidDescriptor{ .pcid = 0, .linear_address = 0 };
        x86_invalidate_all(&descriptor);
        return;
    }
    // The explicit model may lack INVPCID, but still requires real PGE.
    // A CR3 reload alone retains global entries. Changing PGE invalidates
    // every context, including globals, before restoring this CPU's controls.
    const cr4 = readCr4();
    if (cr4 & CR4_PGE != 0) {
        writeCr4(cr4 & ~CR4_PGE);
        writeCr4(cr4);
    } else {
        writeCr3(readCr3());
    }
}

pub inline fn readCr4() usize {
    return asm volatile ("mov %%cr4, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn writeCr4(value: usize) void {
    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (value),
        : .{ .memory = true });
}

pub inline fn enableProcessContextIdentifiers() void {
    if ((readCr3() & CR3_PCID_MASK) != 0) haltFatal();
    writeCr4(readCr4() | CR4_PCIDE);
}

pub inline fn processContextIdentifiersEnabled() bool {
    return (readCr4() & CR4_PCIDE) != 0;
}

pub inline fn globalPagesEnabled() bool {
    return (readCr4() & CR4_PGE) != 0;
}

pub inline fn supervisorAccessPreventionEnabled() bool {
    return (readCr4() & CR4_SMAP) != 0;
}

// The memory clobbers keep user accesses inside the STAC/CLAC window.
pub inline fn allowSupervisorUserMemory() void {
    asm volatile ("stac" ::: .{ .memory = true });
}

pub inline fn forbidSupervisorUserMemory() void {
    asm volatile ("clac" ::: .{ .memory = true });
}

pub fn enableXsaves() void {
    writeCr4(readCr4() | CR4_OSXSAVE);
    writeXcr0(XCR0_X87 | XCR0_SSE | XCR0_YMM);
    // Bound every XSAVES/XRSTORS owner to the enabled native image.
    writeMsr(IA32_XSS_MSR, 0);
    clearTaskSwitched();
}

pub fn xsavesEnabled() bool {
    return (readCr4() & CR4_OSXSAVE) != 0 and readXcr0() == (XCR0_X87 | XCR0_SSE | XCR0_YMM) and
        readMsr(IA32_XSS_MSR) == 0;
}

pub fn enableCet() void {
    writeMsr(IA32_S_CET_MSR, CET_ENDBR_EN);
    writeMsr(IA32_U_CET_MSR, 0);
    writeCr4(readCr4() | CR4_CET);
}

pub fn cetEnabled() bool {
    return (readCr4() & CR4_CET) != 0 and
        (readMsr(IA32_S_CET_MSR) & CET_ENDBR_EN) != 0;
}

pub fn wrpkru(value: u32) void {
    if (!pkuEnabled()) return;
    asm volatile (".byte 0x0f, 0x01, 0xef" // wrpkru
        :
        : [value] "{eax}" (value),
          [ecx] "{ecx}" (@as(u32, 0)),
          [edx] "{edx}" (@as(u32, 0)),
        : .{ .memory = true });
}

// Requires CR4.PKE; callers check their published entry mode first.
pub inline fn rdpkru() u32 {
    return asm volatile (".byte 0x0f, 0x01, 0xee" // rdpkru
        : [value] "={eax}" (-> u32),
        : [ecx] "{ecx}" (@as(u32, 0)),
        : .{ .rdx = true });
}

pub fn pkruAllowKeys(key: u4) u32 {
    var value: u32 = 0xFFFF_FFFC;
    if (key != 0) {
        const shift: u5 = @as(u5, key) * 2;
        value &= ~(@as(u32, 0b11) << shift);
    }
    return value;
}

pub fn allowUserProtectionKey(key: u4) void {
    wrpkru(pkruAllowKeys(key));
}

pub fn enablePku() void {
    writeCr4(readCr4() | CR4_PKE);
    wrpkru(0);
}

pub fn pkuEnabled() bool {
    return (readCr4() & CR4_PKE) != 0;
}

extern var __kernel_data_start: u8;

const DescriptorTableRegister = extern struct {
    limit: u16 align(1),
    base: usize align(1),
};

pub inline fn lassAddressPartitionSupported() bool {
    const instruction = asm volatile ("lea 0(%%rip), %[value]"
        : [value] "=r" (-> usize),
    );
    var gdtr: DescriptorTableRegister = undefined;
    var idtr: DescriptorTableRegister = undefined;
    asm volatile ("sgdt (%[table])"
        :
        : [table] "r" (&gdtr),
        : .{ .memory = true });
    asm volatile ("sidt (%[table])"
        :
        : [table] "r" (&idtr),
        : .{ .memory = true });
    return @import("cpu_baseline.zig").lassAddressPartitionSupported(.{
        .instruction = instruction,
        .stack = stackPointer(),
        .kernel_data = @intFromPtr(&__kernel_data_start),
        .gdt = .{ .base = gdtr.base, .limit = gdtr.limit },
        .idt = .{ .base = idtr.base, .limit = idtr.limit },
    });
}

pub inline fn enableLass() error{UnsupportedKernelAddressPartition}!void {
    if (!lassAddressPartitionSupported()) return error.UnsupportedKernelAddressPartition;
    writeCr4(readCr4() | CR4_LASS);
}

comptime {
    if (@sizeOf(DescriptorTableRegister) != 10 or @alignOf(DescriptorTableRegister) != 1)
        @compileError("SGDT/SIDT operands require an unpadded ten-byte layout");
}

pub fn lassEnabled() bool {
    return (readCr4() & CR4_LASS) != 0;
}

// fred64.S fixes the 4 KiB entry alignment and the CPL0 entry at +256 when
// it is assembled.
extern fn zigos_fred_entry() callconv(.c) void;

pub fn enableFred(kernel_stack_top: usize, double_fault_stack_top: usize) void {
    if (!validFredStackTop(kernel_stack_top) or !validFredStackTop(double_fault_stack_top)) haltFatal();
    const entry = @intFromPtr(&zigos_fred_entry);
    writeMsr(IA32_FRED_RSP0_MSR, kernel_stack_top);
    writeMsr(IA32_FRED_RSP1_MSR, kernel_stack_top);
    writeMsr(IA32_FRED_RSP2_MSR, kernel_stack_top);
    writeMsr(IA32_FRED_RSP3_MSR, double_fault_stack_top);
    writeMsr(IA32_FRED_STKLVLS_MSR, FRED_DOUBLE_FAULT_STACK_LEVELS);
    writeMsr(IA32_FRED_CONFIG_MSR, entry);
    writeCr4(readCr4() | CR4_FRED);
}

pub inline fn fredEntryAddress() usize {
    return @intFromPtr(&zigos_fred_entry);
}

pub inline fn fredEnabled(kernel_stack_top: usize, emergency_stack_top: usize) bool {
    return fredEnabledWith(kernel_stack_top, emergency_stack_top, fredEntryAddress(), struct {
        inline fn readCr4(_: @This()) usize {
            return @import("x86.zig").readCr4();
        }
        inline fn readMsr(_: @This(), msr: u32) u64 {
            return @import("x86.zig").readMsr(msr);
        }
    }{});
}

pub inline fn fredEnabledWith(kernel_stack_top: usize, emergency_stack_top: usize, entry: usize, hardware: anytype) bool {
    return validFredStackTop(kernel_stack_top) and validFredStackTop(emergency_stack_top) and
        fredControlMatchesWith(emergency_stack_top, entry, hardware) and
        hardware.readMsr(IA32_FRED_RSP0_MSR) == kernel_stack_top and
        hardware.readMsr(IA32_FRED_RSP1_MSR) == kernel_stack_top and
        hardware.readMsr(IA32_FRED_RSP2_MSR) == kernel_stack_top;
}

pub inline fn fredControlMatchesWith(emergency_stack_top: usize, entry: usize, hardware: anytype) bool {
    return (hardware.readCr4() & CR4_FRED) != 0 and
        hardware.readMsr(IA32_FRED_CONFIG_MSR) == entry and
        hardware.readMsr(IA32_FRED_STKLVLS_MSR) == FRED_DOUBLE_FAULT_STACK_LEVELS and
        hardware.readMsr(IA32_FRED_RSP3_MSR) == emergency_stack_top;
}

pub inline fn updateFredStack(kernel_stack_top: usize) void {
    updateFredStackWith(kernel_stack_top, struct {
        inline fn writeMsr(_: @This(), msr: u32, value: u64) void {
            @import("x86.zig").writeMsr(msr, value);
        }
    }{});
}

pub inline fn updateFredStackWith(kernel_stack_top: usize, hardware: anytype) void {
    if (!validFredStackTop(kernel_stack_top)) haltFatal();
    hardware.writeMsr(IA32_FRED_RSP0_MSR, kernel_stack_top);
    hardware.writeMsr(IA32_FRED_RSP1_MSR, kernel_stack_top);
    hardware.writeMsr(IA32_FRED_RSP2_MSR, kernel_stack_top);
}

pub inline fn validFredStackTop(stack_top: usize) bool {
    return stack_top >= 0xFFFF_8000_0000_0000 and stack_top % FRED_STACK_ALIGNMENT == 0;
}

pub fn writeXcr0(value: u64) void {
    asm volatile (".byte 0x0f, 0x01, 0xd1" // xsetbv
        :
        : [low] "{eax}" (@as(u32, @truncate(value))),
          [high] "{edx}" (@as(u32, @truncate(value >> 32))),
          [index] "{ecx}" (@as(u32, 0)),
        : .{ .memory = true });
}

pub fn readXcr0() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile (".byte 0x0f, 0x01, 0xd0" // xgetbv
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [index] "{ecx}" (@as(u32, 0)),
    );
    return (@as(u64, high) << 32) | low;
}

test "PCID CR3 composition preserves an aligned page-table root" {
    try @import("std").testing.expectEqual(
        @as(?usize, 0x0000_0000_1234_5007),
        pcidCr3Value(0x0000_0000_1234_5000, 7, false),
    );
    try @import("std").testing.expectEqual(
        @as(?usize, 0x8000_0000_1234_5007),
        pcidCr3Value(0x0000_0000_1234_5000, 7, true),
    );
    try @import("std").testing.expectEqual(@as(?usize, null), pcidCr3Value(0x1234_5001, 7, true));
    try @import("std").testing.expectEqual(@as(?usize, null), pcidCr3Value(0x1234_5000, 0x1000, true));
}

// RDSEED64, CPUID.7.0:EBX[18], with CF checked independently of the data.
// Intel DRNG Software Implementation Guide rev. 2.2, sections 5.1 and 5.3:
// https://cdrdv2-public.intel.com/864722/drng-software-implementation-guide.pdf
pub fn rdseed64() ?u64 {
    var value: u64 = undefined;
    var ready: u8 = undefined;
    asm volatile (
        \\.byte 0x48, 0x0f, 0xc7, 0xf8
        \\setc %[ready]
        : [value] "={rax}" (value),
          [ready] "=r" (ready),
        :
        : .{ .cc = true });
    return if (ready != 0) value else null;
}
