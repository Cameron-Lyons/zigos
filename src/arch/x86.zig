pub inline fn hlt() void {
    asm volatile ("hlt");
}

pub inline fn cli() void {
    asm volatile ("cli");
}

pub inline fn sti() void {
    asm volatile ("sti");
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

pub inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

pub inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "{dx}" (port),
    );
}

pub inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
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
pub const CR0_WP: usize = 1 << 16;
pub const CR0_PG: usize = 1 << 31;

pub const CR4_PGE: usize = 1 << 7;
pub const CR4_OSFXSR: usize = 1 << 9;
pub const CR4_OSXMMEXCPT: usize = 1 << 10;
pub const CR4_UMIP: usize = 1 << 11;
pub const CR4_PCIDE: usize = 1 << 17;
pub const CR4_SMEP: usize = 1 << 20;

pub const CR3_PCID_MASK: usize = 0x0FFF;
pub const CR3_ADDRESS_MASK: usize = 0x000F_FFFF_FFFF_F000;
pub const CR3_NO_FLUSH: usize = 1 << 63;

const InvpcidDescriptor = extern struct {
    pcid: u64,
    linear_address: u64,
};

extern fn x86_invalidate_pcid(descriptor: *const InvpcidDescriptor) callconv(.c) void;

pub const EFER_MSR: u32 = 0xC000_0080;
pub const EFER_NXE: u64 = 1 << 11;

pub inline fn enableNoExecute() void {
    writeMsr(EFER_MSR, readMsr(EFER_MSR) | EFER_NXE);
}

pub inline fn noExecuteEnabled() bool {
    return (readMsr(EFER_MSR) & EFER_NXE) != 0;
}

pub inline fn readCr0() usize {
    return asm volatile ("mov %%cr0, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn writeCr0(value: usize) void {
    asm volatile ("mov %[value], %%cr0"
        :
        : [value] "r" (value),
        : .{ .memory = true });
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

pub inline fn writeCr3WithPcid(page_table_root: usize, pcid: u16, preserve_translations: bool) void {
    writeCr3(pcidCr3Value(page_table_root, pcid, preserve_translations) orelse unreachable);
}

pub inline fn invalidatePcid(pcid: u16) void {
    const descriptor = InvpcidDescriptor{
        .pcid = pcid,
        .linear_address = 0,
    };
    x86_invalidate_pcid(&descriptor);
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
    );
}

pub inline fn enableProcessContextIdentifiers() void {
    if ((readCr3() & CR3_PCID_MASK) != 0) unreachable;
    writeCr4(readCr4() | CR4_PCIDE);
}

pub inline fn processContextIdentifiersEnabled() bool {
    return (readCr4() & CR4_PCIDE) != 0;
}

pub inline fn globalPagesEnabled() bool {
    return (readCr4() & CR4_PGE) != 0;
}

pub fn enableSse() void {
    var cr0 = readCr0();
    cr0 &= ~CR0_EM;
    cr0 |= CR0_MP;
    writeCr0(cr0);

    writeCr4(readCr4() | CR4_OSFXSR | CR4_OSXMMEXCPT);

    asm volatile ("fninit");
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
