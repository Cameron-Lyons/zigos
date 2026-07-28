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

pub const CR0_EM: usize = 1 << 2;
pub const CR0_MP: usize = 1 << 1;

pub const CR4_OSFXSR: usize = 1 << 9;
pub const CR4_OSXMMEXCPT: usize = 1 << 10;
pub const CR4_UMIP: usize = 1 << 11;
pub const CR4_SMEP: usize = 1 << 20;

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

pub fn enableSse() void {
    var cr0: usize = asm volatile ("mov %%cr0, %[value]"
        : [value] "=r" (-> usize),
    );
    cr0 &= ~CR0_EM;
    cr0 |= CR0_MP;
    asm volatile ("mov %[value], %%cr0"
        :
        : [value] "r" (cr0),
    );

    writeCr4(readCr4() | CR4_OSFXSR | CR4_OSXMMEXCPT);

    asm volatile ("fninit");
}
