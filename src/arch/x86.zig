const builtin = @import("builtin");

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

pub inline fn stackPointer() usize {
    return switch (builtin.cpu.arch) {
        .x86 => asm volatile ("mov %%esp, %[value]"
            : [value] "=r" (-> usize),
        ),
        .x86_64 => asm volatile ("mov %%rsp, %[value]"
            : [value] "=r" (-> usize),
        ),
        else => @compileError("x86 stack pointer helper requires an x86 target"),
    };
}

pub inline fn readCr2() usize {
    return asm volatile ("mov %%cr2, %[value]"
        : [value] "=r" (-> usize),
    );
}

pub inline fn invalidatePage(address: usize) void {
    switch (builtin.cpu.arch) {
        .x86 => asm volatile ("invlpg (%%eax)"
            :
            : [address] "{eax}" (address),
            : .{ .memory = true }),
        .x86_64 => asm volatile ("invlpg (%%rax)"
            :
            : [address] "{rax}" (address),
            : .{ .memory = true }),
        else => @compileError("page invalidation requires an x86 target"),
    }
}

pub inline fn loadIdt(descriptor: *const anyopaque) void {
    switch (builtin.cpu.arch) {
        .x86 => asm volatile ("lidtl (%%eax)"
            :
            : [descriptor] "{eax}" (descriptor),
            : .{ .memory = true }),
        .x86_64 => asm volatile ("lidtq (%%rax)"
            :
            : [descriptor] "{rax}" (descriptor),
            : .{ .memory = true }),
        else => @compileError("IDT loading requires an x86 target"),
    }
}

pub const CR0_EM: usize = 1 << 2;
pub const CR0_MP: usize = 1 << 1;
pub const CR0_WP: usize = 1 << 16;
pub const CR0_PG: usize = 1 << 31;

pub const CR4_OSFXSR: usize = 1 << 9;
pub const CR4_OSXMMEXCPT: usize = 1 << 10;
pub const CR4_UMIP: usize = 1 << 11;
pub const CR4_SMEP: usize = 1 << 20;

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
    var cr0 = readCr0();
    cr0 &= ~CR0_EM;
    cr0 |= CR0_MP;
    writeCr0(cr0);

    writeCr4(readCr4() | CR4_OSFXSR | CR4_OSXMMEXCPT);

    asm volatile ("fninit");
}
