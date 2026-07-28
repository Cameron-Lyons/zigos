//! Compile-only coverage for the privileged x86 helpers on every supported
//! word size. This object is never linked into a boot image or executed.

const x86 = @import("x86.zig");
const cpu_features = @import("cpu_features.zig");

pub export fn zigos_x86_arch_compile_check(port: u16, value: u32) u64 {
    const empty_idt = packed struct {
        limit: u16 = 0,
        base: usize = 0,
    }{};
    x86.cli();
    x86.sti();
    if (value == 0xFFFF_FFFF) x86.hlt();

    x86.outb(port, @truncate(value));
    x86.outw(port, @truncate(value));
    x86.outl(port, value);
    const input = @as(u32, x86.inb(port)) |
        (@as(u32, x86.inw(port)) << 8) |
        x86.inl(port);

    const features = cpu_features.detect();
    if (cpu_features.baseline.isSupported(features)) {
        cpu_features.enableSupervisorProtections(features);
    }
    x86.invalidatePage(x86.readCr2());
    x86.loadIdt(&empty_idt);
    x86.writeCr0(x86.readCr0());
    x86.writeCr3(x86.readCr3());
    x86.enableSse();
    return x86.rdtsc() ^ input ^ x86.stackPointer();
}
