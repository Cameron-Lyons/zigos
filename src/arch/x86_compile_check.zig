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
    cpu_features.validateBootstrapCache() catch return 0;
    _ = x86.readMtrrCapabilities();
    _ = x86.readMtrrDefaultType();
    var mtrrs: cpu_features.cache_policy.MtrrState = undefined;
    x86.readMtrrStateInto(&mtrrs) catch return 0;
    mtrrs.requireWriteBack(0x2000000, 4096) catch return 0;
    cpu_features.initializeNativeCachePolicy() catch return 0;
    cpu_features.admitApplicationProcessorCache() catch return 0;
    _ = cpu_features.cache_policy.admittedPhysicalAddressBits() orelse return 0;
    cpu_features.cache_policy.requireAdmittedWriteBack(0x2000000, 4096) catch return 0;
    if (value == 0xFFFF_FFFE) x86.writeBackInvalidateCaches();
    if (value == 0xFFFF_FFFD) x86.flushCacheLine(@intFromPtr(&empty_idt));
    if (cpu_features.baseline.isSupported(features)) {
        cpu_features.enableModernFeatures(features, .hardware_pcid, .hardware, .hardware);
    }
    if (features.rdseed) _ = x86.rdseed64();
    if (features.rdpid) _ = x86.readProcessorId();
    x86.invalidatePage(x86.readCr2());
    x86.loadIdt(&empty_idt);
    x86.writeCr0(x86.readCr0());
    x86.writeCr3(x86.readCr3());
    x86.writeCr3WithPcid(0x1000, 1, true);
    x86.invalidatePcid(1);
    x86.invalidateAllTranslations();
    _ = x86.globalPagesEnabled();
    _ = x86.syscallExtensionEnabled();
    x86.enableSse();
    x86.enableXsaves();
    x86.enableCet();
    x86.enablePku();
    x86.enableLass() catch return 0;
    return x86.rdtsc() ^ input ^ x86.stackPointer();
}
