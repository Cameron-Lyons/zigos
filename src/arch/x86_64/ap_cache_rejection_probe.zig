const std = @import("std");
const options = @import("build_options");
const x86 = @import("../x86.zig");
const cache_policy = @import("../cache_policy.zig");
const cpu_features = @import("../cpu_features.zig");
const bridge = @import("../../kernel/smp/trampoline.zig");
const support = @import("ap_cache_probe_support.zig");

const PAGE_BYTES: usize = 4096;
const Snapshot = cache_policy.BootstrapMtrrSnapshot;
const CASE_LABEL: []const u8 = switch (options.ap_cache_fault) {
    .none => "CONTROL",
    .version => "VERSION",
    .default_reserved => "DEFAULT_RESERVED",
    .mask_reserved => "MASK_RESERVED",
};

extern var smp_trampoline_start: u8;
extern var smp_trampoline_cpu: u64;

var high_entry: u32 = 0;

pub fn panic(_: []const u8, _: ?*std.lang.StackTrace, _: ?usize) noreturn {
    support.fail("panic");
}

pub export fn kernel_main() callconv(.c) noreturn {
    support.initializeBsp();
    // Keep the normal production bridge, physical root and retained stack.
    // Only this isolated image modifies the already copied immutable policy.
    const trampoline = support.prepareBridge(&unexpectedHighEntry);
    const snapshot = snapshotBytes(trampoline);
    injectFault(snapshot);
    publishPage(trampoline);
    support.prepareAp();
    support.serialWrite("ZIGOS:ARCH:X86_64:AP_CACHE:" ++ CASE_LABEL ++ ":ARMED\n");
    support.launchPhysical(trampoline.physical);
    // A rejected AP has no high-entry acknowledgement or ownership release.
    // Retain the SIPI page and stack until the emulator terminates this image.
    if (options.ap_cache_fault == .none) support.retainAndHalt();
    const sentinel: *volatile u32 = &high_entry;
    while (true) {
        if (@atomicLoad(u32, sentinel, .acquire) != 0) support.fail("UNEXPECTED_HIGH_ENTRY");
        asm volatile ("pause");
    }
}

fn snapshotBytes(trampoline: bridge.Trampoline) []u8 {
    const start = @intFromPtr(&smp_trampoline_start);
    const cpu = @intFromPtr(&smp_trampoline_cpu);
    if (cpu < start or trampoline.bytes.len < 8 or
        cpu - start > trampoline.bytes.len - 8) support.fail("snapshot CPU offset");
    const offset = cpu - start + 8;
    if (offset % @alignOf(Snapshot) != 0 or trampoline.bytes.len < @sizeOf(Snapshot) or
        offset > trampoline.bytes.len - @sizeOf(Snapshot)) support.fail("snapshot bounds");
    return trampoline.bytes[offset..][0..@sizeOf(Snapshot)];
}

fn injectFault(snapshot: []u8) void {
    const version = @offsetOf(Snapshot, "version");
    if (std.mem.readInt(u32, snapshot[version..][0..4], .little) !=
        cache_policy.BOOTSTRAP_MTRR_VERSION) support.fail("uncorrupted snapshot version");
    switch (options.ap_cache_fault) {
        .none => {},
        .version => std.mem.writeInt(u32, snapshot[version..][0..4], 0, .little),
        .default_reserved => {
            const offset = @offsetOf(Snapshot, "default_type");
            const original = std.mem.readInt(u32, snapshot[offset..][0..4], .little);
            std.mem.writeInt(u32, snapshot[offset..][0..4], original | (1 << 12), .little);
        },
        .mask_reserved => {
            const capabilities = @offsetOf(Snapshot, "capabilities");
            if (std.mem.readInt(u64, snapshot[capabilities..][0..8], .little) & 0xff == 0)
                support.fail("mask fault requires variable MTRR");
            const offset = @offsetOf(Snapshot, "variable") + @offsetOf(cache_policy.VariableMtrr, "mask");
            const original = std.mem.readInt(u32, snapshot[offset..][0..4], .little);
            // The production preflight rejects this bit even in an inactive
            // variable pair, before any MTRR write or paging activation.
            std.mem.writeInt(u32, snapshot[offset..][0..4], original | 1, .little);
        },
    }
}

fn publishPage(trampoline: bridge.Trampoline) void {
    const line_bytes = cpu_features.clflushLineBytes() orelse support.fail("CLFLUSH geometry");
    const base = @intFromPtr(trampoline.bytes.ptr);
    if (base % PAGE_BYTES != 0 or trampoline.bytes.len > PAGE_BYTES)
        support.fail("SIPI page geometry");
    // Include the uncopied final 128-byte temporary stack, just as normal patch
    // publication does. A disabled-MTRR AP fetches the bridge as UC.
    var offset: usize = 0;
    while (offset < PAGE_BYTES) : (offset += line_bytes) x86.flushCacheLine(base + offset);
    asm volatile ("mfence" ::: .{ .memory = true });
}

fn unexpectedHighEntry(cpu_index: u64) callconv(.c) noreturn {
    const sentinel: *volatile u32 = &high_entry;
    @atomicStore(u32, sentinel, 1, .release);
    if (cpu_index != 1) support.fail("unexpected AP index");
    if (options.ap_cache_fault == .none) {
        support.pass("CONTROL_HIGH_ENTRY");
        support.finish();
    }
    support.fail("UNEXPECTED_HIGH_ENTRY");
}
