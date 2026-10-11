const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const cpu_identity = @import("../cpu_identity.zig");
const paging = @import("../memory/paging64.zig");
const memory = @import("../memory/memory.zig");
const cache_policy = @import("../../arch/cache_policy.zig");
const baseline = @import("../../arch/cpu_baseline.zig");
const cpu_features = @import("../../arch/cpu_features.zig");

extern var smp_trampoline_start: u8;
extern var smp_trampoline_end: u8;
extern var smp_trampoline_cr3: u64;
extern var smp_trampoline_entry: u64;
extern var smp_trampoline_stack: u64;
extern var smp_trampoline_cpu: u64;

pub const PHYSICAL_LIMIT: u32 = 1024 * 1024;
pub const STACK_USABLE_BYTES: usize = 16 * 1024;
const PAGE_BYTES: usize = 4096;

pub const Stack = struct {
    guard: usize,
    top: usize,
};

pub fn allocateStack() ?Stack {
    const bytes = STACK_USABLE_BYTES + 2 * PAGE_BYTES - 1;
    const storage = memory.kmalloc(bytes) orelse return null;
    const guard = std.mem.alignForward(usize, @intFromPtr(storage), PAGE_BYTES);
    const top = std.math.add(usize, guard, PAGE_BYTES + STACK_USABLE_BYTES) catch return null;
    const end = std.math.add(usize, @intFromPtr(storage), bytes) catch return null;
    if (top > end or top % x86.FRED_STACK_ALIGNMENT != 0 or !paging.unmapBorrowedCurrentPage(guard)) return null;
    // The backing remains allocated, including on AP startup timeout. Reset
    // alone does not supply a hotplug stack retirement/ownership protocol.
    return .{ .guard = guard, .top = top };
}

pub const Trampoline = struct {
    physical: u32,
    bytes: []u8,
};

pub fn install() ?Trampoline {
    const physical = paging.claimSipiTrampolinePage() orelse return null;
    if (physical == 0 or physical >= PHYSICAL_LIMIT or physical % 4096 != 0) return null;
    const start = @intFromPtr(&smp_trampoline_start);
    const end = @intFromPtr(&smp_trampoline_end);
    if (end <= start or end - start > 4096) return null;
    // SIPI vectors remain physical. LASS-admitted callers copy and patch the
    // actual production bridge only through its high supervisor alias.
    const alias = paging.directMapAddress(physical) orelse return null;
    const destination: [*]u8 = @ptrFromInt(alias);
    const bytes = destination[0 .. end - start];
    @memcpy(bytes, @as([*]const u8, @ptrFromInt(start))[0 .. end - start]);
    return .{ .physical = physical, .bytes = bytes };
}

pub fn patch(bridge: Trampoline, cpu_index: u8, stack_top: usize, entry: *const fn (u64) callconv(.c) noreturn) bool {
    // Validate coherent publication before changing any launch payload. INIT
    // retains another AP's private dirty lines, which BSP WBINVD cannot retire.
    const line_bytes = cpu_features.clflushLineBytes() orelse return false;
    if (@intFromPtr(bridge.bytes.ptr) % PAGE_BYTES != 0 or bridge.bytes.len > PAGE_BYTES) return false;
    const physical_cr3 = x86.readCr3() & x86.CR3_ADDRESS_MASK;
    if (physical_cr3 == 0 or physical_cr3 % 4096 != 0 or physical_cr3 > std.math.maxInt(u32) or
        cpu_index >= cpu_identity.MAX_CPUS or !baseline.isCanonicalUpperHalf(stack_top) or
        stack_top % x86.FRED_STACK_ALIGNMENT != 0 or !baseline.isCanonicalUpperHalf(@intFromPtr(entry))) return false;
    const symbols = [_]*u64{
        &smp_trampoline_cr3, &smp_trampoline_entry, &smp_trampoline_stack, &smp_trampoline_cpu,
    };
    var offsets: [symbols.len]usize = undefined;
    const start = @intFromPtr(&smp_trampoline_start);
    for (symbols, 0..) |symbol, index| {
        const address = @intFromPtr(symbol);
        if (address < start or bridge.bytes.len < 8 or address - start > bridge.bytes.len - 8) return false;
        offsets[index] = address - start;
    }
    const cache_offset = offsets[3] + 8;
    if (cache_offset % @alignOf(cache_policy.BootstrapMtrrSnapshot) != 0 or
        bridge.bytes.len < @sizeOf(cache_policy.BootstrapMtrrSnapshot) or
        cache_offset > bridge.bytes.len - @sizeOf(cache_policy.BootstrapMtrrSnapshot)) return false;
    const snapshot: *cache_policy.BootstrapMtrrSnapshot = @ptrCast(@alignCast(bridge.bytes[cache_offset..].ptr));
    // This API can only copy the immutable admitted BSP policy. Failure occurs
    // before any entry/stack/CPU slot changes, so no partial launch is possible.
    cache_policy.copyBootstrapMtrrSnapshot(snapshot) catch return false;
    // The assembly owns minimal transition controls; runtime CPU controls are
    // neither copied from the BSP nor activated before this AP's admission.
    const values = [_]u64{
        physical_cr3, @intFromPtr(entry), stack_top, cpu_index,
    };
    for (offsets, values) |offset, value| std.mem.writeInt(u64, bridge.bytes[offset..][0..8], value, .little);
    // A disabled-MTRR AP fetches this page as UC. CLFLUSH retires dirty WB
    // lines across the coherence domain, including a timed-out AP's retained
    // private cache and the uncopied 128-byte temporary stack. An IPI ordering
    // fence alone cannot write those lines back to memory.
    // This is boot-only: callers keep the page untouched until high-entry
    // acknowledgement or completed INIT quiescence before the next patch.
    if (@import("builtin").target.os.tag == .freestanding) {
        var offset: usize = 0;
        while (offset < PAGE_BYTES) : (offset += line_bytes) x86.flushCacheLine(@intFromPtr(bridge.bytes.ptr) + offset);
        asm volatile ("mfence" ::: .{ .memory = true });
    }
    return true;
}
