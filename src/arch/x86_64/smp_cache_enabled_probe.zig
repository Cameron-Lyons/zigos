// Isolated PG0 cache bootstrap evidence, not production AP runtime admission.
const std = @import("std");
const cache = @import("../cache_policy.zig");
const x86 = @import("../x86.zig");
const support = @import("ap_cache_probe_support.zig");

const ControlRecord = extern struct {
    cr0: u32,
    flags: u32,
    pat: u64,
    default_type: u64,
};
const Result = extern struct {
    first: ControlRecord,
    second: ControlRecord,
    observed: cache.BootstrapMtrrSnapshot,
    status: u32,
    reserved: u32,
};

extern var zigos_arch_smp_cache_start: u8;
extern var zigos_arch_smp_cache_end: u8;
extern var zigos_arch_smp_cache_snapshot: u8;
extern var zigos_arch_smp_cache_result: u8;

pub fn panic(_: []const u8, _: ?*std.lang.StackTrace, _: ?usize) noreturn {
    support.fail("panic");
}

pub fn main() noreturn {
    support.initializeBsp();
    var expected: cache.BootstrapMtrrSnapshot = undefined;
    cache.copyBootstrapMtrrSnapshot(&expected) catch support.fail("BSP snapshot");
    const start = @intFromPtr(&zigos_arch_smp_cache_start);
    const end = @intFromPtr(&zigos_arch_smp_cache_end);
    if (end <= start or end - start != 3968) support.fail("PG0 blob bounds");
    const snapshot_offset = checkedOffset(start, end, @intFromPtr(&zigos_arch_smp_cache_snapshot), @sizeOf(cache.BootstrapMtrrSnapshot), @alignOf(cache.BootstrapMtrrSnapshot));
    const result_offset = checkedOffset(start, end, @intFromPtr(&zigos_arch_smp_cache_result), @sizeOf(Result), @alignOf(Result));
    if (snapshot_offset + @sizeOf(cache.BootstrapMtrrSnapshot) > result_offset) support.fail("PG0 payload overlap");
    const page = support.claimPage();
    @memset(page.bytes, 0);
    @memcpy(page.bytes[0 .. end - start], @as([*]const u8, @ptrFromInt(start))[0 .. end - start]);
    const snapshot: *cache.BootstrapMtrrSnapshot = @ptrCast(@alignCast(page.bytes[snapshot_offset..].ptr));
    snapshot.* = expected;
    const result: *Result = @ptrCast(@alignCast(page.bytes[result_offset..].ptr));
    const observed: *volatile Result = result;
    support.publish(page);
    support.startAp(page, &result.status);
    support.waitForPhase(&result.status, 1);
    const first = observed.first;
    if (!enabledControls(first, expected.default_type)) support.fail("first enabled controls");
    support.pass("FIRST_ENABLED");
    support.waitForPhase(&result.status, 2);
    const second = observed.second;
    const actual = observed.observed;
    if (!enabledControls(second, expected.default_type) or second.cr0 != first.cr0 or
        second.pat != first.pat or !snapshotMatches(&expected, &actual) or observed.reserved != 0)
        support.fail("enabled match register readback");
    if (x86.interruptsEnabled()) support.fail("BSP interrupt ownership");
    support.pass("SMP_CACHE_ENABLED_MATCH");
    support.finish();
}

fn checkedOffset(start: usize, end: usize, address: usize, bytes: usize, alignment: usize) usize {
    if (address < start or address > end or bytes > end - address or (address - start) % alignment != 0)
        support.fail("PG0 slot bounds");
    return address - start;
}

fn enabledControls(record: ControlRecord, expected_default: u64) bool {
    return @as(usize, record.cr0) & (cache.CACHE_CONTROL_MASK | x86.CR0_PG) == 0 and
        record.flags & (1 << 9) == 0 and record.pat == cache.BOOTSTRAP_PAT and
        record.default_type == expected_default and record.default_type & cache.MTRR_ENABLED != 0;
}

fn snapshotMatches(expected: *const cache.BootstrapMtrrSnapshot, actual: *const cache.BootstrapMtrrSnapshot) bool {
    return std.mem.eql(u8, std.mem.asBytes(expected), std.mem.asBytes(actual));
}

fn assemblyConstant(source: []const u8, name: []const u8) !usize {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "#define ")) continue;
        var words = std.mem.tokenizeScalar(u8, line[8..], ' ');
        const candidate = words.next() orelse continue;
        if (std.mem.eql(u8, candidate, name)) return std.fmt.parseInt(usize, words.next() orelse return error.MissingValue, 0);
    }
    return error.MissingConstant;
}

test "enabled cache proof assembly layout matches captured controls and complete snapshot" {
    const source = @embedFile("smp_cache_enabled_probe.S");
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ControlRecord));
    try std.testing.expectEqual(@as(usize, 680), @sizeOf(Result));
    inline for (.{
        .{ "PROOF_FIRST_OFFSET", @offsetOf(Result, "first") },
        .{ "PROOF_SECOND_OFFSET", @offsetOf(Result, "second") },
        .{ "PROOF_OBSERVED_OFFSET", @offsetOf(Result, "observed") },
        .{ "PROOF_STATUS_OFFSET", @offsetOf(Result, "status") },
        .{ "PROOF_RESULT_BYTES", @sizeOf(Result) },
        .{ "PROOF_CR0_OFFSET", @offsetOf(ControlRecord, "cr0") },
        .{ "PROOF_FLAGS_OFFSET", @offsetOf(ControlRecord, "flags") },
        .{ "PROOF_PAT_OFFSET", @offsetOf(ControlRecord, "pat") },
        .{ "PROOF_DEFAULT_OFFSET", @offsetOf(ControlRecord, "default_type") },
    }) |pair| try std.testing.expectEqual(pair[1], try assemblyConstant(source, pair[0]));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "    ZIGOS_INITIALIZE_AP_MTRRS "));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, source, "    call zigos_arch_smp_cache_initialize\n"));
    const first = std.mem.indexOf(u8, source, "zigos_arch_smp_cache_first_call:\n").?;
    const second = std.mem.indexOf(u8, source, "zigos_arch_smp_cache_second_call:\n").?;
    try std.testing.expect(std.mem.indexOf(u8, source[first..second], "    wrmsr") == null);
    try std.testing.expect(std.mem.indexOf(u8, source[first..second], "    call .Lproof_require_enabled\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, ".org zigos_arch_smp_cache_start + 3968, 0") != null);
}

test "enabled cache proof rejects every disabled paging interrupt PAT and policy control" {
    const good = ControlRecord{ .cr0 = 0x11, .flags = 2, .pat = cache.BOOTSTRAP_PAT, .default_type = cache.MTRR_ENABLED | 6 };
    try std.testing.expect(enabledControls(good, good.default_type));
    for ([_]u32{ @intCast(x86.CR0_PG), @intCast(cache.CR0_CD), @intCast(cache.CR0_NW) }) |bit| {
        var bad = good;
        bad.cr0 |= bit;
        try std.testing.expect(!enabledControls(bad, good.default_type));
    }
    var bad = good;
    bad.flags |= 1 << 9;
    try std.testing.expect(!enabledControls(bad, good.default_type));
    bad = good;
    bad.pat ^= 1 << 56;
    try std.testing.expect(!enabledControls(bad, good.default_type));
    bad = good;
    bad.default_type &= ~cache.MTRR_ENABLED;
    try std.testing.expect(!enabledControls(bad, bad.default_type));
    bad = good;
    bad.default_type ^= 1;
    try std.testing.expect(!enabledControls(bad, good.default_type));
}

test "enabled cache proof independently compares every implemented and disabled register" {
    const expected = cache.BootstrapMtrrSnapshot{
        .version = cache.BOOTSTRAP_MTRR_VERSION,
        .physical_bits = 36,
        .capabilities = cache.MTRR_FIXED_SUPPORTED | 2,
        .default_type = cache.MTRR_ENABLED | 6,
        .fixed = @splat(0x0606_0606_0606_0606),
        .variable = @splat(.{}),
    };
    var actual = expected;
    try std.testing.expect(snapshotMatches(&expected, &actual));
    for (0..@sizeOf(cache.BootstrapMtrrSnapshot)) |byte| {
        actual = expected;
        std.mem.asBytes(&actual)[byte] ^= 1;
        try std.testing.expect(!snapshotMatches(&expected, &actual));
    }
}
