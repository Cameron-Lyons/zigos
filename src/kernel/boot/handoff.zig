const std = @import("std");
const builtin = @import("builtin");
const kernel_address = @import("../../arch/kernel_address.zig");
const framebuffer = @import("../platform/framebuffer.zig");
const boot_info = @import("../../boot/boot_info.zig");

pub const BootInfo = boot_info.BootInfo;
pub const MemoryKind = boot_info.MemoryKind;
pub const MemoryMapEntry = boot_info.MemoryMapEntry;
pub const MemoryMap = []const MemoryMapEntry;

// Written once by zigos_efi_entry from %rdi: the physical BootInfo address.
pub export var zigos_boot_info_addr: u64 = 0;

pub const Error = error{
    InvalidMemoryMap,
    UnsupportedFramebuffer,
    InvalidFramebuffer,
};

const CaptureState = enum(u8) { pending, valid, invalid };
var captured: BootInfo = undefined;
var capture_state: CaptureState = .pending;

// The boot CPU's first call copies the loader record before any frame
// allocation can reuse its pages. Every later reader shares the validated
// kernel copy; nothing re-reads or re-parses loader memory.
pub fn capturedInfo() ?*const BootInfo {
    if (capture_state == .pending) capture_state = if (capture(zigos_boot_info_addr, &captured)) .valid else .invalid;
    return if (capture_state == .valid) &captured else null;
}

extern const __kernel_start: u8;
extern const __kernel_end: u8;

const Span = struct {
    start: u64,
    end: u64,

    fn overlaps(self: Span, other: Span) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn capture(address: u64, out: *BootInfo) bool {
    if (comptime builtin.os.tag != .freestanding) return false;
    const image = kernelImageSpan() orelse return false;
    const alias = bootInfoAlias(address, image) orelse return false;
    @memcpy(std.mem.asBytes(out), @as([*]const u8, @ptrFromInt(alias))[0..@sizeOf(BootInfo)]);
    out.validate() catch return false;
    return recordClearOfKernelWrites(address, out);
}

fn kernelImageSpan() ?Span {
    const start = kernel_address.imagePhysicalAddress(@intFromPtr(&__kernel_start)) orelse return null;
    const last = kernel_address.imagePhysicalAddress(@intFromPtr(&__kernel_end) - 1) orelse return null;
    return .{ .start = start, .end = std.mem.alignForward(u64, last + 1, 4096) };
}

// The stub allocates the record below the image window, which the bootstrap
// direct map covers. It must not overlap the kernel image, whose .bss holds
// the copy and whose early stack and data writes precede it.
fn bootInfoAlias(address: u64, image: Span) ?usize {
    if (address == 0 or address % @alignOf(BootInfo) != 0) return null;
    const end = std.math.add(u64, address, @sizeOf(BootInfo)) catch return null;
    if (end > kernel_address.image_physical_limit or image.overlaps(.{ .start = address, .end = end })) return null;
    return kernel_address.directMappedAddress(address, kernel_address.image_physical_limit);
}

// The heap and both paging arenas named by the validated copy are kernel
// writable from entry; a record inside one of them could already be stale.
fn recordClearOfKernelWrites(address: u64, info: *const BootInfo) bool {
    const record = Span{ .start = address, .end = address + @sizeOf(BootInfo) };
    const paging = info.paging;
    const owned = [_]Span{
        .{ .start = info.image.heap_base, .end = info.image.heap_base + boot_info.image_info.KERNEL_HEAP_BYTES },
        .{ .start = paging.transition_base, .end = paging.transition_base + paging.transitionBytes() },
        .{ .start = paging.final_base, .end = paging.final_base + paging.finalBytes() },
    };
    for (owned) |span| if (record.overlaps(span)) return false;
    return true;
}

pub const MemoryMapSummary = struct {
    entry_count: u32 = 0,
    usable_entry_count: u32 = 0,
    acpi_entry_count: u32 = 0,
    usable_bytes: u64 = 0,
    acpi_reclaim_bytes: u64 = 0,
    highest_usable_end: u64 = 0,

    pub fn hasUsableMemory(self: MemoryMapSummary) bool {
        return self.usable_entry_count > 0 and self.usable_bytes > 0 and self.highest_usable_end > 0;
    }
};

pub fn summarizeMemoryMap(map: MemoryMap) Error!MemoryMapSummary {
    if (map.len == 0) return error.InvalidMemoryMap;
    var summary = MemoryMapSummary{};
    for (map) |entry| {
        summary.entry_count +|= 1;
        switch (entry.kind) {
            .available => {
                summary.usable_entry_count +|= 1;
                summary.usable_bytes +|= entry.length;
                summary.highest_usable_end = @max(summary.highest_usable_end, entry.end());
            },
            .acpi_reclaimable => {
                summary.acpi_entry_count +|= 1;
                summary.acpi_reclaim_bytes +|= entry.length;
            },
            else => {},
        }
    }
    return summary;
}

pub fn framebufferInfo(info: *const BootInfo) Error!framebuffer.Info {
    const fb = info.framebuffer;
    if (fb.base == 0 or fb.pitch % 4 != 0) return error.InvalidFramebuffer;
    if (fb.red_mask == 0 or fb.green_mask == 0 or fb.blue_mask == 0 or
        fb.red_mask & fb.green_mask != 0 or fb.red_mask & fb.blue_mask != 0 or fb.green_mask & fb.blue_mask != 0)
        return error.UnsupportedFramebuffer;

    const result = framebuffer.Info{
        .physical_address = fb.base,
        .width = fb.width,
        .height = fb.height,
        .pixels_per_scan_line = fb.pitch / 4,
        .format = .bitmask,
        .pixel_mask = .{
            .red = fb.red_mask,
            .green = fb.green_mask,
            .blue = fb.blue_mask,
            .reserved = ~(fb.red_mask | fb.green_mask | fb.blue_mask),
        },
        .buffer_bytes = @as(u64, fb.pitch) * @as(u64, fb.height),
    };
    framebuffer.validate(result) catch return error.InvalidFramebuffer;
    return result;
}

pub fn commandLineHasFlag(info: *const BootInfo, flag: []const u8) bool {
    return commandLineHasFlagBytes(info.commandLine(), flag);
}

fn commandLineHasFlagBytes(command_line: []const u8, flag: []const u8) bool {
    if (flag.len == 0) return false;
    var arguments = std.mem.tokenizeAny(u8, command_line, " \t");
    while (arguments.next()) |argument| {
        if (std.mem.eql(u8, argument, flag)) return true;
    }
    return false;
}

pub fn commandLineU64(info: *const BootInfo, key: []const u8) ?u64 {
    return commandLineU64Bytes(info.commandLine(), key);
}

fn commandLineU64Bytes(command_line: []const u8, key: []const u8) ?u64 {
    if (key.len == 0) return null;
    var value: ?u64 = null;
    var arguments = std.mem.tokenizeAny(u8, command_line, " \t");
    while (arguments.next()) |argument| {
        if (argument.len <= key.len + 1 or
            !std.mem.eql(u8, argument[0..key.len], key) or
            argument[key.len] != '=')
        {
            continue;
        }
        if (value != null) return null;
        value = std.fmt.parseInt(u64, argument[key.len + 1 ..], 10) catch return null;
    }
    return value;
}

test "boot handoff summarizes usable and ACPI memory" {
    const map = [_]MemoryMapEntry{
        .{ .base = 0x100000, .length = 0x2000000, .kind = .available },
        .{ .base = 0x3000000, .length = 0x1000, .kind = .acpi_reclaimable },
    };
    const summary = try summarizeMemoryMap(&map);
    try std.testing.expectEqual(@as(u32, 2), summary.entry_count);
    try std.testing.expectEqual(@as(u32, 1), summary.usable_entry_count);
    try std.testing.expectEqual(@as(u64, 0x2000000), summary.usable_bytes);
    try std.testing.expectEqual(@as(u64, 0x2100000), summary.highest_usable_end);
    try std.testing.expectEqual(@as(u64, 0x1000), summary.acpi_reclaim_bytes);
    try std.testing.expectError(error.InvalidMemoryMap, summarizeMemoryMap(&.{}));
}

test "boot handoff record must lie aligned and wholly inside the image window" {
    const image = Span{ .start = 0x200_0000, .end = 0x280_0000 };
    try std.testing.expect(bootInfoAlias(0x1000, image) != null);
    try std.testing.expect(bootInfoAlias(image.start - @sizeOf(BootInfo), image) != null);
    try std.testing.expect(bootInfoAlias(image.end, image) != null);
    try std.testing.expect(bootInfoAlias(kernel_address.image_physical_limit - @sizeOf(BootInfo), image) != null);
    for ([_]u64{
        0,
        0x1001,
        image.start - @sizeOf(BootInfo) + 8,
        image.start,
        image.end - 8,
        kernel_address.image_physical_limit - @sizeOf(BootInfo) + 8,
        kernel_address.image_physical_limit,
        std.math.maxInt(u64) & ~@as(u64, 7),
    }) |address|
        try std.testing.expect(bootInfoAlias(address, image) == null);
    try std.testing.expect(capturedInfo() == null);
}

test "boot handoff record must not overlap the heap or paging arenas it names" {
    const info = boot_info.testInfo();
    const heap = info.image.heap_base;
    const heap_end = heap + boot_info.image_info.KERNEL_HEAP_BYTES;
    const final_end = info.paging.final_base + info.paging.finalBytes();
    try std.testing.expect(recordClearOfKernelWrites(heap - @sizeOf(BootInfo), &info));
    try std.testing.expect(recordClearOfKernelWrites(heap_end, &info));
    try std.testing.expect(recordClearOfKernelWrites(final_end, &info));
    for ([_]u64{
        heap - @sizeOf(BootInfo) + 8,
        heap_end - 8,
        info.paging.transition_base,
        info.paging.transition_base + info.paging.transitionBytes() - 8,
        info.paging.final_base - 8,
        final_end - 8,
    }) |address|
        try std.testing.expect(!recordClearOfKernelWrites(address, &info));
}

test "command line parsing requires exact flags and unique integer keys" {
    try std.testing.expect(commandLineHasFlagBytes("model_inventory qemu_tsc_frequency_hz=2400000000", "model_inventory"));
    try std.testing.expect(commandLineHasFlagBytes(
        "model_inventory qemu_software_cpu_fallback qemu_tsc_frequency_hz=2400000000",
        "qemu_software_cpu_fallback",
    ));
    try std.testing.expect(!commandLineHasFlagBytes("not_model_inventory", "model_inventory"));
    try std.testing.expectEqual(
        @as(?u64, 2_400_000_000),
        commandLineU64Bytes("model_inventory qemu_tsc_frequency_hz=2400000000", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("not_qemu_tsc_frequency_hz=1", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("qemu_tsc_frequency_hz=1 qemu_tsc_frequency_hz=2", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("qemu_tsc_frequency_hz=invalid", "qemu_tsc_frequency_hz"),
    );
}

test "boot handoff validates rgb framebuffer descriptors" {
    var info = boot_info.testInfo();
    info.framebuffer = .{ .base = 0x8000_0000, .pitch = 1920 * 4, .width = 1920, .height = 1080, .red_mask = 0xff0000, .green_mask = 0xff00, .blue_mask = 0xff };
    const fb = try framebufferInfo(&info);
    try std.testing.expectEqual(@as(u64, 0x8000_0000), fb.physical_address);
    try std.testing.expectEqual(@as(u32, 1920), fb.width);
    try std.testing.expectEqual(@as(u32, 1080), fb.height);
    try std.testing.expectEqual(@as(u32, 0xff00_0000), fb.pixel_mask.reserved);
    var bad_stride = info;
    bad_stride.framebuffer.pitch += 1;
    try std.testing.expectError(error.InvalidFramebuffer, framebufferInfo(&bad_stride));
    var overlapping = info;
    overlapping.framebuffer.green_mask = 0xff0000;
    try std.testing.expectError(error.UnsupportedFramebuffer, framebufferInfo(&overlapping));
    var absent = info;
    absent.framebuffer = .{};
    try std.testing.expectError(error.InvalidFramebuffer, framebufferInfo(&absent));
}
