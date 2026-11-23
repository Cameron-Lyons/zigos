//! The one EFI stub to kernel handoff. The stub fills a BootInfo in loader
//! pages below the image window and passes its physical address in %rdi. Both
//! sides are linked into one signed image, so the layout carries no tags or
//! version words: the kernel copies it once at entry and validates that copy.
const std = @import("std");
pub const memory_kind = @import("memory_kind.zig");
pub const image_info = @import("image_info.zig");
pub const tpm_info = @import("tpm_info.zig");
pub const paging_info = @import("paging_info.zig");

pub const MemoryKind = memory_kind.Kind;
pub const MAX_MEMORY_MAP_ENTRIES = 256;
pub const MAX_COMMAND_LINE_BYTES = 256;
pub const MAX_RSDP_BYTES = 64;
pub const ACPI_RSDP_V2_MIN_BYTES = 36;

pub const MemoryMapEntry = extern struct {
    base: u64,
    length: u64,
    kind: MemoryKind,
    // The original EFI memory type. Only host fixtures omit it.
    firmware_type: u32 = std.math.maxInt(u32),
    attributes: u64 = 0,

    // BootInfo.validate rejects entries whose end overflows.
    pub inline fn end(self: MemoryMapEntry) u64 {
        return self.base + self.length;
    }

    pub inline fn isUsable(self: MemoryMapEntry) bool {
        return self.kind == .available and self.length != 0;
    }
};

// A renderable GOP mode with 8-bit channels. A zero base means the firmware
// mode is absent or unsupported; paging.framebuffer_* still owns its pages.
pub const Framebuffer = extern struct {
    base: u64 = 0,
    pitch: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    red_mask: u32 = 0,
    green_mask: u32 = 0,
    blue_mask: u32 = 0,
};

pub const Error = error{InvalidBootInfo};

pub const BootInfo = extern struct {
    image: image_info.Info,
    paging: paging_info.Info,
    // All zero when firmware exposes no TPM.
    tpm: tpm_info.Info = std.mem.zeroes(tpm_info.Info),
    framebuffer: Framebuffer = .{},
    efi_system_table: u64 = 0,
    memory_map_count: u32 = 0,
    command_line_len: u32 = 0,
    rsdp_len: u32 = 0,
    command_line: [MAX_COMMAND_LINE_BYTES]u8 = @splat(0),
    rsdp: [MAX_RSDP_BYTES]u8 = @splat(0),
    memory_map: [MAX_MEMORY_MAP_ENTRIES]MemoryMapEntry = undefined,

    pub fn memoryMap(self: *const BootInfo) []const MemoryMapEntry {
        return self.memory_map[0..self.memory_map_count];
    }

    pub fn commandLine(self: *const BootInfo) []const u8 {
        return self.command_line[0..self.command_line_len];
    }

    pub fn acpiRsdp(self: *const BootInfo) ?[]const u8 {
        if (self.rsdp_len == 0) return null;
        return self.rsdp[0..self.rsdp_len];
    }

    pub fn tpmLog(self: *const BootInfo) ?tpm_info.Info {
        if (std.mem.allEqual(u8, std.mem.asBytes(&self.tpm), 0)) return null;
        return self.tpm;
    }

    pub fn setMemoryMap(self: *BootInfo, entries: []const MemoryMapEntry) void {
        @memcpy(self.memory_map[0..entries.len], entries);
        self.memory_map_count = @intCast(entries.len);
    }

    // Every count and extent is checked on the kernel's own copy, so no later
    // reader needs to repeat these bounds.
    pub fn validate(self: *const BootInfo) Error!void {
        // Reject a non-boolean authentication byte before reading the field.
        const authenticated = std.mem.asBytes(self)[@offsetOf(BootInfo, "image") + @offsetOf(image_info.Info, "firmware_authenticated")];
        if (authenticated > 1) return error.InvalidBootInfo;
        self.image.validate() catch return error.InvalidBootInfo;
        self.paging.validate() catch return error.InvalidBootInfo;
        if (self.tpmLog()) |tpm| tpm.validate() catch return error.InvalidBootInfo;
        if (self.command_line_len > MAX_COMMAND_LINE_BYTES or
            (self.rsdp_len != 0 and (self.rsdp_len < ACPI_RSDP_V2_MIN_BYTES or self.rsdp_len > MAX_RSDP_BYTES)) or
            self.memory_map_count == 0 or self.memory_map_count > MAX_MEMORY_MAP_ENTRIES)
            return error.InvalidBootInfo;
        var previous_end: u64 = 0;
        for (self.memoryMap()) |entry| {
            const end = std.math.add(u64, entry.base, entry.length) catch return error.InvalidBootInfo;
            if (entry.length == 0 or entry.base < previous_end) return error.InvalidBootInfo;
            previous_end = end;
        }
        try self.validateFramebuffer();
    }

    // A rendered mode is always inside the complete GOP allocation that the
    // paging receipt keeps owned.
    fn validateFramebuffer(self: *const BootInfo) Error!void {
        const fb = self.framebuffer;
        if (fb.base == 0) return;
        const span = (self.paging.framebufferSpan() catch return error.InvalidBootInfo) orelse return error.InvalidBootInfo;
        const visible = std.math.mul(u64, fb.pitch, fb.height) catch return error.InvalidBootInfo;
        const end = std.math.add(u64, fb.base, visible) catch return error.InvalidBootInfo;
        if (fb.base < span.start or end > span.end) return error.InvalidBootInfo;
    }
};

pub fn sortMemoryMap(entries: []MemoryMapEntry) void {
    if (entries.len < 2) return;
    for (1..entries.len) |index| {
        const value = entries[index];
        var position = index;
        while (position != 0 and entries[position - 1].base > value.base) : (position -= 1) entries[position] = entries[position - 1];
        entries[position] = value;
    }
}

comptime {
    if (@sizeOf(MemoryMapEntry) != 32) @compileError("memory map entries must stay 32 bytes");
}

pub fn testInfo() BootInfo {
    if (!@import("builtin").is_test) @compileError("BootInfo fixtures are test-only");
    var info = BootInfo{
        .image = image_info.Info.measure("kernel", "", false, 0x4000000),
        .paging = .{ .transition_pages = 3, .final_pages = 31, .transition_base = 0x1000000, .final_base = 0x2000000 },
    };
    info.setMemoryMap(&.{.{ .base = 0x100000, .length = 0x7f00000, .kind = .available, .firmware_type = 7 }});
    return info;
}

test "EFI image provenance rejects zero digests and an invalid authentication byte" {
    var info = testInfo();
    try info.validate();
    for ([_]u8{ 2, 0xff }) |value| {
        var forged = info;
        std.mem.asBytes(&forged)[@offsetOf(BootInfo, "image") + @offsetOf(image_info.Info, "firmware_authenticated")] = value;
        try std.testing.expectError(error.InvalidBootInfo, forged.validate());
    }
    var zero_kernel = info;
    zero_kernel.image.kernel_digest = @splat(0);
    try std.testing.expectError(error.InvalidBootInfo, zero_kernel.validate());
    var zero_cmdline = info;
    zero_cmdline.image.cmdline_digest = @splat(0);
    try std.testing.expectError(error.InvalidBootInfo, zero_cmdline.validate());
    var forged_heap = info;
    forged_heap.image.heap_base += 1;
    try std.testing.expectError(error.InvalidBootInfo, forged_heap.validate());
}

test "BootInfo rejects malformed counts, map extents and paging or TPM receipts" {
    const Attack = enum { no_map, map_overflow_count, empty_entry, wrapping_entry, unsorted, overlapping, command_line, short_rsdp, long_rsdp, paging, tpm };
    for (std.enums.values(Attack)) |attack| {
        var info = testInfo();
        info.setMemoryMap(&.{
            .{ .base = 0x100000, .length = 0x1000, .kind = .available, .firmware_type = 7 },
            .{ .base = 0x200000, .length = 0x1000, .kind = .reserved, .firmware_type = 0 },
        });
        try info.validate();
        switch (attack) {
            .no_map => info.memory_map_count = 0,
            .map_overflow_count => info.memory_map_count = MAX_MEMORY_MAP_ENTRIES + 1,
            .empty_entry => info.memory_map[1].length = 0,
            .wrapping_entry => info.memory_map[1].base = std.math.maxInt(u64),
            .unsorted => std.mem.swap(MemoryMapEntry, &info.memory_map[0], &info.memory_map[1]),
            .overlapping => info.memory_map[1].base = 0x100fff,
            .command_line => info.command_line_len = MAX_COMMAND_LINE_BYTES + 1,
            .short_rsdp => info.rsdp_len = ACPI_RSDP_V2_MIN_BYTES - 1,
            .long_rsdp => info.rsdp_len = MAX_RSDP_BYTES + 1,
            .paging => info.paging.final_base = info.paging.transition_base,
            .tpm => info.tpm = .{ .log_address = 0x4000000, .log_bytes = 0, .final_events = 2, .pcr11 = @splat(7) },
        }
        try std.testing.expectError(error.InvalidBootInfo, info.validate());
    }
}

test "BootInfo framebuffer must lie inside the owned GOP allocation" {
    var info = testInfo();
    info.paging.framebuffer_base = 0x8000_0000;
    info.paging.framebuffer_bytes = 1024 * 768 * 4;
    info.framebuffer = .{ .base = 0x8000_0000, .pitch = 1024 * 4, .width = 1024, .height = 768, .red_mask = 0xff0000, .green_mask = 0xff00, .blue_mask = 0xff };
    try info.validate();
    var tall = info;
    tall.framebuffer.height += 1;
    try std.testing.expectError(error.InvalidBootInfo, tall.validate());
    var unowned = info;
    unowned.paging.framebuffer_base = 0;
    unowned.paging.framebuffer_bytes = 0;
    try std.testing.expectError(error.InvalidBootInfo, unowned.validate());
    var below = info;
    below.framebuffer.base -= 4096;
    try std.testing.expectError(error.InvalidBootInfo, below.validate());
}

test "BootInfo exposes absent optional TPM RSDP and command line" {
    var info = testInfo();
    try std.testing.expect(info.tpmLog() == null);
    try std.testing.expect(info.acpiRsdp() == null);
    try std.testing.expectEqual(@as(usize, 0), info.commandLine().len);
    info.tpm = .{ .log_address = 0x4000000, .log_bytes = 4096, .final_events = 2, .pcr11 = @splat(7) };
    try info.validate();
    try std.testing.expectEqualDeep(info.tpm, info.tpmLog().?);
}
