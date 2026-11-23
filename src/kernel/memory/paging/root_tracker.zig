const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const cpu_identity = @import("../../cpu_identity.zig");
const table64 = @import("../page_table64.zig");
const virtual_layout = @import("../virtual_layout.zig");
const paging = @import("../paging64.zig");

const PAGE_SIZE: u32 = virtual_layout.PAGE_BYTES;
const MANAGED_PHYSICAL_BYTES = paging.MANAGED_PHYSICAL_BYTES;
const PageDirectory = table64.Table;

pub const Error = error{
    InvalidCpu,
    InvalidRoot,
    Uninitialized,
    AlreadyInitialized,
    HardwareMismatch,
};

// Each CPU owns its slot. Every other CR3 writer restores the value it read,
// so the slot is authoritative and switches never read CR3 back.
const Slot = struct {
    directory: usize align(128) = 0,
    switch_cr3: usize = 0,
};

pub const Tracker = struct {
    slots: [cpu_identity.MAX_CPUS]Slot = @splat(.{}),

    fn slot(self: *@This(), index: u8) Error!*Slot {
        if (index >= self.slots.len) return error.InvalidCpu;
        return &self.slots[index];
    }

    pub inline fn get(self: *@This(), index: u8) Error!*PageDirectory {
        const selected = try self.slot(index);
        const directory = @atomicLoad(usize, &selected.directory, .acquire);
        if (directory == 0) return error.Uninitialized;
        return @ptrFromInt(directory);
    }

    pub fn initialize(self: *@This(), index: u8, directory: *PageDirectory, switch_cr3: usize, actual_cr3: usize) Error!void {
        const selected = try self.slot(index);
        if (@atomicLoad(usize, &selected.directory, .acquire) != 0) return error.AlreadyInitialized;
        try validateRoot(directory, switch_cr3);
        if (!readbackMatchesSwitch(actual_cr3, switch_cr3)) return error.HardwareMismatch;
        selected.switch_cr3 = switch_cr3;
        @atomicStore(usize, &selected.directory, @intFromPtr(directory), .release);
    }

    pub fn switchWith(self: *@This(), index: u8, directory: *PageDirectory, switch_cr3: usize, backend: anytype) Error!void {
        const selected = try self.slot(index);
        if (@atomicLoad(usize, &selected.directory, .acquire) == 0) return error.Uninitialized;
        try validateRoot(directory, switch_cr3);
        // A validated value names exactly one root frame, alias and PCID.
        if (selected.switch_cr3 == switch_cr3) return;
        backend.write(switch_cr3);
        selected.switch_cr3 = switch_cr3;
        @atomicStore(usize, &selected.directory, @intFromPtr(directory), .release);
    }

    pub fn activeOnAnyCpu(self: *@This(), directory: *const PageDirectory) bool {
        for (&self.slots) |*selected| {
            if (@atomicLoad(usize, &selected.directory, .acquire) == @intFromPtr(directory)) return true;
        }
        return false;
    }
};

fn validateRoot(directory: *const PageDirectory, switch_cr3: usize) Error!void {
    const physical = virtual_layout.directMappedPhysicalAddress(@intFromPtr(directory), MANAGED_PHYSICAL_BYTES) orelse
        return error.InvalidRoot;
    if (physical == 0 or physical % PAGE_SIZE != 0 or
        (switch_cr3 & ~(x86.CR3_ADDRESS_MASK | x86.CR3_PCID_MASK | x86.CR3_NO_FLUSH)) != 0 or
        (switch_cr3 & x86.CR3_ADDRESS_MASK) != physical) return error.InvalidRoot;
}

inline fn readbackMatchesSwitch(current_cr3: usize, switch_cr3: usize) bool {
    // NO_FLUSH controls MOV to CR3; hardware never retains it in CR3. Keep the
    // root and PCID comparison even when this CPU's cached directory matches.
    return current_cr3 == (switch_cr3 & ~x86.CR3_NO_FLUSH);
}

comptime {
    if (@alignOf(Slot) != 128 or @sizeOf(Slot) != 128) {
        @compileError("per-CPU current roots must occupy independent cache lines");
    }
}

test "CR3 readback ignores the transient switch control and preserves root and PCID identity" {
    const root_address: usize = 0x0000_0000_1234_5000;
    const current_cr3 = x86.pcidCr3Value(root_address, 7, false).?;
    const preserving_switch = x86.pcidCr3Value(root_address, 7, true).?;
    try std.testing.expect(current_cr3 != preserving_switch);
    try std.testing.expect(readbackMatchesSwitch(current_cr3, preserving_switch));
    try std.testing.expect(readbackMatchesSwitch(current_cr3, current_cr3));
    try std.testing.expect(!readbackMatchesSwitch(
        x86.pcidCr3Value(root_address + PAGE_SIZE, 7, false).?,
        preserving_switch,
    ));
    try std.testing.expect(!readbackMatchesSwitch(
        x86.pcidCr3Value(root_address, 8, false).?,
        preserving_switch,
    ));
    try std.testing.expect(readbackMatchesSwitch(root_address, root_address));
}

test "current root admission rejects uninitialized mismatched and repeated CPU bindings" {
    var tracker: Tracker = .{};
    const kernel: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + PAGE_SIZE);
    const expected = x86.pcidCr3Value(PAGE_SIZE, 0, true).?;
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        try std.testing.expectError(error.Uninitialized, tracker.get(index));
        try std.testing.expectError(error.HardwareMismatch, tracker.initialize(index, kernel, expected, PAGE_SIZE | 1));
        try std.testing.expectError(error.Uninitialized, tracker.get(index));
        try tracker.initialize(index, kernel, expected, PAGE_SIZE);
        try std.testing.expectEqual(kernel, try tracker.get(index));
        try std.testing.expectError(error.AlreadyInitialized, tracker.initialize(index, kernel, expected, PAGE_SIZE));
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(&tracker.slots[index]) % 128);
        if (index != 0) try std.testing.expectEqual(@as(usize, 128), @intFromPtr(&tracker.slots[index]) - @intFromPtr(&tracker.slots[index - 1]));
    }
    try std.testing.expectError(error.InvalidCpu, tracker.get(cpu_identity.MAX_CPUS));
    try std.testing.expectError(error.InvalidCpu, tracker.initialize(cpu_identity.MAX_CPUS, kernel, expected, PAGE_SIZE));
    var empty: Tracker = .{};
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, kernel, 2 * PAGE_SIZE, 2 * PAGE_SIZE));
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, @ptrFromInt(PAGE_SIZE), PAGE_SIZE, PAGE_SIZE));
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, kernel, expected | (1 << 62), PAGE_SIZE));
    try std.testing.expectError(error.Uninitialized, empty.get(0));
}

test "current root switching writes only changed roots or PCIDs and rejects invalid roots before hardware" {
    const Model = struct {
        hardware: usize = PAGE_SIZE,
        writes: u32 = 0,

        pub fn write(self: *@This(), value: usize) void {
            self.writes += 1;
            self.hardware = value & ~x86.CR3_NO_FLUSH;
        }
    };
    var tracker: Tracker = .{};
    const kernel: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + PAGE_SIZE);
    const other: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + 2 * PAGE_SIZE);
    var model: Model = .{};
    try std.testing.expectError(error.Uninitialized, tracker.switchWith(0, kernel, PAGE_SIZE, &model));
    try std.testing.expectEqual(@as(u32, 0), model.writes);
    try tracker.initialize(0, kernel, PAGE_SIZE, PAGE_SIZE);
    try tracker.switchWith(0, kernel, PAGE_SIZE, &model);
    try std.testing.expectEqual(@as(u32, 0), model.writes);
    try tracker.switchWith(0, other, 2 * PAGE_SIZE, &model);
    try tracker.switchWith(0, other, 2 * PAGE_SIZE, &model);
    try std.testing.expectEqual(@as(u32, 1), model.writes);
    try std.testing.expectEqual(@as(usize, 2 * PAGE_SIZE), model.hardware);
    try std.testing.expectEqual(other, try tracker.get(0));
    // The same root under another PCID is a distinct hardware context.
    const tagged = x86.pcidCr3Value(2 * PAGE_SIZE, 5, true).?;
    try tracker.switchWith(0, other, tagged, &model);
    try std.testing.expectEqual(@as(u32, 2), model.writes);
    try std.testing.expectError(error.InvalidRoot, tracker.switchWith(0, other, 3 * PAGE_SIZE, &model));
    try std.testing.expectError(error.InvalidRoot, tracker.switchWith(0, kernel, tagged, &model));
    try std.testing.expectEqual(@as(u32, 2), model.writes);
    try std.testing.expectEqual(other, try tracker.get(0));
    try std.testing.expect(!tracker.activeOnAnyCpu(kernel));
}
