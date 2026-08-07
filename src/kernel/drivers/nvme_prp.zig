const std = @import("std");

pub const PAGE_BYTES: usize = 4096;
pub const MAX_DATA_PAGES: usize = 32;
pub const MAX_TRANSFER_BYTES: usize = MAX_DATA_PAGES * PAGE_BYTES;
pub const MAX_LIST_ENTRIES: usize = MAX_DATA_PAGES - 1;

pub const Error = error{
    EmptyTransfer,
    TransferTooLarge,
    UnalignedBuffer,
    UnalignedList,
    MissingList,
    OverlappingList,
    AddressOverflow,
};

pub const Plan = struct {
    buffer_address: u64,
    second_pointer: u64,
    data_page_count: usize,
    list_entry_count: usize,

    pub fn listEntryAddress(self: Plan, index: usize) ?u64 {
        if (index >= self.list_entry_count) return null;
        return std.math.add(
            u64,
            self.buffer_address,
            @as(u64, @intCast((index + 1) * PAGE_BYTES)),
        ) catch null;
    }
};

pub fn plan(buffer_address: u64, list_address: u64, transfer_bytes: usize) Error!Plan {
    if (transfer_bytes == 0) return error.EmptyTransfer;
    if (transfer_bytes > MAX_TRANSFER_BYTES) return error.TransferTooLarge;
    if (buffer_address % PAGE_BYTES != 0) return error.UnalignedBuffer;
    if (list_address % PAGE_BYTES != 0) return error.UnalignedList;
    const data_page_count = (transfer_bytes + PAGE_BYTES - 1) / PAGE_BYTES;
    const last_data_page = std.math.add(
        u64,
        buffer_address,
        @as(u64, @intCast((data_page_count - 1) * PAGE_BYTES)),
    ) catch return error.AddressOverflow;
    if (data_page_count > 2) {
        if (list_address == 0) return error.MissingList;
        if (list_address >= buffer_address and list_address <= last_data_page) {
            return error.OverlappingList;
        }
    }
    return .{
        .buffer_address = buffer_address,
        .second_pointer = switch (data_page_count) {
            1 => 0,
            2 => buffer_address + PAGE_BYTES,
            else => list_address,
        },
        .data_page_count = data_page_count,
        .list_entry_count = if (data_page_count > 2) data_page_count - 1 else 0,
    };
}

test "NVMe PRP plan uses direct pointers for one or two pages" {
    const one = try plan(0x0200_0000, 0x0300_0000, 512);
    try std.testing.expectEqual(@as(u64, 0), one.second_pointer);
    try std.testing.expectEqual(@as(usize, 1), one.data_page_count);
    try std.testing.expectEqual(@as(usize, 0), one.list_entry_count);

    const two = try plan(0x0200_0000, 0x0300_0000, PAGE_BYTES + 512);
    try std.testing.expectEqual(@as(u64, 0x0200_1000), two.second_pointer);
    try std.testing.expectEqual(@as(usize, 2), two.data_page_count);
    try std.testing.expectEqual(@as(usize, 0), two.list_entry_count);
}

test "NVMe PRP list covers a bounded 128 KiB contiguous transfer" {
    const maximum = try plan(0x0200_0000, 0x0300_0000, MAX_TRANSFER_BYTES);
    try std.testing.expectEqual(@as(u64, 0x0300_0000), maximum.second_pointer);
    try std.testing.expectEqual(@as(usize, MAX_DATA_PAGES), maximum.data_page_count);
    try std.testing.expectEqual(@as(usize, MAX_LIST_ENTRIES), maximum.list_entry_count);
    try std.testing.expectEqual(@as(u64, 0x0200_1000), maximum.listEntryAddress(0).?);
    try std.testing.expectEqual(@as(u64, 0x0201_F000), maximum.listEntryAddress(30).?);
    try std.testing.expect(maximum.listEntryAddress(31) == null);
}

test "NVMe PRP plan rejects unsafe transfer geometry" {
    try std.testing.expectError(error.EmptyTransfer, plan(0x0200_0000, 0x0300_0000, 0));
    try std.testing.expectError(
        error.TransferTooLarge,
        plan(0x0200_0000, 0x0300_0000, MAX_TRANSFER_BYTES + 1),
    );
    try std.testing.expectError(error.UnalignedBuffer, plan(0x0200_0001, 0x0300_0000, 512));
    try std.testing.expectError(error.UnalignedList, plan(0x0200_0000, 0x0300_0001, 512));
    try std.testing.expectError(error.MissingList, plan(0x0200_0000, 0, PAGE_BYTES * 3));
    try std.testing.expectError(
        error.OverlappingList,
        plan(0x0200_0000, 0x0200_1000, PAGE_BYTES * 3),
    );
    try std.testing.expectError(
        error.AddressOverflow,
        plan(std.math.maxInt(u64) - PAGE_BYTES + 1, 0x0300_0000, PAGE_BYTES * 2),
    );
}
