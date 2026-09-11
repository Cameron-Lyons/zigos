pub const page_size: u64 = 0x1000;

pub const image_start: u64 = 0x4000_0000;
pub const image_end_exclusive: u64 = 0x7000_0000;

pub const shared_start: u64 = 0x7000_0000;
pub const shared_end_exclusive: u64 = 0x8000_0000;

pub const accelerator_start: u64 = 0x8000_0000;
pub const accelerator_end_exclusive: u64 = 0xA000_0000;

pub const device_mmio_start: u64 = accelerator_end_exclusive;
pub const device_mmio_end_exclusive: u64 = 0xB000_0000;
pub const DEVICE_MMIO_SLOT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEVICE_MMIO_SLOT_COUNT: usize = @intCast((device_mmio_end_exclusive - device_mmio_start) / DEVICE_MMIO_SLOT_BYTES);

pub const stack_start: u64 = device_mmio_end_exclusive;
pub const user_end_exclusive: u64 = 0xC000_0000;

pub fn deviceMmioSlotBase(slot_index: usize) ?u64 {
    if (slot_index >= DEVICE_MMIO_SLOT_COUNT) return null;
    return device_mmio_start + @as(u64, @intCast(slot_index)) * DEVICE_MMIO_SLOT_BYTES;
}

comptime {
    if (image_start % page_size != 0 or
        image_end_exclusive != shared_start or
        shared_end_exclusive != accelerator_start or
        accelerator_end_exclusive != device_mmio_start or
        device_mmio_end_exclusive != stack_start or
        stack_start >= user_end_exclusive or
        DEVICE_MMIO_SLOT_BYTES % page_size != 0 or
        DEVICE_MMIO_SLOT_COUNT == 0)
    {
        @compileError("userspace virtual-memory regions must be aligned, ordered, and disjoint");
    }
}

test "device MMIO slots cover the brokered controller table" {
    const testing = @import("std").testing;
    try testing.expectEqual(@as(u64, 0xA000_0000), device_mmio_start);
    try testing.expectEqual(@as(u64, 0xB000_0000), device_mmio_end_exclusive);
    try testing.expectEqual(@as(usize, 4), DEVICE_MMIO_SLOT_COUNT);
    try testing.expectEqual(@as(?u64, 0xA000_0000), deviceMmioSlotBase(0));
    try testing.expectEqual(@as(?u64, 0xAC00_0000), deviceMmioSlotBase(3));
    try testing.expectEqual(@as(?u64, null), deviceMmioSlotBase(4));
}
