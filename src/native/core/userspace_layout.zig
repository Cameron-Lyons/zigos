pub const page_size: u64 = 0x1000;
pub const huge_page_size: u64 = 0x20_0000;
pub const user_canonical_end_exclusive: u64 = 0x0000_8000_0000_0000;
pub const USES_2M_IMAGE_PAGES = true;
pub const IMAGE_SLOT_BYTES: u64 = 0x200_0000;
pub const default_stack_top: u64 = 0x0000_007F_FFFF_F000;
pub const default_stack_size: u64 = 64 * 1024;
pub const STACK_SLOT_STRIDE: u64 = default_stack_size + page_size;

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

pub const stack_start: u64 = 0x0000_007F_0000_0000;
pub const user_end_exclusive: u64 = user_canonical_end_exclusive;

pub fn deviceMmioSlotBase(slot_index: usize) ?u64 {
    if (slot_index >= DEVICE_MMIO_SLOT_COUNT) return null;
    return device_mmio_start + @as(u64, @intCast(slot_index)) * DEVICE_MMIO_SLOT_BYTES;
}

pub fn imageBaseForSlot(slot_index: usize) u64 {
    return image_start + @as(u64, @intCast(slot_index)) * IMAGE_SLOT_BYTES;
}

pub fn stackTopForSlot(slot_index: usize) u64 {
    return default_stack_top - @as(u64, @intCast(slot_index)) * STACK_SLOT_STRIDE;
}

comptime {
    if (image_start % page_size != 0 or
        image_start % huge_page_size != 0 or
        image_end_exclusive != shared_start or
        shared_end_exclusive != accelerator_start or
        accelerator_end_exclusive != device_mmio_start or
        device_mmio_end_exclusive <= device_mmio_start or
        stack_start < device_mmio_end_exclusive or
        stack_start >= user_end_exclusive or
        user_end_exclusive != user_canonical_end_exclusive or
        DEVICE_MMIO_SLOT_BYTES % page_size != 0 or
        DEVICE_MMIO_SLOT_COUNT == 0 or
        IMAGE_SLOT_BYTES % huge_page_size != 0 or
        IMAGE_SLOT_BYTES == 0 or
        default_stack_top % page_size != 0 or
        default_stack_size % page_size != 0 or
        STACK_SLOT_STRIDE % page_size != 0 or
        imageBaseForSlot(8) > image_end_exclusive or
        stackTopForSlot(8) - default_stack_size < stack_start)
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

test "user stacks occupy the top of canonical low memory" {
    const testing = @import("std").testing;
    try testing.expectEqual(@as(u64, 0x0000_007F_0000_0000), stack_start);
    try testing.expectEqual(@as(u64, 0x0000_8000_0000_0000), user_end_exclusive);
    try testing.expectEqual(default_stack_top, stackTopForSlot(0));
    try testing.expectEqual(image_start, imageBaseForSlot(0));
    try testing.expect(imageBaseForSlot(1) < image_end_exclusive);
}


