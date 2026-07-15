/// Deliberate 32-bit userspace layout. Keep executable images, shared memory,
/// accelerator apertures, and stacks in disjoint regions so each mapper can
/// reject cross-domain aliases before touching page tables.
pub const page_size: u64 = 0x1000;

pub const image_start: u64 = 0x4000_0000;
pub const image_end_exclusive: u64 = 0x7000_0000;

pub const shared_start: u64 = 0x7000_0000;
pub const shared_end_exclusive: u64 = 0x8000_0000;

pub const accelerator_start: u64 = 0x8000_0000;
pub const accelerator_end_exclusive: u64 = 0xA000_0000;

pub const stack_start: u64 = 0xB000_0000;
pub const user_end_exclusive: u64 = 0xC000_0000;

comptime {
    if (image_start % page_size != 0 or
        image_end_exclusive != shared_start or
        shared_end_exclusive != accelerator_start or
        accelerator_end_exclusive > stack_start or
        stack_start >= user_end_exclusive)
    {
        @compileError("userspace virtual-memory regions must be aligned, ordered, and disjoint");
    }
}
