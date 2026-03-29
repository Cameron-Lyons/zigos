const std = @import("std");
const build_options = @import("build_options");
const userspace_descriptor = @import("userspace_descriptor");

pub const Descriptor = userspace_descriptor.Descriptor;

export var zigos_userspace_descriptor: Descriptor align(@alignOf(Descriptor)) linksection(userspace_descriptor.ELF_SECTION_NAME) = initDescriptor();
export var zigos_userspace_yield_counter: u32 = 0;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    while (true) {}
}

export fn _start() callconv(.naked) noreturn {
    asm volatile (
        \\mov $0x23, %ax
        \\mov %ax, %ds
        \\mov %ax, %es
        \\mov %ax, %fs
        \\mov %ax, %gs
        \\1:
        \\mov zigos_userspace_yield_counter, %eax
        \\add $1, %eax
        \\mov %eax, zigos_userspace_yield_counter
        \\int $129
        \\jmp 1b
    );
}

fn initDescriptor() Descriptor {
    return userspace_descriptor.init(.{
        .component_class = build_options.component_class,
        .signed = build_options.signed,
        .bundle_id = build_options.bundle_id,
        .display_name = build_options.display_name,
        .label = build_options.label,
        .entry = build_options.entry,
        .publisher = build_options.publisher,
    });
}
