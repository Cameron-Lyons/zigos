pub const std = @import("std");
const userspace_descriptor = @import("userspace_descriptor");

pub const Descriptor = userspace_descriptor.Descriptor;
pub const ELF_SECTION_NAME = userspace_descriptor.ELF_SECTION_NAME;

pub fn initDescriptor(spec: userspace_descriptor.InitSpec) Descriptor {
    return userspace_descriptor.init(spec);
}

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    while (true) {}
}

pub fn startAsm(comptime increment: u32) []const u8 {
    return std.fmt.comptimePrint(
        \\mov $0x23, %ax
        \\mov %ax, %ds
        \\mov %ax, %es
        \\mov %ax, %fs
        \\mov %ax, %gs
        \\1:
        \\mov zigos_userspace_yield_counter, %eax
        \\add ${d}, %eax
        \\mov %eax, zigos_userspace_yield_counter
        \\int $129
        \\jmp 1b
    , .{increment});
}
