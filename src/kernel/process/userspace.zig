const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");
const numfmt = @import("../utils/numfmt.zig");

fn user_hello_world() void {
    asm volatile (
        \\mov $1, %%eax
        \\mov $1, %%ebx
        \\lea %[msg], %%ecx
        \\mov $24, %%edx
        \\int $0x80
        :
        : [msg] "m" ("Hello from userspace!\n"),
        : .{ .eax = true, .ebx = true, .ecx = true, .edx = true, .memory = true });

    asm volatile (
        \\mov $0, %%eax
        \\mov $0, %%ebx
        \\int $0x80
        ::: .{ .eax = true, .ebx = true, .memory = true });
}

pub fn createUserTestProcess() void {
    vga.print("Creating user space test process...\n");

    const user_proc = process.create_user_process("user_hello", user_hello_world);

    vga.print("User process created with PID: ");
    numfmt.printDec(user_proc.pid);
    vga.print("\n");
}
