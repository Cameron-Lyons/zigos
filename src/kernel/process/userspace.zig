const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");

fn user_hello_world() void {
    asm volatile (
        \\mov $1, %%eax
        \\mov $1, %%ebx
        \\lea %[msg], %%ecx
        \\mov $24, %%edx
        \\int $0x80
        :
        : [msg] "m" ("Hello from userspace!\n"),
        : "eax", "ebx", "ecx", "edx", "memory"
    );

    asm volatile (
        \\mov $0, %%eax
        \\mov $0, %%ebx
        \\int $0x80
        ::: "eax", "ebx", "memory");
}

pub fn createUserTestProcess() void {
    vga.print("Creating user space test process...\n");

    const user_proc = process.create_user_process("user_hello", user_hello_world);

    vga.print("User process created with PID: ");
    printNumber(user_proc.pid);
    vga.print("\n");
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast((n % 10) + '0'));
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}
