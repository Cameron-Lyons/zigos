const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");
const numfmt = @import("../utils/numfmt.zig");

fn ring3TestFunction() void {
    asm volatile (
        \\mov $1, %%eax
        \\mov $1, %%ebx
        \\lea %[msg], %%ecx
        \\mov $28, %%edx
        \\int $0x80
        :
        : [msg] "m" ("Hello from Ring 3 (user mode)!\n"),
        : .{ .eax = true, .ebx = true, .ecx = true, .edx = true, .memory = true });

    asm volatile (
        \\mov $0, %%eax
        \\xor %%ebx, %%ebx
        \\int $0x80
        ::: .{ .eax = true, .ebx = true, .memory = true });
}

pub fn createRing3TestProcess() void {
    vga.print("Creating Ring 3 test process...\n");

    const proc = process.create_user_process("ring3_test", ring3TestFunction);

    vga.print("Ring 3 process created with PID: ");
    numfmt.printDec(proc.pid);
    vga.print("\n");
}
