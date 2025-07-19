const vga = @import("vga.zig");
const boot = @import("../boot/boot.zig");

export fn kernel_main() void {
    vga.init();
    vga.clear();
    vga.print("Welcome to ZigOS!\n");
    vga.print("A minimal operating system written in Zig\n");
    
    while (true) {}
}