const vga = @import("vga.zig");
const boot = @import("../boot/boot.zig");
const isr = @import("isr.zig");
const keyboard = @import("keyboard.zig");
const paging = @import("paging.zig");
const timer = @import("timer.zig");
const process = @import("process.zig");
const shell = @import("shell.zig");

fn test_process1() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            vga.print("A");
        }
        process.yield();
    }
}

fn test_process2() void {
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % 1000000 == 0) {
            vga.print("B");
        }
        process.yield();
    }
}

export fn kernel_main() void {
    vga.init();
    vga.clear();
    vga.print("Welcome to ZigOS!\n");
    vga.print("A minimal operating system written in Zig\n");
    
    vga.print("Initializing interrupts...\n");
    isr.init();
    vga.print("Interrupts enabled!\n");
    
    vga.print("Initializing paging...\n");
    paging.init();
    
    vga.print("Initializing process management...\n");
    process.init();
    
    vga.print("Initializing timer...\n");
    timer.init(100);
    
    vga.print("Initializing keyboard...\n");
    keyboard.init();
    vga.print("Keyboard ready!\n");
    
    vga.print("Creating test processes...\n");
    _ = process.create_process("test1", test_process1);
    _ = process.create_process("test2", test_process2);
    
    vga.print("Initializing shell...\n");
    var system_shell = shell.Shell.init();
    keyboard.setShell(&system_shell);
    
    asm volatile ("sti");
    
    vga.print("\nZigOS Shell Ready!\n");
    system_shell.printPrompt();
    
    while (system_shell.running) {
        asm volatile ("hlt");
    }
}