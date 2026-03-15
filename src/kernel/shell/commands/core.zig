const vga = @import("../../drivers/vga.zig");
const registry = @import("../registry.zig");

pub fn help() void {
    vga.print("Available commands:\n");
    for (registry.all()) |command| {
        vga.print("  ");
        vga.print(command.name);
        if (command.name.len < 12) {
            for (0..12 - command.name.len) |_| {
                vga.put_char(' ');
            }
        } else {
            vga.put_char(' ');
        }
        vga.print("- ");
        vga.print(command.summary);
        vga.put_char('\n');
    }
}

pub fn clear() void {
    vga.clear();
}
