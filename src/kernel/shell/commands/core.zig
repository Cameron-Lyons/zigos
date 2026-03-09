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

pub fn echo(args: []const [*:0]const u8) void {
    for (args, 0..) |arg, i| {
        if (i > 0) vga.put_char(' ');
        printString(arg);
    }
    vga.put_char('\n');
}

pub fn trueCmd() void {}

pub fn falseCmd() void {}

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
}
