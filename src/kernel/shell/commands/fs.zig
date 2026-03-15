const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const numfmt = @import("../../utils/numfmt.zig");
const common = @import("../common.zig");

const printString = common.printString;
const sliceFromCStr = common.sliceFromCStr;

pub fn rmdir(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: rmdir <directory>\n");
        return;
    }

    const path = args[0];
    vfs.rmdir(sliceFromCStr(path)) catch |err| {
        vga.print("rmdir: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("Directory removed: ");
    printString(path);
    vga.print("\n");
}

pub fn mount(args: []const [*:0]const u8) void {
    if (args.len < 3) {
        vga.print("Usage: mount <device> <path> <fstype>\n");
        vga.print("Example: mount ata0 /mnt fat32\n");
        return;
    }

    const device_str = sliceFromCStr(args[0]);
    const path = sliceFromCStr(args[1]);
    const fstype = sliceFromCStr(args[2]);

    vfs.mount(device_str, path, fstype, 0) catch |err| {
        vga.print("mount: failed to mount ");
        printString(args[0]);
        vga.print(" on ");
        printString(args[1]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("Mounted ");
    printString(args[0]);
    vga.print(" on ");
    printString(args[1]);
    vga.print(" as ");
    printString(args[2]);
    vga.print("\n");
}

pub fn write(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: write <file> <text>\n");
        vga.print("Example: write test.txt \"Hello World\"\n");
        return;
    }

    const path = sliceFromCStr(args[0]);

    const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("write: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var total_written: usize = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const text = sliceFromCStr(args[i]);
        const bytes_written = vfs.write(fd, text) catch |err| {
            vga.print("write: write error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        total_written += bytes_written;

        if (i < args.len - 1) {
            _ = vfs.write(fd, " ") catch {};
            total_written += 1;
        }
    }

    vga.print("Wrote ");
    numfmt.printDec(total_written);
    vga.print(" bytes to ");
    printString(args[0]);
    vga.print("\n");
}
