const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const numfmt = @import("../../utils/numfmt.zig");

pub fn ls(args: []const [*:0]const u8) void {
    const path = if (args.len > 0) args[0] else "/mnt";

    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("ls: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var index: u64 = 0;
    var dirent: vfs.DirEntry = undefined;

    while (true) {
        const has_more = vfs.readdir(fd, &dirent, index) catch |err| {
            vga.print("readdir error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            break;
        };

        if (!has_more) break;

        if (dirent.file_type == vfs.FileType.Directory) {
            vga.print("[DIR] ");
        } else {
            vga.print("      ");
        }

        var i: usize = 0;
        while (i < dirent.name_len and i < 256) : (i += 1) {
            vga.put_char(dirent.name[i]);
        }
        vga.put_char('\n');

        index += 1;
    }
}

pub fn cat(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: cat <file>\n");
        return;
    }

    const path = args[0];

    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("cat: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var buffer: [512]u8 = undefined;
    while (true) {
        const bytes_read = vfs.read(fd, &buffer) catch |err| {
            vga.print("\nread error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            break;
        };

        if (bytes_read == 0) break;

        for (buffer[0..bytes_read]) |byte| {
            if (byte == '\r') continue;
            vga.put_char(byte);
        }
    }
    vga.put_char('\n');
}

pub fn mkdir(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: mkdir <directory>\n");
        return;
    }

    const path = args[0];
    const mode = vfs.FileMode{
        .owner_read = true,
        .owner_write = true,
        .owner_exec = true,
        .group_read = true,
        .group_exec = true,
        .other_read = true,
        .other_exec = true,
    };

    vfs.mkdir(sliceFromCStr(path), mode) catch |err| {
        vga.print("mkdir: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("Directory created: ");
    printString(path);
    vga.print("\n");
}

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

pub fn rm(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: rm <file>\n");
        return;
    }

    const path = args[0];
    vfs.unlink(sliceFromCStr(path)) catch |err| {
        vga.print("rm: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("File removed: ");
    printString(path);
    vga.print("\n");
}

pub fn mv(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: mv <source> <destination>\n");
        return;
    }

    const src = args[0];
    const dst = args[1];
    vfs.rename(sliceFromCStr(src), sliceFromCStr(dst)) catch |err| {
        vga.print("mv: ");
        printString(src);
        vga.print(" -> ");
        printString(dst);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    printString(src);
    vga.print(" -> ");
    printString(dst);
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

pub fn cp(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: cp <source> <destination>\n");
        return;
    }

    const src_path = sliceFromCStr(args[0]);
    const dst_path = sliceFromCStr(args[1]);

    const src_fd = vfs.open(src_path, vfs.O_RDONLY) catch |err| {
        vga.print("cp: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(src_fd) catch {};

    const dst_fd = vfs.open(dst_path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        vga.print("cp: ");
        printString(args[1]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(dst_fd) catch {};

    var buffer: [4096]u8 = undefined;
    var total_copied: usize = 0;
    while (true) {
        const bytes_read = vfs.read(src_fd, &buffer) catch |err| {
            vga.print("cp: read error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        if (bytes_read == 0) break;

        _ = vfs.write(dst_fd, buffer[0..bytes_read]) catch |err| {
            vga.print("cp: write error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        total_copied += bytes_read;
    }

    vga.print("Copied ");
    printString(args[0]);
    vga.print(" to ");
    printString(args[1]);
    vga.print(" (");
    numfmt.printDec(total_copied);
    vga.print(" bytes)\n");
}

pub fn touch(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: touch <file>\n");
        return;
    }

    const path = sliceFromCStr(args[0]);

    const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT) catch |err| {
        vga.print("touch: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vfs.close(fd) catch {};

    vga.print("Created/updated ");
    printString(args[0]);
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

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
}

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}
