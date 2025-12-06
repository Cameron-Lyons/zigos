const std = @import("std");
const vga = @import("vga.zig");
const process = @import("process.zig");
const vfs = @import("vfs.zig");
const memory = @import("memory.zig");
const syscall = @import("syscall.zig");

pub fn ls_main(args: [][]const u8) void {
    _ = args;
    const dir_fd = vfs.open("/", vfs.O_RDONLY) catch {
        vga.print("ls: cannot open directory\n");
        return;
    };
    defer vfs.close(dir_fd) catch {};

    var entry: vfs.DirEntry = undefined;
    var index: u64 = 0;

    while (vfs.readdir(dir_fd, &entry, index) catch false) {
        vga.print(entry.name[0..entry.name_len]);
        if (entry.file_type == vfs.FileType.Directory) {
            vga.print("/");
        }
        vga.print("  ");
        index += 1;
    }
    vga.print("\n");
}

pub fn cat_main(args: [][]const u8) void {
    if (args.len < 2) {
        vga.print("cat: missing file argument\n");
        return;
    }

    const path = args[1];
    const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
        vga.print("cat: cannot open file: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var buffer: [4096]u8 = undefined;
    while (true) {
        const bytes_read = vfs.read(fd, &buffer) catch break;
        if (bytes_read == 0) break;
        for (buffer[0..bytes_read]) |byte| {
            vga.printChar(byte);
        }
    }
    vga.print("\n");
}

pub fn echo_main(args: [][]const u8) void {
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (i > 1) vga.print(" ");
        vga.print(args[i]);
    }
    vga.print("\n");
}

pub fn pwd_main(args: [][]const u8) void {
    _ = args;
    vga.print("/\n");
}

pub fn whoami_main(args: [][]const u8) void {
    _ = args;
    vga.print("root\n");
}

pub fn date_main(args: [][]const u8) void {
    _ = args;
    vga.print("Date: Not implemented yet\n");
}

pub fn uname_main(args: [][]const u8) void {
    _ = args;
    vga.print("ZigOS\n");
}

pub fn test_main(args: [][]const u8) void {
    _ = args;
    vga.print("Test program executed successfully!\n");
}

fn ls_wrapper() void {
    ls_main(&[_][]const u8{"ls"});
}

fn cat_wrapper() void {
    cat_main(&[_][]const u8{"cat", "test.txt"});
}

fn echo_wrapper() void {
    echo_main(&[_][]const u8{"echo", "Hello from user program!"});
}

pub fn createUserProgram(name: []const u8, entry: *const fn () void) void {
    const user_proc = process.create_user_process(name, entry);
    _ = user_proc;
}

pub fn init() void {
    vga.print("User programs module initialized\n");
}

