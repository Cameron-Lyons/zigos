const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const numfmt = @import("../../utils/numfmt.zig");
const common = @import("../common.zig");

const printString = common.printString;
const sliceFromCStr = common.sliceFromCStr;

pub fn find(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: find <directory> <name>\n");
        return;
    }

    const dir_path = sliceFromCStr(args[0]);
    const search_name = sliceFromCStr(args[1]);

    const fd = vfs.open(dir_path, vfs.O_RDONLY) catch |err| {
        vga.print("find: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var index: u64 = 0;
    var dirent: vfs.DirEntry = undefined;
    var found_count: u32 = 0;

    while (true) {
        const has_more = vfs.readdir(fd, &dirent, index) catch |err| {
            if (err != error.EndOfFile) {
                vga.print("readdir error: ");
                vga.print(@errorName(err));
                vga.print("\n");
            }
            break;
        };

        if (!has_more) break;

        const entry_name = dirent.name[0..dirent.name_len];
        if (contains(entry_name, search_name)) {
            var path_buf: [512]u8 = undefined;
            var path_len: usize = 0;

            if (dir_path[dir_path.len - 1] != '/') {
                @memcpy(path_buf[0..dir_path.len], dir_path);
                path_len = dir_path.len;
                path_buf[path_len] = '/';
                path_len += 1;
            } else {
                @memcpy(path_buf[0..dir_path.len], dir_path);
                path_len = dir_path.len;
            }

            @memcpy(path_buf[path_len .. path_len + entry_name.len], entry_name);
            path_len += entry_name.len;

            for (path_buf[0..path_len]) |c| {
                vga.put_char(c);
            }
            vga.put_char('\n');
            found_count += 1;
        }

        index += 1;
    }

    if (found_count == 0) {
        vga.print("No matches found\n");
    }
}

pub fn stat(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: stat <file>\n");
        return;
    }

    const path = sliceFromCStr(args[0]);
    const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
        vga.print("stat: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var stat_info: vfs.FileStat = undefined;
    vfs.fstat(fd, &stat_info) catch |err| {
        vga.print("stat: ");
        printString(args[0]);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };

    vga.print("File: ");
    printString(args[0]);
    vga.print("\n");
    vga.print("Size: ");
    numfmt.printDec(stat_info.size);
    vga.print(" bytes\n");

    vga.print("Type: ");
    switch (stat_info.file_type) {
        .Regular => vga.print("Regular file\n"),
        .Directory => vga.print("Directory\n"),
        .SymLink => vga.print("Symbolic link\n"),
        .BlockDevice => vga.print("Block device\n"),
        .CharDevice => vga.print("Character device\n"),
        .Pipe => vga.print("Pipe\n"),
        .Socket => vga.print("Socket\n"),
    }

    vga.print("Mode: ");
    if (stat_info.mode.owner_read) vga.put_char('r') else vga.put_char('-');
    if (stat_info.mode.owner_write) vga.put_char('w') else vga.put_char('-');
    if (stat_info.mode.owner_exec) vga.put_char('x') else vga.put_char('-');
    if (stat_info.mode.group_read) vga.put_char('r') else vga.put_char('-');
    if (stat_info.mode.group_write) vga.put_char('w') else vga.put_char('-');
    if (stat_info.mode.group_exec) vga.put_char('x') else vga.put_char('-');
    if (stat_info.mode.other_read) vga.put_char('r') else vga.put_char('-');
    if (stat_info.mode.other_write) vga.put_char('w') else vga.put_char('-');
    if (stat_info.mode.other_exec) vga.put_char('x') else vga.put_char('-');
    vga.print("\n");
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (haystack[i + j] != needle[j]) break;
        }
        if (j == needle.len) return true;
    }
    return false;
}
