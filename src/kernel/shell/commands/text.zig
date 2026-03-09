const file_ops = @import("../../fs/file_ops.zig");
const registry = @import("../registry.zig");
const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");

pub fn head(args: []const [*:0]const u8) void {
    var lines: u32 = 10;
    var file_arg_idx: usize = 0;

    if (args.len > 0 and sliceFromCStr(args[0]).len > 2 and args[0][0] == '-' and args[0][1] == 'n') {
        const num_str = sliceFromCStr(args[0]);
        if (num_str.len > 2) {
            var num: u32 = 0;
            var i: usize = 2;
            while (i < num_str.len) : (i += 1) {
                if (num_str[i] >= '0' and num_str[i] <= '9') {
                    num = num * 10 + (num_str[i] - '0');
                } else {
                    break;
                }
            }
            if (num > 0) {
                lines = num;
            }
        }
        file_arg_idx = 1;
    }

    if (args.len <= file_arg_idx) {
        vga.print("Usage: head [-n <lines>] <file>\n");
        return;
    }

    const path = args[file_arg_idx];
    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("head: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var buffer: [512]u8 = undefined;
    var line_count: u32 = 0;
    var in_line = false;

    while (line_count < lines) {
        const bytes_read = vfs.read(fd, &buffer) catch |err| {
            vga.print("\nread error: ");
            vga.print(@errorName(err));
            vga.print("\n");
            break;
        };

        if (bytes_read == 0) break;

        for (buffer[0..bytes_read]) |byte| {
            if (byte == '\r') continue;

            if (byte == '\n') {
                vga.put_char('\n');
                line_count += 1;
                in_line = false;
                if (line_count >= lines) break;
            } else {
                vga.put_char(byte);
                in_line = true;
            }
        }
    }

    if (in_line) {
        vga.put_char('\n');
    }
}

pub fn tail(args: []const [*:0]const u8) void {
    var lines: u32 = 10;
    var file_arg_idx: usize = 0;

    if (args.len > 0 and sliceFromCStr(args[0]).len > 2 and args[0][0] == '-' and args[0][1] == 'n') {
        const num_str = sliceFromCStr(args[0]);
        if (num_str.len > 2) {
            var num: u32 = 0;
            var i: usize = 2;
            while (i < num_str.len) : (i += 1) {
                if (num_str[i] >= '0' and num_str[i] <= '9') {
                    num = num * 10 + (num_str[i] - '0');
                } else {
                    break;
                }
            }
            if (num > 0) {
                lines = num;
            }
        }
        file_arg_idx = 1;
    }

    if (args.len <= file_arg_idx) {
        vga.print("Usage: tail [-n <lines>] <file>\n");
        return;
    }

    const path = args[file_arg_idx];
    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("tail: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var file_buffer: [8192]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < file_buffer.len) {
        const bytes_read = vfs.read(fd, file_buffer[total_read..]) catch |err| {
            if (err != error.EndOfFile) {
                vga.print("\nread error: ");
                vga.print(@errorName(err));
                vga.print("\n");
            }
            break;
        };
        if (bytes_read == 0) break;
        total_read += bytes_read;
    }

    var line_count: u32 = 0;
    var start_pos: usize = total_read;

    if (total_read > 0) {
        var i = total_read;
        while (i > 0 and line_count < lines) {
            i -= 1;
            if (file_buffer[i] == '\n') {
                line_count += 1;
                if (line_count == lines) {
                    start_pos = i + 1;
                    break;
                }
            }
        }
    }

    for (file_buffer[start_pos..total_read]) |byte| {
        if (byte == '\r') continue;
        vga.put_char(byte);
    }
}

pub fn wc(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: wc <file>\n");
        return;
    }

    const path = args[0];
    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("wc: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var buffer: [512]u8 = undefined;
    var lines: u32 = 0;
    var words: u32 = 0;
    var bytes: u32 = 0;
    var in_word = false;

    while (true) {
        const bytes_read = vfs.read(fd, &buffer) catch |err| {
            if (err != error.EndOfFile) {
                vga.print("\nread error: ");
                vga.print(@errorName(err));
                vga.print("\n");
            }
            break;
        };

        if (bytes_read == 0) break;
        bytes += @intCast(bytes_read);

        for (buffer[0..bytes_read]) |byte| {
            if (byte == '\r') continue;

            if (byte == '\n') {
                lines += 1;
                in_word = false;
            } else if (byte == ' ' or byte == '\t') {
                in_word = false;
            } else if (!in_word) {
                words += 1;
                in_word = true;
            }
        }
    }

    printNumber(lines);
    vga.print(" ");
    printNumber(words);
    vga.print(" ");
    printNumber(bytes);
    vga.print(" ");
    printString(path);
    vga.print("\n");
}

pub fn grep(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: grep <pattern> <file>\n");
        return;
    }

    const pattern = sliceFromCStr(args[0]);
    const path = args[1];
    const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
        vga.print("grep: ");
        printString(path);
        vga.print(": ");
        vga.print(@errorName(err));
        vga.print("\n");
        return;
    };
    defer vfs.close(fd) catch {};

    var buffer: [512]u8 = undefined;
    var line_buffer: [256]u8 = undefined;
    var line_pos: usize = 0;
    var line_num: u32 = 1;

    while (true) {
        const bytes_read = vfs.read(fd, &buffer) catch |err| {
            if (err != error.EndOfFile) {
                vga.print("\nread error: ");
                vga.print(@errorName(err));
                vga.print("\n");
            }
            break;
        };

        if (bytes_read == 0) break;

        for (buffer[0..bytes_read]) |byte| {
            if (byte == '\r') continue;

            if (byte == '\n') {
                const line_slice = line_buffer[0..line_pos];
                if (contains(line_slice, pattern)) {
                    printNumber(line_num);
                    vga.print(": ");
                    for (line_slice) |c| {
                        vga.put_char(c);
                    }
                    vga.put_char('\n');
                }
                line_pos = 0;
                line_num += 1;
            } else if (line_pos < line_buffer.len) {
                line_buffer[line_pos] = byte;
                line_pos += 1;
            }
        }
    }

    if (line_pos > 0) {
        const line_slice = line_buffer[0..line_pos];
        if (contains(line_slice, pattern)) {
            printNumber(line_num);
            vga.print(": ");
            for (line_slice) |c| {
                vga.put_char(c);
            }
            vga.put_char('\n');
        }
    }
}

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
    file_ops.fstat(@as(i32, @intCast(fd)), &stat_info) catch |err| {
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
    printNumber(@as(usize, @intCast(stat_info.size)));
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

pub fn hexdump(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: hexdump <file>\n");
        return;
    }

    const path = sliceFromCStr(args[0]);
    const vnode = vfs.lookupPath(path) catch {
        vga.print("hexdump: file not found\n");
        return;
    };

    var buf: [256]u8 = undefined;
    var offset: u64 = 0;

    while (true) {
        const bytes_read = vnode.ops.read(vnode, &buf, offset) catch {
            vga.print("hexdump: read error\n");
            return;
        };
        if (bytes_read == 0) break;

        var i: usize = 0;
        while (i < bytes_read) {
            if (i % 16 == 0) {
                printHex32(@intCast(offset + i));
                vga.print("  ");
            }

            printHex8(buf[i]);
            vga.print(" ");

            if (i % 16 == 15 or i == bytes_read - 1) {
                var pad = (15 - (i % 16)) * 3;
                while (pad > 0) : (pad -= 1) {
                    vga.put_char(' ');
                }
                vga.print(" |");
                const line_start = i - (i % 16);
                var j: usize = line_start;
                while (j <= i) : (j += 1) {
                    const c = buf[j];
                    if (c >= 0x20 and c < 0x7f) {
                        vga.put_char(c);
                    } else {
                        vga.put_char('.');
                    }
                }
                vga.print("|\n");
            }
            i += 1;
        }
        offset += bytes_read;
        if (bytes_read < buf.len) break;
    }
}

pub fn which(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: which <command>\n");
        return;
    }

    const cmd = sliceFromCStr(args[0]);
    if (registry.lookup(cmd) != null) {
        vga.print(cmd);
        vga.print(": shell built-in command\n");
        return;
    }

    vga.print(cmd);
    vga.print(" not found\n");
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

fn printHex32(val: u32) void {
    const hex = "0123456789abcdef";
    var buf: [8]u8 = undefined;
    var v = val;
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        buf[i] = hex[v & 0xf];
        v >>= 4;
    }
    vga.print(&buf);
}

fn printHex8(val: u8) void {
    const hex = "0123456789abcdef";
    var buf: [2]u8 = undefined;
    buf[0] = hex[(val >> 4) & 0xf];
    buf[1] = hex[val & 0xf];
    vga.print(&buf);
}

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
}

fn printNumber(num: usize) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

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

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}
