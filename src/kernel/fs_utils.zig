const std = @import("std");
const vfs = @import("vfs.zig");
const memory = @import("memory.zig");
const vga = @import("vga.zig");

pub const ListDirOptions = struct {
    show_hidden: bool = false,
    show_details: bool = false,
    recursive: bool = false,
    filter_type: ?vfs.FileType = null,
    pattern: ?[]const u8 = null,
};

pub fn listDirectory(path: []const u8, options: ListDirOptions) vfs.VFSError!void {
    const fd = try vfs.open(path, vfs.O_RDONLY);
    defer vfs.close(fd) catch {};

    var index: u64 = 0;
    var entry: vfs.DirEntry = undefined;

    while (try vfs.readdir(fd, &entry, index)) : (index += 1) {
        // Skip hidden files if not requested
        if (!options.show_hidden and entry.name[0] == '.') {
            continue;
        }

        // Filter by type if specified
        if (options.filter_type) |filter| {
            if (entry.file_type != filter) {
                continue;
            }
        }

        // Pattern matching (simple substring for now)
        if (options.pattern) |pattern| {
            if (!contains(entry.name[0..entry.name_len], pattern)) {
                continue;
            }
        }

        if (options.show_details) {
            // Get detailed information
            var full_path: [512]u8 = undefined;
            const path_len = @min(path.len, 256);
            @memcpy(full_path[0..path_len], path[0..path_len]);
            full_path[path_len] = '/';
            @memcpy(full_path[path_len + 1 .. path_len + 1 + entry.name_len], entry.name[0..entry.name_len]);
            full_path[path_len + 1 + entry.name_len] = 0;

            var stat_buf: vfs.FileStat = undefined;
            if (vfs.stat(full_path[0 .. path_len + 1 + entry.name_len], &stat_buf)) |_| {
                printFileDetails(&entry, &stat_buf);
            } else |_| {
                printFileName(&entry);
            }
        } else {
            printFileName(&entry);
        }

        if (options.recursive and entry.file_type == vfs.FileType.Directory) {
            if (entry.name[0] != '.') { // Skip . and ..
                var sub_path: [512]u8 = undefined;
                const path_len = @min(path.len, 256);
                @memcpy(sub_path[0..path_len], path[0..path_len]);
                sub_path[path_len] = '/';
                @memcpy(sub_path[path_len + 1 .. path_len + 1 + entry.name_len], entry.name[0..entry.name_len]);
                
                vga.print("\n");
                vga.print(sub_path[0 .. path_len + 1 + entry.name_len]);
                vga.print(":\n");
                
                listDirectory(sub_path[0 .. path_len + 1 + entry.name_len], options) catch |err| {
                    vga.print("Error listing ");
                    vga.print(sub_path[0 .. path_len + 1 + entry.name_len]);
                    vga.print(": ");
                    vga.print(@errorName(err));
                    vga.print("\n");
                };
            }
        }
    }
}

pub fn copyFile(src_path: []const u8, dst_path: []const u8) vfs.VFSError!void {
    // Open source file for reading
    const src_fd = try vfs.open(src_path, vfs.O_RDONLY);
    defer vfs.close(src_fd) catch {};

    // Get source file size
    var stat_buf: vfs.FileStat = undefined;
    try vfs.stat(src_path, &stat_buf);

    if (stat_buf.file_type == vfs.FileType.Directory) {
        return vfs.VFSError.IsDirectory;
    }

    // Create destination file
    const dst_fd = try vfs.open(dst_path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC);
    defer vfs.close(dst_fd) catch {};

    // Allocate buffer for copying
    const buffer_size: usize = 4096;
    const buffer_mem = memory.kmalloc(buffer_size) orelse return vfs.VFSError.OutOfMemory;
    defer memory.kfree(@as([*]u8, @ptrCast(buffer_mem)));
    const buffer = @as([*]u8, @ptrCast(buffer_mem))[0..buffer_size];

    // Copy data
    var total_copied: usize = 0;
    while (total_copied < stat_buf.size) {
        const to_read = @min(buffer_size, stat_buf.size - total_copied);
        const bytes_read = try vfs.read(src_fd, buffer[0..to_read]);
        if (bytes_read == 0) break;

        var written: usize = 0;
        while (written < bytes_read) {
            const bytes_written = try vfs.write(dst_fd, buffer[written..bytes_read]);
            if (bytes_written == 0) {
                return vfs.VFSError.DeviceError;
            }
            written += bytes_written;
        }

        total_copied += bytes_read;
    }

    // Copy permissions
    vfs.chmod(dst_path, stat_buf.mode) catch {};
}

pub fn moveFile(src_path: []const u8, dst_path: []const u8) vfs.VFSError!void {
    // Try rename first (efficient if same filesystem)
    if (vfs.rename(src_path, dst_path)) |_| {
        return;
    } else |_| {
        // Fall back to copy and delete
        try copyFile(src_path, dst_path);
        try vfs.unlink(src_path);
    }
}

pub fn copyDirectory(src_path: []const u8, dst_path: []const u8) vfs.VFSError!void {
    // Get source directory info
    var stat_buf: vfs.FileStat = undefined;
    try vfs.stat(src_path, &stat_buf);

    if (stat_buf.file_type != vfs.FileType.Directory) {
        return vfs.VFSError.NotDirectory;
    }

    // Create destination directory
    try vfs.mkdir(dst_path, stat_buf.mode);

    // Copy contents
    const src_fd = try vfs.open(src_path, vfs.O_RDONLY);
    defer vfs.close(src_fd) catch {};

    var index: u64 = 0;
    var entry: vfs.DirEntry = undefined;

    while (try vfs.readdir(src_fd, &entry, index)) : (index += 1) {
        // Skip . and ..
        if (entry.name[0] == '.' and (entry.name_len == 1 or 
            (entry.name_len == 2 and entry.name[1] == '.'))) {
            continue;
        }

        // Build full paths
        var src_full: [512]u8 = undefined;
        var dst_full: [512]u8 = undefined;

        const src_len = @min(src_path.len, 256);
        @memcpy(src_full[0..src_len], src_path[0..src_len]);
        src_full[src_len] = '/';
        @memcpy(src_full[src_len + 1 .. src_len + 1 + entry.name_len], entry.name[0..entry.name_len]);

        const dst_len = @min(dst_path.len, 256);
        @memcpy(dst_full[0..dst_len], dst_path[0..dst_len]);
        dst_full[dst_len] = '/';
        @memcpy(dst_full[dst_len + 1 .. dst_len + 1 + entry.name_len], entry.name[0..entry.name_len]);

        if (entry.file_type == vfs.FileType.Directory) {
            // Recursively copy subdirectory
            copyDirectory(
                src_full[0 .. src_len + 1 + entry.name_len],
                dst_full[0 .. dst_len + 1 + entry.name_len]
            ) catch |err| {
                vga.print("Error copying directory: ");
                vga.print(@errorName(err));
                vga.print("\n");
            };
        } else {
            // Copy file
            copyFile(
                src_full[0 .. src_len + 1 + entry.name_len],
                dst_full[0 .. dst_len + 1 + entry.name_len]
            ) catch |err| {
                vga.print("Error copying file: ");
                vga.print(@errorName(err));
                vga.print("\n");
            };
        }
    }
}

pub fn getFileSize(path: []const u8) vfs.VFSError!u64 {
    var stat_buf: vfs.FileStat = undefined;
    try vfs.stat(path, &stat_buf);
    return stat_buf.size;
}

pub fn fileExists(path: []const u8) bool {
    var stat_buf: vfs.FileStat = undefined;
    if (vfs.stat(path, &stat_buf)) |_| {
        return true;
    } else |_| {
        return false;
    }
}

pub fn isDirectory(path: []const u8) vfs.VFSError!bool {
    var stat_buf: vfs.FileStat = undefined;
    try vfs.stat(path, &stat_buf);
    return stat_buf.file_type == vfs.FileType.Directory;
}

pub fn isRegularFile(path: []const u8) vfs.VFSError!bool {
    var stat_buf: vfs.FileStat = undefined;
    try vfs.stat(path, &stat_buf);
    return stat_buf.file_type == vfs.FileType.Regular;
}

pub fn makeDirectory(path: []const u8, create_parents: bool) vfs.VFSError!void {
    if (!create_parents) {
        const default_mode = vfs.FileMode{
            .owner_read = true,
            .owner_write = true,
            .owner_exec = true,
            .group_read = true,
            .group_exec = true,
            .other_read = true,
            .other_exec = true,
        };
        try vfs.mkdir(path, default_mode);
        return;
    }

    // Create parent directories if needed
    var i: usize = 1; // Skip initial '/'
    while (i <= path.len) : (i += 1) {
        if (i == path.len or path[i] == '/') {
            const partial_path = path[0..i];
            if (!fileExists(partial_path)) {
                const default_mode = vfs.FileMode{
                    .owner_read = true,
                    .owner_write = true,
                    .owner_exec = true,
                    .group_read = true,
                    .group_exec = true,
                    .other_read = true,
                    .other_exec = true,
                };
                vfs.mkdir(partial_path, default_mode) catch |err| {
                    if (err != vfs.VFSError.AlreadyExists) {
                        return err;
                    }
                };
            }
        }
    }
}

pub fn removeDirectory(path: []const u8, recursive: bool) vfs.VFSError!void {
    if (!recursive) {
        try vfs.rmdir(path);
        return;
    }

    // Remove contents first
    const fd = try vfs.open(path, vfs.O_RDONLY);
    defer vfs.close(fd) catch {};

    var entries_to_remove: [256]struct {
        name: [256]u8,
        name_len: u16,
        is_dir: bool,
    } = undefined;
    var entry_count: usize = 0;

    var index: u64 = 0;
    var entry: vfs.DirEntry = undefined;

    // Collect entries first (to avoid modifying while iterating)
    while (try vfs.readdir(fd, &entry, index)) : (index += 1) {
        // Skip . and ..
        if (entry.name[0] == '.' and (entry.name_len == 1 or 
            (entry.name_len == 2 and entry.name[1] == '.'))) {
            continue;
        }

        if (entry_count >= entries_to_remove.len) break;

        @memcpy(entries_to_remove[entry_count].name[0..entry.name_len], entry.name[0..entry.name_len]);
        entries_to_remove[entry_count].name_len = entry.name_len;
        entries_to_remove[entry_count].is_dir = entry.file_type == vfs.FileType.Directory;
        entry_count += 1;
    }

    // Remove collected entries
    for (entries_to_remove[0..entry_count]) |item| {
        var full_path: [512]u8 = undefined;
        const path_len = @min(path.len, 256);
        @memcpy(full_path[0..path_len], path[0..path_len]);
        full_path[path_len] = '/';
        @memcpy(full_path[path_len + 1 .. path_len + 1 + item.name_len], item.name[0..item.name_len]);

        if (item.is_dir) {
            removeDirectory(full_path[0 .. path_len + 1 + item.name_len], true) catch |err| {
                vga.print("Error removing directory: ");
                vga.print(@errorName(err));
                vga.print("\n");
            };
        } else {
            vfs.unlink(full_path[0 .. path_len + 1 + item.name_len]) catch |err| {
                vga.print("Error removing file: ");
                vga.print(@errorName(err));
                vga.print("\n");
            };
        }
    }

    // Finally remove the directory itself
    try vfs.rmdir(path);
}

fn printFileName(entry: *const vfs.DirEntry) void {
    if (entry.file_type == vfs.FileType.Directory) {
        vga.setColor(0x09); // Blue for directories
    } else if (entry.file_type == vfs.FileType.CharDevice or 
               entry.file_type == vfs.FileType.BlockDevice) {
        vga.setColor(0x0E); // Yellow for devices
    } else {
        vga.setColor(0x07); // White for regular files
    }
    
    vga.print(entry.name[0..entry.name_len]);
    
    if (entry.file_type == vfs.FileType.Directory) {
        vga.print("/");
    }
    
    vga.setColor(0x07); // Reset to white
    vga.print("  ");
}

fn printFileDetails(entry: *const vfs.DirEntry, stat: *const vfs.FileStat) void {
    // Print type
    switch (stat.file_type) {
        .Directory => vga.print("d"),
        .Regular => vga.print("-"),
        .CharDevice => vga.print("c"),
        .BlockDevice => vga.print("b"),
        .Pipe => vga.print("p"),
        .SymLink => vga.print("l"),
        .Socket => vga.print("s"),
    }

    // Print permissions
    vga.print(if (stat.mode.owner_read) "r" else "-");
    vga.print(if (stat.mode.owner_write) "w" else "-");
    vga.print(if (stat.mode.owner_exec) "x" else "-");
    vga.print(if (stat.mode.group_read) "r" else "-");
    vga.print(if (stat.mode.group_write) "w" else "-");
    vga.print(if (stat.mode.group_exec) "x" else "-");
    vga.print(if (stat.mode.other_read) "r" else "-");
    vga.print(if (stat.mode.other_write) "w" else "-");
    vga.print(if (stat.mode.other_exec) "x" else "-");
    vga.print(" ");

    // Print size (right-aligned in 10 chars)
    printNumber(stat.size, 10);
    vga.print(" ");

    // Print name
    printFileName(entry);
    vga.print("\n");
}

fn printNumber(num: u64, width: usize) void {
    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    if (n == 0) {
        buffer[i] = '0';
        i += 1;
    } else {
        while (n > 0) : (n /= 10) {
            buffer[i] = @as(u8, @intCast('0' + (n % 10)));
            i += 1;
        }
    }

    // Print padding
    if (i < width) {
        for (0..width - i) |_| {
            vga.print(" ");
        }
    }

    // Print number in reverse
    while (i > 0) {
        i -= 1;
        vga.printChar(buffer[i]);
    }
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    
    for (0..haystack.len - needle.len + 1) |i| {
        if (std.mem.eql(u8, haystack[i..i + needle.len], needle)) {
            return true;
        }
    }
    
    return false;
}