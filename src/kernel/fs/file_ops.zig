const std = @import("std");
const vfs = @import("vfs.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");
const ext2 = @import("ext2.zig");

pub const SeekWhence = enum(u32) {
    SET = 0,
    CUR = 1,
    END = 2,
};

pub const FileDescriptor = struct {
    vnode: *vfs.VNode,
    offset: u64,
    flags: u32,
    ref_count: u32,
};

const MAX_FDS = 256;
var file_descriptors: [MAX_FDS]?FileDescriptor = [_]?FileDescriptor{null} ** MAX_FDS;
var next_fd: u32 = 3;

pub fn init() void {
    for (&file_descriptors) |*fd| {
        fd.* = null;
    }
    next_fd = 3;
    vga.print("File operations initialized\n");
}

pub fn open(path: []const u8, flags: u32) !i32 {
    const vnode = vfs.lookupPath(path) catch |err| {
        return switch (err) {
            vfs.VFSError.NotFound => error.FileNotFound,
            vfs.VFSError.PermissionDenied => error.PermissionDenied,
            else => error.OpenFailed,
        };
    };

    if (vnode.ops.open) |open_fn| {
        try open_fn(vnode, flags);
    }

    var fd_index: u32 = 0;
    while (fd_index < MAX_FDS) : (fd_index += 1) {
        if (file_descriptors[fd_index] == null) {
            file_descriptors[fd_index] = FileDescriptor{
                .vnode = vnode,
                .offset = 0,
                .flags = flags,
                .ref_count = 1,
            };
            vnode.ref_count += 1;
            return @intCast(fd_index);
        }
    }

    return error.TooManyOpenFiles;
}

pub fn close(fd: i32) !void {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    if (file_desc.ref_count > 1) {
        file_descriptors[index].?.ref_count -= 1;
        return;
    }

    if (file_desc.vnode.ops.close) |close_fn| {
        try close_fn(file_desc.vnode);
    }

    file_desc.vnode.ref_count -= 1;
    file_descriptors[index] = null;
}

pub fn read(fd: i32, buffer: []u8) !usize {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    var file_desc = &(file_descriptors[index] orelse return error.InvalidFileDescriptor);

    const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, file_desc.offset);
    file_desc.offset += bytes_read;
    return bytes_read;
}

pub fn write(fd: i32, buffer: []const u8) !usize {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    var file_desc = &(file_descriptors[index] orelse return error.InvalidFileDescriptor);

    const bytes_written = try file_desc.vnode.ops.write(file_desc.vnode, buffer, file_desc.offset);
    file_desc.offset += bytes_written;
    return bytes_written;
}

pub fn seek(fd: i32, offset: i64, whence: SeekWhence) !u64 {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    var file_desc = &(file_descriptors[index] orelse return error.InvalidFileDescriptor);

    const new_offset = switch (whence) {
        .SET => if (offset < 0) return error.InvalidOffset else @as(u64, @intCast(offset)),
        .CUR => blk: {
            const signed_current = @as(i64, @intCast(file_desc.offset));
            const new_pos = signed_current + offset;
            if (new_pos < 0) return error.InvalidOffset;
            break :blk @as(u64, @intCast(new_pos));
        },
        .END => blk: {
            const signed_size = @as(i64, @intCast(file_desc.vnode.size));
            const new_pos = signed_size + offset;
            if (new_pos < 0) return error.InvalidOffset;
            break :blk @as(u64, @intCast(new_pos));
        },
    };

    if (file_desc.vnode.ops.seek) |seek_fn| {
        file_desc.offset = try seek_fn(file_desc.vnode, offset, @intFromEnum(whence));
    } else {
        file_desc.offset = new_offset;
    }

    return file_desc.offset;
}

pub fn truncate(fd: i32, size: u64) !void {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    if (file_desc.vnode.ops.truncate) |truncate_fn| {
        try truncate_fn(file_desc.vnode, size);
    } else {
        return error.OperationNotSupported;
    }
}

pub fn fstat(fd: i32, stat: *vfs.FileStat) !void {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    try file_desc.vnode.ops.stat(file_desc.vnode, stat);
}

pub fn dup(old_fd: i32) !i32 {
    if (old_fd < 0 or old_fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const old_index = @as(usize, @intCast(old_fd));
    const old_desc = file_descriptors[old_index] orelse return error.InvalidFileDescriptor;

    var new_fd: u32 = 0;
    while (new_fd < MAX_FDS) : (new_fd += 1) {
        if (file_descriptors[new_fd] == null) {
            file_descriptors[new_fd] = FileDescriptor{
                .vnode = old_desc.vnode,
                .offset = old_desc.offset,
                .flags = old_desc.flags,
                .ref_count = 1,
            };
            old_desc.vnode.ref_count += 1;
            return @intCast(new_fd);
        }
    }

    return error.TooManyOpenFiles;
}

pub fn dup2(old_fd: i32, new_fd: i32) !i32 {
    if (old_fd < 0 or old_fd >= MAX_FDS or new_fd < 0 or new_fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    if (old_fd == new_fd) {
        return new_fd;
    }

    const old_index = @as(usize, @intCast(old_fd));
    const new_index = @as(usize, @intCast(new_fd));
    const old_desc = file_descriptors[old_index] orelse return error.InvalidFileDescriptor;

    if (file_descriptors[new_index]) |_| {
        try close(new_fd);
    }

    file_descriptors[new_index] = FileDescriptor{
        .vnode = old_desc.vnode,
        .offset = old_desc.offset,
        .flags = old_desc.flags,
        .ref_count = 1,
    };
    old_desc.vnode.ref_count += 1;

    return new_fd;
}

pub fn pread(fd: i32, buffer: []u8, offset: u64) !usize {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    return try file_desc.vnode.ops.read(file_desc.vnode, buffer, offset);
}

pub fn pwrite(fd: i32, buffer: []const u8, offset: u64) !usize {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    return try file_desc.vnode.ops.write(file_desc.vnode, buffer, offset);
}

pub fn fsync(fd: i32) !void {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    if (file_desc.vnode.mount_point) |mount_point| {
        var fs_name_len: usize = 0;
        while (fs_name_len < 32 and mount_point.fs_type.name[fs_name_len] != 0) : (fs_name_len += 1) {}
        const fs_name = mount_point.fs_type.name[0..fs_name_len];
        
        if (std.mem.eql(u8, fs_name, "ext2")) {
            ext2.flushFilesystem(mount_point) catch |err| {
                return switch (err) {
                    vfs.VFSError.DeviceError => error.DeviceError,
                    else => error.SyncFailed,
                };
            };
        }
    }
}

pub fn fdatasync(fd: i32) !void {
    return fsync(fd);
}

pub fn tell(fd: i32) !u64 {
    if (fd < 0 or fd >= MAX_FDS) {
        return error.InvalidFileDescriptor;
    }

    const index = @as(usize, @intCast(fd));
    const file_desc = file_descriptors[index] orelse return error.InvalidFileDescriptor;

    return file_desc.offset;
}