const std = @import("std");
const smp = @import("../smp/smp.zig");
const support = @import("../process/syscall/support.zig");
const system = @import("../process/syscall/system.zig");
const vfs = @import("vfs.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

const MAX_RENDER_SIZE = 256;
const VERSION_TEXT = "ZigOS 0.1.0 (Zig 0.16.0-dev)\n";

const dir_mode = vfs.FileMode{
    .owner_read = true,
    .owner_exec = true,
    .group_read = true,
    .group_exec = true,
    .other_read = true,
    .other_exec = true,
};

const file_mode = vfs.FileMode{
    .owner_read = true,
    .group_read = true,
    .other_read = true,
};

const writable_file_mode = vfs.FileMode{
    .owner_read = true,
    .owner_write = true,
    .group_read = true,
    .other_read = true,
};

const NodeKind = enum(u8) {
    root = 1,
    kernel_dir = 2,
    hostname = 3,
    version = 4,
    uptime = 5,
    active_cpus = 6,
    machine = 7,
};

const kernel_entries = [_]struct {
    name: []const u8,
    kind: NodeKind,
    mode: vfs.FileMode,
}{
    .{ .name = "active_cpus", .kind = .active_cpus, .mode = file_mode },
    .{ .name = "hostname", .kind = .hostname, .mode = writable_file_mode },
    .{ .name = "machine", .kind = .machine, .mode = file_mode },
    .{ .name = "uptime", .kind = .uptime, .mode = file_mode },
    .{ .name = "version", .kind = .version, .mode = file_mode },
};

fn encodeNode(kind: NodeKind) u64 {
    return @as(u64, @intFromEnum(kind));
}

fn decodeNode(inode: u64) NodeKind {
    return @enumFromInt(@as(u8, @truncate(inode)));
}

fn createVNode(name: []const u8, file_type: vfs.FileType, mode: vfs.FileMode, inode: u64, mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const raw = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(raw));

    var vnode_name = [_]u8{0} ** 256;
    const name_len = @min(name.len, vnode_name.len - 1);
    @memcpy(vnode_name[0..name_len], name[0..name_len]);

    vnode.* = .{
        .name = vnode_name,
        .name_len = @intCast(name_len),
        .inode = inode,
        .file_type = file_type,
        .mode = mode,
        .size = 0,
        .uid = 0,
        .gid = 0,
        .ref_count = 1,
        .mount_point = mp,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &sysfs_file_ops,
        .private_data = null,
    };

    return vnode;
}

fn fillDirent(dirent: *vfs.DirEntry, name: []const u8, inode: u64, file_type: vfs.FileType) void {
    @memset(&dirent.name, 0);
    const len = @min(name.len, dirent.name.len);
    @memcpy(dirent.name[0..len], name[0..len]);
    dirent.name_len = @intCast(len);
    dirent.inode = inode;
    dirent.file_type = file_type;
}

fn renderNode(kind: NodeKind, buffer: []u8) []const u8 {
    return switch (kind) {
        .hostname => std.fmt.bufPrint(buffer, "{s}\n", .{system.getHostname()}) catch buffer[0..0],
        .version => VERSION_TEXT[0..VERSION_TEXT.len],
        .uptime => blk: {
            const info = support.syntheticSysinfo();
            break :blk std.fmt.bufPrint(buffer, "{d}\n", .{info.uptime}) catch buffer[0..0];
        },
        .active_cpus => std.fmt.bufPrint(buffer, "{d}\n", .{smp.getActiveCPUCount()}) catch buffer[0..0],
        .machine => "i386\n",
        else => buffer[0..0],
    };
}

fn readRendered(buffer: []u8, offset: u64, content: []const u8) usize {
    if (offset >= content.len) return 0;
    const start: usize = @intCast(offset);
    const count = @min(buffer.len, content.len - start);
    @memcpy(buffer[0..count], content[start .. start + count]);
    return count;
}

fn sysfsRead(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    if (vnode.file_type == .Directory) return vfs.VFSError.IsDirectory;

    var render_buffer: [MAX_RENDER_SIZE]u8 = undefined;
    const content = renderNode(decodeNode(vnode.inode), &render_buffer);
    return readRendered(buffer, offset, content);
}

fn sysfsWrite(vnode: *vfs.VNode, buffer: []const u8, offset: u64) vfs.VFSError!usize {
    if (decodeNode(vnode.inode) != .hostname) return vfs.VFSError.ReadOnly;
    if (offset != 0) return vfs.VFSError.InvalidOperation;

    var len = @min(buffer.len, @as(usize, 64));
    while (len > 0 and (buffer[len - 1] == '\n' or buffer[len - 1] == '\r' or buffer[len - 1] == 0)) : (len -= 1) {}
    system.setHostname(buffer[0..len]);
    vnode.size = len + 1;
    return buffer.len;
}

fn sysfsOpen(_: *vfs.VNode, _: u32) vfs.VFSError!void {}

fn sysfsClose(_: *vfs.VNode) vfs.VFSError!void {}

fn sysfsSeek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const size: i64 = @intCast(vnode.size);
    const absolute = switch (whence) {
        vfs.SEEK_SET => offset,
        vfs.SEEK_END => size + offset,
        else => return vfs.VFSError.InvalidOperation,
    };
    if (absolute < 0) return vfs.VFSError.InvalidOperation;
    return @intCast(absolute);
}

fn sysfsIoctl(_: *vfs.VNode, _: u32, _: usize) vfs.VFSError!i32 {
    return vfs.VFSError.InvalidOperation;
}

fn sysfsStat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    var size: u64 = 0;
    if (vnode.file_type == .Regular) {
        var render_buffer: [MAX_RENDER_SIZE]u8 = undefined;
        const content = renderNode(decodeNode(vnode.inode), &render_buffer);
        size = content.len;
        vnode.size = size;
    }

    stat_buf.* = .{
        .inode = vnode.inode,
        .mode = vnode.mode,
        .file_type = vnode.file_type,
        .size = size,
        .blocks = (size + 511) / 512,
        .block_size = 512,
        .uid = 0,
        .gid = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn sysfsReaddir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    switch (decodeNode(vnode.inode)) {
        .root => {
            if (index != 0) return false;
            fillDirent(dirent, "kernel", encodeNode(.kernel_dir), .Directory);
            return true;
        },
        .kernel_dir => {
            if (index >= kernel_entries.len) return false;
            const entry = kernel_entries[@intCast(index)];
            fillDirent(dirent, entry.name, encodeNode(entry.kind), .Regular);
            return true;
        },
        else => return vfs.VFSError.NotDirectory,
    }
}

fn sysfsTruncate(_: *vfs.VNode, _: u64) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn sysfsChmod(_: *vfs.VNode, _: vfs.FileMode) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn sysfsChown(_: *vfs.VNode, _: u32, _: u32) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const sysfs_file_ops = vfs.FileOps{
    .read = sysfsRead,
    .write = sysfsWrite,
    .open = sysfsOpen,
    .close = sysfsClose,
    .seek = sysfsSeek,
    .ioctl = sysfsIoctl,
    .stat = sysfsStat,
    .readdir = sysfsReaddir,
    .truncate = sysfsTruncate,
    .chmod = sysfsChmod,
    .chown = sysfsChown,
};

fn sysfsMount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn sysfsUnmount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn sysfsGetRoot(mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    return createVNode("/", .Directory, dir_mode, encodeNode(.root), mp);
}

fn sysfsLookup(parent: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    switch (decodeNode(parent.inode)) {
        .root => {
            if (!std.mem.eql(u8, name, "kernel")) return vfs.VFSError.NotFound;
            return createVNode("kernel", .Directory, dir_mode, encodeNode(.kernel_dir), parent.mount_point.?);
        },
        .kernel_dir => {
            for (kernel_entries) |entry| {
                if (std.mem.eql(u8, entry.name, name)) {
                    return createVNode(entry.name, .Regular, entry.mode, encodeNode(entry.kind), parent.mount_point.?);
                }
            }
            return vfs.VFSError.NotFound;
        },
        else => return vfs.VFSError.NotDirectory,
    }
}

fn sysfsCreate(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn sysfsMkdir(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn sysfsUnlink(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn sysfsRmdir(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn sysfsRename(_: *vfs.VNode, _: []const u8, _: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const sysfs_ops = vfs.FileSystemOps{
    .mount = sysfsMount,
    .unmount = sysfsUnmount,
    .get_root = sysfsGetRoot,
    .lookup = sysfsLookup,
    .create = sysfsCreate,
    .mkdir = sysfsMkdir,
    .unlink = sysfsUnlink,
    .rmdir = sysfsRmdir,
    .rename = sysfsRename,
};

var sysfs_type = vfs.FileSystemType{
    .name = blk: {
        var name = [_]u8{0} ** 32;
        name[0] = 's';
        name[1] = 'y';
        name[2] = 's';
        name[3] = 'f';
        name[4] = 's';
        break :blk name;
    },
    .ops = &sysfs_ops,
    .next = null,
};

pub fn init() void {
    vfs.registerFileSystem(&sysfs_type) catch {
        vga.print("Failed to register sysfs\n");
        return;
    };
    vga.print("sysfs filesystem registered\n");
}
