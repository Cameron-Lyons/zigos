const std = @import("std");
const vfs = @import("vfs.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

var devfs_mount_point: ?*vfs.MountPoint = null;

fn nullRead(_: *vfs.VNode, _: []u8, _: u64) vfs.VFSError!usize {
    return 0;
}

fn nullWrite(_: *vfs.VNode, buf: []const u8, _: u64) vfs.VFSError!usize {
    return buf.len;
}

fn zeroRead(_: *vfs.VNode, buf: []u8, _: u64) vfs.VFSError!usize {
    @memset(buf, 0);
    return buf.len;
}

fn zeroWrite(_: *vfs.VNode, buf: []const u8, _: u64) vfs.VFSError!usize {
    return buf.len;
}

fn ttyRead(_: *vfs.VNode, _: []u8, _: u64) vfs.VFSError!usize {
    return 0;
}

fn ttyWrite(_: *vfs.VNode, buf: []const u8, _: u64) vfs.VFSError!usize {
    for (buf) |c| {
        vga.print(&[_]u8{c});
    }
    return buf.len;
}

var rng_state: u32 = 0x12345678;

fn xorshift32() u32 {
    var x = rng_state;
    if (x == 0) {
        const timer = @import("../timer/timer.zig");
        x = @truncate(timer.getTicks() | 1);
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

fn randomRead(_: *vfs.VNode, buf: []u8, _: u64) vfs.VFSError!usize {
    var i: usize = 0;
    while (i + 4 <= buf.len) : (i += 4) {
        const val = xorshift32();
        buf[i] = @truncate(val);
        buf[i + 1] = @truncate(val >> 8);
        buf[i + 2] = @truncate(val >> 16);
        buf[i + 3] = @truncate(val >> 24);
    }
    if (i < buf.len) {
        const val = xorshift32();
        var j: u5 = 0;
        while (i < buf.len) : (i += 1) {
            buf[i] = @truncate(val >> (j * 8));
            j +%= 1;
        }
    }
    return buf.len;
}

fn randomWrite(_: *vfs.VNode, buf: []const u8, _: u64) vfs.VFSError!usize {
    for (buf) |b| {
        rng_state ^= @as(u32, b) << @truncate(rng_state & 0x1F);
    }
    return buf.len;
}

fn devOpen(_: *vfs.VNode, _: u32) vfs.VFSError!void {}
fn devClose(_: *vfs.VNode) vfs.VFSError!void {}
fn devSeek(_: *vfs.VNode, _: i64, _: u32) vfs.VFSError!u64 { return 0; }
fn devIoctl(_: *vfs.VNode, _: u32, _: usize) vfs.VFSError!i32 { return 0; }

fn devStat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    stat_buf.* = vfs.FileStat{
        .inode = vnode.inode,
        .mode = vnode.mode,
        .file_type = vnode.file_type,
        .size = 0,
        .blocks = 0,
        .block_size = 0,
        .uid = vnode.uid,
        .gid = vnode.gid,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn devNoReaddir(_: *vfs.VNode, _: *vfs.DirEntry, _: u64) vfs.VFSError!bool {
    return vfs.VFSError.InvalidOperation;
}

fn devTruncate(_: *vfs.VNode, _: u64) vfs.VFSError!void {
    return vfs.VFSError.InvalidOperation;
}

fn devChmod(_: *vfs.VNode, _: vfs.FileMode) vfs.VFSError!void {}
fn devChown(_: *vfs.VNode, _: u32, _: u32) vfs.VFSError!void {}

const null_ops = vfs.FileOps{
    .read = nullRead,
    .write = nullWrite,
    .open = devOpen,
    .close = devClose,
    .seek = devSeek,
    .ioctl = devIoctl,
    .stat = devStat,
    .readdir = devNoReaddir,
    .truncate = devTruncate,
    .chmod = devChmod,
    .chown = devChown,
};

const zero_ops = vfs.FileOps{
    .read = zeroRead,
    .write = zeroWrite,
    .open = devOpen,
    .close = devClose,
    .seek = devSeek,
    .ioctl = devIoctl,
    .stat = devStat,
    .readdir = devNoReaddir,
    .truncate = devTruncate,
    .chmod = devChmod,
    .chown = devChown,
};

const tty_ops = vfs.FileOps{
    .read = ttyRead,
    .write = ttyWrite,
    .open = devOpen,
    .close = devClose,
    .seek = devSeek,
    .ioctl = devIoctl,
    .stat = devStat,
    .readdir = devNoReaddir,
    .truncate = devTruncate,
    .chmod = devChmod,
    .chown = devChown,
};

const random_ops = vfs.FileOps{
    .read = randomRead,
    .write = randomWrite,
    .open = devOpen,
    .close = devClose,
    .seek = devSeek,
    .ioctl = devIoctl,
    .stat = devStat,
    .readdir = devNoReaddir,
    .truncate = devTruncate,
    .chmod = devChmod,
    .chown = devChown,
};

fn rootRead(_: *vfs.VNode, _: []u8, _: u64) vfs.VFSError!usize {
    return vfs.VFSError.IsDirectory;
}

fn rootWrite(_: *vfs.VNode, _: []const u8, _: u64) vfs.VFSError!usize {
    return vfs.VFSError.IsDirectory;
}

fn rootReaddir(_: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    if (index >= device_table.len) return false;

    const dev = device_table[@intCast(index)];
    @memset(&dirent.name, 0);
    @memcpy(dirent.name[0..dev.name.len], dev.name);
    dirent.name_len = @intCast(dev.name.len);
    dirent.inode = dev.inode;
    dirent.file_type = .CharDevice;
    return true;
}

const root_ops = vfs.FileOps{
    .read = rootRead,
    .write = rootWrite,
    .open = devOpen,
    .close = devClose,
    .seek = devSeek,
    .ioctl = devIoctl,
    .stat = devStat,
    .readdir = rootReaddir,
    .truncate = devTruncate,
    .chmod = devChmod,
    .chown = devChown,
};

const DeviceInfo = struct {
    name: []const u8,
    inode: u64,
    ops: *const vfs.FileOps,
};

const device_table = [_]DeviceInfo{
    .{ .name = "null", .inode = 1, .ops = &null_ops },
    .{ .name = "zero", .inode = 2, .ops = &zero_ops },
    .{ .name = "tty", .inode = 3, .ops = &tty_ops },
    .{ .name = "random", .inode = 4, .ops = &random_ops },
    .{ .name = "urandom", .inode = 5, .ops = &random_ops },
};

fn createDevVNode(name: []const u8, inode: u64, file_type: vfs.FileType, ops: *const vfs.FileOps, mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    var vnode_name = [_]u8{0} ** 256;
    const len = @min(name.len, 255);
    @memcpy(vnode_name[0..len], name[0..len]);

    vnode.* = vfs.VNode{
        .name = vnode_name,
        .name_len = @intCast(len),
        .inode = inode,
        .file_type = file_type,
        .mode = .{
            .owner_read = true,
            .owner_write = true,
            .group_read = true,
            .group_write = true,
            .other_read = true,
            .other_write = true,
        },
        .size = 0,
        .ref_count = 1,
        .mount_point = mp,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = ops,
        .private_data = null,
    };

    return vnode;
}

fn devfsMount(mp: *vfs.MountPoint) vfs.VFSError!void {
    devfs_mount_point = mp;
}

fn devfsUnmount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn devfsGetRoot(mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    return createDevVNode("/", 0, .Directory, &root_ops, mp);
}

fn devfsLookup(_: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const mp = devfs_mount_point orelse return vfs.VFSError.NotFound;
    for (device_table) |dev| {
        if (std.mem.eql(u8, name, dev.name)) {
            return createDevVNode(dev.name, dev.inode, .CharDevice, dev.ops, mp);
        }
    }
    return vfs.VFSError.NotFound;
}

fn devfsCreate(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn devfsMkdir(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn devfsUnlink(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn devfsRmdir(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn devfsRename(_: *vfs.VNode, _: []const u8, _: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const devfs_fs_ops = vfs.FileSystemOps{
    .mount = devfsMount,
    .unmount = devfsUnmount,
    .get_root = devfsGetRoot,
    .lookup = devfsLookup,
    .create = devfsCreate,
    .mkdir = devfsMkdir,
    .unlink = devfsUnlink,
    .rmdir = devfsRmdir,
    .rename = devfsRename,
};

var devfs_type = vfs.FileSystemType{
    .name = blk: {
        var name = [_]u8{0} ** 32;
        name[0] = 'd';
        name[1] = 'e';
        name[2] = 'v';
        name[3] = 'f';
        name[4] = 's';
        break :blk name;
    },
    .ops = &devfs_fs_ops,
    .next = null,
};

pub fn init() void {
    vfs.registerFileSystem(&devfs_type) catch {
        vga.print("Failed to register devfs\n");
        return;
    };
    vga.print("devfs filesystem registered\n");
}
