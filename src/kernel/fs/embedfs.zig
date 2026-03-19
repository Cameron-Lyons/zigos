const std = @import("std");
const memory = @import("../memory/memory.zig");
const user_assets = @import("user_assets");
const vfs = @import("vfs.zig");

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
    .owner_exec = true,
    .group_read = true,
    .group_exec = true,
    .other_read = true,
    .other_exec = true,
};

const text_mode = vfs.FileMode{
    .owner_read = true,
    .group_read = true,
    .other_read = true,
};

const Node = struct {
    name: []const u8,
    file_type: vfs.FileType,
    mode: vfs.FileMode,
    data: []const u8 = "",
    children: []const *const Node = &.{},
};

const program_nodes = blk: {
    var nodes: [user_assets.programs.len]Node = undefined;
    for (user_assets.programs, 0..) |program, i| {
        nodes[i] = .{
            .name = program.name,
            .file_type = .Regular,
            .mode = file_mode,
            .data = program.data,
        };
    }
    break :blk nodes;
};

const motd_node: Node align(@alignOf(Node)) = .{ .name = "motd", .file_type = .Regular, .mode = text_mode, .data = user_assets.motd };
const passwd_node: Node align(@alignOf(Node)) = .{ .name = "passwd", .file_type = .Regular, .mode = text_mode, .data = user_assets.passwd };

const usr_bin_children = [_]*const Node{};
const usr_bin_node: Node align(@alignOf(Node)) = .{ .name = "bin", .file_type = .Directory, .mode = dir_mode, .children = usr_bin_children[0..] };
const usr_children = [_]*const Node{&usr_bin_node};
const usr_node: Node align(@alignOf(Node)) = .{ .name = "usr", .file_type = .Directory, .mode = dir_mode, .children = usr_children[0..] };

const bin_children = blk: {
    var children: [program_nodes.len]*const Node = undefined;
    for (&program_nodes, 0..) |*node, i| {
        children[i] = node;
    }
    break :blk children;
};

const bin_node: Node align(@alignOf(Node)) = .{ .name = "bin", .file_type = .Directory, .mode = dir_mode, .children = bin_children[0..] };
const etc_children = [_]*const Node{ &motd_node, &passwd_node };
const etc_node: Node align(@alignOf(Node)) = .{ .name = "etc", .file_type = .Directory, .mode = dir_mode, .children = etc_children[0..] };
const user_home_children = [_]*const Node{};
const user_home_node: Node align(@alignOf(Node)) = .{ .name = "user", .file_type = .Directory, .mode = dir_mode, .children = user_home_children[0..] };
const home_children = [_]*const Node{&user_home_node};
const home_node: Node align(@alignOf(Node)) = .{ .name = "home", .file_type = .Directory, .mode = dir_mode, .children = home_children[0..] };
const tmp_children = [_]*const Node{};
const tmp_node: Node align(@alignOf(Node)) = .{ .name = "tmp", .file_type = .Directory, .mode = dir_mode, .children = tmp_children[0..] };
const mnt_children = [_]*const Node{};
const mnt_node: Node align(@alignOf(Node)) = .{ .name = "mnt", .file_type = .Directory, .mode = dir_mode, .children = mnt_children[0..] };
const dev_children = [_]*const Node{};
const dev_node: Node align(@alignOf(Node)) = .{ .name = "dev", .file_type = .Directory, .mode = dir_mode, .children = dev_children[0..] };
const proc_children = [_]*const Node{};
const proc_node: Node align(@alignOf(Node)) = .{ .name = "proc", .file_type = .Directory, .mode = dir_mode, .children = proc_children[0..] };
const root_home_children = [_]*const Node{};
const root_home_node: Node align(@alignOf(Node)) = .{ .name = "root", .file_type = .Directory, .mode = dir_mode, .children = root_home_children[0..] };
const sys_children = [_]*const Node{};
const sys_node: Node align(@alignOf(Node)) = .{ .name = "sys", .file_type = .Directory, .mode = dir_mode, .children = sys_children[0..] };
const root_children = [_]*const Node{ &bin_node, &dev_node, &etc_node, &home_node, &mnt_node, &proc_node, &root_home_node, &sys_node, &tmp_node, &usr_node };
const root_node: Node align(@alignOf(Node)) = .{ .name = "/", .file_type = .Directory, .mode = dir_mode, .children = root_children[0..] };

fn getNode(vnode: *vfs.VNode) *const Node {
    return @ptrFromInt(@intFromPtr(vnode.private_data.?));
}

fn createVNode(node: *const Node, mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrFromInt(@intFromPtr(vnode_mem));

    var vnode_name = [_]u8{0} ** 256;
    const name_len = @min(node.name.len, vnode_name.len - 1);
    @memcpy(vnode_name[0..name_len], node.name[0..name_len]);

    vnode.* = .{
        .name = vnode_name,
        .name_len = @intCast(name_len),
        .inode = @intFromPtr(node),
        .file_type = node.file_type,
        .mode = node.mode,
        .size = node.data.len,
        .uid = 0,
        .gid = 0,
        .ref_count = 1,
        .mount_point = mp,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &embedfs_file_ops,
        .private_data = @ptrCast(@constCast(node)),
    };

    if (node.file_type == .Directory) {
        var first_child: ?*vfs.VNode = null;
        var previous_child: ?*vfs.VNode = null;

        for (node.children) |child_node| {
            const child_vnode = try createVNode(child_node, mp);
            child_vnode.parent = vnode;
            if (previous_child) |prev| {
                prev.next_sibling = child_vnode;
            } else {
                first_child = child_vnode;
            }
            previous_child = child_vnode;
        }

        vnode.children = first_child;
    }

    return vnode;
}

fn embedfsRead(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    const node = getNode(vnode);
    if (node.file_type == .Directory) return vfs.VFSError.IsDirectory;
    if (offset >= node.data.len) return 0;

    const off: usize = @intCast(offset);
    const count = @min(buffer.len, node.data.len - off);
    std.mem.copyForwards(u8, buffer[0..count], node.data[off .. off + count]);
    return count;
}

fn embedfsWrite(_: *vfs.VNode, _: []const u8, _: u64) vfs.VFSError!usize {
    return vfs.VFSError.ReadOnly;
}

fn embedfsOpen(_: *vfs.VNode, _: u32) vfs.VFSError!void {}

fn embedfsClose(_: *vfs.VNode) vfs.VFSError!void {}

fn embedfsSeek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const node = getNode(vnode);
    const size: i64 = @intCast(node.data.len);
    const absolute = switch (whence) {
        vfs.SEEK_SET => offset,
        vfs.SEEK_END => size + offset,
        else => return vfs.VFSError.InvalidOperation,
    };
    if (absolute < 0) return vfs.VFSError.InvalidOperation;
    return @intCast(absolute);
}

fn embedfsIoctl(_: *vfs.VNode, _: u32, _: usize) vfs.VFSError!i32 {
    return vfs.VFSError.InvalidOperation;
}

fn embedfsStat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    const node = getNode(vnode);
    stat_buf.* = .{
        .inode = vnode.inode,
        .mode = node.mode,
        .file_type = node.file_type,
        .size = node.data.len,
        .blocks = (node.data.len + 511) / 512,
        .block_size = 512,
        .uid = 0,
        .gid = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn embedfsReaddir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    const node = getNode(vnode);
    if (node.file_type != .Directory) return vfs.VFSError.NotDirectory;
    if (index >= node.children.len) return false;

    const child = node.children[@intCast(index)];
    @memset(&dirent.name, 0);
    @memcpy(dirent.name[0..child.name.len], child.name);
    dirent.name_len = @intCast(child.name.len);
    dirent.inode = @intFromPtr(child);
    dirent.file_type = child.file_type;
    return true;
}

fn embedfsTruncate(_: *vfs.VNode, _: u64) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn embedfsChmod(_: *vfs.VNode, _: vfs.FileMode) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn embedfsChown(_: *vfs.VNode, _: u32, _: u32) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const embedfs_file_ops = vfs.FileOps{
    .read = embedfsRead,
    .write = embedfsWrite,
    .open = embedfsOpen,
    .close = embedfsClose,
    .seek = embedfsSeek,
    .ioctl = embedfsIoctl,
    .stat = embedfsStat,
    .readdir = embedfsReaddir,
    .truncate = embedfsTruncate,
    .chmod = embedfsChmod,
    .chown = embedfsChown,
};

fn embedfsMount(mp: *vfs.MountPoint) vfs.VFSError!void {
    mp.private_data = @ptrCast(@constCast(&root_node));
}

fn embedfsUnmount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn embedfsGetRoot(mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    return createVNode(&root_node, mp);
}

fn embedfsLookup(parent: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const node = getNode(parent);
    if (node.file_type != .Directory) return vfs.VFSError.NotDirectory;
    for (node.children) |child| {
        if (std.mem.eql(u8, child.name, name)) {
            return createVNode(child, parent.mount_point.?);
        }
    }
    return vfs.VFSError.NotFound;
}

fn embedfsCreate(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn embedfsMkdir(_: *vfs.VNode, _: []const u8, _: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    return vfs.VFSError.ReadOnly;
}

fn embedfsUnlink(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn embedfsRmdir(_: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

fn embedfsRename(_: *vfs.VNode, _: []const u8, _: *vfs.VNode, _: []const u8) vfs.VFSError!void {
    return vfs.VFSError.ReadOnly;
}

const embedfs_fs_ops = vfs.FileSystemOps{
    .mount = embedfsMount,
    .unmount = embedfsUnmount,
    .get_root = embedfsGetRoot,
    .lookup = embedfsLookup,
    .create = embedfsCreate,
    .mkdir = embedfsMkdir,
    .unlink = embedfsUnlink,
    .rmdir = embedfsRmdir,
    .rename = embedfsRename,
};

var embedfs_type = vfs.FileSystemType{
    .name = blk: {
        var name = [_]u8{0} ** 32;
        @memcpy(name[0..7], "embedfs");
        break :blk name;
    },
    .ops = &embedfs_fs_ops,
    .next = null,
};

pub fn init() void {
    vfs.registerFileSystem(&embedfs_type) catch {};
}
