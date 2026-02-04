const vfs = @import("vfs.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");
const std = @import("std");

const NODE_POOL_SIZE = 512;
const DEFAULT_CAPACITY = 4096;

const TmpfsNode = struct {
    data: ?[*]u8,
    size: usize,
    capacity: usize,
    node_type: vfs.FileType,
    uid: u16,
    gid: u16,
    mode: u16,
    children: ?*TmpfsNode,
    next_sibling: ?*TmpfsNode,
    name: [256]u8,
    name_len: u16,
    parent: ?*TmpfsNode,
    in_use: bool,
};

var node_pool: [NODE_POOL_SIZE]TmpfsNode = [_]TmpfsNode{TmpfsNode{
    .data = null,
    .size = 0,
    .capacity = 0,
    .node_type = .Regular,
    .uid = 0,
    .gid = 0,
    .mode = 0o755,
    .children = null,
    .next_sibling = null,
    .name = [_]u8{0} ** 256,
    .name_len = 0,
    .parent = null,
    .in_use = false,
}} ** NODE_POOL_SIZE;

var tmpfs_root: ?*TmpfsNode = null;

fn allocNode() ?*TmpfsNode {
    for (&node_pool) |*node| {
        if (!node.in_use) {
            node.in_use = true;
            node.data = null;
            node.size = 0;
            node.capacity = 0;
            node.children = null;
            node.next_sibling = null;
            node.parent = null;
            @memset(&node.name, 0);
            node.name_len = 0;
            return node;
        }
    }
    return null;
}

fn freeNode(node: *TmpfsNode) void {
    if (node.data) |d| {
        memory.kfree(@as(*anyopaque, @ptrCast(d)));
        node.data = null;
    }
    node.in_use = false;
}

fn findChild(parent: *TmpfsNode, name: []const u8) ?*TmpfsNode {
    var child = parent.children;
    while (child) |c| {
        if (c.name_len == name.len and std.mem.eql(u8, c.name[0..c.name_len], name)) {
            return c;
        }
        child = c.next_sibling;
    }
    return null;
}

fn addChild(parent: *TmpfsNode, child: *TmpfsNode) void {
    child.parent = parent;
    child.next_sibling = parent.children;
    parent.children = child;
}

fn removeChild(parent: *TmpfsNode, child: *TmpfsNode) void {
    if (parent.children == child) {
        parent.children = child.next_sibling;
        return;
    }

    var prev = parent.children;
    while (prev) |p| {
        if (p.next_sibling == child) {
            p.next_sibling = child.next_sibling;
            return;
        }
        prev = p.next_sibling;
    }
}

fn nodeToVNode(node: *TmpfsNode, mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(vfs.VNode)) orelse return vfs.VFSError.OutOfMemory;
    const vnode: *vfs.VNode = @ptrCast(@alignCast(vnode_mem));

    vnode.* = vfs.VNode{
        .name = node.name,
        .name_len = node.name_len,
        .inode = @intFromPtr(node),
        .file_type = node.node_type,
        .mode = vfs.FileMode{
            .owner_read = (node.mode & 0o400) != 0,
            .owner_write = (node.mode & 0o200) != 0,
            .owner_exec = (node.mode & 0o100) != 0,
            .group_read = (node.mode & 0o040) != 0,
            .group_write = (node.mode & 0o020) != 0,
            .group_exec = (node.mode & 0o010) != 0,
            .other_read = (node.mode & 0o004) != 0,
            .other_write = (node.mode & 0o002) != 0,
            .other_exec = (node.mode & 0o001) != 0,
        },
        .size = node.size,
        .uid = node.uid,
        .gid = node.gid,
        .ref_count = 1,
        .mount_point = mp,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = &tmpfs_file_ops,
        .private_data = @as(*anyopaque, @ptrCast(node)),
    };

    return vnode;
}

fn getNodeFromVNode(vnode: *vfs.VNode) ?*TmpfsNode {
    if (vnode.private_data) |pd| {
        return @as(*TmpfsNode, @ptrCast(@alignCast(pd)));
    }
    return null;
}

fn tmpfsRead(vnode: *vfs.VNode, buffer: []u8, offset: u64) vfs.VFSError!usize {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    if (node.node_type != .Regular) return vfs.VFSError.IsDirectory;

    if (offset >= node.size) return 0;
    const available = node.size - @as(usize, @intCast(offset));
    const to_read = @min(buffer.len, available);

    if (node.data) |d| {
        @memcpy(buffer[0..to_read], d[@intCast(offset)..@as(usize, @intCast(offset)) + to_read]);
    }

    return to_read;
}

fn tmpfsWrite(vnode: *vfs.VNode, buffer: []const u8, offset: u64) vfs.VFSError!usize {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    if (node.node_type != .Regular) return vfs.VFSError.IsDirectory;

    const off: usize = @intCast(offset);
    const needed = off + buffer.len;

    if (needed > node.capacity) {
        const new_capacity = @max(needed, node.capacity * 2);
        const new_data = memory.krealloc(if (node.data) |d| @as(*anyopaque, @ptrCast(d)) else null, new_capacity);
        if (new_data) |nd| {
            node.data = @as([*]u8, @ptrCast(@alignCast(nd)));
            node.capacity = new_capacity;
        } else {
            return vfs.VFSError.NoSpace;
        }
    }

    if (node.data) |d| {
        @memcpy(d[off .. off + buffer.len], buffer);
    }

    if (needed > node.size) {
        node.size = needed;
        vnode.size = needed;
    }

    return buffer.len;
}

fn tmpfsOpen(_: *vfs.VNode, _: u32) vfs.VFSError!void {}

fn tmpfsClose(_: *vfs.VNode) vfs.VFSError!void {}

fn tmpfsSeek(vnode: *vfs.VNode, offset: i64, whence: u32) vfs.VFSError!u64 {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    // SAFETY: assigned in every branch of the switch
    var new_offset: i64 = undefined;

    switch (whence) {
        vfs.SEEK_SET => new_offset = offset,
        vfs.SEEK_END => new_offset = @as(i64, @intCast(node.size)) + offset,
        else => return vfs.VFSError.InvalidOperation,
    }

    if (new_offset < 0) return vfs.VFSError.InvalidOperation;
    return @intCast(new_offset);
}

fn tmpfsIoctl(_: *vfs.VNode, _: u32, _: usize) vfs.VFSError!i32 {
    return vfs.VFSError.InvalidOperation;
}

fn tmpfsStat(vnode: *vfs.VNode, stat_buf: *vfs.FileStat) vfs.VFSError!void {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    stat_buf.* = vfs.FileStat{
        .inode = @intFromPtr(node),
        .mode = vnode.mode,
        .file_type = node.node_type,
        .size = node.size,
        .blocks = (node.size + 511) / 512,
        .block_size = 4096,
        .uid = node.uid,
        .gid = node.gid,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}

fn tmpfsReaddir(vnode: *vfs.VNode, dirent: *vfs.DirEntry, index: u64) vfs.VFSError!bool {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    if (node.node_type != .Directory) return vfs.VFSError.NotDirectory;

    var child = node.children;
    var i: u64 = 0;
    while (child) |c| {
        if (i == index) {
            dirent.name = c.name;
            dirent.name_len = c.name_len;
            dirent.inode = @intFromPtr(c);
            dirent.file_type = c.node_type;
            return true;
        }
        i += 1;
        child = c.next_sibling;
    }
    return false;
}

fn tmpfsTruncate(vnode: *vfs.VNode, size: u64) vfs.VFSError!void {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    const new_size: usize = @intCast(size);

    if (new_size > node.capacity) {
        const new_data = memory.krealloc(if (node.data) |d| @as(*anyopaque, @ptrCast(d)) else null, new_size);
        if (new_data) |nd| {
            node.data = @as([*]u8, @ptrCast(@alignCast(nd)));
            node.capacity = new_size;
        } else {
            return vfs.VFSError.NoSpace;
        }
    }

    if (new_size > node.size) {
        if (node.data) |d| {
            @memset(d[node.size..new_size], 0);
        }
    }

    node.size = new_size;
    vnode.size = new_size;
}

fn tmpfsChmod(vnode: *vfs.VNode, mode: vfs.FileMode) vfs.VFSError!void {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    var m: u16 = 0;
    if (mode.owner_read) m |= 0o400;
    if (mode.owner_write) m |= 0o200;
    if (mode.owner_exec) m |= 0o100;
    if (mode.group_read) m |= 0o040;
    if (mode.group_write) m |= 0o020;
    if (mode.group_exec) m |= 0o010;
    if (mode.other_read) m |= 0o004;
    if (mode.other_write) m |= 0o002;
    if (mode.other_exec) m |= 0o001;
    node.mode = m;
    vnode.mode = mode;
}

fn tmpfsChown(vnode: *vfs.VNode, uid: u32, gid: u32) vfs.VFSError!void {
    const node = getNodeFromVNode(vnode) orelse return vfs.VFSError.InvalidOperation;
    node.uid = @intCast(uid);
    node.gid = @intCast(gid);
    vnode.uid = @intCast(uid);
    vnode.gid = @intCast(gid);
}

const tmpfs_file_ops = vfs.FileOps{
    .read = tmpfsRead,
    .write = tmpfsWrite,
    .open = tmpfsOpen,
    .close = tmpfsClose,
    .seek = tmpfsSeek,
    .ioctl = tmpfsIoctl,
    .stat = tmpfsStat,
    .readdir = tmpfsReaddir,
    .truncate = tmpfsTruncate,
    .chmod = tmpfsChmod,
    .chown = tmpfsChown,
};

fn tmpfsMount(mp: *vfs.MountPoint) vfs.VFSError!void {
    const root = allocNode() orelse return vfs.VFSError.OutOfMemory;
    root.node_type = .Directory;
    root.mode = 0o1777;
    root.uid = 0;
    root.gid = 0;
    root.name[0] = '/';
    root.name_len = 1;

    tmpfs_root = root;
    mp.private_data = @as(*anyopaque, @ptrCast(root));
}

fn tmpfsUnmount(_: *vfs.MountPoint) vfs.VFSError!void {}

fn tmpfsGetRoot(mp: *vfs.MountPoint) vfs.VFSError!*vfs.VNode {
    if (mp.private_data) |pd| {
        const root: *TmpfsNode = @ptrCast(@alignCast(pd));
        return nodeToVNode(root, mp);
    }
    return vfs.VFSError.NotFound;
}

fn tmpfsLookup(parent_vnode: *vfs.VNode, name: []const u8) vfs.VFSError!*vfs.VNode {
    const parent_node = getNodeFromVNode(parent_vnode) orelse return vfs.VFSError.NotFound;
    const child = findChild(parent_node, name) orelse return vfs.VFSError.NotFound;
    return nodeToVNode(child, parent_vnode.mount_point.?);
}

fn tmpfsCreate(parent_vnode: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    const parent_node = getNodeFromVNode(parent_vnode) orelse return vfs.VFSError.InvalidOperation;

    if (findChild(parent_node, name) != null) return vfs.VFSError.AlreadyExists;

    const node = allocNode() orelse return vfs.VFSError.OutOfMemory;
    node.node_type = .Regular;

    var m: u16 = 0;
    if (mode.owner_read) m |= 0o400;
    if (mode.owner_write) m |= 0o200;
    if (mode.owner_exec) m |= 0o100;
    if (mode.group_read) m |= 0o040;
    if (mode.group_write) m |= 0o020;
    if (mode.group_exec) m |= 0o010;
    if (mode.other_read) m |= 0o004;
    if (mode.other_write) m |= 0o002;
    if (mode.other_exec) m |= 0o001;
    node.mode = m;

    const len = @min(name.len, node.name.len - 1);
    @memcpy(node.name[0..len], name[0..len]);
    node.name_len = @intCast(len);

    const initial_buf = memory.kmalloc(DEFAULT_CAPACITY) orelse {
        freeNode(node);
        return vfs.VFSError.OutOfMemory;
    };
    node.data = @as([*]u8, @ptrCast(@alignCast(initial_buf)));
    node.capacity = DEFAULT_CAPACITY;

    addChild(parent_node, node);
    return nodeToVNode(node, parent_vnode.mount_point.?);
}

fn tmpfsMkdir(parent_vnode: *vfs.VNode, name: []const u8, mode: vfs.FileMode) vfs.VFSError!*vfs.VNode {
    const parent_node = getNodeFromVNode(parent_vnode) orelse return vfs.VFSError.InvalidOperation;

    if (findChild(parent_node, name) != null) return vfs.VFSError.AlreadyExists;

    const node = allocNode() orelse return vfs.VFSError.OutOfMemory;
    node.node_type = .Directory;

    var m: u16 = 0;
    if (mode.owner_read) m |= 0o400;
    if (mode.owner_write) m |= 0o200;
    if (mode.owner_exec) m |= 0o100;
    if (mode.group_read) m |= 0o040;
    if (mode.group_write) m |= 0o020;
    if (mode.group_exec) m |= 0o010;
    if (mode.other_read) m |= 0o004;
    if (mode.other_write) m |= 0o002;
    if (mode.other_exec) m |= 0o001;
    node.mode = m;

    const len = @min(name.len, node.name.len - 1);
    @memcpy(node.name[0..len], name[0..len]);
    node.name_len = @intCast(len);

    addChild(parent_node, node);
    return nodeToVNode(node, parent_vnode.mount_point.?);
}

fn tmpfsUnlink(parent_vnode: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_node = getNodeFromVNode(parent_vnode) orelse return vfs.VFSError.InvalidOperation;
    const child = findChild(parent_node, name) orelse return vfs.VFSError.NotFound;

    if (child.node_type == .Directory) return vfs.VFSError.IsDirectory;

    removeChild(parent_node, child);
    freeNode(child);
}

fn tmpfsRmdir(parent_vnode: *vfs.VNode, name: []const u8) vfs.VFSError!void {
    const parent_node = getNodeFromVNode(parent_vnode) orelse return vfs.VFSError.InvalidOperation;
    const child = findChild(parent_node, name) orelse return vfs.VFSError.NotFound;

    if (child.node_type != .Directory) return vfs.VFSError.NotDirectory;
    if (child.children != null) return vfs.VFSError.InvalidOperation;

    removeChild(parent_node, child);
    freeNode(child);
}

fn tmpfsRename(old_parent_vnode: *vfs.VNode, old_name: []const u8, new_parent_vnode: *vfs.VNode, new_name: []const u8) vfs.VFSError!void {
    const old_parent = getNodeFromVNode(old_parent_vnode) orelse return vfs.VFSError.InvalidOperation;
    const new_parent = getNodeFromVNode(new_parent_vnode) orelse return vfs.VFSError.InvalidOperation;
    const node = findChild(old_parent, old_name) orelse return vfs.VFSError.NotFound;

    removeChild(old_parent, node);

    @memset(&node.name, 0);
    const len = @min(new_name.len, node.name.len - 1);
    @memcpy(node.name[0..len], new_name[0..len]);
    node.name_len = @intCast(len);

    addChild(new_parent, node);
}

const tmpfs_fs_ops = vfs.FileSystemOps{
    .mount = tmpfsMount,
    .unmount = tmpfsUnmount,
    .get_root = tmpfsGetRoot,
    .lookup = tmpfsLookup,
    .create = tmpfsCreate,
    .mkdir = tmpfsMkdir,
    .unlink = tmpfsUnlink,
    .rmdir = tmpfsRmdir,
    .rename = tmpfsRename,
};

var tmpfs_type = vfs.FileSystemType{
    .name = blk: {
        var name = [_]u8{0} ** 32;
        name[0] = 't';
        name[1] = 'm';
        name[2] = 'p';
        name[3] = 'f';
        name[4] = 's';
        break :blk name;
    },
    .ops = &tmpfs_fs_ops,
    .next = null,
};

pub fn init() void {
    vfs.registerFileSystem(&tmpfs_type) catch {
        vga.print("Failed to register tmpfs\n");
        return;
    };
    vga.print("tmpfs filesystem registered\n");
}
