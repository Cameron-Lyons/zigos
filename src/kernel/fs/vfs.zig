const std = @import("std");
const memory = @import("../memory/memory.zig");
const abi = @import("../process/syscall/abi.zig");
const readiness = @import("../process/syscall/readiness.zig");
const error_handler = @import("../utils/error.zig");

pub const VFSError = error{
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    InvalidPath,
    AlreadyExists,
    NoSpace,
    ReadOnly,
    InvalidOperation,
    OutOfMemory,
    DeviceError,
    BrokenPipe,
    TooManyOpenFiles,
};

pub const FileType = enum(u8) {
    Regular = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Pipe = 5,
    SymLink = 6,
    Socket = 7,
};

pub const FileMode = packed struct {
    owner_read: bool = false,
    owner_write: bool = false,
    owner_exec: bool = false,

    group_read: bool = false,
    group_write: bool = false,
    group_exec: bool = false,

    other_read: bool = false,
    other_write: bool = false,
    other_exec: bool = false,

    set_uid: bool = false,
    set_gid: bool = false,
    sticky: bool = false,

    _padding: u4 = 0,
};

pub const FileStat = struct {
    inode: u64,
    mode: FileMode,
    file_type: FileType,
    size: u64,
    blocks: u64,
    block_size: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
};

pub const DirEntry = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
};

pub const FileOps = struct {
    read: *const fn (*VNode, []u8, u64) VFSError!usize,
    write: *const fn (*VNode, []const u8, u64) VFSError!usize,
    open: *const fn (*VNode, u32) VFSError!void,
    close: *const fn (*VNode) VFSError!void,
    seek: *const fn (*VNode, i64, u32) VFSError!u64,
    ioctl: *const fn (*VNode, u32, usize) VFSError!i32,
    stat: *const fn (*VNode, *FileStat) VFSError!void,
    readdir: *const fn (*VNode, *DirEntry, u64) VFSError!bool,
    truncate: *const fn (*VNode, u64) VFSError!void,
    chmod: *const fn (*VNode, FileMode) VFSError!void,
    chown: *const fn (*VNode, u32, u32) VFSError!void,
};

pub const VNode = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
    mode: FileMode,
    size: u64,
    uid: u16 = 0,
    gid: u16 = 0,
    ref_count: u32,
    mount_point: ?*MountPoint,
    parent: ?*VNode,
    children: ?*VNode,
    next_sibling: ?*VNode,
    ops: *const FileOps,
    private_data: ?*anyopaque,
};

pub const FileSystemOps = struct {
    mount: *const fn (*MountPoint) VFSError!void,
    unmount: *const fn (*MountPoint) VFSError!void,
    get_root: *const fn (*MountPoint) VFSError!*VNode,
    lookup: *const fn (*VNode, []const u8) VFSError!*VNode,
    create: *const fn (*VNode, []const u8, FileMode) VFSError!*VNode,
    mkdir: *const fn (*VNode, []const u8, FileMode) VFSError!*VNode,
    unlink: *const fn (*VNode, []const u8) VFSError!void,
    rmdir: *const fn (*VNode, []const u8) VFSError!void,
    rename: *const fn (*VNode, []const u8, *VNode, []const u8) VFSError!void,
    symlink: ?*const fn (*VNode, []const u8, []const u8) VFSError!*VNode = null,
    link: ?*const fn (*VNode, []const u8, *VNode) VFSError!void = null,
    readlink: ?*const fn (*VNode, []u8) VFSError!usize = null,
};

pub const FileSystemType = struct {
    name: [32]u8,
    ops: *const FileSystemOps,
    next: ?*FileSystemType,
};

pub const MountPoint = struct {
    device: [256]u8,
    mount_path: [256]u8,
    fs_type: *FileSystemType,
    root: ?*VNode,
    flags: u32,
    private_data: ?*anyopaque,
    next: ?*MountPoint,
};

pub const FileDescriptor = struct {
    vnode: *VNode,
    offset: u64,
    flags: u32,
    fd_flags: u32,
    ref_count: u32,
    path_len: u16,
    path: [512]u8,
};

pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;
pub const O_NONBLOCK: u32 = 0x0800;

const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

var root_vnode: ?*VNode = null;
var mount_list: ?*MountPoint = null;
var fs_type_list: ?*FileSystemType = null;
var vnode_cache: [1024]?*VNode = [_]?*VNode{null} ** 1024;
var fd_table: [256]?*FileDescriptor = [_]?*FileDescriptor{null} ** 256;
var vfs_meta_lock: u32 = 0;
var inotify_notifier: ?*const fn ([]const u8, u32, u32) void = null;

const FD_TABLE_SIZE = 256;
var fd_freelist: [FD_TABLE_SIZE]u8 = undefined;
var fd_freelist_top: usize = 0;

fn lockMeta() void {
    while (@cmpxchgWeak(u32, &vfs_meta_lock, 0, 1, .acquire, .monotonic) != null) {
        while (@atomicLoad(u32, &vfs_meta_lock, .monotonic) != 0) {
            asm volatile ("pause");
        }
    }
}

fn unlockMeta() void {
    @atomicStore(u32, &vfs_meta_lock, 0, .release);
}

fn initFdFreelist() void {
    for (0..FD_TABLE_SIZE) |i| {
        fd_freelist[i] = @intCast(FD_TABLE_SIZE - 1 - i);
    }
    fd_freelist_top = FD_TABLE_SIZE;
}

fn allocFd() ?u32 {
    lockMeta();
    defer unlockMeta();
    if (fd_freelist_top == 0) return null;
    fd_freelist_top -= 1;
    return fd_freelist[fd_freelist_top];
}

fn freeFd(fd: u32) void {
    lockMeta();
    defer unlockMeta();
    if (fd >= FD_TABLE_SIZE) return;
    if (fd_freelist_top >= FD_TABLE_SIZE) return;
    fd_freelist[fd_freelist_top] = @intCast(fd);
    fd_freelist_top += 1;
}

pub fn init() void {
    lockMeta();
    defer unlockMeta();

    initFdFreelist();
    root_vnode = createVNode() catch |err| {
        error_handler.handleError(err, "Failed to create root vnode");
        return;
    };

    if (root_vnode) |root| {
        root.name[0] = '/';
        root.name[1] = 0;
        root.name_len = 1;
        root.file_type = FileType.Directory;
        root.mode = FileMode{
            .owner_read = true,
            .owner_write = true,
            .owner_exec = true,
            .group_read = true,
            .group_exec = true,
            .other_read = true,
            .other_exec = true,
        };
    }
}

pub fn registerInotifyNotifier(callback: *const fn ([]const u8, u32, u32) void) void {
    inotify_notifier = callback;
}

pub fn registerFileSystem(fs_type: *FileSystemType) VFSError!void {
    lockMeta();
    defer unlockMeta();
    fs_type.next = fs_type_list;
    fs_type_list = fs_type;
}

pub fn mount(device: []const u8, mount_path: []const u8, fs_name: []const u8, flags: u32) VFSError!void {
    lockMeta();
    var fs_type = fs_type_list;
    while (fs_type) |fs| : (fs_type = fs.next) {
        if (std.mem.eql(u8, fs.name[0..strlen(&fs.name)], fs_name)) {
            unlockMeta();
            const mp = memory.kmalloc(@sizeOf(MountPoint)) orelse return VFSError.OutOfMemory;
            errdefer memory.kfree(@as([*]u8, @ptrCast(mp)));

            const mount_point: *MountPoint = @ptrCast(@alignCast(mp));

            if (device.len >= 256 or mount_path.len >= 256) return VFSError.InvalidPath;
            @memcpy(mount_point.device[0..device.len], device);
            mount_point.device[device.len] = 0;
            @memcpy(mount_point.mount_path[0..mount_path.len], mount_path);
            mount_point.mount_path[mount_path.len] = 0;
            mount_point.fs_type = fs;
            mount_point.flags = flags;
            mount_point.private_data = null;

            try fs.ops.mount(mount_point);

            mount_point.root = try fs.ops.get_root(mount_point);

            lockMeta();
            mount_point.next = mount_list;
            mount_list = mount_point;
            unlockMeta();

            return;
        }
    }
    unlockMeta();

    return VFSError.InvalidOperation;
}

pub fn unmount(mount_path: []const u8) VFSError!void {
    lockMeta();
    var prev: ?*MountPoint = null;
    var current = mount_list;

    while (current) |mp| {
        const mp_path = mp.mount_path[0..strlen(&mp.mount_path)];
        if (std.mem.eql(u8, mp_path, mount_path)) {
            if (prev) |p| {
                p.next = mp.next;
            } else {
                mount_list = mp.next;
            }
            unlockMeta();

            mp.fs_type.ops.unmount(mp) catch {};
            memory.kfree(@as([*]u8, @ptrCast(mp)));
            return;
        }
        prev = mp;
        current = mp.next;
    }
    unlockMeta();

    return VFSError.NotFound;
}

pub fn open(path: []const u8, flags: u32) VFSError!u32 {
    var created = false;
    const vnode = blk: {
        if (lookupPath(path)) |v| {
            if ((flags & O_CREAT) != 0 and (flags & O_EXCL) != 0) {
                return VFSError.AlreadyExists;
            }
            break :blk v;
        } else |err| {
            if (err == VFSError.NotFound and (flags & O_CREAT) != 0) {
                const parts = splitPath(path);
                const parent = try lookupPath(parts.parent);
                if (parent.file_type != FileType.Directory) {
                    return VFSError.NotDirectory;
                }

                const default_mode = FileMode{
                    .owner_read = true,
                    .owner_write = true,
                    .group_read = true,
                    .other_read = true,
                };

                created = true;
                break :blk try parent.mount_point.?.fs_type.ops.create(parent, parts.name, default_mode);
            } else {
                return err;
            }
        }
    };

    if (vnode.file_type == FileType.Directory and ((flags & O_WRONLY) != 0 or (flags & O_RDWR) != 0)) {
        return VFSError.IsDirectory;
    }

    var truncated = false;
    if ((flags & O_TRUNC) != 0 and vnode.file_type == FileType.Regular) {
        if (vnode.ops.truncate(vnode, 0)) |_| {
            truncated = true;
        } else |_| {}
    }

    try vnode.ops.open(vnode, flags);
    errdefer vnode.ops.close(vnode) catch {};

    const i = allocFd() orelse return VFSError.TooManyOpenFiles;
    errdefer freeFd(i);

    const fd_mem = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    const fd: *FileDescriptor = @ptrCast(@alignCast(fd_mem));

    fd.vnode = vnode;
    fd.offset = if ((flags & O_APPEND) != 0) vnode.size else 0;
    fd.flags = flags;
    fd.fd_flags = 0;
    fd.ref_count = 1;
    fd.path_len = @intCast(@min(path.len, fd.path.len));
    @memset(&fd.path, 0);
    @memcpy(fd.path[0..fd.path_len], path[0..fd.path_len]);

    lockMeta();
    fd_table[i] = fd;
    vnode.ref_count += 1;
    unlockMeta();

    if (created) notifyPathEvent(path, abi.IN_CREATE, abi.IN_CREATE);
    if (truncated) notifyPathEvent(path, abi.IN_MODIFY, abi.IN_MODIFY);
    notifyPathEvent(path, abi.IN_OPEN, abi.IN_OPEN);

    return i;
}

pub fn close(fd: u32) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    lockMeta();
    const file_desc = fd_table[fd] orelse {
        unlockMeta();
        return VFSError.InvalidOperation;
    };
    file_desc.ref_count -= 1;
    if (file_desc.ref_count > 0) {
        unlockMeta();
        return;
    }
    fd_table[fd] = null;
    unlockMeta();

    if (file_desc.vnode.file_type == .Pipe) {
        if (file_desc.vnode.private_data) |pd| {
            const pipe: *PipeData = @ptrCast(@alignCast(pd));
            if ((file_desc.flags & O_WRONLY) != 0) {
                if (pipe.writers > 0) pipe.writers -= 1;
            } else {
                if (pipe.readers > 0) pipe.readers -= 1;
            }
            if (pipe.readers == 0 and pipe.writers == 0) {
                memory.kfree(@as([*]u8, @ptrCast(@alignCast(pd))));
                file_desc.vnode.private_data = null;
            }
        }
    }
    const vnode = file_desc.vnode;
    try vnode.ops.close(vnode);
    lockMeta();
    vnode.ref_count -= 1;
    const free_pipe_vnode = vnode.ref_count == 0 and vnode.file_type == .Pipe;
    unlockMeta();

    if (free_pipe_vnode) {
        memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));
    }
    notifyCloseEvent(file_desc);
    memory.kfree(@as([*]u8, @ptrCast(file_desc)));
    freeFd(fd);
    readiness.notifyVfs();
}

pub fn read(fd: u32, buffer: []u8) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) != 0) {
            return VFSError.PermissionDenied;
        }

        const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, file_desc.offset);
        file_desc.offset += bytes_read;
        if (bytes_read > 0) notifyDescriptorEvent(file_desc, abi.IN_ACCESS, abi.IN_ACCESS);
        return bytes_read;
    }

    return VFSError.InvalidOperation;
}

pub fn write(fd: u32, buffer: []const u8) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
            return VFSError.PermissionDenied;
        }

        if ((file_desc.flags & O_APPEND) != 0) {
            file_desc.offset = file_desc.vnode.size;
        }

        const bytes_written = try file_desc.vnode.ops.write(file_desc.vnode, buffer, file_desc.offset);
        file_desc.offset += bytes_written;
        if (bytes_written > 0) notifyDescriptorEvent(file_desc, abi.IN_MODIFY, abi.IN_MODIFY);
        return bytes_written;
    }

    return VFSError.InvalidOperation;
}

pub fn ioctl(fd: u32, request: u32, arg: usize) VFSError!i32 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        return file_desc.vnode.ops.ioctl(file_desc.vnode, request, arg);
    }

    return VFSError.InvalidOperation;
}

pub fn lseek(fd: u32, offset: i64, whence: u32) VFSError!u64 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if (whence == SEEK_CUR) {
            const cur: i64 = @intCast(file_desc.offset);
            const new_offset = try file_desc.vnode.ops.seek(file_desc.vnode, cur + offset, SEEK_SET);
            file_desc.offset = new_offset;
            return new_offset;
        }
        const new_offset = try file_desc.vnode.ops.seek(file_desc.vnode, offset, whence);
        file_desc.offset = new_offset;
        return new_offset;
    }

    return VFSError.InvalidOperation;
}

pub fn pread(fd: u32, buffer: []u8, offset: u64) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) != 0) {
            return VFSError.PermissionDenied;
        }
        const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, offset);
        if (bytes_read > 0) notifyDescriptorEvent(file_desc, abi.IN_ACCESS, abi.IN_ACCESS);
        return bytes_read;
    }

    return VFSError.InvalidOperation;
}

pub fn pwrite(fd: u32, buffer: []const u8, offset: u64) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
            return VFSError.PermissionDenied;
        }
        const bytes_written = try file_desc.vnode.ops.write(file_desc.vnode, buffer, offset);
        if (bytes_written > 0) notifyDescriptorEvent(file_desc, abi.IN_MODIFY, abi.IN_MODIFY);
        return bytes_written;
    }

    return VFSError.InvalidOperation;
}

pub fn getFileFlags(fd: u32) VFSError!u32 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    if (fd_table[fd]) |file_desc| {
        return file_desc.flags;
    }
    return VFSError.InvalidOperation;
}

pub fn pollFd(fd: u32, requested_events: u16) VFSError!u16 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        return pollDescriptor(file_desc, requested_events);
    }

    return VFSError.InvalidOperation;
}

pub fn setFileFlags(fd: u32, flags: u32) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    if (fd_table[fd]) |file_desc| {
        const changeable = O_APPEND | O_NONBLOCK;
        file_desc.flags = (file_desc.flags & ~changeable) | (flags & changeable);
        return;
    }
    return VFSError.InvalidOperation;
}

pub fn getFdFlags(fd: u32) VFSError!u32 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    if (fd_table[fd]) |file_desc| {
        return file_desc.fd_flags;
    }
    return VFSError.InvalidOperation;
}

pub fn setFdFlags(fd: u32, flags: u32) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    if (fd_table[fd]) |file_desc| {
        file_desc.fd_flags = flags;
        return;
    }
    return VFSError.InvalidOperation;
}

pub fn getVNodeFromFd(fd: u32) VFSError!*VNode {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    if (fd_table[fd]) |file_desc| {
        return file_desc.vnode;
    }
    return VFSError.InvalidOperation;
}

var path_buffer: [512]u8 = undefined;

pub fn getNodePath(vnode: *VNode) VFSError![]const u8 {
    var components: [32]*VNode = undefined;
    var depth: usize = 0;

    var current: ?*VNode = vnode;
    while (current) |node| : (current = node.parent) {
        if (depth >= components.len) return VFSError.InvalidPath;
        components[depth] = node;
        depth += 1;
    }

    if (depth == 0) return VFSError.InvalidPath;

    var pos: usize = 0;

    var i: usize = depth;
    while (i > 0) {
        i -= 1;
        const node = components[i];
        if (node.name_len > 0 and !(node.name_len == 1 and node.name[0] == '/')) {
            path_buffer[pos] = '/';
            pos += 1;
            const name_len = node.name_len;
            if (pos + name_len > path_buffer.len) return VFSError.InvalidPath;
            @memcpy(path_buffer[pos .. pos + name_len], node.name[0..name_len]);
            pos += name_len;
        }
    }

    if (pos == 0) {
        path_buffer[0] = '/';
        pos = 1;
    }

    const mount_point = vnode.mount_point orelse return path_buffer[0..pos];
    const mount_path = mount_point.mount_path[0..strlen(&mount_point.mount_path)];
    if (mount_path.len == 0 or (mount_path.len == 1 and mount_path[0] == '/')) {
        return path_buffer[0..pos];
    }

    if (pos == 1 and path_buffer[0] == '/') {
        if (mount_path.len > path_buffer.len) return VFSError.InvalidPath;
        @memcpy(path_buffer[0..mount_path.len], mount_path);
        return path_buffer[0..mount_path.len];
    }

    var relative_path: [512]u8 = undefined;
    if (pos > relative_path.len or mount_path.len + pos > path_buffer.len) {
        return VFSError.InvalidPath;
    }

    @memcpy(relative_path[0..pos], path_buffer[0..pos]);
    @memcpy(path_buffer[0..mount_path.len], mount_path);
    @memcpy(path_buffer[mount_path.len .. mount_path.len + pos], relative_path[0..pos]);
    return path_buffer[0 .. mount_path.len + pos];
}

pub fn openVNode(vnode: *VNode, flags: u32) VFSError!void {
    if ((flags & O_TRUNC) != 0 and vnode.file_type == FileType.Regular) {
        try truncateVNode(vnode, 0);
    }
    try vnode.ops.open(vnode, flags);
    notifyVNodeEvent(vnode, abi.IN_OPEN, abi.IN_OPEN);
}

pub fn closeVNode(vnode: *VNode, flags: u32) VFSError!void {
    try vnode.ops.close(vnode);
    const writable = (flags & O_WRONLY) != 0 or (flags & O_RDWR) != 0;
    const mask = if (writable) abi.IN_CLOSE_WRITE else abi.IN_CLOSE_NOWRITE;
    notifyVNodeEvent(vnode, mask, mask);
}

pub fn readVNode(vnode: *VNode, buffer: []u8, offset: u64) VFSError!usize {
    const bytes_read = try vnode.ops.read(vnode, buffer, offset);
    if (bytes_read > 0) notifyVNodeEvent(vnode, abi.IN_ACCESS, abi.IN_ACCESS);
    return bytes_read;
}

pub fn writeVNode(vnode: *VNode, buffer: []const u8, offset: u64) VFSError!usize {
    const bytes_written = try vnode.ops.write(vnode, buffer, offset);
    if (bytes_written > 0) notifyVNodeEvent(vnode, abi.IN_MODIFY, abi.IN_MODIFY);
    return bytes_written;
}

pub fn truncateVNode(vnode: *VNode, size: u64) VFSError!void {
    try vnode.ops.truncate(vnode, size);
    notifyVNodeEvent(vnode, abi.IN_MODIFY, abi.IN_MODIFY);
}

pub fn chmodVNode(vnode: *VNode, mode: FileMode) VFSError!void {
    try vnode.ops.chmod(vnode, mode);
    notifyVNodeEvent(vnode, abi.IN_ATTRIB, abi.IN_ATTRIB);
}

pub fn chownVNode(vnode: *VNode, uid: u32, gid: u32) VFSError!void {
    try vnode.ops.chown(vnode, uid, gid);
    notifyVNodeEvent(vnode, abi.IN_ATTRIB, abi.IN_ATTRIB);
}

pub fn stat(path: []const u8, stat_buf: *FileStat) VFSError!void {
    const vnode = try lookupPath(path);
    try vnode.ops.stat(vnode, stat_buf);
}

pub fn fstat(fd: u32, stat_buf: *FileStat) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        try file_desc.vnode.ops.stat(file_desc.vnode, stat_buf);
    } else {
        return VFSError.InvalidOperation;
    }
}

pub fn readdir(fd: u32, dirent: *DirEntry, index: u64) VFSError!bool {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        return file_desc.vnode.ops.readdir(file_desc.vnode, dirent, index);
    }

    return VFSError.InvalidOperation;
}

pub fn readdirNext(fd: u32, dirent: *DirEntry) VFSError!bool {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        const has_entry = try file_desc.vnode.ops.readdir(file_desc.vnode, dirent, file_desc.offset);
        if (has_entry) {
            file_desc.offset += 1;
        }
        return has_entry;
    }

    return VFSError.InvalidOperation;
}

pub fn mkdir(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    _ = try parent.mount_point.?.fs_type.ops.mkdir(parent, parts.name, mode);
}

pub fn create(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    _ = try parent.mount_point.?.fs_type.ops.create(parent, parts.name, mode);
}

pub fn unlink(path: []const u8) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    try parent.mount_point.?.fs_type.ops.unlink(parent, parts.name);
}

pub fn rmdir(path: []const u8) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    try parent.mount_point.?.fs_type.ops.rmdir(parent, parts.name);
}

pub fn mkfifo(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);

    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }

    _ = parent.mount_point.?.fs_type.ops.lookup(parent, parts.name) catch |err| {
        if (err != VFSError.NotFound) return err;

        const vnode = try createVNode();
        errdefer memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));

        const name_len = @min(parts.name.len, vnode.name.len - 1);
        @memcpy(vnode.name[0..name_len], parts.name[0..name_len]);
        vnode.name[name_len] = 0;
        vnode.name_len = @intCast(name_len);
        vnode.file_type = .Pipe;
        vnode.mode = mode;
        vnode.ops = &pipe_ops;
        vnode.parent = parent;
        vnode.mount_point = parent.mount_point;

        const pipe_mem = memory.kmalloc(@sizeOf(PipeData)) orelse return VFSError.OutOfMemory;
        const pipe_data: *PipeData = @ptrCast(@alignCast(pipe_mem));
        pipe_data.* = PipeData{
            .buffer = [_]u8{0} ** PIPE_BUF_SIZE,
            .read_pos = 0,
            .write_pos = 0,
            .count = 0,
            .readers = 0,
            .writers = 0,
        };
        vnode.private_data = pipe_mem;

        vnode.next_sibling = parent.children;
        parent.children = vnode;
        return;
    };

    return VFSError.AlreadyExists;
}

pub fn truncate(path: []const u8, size: u64) VFSError!void {
    const vnode = try lookupPath(path);
    if (vnode.file_type == FileType.Directory) {
        return VFSError.IsDirectory;
    }
    try vnode.ops.truncate(vnode, size);
}

pub fn symlink(target: []const u8, linkpath: []const u8) VFSError!void {
    const parts = splitPath(linkpath);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }

    if (parent.mount_point) |mp| {
        if (mp.fs_type.ops.symlink) |symlink_fn| {
            _ = try symlink_fn(parent, parts.name, target);
            return;
        }
    }

    return VFSError.InvalidOperation;
}

pub fn link(target_path: []const u8, linkpath: []const u8) VFSError!void {
    const target = try lookupPath(target_path);
    if (target.file_type == FileType.Directory) {
        return VFSError.IsDirectory;
    }

    const parts = splitPath(linkpath);
    const parent = try lookupPath(parts.parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }

    if (parent.mount_point) |mp| {
        if (mp.fs_type.ops.link) |link_fn| {
            try link_fn(parent, parts.name, target);
            return;
        }
    }

    return VFSError.InvalidOperation;
}

pub fn readlink(path: []const u8, buffer: []u8) VFSError!usize {
    const vnode = try lookupPath(path);
    if (vnode.file_type != FileType.SymLink) {
        return VFSError.InvalidOperation;
    }

    if (vnode.mount_point) |mp| {
        if (mp.fs_type.ops.readlink) |readlink_fn| {
            return try readlink_fn(vnode, buffer);
        }
    }

    return VFSError.InvalidOperation;
}

pub fn ftruncate(fd: u32, size: u64) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
            return VFSError.PermissionDenied;
        }
        try file_desc.vnode.ops.truncate(file_desc.vnode, size);
        notifyDescriptorEvent(file_desc, abi.IN_MODIFY, abi.IN_MODIFY);
    } else {
        return VFSError.InvalidOperation;
    }
}

pub fn chmod(path: []const u8, mode: FileMode) VFSError!void {
    const vnode = try lookupPath(path);
    try vnode.ops.chmod(vnode, mode);
}

pub fn fchmod(fd: u32, mode: FileMode) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        try file_desc.vnode.ops.chmod(file_desc.vnode, mode);
        notifyDescriptorEvent(file_desc, abi.IN_ATTRIB, abi.IN_ATTRIB);
    } else {
        return VFSError.InvalidOperation;
    }
}

pub fn chown(path: []const u8, uid: u32, gid: u32) VFSError!void {
    const vnode = try lookupPath(path);
    try vnode.ops.chown(vnode, uid, gid);
}

pub fn fchown(fd: u32, uid: u32, gid: u32) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;

    if (fd_table[fd]) |file_desc| {
        try file_desc.vnode.ops.chown(file_desc.vnode, uid, gid);
        notifyDescriptorEvent(file_desc, abi.IN_ATTRIB, abi.IN_ATTRIB);
    } else {
        return VFSError.InvalidOperation;
    }
}

const PIPE_BUF_SIZE = 4096;
const PIPE_BUF_MASK = PIPE_BUF_SIZE - 1;

fn pollDescriptor(file_desc: *const FileDescriptor, requested_events: u16) u16 {
    var ready: u16 = 0;

    if (file_desc.vnode.file_type == .Pipe) {
        const pipe: *const PipeData = @ptrCast(@alignCast(file_desc.vnode.private_data orelse return 0));

        if ((requested_events & POLLIN) != 0 and (pipe.count > 0 or pipe.writers == 0)) {
            ready |= POLLIN;
        }

        if ((requested_events & POLLOUT) != 0 and pipe.readers != 0 and pipe.count < PIPE_BUF_SIZE) {
            ready |= POLLOUT;
        }

        return ready;
    }

    const access_mode = file_desc.flags & 0x3;
    if ((requested_events & POLLIN) != 0 and (access_mode == O_RDONLY or access_mode == O_RDWR)) {
        ready |= POLLIN;
    }
    if ((requested_events & POLLOUT) != 0 and (access_mode == O_WRONLY or access_mode == O_RDWR)) {
        ready |= POLLOUT;
    }
    return ready;
}

const PipeData = struct {
    buffer: [PIPE_BUF_SIZE]u8,
    read_pos: usize,
    write_pos: usize,
    count: usize,
    readers: u32,
    writers: u32,
};

fn pipeRead(vnode: *VNode, buf: []u8, _: u64) VFSError!usize {
    const pipe: *PipeData = @ptrCast(@alignCast(vnode.private_data orelse return VFSError.InvalidOperation));
    if (pipe.count == 0) {
        if (pipe.writers == 0) return 0;
        return 0;
    }

    const to_read = @min(buf.len, pipe.count);
    if (to_read == 0) return 0;

    const first_chunk = @min(to_read, PIPE_BUF_SIZE - pipe.read_pos);
    @memcpy(buf[0..first_chunk], pipe.buffer[pipe.read_pos .. pipe.read_pos + first_chunk]);

    const second_chunk = to_read - first_chunk;
    if (second_chunk != 0) {
        @memcpy(buf[first_chunk..to_read], pipe.buffer[0..second_chunk]);
    }

    pipe.read_pos = (pipe.read_pos + to_read) & PIPE_BUF_MASK;
    pipe.count -= to_read;
    readiness.notifyVfs();
    return to_read;
}

fn pipeWrite(vnode: *VNode, buf: []const u8, _: u64) VFSError!usize {
    const pipe: *PipeData = @ptrCast(@alignCast(vnode.private_data orelse return VFSError.InvalidOperation));
    if (pipe.readers == 0) return VFSError.BrokenPipe;
    const available = PIPE_BUF_SIZE - pipe.count;
    if (available == 0) return VFSError.NoSpace;

    const to_write = @min(buf.len, available);
    if (to_write == 0) return 0;

    const first_chunk = @min(to_write, PIPE_BUF_SIZE - pipe.write_pos);
    @memcpy(pipe.buffer[pipe.write_pos .. pipe.write_pos + first_chunk], buf[0..first_chunk]);

    const second_chunk = to_write - first_chunk;
    if (second_chunk != 0) {
        @memcpy(pipe.buffer[0..second_chunk], buf[first_chunk..to_write]);
    }

    pipe.write_pos = (pipe.write_pos + to_write) & PIPE_BUF_MASK;
    pipe.count += to_write;
    readiness.notifyVfs();
    return to_write;
}

fn pipeNoOp(_: *VNode, _: u32) VFSError!void {}
fn pipeClose(_: *VNode) VFSError!void {}
fn pipeSeek(_: *VNode, _: i64, _: u32) VFSError!u64 {
    return VFSError.InvalidOperation;
}
fn pipeIoctl(_: *VNode, _: u32, _: usize) VFSError!i32 {
    return VFSError.InvalidOperation;
}
fn pipeStat(vnode: *VNode, stat_buf: *FileStat) VFSError!void {
    const pipe: *PipeData = @ptrCast(@alignCast(vnode.private_data orelse return VFSError.InvalidOperation));
    stat_buf.* = FileStat{
        .inode = 0,
        .mode = vnode.mode,
        .file_type = .Pipe,
        .size = pipe.count,
        .blocks = 0,
        .block_size = PIPE_BUF_SIZE,
        .uid = 0,
        .gid = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
    };
}
fn pipeReaddir(_: *VNode, _: *DirEntry, _: u64) VFSError!bool {
    return VFSError.InvalidOperation;
}
fn pipeTruncate(_: *VNode, _: u64) VFSError!void {
    return VFSError.InvalidOperation;
}
fn pipeChmod(_: *VNode, _: FileMode) VFSError!void {
    return VFSError.InvalidOperation;
}
fn pipeChown(_: *VNode, _: u32, _: u32) VFSError!void {
    return VFSError.InvalidOperation;
}

const pipe_ops = FileOps{
    .read = pipeRead,
    .write = pipeWrite,
    .open = pipeNoOp,
    .close = pipeClose,
    .seek = pipeSeek,
    .ioctl = pipeIoctl,
    .stat = pipeStat,
    .readdir = pipeReaddir,
    .truncate = pipeTruncate,
    .chmod = pipeChmod,
    .chown = pipeChown,
};

pub fn createPipe() VFSError!struct { read_fd: u32, write_fd: u32 } {
    const pipe_mem = memory.kmalloc(@sizeOf(PipeData)) orelse return VFSError.OutOfMemory;
    errdefer memory.kfree(@as([*]u8, @ptrCast(pipe_mem)));

    const pipe: *PipeData = @ptrCast(@alignCast(pipe_mem));
    pipe.* = PipeData{
        .buffer = [_]u8{0} ** PIPE_BUF_SIZE,
        .read_pos = 0,
        .write_pos = 0,
        .count = 0,
        .readers = 1,
        .writers = 1,
    };

    const vnode = try createVNode();
    errdefer memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));

    vnode.file_type = .Pipe;
    vnode.mode = FileMode{
        .owner_read = true,
        .owner_write = true,
    };
    vnode.ops = &pipe_ops;
    vnode.private_data = pipe_mem;

    const read_fd_idx = allocFd() orelse return VFSError.TooManyOpenFiles;
    errdefer freeFd(read_fd_idx);

    const write_fd_idx = allocFd() orelse return VFSError.TooManyOpenFiles;
    errdefer freeFd(write_fd_idx);

    const read_fd_mem = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    errdefer memory.kfree(@as([*]u8, @ptrCast(read_fd_mem)));

    const read_fd: *FileDescriptor = @ptrCast(@alignCast(read_fd_mem));
    read_fd.* = FileDescriptor{ .vnode = vnode, .offset = 0, .flags = O_RDONLY, .fd_flags = 0, .ref_count = 1, .path_len = 0, .path = [_]u8{0} ** 512 };

    const write_fd_mem = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    const write_fd: *FileDescriptor = @ptrCast(@alignCast(write_fd_mem));
    write_fd.* = FileDescriptor{ .vnode = vnode, .offset = 0, .flags = O_WRONLY, .fd_flags = 0, .ref_count = 1, .path_len = 0, .path = [_]u8{0} ** 512 };

    fd_table[read_fd_idx] = read_fd;
    fd_table[write_fd_idx] = write_fd;
    vnode.ref_count += 2;

    return .{ .read_fd = read_fd_idx, .write_fd = write_fd_idx };
}

pub fn dup2(old_fd: u32, new_fd: u32) VFSError!u32 {
    if (old_fd >= fd_table.len or new_fd >= fd_table.len) return VFSError.InvalidOperation;
    const old_desc = fd_table[old_fd] orelse return VFSError.InvalidOperation;

    if (old_fd == new_fd) return new_fd;

    if (fd_table[new_fd]) |existing| {
        existing.ref_count -= 1;
        if (existing.ref_count == 0) {
            existing.vnode.ops.close(existing.vnode) catch {};
            existing.vnode.ref_count -= 1;
            memory.kfree(@as([*]u8, @ptrCast(existing)));
        }
        fd_table[new_fd] = null;
    }

    const fd_m = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    const new_desc: *FileDescriptor = @ptrCast(@alignCast(fd_m));
    new_desc.* = FileDescriptor{
        .vnode = old_desc.vnode,
        .offset = old_desc.offset,
        .flags = old_desc.flags,
        .fd_flags = 0,
        .ref_count = 1,
        .path_len = old_desc.path_len,
        .path = old_desc.path,
    };
    fd_table[new_fd] = new_desc;
    old_desc.vnode.ref_count += 1;
    retainPipeEndpoint(new_desc);

    return new_fd;
}

pub fn dup(old_fd: u32) VFSError!u32 {
    if (old_fd >= fd_table.len) return VFSError.InvalidOperation;
    const old_desc = fd_table[old_fd] orelse return VFSError.InvalidOperation;

    const new_fd = allocFd() orelse return VFSError.TooManyOpenFiles;
    errdefer freeFd(new_fd);

    const fd_m = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    const new_desc: *FileDescriptor = @ptrCast(@alignCast(fd_m));
    new_desc.* = FileDescriptor{
        .vnode = old_desc.vnode,
        .offset = old_desc.offset,
        .flags = old_desc.flags,
        .fd_flags = old_desc.fd_flags,
        .ref_count = 1,
        .path_len = old_desc.path_len,
        .path = old_desc.path,
    };
    fd_table[new_fd] = new_desc;
    old_desc.vnode.ref_count += 1;
    retainPipeEndpoint(new_desc);

    return new_fd;
}

fn retainPipeEndpoint(file_desc: *const FileDescriptor) void {
    if (file_desc.vnode.file_type != .Pipe) return;
    const pipe: *PipeData = @ptrCast(@alignCast(file_desc.vnode.private_data orelse return));
    if ((file_desc.flags & O_WRONLY) != 0) {
        pipe.writers += 1;
    } else {
        pipe.readers += 1;
    }
}

fn notifyPathEvent(path: []const u8, exact_mask: u32, parent_mask: u32) void {
    const callback = inotify_notifier orelse return;
    callback(path, exact_mask, parent_mask);
}

fn notifyVNodeEvent(vnode: *VNode, exact_mask: u32, parent_mask: u32) void {
    const path = getNodePath(vnode) catch return;
    notifyPathEvent(path, exact_mask, parent_mask);
}

fn notifyDescriptorEvent(file_desc: *const FileDescriptor, exact_mask: u32, parent_mask: u32) void {
    if (file_desc.path_len == 0) return;
    notifyPathEvent(file_desc.path[0..file_desc.path_len], exact_mask, parent_mask);
}

fn notifyCloseEvent(file_desc: *const FileDescriptor) void {
    const writable = (file_desc.flags & O_WRONLY) != 0 or (file_desc.flags & O_RDWR) != 0;
    const mask = if (writable) abi.IN_CLOSE_WRITE else abi.IN_CLOSE_NOWRITE;
    notifyDescriptorEvent(file_desc, mask, mask);
}

pub fn rename(old_path: []const u8, new_path: []const u8) VFSError!void {
    if (std.mem.eql(u8, old_path, new_path)) return;

    const old_parts = splitPath(old_path);
    const new_parts = splitPath(new_path);

    const old_parent = try lookupPath(old_parts.parent);
    const new_parent = try lookupPath(new_parts.parent);

    if (old_parent.file_type != FileType.Directory or new_parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }

    if (old_parent.mount_point != new_parent.mount_point) {
        return VFSError.InvalidOperation;
    }

    try old_parent.mount_point.?.fs_type.ops.rename(old_parent, old_parts.name, new_parent, new_parts.name);
}

fn createVNode() VFSError!*VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(VNode)) orelse return VFSError.OutOfMemory;
    const vnode: *VNode = @ptrCast(@alignCast(vnode_mem));

    vnode.* = VNode{
        .name = [_]u8{0} ** 256,
        .name_len = 0,
        .inode = 0,
        .file_type = FileType.Regular,
        .mode = FileMode{},
        .size = 0,
        .uid = 0,
        .gid = 0,
        .ref_count = 0,
        .mount_point = null,
        .parent = null,
        .children = null,
        .next_sibling = null,
        // SAFETY: assigned by the filesystem driver before the vnode is used
        .ops = undefined,
        .private_data = null,
    };

    return vnode;
}

pub fn lookupPath(path: []const u8) VFSError!*VNode {
    if (path.len == 0 or path[0] != '/') {
        return VFSError.InvalidPath;
    }

    var current: *VNode = undefined;
    var i: usize = 1;

    if (findBestMountPoint(path)) |mp| {
        current = mp.root orelse return VFSError.NotFound;
        const mount_path = mp.mount_path[0..strlen(&mp.mount_path)];
        if (path.len == mount_path.len or (mount_path.len == 1 and path.len == 1)) {
            return current;
        }
        i = if (mount_path.len == 1) 1 else mount_path.len;
    } else {
        current = root_vnode orelse return VFSError.NotFound;
        if (path.len == 1) {
            return current;
        }
    }

    while (i < path.len) {
        while (i < path.len and path[i] == '/') : (i += 1) {}

        if (i >= path.len) break;

        const start = i;
        while (i < path.len and path[i] != '/') : (i += 1) {}

        const component = path[start..i];

        if (current.mount_point) |mp| {
            current = mp.fs_type.ops.lookup(current, component) catch {
                return VFSError.NotFound;
            };
        } else {
            var child = current.children;
            var found = false;

            while (child) |c| : (child = c.next_sibling) {
                if (std.mem.eql(u8, c.name[0..c.name_len], component)) {
                    current = c;
                    found = true;
                    break;
                }
            }

            if (!found) {
                return VFSError.NotFound;
            }
        }
    }

    return current;
}

fn findBestMountPoint(path: []const u8) ?*MountPoint {
    var best: ?*MountPoint = null;
    var best_len: usize = 0;
    var current = mount_list;

    while (current) |mp| : (current = mp.next) {
        const mount_path = mp.mount_path[0..strlen(&mp.mount_path)];
        if (!mountPathMatches(path, mount_path)) continue;
        if (mount_path.len >= best_len) {
            best = mp;
            best_len = mount_path.len;
        }
    }

    return best;
}

fn mountPathMatches(path: []const u8, mount_path: []const u8) bool {
    if (mount_path.len == 1 and mount_path[0] == '/') {
        return true;
    }

    if (path.len < mount_path.len) return false;
    if (!std.mem.eql(u8, path[0..mount_path.len], mount_path)) return false;
    return path.len == mount_path.len or path[mount_path.len] == '/';
}

const PathParts = struct {
    parent: []const u8,
    name: []const u8,
};

fn splitPath(path: []const u8) PathParts {
    var last_slash: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/') {
            last_slash = i;
        }
    }
    return .{
        .parent = if (last_slash == 0) "/" else path[0..last_slash],
        .name = path[last_slash + 1 ..],
    };
}

fn strlen(str: []const u8) usize {
    var i: usize = 0;
    while (i < str.len and str[i] != 0) : (i += 1) {}
    return i;
}
