const std = @import("std");
const fd_freelist_mod = @import("fd_freelist.zig");
const vfs_types = @import("vfs/types.zig");
const vfs_path = @import("vfs/path.zig");
const memory = @import("../memory/memory.zig");
const abi = @import("../process/syscall/abi.zig");
const path_semantics = @import("../process/syscall/path_semantics.zig");
const readiness = @import("../process/syscall/readiness.zig");
const error_handler = @import("../utils/error.zig");

pub const VFSError = vfs_types.VFSError;
pub const FileType = vfs_types.FileType;
pub const FileMode = vfs_types.FileMode;
pub const FileStat = vfs_types.FileStat;
pub const DirEntry = vfs_types.DirEntry;
pub const FileOps = vfs_types.FileOps;
pub const VNode = vfs_types.VNode;
pub const FileSystemOps = vfs_types.FileSystemOps;
pub const FileSystemType = vfs_types.FileSystemType;
pub const MountPoint = vfs_types.MountPoint;
pub const FileDescriptor = vfs_types.FileDescriptor;
pub const MountInfo = vfs_types.MountInfo;
pub const O_RDONLY: u32 = vfs_types.O_RDONLY;
pub const O_WRONLY: u32 = vfs_types.O_WRONLY;
pub const O_RDWR: u32 = vfs_types.O_RDWR;
pub const O_CREAT: u32 = vfs_types.O_CREAT;
pub const O_EXCL: u32 = vfs_types.O_EXCL;
pub const O_TRUNC: u32 = vfs_types.O_TRUNC;
pub const O_APPEND: u32 = vfs_types.O_APPEND;
pub const O_NONBLOCK: u32 = vfs_types.O_NONBLOCK;

const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;

pub const SEEK_SET: u32 = vfs_types.SEEK_SET;
pub const SEEK_CUR: u32 = vfs_types.SEEK_CUR;
pub const SEEK_END: u32 = vfs_types.SEEK_END;

const PathParts = vfs_path.PathParts;
const splitPath = vfs_path.splitPath;
const mountPathMatches = vfs_path.mountPathMatches;
const hasRemainingComponents = vfs_path.hasRemainingComponents;

var root_vnode: ?*VNode = null;
var mount_list: ?*MountPoint = null;
var fs_type_list: ?*FileSystemType = null;
var fd_table: [256]?*FileDescriptor = [_]?*FileDescriptor{null} ** 256;
var mount_state_lock: u32 = 0;
var vnode_ref_lock: u32 = 0;
var fd_state_lock: u32 = 0;
var path_buffer_lock: u32 = 0;
var inotify_notifier: ?*const fn ([]const u8, u32, u32) void = null;

const FD_TABLE_SIZE = 256;
const MAX_SYMLINK_DEPTH: usize = 8;
var fd_freelist: [FD_TABLE_SIZE]u8 = undefined;
var fd_freelist_top: usize = 0;

fn lockSpin(lock: *u32) void {
    while (@cmpxchgWeak(u32, lock, 0, 1, .acquire, .monotonic) != null) {
        while (@atomicLoad(u32, lock, .monotonic) != 0) {
            asm volatile ("pause");
        }
    }
}

fn unlockSpin(lock: *u32) void {
    @atomicStore(u32, lock, 0, .release);
}

fn lockMountState() void {
    lockSpin(&mount_state_lock);
}

fn unlockMountState() void {
    unlockSpin(&mount_state_lock);
}

fn lockVNodeRefs() void {
    lockSpin(&vnode_ref_lock);
}

fn unlockVNodeRefs() void {
    unlockSpin(&vnode_ref_lock);
}

fn lockFdState() void {
    lockSpin(&fd_state_lock);
}

fn unlockFdState() void {
    unlockSpin(&fd_state_lock);
}

fn lockPathBuffer() void {
    lockSpin(&path_buffer_lock);
}

fn unlockPathBuffer() void {
    unlockSpin(&path_buffer_lock);
}

fn retainMountPoint(mp: *MountPoint) void {
    lockMountState();
    mp.ref_count += 1;
    unlockMountState();
}

fn releaseMountPoint(mp: *MountPoint) void {
    lockMountState();
    if (mp.ref_count > 0) {
        mp.ref_count -= 1;
    }
    unlockMountState();
}

pub fn retainLookupVNode(vnode: *VNode) void {
    if (vnode.mount_point) |mp| {
        retainMountPoint(mp);
    }
}

pub fn releaseLookupVNode(vnode: *VNode) void {
    if (vnode.mount_point) |mp| {
        releaseMountPoint(mp);
    }

    releaseTransientLookupVNode(vnode);
}

pub fn discardLookupVNode(vnode: *VNode) void {
    releaseTransientLookupVNode(vnode);
}

fn releaseTransientLookupVNode(vnode: *VNode) void {
    if (isPersistentVNode(vnode)) return;

    const parent = vnode.parent;
    lockVNodeRefs();
    if (vnode.ref_count > 0) {
        vnode.ref_count -= 1;
    }
    const should_free = vnode.ref_count == 0;
    unlockVNodeRefs();

    if (should_free) {
        memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));
        if (parent) |lookup_parent| {
            if (!isPersistentVNode(lookup_parent)) {
                releaseTransientLookupVNode(lookup_parent);
            }
        }
    }
}

fn isPersistentVNode(vnode: *VNode) bool {
    if (root_vnode) |root| {
        if (vnode == root) return true;
    }
    if (vnode.mount_point) |mp| {
        return mp.root == vnode;
    }
    return false;
}

fn initFdFreelistLocked() void {
    fd_freelist_mod.initFreelist(&fd_freelist, &fd_freelist_top);
}

fn allocFdLocked() ?u32 {
    return fd_freelist_mod.allocFd(&fd_freelist, &fd_freelist_top);
}

fn allocFd() ?u32 {
    lockFdState();
    defer unlockFdState();
    return allocFdLocked();
}

fn freeFdLocked(fd: u32) void {
    fd_freelist_mod.freeFd(&fd_freelist, &fd_freelist_top, fd);
}

fn freeFd(fd: u32) void {
    lockFdState();
    defer unlockFdState();
    freeFdLocked(fd);
}

fn reserveFdLocked(fd: u32) bool {
    return fd_freelist_mod.reserveFd(&fd_freelist, &fd_freelist_top, fd);
}

fn installDescriptor(fd: u32, file_desc: *FileDescriptor) VFSError!void {
    if (fd >= FD_TABLE_SIZE) return VFSError.InvalidOperation;
    lockFdState();
    defer unlockFdState();
    fd_table[fd] = file_desc;
}

fn replaceDescriptor(fd: u32, file_desc: *FileDescriptor) VFSError!?*FileDescriptor {
    if (fd >= FD_TABLE_SIZE) return VFSError.InvalidOperation;

    lockFdState();
    defer unlockFdState();

    const existing = fd_table[fd];
    if (existing == null and !reserveFdLocked(fd)) {
        return VFSError.InvalidOperation;
    }
    fd_table[fd] = file_desc;
    return existing;
}

fn retainDescriptor(fd: u32) VFSError!*FileDescriptor {
    if (fd >= FD_TABLE_SIZE) return VFSError.InvalidOperation;

    lockFdState();
    defer unlockFdState();

    const file_desc = fd_table[fd] orelse return VFSError.InvalidOperation;
    file_desc.ref_count += 1;
    return file_desc;
}

fn takeDescriptor(fd: u32) VFSError!*FileDescriptor {
    if (fd >= FD_TABLE_SIZE) return VFSError.InvalidOperation;

    lockFdState();
    defer unlockFdState();

    const file_desc = fd_table[fd] orelse return VFSError.InvalidOperation;
    fd_table[fd] = null;
    freeFdLocked(fd);
    return file_desc;
}

fn releaseDescriptor(file_desc: *FileDescriptor) void {
    lockFdState();
    if (file_desc.ref_count == 0) {
        unlockFdState();
        return;
    }
    file_desc.ref_count -= 1;
    const should_destroy = file_desc.ref_count == 0;
    unlockFdState();

    if (should_destroy) {
        destroyDescriptor(file_desc);
    }
}

fn destroyDescriptor(file_desc: *FileDescriptor) void {
    const mount_point = file_desc.vnode.mount_point;
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
    vnode.ops.close(vnode) catch {};

    lockVNodeRefs();
    if (vnode.ref_count > 0) {
        vnode.ref_count -= 1;
    }
    const free_vnode = vnode.ref_count == 0 and !isPersistentVNode(vnode);
    unlockVNodeRefs();

    if (free_vnode) {
        memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));
    }

    notifyCloseEvent(file_desc);
    if (mount_point) |mp| {
        releaseMountPoint(mp);
    }
    memory.kfree(@as([*]u8, @ptrCast(file_desc)));
}

pub fn init() void {
    lockFdState();
    initFdFreelistLocked();
    unlockFdState();

    lockMountState();
    defer unlockMountState();

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
    lockMountState();
    defer unlockMountState();
    inotify_notifier = callback;
}

pub fn registerFileSystem(fs_type: *FileSystemType) VFSError!void {
    lockMountState();
    defer unlockMountState();
    fs_type.next = fs_type_list;
    fs_type_list = fs_type;
}

pub fn mount(device: []const u8, mount_path: []const u8, fs_name: []const u8, flags: u32) VFSError!void {
    lockMountState();
    var fs_type = fs_type_list;
    while (fs_type) |fs| : (fs_type = fs.next) {
        if (std.mem.eql(u8, fs.name[0..strlen(&fs.name)], fs_name)) {
            unlockMountState();
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
            mount_point.ref_count = 1;
            mount_point.private_data = null;
            mount_point.next = null;

            try fs.ops.mount(mount_point);

            mount_point.root = try fs.ops.get_root(mount_point);

            lockMountState();
            mount_point.next = mount_list;
            mount_list = mount_point;
            unlockMountState();

            return;
        }
    }
    unlockMountState();

    return VFSError.InvalidOperation;
}

pub fn unmount(mount_path: []const u8) VFSError!void {
    lockMountState();
    var prev: ?*MountPoint = null;
    var current = mount_list;

    while (current) |mp| {
        const mp_path = mp.mount_path[0..strlen(&mp.mount_path)];
        if (std.mem.eql(u8, mp_path, mount_path)) {
            if (mp.ref_count != 1) {
                unlockMountState();
                return VFSError.Busy;
            }
            if (prev) |p| {
                p.next = mp.next;
            } else {
                mount_list = mp.next;
            }
            unlockMountState();

            mp.fs_type.ops.unmount(mp) catch {};
            memory.kfree(@as([*]u8, @ptrCast(mp)));
            return;
        }
        prev = mp;
        current = mp.next;
    }
    unlockMountState();

    return VFSError.NotFound;
}

pub fn snapshotMounts(buffer: []MountInfo) usize {
    lockMountState();
    defer unlockMountState();

    var count: usize = 0;
    var current = mount_list;
    while (current) |mp| : (current = mp.next) {
        if (count >= buffer.len) break;

        var info = MountInfo{};
        info.device_len = @intCast(strlen(&mp.device));
        info.mount_path_len = @intCast(strlen(&mp.mount_path));
        info.fs_name_len = @intCast(strlen(&mp.fs_type.name));
        info.flags = mp.flags;

        @memcpy(info.device[0..info.device_len], mp.device[0..info.device_len]);
        @memcpy(info.mount_path[0..info.mount_path_len], mp.mount_path[0..info.mount_path_len]);
        @memcpy(info.fs_name[0..info.fs_name_len], mp.fs_type.name[0..info.fs_name_len]);

        buffer[count] = info;
        count += 1;
    }

    return count;
}

pub fn open(path: []const u8, flags: u32) VFSError!u32 {
    var created = false;
    var held_parent: ?*VNode = null;
    defer if (held_parent) |parent| releaseLookupVNode(parent);

    const vnode = blk: {
        if (lookupPathRetained(path)) |v| {
            if ((flags & O_CREAT) != 0 and (flags & O_EXCL) != 0) {
                releaseLookupVNode(v);
                return VFSError.AlreadyExists;
            }
            break :blk v;
        } else |err| {
            if (err == VFSError.NotFound and (flags & O_CREAT) != 0) {
                const parts = splitPath(path);
                const parent = try lookupPathRetained(parts.parent);
                held_parent = parent;
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
                const child = try parent.mount_point.?.fs_type.ops.create(parent, parts.name, default_mode);
                retainLookupVNode(child);
                break :blk child;
            } else {
                return err;
            }
        }
    };
    defer releaseLookupVNode(vnode);

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

    try installDescriptor(i, fd);
    retainLookupVNode(vnode);
    lockVNodeRefs();
    vnode.ref_count += 1;
    unlockVNodeRefs();

    if (created) notifyPathEvent(path, abi.IN_CREATE, abi.IN_CREATE);
    if (truncated) notifyPathEvent(path, abi.IN_MODIFY, abi.IN_MODIFY);
    notifyPathEvent(path, abi.IN_OPEN, abi.IN_OPEN);

    return i;
}

pub fn close(fd: u32) VFSError!void {
    const file_desc = try takeDescriptor(fd);
    releaseDescriptor(file_desc);
    readiness.notifyVfs();
}

pub fn read(fd: u32, buffer: []u8) VFSError!usize {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    if ((file_desc.flags & O_WRONLY) != 0) {
        return VFSError.PermissionDenied;
    }

    const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, file_desc.offset);
    file_desc.offset += bytes_read;
    if (bytes_read > 0) notifyDescriptorEvent(file_desc, abi.IN_ACCESS, abi.IN_ACCESS);
    return bytes_read;
}

pub fn write(fd: u32, buffer: []const u8) VFSError!usize {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

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

pub fn ioctl(fd: u32, request: u32, arg: usize) VFSError!i32 {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    return file_desc.vnode.ops.ioctl(file_desc.vnode, request, arg);
}

pub fn lseek(fd: u32, offset: i64, whence: u32) VFSError!u64 {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

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

pub fn pread(fd: u32, buffer: []u8, offset: u64) VFSError!usize {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    if ((file_desc.flags & O_WRONLY) != 0) {
        return VFSError.PermissionDenied;
    }

    const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, offset);
    if (bytes_read > 0) notifyDescriptorEvent(file_desc, abi.IN_ACCESS, abi.IN_ACCESS);
    return bytes_read;
}

pub fn pwrite(fd: u32, buffer: []const u8, offset: u64) VFSError!usize {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
        return VFSError.PermissionDenied;
    }

    const bytes_written = try file_desc.vnode.ops.write(file_desc.vnode, buffer, offset);
    if (bytes_written > 0) notifyDescriptorEvent(file_desc, abi.IN_MODIFY, abi.IN_MODIFY);
    return bytes_written;
}

pub fn getFileFlags(fd: u32) VFSError!u32 {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    return file_desc.flags;
}

pub fn pollFd(fd: u32, requested_events: u16) VFSError!u16 {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    return pollDescriptor(file_desc, requested_events);
}

pub fn setFileFlags(fd: u32, flags: u32) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    const changeable = O_APPEND | O_NONBLOCK;
    file_desc.flags = (file_desc.flags & ~changeable) | (flags & changeable);
}

pub fn getFdFlags(fd: u32) VFSError!u32 {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    return file_desc.fd_flags;
}

pub fn setFdFlags(fd: u32, flags: u32) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    file_desc.fd_flags = flags;
}

pub fn getVNodeFromFd(fd: u32) VFSError!*VNode {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    retainLookupVNode(file_desc.vnode);
    lockVNodeRefs();
    file_desc.vnode.ref_count += 1;
    unlockVNodeRefs();

    return file_desc.vnode;
}

pub fn releaseVNode(vnode: *VNode) void {
    const mount_point = vnode.mount_point;
    lockVNodeRefs();
    if (vnode.ref_count > 0) {
        vnode.ref_count -= 1;
    }
    const free_pipe_vnode = vnode.ref_count == 0 and vnode.file_type == .Pipe;
    unlockVNodeRefs();

    if (free_pipe_vnode) {
        memory.kfree(@as([*]u8, @ptrCast(@alignCast(vnode))));
    }
    if (mount_point) |mp| {
        releaseMountPoint(mp);
    }
}

var path_buffer: [512]u8 = undefined;

pub fn getNodePath(vnode: *VNode) VFSError![]const u8 {
    lockMountState();
    defer unlockMountState();
    lockPathBuffer();
    defer unlockPathBuffer();

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
    const vnode = try lookupPathRetained(path);
    defer releaseLookupVNode(vnode);
    try vnode.ops.stat(vnode, stat_buf);
}

pub fn lstat(path: []const u8, stat_buf: *FileStat) VFSError!void {
    const vnode = try lookupPathNoFollowRetained(path);
    defer releaseLookupVNode(vnode);
    try vnode.ops.stat(vnode, stat_buf);
}

pub fn fstat(fd: u32, stat_buf: *FileStat) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    try file_desc.vnode.ops.stat(file_desc.vnode, stat_buf);
}

pub fn readdir(fd: u32, dirent: *DirEntry, index: u64) VFSError!bool {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    return file_desc.vnode.ops.readdir(file_desc.vnode, dirent, index);
}

pub fn readdirNext(fd: u32, dirent: *DirEntry) VFSError!bool {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    const has_entry = try file_desc.vnode.ops.readdir(file_desc.vnode, dirent, file_desc.offset);
    if (has_entry) {
        file_desc.offset += 1;
    }
    return has_entry;
}

pub fn mkdir(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    _ = try parent.mount_point.?.fs_type.ops.mkdir(parent, parts.name, mode);
}

pub fn create(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    _ = try parent.mount_point.?.fs_type.ops.create(parent, parts.name, mode);
}

pub fn unlink(path: []const u8) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    try parent.mount_point.?.fs_type.ops.unlink(parent, parts.name);
}

pub fn rmdir(path: []const u8) VFSError!void {
    const parts = splitPath(path);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    try parent.mount_point.?.fs_type.ops.rmdir(parent, parts.name);
}

pub fn mkfifo(path: []const u8, mode: FileMode) VFSError!void {
    const parts = splitPath(path);

    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
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
    const vnode = try lookupPathRetained(path);
    defer releaseLookupVNode(vnode);
    if (vnode.file_type == FileType.Directory) {
        return VFSError.IsDirectory;
    }
    try vnode.ops.truncate(vnode, size);
}

pub fn symlink(target: []const u8, linkpath: []const u8) VFSError!void {
    const parts = splitPath(linkpath);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
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
    const target = try lookupPathRetained(target_path);
    defer releaseLookupVNode(target);
    if (target.file_type == FileType.Directory) {
        return VFSError.IsDirectory;
    }

    const parts = splitPath(linkpath);
    const parent = try lookupPathRetained(parts.parent);
    defer releaseLookupVNode(parent);
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
    const vnode = try lookupPathNoFollowRetained(path);
    defer releaseLookupVNode(vnode);
    return readlinkVNode(vnode, buffer);
}

pub fn ftruncate(fd: u32, size: u64) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);

    if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
        return VFSError.PermissionDenied;
    }
    try file_desc.vnode.ops.truncate(file_desc.vnode, size);
    notifyDescriptorEvent(file_desc, abi.IN_MODIFY, abi.IN_MODIFY);
}

pub fn chmod(path: []const u8, mode: FileMode) VFSError!void {
    const vnode = try lookupPathRetained(path);
    defer releaseLookupVNode(vnode);
    try vnode.ops.chmod(vnode, mode);
}

pub fn fchmod(fd: u32, mode: FileMode) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    try file_desc.vnode.ops.chmod(file_desc.vnode, mode);
    notifyDescriptorEvent(file_desc, abi.IN_ATTRIB, abi.IN_ATTRIB);
}

pub fn chown(path: []const u8, uid: u32, gid: u32) VFSError!void {
    const vnode = try lookupPathRetained(path);
    defer releaseLookupVNode(vnode);
    try vnode.ops.chown(vnode, uid, gid);
}

pub fn fchown(fd: u32, uid: u32, gid: u32) VFSError!void {
    const file_desc = try retainDescriptor(fd);
    defer releaseDescriptor(file_desc);
    try file_desc.vnode.ops.chown(file_desc.vnode, uid, gid);
    notifyDescriptorEvent(file_desc, abi.IN_ATTRIB, abi.IN_ATTRIB);
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

    try installDescriptor(read_fd_idx, read_fd);
    try installDescriptor(write_fd_idx, write_fd);
    lockVNodeRefs();
    vnode.ref_count += 2;
    unlockVNodeRefs();

    return .{ .read_fd = read_fd_idx, .write_fd = write_fd_idx };
}

pub fn dup2(old_fd: u32, new_fd: u32) VFSError!u32 {
    const old_desc = try retainDescriptor(old_fd);
    defer releaseDescriptor(old_desc);

    if (old_fd == new_fd) return new_fd;

    const fd_m = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    errdefer memory.kfree(@as([*]u8, @ptrCast(fd_m)));

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
    const existing = try replaceDescriptor(new_fd, new_desc);
    retainLookupVNode(new_desc.vnode);
    lockVNodeRefs();
    old_desc.vnode.ref_count += 1;
    unlockVNodeRefs();
    retainPipeEndpoint(new_desc);
    if (existing) |replaced| {
        releaseDescriptor(replaced);
    }

    return new_fd;
}

pub fn dup(old_fd: u32) VFSError!u32 {
    const old_desc = try retainDescriptor(old_fd);
    defer releaseDescriptor(old_desc);

    const new_fd = allocFd() orelse return VFSError.TooManyOpenFiles;
    errdefer freeFd(new_fd);

    const fd_m = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
    errdefer memory.kfree(@as([*]u8, @ptrCast(fd_m)));

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
    try installDescriptor(new_fd, new_desc);
    retainLookupVNode(new_desc.vnode);
    lockVNodeRefs();
    old_desc.vnode.ref_count += 1;
    unlockVNodeRefs();
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

fn loadInotifyNotifier() ?*const fn ([]const u8, u32, u32) void {
    lockMountState();
    defer unlockMountState();
    return inotify_notifier;
}

fn notifyPathEvent(path: []const u8, exact_mask: u32, parent_mask: u32) void {
    const callback = loadInotifyNotifier() orelse return;
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

    const old_parent = try lookupPathRetained(old_parts.parent);
    defer releaseLookupVNode(old_parent);
    const new_parent = try lookupPathRetained(new_parts.parent);
    defer releaseLookupVNode(new_parent);

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
    lockMountState();
    defer unlockMountState();
    return lookupPathLocked(path, true);
}

pub fn lookupPathNoFollow(path: []const u8) VFSError!*VNode {
    lockMountState();
    defer unlockMountState();
    return lookupPathLocked(path, false);
}

pub fn lookupPathRetained(path: []const u8) VFSError!*VNode {
    lockMountState();
    defer unlockMountState();

    const vnode = try lookupPathLocked(path, true);
    if (vnode.mount_point) |mp| {
        mp.ref_count += 1;
    }
    return vnode;
}

pub fn lookupPathNoFollowRetained(path: []const u8) VFSError!*VNode {
    lockMountState();
    defer unlockMountState();

    const vnode = try lookupPathLocked(path, false);
    if (vnode.mount_point) |mp| {
        mp.ref_count += 1;
    }
    return vnode;
}

fn lookupPathLocked(path: []const u8, follow_final_symlink: bool) VFSError!*VNode {
    if (path.len == 0 or path[0] != '/') return VFSError.InvalidPath;
    if (path.len >= 512) return VFSError.InvalidPath;

    var resolved_path_storage: [512]u8 = undefined;
    @memcpy(resolved_path_storage[0..path.len], path);
    var resolved_path = resolved_path_storage[0..path.len];

    var symlink_depth: usize = 0;
    restart: while (true) {
        var current: *VNode = undefined;
        var i: usize = 1;

        if (findBestMountPointLocked(resolved_path)) |mp| {
            current = mp.root orelse return VFSError.NotFound;
            const mount_path = mp.mount_path[0..strlen(&mp.mount_path)];
            if (resolved_path.len == mount_path.len or (mount_path.len == 1 and resolved_path.len == 1)) {
                return current;
            }
            i = if (mount_path.len == 1) 1 else mount_path.len;
        } else {
            current = root_vnode orelse return VFSError.NotFound;
            if (resolved_path.len == 1) {
                return current;
            }
        }

        while (i < resolved_path.len) {
            while (i < resolved_path.len and resolved_path[i] == '/') : (i += 1) {}
            if (i >= resolved_path.len) break;

            const component_start = i;
            while (i < resolved_path.len and resolved_path[i] != '/') : (i += 1) {}
            const component_end = i;
            const component = resolved_path[component_start..component_end];

            const prev = current;
            current = lookupChildLocked(prev, component) catch {
                if (!isPersistentVNode(prev)) {
                    releaseTransientLookupVNode(prev);
                }
                return VFSError.NotFound;
            };
            if (!isPersistentVNode(prev)) {
                releaseTransientLookupVNode(prev);
            }

            const should_follow = current.file_type == .SymLink and
                (follow_final_symlink or hasRemainingComponents(resolved_path, component_end));
            if (!should_follow) continue;

            if (symlink_depth >= MAX_SYMLINK_DEPTH) {
                if (!isPersistentVNode(current)) {
                    releaseTransientLookupVNode(current);
                }
                return VFSError.InvalidPath;
            }

            var link_target_storage: [512]u8 = undefined;
            const link_len = readlinkVNode(current, &link_target_storage) catch |err| {
                if (!isPersistentVNode(current)) {
                    releaseTransientLookupVNode(current);
                }
                return err;
            };
            const link_target = link_target_storage[0..link_len];

            var normalized_target_storage: [512]u8 = undefined;
            const parent_path = if (component_start <= 1) "/" else resolved_path[0 .. component_start - 1];
            const normalized_target = if (link_target.len > 0 and link_target[0] == '/')
                path_semantics.resolveActualPath("/", link_target, &normalized_target_storage) catch {
                    if (!isPersistentVNode(current)) {
                        releaseTransientLookupVNode(current);
                    }
                    return VFSError.InvalidPath;
                }
            else
                path_semantics.resolvePathFromDir("/", parent_path, link_target, &normalized_target_storage) catch {
                    if (!isPersistentVNode(current)) {
                        releaseTransientLookupVNode(current);
                    }
                    return VFSError.InvalidPath;
                };

            const remainder = resolved_path[component_end..];
            const required_len = normalized_target.len + remainder.len;
            if (required_len == 0 or required_len >= resolved_path_storage.len) {
                if (!isPersistentVNode(current)) {
                    releaseTransientLookupVNode(current);
                }
                return VFSError.InvalidPath;
            }

            @memcpy(resolved_path_storage[0..normalized_target.len], normalized_target);
            @memcpy(resolved_path_storage[normalized_target.len..required_len], remainder);
            resolved_path = resolved_path_storage[0..required_len];

            if (!isPersistentVNode(current)) {
                releaseTransientLookupVNode(current);
            }

            symlink_depth += 1;
            continue :restart;
        }

        return current;
    }
}

fn lookupChildLocked(current: *VNode, component: []const u8) VFSError!*VNode {
    if (current.mount_point) |mp| {
        const child = try mp.fs_type.ops.lookup(current, component);
        attachLookupParent(child, current);
        return child;
    }

    var child = current.children;
    while (child) |c| : (child = c.next_sibling) {
        if (std.mem.eql(u8, c.name[0..c.name_len], component)) {
            return c;
        }
    }
    return VFSError.NotFound;
}

fn attachLookupParent(child: *VNode, parent: *VNode) void {
    if (child == parent or child.parent != null) return;

    child.parent = parent;
    if (isPersistentVNode(parent)) return;

    lockVNodeRefs();
    parent.ref_count += 1;
    unlockVNodeRefs();
}

fn readlinkVNode(vnode: *VNode, buffer: []u8) VFSError!usize {
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

fn findBestMountPointLocked(path: []const u8) ?*MountPoint {
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

fn strlen(str: []const u8) usize {
    var i: usize = 0;
    while (i < str.len and str[i] != 0) : (i += 1) {}
    return i;
}
