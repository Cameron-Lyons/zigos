const std = @import("std");
const abi = @import("abi.zig");
const at_semantics = @import("at_semantics.zig");
const common = @import("common.zig");
const cwd_mod = @import("cwd.zig");
const errno = @import("errno.zig");
const syscall_event = @import("event.zig");
const credentials = @import("../credentials.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

const StatxTimestamp = extern struct {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
};

const Statx = extern struct {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    __spare2: u64,
    __spare3: [12]u64,
};

const UtimensatTimespec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

pub fn sys_openat(dirfd: i32, pathname: [*]const u8, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    const fd = vfs.open(resolved, @intCast(flags)) catch |err| return errno.vfsErrno(err);
    return @intCast(@as(i32, @intCast(fd)) + abi.FD_OFFSET);
}

pub fn sys_mkdirat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    vfs.mkdir(resolved, common.fileModeFromBits(mode)) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_unlinkat(dirfd: i32, pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    if (flags & abi.AT_REMOVEDIR != 0) {
        vfs.rmdir(resolved) catch |err| return errno.vfsErrno(err);
        syscall_event.notifyInotifyPathEvent(resolved, abi.IN_DELETE_SELF, abi.IN_DELETE);
    } else {
        vfs.unlink(resolved) catch |err| return errno.vfsErrno(err);
        syscall_event.notifyInotifyPathEvent(resolved, abi.IN_DELETE_SELF, abi.IN_DELETE);
    }
    return 0;
}

pub fn sys_linkat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8, flags: u32) i32 {
    _ = flags;

    if (!protection.verifyUserPointer(@intFromPtr(oldpath), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var old_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var new_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return abi.EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return abi.EINVAL;

    var resolved_old_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_new_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;

    const resolved_old = resolveDirFd(olddirfd, old_slice, &resolved_old_buf) orelse return abi.EBADF;
    const resolved_new = resolveDirFd(newdirfd, new_slice, &resolved_new_buf) orelse return abi.EBADF;

    vfs.link(resolved_old, resolved_new) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved_new, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_fchmodat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    vfs.chmod(resolved, common.fileModeFromBits(mode)) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_ATTRIB, 0);
    return 0;
}

pub fn sys_fchownat(dirfd: i32, pathname: [*]const u8, owner: i32, group: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    if (process_mod.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return abi.EPERM;
        }
    }

    const vnode = vfs.lookupPathRetained(resolved) catch |err| return errno.vfsErrno(err);
    defer vfs.releaseLookupVNode(vnode);

    const uid: u32 = if (owner < 0) vnode.uid else @intCast(owner);
    const gid: u32 = if (group < 0) vnode.gid else @intCast(group);

    vnode.ops.chown(vnode, uid, gid) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_ATTRIB, 0);
    return 0;
}

pub fn sys_renameat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var old_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var new_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return abi.EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return abi.EINVAL;

    var resolved_old_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_new_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;

    const resolved_old = resolveDirFd(olddirfd, old_slice, &resolved_old_buf) orelse return abi.EBADF;
    const resolved_new = resolveDirFd(newdirfd, new_slice, &resolved_new_buf) orelse return abi.EBADF;

    vfs.rename(resolved_old, resolved_new) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyRename(resolved_old, resolved_new);
    return 0;
}

pub fn sys_faccessat(dirfd: i32, pathname: [*]const u8, mode: u32, flags: u32) i32 {
    _ = flags;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EFAULT;

    var full_path_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const full_path = resolveCwdPathOnly(dirfd, path_slice, &full_path_buf) orelse return abi.EBADF;

    const vnode = vfs.lookupPath(full_path) catch |err| return errno.vfsErrno(err);
    vfs.discardLookupVNode(vnode);
    _ = mode;
    return 0;
}

pub fn sys_statx(dirfd: i32, pathname: [*]const u8, flags: u32, mask: u32, statxbuf: usize) i32 {
    _ = flags;
    _ = mask;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    if (!protection.verifyUserPointer(statxbuf, @sizeOf(Statx))) return abi.EFAULT;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EFAULT;

    var full_path_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const full_path = resolveCwdPathOnly(dirfd, path_slice, &full_path_buf) orelse return abi.EBADF;

    const vnode = vfs.lookupPathRetained(full_path) catch |err| return errno.vfsErrno(err);
    defer vfs.releaseLookupVNode(vnode);

    var stat_buf: vfs.FileStat = undefined;
    vnode.ops.stat(vnode, &stat_buf) catch |err| return errno.vfsErrno(err);

    const mode_bits: u16 = @as(u16, if (stat_buf.mode.owner_read) 0o400 else 0) |
        @as(u16, if (stat_buf.mode.owner_write) 0o200 else 0) |
        @as(u16, if (stat_buf.mode.owner_exec) 0o100 else 0) |
        @as(u16, if (stat_buf.mode.group_read) 0o040 else 0) |
        @as(u16, if (stat_buf.mode.group_write) 0o020 else 0) |
        @as(u16, if (stat_buf.mode.group_exec) 0o010 else 0) |
        @as(u16, if (stat_buf.mode.other_read) 0o004 else 0) |
        @as(u16, if (stat_buf.mode.other_write) 0o002 else 0) |
        @as(u16, if (stat_buf.mode.other_exec) 0o001 else 0);

    const type_bits: u16 = switch (stat_buf.file_type) {
        .Regular => 0o100000,
        .Directory => 0o040000,
        .SymLink => 0o120000,
        .CharDevice => 0o020000,
        .BlockDevice => 0o060000,
        .Pipe => 0o010000,
        .Socket => 0o140000,
    };

    var result = Statx{
        .stx_mask = abi.STATX_BASIC_STATS,
        .stx_blksize = stat_buf.block_size,
        .stx_attributes = 0,
        .stx_nlink = 1,
        .stx_uid = stat_buf.uid,
        .stx_gid = stat_buf.gid,
        .stx_mode = mode_bits | type_bits,
        .__spare0 = 0,
        .stx_ino = stat_buf.inode,
        .stx_size = stat_buf.size,
        .stx_blocks = stat_buf.blocks,
        .stx_attributes_mask = 0,
        .stx_atime = .{ .tv_sec = @intCast(stat_buf.atime), .tv_nsec = 0, .__reserved = 0 },
        .stx_btime = .{ .tv_sec = 0, .tv_nsec = 0, .__reserved = 0 },
        .stx_ctime = .{ .tv_sec = @intCast(stat_buf.ctime), .tv_nsec = 0, .__reserved = 0 },
        .stx_mtime = .{ .tv_sec = @intCast(stat_buf.mtime), .tv_nsec = 0, .__reserved = 0 },
        .stx_rdev_major = 0,
        .stx_rdev_minor = 0,
        .stx_dev_major = 0,
        .stx_dev_minor = 0,
        .stx_mnt_id = 0,
        .__spare2 = 0,
        .__spare3 = [_]u64{0} ** 12,
    };

    protection.copyToUser(statxbuf, std.mem.asBytes(&result)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_utimensat(dirfd: i32, pathname: [*]const u8, times_ptr: usize, flags: u32) i32 {
    _ = dirfd;
    _ = flags;

    if (@intFromPtr(pathname) != 0) {
        if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    }

    if (times_ptr != 0) {
        if (!protection.verifyUserPointer(times_ptr, @sizeOf(UtimensatTimespec) * 2)) return abi.EFAULT;
    }

    return 0;
}

pub fn sys_futimesat(dirfd: i32, pathname: [*]const u8, times_ptr: usize) i32 {
    _ = dirfd;

    if (@intFromPtr(pathname) != 0) {
        if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    }

    if (times_ptr != 0) {
        if (!protection.verifyUserPointer(times_ptr, 16)) return abi.EFAULT;
    }

    return 0;
}

pub fn sys_fstatat(dirfd: i32, pathname: [*]const u8, statbuf: usize, flags: u32) i32 {
    _ = flags;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    if (!protection.verifyUserPointer(statbuf, @sizeOf(vfs.FileStat))) return abi.EFAULT;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EFAULT;

    var full_path_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const full_path = resolveCwdPathOnly(dirfd, path_slice, &full_path_buf) orelse return abi.EBADF;

    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(full_path, &stat_buf) catch |err| return errno.vfsErrno(err);

    protection.copyToUser(statbuf, std.mem.asBytes(&stat_buf)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_symlinkat(target: [*]const u8, newdirfd: i32, linkpath: [*]const u8) i32 {
    _ = newdirfd;

    if (!protection.verifyUserPointer(@intFromPtr(target), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    if (!protection.verifyUserPointer(@intFromPtr(linkpath), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;

    var target_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const target_slice = protection.copyStringFromUser(&target_buffer, @intFromPtr(target)) catch return abi.EFAULT;

    var link_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const link_slice = protection.copyStringFromUser(&link_buffer, @intFromPtr(linkpath)) catch return abi.EFAULT;

    vfs.symlink(target_slice, link_slice) catch |err| return errno.vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(link_slice, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_readlinkat(dirfd: i32, pathname: [*]const u8, buf: [*]u8, bufsiz: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;
    if (!protection.verifyUserPointer(@intFromPtr(buf), bufsiz)) return abi.EFAULT;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EFAULT;

    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return abi.EBADF;

    var link_target: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const len = vfs.readlink(resolved, &link_target) catch |err| return errno.vfsErrno(err);

    const copy_len = @min(len, bufsiz);
    protection.copyToUser(@intFromPtr(buf), link_target[0..copy_len]) catch return abi.EFAULT;
    return @intCast(copy_len);
}

fn resolveDirFd(dirfd: i32, path: []const u8, buf: *[common.RESOLVED_PATH_BUFFER_SIZE]u8) ?[]const u8 {
    if (dirfd == abi.AT_FDCWD) {
        var visible_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
        return at_semantics.resolveAtPath(cwd_mod.getActualRoot(), cwd_mod.getCwd(), null, path, &visible_buf, buf) catch null;
    }

    if (dirfd < abi.FD_OFFSET) return null;
    const vfs_fd: u32 = @intCast(dirfd - abi.FD_OFFSET);
    const vnode = vfs.getVNodeFromFd(vfs_fd) catch return null;
    defer vfs.releaseVNode(vnode);
    if (vnode.file_type != .Directory) return null;

    const base_path = vfs.getNodePath(vnode) catch return null;
    var visible_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    return at_semantics.resolveAtPath(cwd_mod.getActualRoot(), cwd_mod.getCwd(), base_path, path, &visible_buf, buf) catch null;
}

fn resolveCwdPathOnly(dirfd: i32, path: []const u8, buf: *[common.RESOLVED_PATH_BUFFER_SIZE]u8) ?[]const u8 {
    return resolveDirFd(dirfd, path, buf);
}
