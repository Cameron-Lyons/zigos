const std = @import("std");
const abi = @import("abi.zig");
const common = @import("common.zig");
const errno = @import("errno.zig");
const syscall_event = @import("event.zig");
const support = @import("support.zig");
const credentials = @import("../credentials.zig");
const process_mod = @import("../process.zig");
const network = @import("../../net/network.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

const vfsErrno = errno.vfsErrno;
const RANDOM_FILL_BUFFER_SIZE = support.RANDOM_FILL_BUFFER_SIZE;
const copyUserPathFromPointer = support.copyUserPathFromPointer;
const resolveUserPathFromPointer = support.resolveUserPathFromPointer;
const errnoFromResolvedUserPathError = support.errnoFromResolvedUserPathError;
const Sysinfo = support.Sysinfo;
const syntheticSysinfo = support.syntheticSysinfo;
const fillRandomBytes = support.fillRandomBytes;

pub fn sys_getuid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.creds.uid);
    }
    return 0;
}

pub fn sys_getgid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.creds.gid);
    }
    return 0;
}

pub fn sys_setuid(uid: u16) i32 {
    const proc = process_mod.current_process orelse return abi.ESRCH;
    if (proc.creds.euid == 0 or proc.creds.uid == uid) {
        proc.creds.uid = uid;
        proc.creds.euid = uid;
        return 0;
    }
    return abi.EPERM;
}

pub fn sys_setgid(gid: u16) i32 {
    const proc = process_mod.current_process orelse return abi.ESRCH;
    if (proc.creds.euid == 0 or proc.creds.gid == gid) {
        proc.creds.gid = gid;
        proc.creds.egid = gid;
        return 0;
    }
    return abi.EPERM;
}

pub fn sys_chown(pathname: [*]const u8, uid: u16, gid: u16) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) {
        return abi.EINVAL;
    }

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    if (process_mod.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return abi.EPERM;
        }
    }

    vfs.chown(path_slice, uid, gid) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(path_slice, abi.IN_ATTRIB, 0);
    return 0;
}

pub fn sys_access(pathname: [*]const u8, mode: u32) i32 {
    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveUserPathFromPointer(pathname, &kernel_buffer, &resolved_buf) catch |err| {
        return errnoFromResolvedUserPathError(err, abi.EINVAL);
    };

    const vnode = vfs.lookupPathRetained(resolved) catch return abi.ENOENT;
    defer vfs.releaseLookupVNode(vnode);

    if (mode == 0) return 0;

    if (process_mod.current_process) |proc| {
        var access_bits: u3 = 0;
        if (mode & 4 != 0) access_bits |= 4;
        if (mode & 2 != 0) access_bits |= 2;
        if (mode & 1 != 0) access_bits |= 1;
        if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access_bits)) {
            return abi.EACCES;
        }
    }

    return 0;
}

pub fn sys_chmod(pathname: [*]const u8, mode: u32) i32 {
    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveUserPathFromPointer(pathname, &kernel_buffer, &resolved_buf) catch |err| {
        return errnoFromResolvedUserPathError(err, abi.EINVAL);
    };

    vfs.chmod(resolved, common.fileModeFromBits(mode)) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(resolved, abi.IN_ATTRIB, 0);
    return 0;
}

pub fn sys_fchmod(fd: i32, mode: u32) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    vfs.fchmod(vfs_fd, common.fileModeFromBits(mode)) catch |err| return vfsErrno(err);
    return 0;
}

pub fn sys_ftruncate(fd: i32, length: usize) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;
    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);

    vfs.ftruncate(vfs_fd, length) catch |err| return vfsErrno(err);
    return 0;
}

pub fn sys_symlink(target: [*]const u8, linkpath: [*]const u8) i32 {
    var target_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var link_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;

    const target_slice = copyUserPathFromPointer(target, &target_buf) catch return abi.EINVAL;
    const link_slice = copyUserPathFromPointer(linkpath, &link_buf) catch return abi.EINVAL;

    vfs.symlink(target_slice, link_slice) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(link_slice, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_link(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    var old_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var new_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;

    const old_slice = copyUserPathFromPointer(oldpath, &old_buf) catch return abi.EINVAL;
    const new_slice = copyUserPathFromPointer(newpath, &new_buf) catch return abi.EINVAL;

    vfs.link(old_slice, new_slice) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(new_slice, abi.IN_CREATE, abi.IN_CREATE);
    return 0;
}

pub fn sys_readlink(pathname: [*]const u8, buf: [*]u8, buf_size: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), buf_size)) return abi.EINVAL;

    var path_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveUserPathFromPointer(pathname, &path_buf, &resolved_buf) catch |err| {
        return errnoFromResolvedUserPathError(err, abi.EINVAL);
    };

    var kernel_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const read_size = @min(buf_size, kernel_buf.len);
    const link_len = vfs.readlink(resolved, kernel_buf[0..read_size]) catch |err| return vfsErrno(err);

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0..link_len]) catch return abi.EINVAL;
    return @intCast(link_len);
}

pub fn sys_umask(mask: u16) i32 {
    const proc = process_mod.current_process orelse return abi.ESRCH;
    const old = proc.umask;
    proc.umask = mask & 0o777;
    return @intCast(old);
}

pub fn sys_truncate(pathname: [*]const u8, length: usize) i32 {
    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = copyUserPathFromPointer(pathname, &kernel_buffer) catch return abi.EINVAL;

    vfs.truncate(path_slice, length) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(path_slice, abi.IN_MODIFY, 0);
    return 0;
}

pub fn sys_fchown(fd: i32, uid: u16, gid: u16) i32 {
    if (fd < abi.FD_OFFSET) return abi.EBADF;

    if (process_mod.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return abi.EPERM;
        }
    }

    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
    vfs.fchown(vfs_fd, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

pub fn sys_lstat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) return abi.EINVAL;

    var kernel_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = resolveUserPathFromPointer(pathname, &kernel_buffer, &resolved_buf) catch |err| {
        return errnoFromResolvedUserPathError(err, abi.EINVAL);
    };

    var stat_buf: vfs.FileStat = undefined;
    vfs.lstat(resolved, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_geteuid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.creds.euid);
    }
    return 0;
}

pub fn sys_getegid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.creds.egid);
    }
    return 0;
}

pub fn sys_mkfifo(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EINVAL;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EINVAL;

    vfs.mkfifo(path_slice, common.fileModeFromBits(mode)) catch |err| return vfsErrno(err);
    return 0;
}

pub fn sys_mknod(pathname: [*]const u8, mode: u32, dev: u32) i32 {
    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = copyUserPathFromPointer(pathname, &path_buffer) catch return abi.EINVAL;

    const file_type = mode & abi.S_IFMT;
    const perms = mode & 0o777;
    const mode_struct = common.fileModeFromBits(perms);

    if (file_type == abi.S_IFIFO) {
        vfs.mkfifo(path_slice, mode_struct) catch |err| return vfsErrno(err);
        return 0;
    }

    if (file_type == abi.S_IFREG) {
        vfs.create(path_slice, mode_struct) catch |err| return vfsErrno(err);
        return 0;
    }

    _ = dev;
    return abi.EINVAL;
}

pub fn sys_getrandom(buf: [*]u8, buflen: usize, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), buflen)) return abi.EFAULT;
    _ = flags;

    var kernel_buffer: [RANDOM_FILL_BUFFER_SIZE]u8 = undefined;
    var written: usize = 0;

    while (written < buflen) {
        const chunk_size = @min(buflen - written, kernel_buffer.len);
        fillRandomBytes(kernel_buffer[0..chunk_size]);
        protection.copyToUser(@intFromPtr(buf) + written, kernel_buffer[0..chunk_size]) catch return abi.EFAULT;
        written += chunk_size;
    }

    return @intCast(written);
}

pub fn sys_sysinfo(info_ptr: usize) i32 {
    if (!protection.verifyUserPointer(info_ptr, @sizeOf(Sysinfo))) return abi.EFAULT;

    const info = syntheticSysinfo();

    protection.copyToUser(info_ptr, std.mem.asBytes(&info)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_getprocs(buffer_ptr: usize, capacity: usize) i32 {
    if (capacity == 0) return 0;
    if (!protection.verifyUserPointer(buffer_ptr, capacity * @sizeOf(abi.ProcInfo))) return abi.EFAULT;

    var proc = process_mod.getProcessList();
    var index: usize = 0;
    while (proc) |current| : (proc = current.next) {
        if (index >= capacity) break;

        var info = abi.ProcInfo{
            .pid = current.pid,
            .parent_pid = current.parent_pid,
            .state = @intFromEnum(current.state),
            ._padding = .{ 0, 0, 0 },
            .name = [_]u8{0} ** 64,
        };
        @memcpy(&info.name, &current.name);

        protection.copyToUser(buffer_ptr + index * @sizeOf(abi.ProcInfo), std.mem.asBytes(&info)) catch return abi.EFAULT;
        index += 1;
    }

    return @intCast(index);
}

pub fn sys_ping(ipv4_addr: u32) i32 {
    network.ping(ipv4_addr);
    return 0;
}
