const std = @import("std");
const abi = @import("abi.zig");
const common = @import("common.zig");
const cwd = @import("cwd.zig");
const errno = @import("errno.zig");
const credentials = @import("../credentials.zig");
const process = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const support = @import("support.zig");
const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const x86 = @import("../../../arch/x86.zig");

const UtsName = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
};

var system_hostname: [65]u8 = blk: {
    var name = [_]u8{0} ** 65;
    name[0] = 'z';
    name[1] = 'i';
    name[2] = 'g';
    name[3] = 'o';
    name[4] = 's';
    break :blk name;
};
var hostname_len: usize = 5;

pub fn getHostname() []const u8 {
    return system_hostname[0..hostname_len];
}

pub fn setHostname(name: []const u8) void {
    const len = @min(name.len, 64);
    @memset(&system_hostname, 0);
    @memcpy(system_hostname[0..len], name[0..len]);
    hostname_len = len;
}

pub fn sys_gethostname(name_addr: usize, len: usize) i32 {
    if (len == 0) return abi.EINVAL;
    if (!protection.verifyUserPointer(name_addr, len)) return abi.EINVAL;

    const copy_len = @min(len - 1, hostname_len);
    var buf: [65]u8 = undefined;
    @memcpy(buf[0..copy_len], system_hostname[0..copy_len]);
    buf[copy_len] = 0;

    protection.copyToUser(name_addr, buf[0 .. copy_len + 1]) catch return abi.EINVAL;
    return 0;
}

pub fn sys_sethostname(name_addr: usize, len: usize) i32 {
    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return abi.EPERM;
        }
    }

    if (len > 64) return abi.EINVAL;
    if (!protection.verifyUserPointer(name_addr, len)) return abi.EINVAL;

    var buf: [64]u8 = undefined;
    protection.copyFromUser(buf[0..len], name_addr) catch return abi.EINVAL;

    setHostname(buf[0..len]);
    return 0;
}

pub fn sys_uname(buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(UtsName))) return abi.EINVAL;

    var buf: UtsName = undefined;
    fillField(&buf.sysname, "ZigOS");
    fillField(&buf.nodename, system_hostname[0..hostname_len]);
    fillField(&buf.release, "0.1.0");
    fillField(&buf.version, "ZigOS 0.1.0 (Zig 0.16.0-dev)");
    fillField(&buf.machine, "i386");

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return abi.EINVAL;
    return 0;
}

fn fillField(dest: *[65]u8, src: []const u8) void {
    @memset(dest, 0);
    const len = @min(src.len, 64);
    @memcpy(dest[0..len], src[0..len]);
}

pub fn sys_chroot(path: [*]const u8) i32 {
    const proc = process.getEffectiveCurrent() orelse return abi.ESRCH;
    if (proc.creds.euid != 0) return abi.EPERM;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var resolved_buf: [common.RESOLVED_PATH_BUFFER_SIZE]u8 = undefined;
    const resolved = support.resolveUserPathFromPointer(path, &path_buffer, &resolved_buf) catch |err| {
        return support.errnoFromResolvedUserPathError(err, abi.EFAULT);
    };

    const vnode = vfs.lookupPathRetained(resolved) catch |err| return errno.vfsErrno(err);
    defer vfs.releaseLookupVNode(vnode);
    if (vnode.file_type != .Directory) return abi.ENOTDIR;

    if (!cwd.setChroot(resolved)) return abi.ENAMETOOLONG;

    return 0;
}

pub fn sys_mount(source: usize, target: usize, fstype: usize, mountflags: usize, data: usize) i32 {
    _ = data;

    const proc = process.current_process orelse return abi.ESRCH;
    if (proc.creds.euid != 0) return abi.EPERM;

    if (!protection.verifyUserPointer(fstype, 32)) return abi.EFAULT;

    var source_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var target_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    var fstype_buf: [32]u8 = undefined;

    const source_path = support.copyUserPathFromAddress(source, &source_buf) catch return abi.EFAULT;
    const target_path = support.copyUserPathFromAddress(target, &target_buf) catch return abi.EFAULT;
    const fstype_str = protection.copyStringFromUser(&fstype_buf, fstype) catch return abi.EFAULT;

    vfs.mount(source_path, target_path, fstype_str, @truncate(mountflags)) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_umount2(target: [*]const u8, flags: u32) i32 {
    _ = flags;

    const proc = process.current_process orelse return abi.ESRCH;
    if (proc.creds.euid != 0) return abi.EPERM;

    var target_buf: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const target_path = support.copyUserPathFromPointer(target, &target_buf) catch return abi.EFAULT;

    vfs.unmount(target_path) catch |err| return errno.vfsErrno(err);
    return 0;
}

pub fn sys_swapon(path: [*]const u8, swapflags: u32) i32 {
    _ = path;
    _ = swapflags;
    return abi.EPERM;
}

pub fn sys_swapoff(path: [*]const u8) i32 {
    _ = path;
    return abi.EPERM;
}

pub fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, arg: usize) i32 {
    _ = arg;

    if (magic1 != abi.LINUX_REBOOT_MAGIC1) return abi.EINVAL;
    if (magic2 != abi.LINUX_REBOOT_MAGIC2 and magic2 != 0x85072010 and magic2 != 0x5121996 and magic2 != 0x16041998) return abi.EINVAL;

    switch (cmd) {
        abi.LINUX_REBOOT_CMD_RESTART, abi.LINUX_REBOOT_CMD_HALT, abi.LINUX_REBOOT_CMD_POWER_OFF => {
            vga.print("\nSystem halting...\n");
            x86.hlt();
            while (true) {
                x86.hlt();
            }
        },
        else => return abi.EINVAL,
    }
}
