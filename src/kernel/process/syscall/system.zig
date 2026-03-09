const std = @import("std");
const abi = @import("abi.zig");
const credentials = @import("../credentials.zig");
const process = @import("../process.zig");
const protection = @import("../../memory/protection.zig");

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
