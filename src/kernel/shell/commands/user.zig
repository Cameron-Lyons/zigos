const process = @import("../../process/process.zig");
const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const environ = @import("../../utils/environ.zig");
const syscall_mod = @import("../../process/syscall/exports.zig");
const common = @import("../common.zig");

const printString = common.printString;
const sliceFromCStr = common.sliceFromCStr;

pub fn cd(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        if (!syscall_mod.setCwd("/")) {
            vga.print("cd: failed to change to /\n");
        }
        return;
    }

    const arg = args[0];
    var arg_len: usize = 0;
    while (arg_len < 255 and arg[arg_len] != 0) : (arg_len += 1) {}
    const arg_slice = arg[0..arg_len];
    if (arg_slice.len == 0) return;

    if (!syscall_mod.setCwd(arg_slice)) {
        vga.print("cd: no such directory: ");
        printString(arg);
        vga.print("\n");
    }
}

pub fn ln(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: ln [-s] <target> <linkname>\n");
        return;
    }

    var symlink_mode = false;
    var target_idx: usize = 0;
    var link_idx: usize = 1;

    if (streq(args[0], "-s")) {
        symlink_mode = true;
        if (args.len < 3) {
            vga.print("Usage: ln -s <target> <linkname>\n");
            return;
        }
        target_idx = 1;
        link_idx = 2;
    }

    var target_buf: [256]u8 = [_]u8{0} ** 256;
    var link_buf: [256]u8 = [_]u8{0} ** 256;
    var target_len: usize = 0;
    var link_len: usize = 0;

    while (target_len < 255 and args[target_idx][target_len] != 0) : (target_len += 1) {
        target_buf[target_len] = args[target_idx][target_len];
    }
    while (link_len < 255 and args[link_idx][link_len] != 0) : (link_len += 1) {
        link_buf[link_len] = args[link_idx][link_len];
    }

    if (symlink_mode) {
        vfs.symlink(target_buf[0..target_len], link_buf[0..link_len]) catch |err| {
            vga.print("ln: failed to create symlink: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
    } else {
        vfs.link(target_buf[0..target_len], link_buf[0..link_len]) catch |err| {
            vga.print("ln: failed to create link: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
    }
}

pub fn umask(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        if (process.current_process) |proc| {
            const mask = proc.umask;
            vga.print("0");
            vga.put_char('0' + @as(u8, @intCast((mask >> 6) & 7)));
            vga.put_char('0' + @as(u8, @intCast((mask >> 3) & 7)));
            vga.put_char('0' + @as(u8, @intCast(mask & 7)));
            vga.print("\n");
        }
        return;
    }

    const value = sliceFromCStr(args[0]);
    var parsed: u16 = 0;
    for (value) |c| {
        if (c < '0' or c > '7') {
            vga.print("umask: invalid octal number\n");
            return;
        }
        parsed = parsed * 8 + @as(u16, c - '0');
    }
    if (process.current_process) |proc| {
        proc.umask = parsed & 0o777;
    }
}

pub fn chown(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: chown <uid> <file>\n");
        return;
    }

    const uid = parseNumber(args[0]) orelse {
        vga.print("chown: invalid uid\n");
        return;
    };

    const vnode = vfs.lookupPathRetained(sliceFromCStr(args[1])) catch {
        vga.print("chown: file not found\n");
        return;
    };
    defer vfs.releaseLookupVNode(vnode);

    vfs.chownVNode(vnode, @intCast(uid), vnode.gid) catch {
        vga.print("chown: operation failed\n");
    };
}

pub fn chgrp(args: []const [*:0]const u8) void {
    if (args.len < 2) {
        vga.print("Usage: chgrp <gid> <file>\n");
        return;
    }

    const gid = parseNumber(args[0]) orelse {
        vga.print("chgrp: invalid gid\n");
        return;
    };

    const vnode = vfs.lookupPathRetained(sliceFromCStr(args[1])) catch {
        vga.print("chgrp: file not found\n");
        return;
    };
    defer vfs.releaseLookupVNode(vnode);

    vfs.chownVNode(vnode, vnode.uid, @intCast(gid)) catch {
        vga.print("chgrp: operation failed\n");
    };
}

pub fn exportVar(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        environ.printAll();
        return;
    }

    const arg = sliceFromCStr(args[0]);
    var eq_pos: ?usize = null;
    for (arg, 0..) |c, i| {
        if (c == '=') {
            eq_pos = i;
            break;
        }
    }

    if (eq_pos) |pos| {
        const name = arg[0..pos];
        const value = arg[pos + 1 ..];
        environ.setVar(name, value) catch |err| {
            vga.print("export: ");
            switch (err) {
                error.InvalidName => vga.print("invalid variable name\n"),
                error.ValueTooLong => vga.print("value too long\n"),
                error.TooManyVars => vga.print("too many environment variables\n"),
            }
        };
        return;
    }

    vga.print("Usage: export VAR=value\n");
}

pub fn unset(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: unset VAR\n");
        return;
    }

    environ.unsetVar(sliceFromCStr(args[0]));
}

fn streq(a: [*:0]const u8, b: [*:0]const u8) bool {
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return a[i] == 0 and b[i] == 0;
}

fn parseNumber(str: [*:0]const u8) ?u32 {
    var result: u32 = 0;
    var i: usize = 0;

    if (str[0] == 0) return null;

    while (str[i] != 0) : (i += 1) {
        if (str[i] < '0' or str[i] > '9') return null;
        result = result * 10 + (str[i] - '0');
    }

    return result;
}
