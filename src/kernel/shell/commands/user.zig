const process = @import("../../process/process.zig");
const timer = @import("../../timer/timer.zig");
const vfs = @import("../../fs/vfs.zig");
const vga = @import("../../drivers/vga.zig");
const environ = @import("../../utils/environ.zig");
const syscall_mod = @import("../../process/syscall.zig");

pub fn uname(args: []const [*:0]const u8) void {
    var show_all = false;
    var show_sysname = false;
    var show_nodename = false;
    var show_release = false;
    var show_version = false;
    var show_machine = false;

    if (args.len == 0) {
        show_sysname = true;
    } else {
        for (args) |arg| {
            if (streq(arg, "-a") or streq(arg, "--all")) {
                show_all = true;
            } else if (streq(arg, "-s") or streq(arg, "--kernel-name")) {
                show_sysname = true;
            } else if (streq(arg, "-n") or streq(arg, "--nodename")) {
                show_nodename = true;
            } else if (streq(arg, "-r") or streq(arg, "--kernel-release")) {
                show_release = true;
            } else if (streq(arg, "-v") or streq(arg, "--kernel-version")) {
                show_version = true;
            } else if (streq(arg, "-m") or streq(arg, "--machine")) {
                show_machine = true;
            }
        }
    }

    var first = true;
    if (show_all or show_sysname) {
        vga.print("ZigOS");
        first = false;
    }
    if (show_all or show_nodename) {
        if (!first) vga.print(" ");
        vga.print(syscall_mod.getHostname());
        first = false;
    }
    if (show_all or show_release) {
        if (!first) vga.print(" ");
        vga.print("0.1.0");
        first = false;
    }
    if (show_all or show_version) {
        if (!first) vga.print(" ");
        vga.print("ZigOS 0.1.0");
        first = false;
    }
    if (show_all or show_machine) {
        if (!first) vga.print(" ");
        vga.print("i386");
        first = false;
    }
    if (first) {
        vga.print("ZigOS");
    }
    vga.print("\n");
}

pub fn whoami() void {
    vga.print("root\n");
}

pub fn pwd() void {
    vga.print(syscall_mod.getCwd());
    vga.print("\n");
}

pub fn cd(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        if (!syscall_mod.setCwd("/")) {
            vga.print("cd: failed to change to /\n");
        }
        return;
    }

    var path_buf: [256]u8 = [_]u8{0} ** 256;
    const arg = args[0];
    var arg_len: usize = 0;
    while (arg_len < 255 and arg[arg_len] != 0) : (arg_len += 1) {}
    const arg_slice = arg[0..arg_len];
    if (arg_slice.len == 0) return;

    if (arg_slice[0] == '/') {
        @memcpy(path_buf[0..arg_len], arg_slice);
        if (!syscall_mod.setCwd(path_buf[0..arg_len])) {
            vga.print("cd: no such directory: ");
            printString(arg);
            vga.print("\n");
        }
        return;
    }

    const cwd = syscall_mod.getCwd();
    var path_len: usize = 0;
    if (cwd.len >= path_buf.len) {
        vga.print("cd: path too long\n");
        return;
    }

    @memcpy(path_buf[0..cwd.len], cwd);
    path_len = cwd.len;
    if (path_len > 1) {
        path_buf[path_len] = '/';
        path_len += 1;
    }
    if (path_len + arg_len > path_buf.len) {
        vga.print("cd: path too long\n");
        return;
    }

    @memcpy(path_buf[path_len .. path_len + arg_len], arg_slice);
    path_len += arg_len;
    if (!syscall_mod.setCwd(path_buf[0..path_len])) {
        vga.print("cd: no such directory: ");
        printString(arg);
        vga.print("\n");
    }
}

pub fn id() void {
    if (process.current_process) |proc| {
        vga.print("uid=");
        printNumber(@as(usize, proc.creds.uid));
        vga.print("(");
        if (proc.creds.uid == 0) vga.print("root") else vga.print("user");
        vga.print(") gid=");
        printNumber(@as(usize, proc.creds.gid));
        vga.print("(");
        if (proc.creds.gid == 0) vga.print("root") else vga.print("users");
        vga.print(") euid=");
        printNumber(@as(usize, proc.creds.euid));
        vga.print(" egid=");
        printNumber(@as(usize, proc.creds.egid));
        vga.print("\n");
    }
}

pub fn date() void {
    const ticks = timer.getTicks();
    const total_secs = ticks / 100;
    const hours = total_secs / 3600;
    const mins = (total_secs % 3600) / 60;
    const secs = total_secs % 60;
    vga.print("System uptime: ");
    if (hours > 0) {
        printNumber(@intCast(hours));
        vga.print("h ");
    }
    printNumber(@intCast(mins));
    vga.print("m ");
    printNumber(@intCast(secs));
    vga.print("s (");
    printNumber(@intCast(ticks));
    vga.print(" ticks)\n");
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

pub fn hostname(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print(syscall_mod.getHostname());
        vga.print("\n");
        return;
    }

    syscall_mod.setHostname(sliceFromCStr(args[0]));
}

pub fn sleep(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: sleep <seconds>\n");
        return;
    }

    const secs = parseNumber(args[0]) orelse {
        vga.print("sleep: invalid number\n");
        return;
    };

    const start = timer.getTicks();
    const target = start + @as(u64, secs) * 100;
    while (timer.getTicks() < target) {
        process.yield();
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

    const vnode = vfs.lookupPath(sliceFromCStr(args[1])) catch {
        vga.print("chown: file not found\n");
        return;
    };

    vnode.ops.chown(vnode, @intCast(uid), vnode.gid) catch {
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

    const vnode = vfs.lookupPath(sliceFromCStr(args[1])) catch {
        vga.print("chgrp: file not found\n");
        return;
    };

    vnode.ops.chown(vnode, vnode.uid, @intCast(gid)) catch {
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

pub fn env() void {
    environ.printAll();
}

fn streq(a: [*:0]const u8, b: [*:0]const u8) bool {
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return a[i] == 0 and b[i] == 0;
}

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
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

fn printNumber(num: usize) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast((n % 10) + '0'));
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}
