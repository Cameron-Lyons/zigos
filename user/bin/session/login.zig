const std = @import("std");
const account = @import("account");
const cstr = @import("cstr");
const envutil = @import("envutil");
const fsutil = @import("fsutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const MAX_LINE = 128;
const MAX_PATH = 256;
const MAX_ENV = 8;
const MAX_LOGIN_ATTEMPTS = 3;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    var passwd_buffer: [account.MAX_FILE]u8 = undefined;
    const passwd_data = account.loadPasswd(&passwd_buffer) orelse {
        stdio.eputs("login: failed to read /etc/passwd\n");
        return 1;
    };

    var login_buffer: [MAX_LINE]u8 = undefined;
    var password_buffer: [MAX_LINE]u8 = undefined;
    var used_arg = false;
    var attempts: usize = 0;

    while (true) {
        const username = blk: {
            if (!used_arg and argc >= 2) {
                used_arg = true;
                break :blk cstr.optionalSlice(argv[1]);
            }

            stdio.puts("login: ");
            const len = readLine(&login_buffer) orelse return 0;
            if (len == 0) continue;
            break :blk login_buffer[0..len];
        };

        const user_account = account.findByName(passwd_data, username) orelse {
            stdio.eprint("login: unknown user: {s}\n", .{username});
            if (used_arg and argc >= 2) return 1;
            attempts += 1;
            if (attempts >= MAX_LOGIN_ATTEMPTS) return 1;
            continue;
        };

        stdio.puts("password: ");
        const password_len = readPassword(&password_buffer) orelse return 0;
        stdio.puts("\n");

        if (!account.verifyPassword(user_account, password_buffer[0..password_len])) {
            stdio.eputs("login: authentication failed\n");
            attempts += 1;
            if (used_arg and argc >= 2) return 1;
            if (attempts >= MAX_LOGIN_ATTEMPTS) return 1;
            continue;
        }

        return startSession(user_account);
    }
}

fn startSession(user_account: account.Account) i32 {
    var home_buffer: [MAX_PATH]u8 = undefined;
    var shell_buffer: [MAX_PATH]u8 = undefined;

    const home_path = toCString(user_account.home, &home_buffer) orelse {
        stdio.eputs("login: HOME path is too long\n");
        return 1;
    };
    const shell_path = toCString(user_account.shell, &shell_buffer) orelse {
        stdio.eputs("login: shell path is too long\n");
        return 1;
    };

    if (syscall.setgid(user_account.gid) < 0) {
        stdio.eputs("login: setgid failed\n");
        return 1;
    }
    if (syscall.setuid(user_account.uid) < 0) {
        stdio.eputs("login: setuid failed\n");
        return 1;
    }

    if (syscall.chdir(home_path) < 0) {
        stdio.eprint("login: failed to enter {s}\n", .{user_account.home});
    }

    printMotd();
    stdio.print("Welcome {s}\n", .{user_account.name});

    var argv: [2]?[*:0]const u8 = [_]?[*:0]const u8{ shell_path, null };
    var env_storage: [MAX_ENV][MAX_PATH]u8 = [_][MAX_PATH]u8{[_]u8{0} ** MAX_PATH} ** MAX_ENV;
    var session_env: [MAX_ENV + 1]?[*:0]const u8 = [_]?[*:0]const u8{null} ** (MAX_ENV + 1);
    const env_count = buildSessionEnv(user_account, &env_storage, &session_env);
    session_env[env_count] = null;

    _ = syscall.execve(shell_path, &argv, &session_env);
    stdio.eprint("login: failed to exec {s}\n", .{user_account.shell});
    return 1;
}

fn buildSessionEnv(user_account: account.Account, env_storage: *[MAX_ENV][MAX_PATH]u8, session_env: *[MAX_ENV + 1]?[*:0]const u8) usize {
    var count: usize = 0;
    count += appendEnv(env_storage, session_env, count, "HOME", user_account.home);
    count += appendEnv(env_storage, session_env, count, "PATH", envutil.default_path);
    count += appendEnv(env_storage, session_env, count, "SHELL", user_account.shell);
    count += appendEnv(env_storage, session_env, count, "TERM", "vga");
    count += appendEnv(env_storage, session_env, count, "USER", user_account.name);
    return count;
}

fn appendEnv(
    env_storage: *[MAX_ENV][MAX_PATH]u8,
    session_env: *[MAX_ENV + 1]?[*:0]const u8,
    index: usize,
    name: []const u8,
    value: []const u8,
) usize {
    if (index >= env_storage.len or name.len + value.len + 2 > env_storage[index].len) return 0;

    @memcpy(env_storage[index][0..name.len], name);
    env_storage[index][name.len] = '=';
    @memcpy(env_storage[index][name.len + 1 .. name.len + 1 + value.len], value);
    env_storage[index][name.len + 1 + value.len] = 0;
    session_env[index] = @ptrCast(env_storage[index][0..].ptr);
    return 1;
}

fn printMotd() void {
    var motd_buffer: [account.MAX_FILE]u8 = undefined;
    const motd = fsutil.readFile("/etc/motd", &motd_buffer) catch return;
    stdio.writeAll(syscall.STDOUT, motd);
    if (motd.len == 0 or motd[motd.len - 1] != '\n') {
        stdio.puts("\n");
    }
}

fn readLine(buffer: []u8) ?usize {
    var len: usize = 0;
    var ch_buf: [1]u8 = undefined;

    while (len + 1 < buffer.len) {
        const rc = syscall.read(syscall.STDIN, ch_buf[0..]);
        if (rc <= 0) return null;

        const ch = ch_buf[0];
        switch (ch) {
            '\r' => {},
            '\n' => break,
            4 => {
                if (len == 0) return null;
                break;
            },
            '\x08' => {
                if (len > 0) len -= 1;
            },
            else => {
                buffer[len] = ch;
                len += 1;
            },
        }
    }

    buffer[len] = 0;
    return len;
}

fn readPassword(buffer: []u8) ?usize {
    var termios = syscall.Termios{
        .c_iflag = 0,
        .c_oflag = 0,
        .c_cflag = 0,
        .c_lflag = 0,
        .c_line = 0,
        .c_cc = [_]u8{0} ** 19,
    };
    const had_termios = syscall.ioctl(syscall.STDIN, syscall.TCGETS, @intFromPtr(&termios)) == 0;
    var old_lflag: u32 = 0;
    if (had_termios) {
        old_lflag = termios.c_lflag;
        termios.c_lflag &= ~@as(u32, syscall.TTY_LFLAG_ECHO);
        _ = syscall.ioctl(syscall.STDIN, syscall.TCSETS, @intFromPtr(&termios));
    }
    defer if (had_termios) {
        termios.c_lflag = old_lflag;
        _ = syscall.ioctl(syscall.STDIN, syscall.TCSETS, @intFromPtr(&termios));
    };

    return readLine(buffer);
}

fn toCString(slice: []const u8, buffer: []u8) ?[*:0]const u8 {
    if (slice.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..slice.len], slice);
    buffer[slice.len] = 0;
    return @ptrCast(buffer.ptr);
}
