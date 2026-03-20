const std = @import("std");
const cstr = @import("cstr");
const envutil = @import("envutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const MAX_LINE = 256;
const MAX_ARGS = 32;
const MAX_PATH = 256;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    if (argc >= 3 and std.mem.eql(u8, cstr.optionalSlice(argv[1]), "-c")) {
        var command_buffer: [MAX_LINE]u8 = undefined;
        const command = cstr.optionalSlice(argv[2]);
        if (command.len >= command_buffer.len) {
            stdio.eputs("sh: command line too long\n");
            return 1;
        }

        @memcpy(command_buffer[0..command.len], command);
        command_buffer[command.len] = 0;
        return runCommand(command_buffer[0..command.len], envp);
    }

    return runInteractive(envp);
}

fn runInteractive(envp: [*]const ?[*:0]const u8) i32 {
    var line_buffer: [MAX_LINE]u8 = undefined;

    while (true) {
        printPrompt(envp);
        const maybe_len = readLine(&line_buffer) orelse {
            stdio.puts("\n");
            return 0;
        };

        const line = line_buffer[0..maybe_len];
        const exit_code = runCommand(line, envp);
        if (exit_code == -255) {
            return 0;
        }
    }
}

fn runCommand(line: []u8, envp: [*]const ?[*:0]const u8) i32 {
    var argv: [MAX_ARGS + 1]?[*:0]const u8 = [_]?[*:0]const u8{null} ** (MAX_ARGS + 1);
    const argc = tokenizeLine(line, &argv);
    if (argc == 0) return 0;

    if (tryBuiltin(argc, &argv, envp)) |code| {
        return code;
    }

    const pid = syscall.spawnve(argv[0].?, @ptrCast(&argv[0]), envp);
    if (syscall.isError(pid)) {
        stdio.eprint("sh: failed to spawn {s}\n", .{cstr.optionalSlice(argv[0])});
        return 1;
    }

    var status: i32 = 0;
    const waited = syscall.wait4(pid, &status, 0, null);
    if (syscall.isError(waited)) {
        stdio.eputs("sh: wait4 failed\n");
        return 1;
    }

    return status;
}

fn tryBuiltin(argc: usize, argv: *[MAX_ARGS + 1]?[*:0]const u8, envp: [*]const ?[*:0]const u8) ?i32 {
    const command = cstr.optionalSlice(argv[0]);

    if (std.mem.eql(u8, command, "exit")) {
        if (argc >= 2) {
            return std.fmt.parseInt(i32, cstr.optionalSlice(argv[1]), 10) catch 1;
        }
        return -255;
    }

    if (std.mem.eql(u8, command, "cd")) {
        return builtinCd(argc, argv, envp);
    }

    if (std.mem.eql(u8, command, "pwd")) {
        return builtinPwd();
    }

    return null;
}

fn builtinCd(argc: usize, argv: *[MAX_ARGS + 1]?[*:0]const u8, envp: [*]const ?[*:0]const u8) i32 {
    if (argc >= 2) {
        const rc = syscall.chdir(argv[1].?);
        if (syscall.isError(rc)) {
            stdio.eputs("sh: cd failed\n");
            return 1;
        }
        return 0;
    }

    const home = envutil.lookup(envp, "HOME") orelse "/";
    var home_buffer: [MAX_PATH]u8 = undefined;
    if (home.len >= home_buffer.len) {
        stdio.eputs("sh: HOME is too long\n");
        return 1;
    }

    @memcpy(home_buffer[0..home.len], home);
    home_buffer[home.len] = 0;
    const rc = syscall.chdir(@ptrCast(home_buffer[0..].ptr));
    if (syscall.isError(rc)) {
        stdio.eputs("sh: cd failed\n");
        return 1;
    }
    return 0;
}

fn builtinPwd() i32 {
    var cwd_buffer: [MAX_PATH]u8 = undefined;
    const rc = syscall.getcwd(&cwd_buffer);
    if (syscall.isError(rc)) {
        stdio.eputs("sh: pwd failed\n");
        return 1;
    }

    stdio.writeAll(syscall.STDOUT, cwd_buffer[0..@intCast(rc)]);
    stdio.puts("\n");
    return 0;
}

fn tokenizeLine(line: []u8, argv: *[MAX_ARGS + 1]?[*:0]const u8) usize {
    argv.* = [_]?[*:0]const u8{null} ** (MAX_ARGS + 1);

    var count: usize = 0;
    var cursor: usize = 0;
    while (cursor < line.len and count < MAX_ARGS) {
        while (cursor < line.len and isSpace(line[cursor])) : (cursor += 1) {}
        if (cursor >= line.len) break;

        const start = cursor;
        while (cursor < line.len and !isSpace(line[cursor])) : (cursor += 1) {}
        if (cursor < line.len) {
            line[cursor] = 0;
            cursor += 1;
        }

        argv[count] = @ptrCast(&line[start]);
        count += 1;
    }

    return count;
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

fn printPrompt(envp: [*]const ?[*:0]const u8) void {
    const user = envutil.lookup(envp, "USER") orelse "user";
    var cwd_buffer: [MAX_PATH]u8 = undefined;
    const cwd = blk: {
        const rc = syscall.getcwd(&cwd_buffer);
        if (syscall.isError(rc)) break :blk "/";
        break :blk cwd_buffer[0..@intCast(rc)];
    };

    stdio.print("{s}:{s}$ ", .{ user, cwd });
}

fn isSpace(char: u8) bool {
    return char == ' ' or char == '\t';
}
