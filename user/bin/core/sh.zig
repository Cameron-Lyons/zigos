const std = @import("std");
const cstr = @import("cstr");
const envutil = @import("envutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const MAX_LINE = 512;
const MAX_ARGS = 32;
const MAX_STAGES = 8;
const MAX_PATH = 256;
const MAX_TEMP_PATH = 64;
const MAX_PROC_INFO = 64;
const PROCESS_STATE_TERMINATED: u8 = 3;

const ParseError = error{
    UnterminatedQuote,
    TrailingEscape,
    TooManyArgs,
    TooManyStages,
    MissingCommand,
    MissingPath,
    DuplicateRedirect,
    UnsupportedRedirectionLayout,
};

const PendingRedirect = struct {
    fd: i32,
    append: bool,
};

const Stage = struct {
    argv: [MAX_ARGS + 1]?[*:0]const u8 = [_]?[*:0]const u8{null} ** (MAX_ARGS + 1),
    argc: usize = 0,
    stdin_path: ?[*:0]const u8 = null,
    stdout_path: ?[*:0]const u8 = null,
    stdout_append: bool = false,
    stderr_path: ?[*:0]const u8 = null,
    stderr_append: bool = false,
};

const Pipeline = struct {
    stages: [MAX_STAGES]Stage = [_]Stage{Stage{}} ** MAX_STAGES,
    stage_count: usize = 0,
};

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
        return runCommand(command_buffer[0 .. command.len + 1], envp, true);
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

        _ = runCommand(line_buffer[0 .. maybe_len + 1], envp, false);
    }
}

fn runCommand(line: []u8, envp: [*]const ?[*:0]const u8, exec_simple_external: bool) i32 {
    var pipeline = Pipeline{};
    parsePipeline(line, &pipeline) catch |err| {
        printParseError(err);
        return 1;
    };
    if (pipeline.stage_count == 0) return 0;

    const first_stage = &pipeline.stages[0];
    if (pipeline.stage_count == 1 and !stageHasRedirection(first_stage)) {
        if (tryBuiltin(first_stage, envp)) |code| {
            return code;
        }

        if (exec_simple_external) {
            return execSimpleStage(first_stage, envp);
        }

        return spawnStage(first_stage, envp);
    }

    if (isParentOnlyBuiltin(cstr.optionalSlice(first_stage.argv[0]))) {
        stdio.eprint("sh: {s}: builtin requires a simple command\n", .{cstr.optionalSlice(first_stage.argv[0])});
        return 1;
    }

    return runPipeline(&pipeline, envp);
}

fn parsePipeline(line: []u8, pipeline: *Pipeline) ParseError!void {
    pipeline.* = Pipeline{};
    pipeline.stage_count = 1;

    var stage_idx: usize = 0;
    var stage = &pipeline.stages[stage_idx];
    var token_start: ?usize = null;
    var pending_redirect: ?PendingRedirect = null;
    var in_single_quote = false;
    var in_double_quote = false;
    var escaping = false;
    var saw_content = false;
    var write_idx: usize = 0;
    var read_idx: usize = 0;

    while (read_idx < line.len and line[read_idx] != 0) : (read_idx += 1) {
        const char = line[read_idx];

        if (escaping) {
            if (token_start == null) token_start = write_idx;
            line[write_idx] = char;
            write_idx += 1;
            escaping = false;
            saw_content = true;
            continue;
        }

        if (in_single_quote) {
            if (char == '\'') {
                in_single_quote = false;
            } else {
                line[write_idx] = char;
                write_idx += 1;
            }
            saw_content = true;
            continue;
        }

        if (in_double_quote) {
            switch (char) {
                '"' => in_double_quote = false,
                '\\' => escaping = true,
                else => {
                    line[write_idx] = char;
                    write_idx += 1;
                },
            }
            saw_content = true;
            continue;
        }

        if (isSpace(char)) {
            try finishToken(stage, line, &token_start, &write_idx, &pending_redirect);
            continue;
        }

        if (char == '\'') {
            if (token_start == null) token_start = write_idx;
            in_single_quote = true;
            saw_content = true;
            continue;
        }

        if (char == '"') {
            if (token_start == null) token_start = write_idx;
            in_double_quote = true;
            saw_content = true;
            continue;
        }

        if (char == '\\') {
            if (token_start == null) token_start = write_idx;
            escaping = true;
            saw_content = true;
            continue;
        }

        if (token_start == null and (char == '1' or char == '2') and read_idx + 1 < line.len and line[read_idx + 1] == '>') {
            if (pending_redirect != null) return error.MissingPath;
            pending_redirect = .{
                .fd = if (char == '1') syscall.STDOUT else syscall.STDERR,
                .append = read_idx + 2 < line.len and line[read_idx + 2] == '>',
            };
            read_idx += if (pending_redirect.?.append) 2 else 1;
            saw_content = true;
            continue;
        }

        switch (char) {
            '|' => {
                if (pending_redirect != null) return error.MissingPath;
                try finishToken(stage, line, &token_start, &write_idx, &pending_redirect);
                if (stage.argc == 0) return error.MissingCommand;
                if (stage_idx + 1 >= MAX_STAGES) return error.TooManyStages;
                stage_idx += 1;
                pipeline.stage_count = stage_idx + 1;
                stage = &pipeline.stages[stage_idx];
                saw_content = true;
            },
            '<' => {
                if (pending_redirect != null) return error.MissingPath;
                try finishToken(stage, line, &token_start, &write_idx, &pending_redirect);
                pending_redirect = .{ .fd = syscall.STDIN, .append = false };
                saw_content = true;
            },
            '>' => {
                if (pending_redirect != null) return error.MissingPath;
                try finishToken(stage, line, &token_start, &write_idx, &pending_redirect);
                pending_redirect = .{
                    .fd = syscall.STDOUT,
                    .append = read_idx + 1 < line.len and line[read_idx + 1] == '>',
                };
                if (pending_redirect.?.append) read_idx += 1;
                saw_content = true;
            },
            else => {
                if (token_start == null) token_start = write_idx;
                line[write_idx] = char;
                write_idx += 1;
                saw_content = true;
            },
        }
    }

    if (escaping) return error.TrailingEscape;
    if (in_single_quote or in_double_quote) return error.UnterminatedQuote;

    try finishToken(stage, line, &token_start, &write_idx, &pending_redirect);
    if (pending_redirect != null) return error.MissingPath;

    if (stage.argc == 0) {
        if (!saw_content) {
            pipeline.stage_count = 0;
            return;
        }
        return error.MissingCommand;
    }

    try validatePipelineLayout(pipeline);
}

fn finishToken(
    stage: *Stage,
    line: []u8,
    token_start: *?usize,
    write_idx: *usize,
    pending_redirect: *?PendingRedirect,
) ParseError!void {
    const start = token_start.* orelse return;
    line[write_idx.*] = 0;
    const token: [*:0]const u8 = @ptrCast(&line[start]);
    write_idx.* += 1;
    token_start.* = null;

    if (pending_redirect.*) |redirect| {
        try assignRedirect(stage, redirect, token);
        pending_redirect.* = null;
        return;
    }

    if (stage.argc >= MAX_ARGS) return error.TooManyArgs;
    stage.argv[stage.argc] = token;
    stage.argc += 1;
    stage.argv[stage.argc] = null;
}

fn assignRedirect(stage: *Stage, redirect: PendingRedirect, path: [*:0]const u8) ParseError!void {
    switch (redirect.fd) {
        syscall.STDIN => {
            if (stage.stdin_path != null) return error.DuplicateRedirect;
            stage.stdin_path = path;
        },
        syscall.STDOUT => {
            if (stage.stdout_path != null) return error.DuplicateRedirect;
            stage.stdout_path = path;
            stage.stdout_append = redirect.append;
        },
        syscall.STDERR => {
            if (stage.stderr_path != null) return error.DuplicateRedirect;
            stage.stderr_path = path;
            stage.stderr_append = redirect.append;
        },
        else => unreachable,
    }
}

fn validatePipelineLayout(pipeline: *const Pipeline) ParseError!void {
    if (pipeline.stage_count <= 1) return;

    var idx: usize = 0;
    while (idx < pipeline.stage_count) : (idx += 1) {
        const stage = pipeline.stages[idx];
        if (idx != 0 and stage.stdin_path != null) return error.UnsupportedRedirectionLayout;
        if (idx + 1 < pipeline.stage_count and stage.stdout_path != null) return error.UnsupportedRedirectionLayout;
    }
}

fn stageHasRedirection(stage: *const Stage) bool {
    return stage.stdin_path != null or stage.stdout_path != null or stage.stderr_path != null;
}

fn tryBuiltin(stage: *const Stage, envp: [*]const ?[*:0]const u8) ?i32 {
    const command = cstr.optionalSlice(stage.argv[0]);

    if (std.mem.eql(u8, command, "exit")) {
        builtinExit(stage);
    }

    if (std.mem.eql(u8, command, "cd")) {
        return builtinCd(stage, envp);
    }

    if (std.mem.eql(u8, command, "pwd")) {
        return builtinPwd();
    }

    return null;
}

fn isParentOnlyBuiltin(command: []const u8) bool {
    return std.mem.eql(u8, command, "cd") or std.mem.eql(u8, command, "exit");
}

fn builtinExit(stage: *const Stage) noreturn {
    const code = if (stage.argc >= 2)
        std.fmt.parseInt(i32, cstr.optionalSlice(stage.argv[1]), 10) catch 1
    else
        0;
    syscall.exit(code);
}

fn builtinCd(stage: *const Stage, envp: [*]const ?[*:0]const u8) i32 {
    if (stage.argc >= 2) {
        const rc = syscall.chdir(stage.argv[1].?);
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

fn spawnStage(stage: *const Stage, envp: [*]const ?[*:0]const u8) i32 {
    const pid = syscall.spawnve(stage.argv[0].?, @ptrCast(&stage.argv[0]), envp);
    if (syscall.isError(pid)) {
        stdio.eprint("sh: failed to spawn {s}\n", .{cstr.optionalSlice(stage.argv[0])});
        return 1;
    }

    return waitForChild(pid);
}

fn execSimpleStage(stage: *const Stage, envp: [*]const ?[*:0]const u8) i32 {
    const rc = syscall.execve(stage.argv[0].?, @ptrCast(&stage.argv[0]), envp);
    if (syscall.isError(rc)) {
        stdio.eprint("sh: failed to exec {s}\n", .{cstr.optionalSlice(stage.argv[0])});
        return 1;
    }
    return 1;
}

fn runPipeline(pipeline: *const Pipeline, envp: [*]const ?[*:0]const u8) i32 {
    var temp_paths: [MAX_STAGES - 1][MAX_TEMP_PATH]u8 = [_][MAX_TEMP_PATH]u8{[_]u8{0} ** MAX_TEMP_PATH} ** (MAX_STAGES - 1);
    var temp_lens: [MAX_STAGES - 1]usize = [_]usize{0} ** (MAX_STAGES - 1);

    if (pipeline.stage_count > 1) {
        var idx: usize = 0;
        while (idx + 1 < pipeline.stage_count) : (idx += 1) {
            temp_lens[idx] = makePipelineTempPath(&temp_paths[idx], idx) orelse {
                stdio.eputs("sh: pipeline temp path too long\n");
                return 1;
            };
        }
    }
    defer cleanupPipelineTempFiles(&temp_paths, &temp_lens, pipeline.stage_count);

    var stage_idx: usize = 0;
    while (stage_idx < pipeline.stage_count) : (stage_idx += 1) {
        const stage = &pipeline.stages[stage_idx];
        const opened_input = if (stage.stdin_path) |path|
            openRedirectFile(path, syscall.O_RDONLY)
        else if (stage_idx > 0)
            openRedirectFile(@ptrCast(temp_paths[stage_idx - 1][0..].ptr), syscall.O_RDONLY)
        else
            null;
        if ((stage.stdin_path != null or stage_idx > 0) and opened_input == null) return 1;

        const opened_output = if (stage.stdout_path) |path|
            openRedirectFile(path, syscall.O_WRONLY | syscall.O_CREAT | if (stage.stdout_append) syscall.O_APPEND else syscall.O_TRUNC)
        else if (stage_idx + 1 < pipeline.stage_count)
            openRedirectFile(@ptrCast(temp_paths[stage_idx][0..].ptr), syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC)
        else
            null;
        if ((stage.stdout_path != null or stage_idx + 1 < pipeline.stage_count) and opened_output == null) {
            closeOptionalFd(opened_input);
            return 1;
        }

        const opened_error = if (stage.stderr_path) |path|
            openRedirectFile(path, syscall.O_WRONLY | syscall.O_CREAT | if (stage.stderr_append) syscall.O_APPEND else syscall.O_TRUNC)
        else
            null;
        if (stage.stderr_path != null and opened_error == null) {
            closeOptionalFd(opened_input);
            closeOptionalFd(opened_output);
            return 1;
        }

        var stdio_config = syscall.SpawnStdio{
            .stdin_fd = if (opened_input) |fd| fd else -1,
            .stdout_fd = if (opened_output) |fd| fd else -1,
            .stderr_fd = if (opened_error) |fd| fd else -1,
        };
        const pid = syscall.spawnveWithStdio(stage.argv[0].?, @ptrCast(&stage.argv[0]), envp, &stdio_config);
        if (syscall.isError(pid)) {
            stdio.eprint("sh: failed to spawn {s}\n", .{cstr.optionalSlice(stage.argv[0])});
            closeOptionalFd(opened_input);
            closeOptionalFd(opened_output);
            closeOptionalFd(opened_error);
            return 1;
        }

        closeOptionalFd(opened_input);
        closeOptionalFd(opened_output);
        closeOptionalFd(opened_error);
        const status = waitForChild(pid);
        if (status != 0 or stage_idx + 1 == pipeline.stage_count) {
            if (status != 0) return status;
            return status;
        }
    }

    return 0;
}

fn openRedirectFile(path: [*:0]const u8, flags: u32) ?i32 {
    const fd = syscall.open(path, flags);
    if (syscall.isError(fd)) {
        stdio.eprint("sh: failed to open {s}\n", .{cstr.slice(path)});
        return null;
    }
    return fd;
}

fn waitForChild(pid: i32) i32 {
    while (true) {
        var proc_info: [MAX_PROC_INFO]syscall.ProcInfo = undefined;
        const count = syscall.getprocs(proc_info[0..]);
        if (syscall.isError(count)) {
            stdio.eputs("sh: getprocs failed\n");
            return 1;
        }

        var found = false;
        var terminated = false;
        var idx: usize = 0;
        while (idx < @as(usize, @intCast(count))) : (idx += 1) {
            if (proc_info[idx].pid != @as(u32, @intCast(pid))) continue;
            found = true;
            terminated = proc_info[idx].state == PROCESS_STATE_TERMINATED;
            break;
        }

        if (!found or terminated) {
            var status: i32 = 0;
            const waited = syscall.wait4(pid, &status, @intCast(syscall.WNOHANG), null);
            if (syscall.isError(waited)) {
                stdio.eputs("sh: wait4 failed\n");
                return 1;
            }
            if (waited == pid) {
                return status;
            }
            if (!found) {
                stdio.eputs("sh: child vanished\n");
                return 1;
            }
            _ = syscall.schedYield();
            continue;
        }

        _ = syscall.schedYield();
    }
}

fn makePipelineTempPath(buffer: *[MAX_TEMP_PATH]u8, stage_idx: usize) ?usize {
    const rendered = std.fmt.bufPrint(buffer, "/tmp/.sh-pipe-{d}-{d}", .{ syscall.getpid(), stage_idx }) catch return null;
    if (rendered.len >= buffer.len) return null;
    buffer[rendered.len] = 0;
    return rendered.len;
}

fn cleanupPipelineTempFiles(temp_paths: *const [MAX_STAGES - 1][MAX_TEMP_PATH]u8, temp_lens: *const [MAX_STAGES - 1]usize, stage_count: usize) void {
    if (stage_count <= 1) return;

    var idx: usize = 0;
    while (idx + 1 < stage_count) : (idx += 1) {
        if (temp_lens[idx] == 0) continue;
        _ = syscall.unlink(@ptrCast(temp_paths[idx][0..].ptr));
    }
}

fn closeOptionalFd(fd: ?i32) void {
    if (fd) |value| {
        _ = syscall.close(value);
    }
}

fn closeFd(fd: i32) void {
    if (fd >= 0) {
        _ = syscall.close(fd);
    }
}

fn printParseError(err: ParseError) void {
    switch (err) {
        error.UnterminatedQuote => stdio.eputs("sh: unterminated quote\n"),
        error.TrailingEscape => stdio.eputs("sh: trailing escape\n"),
        error.TooManyArgs => stdio.eputs("sh: too many arguments\n"),
        error.TooManyStages => stdio.eputs("sh: too many pipeline stages\n"),
        error.MissingCommand => stdio.eputs("sh: missing command\n"),
        error.MissingPath => stdio.eputs("sh: missing redirection path\n"),
        error.DuplicateRedirect => stdio.eputs("sh: duplicate redirection\n"),
        error.UnsupportedRedirectionLayout => stdio.eputs("sh: unsupported redirection layout\n"),
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
