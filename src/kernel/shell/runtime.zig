const std = @import("std");
const console = @import("../utils/console.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");
const process = @import("../process/process.zig");
const vfs = @import("../fs/vfs.zig");
const abi = @import("../process/syscall/abi.zig");
const cwd_mod = @import("../process/syscall/cwd.zig");
const environ = @import("../utils/environ.zig");
const common = @import("common.zig");
const parser = @import("parser/pipeline.zig");
const glob = @import("glob.zig");
const registry = @import("registry.zig");
const shell_external = @import("launcher.zig");

const sliceFromCStr = common.sliceFromCStr;

const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;
const MAX_ARGS = parser.MAX_ARGS;
const MAX_PIPE_STAGES = parser.MAX_PIPE_STAGES;
const MAX_TOKENS = parser.MAX_TOKENS;

const TokenizationError = parser.TokenizationError;
const CommandToken = parser.CommandToken;
const CommandCaptureError = parser.CommandCaptureError;
const PipelineConfigError = parser.PipelineConfigError;
const ParsedStage = parser.ParsedStage;
const ParsedPipeline = parser.ParsedPipeline;

pub const ExternalLaunchError = shell_external.ExternalLaunchError;

pub const Runtime = struct {
    context: ?*anyopaque,
    nextCaptureIdFn: *const fn (?*anyopaque) u32,
    dispatchBuiltinFn: *const fn (?*anyopaque, registry.CommandId, []const [*:0]const u8) void,
    registerBackgroundJobFn: *const fn (?*anyopaque, u32, []const CommandToken) void,
    waitForForegroundFn: *const fn (?*anyopaque, u32) bool,
    setForegroundProcessGroupFn: *const fn (?*anyopaque, ?u32) void,
    launchExternalFn: *const fn (?*anyopaque, []const [*:0]const u8, ?i8, ?i32, ?i32, ?u32) ExternalLaunchError!u32,

    fn nextCaptureId(self: *const Runtime) u32 {
        return self.nextCaptureIdFn(self.context);
    }

    fn dispatchBuiltin(self: *const Runtime, command_id: registry.CommandId, args: []const [*:0]const u8) void {
        self.dispatchBuiltinFn(self.context, command_id, args);
    }

    fn registerBackgroundJob(self: *const Runtime, pid: u32, tokens: []const CommandToken) void {
        self.registerBackgroundJobFn(self.context, pid, tokens);
    }

    fn waitForForegroundCommand(self: *const Runtime, pid: u32) bool {
        return self.waitForForegroundFn(self.context, pid);
    }

    fn setForegroundProcessGroup(self: *const Runtime, pgid: ?u32) void {
        self.setForegroundProcessGroupFn(self.context, pgid);
    }

    fn launchExternal(self: *const Runtime, command_args: []const [*:0]const u8, nice_value: ?i8, stdin_fd: ?i32, stdout_fd: ?i32, process_group: ?u32) ExternalLaunchError!u32 {
        return self.launchExternalFn(self.context, command_args, nice_value, stdin_fd, stdout_fd, process_group);
    }
};

pub fn dispatchesInShell(command_meta: *const registry.Command) bool {
    return !command_meta.prefer_external_program;
}

pub fn executeLine(runtime: *const Runtime, line: []const u8, wait_for_external: bool) bool {
    if (line.len == 0) {
        return true;
    }

    vga.put_char('\n');

    var token_storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;
    const token_count = parser.tokenizeCommandLine(
        line,
        &token_storage,
        &tokens,
        makeParserHooks(runtime),
        true,
    ) catch |err| {
        printTokenizationError(err);
        return false;
    };

    if (token_count == 0) {
        return true;
    }

    const background_requested = parser.isBackgroundRequest(tokens[0..token_count]);
    const effective_token_count = if (background_requested) token_count - 1 else token_count;
    if (!parser.isValidBackgroundPlacement(tokens[0..token_count])) {
        vga.print("Invalid background job placement\n");
        return false;
    }

    if (effective_token_count == 0) {
        return true;
    }

    if (parser.containsShellOperators(tokens[0..effective_token_count])) {
        return executePipeline(runtime, tokens[0..effective_token_count], background_requested);
    }

    var args_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    var args: [MAX_ARGS][*:0]const u8 = undefined;
    const arg_count = expandSimpleCommandTokens(tokens[0..effective_token_count], &args_storage, &args) catch |err| {
        printPipelineConfigError(err);
        return false;
    };

    const command = args[0];
    const command_name = sliceFromCStr(command);
    if (registry.lookup(command_name)) |command_meta| {
        if (background_requested) {
            if (!command_meta.has_external_program) {
                vga.print("Background execution requires an external command\n");
                return false;
            }
        } else if (dispatchesInShell(command_meta)) {
            runtime.dispatchBuiltin(command_meta.id, args[1..arg_count]);
            return true;
        }
    }

    const pid = runtime.launchExternal(args[0..arg_count], null, null, null, null) catch |err| {
        shell_external.printExternalCommandError(command, err);
        return false;
    };

    if (background_requested or !wait_for_external) {
        if (background_requested) {
            runtime.registerBackgroundJob(pid, tokens[0..effective_token_count]);
        }
        return true;
    }

    return runtime.waitForForegroundCommand(pid);
}

fn executePipeline(runtime: *const Runtime, tokens: []const CommandToken, background_requested: bool) bool {
    const pipeline_mem = memory.kmalloc(@sizeOf(ParsedPipeline)) orelse {
        printPipelineConfigError(error.ArgumentTooLong);
        return false;
    };
    defer memory.kfree(pipeline_mem);
    const pipeline: *ParsedPipeline = @ptrCast(@alignCast(pipeline_mem));

    parser.parsePipelineInto(tokens, pipeline) catch |err| {
        printPipelineConfigError(err);
        return false;
    };

    if (background_requested) {
        printPipelineConfigError(error.UnsupportedBackground);
        return false;
    }

    if (!validatePipelineStages(pipeline)) {
        return false;
    }

    expandPipelineGlobs(pipeline) catch |err| {
        printPipelineConfigError(err);
        return false;
    };

    var temp_paths: [MAX_PIPE_STAGES - 1][64]u8 = [_][64]u8{[_]u8{0} ** 64} ** (MAX_PIPE_STAGES - 1);
    var temp_path_lens: [MAX_PIPE_STAGES - 1]usize = [_]usize{0} ** (MAX_PIPE_STAGES - 1);
    if (pipeline.stage_count > 1) {
        var temp_idx: usize = 0;
        while (temp_idx + 1 < pipeline.stage_count) : (temp_idx += 1) {
            temp_path_lens[temp_idx] = makePipelineTempPath(&temp_paths[temp_idx], temp_idx) catch {
                printPipelineConfigError(error.OpenFailed);
                return false;
            };
        }
    }
    defer cleanupPipelineTempFiles(&temp_paths, &temp_path_lens, pipeline.stage_count);

    var success = true;
    var stage_idx: usize = 0;
    while (stage_idx < pipeline.stage_count) : (stage_idx += 1) {
        const stage = &pipeline.stages[stage_idx];
        const stdin_fd = openStageInput(stage, &temp_paths, &temp_path_lens, stage_idx) catch |err| {
            printPipelineConfigError(err);
            return false;
        };

        const stdout_fd = openStageOutput(stage, &temp_paths, &temp_path_lens, pipeline.stage_count, stage_idx) catch |err| {
            closeRedirectFd(stdin_fd);
            printPipelineConfigError(err);
            return false;
        };

        const pid = runtime.launchExternal(
            stage.args[0..stage.arg_count],
            null,
            stdin_fd,
            stdout_fd,
            null,
        ) catch |err| {
            closeRedirectFd(stdin_fd);
            closeRedirectFd(stdout_fd);
            if (stage.arg_count > 0) {
                shell_external.printExternalCommandError(stage.args[0], err);
            } else {
                printPipelineConfigError(error.EmptyStage);
            }
            return false;
        };
        closeRedirectFd(stdin_fd);
        closeRedirectFd(stdout_fd);

        if (!runtime.waitForForegroundCommand(pid)) {
            success = false;
            break;
        }
    }

    return success;
}

fn makeParserHooks(runtime: *const Runtime) parser.ExpansionHooks {
    return .{
        .context = @ptrCast(@constCast(runtime)),
        .getVarFn = parserGetVar,
        .captureCommandFn = parserCaptureCommand,
    };
}

fn parserGetVar(_: ?*anyopaque, name: []const u8) ?[]const u8 {
    return environ.getVar(name);
}

fn parserCaptureCommand(context: ?*anyopaque, line: []const u8, output: []u8) CommandCaptureError!usize {
    const runtime: *Runtime = @ptrCast(@alignCast(context orelse return error.CommandFailed));
    return captureCommandSubstitution(runtime, line, output);
}

fn captureCommandSubstitution(runtime: *const Runtime, line: []const u8, output: []u8) error{ CommandFailed, NoSpaceLeft }!usize {
    var token_storage: [MAX_TOKENS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_TOKENS;
    var tokens: [MAX_TOKENS]CommandToken = undefined;
    const token_count = parser.tokenizeCommandLine(line, &token_storage, &tokens, makeParserHooks(runtime), false) catch |err| {
        logCommandSubstitutionFailure("tokenize", line, @errorName(err));
        return error.CommandFailed;
    };
    if (token_count == 0) return 0;
    if (parser.containsShellOperators(tokens[0..token_count])) {
        logCommandSubstitutionFailure("tokenize", line, "shell-operator");
        return error.CommandFailed;
    }

    var args_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    var args: [MAX_ARGS][*:0]const u8 = undefined;
    const arg_count = expandSimpleCommandTokens(tokens[0..token_count], &args_storage, &args) catch |err| {
        logCommandSubstitutionFailure("expand", line, @errorName(err));
        return error.CommandFailed;
    };
    if (arg_count == 0) return 0;

    const command_name = sliceFromCStr(args[0]);
    if (registry.lookup(command_name)) |command_meta| {
        if (dispatchesInShell(command_meta)) {
            logCommandSubstitutionFailure("dispatch", line, "builtin-only");
            return error.CommandFailed;
        }
    }

    var temp_path: [64]u8 = undefined;
    const temp_len = makeCommandCapturePath(runtime, &temp_path) catch |err| {
        logCommandSubstitutionFailure("temp-path", line, @errorName(err));
        return err;
    };
    const temp_path_z: [*:0]const u8 = @ptrCast(&temp_path[0]);
    const stdout_fd = openRedirectFd(temp_path_z, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
        logCommandSubstitutionFailure("redirect", line, @errorName(err));
        return error.CommandFailed;
    };
    defer closeRedirectFd(stdout_fd);
    defer vfs.unlink(temp_path[0..temp_len]) catch {};

    const pid = runtime.launchExternal(args[0..arg_count], null, null, stdout_fd, null) catch |err| {
        logCommandSubstitutionFailure("launch", line, @errorName(err));
        return error.CommandFailed;
    };
    if (!runtime.waitForForegroundCommand(pid)) {
        logCommandSubstitutionFailure("wait", line, "non-zero-exit");
        return error.CommandFailed;
    }

    const fd = vfs.open(temp_path[0..temp_len], vfs.O_RDONLY) catch |err| {
        logCommandSubstitutionFailure("open", line, @errorName(err));
        return error.CommandFailed;
    };
    defer vfs.close(fd) catch {};
    const bytes_read = vfs.read(fd, output) catch |err| {
        logCommandSubstitutionFailure("read", line, @errorName(err));
        return error.CommandFailed;
    };

    return trimCommandSubstitution(output[0..bytes_read]);
}

fn logCommandSubstitutionFailure(stage: []const u8, line: []const u8, reason: []const u8) void {
    const display_line = if (line.len > 96) line[0..96] else line;
    var line_buf: [192]u8 = undefined;
    const rendered = std.fmt.bufPrint(&line_buf, "cmdsub[{s}] {s}: {s}\n", .{ stage, reason, display_line }) catch "cmdsub failure\n";
    console.print(rendered);
}

fn trimCommandSubstitution(output: []u8) usize {
    var len = output.len;
    while (len > 0 and (output[len - 1] == '\n' or output[len - 1] == '\r')) : (len -= 1) {}
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (output[i] == '\n' or output[i] == '\r') {
            output[i] = ' ';
        }
    }
    return len;
}

fn makeCommandCapturePath(runtime: *const Runtime, buffer: *[64]u8) error{NoSpaceLeft}!usize {
    const current_pid = process.getCurrentPID();
    const capture_id = runtime.nextCaptureId();
    const rendered = std.fmt.bufPrint(buffer, "/tmp/.cmdsub-{d}-{d}", .{ current_pid, capture_id }) catch return error.NoSpaceLeft;
    if (rendered.len >= buffer.len) return error.NoSpaceLeft;
    buffer[rendered.len] = 0;
    return rendered.len;
}

fn expandSimpleCommandTokens(tokens: []const CommandToken, args_storage: *[MAX_ARGS][MAX_COMMAND_LENGTH]u8, out_args: *[MAX_ARGS][*:0]const u8) PipelineConfigError!usize {
    var arg_count: usize = 0;
    for (tokens) |token| {
        if (token.kind != .word) return error.UnsupportedRedirection;
        try appendExpandedToken(token.text, token.has_glob, args_storage, out_args, &arg_count);
    }
    return arg_count;
}

fn copyIntoStageBuffer(buffer: *[MAX_COMMAND_LENGTH]u8, text: []const u8) PipelineConfigError!void {
    if (text.len >= buffer.len) return error.ArgumentTooLong;
    @memset(buffer, 0);
    @memcpy(buffer[0..text.len], text);
}

fn validatePipelineStages(pipeline: *const ParsedPipeline) bool {
    for (pipeline.stages[0..pipeline.stage_count]) |stage| {
        const command_name = sliceFromCStr(stage.args[0]);
        if (registry.lookup(command_name)) |command_meta| {
            if (command_meta.has_external_program) continue;
            vga.print("Pipelines and redirection currently require external commands: ");
            vga.print(sliceFromCStr(stage.args[0]));
            vga.print("\n");
            return false;
        }
    }
    return true;
}

fn expandPipelineGlobs(pipeline: *ParsedPipeline) PipelineConfigError!void {
    for (pipeline.stages[0..pipeline.stage_count]) |*stage| {
        try expandStageArgs(stage);
        try expandStageRedirect(stage, true);
        try expandStageRedirect(stage, false);
    }
}

fn expandStageArgs(stage: *ParsedStage) PipelineConfigError!void {
    var expanded_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    var expanded_args: [MAX_ARGS][*:0]const u8 = undefined;
    var expanded_count: usize = 0;

    var i: usize = 0;
    while (i < stage.arg_count) : (i += 1) {
        try appendExpandedToken(stage.args[i], stage.arg_glob[i], &expanded_storage, &expanded_args, &expanded_count);
    }

    stage.arg_storage = expanded_storage;
    stage.arg_count = expanded_count;
    i = 0;
    while (i < expanded_count) : (i += 1) {
        stage.args[i] = @ptrCast(&stage.arg_storage[i][0]);
        stage.arg_glob[i] = false;
    }
}

fn expandStageRedirect(stage: *ParsedStage, is_input: bool) PipelineConfigError!void {
    const raw_path = if (is_input) stage.stdin_path else stage.stdout_path;
    if (raw_path == null) return;
    const has_glob = if (is_input) stage.stdin_glob else stage.stdout_glob;
    if (!has_glob) return;

    var match_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    const matches = try resolveGlobMatches(sliceFromCStr(raw_path.?), &match_storage);
    if (matches == 0) return;
    if (matches > 1) return error.AmbiguousRedirect;

    if (is_input) {
        stage.stdin_path_storage = match_storage[0];
        stage.stdin_path = @ptrCast(&stage.stdin_path_storage[0]);
        stage.stdin_glob = false;
    } else {
        stage.stdout_path_storage = match_storage[0];
        stage.stdout_path = @ptrCast(&stage.stdout_path_storage[0]);
        stage.stdout_glob = false;
    }
}

fn appendExpandedToken(token: [*:0]const u8, has_glob: bool, storage: *[MAX_ARGS][MAX_COMMAND_LENGTH]u8, out_args: *[MAX_ARGS][*:0]const u8, arg_count: *usize) PipelineConfigError!void {
    const token_slice = sliceFromCStr(token);
    if (!has_glob) {
        if (arg_count.* >= MAX_ARGS) return error.ArgumentTooLong;
        try copyIntoStageBuffer(&storage[arg_count.*], token_slice);
        out_args[arg_count.*] = @ptrCast(&storage[arg_count.*][0]);
        arg_count.* += 1;
        return;
    }

    var match_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    const match_count = try resolveGlobMatches(token_slice, &match_storage);

    if (match_count == 0) {
        if (arg_count.* >= MAX_ARGS) return error.ArgumentTooLong;
        try copyIntoStageBuffer(&storage[arg_count.*], token_slice);
        out_args[arg_count.*] = @ptrCast(&storage[arg_count.*][0]);
        arg_count.* += 1;
        return;
    }

    var match_idx: usize = 0;
    while (match_idx < match_count) : (match_idx += 1) {
        if (arg_count.* >= MAX_ARGS) return error.ArgumentTooLong;
        storage[arg_count.*] = match_storage[match_idx];
        out_args[arg_count.*] = @ptrCast(&storage[arg_count.*][0]);
        arg_count.* += 1;
    }
}

fn resolveGlobMatches(pattern: []const u8, out_matches: *[MAX_ARGS][MAX_COMMAND_LENGTH]u8) PipelineConfigError!usize {
    if (!glob.containsWildcardChars(pattern)) return 0;

    var absolute_pattern_storage: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH;
    const absolute_pattern = try makeAbsolutePath(pattern, &absolute_pattern_storage);
    var pattern_cache = glob.PatternCache(MAX_ARGS){};

    var current_paths: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    var next_paths: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
    current_paths[0][0] = '/';
    current_paths[0][1] = 0;
    var current_count: usize = 1;

    var component_start: usize = 0;
    while (component_start < absolute_pattern.len and absolute_pattern[component_start] == '/') : (component_start += 1) {}

    while (component_start < absolute_pattern.len) {
        var component_end = component_start;
        while (component_end < absolute_pattern.len and absolute_pattern[component_end] != '/') : (component_end += 1) {}
        const component = absolute_pattern[component_start..component_end];
        const wildcard_component = glob.containsWildcardChars(component);

        var next_count: usize = 0;
        var current_idx: usize = 0;
        while (current_idx < current_count) : (current_idx += 1) {
            const base_path = sliceFromCStr(@ptrCast(&current_paths[current_idx][0]));
            if (wildcard_component) {
                const compiled_pattern = try pattern_cache.getOrCompile(component);
                try collectGlobMatches(base_path, compiled_pattern, &next_paths, &next_count);
            } else {
                if (next_count >= MAX_ARGS) return error.ArgumentTooLong;
                const joined = try glob.joinPath(base_path, component, &next_paths[next_count]);
                if (pathExists(joined)) {
                    next_count += 1;
                }
            }
        }

        current_paths = next_paths;
        next_paths = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS;
        current_count = next_count;
        if (current_count == 0) return 0;

        component_start = component_end;
        while (component_start < absolute_pattern.len and absolute_pattern[component_start] == '/') : (component_start += 1) {}
    }

    out_matches.* = current_paths;
    return current_count;
}

fn makeAbsolutePath(path: []const u8, buffer: *[MAX_COMMAND_LENGTH]u8) PipelineConfigError![]const u8 {
    return cwd_mod.resolvePath(path, buffer) orelse error.ArgumentTooLong;
}

fn collectGlobMatches(base_path: []const u8, compiled_pattern: *const glob.CompiledPattern, out_paths: *[MAX_ARGS][MAX_COMMAND_LENGTH]u8, out_count: *usize) PipelineConfigError!void {
    const fd = vfs.open(base_path, vfs.O_RDONLY) catch return;
    defer vfs.close(fd) catch {};

    const pattern = compiled_pattern.slice();
    var dirent: vfs.DirEntry = undefined;
    while (true) {
        const has_entry = vfs.readdirNext(fd, &dirent) catch return;
        if (!has_entry) break;

        const entry_name = dirent.name[0..dirent.name_len];
        if (entry_name.len == 0) continue;
        if (std.mem.eql(u8, entry_name, ".") or std.mem.eql(u8, entry_name, "..")) continue;
        if (entry_name[0] == '.' and (pattern.len == 0 or pattern[0] != '.')) continue;
        if (!compiled_pattern.matches(entry_name)) continue;
        if (out_count.* >= MAX_ARGS) return error.ArgumentTooLong;
        _ = try glob.joinPath(base_path, entry_name, &out_paths[out_count.*]);
        out_count.* += 1;
    }
}

fn pathExists(path: []const u8) bool {
    const vnode = vfs.lookupPath(path) catch return false;
    vfs.discardLookupVNode(vnode);
    return true;
}

fn openRedirectFd(path: [*:0]const u8, flags: u32) PipelineConfigError!i32 {
    var resolved_path_buf: [MAX_COMMAND_LENGTH]u8 = undefined;
    const input_path = sliceFromCStr(path);
    const resolved_path = cwd_mod.resolvePath(input_path, &resolved_path_buf) orelse {
        logRedirectFailure("resolve", input_path, "ResolveFailed");
        return error.OpenFailed;
    };
    const raw_fd = vfs.open(resolved_path, flags) catch |err| {
        logRedirectFailure("open", resolved_path, @errorName(err));
        return error.OpenFailed;
    };
    errdefer vfs.close(raw_fd) catch {};
    const child_fd = vfs.dup(raw_fd) catch |err| {
        logRedirectFailure("dup", resolved_path, @errorName(err));
        return error.DupFailed;
    };
    vfs.close(raw_fd) catch |err| {
        logRedirectFailure("close", resolved_path, @errorName(err));
        return error.CloseFailed;
    };
    return @as(i32, @intCast(child_fd)) + @as(i32, @intCast(abi.FD_OFFSET));
}

fn logRedirectFailure(stage: []const u8, path: []const u8, reason: []const u8) void {
    var line_buf: [192]u8 = undefined;
    const rendered = std.fmt.bufPrint(&line_buf, "redirect[{s}] {s}: {s}\n", .{ stage, reason, path }) catch "redirect failure\n";
    console.print(rendered);
}

fn closeRedirectFd(fd: ?i32) void {
    if (fd) |value| {
        if (value >= @as(i32, @intCast(abi.FD_OFFSET))) {
            const vfs_fd: u32 = @intCast(value - @as(i32, @intCast(abi.FD_OFFSET)));
            vfs.close(vfs_fd) catch {};
        }
    }
}

fn openStageInput(stage: *const ParsedStage, temp_paths: *const [MAX_PIPE_STAGES - 1][64]u8, temp_path_lens: *const [MAX_PIPE_STAGES - 1]usize, stage_idx: usize) PipelineConfigError!?i32 {
    if (stage.stdin_path) |path| {
        return try openRedirectFd(path, vfs.O_RDONLY);
    }
    if (stage_idx == 0) return null;

    const temp_path = temp_paths[stage_idx - 1][0..temp_path_lens[stage_idx - 1]];
    return try openRedirectFd(@ptrCast(temp_path.ptr), vfs.O_RDONLY);
}

fn openStageOutput(stage: *const ParsedStage, temp_paths: *const [MAX_PIPE_STAGES - 1][64]u8, temp_path_lens: *const [MAX_PIPE_STAGES - 1]usize, stage_count: usize, stage_idx: usize) PipelineConfigError!?i32 {
    if (stage.stdout_path) |path| {
        const flags = vfs.O_WRONLY | vfs.O_CREAT | if (stage.append_stdout) vfs.O_APPEND else vfs.O_TRUNC;
        return try openRedirectFd(path, flags);
    }
    if (stage_idx + 1 >= stage_count) return null;

    const temp_path = temp_paths[stage_idx][0..temp_path_lens[stage_idx]];
    return try openRedirectFd(@ptrCast(temp_path.ptr), vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC);
}

fn makePipelineTempPath(buffer: *[64]u8, stage_idx: usize) error{NoSpaceLeft}!usize {
    const current_pid = process.getCurrentPID();
    const rendered = std.fmt.bufPrint(buffer, "/tmp/.pipe-{d}-{d}", .{ current_pid, stage_idx }) catch return error.NoSpaceLeft;
    if (rendered.len >= buffer.len) return error.NoSpaceLeft;
    buffer[rendered.len] = 0;
    return rendered.len;
}

fn cleanupPipelineTempFiles(temp_paths: *const [MAX_PIPE_STAGES - 1][64]u8, temp_path_lens: *const [MAX_PIPE_STAGES - 1]usize, stage_count: usize) void {
    if (stage_count < 2) return;
    var i: usize = 0;
    while (i + 1 < stage_count) : (i += 1) {
        if (temp_path_lens[i] == 0) continue;
        const temp_path = temp_paths[i][0..temp_path_lens[i]];
        vfs.unlink(temp_path) catch {};
    }
}

fn printPipelineConfigError(err: PipelineConfigError) void {
    switch (err) {
        error.EmptyStage => vga.print("Invalid pipeline: empty command stage\n"),
        error.MissingPath => vga.print("Invalid redirection: missing path\n"),
        error.TooManyStages => vga.print("Too many pipeline stages\n"),
        error.UnsupportedBuiltin => vga.print("Pipelines and redirection require external commands\n"),
        error.UnsupportedRedirection => vga.print("Unsupported redirection layout\n"),
        error.AmbiguousRedirect => vga.print("Redirection target expands to multiple paths\n"),
        error.UnsupportedBackground => vga.print("Background execution for this command form is not supported\n"),
        error.OpenFailed => vga.print("Failed to open redirection target\n"),
        error.PipeFailed => vga.print("Failed to create pipe\n"),
        error.DupFailed => vga.print("Failed to duplicate file descriptor\n"),
        error.CloseFailed => vga.print("Failed to close temporary file descriptor\n"),
        error.ArgumentTooLong => vga.print("Too many arguments in pipeline stage\n"),
    }
}

fn printTokenizationError(err: TokenizationError) void {
    switch (err) {
        error.UnterminatedQuote => vga.print("Unterminated quoted string\n"),
        error.UnterminatedSubstitution => vga.print("Unterminated command substitution\n"),
        error.TrailingEscape => vga.print("Trailing escape in command line\n"),
        error.TooManyTokens => vga.print("Too many shell tokens\n"),
        error.TokenTooLong => vga.print("Shell token too long\n"),
        error.CommandSubstitutionFailed => vga.print("Command substitution failed\n"),
    }
}
