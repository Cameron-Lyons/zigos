// zlint-disable suppressed-errors
const std = @import("std");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const process = @import("../process/process.zig");
const paging = @import("../memory/paging.zig");
const vfs = @import("../fs/vfs.zig");
const network = @import("../net/network.zig");
const core_commands = @import("commands/core.zig");
const fs_commands = @import("commands/fs.zig");
const process_commands = @import("commands/process.zig");
const system_commands = @import("commands/system.zig");
const text_commands = @import("commands/text.zig");
const user_commands = @import("commands/user.zig");
const scheduler = @import("../process/scheduler.zig");
const editor = @import("editor.zig");
const registry = @import("registry.zig");
const memory = @import("../memory/memory.zig");
const keyboard = @import("../drivers/keyboard.zig");
const numfmt = @import("../utils/numfmt.zig");
const posix = @import("../utils/posix.zig");

const MAX_COMMAND_LENGTH = 256;
const MAX_ARGS = 16;
const MAX_HISTORY = 50;
const MAX_EXTERNAL_LAUNCHES = 8;
const MAX_PIPE_STAGES = 8;

const ExternalLaunchError = error{
    CommandNotFound,
    CommandPathTooLong,
    ArgumentTooLong,
    CommandReadFailed,
    CommandTooLarge,
    TooManyLaunches,
};

const ExternalCommandLaunch = struct {
    in_use: bool = false,
    pid: u32 = 0,
    path_len: usize = 0,
    argc: usize = 0,
    path: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
    argv_len: [MAX_ARGS]usize = [_]usize{0} ** MAX_ARGS,
    argv_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS,
    file_len: usize = 0,
    file_storage: [32768]u8 = [_]u8{0} ** 32768,
};

const ParsedStage = struct {
    args: [MAX_ARGS][*:0]const u8 = undefined,
    arg_count: usize = 0,
    stdin_path: ?[*:0]const u8 = null,
    stdout_path: ?[*:0]const u8 = null,
    append_stdout: bool = false,
};

const ParsedPipeline = struct {
    stages: [MAX_PIPE_STAGES]ParsedStage = [_]ParsedStage{ParsedStage{}} ** MAX_PIPE_STAGES,
    stage_count: usize = 0,
};

const PipelineConfigError = error{
    EmptyStage,
    MissingPath,
    TooManyStages,
    ArgumentTooLong,
    UnsupportedBuiltin,
    UnsupportedRedirection,
    OpenFailed,
    PipeFailed,
    DupFailed,
    CloseFailed,
};

var external_command_launches: [MAX_EXTERNAL_LAUNCHES]ExternalCommandLaunch = [_]ExternalCommandLaunch{ExternalCommandLaunch{}} ** MAX_EXTERNAL_LAUNCHES;

pub const ArrowKey = enum {
    Up,
    Down,
    Left,
    Right,
};

pub const Shell = struct {
    command_buffer: [MAX_COMMAND_LENGTH]u8,
    buffer_pos: usize,
    cursor_pos: usize,
    running: bool,
    history: [MAX_HISTORY][MAX_COMMAND_LENGTH]u8,
    history_count: usize,
    history_index: usize,

    pub fn init() Shell {
        return Shell{
            .command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH,
            .buffer_pos = 0,
            .cursor_pos = 0,
            .running = true,
            .history = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_HISTORY,
            .history_count = 0,
            .history_index = 0,
        };
    }

    pub fn handleChar(self: *Shell, char: u8) void {
        switch (char) {
            '\n' => {
                if (self.buffer_pos > 0) {
                    self.addToHistory();
                }
                _ = self.executeCommand(false);
                self.buffer_pos = 0;
                self.cursor_pos = 0;
                self.command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH;
                self.history_index = self.history_count;
                self.printPrompt();
            },
            '\x08' => {
                if (self.cursor_pos > 0) {
                    var i = self.cursor_pos - 1;
                    while (i < self.buffer_pos) : (i += 1) {
                        self.command_buffer[i] = if (i + 1 < self.buffer_pos) self.command_buffer[i + 1] else 0;
                    }
                    self.buffer_pos -= 1;
                    self.cursor_pos -= 1;
                    self.redrawFromCursor();
                }
            },
            else => {
                if (self.buffer_pos < MAX_COMMAND_LENGTH - 1) {
                    var i = self.buffer_pos;
                    while (i > self.cursor_pos) : (i -= 1) {
                        self.command_buffer[i] = self.command_buffer[i - 1];
                    }
                    self.command_buffer[self.cursor_pos] = char;
                    self.buffer_pos += 1;
                    self.cursor_pos += 1;
                    self.redrawFromCursor();
                }
            },
        }
    }

    fn addToHistory(self: *Shell) void {
        if (self.buffer_pos == 0) return;

        if (self.history_count > 0) {
            const last_idx = (self.history_count - 1) % MAX_HISTORY;
            var same = true;
            var i: usize = 0;
            while (i < self.buffer_pos) : (i += 1) {
                if (self.history[last_idx][i] != self.command_buffer[i]) {
                    same = false;
                    break;
                }
            }
            if (same and self.history[last_idx][self.buffer_pos] == 0) {
                return;
            }
        }

        const idx = self.history_count % MAX_HISTORY;
        @memcpy(self.history[idx][0..self.buffer_pos], self.command_buffer[0..self.buffer_pos]);
        self.history[idx][self.buffer_pos] = 0;
        self.history_count += 1;
    }

    pub fn handleArrowKey(self: *Shell, key: ArrowKey) void {
        switch (key) {
            .Up => {
                if (self.history_count == 0) return;
                if (self.history_index > 0) {
                    self.history_index -= 1;
                } else {
                    return;
                }
                self.loadHistoryEntry();
            },
            .Down => {
                if (self.history_index < self.history_count) {
                    self.history_index += 1;
                    if (self.history_index == self.history_count) {
                        self.clearLine();
                        self.command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH;
                        self.buffer_pos = 0;
                    } else {
                        self.loadHistoryEntry();
                    }
                }
            },
            .Left => {
                if (self.cursor_pos > 0) {
                    self.cursor_pos -= 1;
                    vga.put_char('\x08');
                }
            },
            .Right => {
                if (self.cursor_pos < self.buffer_pos) {
                    vga.put_char(self.command_buffer[self.cursor_pos]);
                    self.cursor_pos += 1;
                }
            },
        }
    }

    fn loadHistoryEntry(self: *Shell) void {
        const idx = self.history_index % MAX_HISTORY;

        self.clearLine();

        var i: usize = 0;
        while (i < MAX_COMMAND_LENGTH and self.history[idx][i] != 0) : (i += 1) {
            self.command_buffer[i] = self.history[idx][i];
            vga.put_char(self.command_buffer[i]);
        }
        self.buffer_pos = i;
        self.cursor_pos = i;

        while (i < MAX_COMMAND_LENGTH) : (i += 1) {
            self.command_buffer[i] = 0;
        }
    }

    fn clearLine(self: *Shell) void {
        while (self.buffer_pos > 0) {
            vga.put_char('\x08');
            vga.put_char(' ');
            vga.put_char('\x08');
            self.buffer_pos -= 1;
        }
        self.cursor_pos = 0;
    }

    fn redrawFromCursor(self: *Shell) void {
        var i = self.cursor_pos;
        while (i < self.buffer_pos) : (i += 1) {
            vga.put_char(self.command_buffer[i]);
        }
        var j = self.buffer_pos;
        while (j > self.cursor_pos) : (j -= 1) {
            vga.put_char(' ');
            vga.put_char('\x08');
        }
    }

    pub fn handleTabCompletion(self: *Shell) void {
        if (self.buffer_pos == 0) return;

        var word_start: usize = 0;
        var i: usize = 0;
        while (i < self.buffer_pos) : (i += 1) {
            if (self.command_buffer[i] == ' ') {
                word_start = i + 1;
            }
        }

        if (word_start == 0) {
            self.completeCommand();
        } else {
            self.completeFilePath(word_start);
        }
    }

    fn completeCommand(self: *Shell) void {
        var partial: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH;
        @memcpy(partial[0..self.buffer_pos], self.command_buffer[0..self.buffer_pos]);

        // SAFETY: entries assigned in the following command matching loop; match_count tracks valid entries
        var matches: [16][]const u8 = undefined;
        const match_count = registry.complete(partial[0..self.buffer_pos], matches[0..]);

        if (match_count == 1) {
            const cmd = matches[0];
            self.clearLine();
            for (cmd) |c| {
                self.command_buffer[self.buffer_pos] = c;
                vga.put_char(c);
                self.buffer_pos += 1;
            }
            self.command_buffer[self.buffer_pos] = ' ';
            vga.put_char(' ');
            self.buffer_pos += 1;
        } else if (match_count > 1) {
            vga.print("\n");
            for (matches[0..match_count]) |match| {
                vga.print("  ");
                for (match) |c| {
                    vga.put_char(c);
                }
                vga.print("\n");
            }
            self.printPrompt();

            var k: usize = 0;
            while (k < self.buffer_pos) : (k += 1) {
                vga.put_char(self.command_buffer[k]);
            }
        }
    }

    fn completeFilePath(self: *Shell, word_start: usize) void {
        var partial_path: [256]u8 = [_]u8{0} ** 256;
        var partial_len: usize = 0;
        var k = word_start;
        while (k < self.buffer_pos) : (k += 1) {
            partial_path[partial_len] = self.command_buffer[k];
            partial_len += 1;
        }

        if (partial_len == 0) return;

        // SAFETY: filled by memcpy in the path splitting logic below
        var dir_path: [256]u8 = undefined;
        // SAFETY: filled by memcpy in the path splitting logic below
        var file_part: [256]u8 = undefined;
        var dir_len: usize = 0;
        var file_len: usize = 0;

        var last_slash: ?usize = null;
        var i: usize = 0;
        while (i < partial_len) : (i += 1) {
            if (partial_path[i] == '/') {
                last_slash = i;
            }
        }

        if (last_slash) |slash_pos| {
            @memcpy(dir_path[0 .. slash_pos + 1], partial_path[0 .. slash_pos + 1]);
            dir_len = slash_pos + 1;
            @memcpy(file_part[0 .. partial_len - dir_len], partial_path[dir_len..partial_len]);
            file_len = partial_len - dir_len;
        } else {
            @memcpy(dir_path[0..2], "./");
            dir_len = 2;
            @memcpy(file_part[0..partial_len], partial_path[0..partial_len]);
            file_len = partial_len;
        }

        const dir_fd = vfs.open(dir_path[0..dir_len], vfs.O_RDONLY) catch {
            return;
        };
        defer vfs.close(dir_fd) catch {};

        // SAFETY: entries written in the directory scan loop; match_count tracks valid entries
        var matches: [32][256]u8 = undefined;
        // SAFETY: entries set from matches slices; match_count tracks valid entries
        var match_names: [32][]const u8 = undefined;
        var match_count: usize = 0;

        var index: u64 = 0;
        // SAFETY: Populated by vfs.readdir call below
        var dirent: vfs.DirEntry = undefined;

        while (match_count < 32) {
            const has_more = vfs.readdir(dir_fd, &dirent, index) catch {
                break;
            };
            if (!has_more) break;

            const entry_name = dirent.name[0..dirent.name_len];
            if (entry_name.len == 0 or (entry_name.len == 1 and entry_name[0] == '.')) {
                index += 1;
                continue;
            }
            if (entry_name.len == 2 and entry_name[0] == '.' and entry_name[1] == '.') {
                index += 1;
                continue;
            }

            if (file_len == 0 or (entry_name.len >= file_len)) {
                var matching = true;
                var j: usize = 0;
                while (j < file_len) : (j += 1) {
                    if (entry_name[j] != file_part[j]) {
                        matching = false;
                        break;
                    }
                }

                if (matching) {
                    @memcpy(matches[match_count][0..entry_name.len], entry_name);
                    match_names[match_count] = matches[match_count][0..entry_name.len];
                    match_count += 1;
                }
            }

            index += 1;
        }

        if (match_count == 1) {
            const match = match_names[0];
            const is_dir = (dirent.file_type == vfs.FileType.Directory);
            const suffix = if (is_dir) "/" else " ";

            while (self.buffer_pos > word_start) {
                self.buffer_pos -= 1;
                self.cursor_pos -= 1;
                vga.put_char('\x08');
            }

            for (match) |c| {
                self.command_buffer[self.buffer_pos] = c;
                vga.put_char(c);
                self.buffer_pos += 1;
                self.cursor_pos += 1;
            }

            for (suffix) |c| {
                self.command_buffer[self.buffer_pos] = c;
                vga.put_char(c);
                self.buffer_pos += 1;
                self.cursor_pos += 1;
            }
        } else if (match_count > 1) {
            vga.print("\n");
            for (match_names[0..match_count]) |match| {
                vga.print("  ");
                for (match) |c| {
                    vga.put_char(c);
                }
                vga.print("\n");
            }
            self.printPrompt();

            var pos: usize = 0;
            while (pos < self.buffer_pos) : (pos += 1) {
                vga.put_char(self.command_buffer[pos]);
            }
        }
    }

    pub fn printPrompt(self: *const Shell) void {
        _ = self;
        const syscall_mod = @import("../process/syscall.zig");
        const cwd = syscall_mod.getCwd();
        vga.print("zigos:");
        vga.print(cwd);
        vga.print("> ");
    }

    pub fn runCommandLine(self: *Shell, line: []const u8) bool {
        if (line.len == 0 or line.len >= MAX_COMMAND_LENGTH) {
            return false;
        }

        self.command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH;
        @memcpy(self.command_buffer[0..line.len], line);
        self.buffer_pos = line.len;
        self.cursor_pos = line.len;
        return self.executeCommand(true);
    }

    fn executeCommand(self: *Shell, wait_for_external: bool) bool {
        if (self.buffer_pos == 0) {
            return true;
        }

        vga.put_char('\n');

        // SAFETY: entries assigned during command argument parsing; argc tracks valid entries
        var args: [MAX_ARGS][*:0]const u8 = undefined;
        var arg_count: usize = 0;
        var i: usize = 0;
        var arg_start: usize = 0;

        while (i < self.buffer_pos and isWhitespace(self.command_buffer[i])) : (i += 1) {}
        arg_start = i;

        while (i < self.buffer_pos and arg_count < MAX_ARGS) {
            if (isWhitespace(self.command_buffer[i]) or i == self.buffer_pos - 1) {
                var arg_end = i;
                if (i == self.buffer_pos - 1 and !isWhitespace(self.command_buffer[i])) {
                    arg_end = i + 1;
                }

                if (arg_end > arg_start) {
                    self.command_buffer[arg_end] = 0;
                    args[arg_count] = @as([*:0]const u8, @ptrCast(&self.command_buffer[arg_start]));
                    arg_count += 1;
                }

                i = if (arg_end < self.buffer_pos) arg_end + 1 else arg_end;
                while (i < self.buffer_pos and isWhitespace(self.command_buffer[i])) : (i += 1) {}
                arg_start = i;
            } else {
                i += 1;
            }
        }

        if (arg_count == 0) {
            return true;
        }

        if (containsShellOperators(args[0..arg_count])) {
            return self.executePipeline(args[0..arg_count]);
        }

        const command = args[0];
        const command_name = sliceFromCStr(command);
        if (registry.lookup(command_name)) |command_meta| {
            self.dispatchCommand(command_meta.id, args[1..arg_count]);
            return true;
        }

        const pid = self.launchExternalCommand(args[0..arg_count], null) catch |err| {
            printExternalCommandError(command, err);
            return false;
        };

        if (!wait_for_external) {
            return true;
        }

        return waitForExternalCommand(pid);
    }

    fn executePipeline(self: *Shell, tokens: []const [*:0]const u8) bool {
        var pipeline = parsePipeline(tokens) catch |err| {
            printPipelineConfigError(err);
            return false;
        };

        if (!validatePipelineStages(&pipeline)) {
            return false;
        }

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
            const pid = self.launchExternalCommandWithRedirects(
                stage.args[0..stage.arg_count],
                null,
                stdin_fd,
                stdout_fd,
            ) catch |err| {
                closeRedirectFd(stdin_fd);
                closeRedirectFd(stdout_fd);
                if (stage.arg_count > 0) {
                    printExternalCommandError(stage.args[0], err);
                } else {
                    printPipelineConfigError(error.EmptyStage);
                }
                return false;
            };

            if (!waitForExternalCommand(pid)) {
                success = false;
                break;
            }
        }

        return success;
    }

    fn launchExternalCommand(self: *const Shell, command_args: []const [*:0]const u8, nice_value: ?i8) ExternalLaunchError!u32 {
        return self.launchExternalCommandWithRedirects(command_args, nice_value, null, null);
    }

    fn launchExternalCommandWithRedirects(self: *const Shell, command_args: []const [*:0]const u8, nice_value: ?i8, stdin_fd: ?i32, stdout_fd: ?i32) ExternalLaunchError!u32 {
        _ = self;
        if (command_args.len == 0) {
            return error.CommandNotFound;
        }

        var resolved_path_buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
        const resolved_path = try resolveExternalCommandPath(sliceFromCStr(command_args[0]), &resolved_path_buffer);
        const launch = try allocateExternalCommandLaunch();
        errdefer releaseExternalCommandLaunch(launch);

        launch.path_len = resolved_path.len;
        @memcpy(launch.path[0..resolved_path.len], resolved_path);
        launch.argc = command_args.len;
        launch.file_len = try readExternalCommandBytes(resolved_path, &launch.file_storage);

        var i: usize = 0;
        while (i < command_args.len) : (i += 1) {
            const arg = sliceFromCStr(command_args[i]);
            if (arg.len > launch.argv_storage[i].len) {
                return error.ArgumentTooLong;
            }
            @memcpy(launch.argv_storage[i][0..arg.len], arg);
            launch.argv_len[i] = arg.len;
        }

        const process_name = sliceFromCStr(command_args[0]);
        const user_proc = process.create_exec_process(process_name);
        user_proc.stdin_redirect = stdin_fd;
        user_proc.stdout_redirect = stdout_fd;
        launch.pid = user_proc.pid;

        if (nice_value) |nice| {
            if (!scheduler.setProcessNice(user_proc.pid, nice)) {
                _ = process.setNice(user_proc.pid, nice);
            }
        }

        return user_proc.pid;
    }

    fn dispatchCommand(self: *Shell, command_id: registry.CommandId, args: []const [*:0]const u8) void {
        switch (command_id) {
            .help => core_commands.help(),
            .clear => core_commands.clear(),
            .echo => core_commands.echo(args),
            .ps => process_commands.ps(),
            .meminfo => process_commands.memInfo(),
            .uptime => process_commands.uptime(),
            .kill => process_commands.kill(args),
            .shutdown => self.cmdShutdown(),
            .memtest => system_commands.memTest(),
            .panic => system_commands.panicCmd(),
            .lsdev => system_commands.lsDev(),
            .multitask => system_commands.multitask(),
            .scheduler => system_commands.schedulerCommand(args),
            .schedstats => system_commands.schedStats(),
            .ls => fs_commands.ls(args),
            .cat => fs_commands.cat(args),
            .mkdir => fs_commands.mkdir(args),
            .rmdir => fs_commands.rmdir(args),
            .rm => fs_commands.rm(args),
            .mv => fs_commands.mv(args),
            .mount => fs_commands.mount(args),
            .ping => self.cmdPing(args),
            .httpd => self.cmdHttpd(args),
            .netstat => self.cmdNetstat(),
            .nslookup => self.cmdNslookup(args),
            .dhcp => self.cmdDhcp(args),
            .route => self.cmdRoute(args),
            .arp => self.cmdArp(args),
            .nettest => self.cmdNetTest(),
            .synctest => self.cmdSyncTest(),
            .ipctest => self.cmdIpcTest(),
            .procmon => self.cmdProcMon(),
            .top => self.cmdTop(),
            .cp => fs_commands.cp(args),
            .touch => fs_commands.touch(args),
            .write => fs_commands.write(args),
            .edit => self.cmdEdit(args),
            .nice => self.cmdNice(args),
            .renice => self.cmdRenice(args),
            .chmod => self.cmdChmod(args),
            .export_var => user_commands.exportVar(args),
            .unset => user_commands.unset(args),
            .env => user_commands.env(),
            .head => text_commands.head(args),
            .tail => text_commands.tail(args),
            .wc => text_commands.wc(args),
            .grep => text_commands.grep(args),
            .find => text_commands.find(args),
            .stat => text_commands.stat(args),
            .uname => user_commands.uname(args),
            .whoami => user_commands.whoami(),
            .pwd => user_commands.pwd(),
            .cd => user_commands.cd(args),
            .sort => self.cmdSort(args),
            .uniq => self.cmdUniq(args),
            .ifconfig => self.cmdIfconfig(args),
            .df => self.cmdDf(args),
            .smptest => self.cmdSmpTest(),
            .fileiotest => self.cmdFileioTest(),
            .ext2writetest => self.cmdExt2WriteTest(),
            .tcptest => self.cmdTcpTest(),
            .id => user_commands.id(),
            .date => user_commands.date(),
            .ln => user_commands.ln(args),
            .hostname => user_commands.hostname(args),
            .sleep => user_commands.sleep(args),
            .umask => user_commands.umask(args),
            .chown => user_commands.chown(args),
            .chgrp => user_commands.chgrp(args),
            .true_cmd => core_commands.trueCmd(),
            .false_cmd => core_commands.falseCmd(),
            .test_cmd => self.cmdTest(args),
            .hexdump => text_commands.hexdump(args),
            .which => text_commands.which(args),
        }
    }

    fn cmdShutdown(self: *Shell) void {
        vga.print("Shutting down...\n");
        self.running = false;
        while (true) {
            asm volatile ("hlt");
        }
    }

    fn cmdEdit(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: edit <file>\n");
            return;
        }

        const filename = sliceFromCStr(args[0]);
        const allocator = memory.getDefaultAllocator();

        var text_editor = editor.TextEditor.init(allocator) catch {
            vga.print("Failed to initialize editor\n");
            return;
        };
        defer text_editor.deinit();

        text_editor.loadFile(filename) catch |err| {
            vga.print("Warning: Could not load file: ");
            vga.print(@errorName(err));
            vga.print("\n");
        };

        vga.clear();
        text_editor.draw();

        while (text_editor.running) {
            if (keyboard.has_char()) {
                if (keyboard.getchar()) |key| {
                    text_editor.handleKey(key);
                    text_editor.draw();
                }
            }
        }

        vga.clear();
    }

    fn cmdNice(self: *const Shell, args: []const [*:0]const u8) void {
        if (args.len < 2) {
            vga.print("Usage: nice <priority> <command> [args...]\n");
            vga.print("Priority range: -20 (highest) to 19 (lowest)\n");
            return;
        }

        const priority_str = sliceFromCStr(args[0]);
        var priority: i8 = 0;
        var is_negative = false;
        var i: usize = 0;

        if (priority_str[0] == '-') {
            is_negative = true;
            i = 1;
        }

        while (i < priority_str.len) : (i += 1) {
            if (priority_str[i] >= '0' and priority_str[i] <= '9') {
                priority = priority * 10 + @as(i8, @intCast(priority_str[i] - '0'));
            } else {
                break;
            }
        }

        if (is_negative) {
            priority = -priority;
        }

        if (priority < -20) priority = -20;
        if (priority > 19) priority = 19;

        const command_name = sliceFromCStr(args[1]);

        if (registry.lookup(command_name) != null) {
            vga.print("nice: Priority adjustment for built-in commands is not supported.\n");
            vga.print("Built-in commands run in the shell context and cannot have their priority changed.\n");
            vga.print("To use priority adjustment, run an external program instead.\n");
            return;
        }

        const pid = self.launchExternalCommand(args[1..], priority) catch |err| {
            switch (err) {
                error.CommandNotFound => {
                    vga.print("nice: Command not found: ");
                    printString(args[1]);
                    vga.print("\n");
                },
                error.CommandPathTooLong => vga.print("nice: Command path too long\n"),
                error.ArgumentTooLong => vga.print("nice: Argument too long\n"),
                error.CommandReadFailed => vga.print("nice: Failed to read command file\n"),
                error.CommandTooLarge => vga.print("nice: Command file too large\n"),
                error.TooManyLaunches => vga.print("nice: Too many commands are pending launch\n"),
            }
            return;
        };

        vga.print("Running '");
        printString(args[1]);
        vga.print("' with nice value ");
        if (priority < 0) {
            vga.put_char('-');
            numfmt.printDec(@as(usize, @intCast(-priority)));
        } else {
            numfmt.printDec(@as(usize, @intCast(priority)));
        }
        vga.print(" (PID: ");
        numfmt.printDec(pid);
        vga.print(")\n");
    }

    fn cmdRenice(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: renice <priority> <pid>\n");
            vga.print("Priority range: -20 (highest) to 19 (lowest)\n");
            return;
        }

        const priority_str = sliceFromCStr(args[0]);
        var priority: i8 = 0;
        var is_negative = false;
        var i: usize = 0;

        if (priority_str[0] == '-') {
            is_negative = true;
            i = 1;
        }

        while (i < priority_str.len) : (i += 1) {
            if (priority_str[i] >= '0' and priority_str[i] <= '9') {
                priority = priority * 10 + @as(i8, @intCast(priority_str[i] - '0'));
            } else {
                break;
            }
        }

        if (is_negative) {
            priority = -priority;
        }

        if (priority < -20) priority = -20;
        if (priority > 19) priority = 19;

        const pid = parseNumber(args[1]) orelse 0;

        if (pid == 0) {
            vga.print("renice: Invalid PID\n");
            return;
        }

        if (scheduler.setProcessNice(pid, priority)) {
            vga.print("Changed nice value of process ");
            numfmt.printDec(pid);
            vga.print(" to ");
            if (priority < 0) {
                vga.put_char('-');
                numfmt.printDec(@as(usize, @intCast(-priority)));
            } else {
                numfmt.printDec(@as(usize, @intCast(priority)));
            }
            vga.print("\n");
        } else if (process.setNice(pid, priority)) {
            vga.print("Changed nice value of process ");
            numfmt.printDec(pid);
            vga.print(" to ");
            if (priority < 0) {
                vga.put_char('-');
                numfmt.printDec(@as(usize, @intCast(-priority)));
            } else {
                numfmt.printDec(@as(usize, @intCast(priority)));
            }
            vga.print("\n");
        } else {
            vga.print("Failed to change priority: process ");
            numfmt.printDec(pid);
            vga.print(" not found\n");
        }
    }

    fn cmdChmod(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: chmod <mode> <file>\n");
            vga.print("Example: chmod 755 file.txt\n");
            return;
        }

        const mode_str = sliceFromCStr(args[0]);
        var mode_value: u16 = 0;
        for (mode_str) |c| {
            if (c >= '0' and c <= '7') {
                mode_value = mode_value * 8 + (c - '0');
            } else {
                vga.print("Invalid mode: ");
                printString(args[0]);
                vga.print("\n");
                return;
            }
        }

        const mode = vfs.FileMode{
            .owner_read = (mode_value & 0o400) != 0,
            .owner_write = (mode_value & 0o200) != 0,
            .owner_exec = (mode_value & 0o100) != 0,
            .group_read = (mode_value & 0o040) != 0,
            .group_write = (mode_value & 0o020) != 0,
            .group_exec = (mode_value & 0o010) != 0,
            .other_read = (mode_value & 0o004) != 0,
            .other_write = (mode_value & 0o002) != 0,
            .other_exec = (mode_value & 0o001) != 0,
        };

        const path = sliceFromCStr(args[1]);
        vfs.chmod(path, mode) catch |err| {
            vga.print("chmod: ");
            printString(args[1]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("Changed permissions of ");
        printString(args[1]);
        vga.print(" to ");
        printString(args[0]);
        vga.print("\n");
    }

    fn cmdTrue(self: *const Shell) void {
        _ = self;
    }

    fn cmdFalse(self: *const Shell) void {
        _ = self;
        vga.print("");
    }

    fn cmdTest(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("false\n");
            return;
        }

        const arg = sliceFromCStr(args[0]);

        if (args.len == 1) {
            if (arg.len > 0) {
                vga.print("true\n");
            } else {
                vga.print("false\n");
            }
            return;
        }

        if (args.len == 2) {
            const op = sliceFromCStr(args[0]);
            const operand = sliceFromCStr(args[1]);

            if (strEqlSlice(op, "-n")) {
                if (operand.len > 0) {
                    vga.print("true\n");
                } else {
                    vga.print("false\n");
                }
                return;
            } else if (strEqlSlice(op, "-z")) {
                if (operand.len == 0) {
                    vga.print("true\n");
                } else {
                    vga.print("false\n");
                }
                return;
            } else if (strEqlSlice(op, "-e") or strEqlSlice(op, "-f") or strEqlSlice(op, "-d")) {
                if (vfs.lookupPath(operand)) |vnode| {
                    if (strEqlSlice(op, "-d")) {
                        if (vnode.file_type == .Directory) {
                            vga.print("true\n");
                        } else {
                            vga.print("false\n");
                        }
                    } else {
                        vga.print("true\n");
                    }
                } else |_| {
                    vga.print("false\n");
                }
                return;
            }
        }

        if (args.len == 3) {
            const left = sliceFromCStr(args[0]);
            const op = sliceFromCStr(args[1]);
            const right = sliceFromCStr(args[2]);

            if (strEqlSlice(op, "=") or strEqlSlice(op, "==")) {
                if (strEqlSlice(left, right)) {
                    vga.print("true\n");
                } else {
                    vga.print("false\n");
                }
                return;
            } else if (strEqlSlice(op, "!=")) {
                if (!strEqlSlice(left, right)) {
                    vga.print("true\n");
                } else {
                    vga.print("false\n");
                }
                return;
            }
        }

        vga.print("test: invalid expression\n");
    }

    fn strEqlSlice(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ac, bc| {
            if (ac != bc) return false;
        }
        return true;
    }

    const LineSpan = struct {
        start: usize,
        len: usize,
    };

    fn lineLessThan(file_buffer: []const u8, lhs: LineSpan, rhs: LineSpan) bool {
        const left = file_buffer[lhs.start .. lhs.start + lhs.len];
        const right = file_buffer[rhs.start .. rhs.start + rhs.len];
        const min_len = @min(left.len, right.len);

        var i: usize = 0;
        while (i < min_len) : (i += 1) {
            if (left[i] != right[i]) {
                return left[i] < right[i];
            }
        }

        return left.len < right.len;
    }

    fn sortLines(file_buffer: []const u8, lines: []LineSpan) void {
        var i: usize = 1;
        while (i < lines.len) : (i += 1) {
            const current = lines[i];
            var j = i;
            while (j > 0 and lineLessThan(file_buffer, current, lines[j - 1])) : (j -= 1) {
                lines[j] = lines[j - 1];
            }
            lines[j] = current;
        }
    }

    fn cmdSort(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: sort <file>\n");
            return;
        }

        const path = sliceFromCStr(args[0]);
        const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
            vga.print("sort: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        var line_count: usize = 0;
        // SAFETY: filled by the subsequent vfs.read calls
        var file_buffer: [4096]u8 = undefined;
        var total_read: usize = 0;

        while (total_read < file_buffer.len) {
            const bytes_read = vfs.read(fd, file_buffer[total_read..]) catch |err| {
                if (err != error.EndOfFile) {
                    vga.print("\nread error: ");
                    vga.print(@errorName(err));
                    vga.print("\n");
                }
                break;
            };
            if (bytes_read == 0) break;
            total_read += bytes_read;
        }

        var lines: [256]LineSpan = undefined;
        var current_line_start: usize = 0;
        var i: usize = 0;

        while (i < total_read and line_count < 256) {
            if (file_buffer[i] == '\n' or file_buffer[i] == '\r') {
                if (i > current_line_start) {
                    lines[line_count] = .{
                        .start = current_line_start,
                        .len = i - current_line_start,
                    };
                    line_count += 1;
                }
                if (file_buffer[i] == '\r' and i + 1 < total_read and file_buffer[i + 1] == '\n') {
                    i += 2;
                } else {
                    i += 1;
                }
                current_line_start = i;
            } else {
                i += 1;
            }
        }

        if (current_line_start < total_read and line_count < 256) {
            lines[line_count] = .{
                .start = current_line_start,
                .len = total_read - current_line_start,
            };
            line_count += 1;
        }

        sortLines(file_buffer[0..total_read], lines[0..line_count]);

        var j: usize = 0;
        while (j < line_count) : (j += 1) {
            const line = file_buffer[lines[j].start .. lines[j].start + lines[j].len];
            for (line) |byte| {
                vga.put_char(byte);
            }
            vga.put_char('\n');
        }
    }

    fn cmdUniq(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: uniq <file>\n");
            return;
        }

        const path = sliceFromCStr(args[0]);
        const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
            vga.print("uniq: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: filled by the subsequent vfs.read call
        var buffer: [512]u8 = undefined;
        // SAFETY: characters accumulated during line comparison
        var prev_line: [256]u8 = undefined;
        var prev_line_len: usize = 0;
        // SAFETY: characters accumulated during line comparison
        var current_line: [256]u8 = undefined;
        var current_line_len: usize = 0;
        var first_line = true;

        while (true) {
            const bytes_read = vfs.read(fd, &buffer) catch |err| {
                if (err != error.EndOfFile) {
                    vga.print("\nread error: ");
                    vga.print(@errorName(err));
                    vga.print("\n");
                }
                break;
            };

            if (bytes_read == 0) break;

            for (buffer[0..bytes_read]) |byte| {
                if (byte == '\r') continue;

                if (byte == '\n') {
                    current_line[current_line_len] = 0;
                    const current_slice = current_line[0..current_line_len];

                    if (first_line) {
                        for (current_slice) |c| {
                            vga.put_char(c);
                        }
                        vga.put_char('\n');
                        @memcpy(&prev_line, &current_line);
                        prev_line_len = current_line_len;
                        first_line = false;
                    } else {
                        var different = false;
                        if (current_line_len != prev_line_len) {
                            different = true;
                        } else {
                            var i: usize = 0;
                            while (i < current_line_len) : (i += 1) {
                                if (current_slice[i] != prev_line[i]) {
                                    different = true;
                                    break;
                                }
                            }
                        }

                        if (different) {
                            for (current_slice) |c| {
                                vga.put_char(c);
                            }
                            vga.put_char('\n');
                            @memcpy(&prev_line, &current_line);
                            prev_line_len = current_line_len;
                        }
                    }

                    current_line_len = 0;
                } else {
                    if (current_line_len < current_line.len - 1) {
                        current_line[current_line_len] = byte;
                        current_line_len += 1;
                    }
                }
            }
        }

        if (current_line_len > 0) {
            current_line[current_line_len] = 0;
            const current_slice = current_line[0..current_line_len];

            if (first_line) {
                for (current_slice) |c| {
                    vga.put_char(c);
                }
                vga.put_char('\n');
            } else {
                var different = false;
                if (current_line_len != prev_line_len) {
                    different = true;
                } else {
                    var i: usize = 0;
                    while (i < current_line_len) : (i += 1) {
                        if (current_slice[i] != prev_line[i]) {
                            different = true;
                            break;
                        }
                    }
                }

                if (different) {
                    for (current_slice) |c| {
                        vga.put_char(c);
                    }
                    vga.put_char('\n');
                }
            }
        }
    }

    fn cmdIfconfig(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        _ = args;

        const interface_name = "eth0";
        const mac_addr = network.getMacAddress();

        vga.print(interface_name);
        vga.print(": flags=4093<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n");
        vga.print("        inet ");
        network.printIPv4(network.getLocalIP());
        vga.print("  netmask ");
        network.printIPv4(network.getNetmask());
        vga.print("  broadcast ");

        const local_ip = network.getLocalIP();
        const netmask = network.getNetmask();
        const ipv4_mod = network.ipv4;
        const broadcast = ipv4_mod.IPv4Address{
            .octets = .{
                local_ip.octets[0] | (~netmask.octets[0] & 0xFF),
                local_ip.octets[1] | (~netmask.octets[1] & 0xFF),
                local_ip.octets[2] | (~netmask.octets[2] & 0xFF),
                local_ip.octets[3] | (~netmask.octets[3] & 0xFF),
            },
        };
        network.printIPv4(broadcast);
        vga.print("\n");

        vga.print("        ether ");
        var i: usize = 0;
        while (i < 6) : (i += 1) {
            const byte = mac_addr[i];
            const high = (byte >> 4) & 0xF;
            const low = byte & 0xF;
            if (high < 10) {
                vga.put_char(@as(u8, @intCast('0' + high)));
            } else {
                vga.put_char(@as(u8, @intCast('a' + high - 10)));
            }
            if (low < 10) {
                vga.put_char(@as(u8, @intCast('0' + low)));
            } else {
                vga.put_char(@as(u8, @intCast('a' + low - 10)));
            }
            if (i < 5) vga.put_char(':');
        }
        vga.print("\n");

        const gateway = network.getGateway();
        if (gateway.octets[0] != 0 or gateway.octets[1] != 0 or gateway.octets[2] != 0 or gateway.octets[3] != 0) {
            vga.print("        gateway ");
            network.printIPv4(gateway);
            vga.print("\n");
        }
    }

    fn cmdDf(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        _ = args;

        const stats = paging.getMemoryStats();

        vga.print("Filesystem     1K-blocks      Used Available Use% Mounted on\n");

        const total_kb = stats.total_frames * 4096 / 1024;
        const used_kb = stats.used_frames * 4096 / 1024;
        const free_kb = total_kb - used_kb;
        const use_percent = if (total_kb > 0) (used_kb * 100) / total_kb else 0;

        vga.print("rootfs          ");
        numfmt.printDec(total_kb);
        vga.print("      ");
        numfmt.printDec(used_kb);
        vga.print("      ");
        numfmt.printDec(free_kb);
        vga.print("   ");
        numfmt.printDec(use_percent);
        vga.print("% /\n");
    }

    fn cmdPing(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;

        if (args.len == 0) {
            vga.print("Usage: ping <ip_address>\n");
            vga.print("Example: ping 192.168.1.1\n");
            return;
        }

        const ip_str = sliceFromCStr(args[0]);
        if (network.parseIPv4(ip_str)) |ip| {
            vga.print("Pinging ");
            printString(args[0]);
            vga.print("...\n");
            network.ping(ip);
        } else {
            vga.print("Invalid IP address: ");
            printString(args[0]);
            vga.print("\n");
        }
    }

    fn cmdHttpd(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const http = @import("../net/http.zig");

        if (args.len == 0) {
            vga.print("Usage: httpd <start|stop> [port]\n");
            vga.print("Example: httpd start 8080\n");
            return;
        }

        if (streq(args[0], "start")) {
            var port: u16 = 80;
            if (args.len > 1) {
                port = parseNumberU16(sliceFromCStr(args[1]));
            }

            vga.print("Starting HTTP server on port ");
            numfmt.printDec(port);
            vga.print("...\n");

            var server = http.HTTPServer.init(port);
            server.start() catch {
                vga.print("Failed to start HTTP server\n");
                return;
            };

            const server_process = process.create_process("httpd", struct {
                fn serverLoop() void {
                    var s = http.HTTPServer.init(80);
                    s.start() catch return;
                    s.handleConnections();
                }
            }.serverLoop);
            _ = server_process;

            vga.print("HTTP server started successfully\n");
        } else if (streq(args[0], "stop")) {
            vga.print("Stopping HTTP server...\n");
            vga.print("HTTP server stopped\n");
        } else {
            vga.print("Unknown action: ");
            printString(args[0]);
            vga.print("\n");
        }
    }

    fn cmdNetstat(self: *const Shell) void {
        _ = self;
        vga.print("Network Statistics:\n");
        vga.print("------------------\n");

        const local_ip = network.getLocalIP();
        vga.print("Local IP: ");
        network.printIPv4(local_ip);
        vga.print("\n");

        const gateway = network.getGateway();
        vga.print("Gateway: ");
        network.printIPv4(gateway);
        vga.print("\n");

        const netmask = network.getNetmask();
        vga.print("Netmask: ");
        network.printIPv4(netmask);
        vga.print("\n");

        vga.print("\nActive Connections:\n");
        vga.print("Proto  Local Address       Foreign Address     State\n");
        vga.print("-----  -----------------   -----------------   -----\n");
    }

    fn cmdNslookup(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const dns = @import("../net/dns.zig");

        if (args.len == 0) {
            vga.print("Usage: nslookup <domain>\n");
            vga.print("Example: nslookup example.com\n");
            return;
        }

        vga.print("Looking up ");
        printString(args[0]);
        vga.print("...\n");

        var domain_len: usize = 0;
        while (args[0][domain_len] != 0) : (domain_len += 1) {}
        const domain = args[0][0..domain_len];

        const ip = dns.resolve(domain) catch |err| {
            vga.print("Failed to resolve: ");
            switch (err) {
                error.NotInitialized => vga.print("DNS not initialized\n"),
                error.InvalidResponse => vga.print("Invalid DNS response\n"),
                error.NotResponse => vga.print("Not a DNS response\n"),
                error.DNSError => vga.print("DNS server error\n"),
                error.NoAnswer => vga.print("No answer from DNS server\n"),
                error.NoARecord => vga.print("No A record found\n"),
                else => vga.print("Unknown error\n"),
            }
            return;
        };

        printString(args[0]);
        vga.print(" -> ");
        network.printIPv4(ip);
        vga.print("\n");
    }

    fn cmdDhcp(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const dhcp = @import("../net/dhcp.zig");

        if (args.len == 0) {
            vga.print("Usage: dhcp <request|release>\n");
            return;
        }

        if (streq(args[0], "request")) {
            vga.print("Requesting IP address via DHCP...\n");
            dhcp.requestAddress() catch |err| {
                vga.print("DHCP request failed: ");
                switch (err) {
                    error.NotInitialized => vga.print("DHCP not initialized\n"),
                    else => vga.print("Unknown error\n"),
                }
            };
        } else if (streq(args[0], "release")) {
            vga.print("Releasing DHCP lease...\n");
            dhcp.releaseAddress() catch |err| {
                vga.print("DHCP release failed: ");
                switch (err) {
                    error.NotInitialized => vga.print("DHCP not initialized\n"),
                    else => vga.print("Unknown error\n"),
                }
            };
        } else {
            vga.print("Unknown DHCP command: ");
            printString(args[0]);
            vga.print("\n");
        }
    }

    fn cmdRoute(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        _ = args;
        const routing = @import("../net/routing.zig");

        const table = routing.getRoutingTable();
        table.printRoutes();
    }

    fn cmdArp(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        _ = args;
        const routing = @import("../net/routing.zig");

        const table = routing.getRoutingTable();
        table.printARPCache();
    }

    fn cmdNetTest(self: *const Shell) void {
        _ = self;
        const net_test = @import("../tests/net_test.zig");
        net_test.runNetworkTests();
    }

    fn cmdSyncTest(self: *const Shell) void {
        _ = self;
        const sync = @import("../utils/sync.zig");
        sync.runSynchronizationTests();
    }

    fn cmdIpcTest(self: *const Shell) void {
        _ = self;
        const ipc = @import("../process/ipc.zig");
        ipc.runIPCTests();
    }

    fn cmdSmpTest(self: *const Shell) void {
        _ = self;
        const test_smp = @import("../tests/test_smp.zig");
        test_smp.runSMPTests();
    }

    fn cmdFileioTest(self: *const Shell) void {
        _ = self;
        const test_file_io = @import("../tests/test_file_io.zig");
        test_file_io.runFileIOTests();
    }

    fn cmdExt2WriteTest(self: *const Shell) void {
        _ = self;
        const test_ext2 = @import("../tests/test_ext2_write.zig");
        test_ext2.runExt2WriteTests();
    }

    fn cmdTcpTest(self: *const Shell) void {
        _ = self;
        const test_tcp = @import("../tests/test_tcp_reliability.zig");
        test_tcp.runTCPReliabilityTests();
    }

    fn cmdProcMon(self: *const Shell) void {
        _ = self;
        const procmon = @import("../tests/procmon.zig");
        procmon.printSystemStats();
    }

    fn cmdTop(self: *const Shell) void {
        _ = self;
        const procmon = @import("../tests/procmon.zig");

        vga.clear();
        procmon.printCPUGraph();
        vga.print("\n");

        const cpu = procmon.getCPUUsage();
        vga.print("CPU: User: ");
        numfmt.printDec(cpu.user_percent);
        vga.print("% System: ");
        numfmt.printDec(cpu.system_percent);
        vga.print("% Idle: ");
        numfmt.printDec(cpu.idle_percent);
        vga.print("%\n");

        procmon.printProcessList();
    }

    fn parseNumberU16(str: []const u8) u16 {
        var result: u16 = 0;
        for (str) |c| {
            if (c >= '0' and c <= '9') {
                result = result * 10 + (c - '0');
            } else {
                break;
            }
        }
        return result;
    }
};

fn allocateExternalCommandLaunch() ExternalLaunchError!*ExternalCommandLaunch {
    for (&external_command_launches) |*launch| {
        if (!launch.in_use) {
            launch.* = ExternalCommandLaunch{ .in_use = true };
            return launch;
        }
    }
    return error.TooManyLaunches;
}

fn releaseExternalCommandLaunch(launch: *ExternalCommandLaunch) void {
    launch.* = ExternalCommandLaunch{};
}

fn findExternalCommandLaunch(pid: u32) ?*ExternalCommandLaunch {
    for (&external_command_launches) |*launch| {
        if (launch.in_use and launch.pid == pid) {
            return launch;
        }
    }
    return null;
}

pub export fn external_command_entry_c() callconv(.c) void {
    const pid = process.getCurrentPID();
    const launch = findExternalCommandLaunch(pid) orelse {
        vga.print("exec: missing launch context\n");
        _ = process.terminateProcess(pid);
        return;
    };

    var path_buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
    const path_len = launch.path_len;
    @memcpy(path_buffer[0..path_len], launch.path[0..path_len]);

    var argv_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = undefined;
    var argv: [MAX_ARGS][]const u8 = undefined;
    const argc = launch.argc;

    var i: usize = 0;
    while (i < argc) : (i += 1) {
        const arg_len = launch.argv_len[i];
        @memcpy(argv_storage[i][0..arg_len], launch.argv_storage[i][0..arg_len]);
        argv[i] = argv_storage[i][0..arg_len];
    }

    var envp: [0][]const u8 = undefined;
    posix.execveFromData(launch.file_storage[0..launch.file_len], argv[0..argc], &envp) catch |err| {
        console.print("Failed to execute ");
        console.print(path_buffer[0..path_len]);
        console.print(": ");
        console.print(@errorName(err));
        console.print("\n");
        _ = process.terminateProcess(pid);
    };
}

fn waitForExternalCommand(pid: u32) bool {
    const exit_code = posix.waitForProcess(pid) catch |err| {
        if (findExternalCommandLaunch(pid)) |launch| {
            releaseExternalCommandLaunch(launch);
        }
        vga.print("Failed to wait for command: ");
        vga.print(@errorName(err));
        vga.print("\n");
        return false;
    };

    if (findExternalCommandLaunch(pid)) |launch| {
        releaseExternalCommandLaunch(launch);
    }

    if (exit_code != 0) {
        vga.print("Command exited with status ");
        numfmt.printDec(@as(usize, @intCast(if (exit_code < 0) -exit_code else exit_code)));
        vga.print("\n");
        return false;
    }

    return true;
}

fn containsShellOperators(tokens: []const [*:0]const u8) bool {
    for (tokens) |token| {
        const slice = sliceFromCStr(token);
        if (std.mem.eql(u8, slice, "|") or std.mem.eql(u8, slice, "<") or std.mem.eql(u8, slice, ">") or std.mem.eql(u8, slice, ">>")) {
            return true;
        }
    }
    return false;
}

fn parsePipeline(tokens: []const [*:0]const u8) PipelineConfigError!ParsedPipeline {
    var result = ParsedPipeline{};
    result.stage_count = 1;

    var stage_idx: usize = 0;
    var token_idx: usize = 0;
    while (token_idx < tokens.len) : (token_idx += 1) {
        const token = tokens[token_idx];
        const token_slice = sliceFromCStr(token);
        var stage = &result.stages[stage_idx];

        if (std.mem.eql(u8, token_slice, "|")) {
            if (stage.arg_count == 0) return error.EmptyStage;
            if (stage_idx + 1 >= MAX_PIPE_STAGES) return error.TooManyStages;
            stage_idx += 1;
            result.stage_count = stage_idx + 1;
            continue;
        }

        if (std.mem.eql(u8, token_slice, "<")) {
            if (token_idx + 1 >= tokens.len) return error.MissingPath;
            if (stage_idx != 0 or stage.stdin_path != null) return error.UnsupportedRedirection;
            token_idx += 1;
            stage.stdin_path = tokens[token_idx];
            continue;
        }

        if (std.mem.eql(u8, token_slice, ">") or std.mem.eql(u8, token_slice, ">>")) {
            if (token_idx + 1 >= tokens.len) return error.MissingPath;
            if (stage.stdout_path != null) return error.UnsupportedRedirection;
            token_idx += 1;
            stage.stdout_path = tokens[token_idx];
            stage.append_stdout = std.mem.eql(u8, token_slice, ">>");
            continue;
        }

        if (stage.arg_count >= MAX_ARGS) return error.ArgumentTooLong;
        stage.args[stage.arg_count] = token;
        stage.arg_count += 1;
    }

    for (result.stages[0..result.stage_count]) |stage| {
        if (stage.arg_count == 0) return error.EmptyStage;
    }

    if (result.stage_count > 1) {
        if (result.stages[0].stdout_path != null) return error.UnsupportedRedirection;
        var idx: usize = 1;
        while (idx < result.stage_count) : (idx += 1) {
            const stage = result.stages[idx];
            if (idx < result.stage_count - 1 and stage.stdout_path != null) return error.UnsupportedRedirection;
            if (stage.stdin_path != null) return error.UnsupportedRedirection;
        }
    }

    return result;
}

fn validatePipelineStages(pipeline: *const ParsedPipeline) bool {
    for (pipeline.stages[0..pipeline.stage_count]) |stage| {
        const command_name = sliceFromCStr(stage.args[0]);
        if (registry.lookup(command_name) != null) {
            vga.print("Pipelines and redirection currently require external commands: ");
            printString(stage.args[0]);
            vga.print("\n");
            return false;
        }
    }
    return true;
}

fn openRedirectFd(path: [*:0]const u8, flags: u32) PipelineConfigError!i32 {
    const raw_fd = vfs.open(sliceFromCStr(path), flags) catch return error.OpenFailed;
    errdefer vfs.close(raw_fd) catch {};
    const child_fd = vfs.dup(raw_fd) catch return error.DupFailed;
    vfs.close(raw_fd) catch return error.CloseFailed;
    return @as(i32, @intCast(child_fd)) + @as(i32, @intCast(vfsAbiFdOffset()));
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

fn closeRedirectFd(fd: ?i32) void {
    if (fd) |value| {
        if (value >= @as(i32, @intCast(vfsAbiFdOffset()))) {
            const vfs_fd: u32 = @intCast(value - @as(i32, @intCast(vfsAbiFdOffset())));
            vfs.close(vfs_fd) catch {};
        }
    }
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
        error.OpenFailed => vga.print("Failed to open redirection target\n"),
        error.PipeFailed => vga.print("Failed to create pipe\n"),
        error.DupFailed => vga.print("Failed to duplicate file descriptor\n"),
        error.CloseFailed => vga.print("Failed to close temporary file descriptor\n"),
        error.ArgumentTooLong => vga.print("Too many arguments in pipeline stage\n"),
    }
}

fn vfsAbiFdOffset() u32 {
    return @import("../process/syscall/abi.zig").FD_OFFSET;
}

fn readExternalCommandBytes(path: []const u8, buffer: []u8) ExternalLaunchError!usize {
    const fd = vfs.open(path, vfs.O_RDONLY) catch return error.CommandReadFailed;
    defer vfs.close(fd) catch {};

    var stat_buf: vfs.FileStat = undefined;
    vfs.fstat(fd, &stat_buf) catch return error.CommandReadFailed;
    const size: usize = @intCast(stat_buf.size);
    if (size > buffer.len) return error.CommandTooLarge;

    const bytes_read = vfs.read(fd, buffer[0..size]) catch return error.CommandReadFailed;
    if (bytes_read != size) return error.CommandReadFailed;
    return size;
}

fn resolveExternalCommandPath(command_name: []const u8, buffer: *[MAX_COMMAND_LENGTH]u8) ExternalLaunchError![]const u8 {
    if (command_name.len == 0) {
        return error.CommandNotFound;
    }

    if (isExplicitCommandPath(command_name)) {
        if (command_name.len > buffer.len) {
            return error.CommandPathTooLong;
        }

        @memcpy(buffer[0..command_name.len], command_name);
        const direct_path = buffer[0..command_name.len];
        if (externalCommandPathExists(direct_path)) {
            return direct_path;
        }
        return error.CommandNotFound;
    }

    const search_prefixes = [_][]const u8{ "/bin/", "/usr/bin/", "/mnt/bin/" };
    var path_too_long = true;

    for (search_prefixes) |prefix| {
        if (prefix.len + command_name.len > buffer.len) {
            continue;
        }

        path_too_long = false;
        @memcpy(buffer[0..prefix.len], prefix);
        @memcpy(buffer[prefix.len .. prefix.len + command_name.len], command_name);

        const candidate = buffer[0 .. prefix.len + command_name.len];
        if (externalCommandPathExists(candidate)) {
            return candidate;
        }
    }

    if (path_too_long) {
        return error.CommandPathTooLong;
    }

    return error.CommandNotFound;
}

fn externalCommandPathExists(path: []const u8) bool {
    const fd = vfs.open(path, vfs.O_RDONLY) catch return false;
    vfs.close(fd) catch {};
    return true;
}

fn isExplicitCommandPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/') return true;

    for (path) |char| {
        if (char == '/') return true;
    }

    return false;
}

fn printExternalCommandError(command: [*:0]const u8, err: ExternalLaunchError) void {
    switch (err) {
        error.CommandNotFound => {
            vga.print("Unknown command: ");
            printString(command);
            vga.print("\nType 'help' for available commands.\n");
        },
        error.CommandPathTooLong => vga.print("Command path too long\n"),
        error.ArgumentTooLong => vga.print("Command argument too long\n"),
        error.CommandReadFailed => vga.print("Failed to read command file\n"),
        error.CommandTooLarge => vga.print("Command file too large\n"),
        error.TooManyLaunches => vga.print("Too many commands are pending launch\n"),
    }
}

fn isWhitespace(char: u8) bool {
    return char == ' ' or char == '\t';
}

fn streq(a: [*:0]const u8, b: [*:0]const u8) bool {
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return a[i] == b[i];
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
        if (str[i] < '0' or str[i] > '9') {
            return null;
        }

        const digit = str[i] - '0';
        const new_result = result *% 10 +% digit;

        if (new_result < result) {
            return null;
        }

        result = new_result;
    }

    return result;
}

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}
