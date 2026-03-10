// zlint-disable suppressed-errors
const vga = @import("../drivers/vga.zig");
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

const MAX_COMMAND_LENGTH = 256;
const MAX_ARGS = 16;
const MAX_HISTORY = 50;

// SAFETY: written via memcpy before being read; length tracked by nice_command_path_len_storage
var nice_command_path_storage: [256]u8 = undefined;
var nice_command_path_len_storage: usize = 0;

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
                self.executeCommand();
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

    fn executeCommand(self: *Shell) void {
        if (self.buffer_pos == 0) {
            return;
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

                while (i < self.buffer_pos and isWhitespace(self.command_buffer[i])) : (i += 1) {}
                arg_start = i;
            } else {
                i += 1;
            }
        }

        if (arg_count == 0) {
            return;
        }

        const command = args[0];
        const command_name = sliceFromCStr(command);
        const command_meta = registry.lookup(command_name) orelse {
            vga.print("Unknown command: ");
            printString(command);
            vga.print("\nType 'help' for available commands.\n");
            return;
        };

        self.dispatchCommand(command_meta.id, args[1..arg_count]);
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
        _ = self;
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

        // SAFETY: filled by the subsequent path resolution logic
        var command_path: [256]u8 = undefined;
        var path_len: usize = 0;

        if (command_name.len + 5 < command_path.len) {
            @memcpy(command_path[0..4], "/bin");
            command_path[4] = '/';
            @memcpy(command_path[5 .. 5 + command_name.len], command_name);
            command_path[5 + command_name.len] = 0;
            path_len = 5 + command_name.len;
        } else {
            vga.print("nice: Command path too long\n");
            return;
        }

        var file_found = false;
        if (vfs.open(command_path[0..path_len], vfs.O_RDONLY)) |fd| {
            vfs.close(fd) catch {};
            file_found = true;
        } else |_| {
            if (command_name.len < command_path.len) {
                @memcpy(command_path[0..command_name.len], command_name);
                command_path[command_name.len] = 0;
                path_len = command_name.len;

                if (vfs.open(command_path[0..path_len], vfs.O_RDONLY)) |fd| {
                    vfs.close(fd) catch {};
                    file_found = true;
                } else |_| {
                    file_found = false;
                }
            }
        }

        if (!file_found) {
            vga.print("nice: Command not found: ");
            printString(args[1]);
            vga.print("\n");
            return;
        }

        @memcpy(&nice_command_path_storage, &command_path);
        nice_command_path_len_storage = path_len;

        const ExecWrapper = struct {
            fn exec_wrapper() void {
                const posix2 = @import("../utils/posix.zig");

                // SAFETY: filled by the subsequent memcpy from nice_command_path_storage
                var path_buf: [256]u8 = undefined;
                @memcpy(&path_buf, &nice_command_path_storage);

                // SAFETY: element assigned immediately below
                var argv: [1][]const u8 = undefined;
                argv[0] = path_buf[0..nice_command_path_len_storage];

                // SAFETY: zero-length array, no elements to initialize
                var envp: [0][]const u8 = undefined;

                posix2.execve(path_buf[0..nice_command_path_len_storage], &argv, &envp) catch |err| {
                    const vga2 = @import("../drivers/vga.zig");
                    vga2.print("nice: Failed to execute: ");
                    vga2.print(@errorName(err));
                    vga2.print("\n");
                    _ = process.terminateProcess(process.getCurrentPID());
                };
            }
        };

        const user_proc = process.create_user_process(command_name, ExecWrapper.exec_wrapper);

        if (scheduler.setProcessNice(user_proc.pid, priority)) {
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
            numfmt.printDec(user_proc.pid);
            vga.print(")\n");
        } else {
            if (process.setNice(user_proc.pid, priority)) {
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
                numfmt.printDec(user_proc.pid);
                vga.print(")\n");
            } else {
                vga.print("nice: Failed to set priority\n");
            }
        }
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
