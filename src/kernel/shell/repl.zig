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
const signal = @import("../process/signal.zig");
const editor = @import("editor.zig");
const registry = @import("registry.zig");
const memory = @import("../memory/memory.zig");
const keyboard = @import("../drivers/keyboard.zig");
const numfmt = @import("../utils/numfmt.zig");
const posix = @import("../utils/posix.zig");
const cwd_mod = @import("../process/syscall/cwd.zig");
const environ = @import("../utils/environ.zig");
const common = @import("common.zig");
const parser = @import("parser/pipeline.zig");
const jobctl = @import("jobs.zig");
const glob = @import("glob.zig");
const execution = @import("runtime.zig");
const shell_external = @import("launcher.zig");
const httpd_runtime = @import("httpd.zig");

const printString = common.printString;
const sliceFromCStr = common.sliceFromCStr;

const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;
const MAX_ARGS = parser.MAX_ARGS;
const MAX_HISTORY = 50;
const MAX_TOKENS = parser.MAX_TOKENS;

const TokenKind = parser.TokenKind;
const CommandToken = parser.CommandToken;
const BackgroundJob = jobctl.BackgroundJob;

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
    job_table: jobctl.JobTable,
    next_capture_id: u32,

    pub fn init() Shell {
        return Shell{
            .command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH,
            .buffer_pos = 0,
            .cursor_pos = 0,
            .running = true,
            .history = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_HISTORY,
            .history_count = 0,
            .history_index = 0,
            .job_table = .{},
            .next_capture_id = 1,
        };
    }

    pub fn latestBackgroundPid(self: *Shell) ?u32 {
        return self.job_table.latestPid();
    }

    pub fn handleChar(self: *Shell, char: u8) void {
        if (foregroundPidSignal(self, char)) {
            return;
        }

        switch (char) {
            '\n' => {
                if (self.buffer_pos > 0) {
                    self.addToHistory();
                }
                _ = self.executeCommand(false);
                pollBackgroundJobs(self, true);
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
        const syscall_mod = @import("../process/syscall/exports.zig");
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
        const runtime = makeExecutionRuntime(self);
        return execution.executeLine(&runtime, self.command_buffer[0..self.buffer_pos], wait_for_external);
    }

    fn dispatchCommand(self: *Shell, command_id: registry.CommandId, args: []const [*:0]const u8) void {
        switch (command_id) {
            .help => core_commands.help(),
            .clear => core_commands.clear(),
            .meminfo => process_commands.memInfo(),
            .uptime => process_commands.uptime(),
            .jobs => self.cmdJobs(),
            .fg => self.cmdFg(args),
            .bg => self.cmdBg(args),
            .shutdown => self.cmdShutdown(),
            .memtest => system_commands.memTest(),
            .panic => system_commands.panicCmd(),
            .lsdev => system_commands.lsDev(),
            .multitask => system_commands.multitask(),
            .scheduler => system_commands.schedulerCommand(args),
            .schedstats => system_commands.schedStats(),
            .rmdir => fs_commands.rmdir(args),
            .mount => fs_commands.mount(args),
            .umount => fs_commands.umount(args),
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
            .write => fs_commands.write(args),
            .edit => self.cmdEdit(args),
            .nice => self.cmdNice(args),
            .renice => self.cmdRenice(args),
            .chmod => self.cmdChmod(args),
            .export_var => user_commands.exportVar(args),
            .unset => user_commands.unset(args),
            .find => text_commands.find(args),
            .stat => text_commands.stat(args),
            .cd => user_commands.cd(args),
            .ifconfig => self.cmdIfconfig(args),
            .df => self.cmdDf(args),
            .smptest => self.cmdSmpTest(),
            .fileiotest => self.cmdFileioTest(),
            .ext2writetest => self.cmdExt2WriteTest(),
            .tcptest => self.cmdTcpTest(),
            .ln => user_commands.ln(args),
            .umask => user_commands.umask(args),
            .chown => user_commands.chown(args),
            .chgrp => user_commands.chgrp(args),
            else => unreachable,
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

    fn cmdJobs(self: *Shell) void {
        pollBackgroundJobs(self, false);

        var found = false;
        for (&self.job_table.jobs) |*job| {
            if (!job.active) continue;
            found = true;
            var line_buf: [32]u8 = undefined;
            const prefix = std.fmt.bufPrint(&line_buf, "[{d}] {s} ", .{ job.id, if (job.stopped) "Stopped" else "Running" }) catch "[?] Running ";
            console.print(prefix);
            console.print(job.commandSlice());
            console.print("\n");
        }

        if (!found) {
            console.print("No background jobs\n");
        }
    }

    fn cmdFg(self: *Shell, args: []const [*:0]const u8) void {
        pollBackgroundJobs(self, false);
        const job = findSelectedJob(self, args) orelse {
            vga.print("fg: no such job\n");
            return;
        };

        if (job.stopped) {
            signal.kill(@intCast(job.pid), signal.SIGCONT) catch {
                vga.print("fg: failed to continue job\n");
                return;
            };
            job.stopped = false;
        }

        console.print(job.commandSlice());
        console.print("\n");

        const keep_job = !waitForForegroundCommand(self, job.pid);
        if (!keep_job or !job.stopped) {
            job.active = false;
        }
    }

    fn cmdBg(self: *Shell, args: []const [*:0]const u8) void {
        pollBackgroundJobs(self, false);
        const job = findSelectedJob(self, args) orelse {
            vga.print("bg: no such job\n");
            return;
        };

        if (!job.stopped) {
            vga.print("bg: job already running\n");
            return;
        }

        signal.kill(@intCast(job.pid), signal.SIGCONT) catch {
            vga.print("bg: failed to continue job\n");
            return;
        };
        job.stopped = false;

        var line_buf: [32]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "[{d}] {d}\n", .{ job.id, job.pid }) catch "[?]\n";
        console.print(line);
    }

    fn cmdNice(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: nice <priority> <command> [args...]\n");
            vga.print("Priority range: -20 (highest) to 19 (lowest)\n");
            return;
        }

        const priority = parseClampedPriority(args[0]) orelse {
            vga.print("nice: Invalid priority\n");
            return;
        };

        const command_name = sliceFromCStr(args[1]);

        if (registry.lookup(command_name)) |command_meta| {
            if (execution.dispatchesInShell(command_meta)) {
                vga.print("nice: Priority adjustment for built-in commands is not supported.\n");
                vga.print("Built-in commands run in the shell context and cannot have their priority changed.\n");
                vga.print("To use priority adjustment, run an external program instead.\n");
                return;
            }
        }

        const pid = shell_external.launchExternalCommand(args[1..], priority, null, null) catch |err| {
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
                error.EnvironmentTooLarge => vga.print("nice: Environment is too large\n"),
                error.RedirectDupFailed => vga.print("nice: Failed to duplicate redirected file descriptor\n"),
                error.TooManyLaunches => vga.print("nice: Too many commands are pending launch\n"),
            }
            return;
        };

        vga.print("Running '");
        printString(args[1]);
        vga.print("' with nice value ");
        printSignedPriority(priority);
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

        const priority = parseClampedPriority(args[0]) orelse {
            vga.print("renice: Invalid priority\n");
            return;
        };

        const pid = parseNumber(args[1]) orelse 0;

        if (pid == 0) {
            vga.print("renice: Invalid PID\n");
            return;
        }

        if (scheduler.setProcessNice(pid, priority)) {
            vga.print("Changed nice value of process ");
            numfmt.printDec(pid);
            vga.print(" to ");
            printSignedPriority(priority);
            vga.print("\n");
        } else if (process.setNice(pid, priority)) {
            vga.print("Changed nice value of process ");
            numfmt.printDec(pid);
            vga.print(" to ");
            printSignedPriority(priority);
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

    fn cmdHttpd(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;

        if (args.len == 0) {
            vga.print("Usage: httpd <start|stop> [port]\n");
            vga.print("Example: httpd start 8080\n");
            return;
        }

        if (streq(args[0], "start")) {
            if (httpd_runtime.running()) {
                vga.print("HTTP server is already running\n");
                return;
            }

            var port: u16 = 80;
            if (args.len > 1) {
                port = parseNumberU16(sliceFromCStr(args[1]));
            }

            const server_pid = httpd_runtime.start(port);

            vga.print("Starting HTTP server on port ");
            numfmt.printDec(port);
            vga.print(" (pid ");
            numfmt.printDec(server_pid);
            vga.print(")\n");
        } else if (streq(args[0], "stop")) {
            _ = httpd_runtime.stop() orelse {
                vga.print("HTTP server is not running\n");
                return;
            };

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

fn registerBackgroundJob(self: *Shell, pid: u32, tokens: []const CommandToken) void {
    var command_buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
    const command_len = buildCommandText(tokens, &command_buffer) catch 0;
    const job = self.job_table.register(pid, command_buffer[0..command_len]) catch {
        console.print("Too many background jobs\n");
        return;
    };

    var line_buf: [32]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "[{d}] {d}\n", .{ job.id, pid }) catch "[?]\n";
    console.print(line);
}

fn waitForForegroundCommand(self: *Shell, pid: u32) bool {
    self.job_table.foreground_pid = pid;
    defer self.job_table.foreground_pid = null;

    const result = posix.waitForProcessEvent(pid) catch |err| {
        shell_external.releaseIfPresent(pid);
        console.print("Failed to wait for command: ");
        console.print(@errorName(err));
        console.print("\n");
        return false;
    };

    switch (result) {
        .exited => |exit_code| {
            shell_external.releaseIfPresent(pid);
            if (exit_code != 0) {
                var line_buf: [64]u8 = undefined;
                const line = std.fmt.bufPrint(&line_buf, "Foreground command {d} exited with {d}\n", .{ pid, exit_code }) catch "Foreground command failed\n";
                console.print(line);
            }
            return exit_code == 0;
        },
        .stopped => {
            markJobStopped(self, pid);
            var line_buf: [64]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buf, "Foreground command {d} stopped\n", .{pid}) catch "Foreground command stopped\n";
            console.print(line);
            return false;
        },
    }
}

fn pollBackgroundJobs(self: *Shell, notify: bool) void {
    for (&self.job_table.jobs) |*job| {
        if (!job.active) continue;
        if (process.getProcessByPid(job.pid)) |proc| {
            job.stopped = proc.state == .Stopped;
        }
        const exit_code = posix.pollProcessExit(job.pid) catch {
            shell_external.releaseIfPresent(job.pid);
            job.active = false;
            continue;
        } orelse continue;

        if (notify) {
            var line_buf: [48]u8 = undefined;
            const prefix = std.fmt.bufPrint(&line_buf, "[{d}] Done ", .{job.id}) catch "[?] Done ";
            console.print(prefix);
            console.print(job.commandSlice());
            if (exit_code != 0) {
                var status_buf: [24]u8 = undefined;
                const status_line = std.fmt.bufPrint(&status_buf, " (exit {d})", .{@as(usize, @intCast(if (exit_code < 0) -exit_code else exit_code))}) catch "";
                console.print(status_line);
            }
            console.print("\n");
        }

        shell_external.releaseIfPresent(job.pid);
        job.active = false;
    }
}

fn markJobStopped(self: *Shell, pid: u32) void {
    const job = self.job_table.findByPid(pid) orelse return;
    job.stopped = true;
    var line_buf: [40]u8 = undefined;
    const prefix = std.fmt.bufPrint(&line_buf, "[{d}] Stopped ", .{job.id}) catch "[?] Stopped ";
    console.print(prefix);
    console.print(job.commandSlice());
    console.print("\n");
}

fn findSelectedJob(self: *Shell, args: []const [*:0]const u8) ?*BackgroundJob {
    const spec = if (args.len == 0) null else sliceFromCStr(args[0]);
    return self.job_table.select(spec);
}

fn foregroundPidSignal(self: *Shell, char: u8) bool {
    const pid = self.job_table.foreground_pid orelse return false;
    const signum: i32 = switch (char) {
        3 => signal.SIGINT,
        26 => signal.SIGTSTP,
        else => return false,
    };

    signal.kill(@intCast(pid), signum) catch {};
    if (char == 3) {
        console.print("^C\n");
    } else if (char == 26) {
        console.print("^Z\n");
    }
    return true;
}

fn makeExecutionRuntime(self: *Shell) execution.Runtime {
    return .{
        .context = self,
        .nextCaptureIdFn = executionNextCaptureId,
        .dispatchBuiltinFn = executionDispatchBuiltin,
        .registerBackgroundJobFn = executionRegisterBackgroundJob,
        .waitForForegroundFn = executionWaitForForegroundCommand,
        .launchExternalFn = executionLaunchExternal,
    };
}

fn shellFromExecutionContext(context: ?*anyopaque) *Shell {
    return @ptrCast(@alignCast(context orelse unreachable));
}

fn executionNextCaptureId(context: ?*anyopaque) u32 {
    const self = shellFromExecutionContext(context);
    const capture_id = self.next_capture_id;
    self.next_capture_id += 1;
    return capture_id;
}

fn executionDispatchBuiltin(context: ?*anyopaque, command_id: registry.CommandId, args: []const [*:0]const u8) void {
    const self = shellFromExecutionContext(context);
    self.dispatchCommand(command_id, args);
}

fn executionRegisterBackgroundJob(context: ?*anyopaque, pid: u32, tokens: []const CommandToken) void {
    const self = shellFromExecutionContext(context);
    registerBackgroundJob(self, pid, tokens);
}

fn executionWaitForForegroundCommand(context: ?*anyopaque, pid: u32) bool {
    const self = shellFromExecutionContext(context);
    return waitForForegroundCommand(self, pid);
}

fn executionLaunchExternal(_: ?*anyopaque, command_args: []const [*:0]const u8, nice_value: ?i8, stdin_fd: ?i32, stdout_fd: ?i32) execution.ExternalLaunchError!u32 {
    return shell_external.launchExternalCommand(command_args, nice_value, stdin_fd, stdout_fd);
}

fn buildCommandText(tokens: []const CommandToken, buffer: *[MAX_COMMAND_LENGTH]u8) error{NoSpaceLeft}!usize {
    @memset(buffer, 0);
    var len: usize = 0;
    for (tokens, 0..) |token, idx| {
        if (idx != 0) {
            if (len + 1 >= buffer.len) return error.NoSpaceLeft;
            buffer[len] = ' ';
            len += 1;
        }
        if (len + token.len >= buffer.len) return error.NoSpaceLeft;
        const token_text = sliceFromCStr(token.text);
        @memcpy(buffer[len .. len + token_text.len], token_text);
        len += token_text.len;
    }
    return len;
}

fn streq(a: [*:0]const u8, b: [*:0]const u8) bool {
    var i: usize = 0;
    while (a[i] != 0 and b[i] != 0) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return a[i] == b[i];
}

fn parseClampedPriority(str: [*:0]const u8) ?i8 {
    const slice = sliceFromCStr(str);
    if (slice.len == 0) return null;

    var start: usize = 0;
    var sign: i32 = 1;
    if (slice[0] == '-') {
        sign = -1;
        start = 1;
    } else if (slice[0] == '+') {
        start = 1;
    }
    if (start == slice.len) return null;

    var value: i32 = 0;
    for (slice[start..]) |char| {
        if (char < '0' or char > '9') return null;
        value = value * 10 + @as(i32, char - '0');
    }

    const signed_value = sign * value;
    const clamped = @min(@max(signed_value, -20), 19);
    return @intCast(clamped);
}

fn printSignedPriority(value: i8) void {
    if (value < 0) {
        vga.put_char('-');
        numfmt.printDec(@as(usize, @intCast(-value)));
        return;
    }

    numfmt.printDec(@as(usize, @intCast(value)));
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
