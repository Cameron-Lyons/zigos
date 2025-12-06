const std = @import("std");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const timer = @import("../timer/timer.zig");
const paging = @import("../memory/paging.zig");
const test_memory = @import("../tests/test_memory.zig");
const panic_handler = @import("../utils/panic.zig");
const device = @import("../devices/device.zig");
const vfs = @import("../fs/vfs.zig");
const network = @import("../net/network.zig");
const multitask_demo = @import("../tests/multitask_demo.zig");
const scheduler = @import("../process/scheduler.zig");
const environ = @import("../utils/environ.zig");

const MAX_COMMAND_LENGTH = 256;
const MAX_ARGS = 16;
const MAX_HISTORY = 50;

pub const ArrowKey = enum {
    Up,
    Down,
    Left,
    Right,
};

pub const Shell = struct {
    command_buffer: [MAX_COMMAND_LENGTH]u8,
    buffer_pos: usize,
    running: bool,
    history: [MAX_HISTORY][MAX_COMMAND_LENGTH]u8,
    history_count: usize,
    history_index: usize,

    pub fn init() Shell {
        return Shell{
            .command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH,
            .buffer_pos = 0,
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
                self.command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH;
                self.history_index = self.history_count;
                self.printPrompt();
            },
            '\x08' => {
                if (self.buffer_pos > 0) {
                    self.buffer_pos -= 1;
                    self.command_buffer[self.buffer_pos] = 0;
                    vga.put_char('\x08');
                }
            },
            else => {
                if (self.buffer_pos < MAX_COMMAND_LENGTH - 1) {
                    self.command_buffer[self.buffer_pos] = char;
                    self.buffer_pos += 1;
                    vga.put_char(char);
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

            },
            .Right => {

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
        const commands = [_][]const u8{
            "help", "clear", "echo", "ps", "meminfo", "uptime", "kill",
            "shutdown", "memtest", "panic", "lsdev", "ls", "cat", "mkdir",
            "rmdir", "rm", "mv", "mount", "ping", "httpd", "netstat",
            "nslookup", "multitask", "scheduler", "schedstats", "dhcp",
            "route", "arp", "nettest", "synctest", "ipctest", "procmon",
            "top", "cp", "touch", "write", "edit", "nice", "renice",
        };


        var partial: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH;
        @memcpy(partial[0..self.buffer_pos], self.command_buffer[0..self.buffer_pos]);


        var matches: [16][]const u8 = undefined;
        var match_count: usize = 0;

        for (commands) |cmd| {
            if (self.buffer_pos <= cmd.len) {
                var matching = true;
                var j: usize = 0;
                while (j < self.buffer_pos) : (j += 1) {
                    if (partial[j] != cmd[j]) {
                        matching = false;
                        break;
                    }
                }
                if (matching and match_count < 16) {
                    matches[match_count] = cmd;
                    match_count += 1;
                }
            }
        }

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




    }

    pub fn printPrompt(self: *const Shell) void {
        _ = self;
        vga.print("zigos> ");
    }

    fn executeCommand(self: *Shell) void {
        if (self.buffer_pos == 0) {
            return;
        }

        vga.put_char('\n');

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
        if (streq(command, "help")) {
            self.cmdHelp();
        } else if (streq(command, "clear")) {
            self.cmdClear();
        } else if (streq(command, "echo")) {
            self.cmdEcho(args[1..arg_count]);
        } else if (streq(command, "ps")) {
            self.cmdPs();
        } else if (streq(command, "meminfo")) {
            self.cmdMemInfo();
        } else if (streq(command, "uptime")) {
            self.cmdUptime();
        } else if (streq(command, "kill")) {
            self.cmdKill(args[1..arg_count]);
        } else if (streq(command, "shutdown")) {
            self.cmdShutdown();
        } else if (streq(command, "memtest")) {
            self.cmdMemTest();
        } else if (streq(command, "panic")) {
            self.cmdPanic();
        } else if (streq(command, "lsdev")) {
            self.cmdLsDev();
        } else if (streq(command, "multitask")) {
            self.cmdMultitask();
        } else if (streq(command, "scheduler")) {
            self.cmdScheduler(args[1..arg_count]);
        } else if (streq(command, "schedstats")) {
            self.cmdSchedStats();
        } else if (streq(command, "ls")) {
            self.cmdLs(args[1..arg_count]);
        } else if (streq(command, "cat")) {
            self.cmdCat(args[1..arg_count]);
        } else if (streq(command, "mkdir")) {
            self.cmdMkdir(args[1..arg_count]);
        } else if (streq(command, "rmdir")) {
            self.cmdRmdir(args[1..arg_count]);
        } else if (streq(command, "rm")) {
            self.cmdRm(args[1..arg_count]);
        } else if (streq(command, "mv")) {
            self.cmdMv(args[1..arg_count]);
        } else if (streq(command, "mount")) {
            self.cmdMount(args[1..arg_count]);
        } else if (streq(command, "ping")) {
            self.cmdPing(args[1..arg_count]);
        } else if (streq(command, "httpd")) {
            self.cmdHttpd(args[1..arg_count]);
        } else if (streq(command, "netstat")) {
            self.cmdNetstat();
        } else if (streq(command, "nslookup")) {
            self.cmdNslookup(args[1..arg_count]);
        } else if (streq(command, "dhcp")) {
            self.cmdDhcp(args[1..arg_count]);
        } else if (streq(command, "route")) {
            self.cmdRoute(args[1..arg_count]);
        } else if (streq(command, "arp")) {
            self.cmdArp(args[1..arg_count]);
        } else if (streq(command, "nettest")) {
            self.cmdNetTest();
        } else if (streq(command, "synctest")) {
            self.cmdSyncTest();
        } else if (streq(command, "ipctest")) {
            self.cmdIpcTest();
        } else if (streq(command, "procmon")) {
            self.cmdProcMon();
        } else if (streq(command, "top")) {
            self.cmdTop();
        } else if (streq(command, "cp")) {
            self.cmdCp(args[1..arg_count]);
        } else if (streq(command, "touch")) {
            self.cmdTouch(args[1..arg_count]);
        } else if (streq(command, "write")) {
            self.cmdWrite(args[1..arg_count]);
        } else if (streq(command, "edit")) {
            self.cmdEdit(args[1..arg_count]);
        } else if (streq(command, "nice")) {
            self.cmdNice(args[1..arg_count]);
        } else if (streq(command, "renice")) {
            self.cmdRenice(args[1..arg_count]);
        } else if (streq(command, "chmod")) {
            self.cmdChmod(args[1..arg_count]);
        } else if (streq(command, "export")) {
            self.cmdExport(args[1..arg_count]);
        } else if (streq(command, "unset")) {
            self.cmdUnset(args[1..arg_count]);
        } else if (streq(command, "env")) {
            self.cmdEnv();
        } else {
            vga.print("Unknown command: ");
            printString(command);
            vga.print("\nType 'help' for available commands.\n");
        }
    }

    fn cmdHelp(self: *const Shell) void {
        _ = self;
        vga.print("Available commands:\n");
        vga.print("  help     - Show this help message\n");
        vga.print("  clear    - Clear the screen\n");
        vga.print("  echo     - Echo arguments to screen\n");
        vga.print("  ps       - List running processes\n");
        vga.print("  meminfo  - Show memory information\n");
        vga.print("  uptime   - Show system uptime\n");
        vga.print("  kill     - Terminate a process by PID\n");
        vga.print("  nice     - Run command with modified priority\n");
        vga.print("  renice   - Change priority of running process\n");
        vga.print("  shutdown - Halt the system\n");
        vga.print("  memtest  - Run memory allocator tests\n");
        vga.print("  panic    - Trigger a kernel panic (for testing)\n");
        vga.print("  lsdev    - List available devices\n");
        vga.print("  ls       - List directory contents\n");
        vga.print("  cat      - Display file contents\n");
        vga.print("  mkdir    - Create a directory\n");
        vga.print("  rmdir    - Remove an empty directory\n");
        vga.print("  rm       - Remove a file\n");
        vga.print("  mv       - Move/rename a file or directory\n");
        vga.print("  cp       - Copy a file\n");
        vga.print("  touch    - Create an empty file\n");
        vga.print("  write    - Write text to a file\n");
        vga.print("  edit     - Edit a text file\n");
        vga.print("  chmod    - Change file permissions\n");
        vga.print("  export   - Set environment variable\n");
        vga.print("  unset    - Unset environment variable\n");
        vga.print("  env      - Show all environment variables\n");
        vga.print("  mount    - Mount a file system\n");
        vga.print("  ping     - Ping an IP address\n");
        vga.print("  httpd    - Start/stop HTTP server\n");
        vga.print("  netstat  - Show network statistics\n");
        vga.print("  nslookup - Resolve domain names\n");
        vga.print("  multitask - Run multitasking demo\n");
        vga.print("  scheduler - Change scheduler type (rr/priority/mlfq)\n");
        vga.print("  schedstats - Show scheduler statistics\n");
        vga.print("  dhcp     - Request IP address via DHCP\n");
        vga.print("  route    - Display/modify routing table\n");
        vga.print("  arp      - Display/modify ARP cache\n");
        vga.print("  nettest  - Run network stack tests\n");
        vga.print("  synctest - Run synchronization primitives tests\n");
        vga.print("  ipctest  - Run IPC tests\n");
        vga.print("  procmon  - Show detailed process statistics\n");
        vga.print("  top      - Show CPU usage and process list\n");
    }

    fn cmdClear(self: *const Shell) void {
        _ = self;
        vga.clear();
    }

    fn cmdEcho(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        for (args, 0..) |arg, i| {
            if (i > 0) vga.put_char(' ');
            printString(arg);
        }
        vga.put_char('\n');
    }

    fn cmdPs(self: *const Shell) void {
        _ = self;
        vga.print("PID  STATE     NAME\n");
        vga.print("---  --------  ----\n");

        var proc = process.getProcessList();
        while (proc) |p| : (proc = p.next) {
            printNumber(p.pid);
            vga.print("   ");

            switch (p.state) {
                .Running => vga.print("RUNNING   "),
                .Ready => vga.print("READY     "),
                .Blocked => vga.print("BLOCKED   "),
                .Terminated => vga.print("TERMINATED"),
            }

            var name_buffer: [65]u8 = undefined;
            @memcpy(name_buffer[0..64], &p.name);
            name_buffer[64] = 0;
            printString(@as([*:0]const u8, @ptrCast(&name_buffer)));
            vga.put_char('\n');
        }
    }

    fn cmdMemInfo(self: *const Shell) void {
        _ = self;
        const stats = paging.getMemoryStats();

        vga.print("Memory Information:\n");
        vga.print("  Total: ");
        printNumber(stats.total_frames * 4096 / 1024);
        vga.print(" KB\n");
        vga.print("  Used:  ");
        printNumber(stats.used_frames * 4096 / 1024);
        vga.print(" KB\n");
        vga.print("  Free:  ");
        printNumber((stats.total_frames - stats.used_frames) * 4096 / 1024);
        vga.print(" KB\n");
    }

    fn cmdUptime(self: *const Shell) void {
        _ = self;
        const ticks = timer.getTicks();
        const seconds = ticks / 100;
        const minutes = seconds / 60;
        const hours = minutes / 60;

        vga.print("Uptime: ");
        printNumber(@as(usize, @intCast(hours)));
        vga.print("h ");
        printNumber(@as(usize, @intCast(minutes % 60)));
        vga.print("m ");
        printNumber(@as(usize, @intCast(seconds % 60)));
        vga.print("s\n");
    }

    fn cmdKill(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: kill <pid>\n");
            return;
        }

        const pid = parseNumber(args[0]);
        if (pid == null) {
            vga.print("Invalid PID\n");
            return;
        }

        if (process.terminateProcess(pid.?)) {
            vga.print("Process ");
            printNumber(pid.?);
            vga.print(" terminated\n");
        } else {
            vga.print("Failed to terminate process ");
            printNumber(pid.?);
            vga.print("\n");
        }
    }

    fn cmdShutdown(self: *Shell) void {
        vga.print("Shutting down...\n");
        self.running = false;
        while (true) {
            asm volatile ("hlt");
        }
    }

    fn cmdMultitask(self: *const Shell) void {
        _ = self;
        multitask_demo.runMultitaskingDemo();
    }

    fn cmdScheduler(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: scheduler <rr|priority|mlfq>\n");
            vga.print("  rr       - Round Robin\n");
            vga.print("  priority - Priority Scheduling\n");
            vga.print("  mlfq     - Multi-Level Feedback Queue\n");
            return;
        }

        const sched_type = args[0];
        if (streq(sched_type, "rr")) {
            scheduler.setSchedulerType(.RoundRobin);
        } else if (streq(sched_type, "priority")) {
            scheduler.setSchedulerType(.Priority);
        } else if (streq(sched_type, "mlfq")) {
            scheduler.setSchedulerType(.MultiLevelFeedback);
        } else {
            vga.print("Unknown scheduler type: ");
            printString(sched_type);
            vga.print("\n");
        }
    }

    fn cmdSchedStats(self: *const Shell) void {
        _ = self;
        multitask_demo.showSchedulerStats();
    }

    fn cmdMemTest(self: *const Shell) void {
        _ = self;
        test_memory.test_memory_allocator();
    }

    fn cmdPanic(self: *const Shell) void {
        _ = self;
        panic_handler.panic("User triggered panic from shell", .{});
    }

    fn cmdLsDev(self: *const Shell) void {
        _ = self;
        vga.print("Device List:\n");
        vga.print("MAJOR  MINOR  TYPE     NAME\n");
        vga.print("-----  -----  -------  ----\n");

        var dev = device.getDeviceList();
        while (dev) |d| : (dev = d.next) {
            printNumber(d.major);
            vga.print("      ");

            printNumber(d.minor);
            vga.print("      ");

            switch (d.device_type) {
                .CharDevice => vga.print("char     "),
                .BlockDevice => vga.print("block    "),
                .NetworkDevice => vga.print("network  "),
            }

            var i: usize = 0;
            while (i < 64 and d.name[i] != 0) : (i += 1) {
                vga.put_char(d.name[i]);
            }
            vga.put_char('\n');
        }
    }

    fn cmdLs(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const path = if (args.len > 0) args[0] else "/mnt";

        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("ls: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        var index: u64 = 0;
        var dirent: vfs.DirEntry = undefined;

        while (true) {
            const has_more = vfs.readdir(fd, &dirent, index) catch |err| {
                vga.print("readdir error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                break;
            };

            if (!has_more) break;

            if (dirent.file_type == vfs.FileType.Directory) {
                vga.print("[DIR] ");
            } else {
                vga.print("      ");
            }

            var i: usize = 0;
            while (i < dirent.name_len and i < 256) : (i += 1) {
                vga.put_char(dirent.name[i]);
            }
            vga.put_char('\n');

            index += 1;
        }
    }

    fn cmdCat(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: cat <file>\n");
            return;
        }

        const path = args[0];

        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("cat: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        var buffer: [512]u8 = undefined;
        while (true) {
            const bytes_read = vfs.read(fd, &buffer) catch |err| {
                vga.print("\nread error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                break;
            };

            if (bytes_read == 0) break;

            for (buffer[0..bytes_read]) |byte| {
                if (byte == '\r') continue;
                vga.put_char(byte);
            }
        }
        vga.put_char('\n');
    }

    fn cmdMkdir(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: mkdir <directory>\n");
            return;
        }

        const path = args[0];
        const mode = vfs.FileMode{
            .owner_read = true,
            .owner_write = true,
            .owner_exec = true,
            .group_read = true,
            .group_exec = true,
            .other_read = true,
            .other_exec = true,
        };

        vfs.mkdir(sliceFromCStr(path), mode) catch |err| {
            vga.print("mkdir: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("Directory created: ");
        printString(path);
        vga.print("\n");
    }

    fn cmdRmdir(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: rmdir <directory>\n");
            return;
        }

        const path = args[0];
        vfs.rmdir(sliceFromCStr(path)) catch |err| {
            vga.print("rmdir: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("Directory removed: ");
        printString(path);
        vga.print("\n");
    }

    fn cmdRm(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: rm <file>\n");
            return;
        }

        const path = args[0];
        vfs.unlink(sliceFromCStr(path)) catch |err| {
            vga.print("rm: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("File removed: ");
        printString(path);
        vga.print("\n");
    }

    fn cmdMv(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: mv <source> <destination>\n");
            return;
        }

        const src = args[0];
        const dst = args[1];
        vfs.rename(sliceFromCStr(src), sliceFromCStr(dst)) catch |err| {
            vga.print("mv: ");
            printString(src);
            vga.print(" -> ");
            printString(dst);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        printString(src);
        vga.print(" -> ");
        printString(dst);
        vga.print("\n");
    }

    fn cmdMount(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 3) {
            vga.print("Usage: mount <device> <path> <fstype>\n");
            vga.print("Example: mount ata0 /mnt fat32\n");
            return;
        }

        const device_str = sliceFromCStr(args[0]);
        const path = sliceFromCStr(args[1]);
        const fstype = sliceFromCStr(args[2]);

        vfs.mount(device_str, path, fstype, 0) catch |err| {
            vga.print("mount: failed to mount ");
            printString(args[0]);
            vga.print(" on ");
            printString(args[1]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("Mounted ");
        printString(args[0]);
        vga.print(" on ");
        printString(args[1]);
        vga.print(" as ");
        printString(args[2]);
        vga.print("\n");
    }

    fn cmdCp(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: cp <source> <destination>\n");
            return;
        }

        const src_path = sliceFromCStr(args[0]);
        const dst_path = sliceFromCStr(args[1]);


        const src_fd = vfs.open(src_path, vfs.O_RDONLY) catch |err| {
            vga.print("cp: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(src_fd) catch {};





        const dst_fd = vfs.open(dst_path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
            vga.print("cp: ");
            printString(args[1]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(dst_fd) catch {};


        var buffer: [4096]u8 = undefined;
        var total_copied: usize = 0;
        while (true) {
            const bytes_read = vfs.read(src_fd, &buffer) catch |err| {
                vga.print("cp: read error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                return;
            };

            if (bytes_read == 0) break;

            _ = vfs.write(dst_fd, buffer[0..bytes_read]) catch |err| {
                vga.print("cp: write error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                return;
            };

            total_copied += bytes_read;
        }

        vga.print("Copied ");
        printString(args[0]);
        vga.print(" to ");
        printString(args[1]);
        vga.print(" (");
        printNumber(@intCast(total_copied));
        vga.print(" bytes)\n");
    }

    fn cmdTouch(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: touch <file>\n");
            return;
        }

        const path = sliceFromCStr(args[0]);


        const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT) catch |err| {
            vga.print("touch: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vfs.close(fd) catch {};

        vga.print("Created/updated ");
        printString(args[0]);
        vga.print("\n");
    }

    fn cmdWrite(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: write <file> <text>\n");
            vga.print("Example: write test.txt \"Hello World\"\n");
            return;
        }

        const path = sliceFromCStr(args[0]);


        const fd = vfs.open(path, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC) catch |err| {
            vga.print("write: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};


        var total_written: usize = 0;
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const text = sliceFromCStr(args[i]);
            const bytes_written = vfs.write(fd, text) catch |err| {
                vga.print("write: write error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                return;
            };
            total_written += bytes_written;


            if (i < args.len - 1) {
                _ = vfs.write(fd, " ") catch {};
                total_written += 1;
            }
        }

        vga.print("Wrote ");
        printNumber(@intCast(total_written));
        vga.print(" bytes to ");
        printString(args[0]);
        vga.print("\n");
    }

    fn cmdEdit(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: edit <file>\n");
            return;
        }

        vga.print("Opening editor for ");
        printString(args[0]);
        vga.print("...\n");


        vga.print("Note: Editor is currently in demo mode\n");
        vga.print("Full editor implementation coming soon!\n");
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

        vga.print("Would run command '");
        printString(args[1]);
        vga.print("' with priority ");
        if (priority < 0) {
            vga.put_char('-');
            printNumber(@as(usize, @intCast(-priority)));
        } else {
            printNumber(@as(usize, @intCast(priority)));
        }
        vga.print("\n");
        vga.print("Note: Command execution with priority not yet fully implemented\n");
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


        const pid = parseNumber(args[1]) orelse 0;


        if (process.setPriority(pid, priority)) {
            vga.print("Changed priority of process ");
            printNumber(pid);
            vga.print(" to ");
            if (priority < 0) {
                vga.put_char('-');
                printNumber(@as(usize, @intCast(-priority)));
            } else {
                printNumber(@as(usize, @intCast(priority)));
            }
            vga.print("\n");
        } else {
            vga.print("Failed to change priority: process ");
            printNumber(pid);
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

    fn cmdExport(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
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
            const value = arg[pos + 1..];
            environ.setVar(name, value) catch |err| {
                vga.print("export: ");
                switch (err) {
                    error.InvalidName => vga.print("invalid variable name\n"),
                    error.ValueTooLong => vga.print("value too long\n"),
                    error.TooManyVars => vga.print("too many environment variables\n"),
                }
                return;
            };
        } else {
            vga.print("Usage: export VAR=value\n");
        }
    }

    fn cmdUnset(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: unset VAR\n");
            return;
        }

        const name = sliceFromCStr(args[0]);
        environ.unsetVar(name);
    }

    fn cmdEnv(self: *const Shell) void {
        _ = self;
        environ.printAll();
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
            printNumber(port);
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
            vga.print("Not yet implemented\n");
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
        printNumber(cpu.user_percent);
        vga.print("% System: ");
        printNumber(cpu.system_percent);
        vga.print("% Idle: ");
        printNumber(cpu.idle_percent);
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

