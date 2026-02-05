// zlint-disable suppressed-errors
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
const editor = @import("editor.zig");
const memory = @import("../memory/memory.zig");
const keyboard = @import("../drivers/keyboard.zig");

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
        const commands = [_][]const u8{
            "help", "clear", "echo", "ps", "meminfo", "uptime", "kill",
            "shutdown", "memtest", "panic", "lsdev", "ls", "cat", "mkdir",
            "rmdir", "rm", "mv", "mount", "ping", "httpd", "netstat",
            "nslookup", "multitask", "scheduler", "schedstats", "dhcp",
            "route", "arp", "nettest", "synctest", "ipctest", "procmon",
            "top", "cp", "touch", "write", "edit", "nice", "renice",
            "head", "tail", "wc", "grep", "find", "stat", "uname",
            "whoami", "pwd", "sort", "uniq", "ifconfig", "df",
            "smptest", "fileiotest", "ext2writetest", "tcptest",
            "true", "false", "test", "hexdump", "which",
        };


        var partial: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH;
        @memcpy(partial[0..self.buffer_pos], self.command_buffer[0..self.buffer_pos]);


        // SAFETY: entries assigned in the following command matching loop; match_count tracks valid entries
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
            @memcpy(dir_path[0..slash_pos + 1], partial_path[0..slash_pos + 1]);
            dir_len = slash_pos + 1;
            @memcpy(file_part[0..partial_len - dir_len], partial_path[dir_len..partial_len]);
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
        } else if (streq(command, "head")) {
            self.cmdHead(args[1..arg_count]);
        } else if (streq(command, "tail")) {
            self.cmdTail(args[1..arg_count]);
        } else if (streq(command, "wc")) {
            self.cmdWc(args[1..arg_count]);
        } else if (streq(command, "grep")) {
            self.cmdGrep(args[1..arg_count]);
        } else if (streq(command, "find")) {
            self.cmdFind(args[1..arg_count]);
        } else if (streq(command, "stat")) {
            self.cmdStat(args[1..arg_count]);
        } else if (streq(command, "uname")) {
            self.cmdUname(args[1..arg_count]);
        } else if (streq(command, "whoami")) {
            self.cmdWhoami();
        } else if (streq(command, "pwd")) {
            self.cmdPwd();
        } else if (streq(command, "cd")) {
            self.cmdCd(args[1..arg_count]);
        } else if (streq(command, "sort")) {
            self.cmdSort(args[1..arg_count]);
        } else if (streq(command, "uniq")) {
            self.cmdUniq(args[1..arg_count]);
        } else if (streq(command, "ifconfig")) {
            self.cmdIfconfig(args[1..arg_count]);
        } else if (streq(command, "df")) {
            self.cmdDf(args[1..arg_count]);
        } else if (streq(command, "smptest")) {
            self.cmdSmpTest();
        } else if (streq(command, "fileiotest")) {
            self.cmdFileioTest();
        } else if (streq(command, "ext2writetest")) {
            self.cmdExt2WriteTest();
        } else if (streq(command, "tcptest")) {
            self.cmdTcpTest();
        } else if (streq(command, "id")) {
            self.cmdId();
        } else if (streq(command, "date")) {
            self.cmdDate();
        } else if (streq(command, "ln")) {
            self.cmdLn(args[1..arg_count]);
        } else if (streq(command, "hostname")) {
            self.cmdHostname(args[1..arg_count]);
        } else if (streq(command, "sleep")) {
            self.cmdSleep(args[1..arg_count]);
        } else if (streq(command, "umask")) {
            self.cmdUmask(args[1..arg_count]);
        } else if (streq(command, "chown")) {
            self.cmdChown(args[1..arg_count]);
        } else if (streq(command, "chgrp")) {
            self.cmdChgrp(args[1..arg_count]);
        } else if (streq(command, "true")) {
            self.cmdTrue();
        } else if (streq(command, "false")) {
            self.cmdFalse();
        } else if (streq(command, "test")) {
            self.cmdTest(args[1..arg_count]);
        } else if (streq(command, "hexdump")) {
            self.cmdHexdump(args[1..arg_count]);
        } else if (streq(command, "which")) {
            self.cmdWhich(args[1..arg_count]);
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
        vga.print("  head     - Display first lines of a file\n");
        vga.print("  tail     - Display last lines of a file\n");
        vga.print("  wc       - Count lines, words, and bytes in a file\n");
        vga.print("  grep     - Search for text in files\n");
        vga.print("  find     - Find files by name\n");
        vga.print("  stat     - Display file statistics\n");
        vga.print("  uname    - Display system information\n");
        vga.print("  whoami   - Display current user\n");
        vga.print("  pwd      - Print working directory\n");
        vga.print("  sort     - Sort lines in a file\n");
        vga.print("  uniq     - Remove duplicate consecutive lines\n");
        vga.print("  ifconfig - Display network interface configuration\n");
        vga.print("  df       - Display disk space usage\n");
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
        vga.print("  smptest  - Run SMP/multicore tests\n");
        vga.print("  fileiotest - Run file I/O syscall tests\n");
        vga.print("  ext2writetest - Run ext2 write operation tests\n");
        vga.print("  tcptest  - Run TCP reliability tests\n");
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
                .Zombie => vga.print("ZOMBIE    "),
                .Stopped => vga.print("STOPPED   "),
                .Waiting => vga.print("WAITING   "),
            }

            // SAFETY: filled by the subsequent memcpy from process name
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
        // SAFETY: Populated by vfs.readdir call below
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

        // SAFETY: filled by the subsequent vfs.read call
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


        // SAFETY: filled by the subsequent vfs.read call in the copy loop
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
        
        const is_builtin = streq(args[1], "help") or
            streq(args[1], "clear") or
            streq(args[1], "echo") or
            streq(args[1], "ps") or
            streq(args[1], "meminfo") or
            streq(args[1], "uptime") or
            streq(args[1], "kill") or
            streq(args[1], "shutdown") or
            streq(args[1], "memtest") or
            streq(args[1], "panic") or
            streq(args[1], "lsdev") or
            streq(args[1], "multitask") or
            streq(args[1], "scheduler") or
            streq(args[1], "schedstats") or
            streq(args[1], "ls") or
            streq(args[1], "cat") or
            streq(args[1], "mkdir") or
            streq(args[1], "rmdir") or
            streq(args[1], "rm") or
            streq(args[1], "mv") or
            streq(args[1], "mount") or
            streq(args[1], "ping") or
            streq(args[1], "httpd") or
            streq(args[1], "netstat") or
            streq(args[1], "nslookup") or
            streq(args[1], "dhcp") or
            streq(args[1], "route") or
            streq(args[1], "arp") or
            streq(args[1], "nettest") or
            streq(args[1], "synctest") or
            streq(args[1], "ipctest") or
            streq(args[1], "procmon") or
            streq(args[1], "top") or
            streq(args[1], "cp") or
            streq(args[1], "touch") or
            streq(args[1], "write") or
            streq(args[1], "edit") or
            streq(args[1], "head") or
            streq(args[1], "tail") or
            streq(args[1], "wc") or
            streq(args[1], "grep") or
            streq(args[1], "find") or
            streq(args[1], "stat") or
            streq(args[1], "uname") or
            streq(args[1], "whoami") or
            streq(args[1], "pwd") or
            streq(args[1], "sort") or
            streq(args[1], "uniq") or
            streq(args[1], "ifconfig") or
            streq(args[1], "df") or
            streq(args[1], "nice") or
            streq(args[1], "renice") or
            streq(args[1], "chmod") or
            streq(args[1], "export") or
            streq(args[1], "unset") or
            streq(args[1], "env");

        if (is_builtin) {
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
            @memcpy(command_path[5..5+command_name.len], command_name);
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
                printNumber(@as(usize, @intCast(-priority)));
            } else {
                printNumber(@as(usize, @intCast(priority)));
            }
            vga.print(" (PID: ");
            printNumber(user_proc.pid);
            vga.print(")\n");
        } else {
            if (process.setNice(user_proc.pid, priority)) {
                vga.print("Running '");
                printString(args[1]);
                vga.print("' with nice value ");
                if (priority < 0) {
                    vga.put_char('-');
                    printNumber(@as(usize, @intCast(-priority)));
                } else {
                    printNumber(@as(usize, @intCast(priority)));
                }
                vga.print(" (PID: ");
                printNumber(user_proc.pid);
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
            printNumber(pid);
            vga.print(" to ");
            if (priority < 0) {
                vga.put_char('-');
                printNumber(@as(usize, @intCast(-priority)));
            } else {
                printNumber(@as(usize, @intCast(priority)));
            }
            vga.print("\n");
        } else if (process.setNice(pid, priority)) {
            vga.print("Changed nice value of process ");
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

    fn cmdHead(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        var lines: u32 = 10;
        var file_arg_idx: usize = 0;

        if (args.len > 0 and sliceFromCStr(args[0]).len > 2 and args[0][0] == '-' and args[0][1] == 'n') {
            const num_str = sliceFromCStr(args[0]);
            if (num_str.len > 2) {
                var num: u32 = 0;
                var i: usize = 2;
                while (i < num_str.len) : (i += 1) {
                    if (num_str[i] >= '0' and num_str[i] <= '9') {
                        num = num * 10 + (num_str[i] - '0');
                    } else {
                        break;
                    }
                }
                if (num > 0) {
                    lines = num;
                }
            }
            file_arg_idx = 1;
        }

        if (args.len <= file_arg_idx) {
            vga.print("Usage: head [-n <lines>] <file>\n");
            return;
        }

        const path = args[file_arg_idx];
        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("head: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: filled by the subsequent vfs.read call
        var buffer: [512]u8 = undefined;
        var line_count: u32 = 0;
        var in_line = false;

        while (line_count < lines) {
            const bytes_read = vfs.read(fd, &buffer) catch |err| {
                vga.print("\nread error: ");
                vga.print(@errorName(err));
                vga.print("\n");
                break;
            };

            if (bytes_read == 0) break;

            for (buffer[0..bytes_read]) |byte| {
                if (byte == '\r') continue;
                
                if (byte == '\n') {
                    vga.put_char('\n');
                    line_count += 1;
                    in_line = false;
                    if (line_count >= lines) break;
                } else {
                    vga.put_char(byte);
                    in_line = true;
                }
            }
        }

        if (in_line) {
            vga.put_char('\n');
        }
    }

    fn cmdTail(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        var lines: u32 = 10;
        var file_arg_idx: usize = 0;

        if (args.len > 0 and sliceFromCStr(args[0]).len > 2 and args[0][0] == '-' and args[0][1] == 'n') {
            const num_str = sliceFromCStr(args[0]);
            if (num_str.len > 2) {
                var num: u32 = 0;
                var i: usize = 2;
                while (i < num_str.len) : (i += 1) {
                    if (num_str[i] >= '0' and num_str[i] <= '9') {
                        num = num * 10 + (num_str[i] - '0');
                    } else {
                        break;
                    }
                }
                if (num > 0) {
                    lines = num;
                }
            }
            file_arg_idx = 1;
        }

        if (args.len <= file_arg_idx) {
            vga.print("Usage: tail [-n <lines>] <file>\n");
            return;
        }

        const path = args[file_arg_idx];
        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("tail: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: filled by the subsequent vfs.read calls
        var file_buffer: [8192]u8 = undefined;
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

        var line_count: u32 = 0;
        var start_pos: usize = total_read;
        
        if (total_read > 0) {
            var i = total_read;
            while (i > 0 and line_count < lines) {
                i -= 1;
                if (file_buffer[i] == '\n') {
                    line_count += 1;
                    if (line_count == lines) {
                        start_pos = i + 1;
                        break;
                    }
                }
            }
        }

        for (file_buffer[start_pos..total_read]) |byte| {
            if (byte == '\r') continue;
            vga.put_char(byte);
        }
    }

    fn cmdWc(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: wc <file>\n");
            return;
        }

        const path = args[0];
        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("wc: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: filled by the subsequent vfs.read call
        var buffer: [512]u8 = undefined;
        var lines: u32 = 0;
        var words: u32 = 0;
        var bytes: u32 = 0;
        var in_word = false;

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
            bytes += @intCast(bytes_read);

            for (buffer[0..bytes_read]) |byte| {
                if (byte == '\r') continue;
                
                if (byte == '\n') {
                    lines += 1;
                    in_word = false;
                } else if (byte == ' ' or byte == '\t') {
                    in_word = false;
                } else {
                    if (!in_word) {
                        words += 1;
                        in_word = true;
                    }
                }
            }
        }

        printNumber(lines);
        vga.print(" ");
        printNumber(words);
        vga.print(" ");
        printNumber(bytes);
        vga.print(" ");
        printString(path);
        vga.print("\n");
    }

    fn cmdGrep(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: grep <pattern> <file>\n");
            return;
        }

        const pattern = sliceFromCStr(args[0]);
        const path = args[1];
        const fd = vfs.open(sliceFromCStr(path), vfs.O_RDONLY) catch |err| {
            vga.print("grep: ");
            printString(path);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: filled by the subsequent vfs.read call
        var buffer: [512]u8 = undefined;
        // SAFETY: characters accumulated during line parsing
        var line_buffer: [256]u8 = undefined;
        var line_pos: usize = 0;
        var line_num: u32 = 1;

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
                    line_buffer[line_pos] = 0;
                    const line_slice = line_buffer[0..line_pos];
                    
                    var found = false;
                    if (line_slice.len >= pattern.len) {
                        var i: usize = 0;
                        while (i <= line_slice.len - pattern.len) : (i += 1) {
                            var match = true;
                            var j: usize = 0;
                            while (j < pattern.len) : (j += 1) {
                                if (line_slice[i + j] != pattern[j]) {
                                    match = false;
                                    break;
                                }
                            }
                            if (match) {
                                found = true;
                                break;
                            }
                        }
                    }

                    if (found) {
                        printNumber(line_num);
                        vga.print(": ");
                        for (line_slice) |c| {
                            vga.put_char(c);
                        }
                        vga.put_char('\n');
                    }

                    line_pos = 0;
                    line_num += 1;
                } else {
                    if (line_pos < line_buffer.len - 1) {
                        line_buffer[line_pos] = byte;
                        line_pos += 1;
                    }
                }
            }
        }

        if (line_pos > 0) {
            line_buffer[line_pos] = 0;
            const line_slice = line_buffer[0..line_pos];
            
            var found = false;
            if (line_slice.len >= pattern.len) {
                var i: usize = 0;
                while (i <= line_slice.len - pattern.len) : (i += 1) {
                    var match = true;
                    var j: usize = 0;
                    while (j < pattern.len) : (j += 1) {
                        if (line_slice[i + j] != pattern[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        found = true;
                        break;
                    }
                }
            }

            if (found) {
                printNumber(line_num);
                vga.print(": ");
                for (line_slice) |c| {
                    vga.put_char(c);
                }
                vga.put_char('\n');
            }
        }
    }

    fn cmdFind(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: find <directory> <name>\n");
            return;
        }

        const dir_path = sliceFromCStr(args[0]);
        const search_name = sliceFromCStr(args[1]);

        const fd = vfs.open(dir_path, vfs.O_RDONLY) catch |err| {
            vga.print("find: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        var index: u64 = 0;
        // SAFETY: Populated by vfs.readdir call below
        var dirent: vfs.DirEntry = undefined;
        var found_count: u32 = 0;

        while (true) {
            const has_more = vfs.readdir(fd, &dirent, index) catch |err| {
                if (err != error.EndOfFile) {
                    vga.print("readdir error: ");
                    vga.print(@errorName(err));
                    vga.print("\n");
                }
                break;
            };

            if (!has_more) break;

            const entry_name = dirent.name[0..dirent.name_len];
            
            var matches = false;
            if (entry_name.len >= search_name.len) {
                var i: usize = 0;
                while (i <= entry_name.len - search_name.len) : (i += 1) {
                    var match = true;
                    var j: usize = 0;
                    while (j < search_name.len) : (j += 1) {
                        if (entry_name[i + j] != search_name[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        matches = true;
                        break;
                    }
                }
            }

            if (matches) {
                // SAFETY: filled by the subsequent path construction logic
                var path_buf: [512]u8 = undefined;
                var path_len: usize = 0;
                
                if (dir_path[dir_path.len - 1] != '/') {
                    @memcpy(path_buf[0..dir_path.len], dir_path);
                    path_len = dir_path.len;
                    path_buf[path_len] = '/';
                    path_len += 1;
                } else {
                    @memcpy(path_buf[0..dir_path.len], dir_path);
                    path_len = dir_path.len;
                }
                
                @memcpy(path_buf[path_len..path_len + entry_name.len], entry_name);
                path_len += entry_name.len;
                
                for (path_buf[0..path_len]) |c| {
                    vga.put_char(c);
                }
                vga.put_char('\n');
                found_count += 1;
            }

            index += 1;
        }

        if (found_count == 0) {
            vga.print("No matches found\n");
        }
    }

    fn cmdStat(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: stat <file>\n");
            return;
        }

        const path = sliceFromCStr(args[0]);
        const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
            vga.print("stat: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };
        defer vfs.close(fd) catch {};

        // SAFETY: Populated by vfs.stat call below
        var stat_info: vfs.FileStat = undefined;
        const file_ops = @import("../fs/file_ops.zig");
        file_ops.fstat(@as(i32, @intCast(fd)), &stat_info) catch |err| {
            vga.print("stat: ");
            printString(args[0]);
            vga.print(": ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        vga.print("File: ");
        printString(args[0]);
        vga.print("\n");
        vga.print("Size: ");
        printNumber(@as(usize, @intCast(stat_info.size)));
        vga.print(" bytes\n");
        
        vga.print("Type: ");
        switch (stat_info.file_type) {
            .Regular => vga.print("Regular file\n"),
            .Directory => vga.print("Directory\n"),
            .SymLink => vga.print("Symbolic link\n"),
            .BlockDevice => vga.print("Block device\n"),
            .CharDevice => vga.print("Character device\n"),
            .Pipe => vga.print("Pipe\n"),
            .Socket => vga.print("Socket\n"),
        }

        vga.print("Mode: ");
        if (stat_info.mode.owner_read) vga.put_char('r') else vga.put_char('-');
        if (stat_info.mode.owner_write) vga.put_char('w') else vga.put_char('-');
        if (stat_info.mode.owner_exec) vga.put_char('x') else vga.put_char('-');
        if (stat_info.mode.group_read) vga.put_char('r') else vga.put_char('-');
        if (stat_info.mode.group_write) vga.put_char('w') else vga.put_char('-');
        if (stat_info.mode.group_exec) vga.put_char('x') else vga.put_char('-');
        if (stat_info.mode.other_read) vga.put_char('r') else vga.put_char('-');
        if (stat_info.mode.other_write) vga.put_char('w') else vga.put_char('-');
        if (stat_info.mode.other_exec) vga.put_char('x') else vga.put_char('-');
        vga.print("\n");
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

    fn cmdUname(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const syscall_mod = @import("../process/syscall.zig");
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

    fn cmdWhoami(self: *const Shell) void {
        _ = self;
        vga.print("root\n");
    }

    fn cmdPwd(self: *const Shell) void {
        _ = self;
        const syscall_mod = @import("../process/syscall.zig");
        const cwd = syscall_mod.getCwd();
        vga.print(cwd);
        vga.print("\n");
    }

    fn cmdCd(self: *Shell, args: []const [*:0]const u8) void {
        _ = self;
        const syscall_mod = @import("../process/syscall.zig");

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

        if (arg_slice[0] == '/') {
            @memcpy(path_buf[0..arg_len], arg_slice);
            if (!syscall_mod.setCwd(path_buf[0..arg_len])) {
                vga.print("cd: no such directory: ");
                printString(arg);
                vga.print("\n");
            }
        } else {
            const cwd = syscall_mod.getCwd();
            var path_len: usize = 0;
            @memcpy(path_buf[0..cwd.len], cwd);
            path_len = cwd.len;
            if (path_len > 1) {
                path_buf[path_len] = '/';
                path_len += 1;
            }
            @memcpy(path_buf[path_len .. path_len + arg_len], arg_slice);
            path_len += arg_len;
            if (!syscall_mod.setCwd(path_buf[0..path_len])) {
                vga.print("cd: no such directory: ");
                printString(arg);
                vga.print("\n");
            }
        }
    }

    fn cmdId(self: *const Shell) void {
        _ = self;
        const proc = @import("../process/process.zig");
        if (proc.current_process) |p| {
            vga.print("uid=");
            printNumber(@as(usize, p.creds.uid));
            vga.print("(");
            if (p.creds.uid == 0) vga.print("root") else vga.print("user");
            vga.print(") gid=");
            printNumber(@as(usize, p.creds.gid));
            vga.print("(");
            if (p.creds.gid == 0) vga.print("root") else vga.print("users");
            vga.print(") euid=");
            printNumber(@as(usize, p.creds.euid));
            vga.print(" egid=");
            printNumber(@as(usize, p.creds.egid));
            vga.print("\n");
        }
    }

    fn cmdDate(self: *const Shell) void {
        _ = self;
        const t = @import("../timer/timer.zig");
        const ticks = t.getTicks();
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

    fn cmdLn(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
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

    fn cmdHostname(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        const syscall_mod = @import("../process/syscall.zig");
        if (args.len == 0) {
            vga.print(syscall_mod.getHostname());
            vga.print("\n");
            return;
        }

        const name = sliceFromCStr(args[0]);
        syscall_mod.setHostname(name);
    }

    fn cmdSleep(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: sleep <seconds>\n");
            return;
        }

        const secs = parseNumber(args[0]) orelse {
            vga.print("sleep: invalid number\n");
            return;
        };

        const t = @import("../timer/timer.zig");
        const start = t.getTicks();
        const target = start + @as(u64, secs) * 100;
        while (t.getTicks() < target) {
            process.yield();
        }
    }

    fn cmdUmask(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            if (process.current_process) |proc| {
                const m = proc.umask;
                vga.print("0");
                vga.put_char('0' + @as(u8, @intCast((m >> 6) & 7)));
                vga.put_char('0' + @as(u8, @intCast((m >> 3) & 7)));
                vga.put_char('0' + @as(u8, @intCast(m & 7)));
                vga.print("\n");
            }
            return;
        }

        const s = sliceFromCStr(args[0]);
        var val: u16 = 0;
        for (s) |c| {
            if (c < '0' or c > '7') {
                vga.print("umask: invalid octal number\n");
                return;
            }
            val = val * 8 + @as(u16, c - '0');
        }
        if (process.current_process) |proc| {
            proc.umask = val & 0o777;
        }
    }

    fn cmdChown(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: chown <uid> <file>\n");
            return;
        }

        const uid = parseNumber(args[0]) orelse {
            vga.print("chown: invalid uid\n");
            return;
        };

        const path = sliceFromCStr(args[1]);
        const vnode = vfs.lookupPath(path) catch {
            vga.print("chown: file not found\n");
            return;
        };

        vnode.ops.chown(vnode, @intCast(uid), vnode.gid) catch {
            vga.print("chown: operation failed\n");
            return;
        };
    }

    fn cmdChgrp(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len < 2) {
            vga.print("Usage: chgrp <gid> <file>\n");
            return;
        }

        const gid = parseNumber(args[0]) orelse {
            vga.print("chgrp: invalid gid\n");
            return;
        };

        const path = sliceFromCStr(args[1]);
        const vnode = vfs.lookupPath(path) catch {
            vga.print("chgrp: file not found\n");
            return;
        };

        vnode.ops.chown(vnode, vnode.uid, @intCast(gid)) catch {
            vga.print("chgrp: operation failed\n");
            return;
        };
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

    fn cmdHexdump(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: hexdump <file>\n");
            return;
        }

        const path = sliceFromCStr(args[0]);
        const vnode = vfs.lookupPath(path) catch {
            vga.print("hexdump: file not found\n");
            return;
        };

        var buf: [256]u8 = undefined;
        var offset: u64 = 0;

        while (true) {
            const bytes_read = vnode.ops.read(vnode, &buf, offset) catch {
                vga.print("hexdump: read error\n");
                return;
            };
            if (bytes_read == 0) break;

            var i: usize = 0;
            while (i < bytes_read) {
                if (i % 16 == 0) {
                    printHex32(@intCast(offset + i));
                    vga.print("  ");
                }

                printHex8(buf[i]);
                vga.print(" ");

                if (i % 16 == 15 or i == bytes_read - 1) {
                    var pad = (15 - (i % 16)) * 3;
                    while (pad > 0) : (pad -= 1) {
                        vga.put_char(' ');
                    }
                    vga.print(" |");
                    const line_start = i - (i % 16);
                    var j: usize = line_start;
                    while (j <= i) : (j += 1) {
                        const c = buf[j];
                        if (c >= 0x20 and c < 0x7f) {
                            vga.put_char(c);
                        } else {
                            vga.put_char('.');
                        }
                    }
                    vga.print("|\n");
                }
                i += 1;
            }
            offset += bytes_read;
            if (bytes_read < buf.len) break;
        }
    }

    fn printHex32(val: u32) void {
        const hex = "0123456789abcdef";
        var buf: [8]u8 = undefined;
        var v = val;
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            buf[i] = hex[v & 0xf];
            v >>= 4;
        }
        vga.print(&buf);
    }

    fn printHex8(val: u8) void {
        const hex = "0123456789abcdef";
        var buf: [2]u8 = undefined;
        buf[0] = hex[(val >> 4) & 0xf];
        buf[1] = hex[val & 0xf];
        vga.print(&buf);
    }

    fn cmdWhich(self: *const Shell, args: []const [*:0]const u8) void {
        _ = self;
        if (args.len == 0) {
            vga.print("Usage: which <command>\n");
            return;
        }

        const cmd = sliceFromCStr(args[0]);
        const builtins = [_][]const u8{
            "help", "clear", "echo", "ps", "meminfo", "uptime", "kill",
            "shutdown", "memtest", "panic", "lsdev", "ls", "cat", "mkdir",
            "rmdir", "rm", "mv", "mount", "ping", "httpd", "netstat",
            "nslookup", "multitask", "scheduler", "schedstats", "dhcp",
            "route", "arp", "nettest", "synctest", "ipctest", "procmon",
            "top", "cp", "touch", "write", "edit", "nice", "renice",
            "head", "tail", "wc", "grep", "find", "stat", "uname",
            "whoami", "pwd", "sort", "uniq", "ifconfig", "df", "cd",
            "smptest", "fileiotest", "ext2writetest", "tcptest", "id",
            "date", "ln", "hostname", "sleep", "umask", "chown", "chgrp",
            "true", "false", "test", "hexdump", "which",
        };

        for (builtins) |builtin| {
            if (strEqlSlice(cmd, builtin)) {
                vga.print(builtin);
                vga.print(": shell built-in command\n");
                return;
            }
        }

        vga.print(cmd);
        vga.print(" not found\n");
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

        // SAFETY: entries assigned in the following line-scanning loop; line_count tracks valid entries
        var line_starts: [256]usize = undefined;
        // SAFETY: entries assigned in the following line-scanning loop; line_count tracks valid entries
        var line_lens: [256]usize = undefined;
        var current_line_start: usize = 0;
        var i: usize = 0;

        while (i < total_read and line_count < 256) {
            if (file_buffer[i] == '\n' or file_buffer[i] == '\r') {
                if (i > current_line_start) {
                    line_starts[line_count] = current_line_start;
                    line_lens[line_count] = i - current_line_start;
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
            line_starts[line_count] = current_line_start;
            line_lens[line_count] = total_read - current_line_start;
            line_count += 1;
        }

        var swapped = true;
        while (swapped) {
            swapped = false;
            var j: usize = 0;
            while (j < line_count - 1) : (j += 1) {
                const line1 = file_buffer[line_starts[j]..line_starts[j] + line_lens[j]];
                const line2 = file_buffer[line_starts[j + 1]..line_starts[j + 1] + line_lens[j + 1]];
                
                var cmp: i32 = 0;
                const min_len = @min(line1.len, line2.len);
                var k: usize = 0;
                while (k < min_len) : (k += 1) {
                    if (line1[k] < line2[k]) {
                        cmp = -1;
                        break;
                    } else if (line1[k] > line2[k]) {
                        cmp = 1;
                        break;
                    }
                }
                if (cmp == 0) {
                    if (line1.len < line2.len) {
                        cmp = -1;
                    } else if (line1.len > line2.len) {
                        cmp = 1;
                    }
                }

                if (cmp > 0) {
                    const temp_start = line_starts[j];
                    const temp_len = line_lens[j];
                    line_starts[j] = line_starts[j + 1];
                    line_lens[j] = line_lens[j + 1];
                    line_starts[j + 1] = temp_start;
                    line_lens[j + 1] = temp_len;
                    swapped = true;
                }
            }
        }

        var j: usize = 0;
        while (j < line_count) : (j += 1) {
            const line = file_buffer[line_starts[j]..line_starts[j] + line_lens[j]];
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
        printNumber(total_kb);
        vga.print("      ");
        printNumber(used_kb);
        vga.print("      ");
        printNumber(free_kb);
        vga.print("   ");
        printNumber(use_percent);
        vga.print("% /\n");
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

    // SAFETY: filled by the following digit extraction loop
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

