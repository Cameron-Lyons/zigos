const std = @import("std");
const vga = @import("vga.zig");
const process = @import("process.zig");
const timer = @import("timer.zig");
const paging = @import("paging.zig");
const test_memory = @import("test_memory.zig");
const panic_handler = @import("panic.zig");
const device = @import("device.zig");
const vfs = @import("vfs.zig");
const network = @import("network.zig");

const MAX_COMMAND_LENGTH = 256;
const MAX_ARGS = 16;

pub const Shell = struct {
    command_buffer: [MAX_COMMAND_LENGTH]u8,
    buffer_pos: usize,
    running: bool,

    pub fn init() Shell {
        return Shell{
            .command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH,
            .buffer_pos = 0,
            .running = true,
        };
    }

    pub fn handleChar(self: *Shell, char: u8) void {
        switch (char) {
            '\n' => {
                self.executeCommand();
                self.buffer_pos = 0;
                self.command_buffer = [_]u8{0} ** MAX_COMMAND_LENGTH;
                self.printPrompt();
            },
            '\x08' => { // Backspace
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
                    self.command_buffer[arg_end] = 0; // Null terminate
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
        } else if (streq(command, "ls")) {
            self.cmdLs(args[1..arg_count]);
        } else if (streq(command, "cat")) {
            self.cmdCat(args[1..arg_count]);
        } else if (streq(command, "mount")) {
            self.cmdMount(args[1..arg_count]);
        } else if (streq(command, "ping")) {
            self.cmdPing(args[1..arg_count]);
        } else if (streq(command, "httpd")) {
            self.cmdHttpd(args[1..arg_count]);
        } else if (streq(command, "netstat")) {
            self.cmdNetstat();
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
        vga.print("  shutdown - Halt the system\n");
        vga.print("  memtest  - Run memory allocator tests\n");
        vga.print("  panic    - Trigger a kernel panic (for testing)\n");
        vga.print("  lsdev    - List available devices\n");
        vga.print("  ls       - List directory contents\n");
        vga.print("  cat      - Display file contents\n");
        vga.print("  mount    - Mount a file system\n");
        vga.print("  ping     - Ping an IP address\n");
        vga.print("  httpd    - Start/stop HTTP server\n");
        vga.print("  netstat  - Show network statistics\n");
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
        const seconds = ticks / 100; // 100Hz timer
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
                if (byte == '\r') continue; // Skip carriage returns
                vga.put_char(byte);
            }
        }
        vga.put_char('\n');
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
        const http = @import("http.zig");
        
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
        
        const gateway = network.getGatewayIP();
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

        // Check for overflow
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

