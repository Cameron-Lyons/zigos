const paging = @import("../../memory/paging.zig");
const process = @import("../../process/process.zig");
const timer = @import("../../timer/timer.zig");
const vga = @import("../../drivers/vga.zig");

pub fn ps() void {
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

        var name_buffer: [65]u8 = undefined;
        @memcpy(name_buffer[0..64], &p.name);
        name_buffer[64] = 0;
        printString(@as([*:0]const u8, @ptrCast(&name_buffer)));
        vga.put_char('\n');
    }
}

pub fn memInfo() void {
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

pub fn uptime() void {
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

pub fn kill(args: []const [*:0]const u8) void {
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

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
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
