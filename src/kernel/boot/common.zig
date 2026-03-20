const console = @import("../utils/console.zig");
const config = @import("../config.zig");

pub fn printBootMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

pub fn printBootProfile() void {
    console.print("BOOT:PROFILE:");
    console.print(config.name());
    console.print("\n");
}

pub fn printCpuCount(count: u32) void {
    var cpu_str: [10]u8 = undefined;
    var cpu_count = count;
    var idx: usize = 0;

    if (cpu_count == 0) {
        cpu_str[0] = '0';
        idx = 1;
    } else {
        while (cpu_count > 0) : (idx += 1) {
            cpu_str[idx] = @as(u8, @intCast('0' + (cpu_count % 10)));
            cpu_count /= 10;
        }
        var i: usize = 0;
        while (i < idx / 2) : (i += 1) {
            const tmp = cpu_str[i];
            cpu_str[i] = cpu_str[idx - 1 - i];
            cpu_str[idx - 1 - i] = tmp;
        }
    }

    console.print(cpu_str[0..idx]);
}

pub fn enterIdleLoop() noreturn {
    asm volatile ("sti");
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn idleTaskPlaceholder() void {}
