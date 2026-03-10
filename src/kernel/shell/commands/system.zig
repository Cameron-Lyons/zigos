const std = @import("std");
const device = @import("../../devices/device.zig");
const multitask_demo = @import("../../tests/multitask_demo.zig");
const panic_handler = @import("../../utils/panic.zig");
const numfmt = @import("../../utils/numfmt.zig");
const scheduler = @import("../../process/scheduler.zig");
const test_memory = @import("../../tests/test_memory.zig");
const vga = @import("../../drivers/vga.zig");

pub fn multitask() void {
    multitask_demo.runMultitaskingDemo();
}

pub fn schedulerCommand(args: []const [*:0]const u8) void {
    if (args.len == 0) {
        vga.print("Usage: scheduler <rr|priority|mlfq>\n");
        vga.print("  rr       - Round Robin\n");
        vga.print("  priority - Priority Scheduling\n");
        vga.print("  mlfq     - Multi-Level Feedback Queue\n");
        return;
    }

    const sched_type = sliceFromCStr(args[0]);
    if (std.mem.eql(u8, sched_type, "rr")) {
        scheduler.setSchedulerType(.RoundRobin);
    } else if (std.mem.eql(u8, sched_type, "priority")) {
        scheduler.setSchedulerType(.Priority);
    } else if (std.mem.eql(u8, sched_type, "mlfq")) {
        scheduler.setSchedulerType(.MultiLevelFeedback);
    } else {
        vga.print("Unknown scheduler type: ");
        printString(args[0]);
        vga.print("\n");
    }
}

pub fn schedStats() void {
    multitask_demo.showSchedulerStats();
}

pub fn memTest() void {
    test_memory.test_memory_allocator();
}

pub fn panicCmd() void {
    panic_handler.panic("User triggered panic from shell", .{});
}

pub fn lsDev() void {
    vga.print("Device List:\n");
    vga.print("MAJOR  MINOR  TYPE     NAME\n");
    vga.print("-----  -----  -------  ----\n");

    var dev = device.getDeviceList();
    while (dev) |d| : (dev = d.next) {
        numfmt.printDec(d.major);
        vga.print("      ");

        numfmt.printDec(d.minor);
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

fn printString(str: [*:0]const u8) void {
    var i: usize = 0;
    while (str[i] != 0) : (i += 1) {
        vga.put_char(str[i]);
    }
}

fn sliceFromCStr(str: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (str[len] != 0) : (len += 1) {}
    return str[0..len];
}
