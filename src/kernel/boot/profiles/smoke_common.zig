const std = @import("std");
const shell = @import("../../shell/repl.zig");
const common = @import("../common.zig");
const console = @import("../../utils/console.zig");

pub fn printStepEvent(comptime prefix: []const u8, marker: []const u8, phase: []const u8) void {
    var line_buf: [96]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "{s}:STEP:{s}:{s}\n", .{ prefix, phase, marker }) catch "SMOKE:STEP\n";
    console.print(line);
}

pub fn runStep(comptime prefix: []const u8, smoke_shell: *shell.Shell, command: []const u8, marker: []const u8) bool {
    printStepEvent(prefix, marker, "START");
    if (!smoke_shell.runCommandLine(command)) {
        printStepEvent(prefix, marker, "FAIL");
        return false;
    }
    common.printBootMarker(marker);
    return true;
}
