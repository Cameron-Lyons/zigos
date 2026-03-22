const std = @import("std");
const process = @import("../../process/process.zig");
const shell = @import("../../shell/repl.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const support = @import("support.zig");

fn printStepEvent(marker: []const u8, phase: []const u8) void {
    var line_buf: [96]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "USERLAND_SH:STEP:{s}:{s}\n", .{ phase, marker }) catch "USERLAND_SH:STEP\n";
    @import("../../utils/console.zig").print(line);
}

fn runStep(smoke_shell: *shell.Shell, command: []const u8, marker: []const u8) bool {
    printStepEvent(marker, "START");
    if (!smoke_shell.runCommandLine(command)) {
        printStepEvent(marker, "FAIL");
        return false;
    }
    common.printBootMarker(marker);
    return true;
}

fn userlandShSmokeRunner() callconv(.c) void {
    var smoke_shell = shell.Shell.init();
    const commands = [_]struct {
        command: []const u8,
        marker: []const u8,
    }{
        .{ .command = "/bin/sh -c \"/bin/echo USERLAND_SH:SIMPLE\"", .marker = "USERLAND_SH:SIMPLE_OK" },
        .{ .command = "/bin/sh -c \"pwd\"", .marker = "USERLAND_SH:PWD_OK" },
        .{ .command = "/bin/sh -c \"/bin/true\"", .marker = "USERLAND_SH:TRUE_OK" },
    };

    common.printBootMarker("USERLAND_SH:START");

    for (commands) |step| {
        if (!runStep(&smoke_shell, step.command, step.marker)) {
            common.printBootMarker("USERLAND_SH:FAIL");
            qemu_exit.failure();
        }
    }

    common.printBootMarker("USERLAND_SH:PASS");
    qemu_exit.success();
}

pub fn run() noreturn {
    var shell_instance: shell.Shell = undefined;
    support.initializeShell(&shell_instance);

    const runner = process.create_kernel_process("userland_sh_smoke_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);
    userlandShSmokeRunner();
    unreachable;
}
