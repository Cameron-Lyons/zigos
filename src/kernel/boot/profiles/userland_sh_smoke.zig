const process = @import("../../process/process.zig");
const shell = @import("../../shell/repl.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const smoke_common = @import("smoke_common.zig");
const support = @import("support.zig");

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
        if (!smoke_common.runStep("USERLAND_SH", &smoke_shell, step.command, step.marker)) {
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
