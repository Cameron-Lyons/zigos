const shell = @import("../../shell/repl.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const support = @import("support.zig");

pub fn run() noreturn {
    var system_shell: shell.Shell = undefined;
    support.initializeShell(&system_shell);
    common.printBootMarker("BOOT:PASS");
    qemu_exit.success();
}
