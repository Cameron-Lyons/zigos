const console = @import("../../utils/console.zig");
const process = @import("../../process/process.zig");
const shell = @import("../../shell/repl.zig");
const common = @import("../common.zig");
const support = @import("support.zig");

pub fn run() noreturn {
    if (support.launchInitProcess()) |init_proc| {
        console.print("\nZigOS Init Ready!\n");
        process.switchToProcess(init_proc);
    }

    var system_shell: shell.Shell = undefined;
    support.createDemoProcesses();
    support.initializeShell(&system_shell);

    console.print("\nFalling back to kernel shell.\n");
    console.print("ZigOS Shell Ready!\n");
    system_shell.printPrompt();

    asm volatile ("sti");

    while (system_shell.running) {
        asm volatile ("hlt");
    }

    common.enterIdleLoop();
}
