const console = @import("../../utils/console.zig");
const keyboard = @import("../../drivers/keyboard.zig");
const process = @import("../../process/process.zig");
const shell = @import("../../shell/repl.zig");
const external = @import("../../shell/launcher.zig");
const common = @import("../common.zig");

pub fn createDemoProcesses() void {
    console.print("Creating test processes...\n");
    const test_syscall = @import("../../tests/test_syscall.zig");
    _ = process.create_process("test1", testProcess1);
    _ = process.create_process("test2", testProcess2);
    _ = process.create_process("syscall_test", test_syscall.test_syscall_process);

    const userspace = @import("../../process/userspace.zig");
    userspace.createUserTestProcess();

    const ring3 = @import("../../process/ring3.zig");
    ring3.createRing3TestProcess();
}

pub fn initializeShell(shell_instance: *shell.Shell) void {
    console.print("Initializing shell...\n");
    shell_instance.* = shell.Shell.init();
    keyboard.setShell(shell_instance);
    common.printBootMarker("BOOT:SHELL_READY");
}

pub fn launchInitProcess() ?*process.Process {
    const init_command = [_][*:0]const u8{"/bin/init"};
    const pid = external.launchExternalCommand(init_command[0..], null, null, null) catch |err| {
        console.print("Failed to launch /bin/init: ");
        console.print(@errorName(err));
        console.print("\n");
        return null;
    };

    console.print("Init process launched\n");
    return process.getProcessByPid(pid);
}

fn runTestProcess(marker: []const u8) void {
    const test_process_log_interval: u32 = 1_000_000;
    var i: u32 = 0;
    while (true) : (i += 1) {
        if (i % test_process_log_interval == 0) {
            console.print(marker);
        }
        process.yield();
    }
}

fn testProcess1() void {
    runTestProcess("A");
}

fn testProcess2() void {
    runTestProcess("B");
}
