const console = @import("../../utils/console.zig");
const process = @import("../../process/process.zig");
const ipc = @import("../../process/ipc.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const test_file_io = @import("../../tests/test_file_io.zig");
const test_tcp = @import("../../tests/test_tcp_reliability.zig");
const sync = @import("../../utils/sync.zig");

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("MANUAL:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("manual_regression_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running manual regression suites...\n");
    common.printBootMarker("MANUAL:START");

    common.printBootMarker("MANUAL:FILEIO:START");
    if (!test_file_io.runFileIOTestsChecked()) {
        fail("MANUAL:FILEIO:FAIL");
    }
    common.printBootMarker("MANUAL:FILEIO:PASS");

    common.printBootMarker("MANUAL:TCP:START");
    if (!test_tcp.runTCPReliabilityTestsChecked()) {
        fail("MANUAL:TCP:FAIL");
    }
    common.printBootMarker("MANUAL:TCP:PASS");

    common.printBootMarker("MANUAL:SYNC:START");
    if (!sync.runSynchronizationTestsChecked()) {
        fail("MANUAL:SYNC:FAIL");
    }
    common.printBootMarker("MANUAL:SYNC:PASS");

    common.printBootMarker("MANUAL:IPC:START");
    if (!ipc.runIPCTestsChecked()) {
        fail("MANUAL:IPC:FAIL");
    }
    common.printBootMarker("MANUAL:IPC:PASS");

    common.printBootMarker("MANUAL:PASS");
    qemu_exit.success();
}
