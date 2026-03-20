const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM tests...\n");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.test_virtual_memory()) {
        common.printBootMarker("TEST:VM:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("TEST:VM:FAIL");
    qemu_exit.failure();
}
