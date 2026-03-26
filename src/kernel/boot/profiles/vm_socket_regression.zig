const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM socket regression suite...\n");
    common.printBootMarker("VMSOCK:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmSocketTestsChecked()) {
        common.printBootMarker("VMSOCK:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMSOCK:FAIL");
    qemu_exit.failure();
}
