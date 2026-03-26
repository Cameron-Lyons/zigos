const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM event regression suite...\n");
    common.printBootMarker("VMEVT:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmEventTestsChecked()) {
        common.printBootMarker("VMEVT:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMEVT:FAIL");
    qemu_exit.failure();
}
