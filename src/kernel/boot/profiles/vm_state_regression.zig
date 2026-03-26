const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM state regression suite...\n");
    common.printBootMarker("VMSTATE:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmStateTestsChecked()) {
        common.printBootMarker("VMSTATE:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMSTATE:FAIL");
    qemu_exit.failure();
}
