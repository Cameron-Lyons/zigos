const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM core regression suite...\n");
    common.printBootMarker("VMCORE:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmCoreTestsChecked()) {
        common.printBootMarker("VMCORE:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMCORE:FAIL");
    qemu_exit.failure();
}
