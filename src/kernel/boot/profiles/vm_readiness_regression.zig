const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM readiness regression suite...\n");
    common.printBootMarker("VMREADY:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmReadinessTestsChecked()) {
        common.printBootMarker("VMREADY:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMREADY:FAIL");
    qemu_exit.failure();
}
