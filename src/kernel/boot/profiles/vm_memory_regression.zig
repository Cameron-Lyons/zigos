const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM memory regression suite...\n");
    common.printBootMarker("VMMEM:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmMemoryTestsChecked()) {
        common.printBootMarker("VMMEM:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMMEM:FAIL");
    qemu_exit.failure();
}
