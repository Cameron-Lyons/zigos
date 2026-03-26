const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM tty regression suite...\n");
    common.printBootMarker("VMTTY:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmTtyTestsChecked()) {
        common.printBootMarker("VMTTY:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMTTY:FAIL");
    qemu_exit.failure();
}
