const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");

pub fn run() noreturn {
    console.print("Running VM inotify regression suite...\n");
    common.printBootMarker("VMINOTIFY:START");

    const vm_test = @import("../../tests/vm_test.zig");
    if (vm_test.runVmInotifyTestsChecked()) {
        common.printBootMarker("VMINOTIFY:PASS");
        qemu_exit.success();
    }

    common.printBootMarker("VMINOTIFY:FAIL");
    qemu_exit.failure();
}
