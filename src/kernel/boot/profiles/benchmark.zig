const console = @import("../../utils/console.zig");
const benchmark_suite = @import("../../benchmarks/suite.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");

pub fn run() noreturn {
    console.print("Running kernel benchmarks...\n");
    if (benchmark_suite.run()) {
        qemu_exit.success();
    }
    qemu_exit.failure();
}
