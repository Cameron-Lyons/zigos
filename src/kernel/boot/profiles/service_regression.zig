const console = @import("../../utils/console.zig");
const e1000 = @import("../../drivers/e1000.zig");
const rtl8139 = @import("../../drivers/rtl8139.zig");
const virtio = @import("../../drivers/virtio.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const net_test = @import("../../tests/net_test.zig");
const test_memory = @import("../../tests/test_memory.zig");
const test_syscall = @import("../../tests/test_syscall.zig");

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("SERVREG:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("service_regression_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running service regression suites...\n");
    common.printBootMarker("SERVREG:START");

    common.printBootMarker("SERVREG:MEMORY:START");
    if (!test_memory.runMemoryTestsChecked()) {
        fail("SERVREG:MEMORY:FAIL");
    }
    common.printBootMarker("SERVREG:MEMORY:PASS");

    common.printBootMarker("SERVREG:SYSCALL:START");
    if (!test_syscall.runSyscallTestsChecked()) {
        fail("SERVREG:SYSCALL:FAIL");
    }
    common.printBootMarker("SERVREG:SYSCALL:PASS");

    common.printBootMarker("SERVREG:NETWORK:START");
    if (!net_test.runNetworkTestsChecked()) {
        fail("SERVREG:NETWORK:FAIL");
    }
    common.printBootMarker("SERVREG:NETWORK:PASS");

    common.printBootMarker("SERVREG:RTL8139:START");
    if (!rtl8139.runInterruptSelfTestChecked()) {
        fail("SERVREG:RTL8139:FAIL");
    }
    common.printBootMarker("SERVREG:RTL8139:PASS");

    common.printBootMarker("SERVREG:E1000:START");
    if (!e1000.runInterruptSelfTestChecked()) {
        fail("SERVREG:E1000:FAIL");
    }
    common.printBootMarker("SERVREG:E1000:PASS");

    common.printBootMarker("SERVREG:VIRTIO:START");
    if (!virtio.runInterruptSelfTestChecked()) {
        fail("SERVREG:VIRTIO:FAIL");
    }
    common.printBootMarker("SERVREG:VIRTIO:PASS");

    common.printBootMarker("SERVREG:PASS");
    qemu_exit.success();
}
