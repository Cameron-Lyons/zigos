const console = @import("../../utils/console.zig");
const arp = @import("../../net/arp.zig");
const network = @import("../../net/network.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const timer = @import("../../timer/timer.zig");
const virtio = @import("../../drivers/virtio.zig");
const common = @import("../common.zig");

const injected_sender_ip: u32 = 0x0A000001;
const injected_sender_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x66 };

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("VIRTIOINGRESS:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("virtio_ingress_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running VirtIO ingress regression...\n");
    common.printBootMarker("VIRTIOINGRESS:START");

    virtio.init();
    if (!virtio.isInitialized()) {
        fail("VIRTIOINGRESS:DRIVER:FAIL");
    }
    common.printBootMarker("VIRTIOINGRESS:DRIVER:PASS");

    const deadline = timer.getTicks() + 800;
    while (timer.getTicks() < deadline) {
        if (network.receivePacket()) |packet| {
            network.processPacket(packet, network.getMacAddress());
            common.printBootMarker("VIRTIOINGRESS:PACKET:PASS");
        }

        if (arp.resolve(injected_sender_ip)) |resolved_mac| {
            if (resolved_mac[0] == injected_sender_mac[0] and
                resolved_mac[1] == injected_sender_mac[1] and
                resolved_mac[2] == injected_sender_mac[2] and
                resolved_mac[3] == injected_sender_mac[3] and
                resolved_mac[4] == injected_sender_mac[4] and
                resolved_mac[5] == injected_sender_mac[5])
            {
                common.printBootMarker("VIRTIOINGRESS:ARP:PASS");
                common.printBootMarker("VIRTIOINGRESS:PASS");
                qemu_exit.success();
            }
        }

        asm volatile ("pause");
    }

    fail("VIRTIOINGRESS:ARP:FAIL");
}
