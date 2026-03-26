const console = @import("../../utils/console.zig");
const arp = @import("../../net/arp.zig");
const network = @import("../../net/network.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const rtl8139 = @import("../../drivers/rtl8139.zig");
const timer = @import("../../timer/timer.zig");
const common = @import("../common.zig");

const injected_sender_ip: u32 = 0x0A000001;
const injected_sender_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x55 };

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("NICINGRESS:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("nic_ingress_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running NIC ingress regression...\n");
    common.printBootMarker("NICINGRESS:START");

    rtl8139.init();
    if (!rtl8139.isInitialized()) {
        fail("NICINGRESS:DRIVER:FAIL");
    }
    common.printBootMarker("NICINGRESS:DRIVER:PASS");

    const deadline = timer.getTicks() + 800;
    var packet_seen = false;
    while (timer.getTicks() < deadline) {
        if (rtl8139.receive()) |packet| {
            network.processPacket(packet, rtl8139.getMacAddress());
            if (!packet_seen) {
                common.printBootMarker("NICINGRESS:PACKET:PASS");
                packet_seen = true;
            }
        }
        if (arp.resolve(injected_sender_ip)) |resolved_mac| {
            if (resolved_mac[0] == injected_sender_mac[0] and
                resolved_mac[1] == injected_sender_mac[1] and
                resolved_mac[2] == injected_sender_mac[2] and
                resolved_mac[3] == injected_sender_mac[3] and
                resolved_mac[4] == injected_sender_mac[4] and
                resolved_mac[5] == injected_sender_mac[5])
            {
                common.printBootMarker("NICINGRESS:ARP:PASS");
                common.printBootMarker("NICINGRESS:PASS");
                qemu_exit.success();
            }
        }
        asm volatile ("pause");
    }

    rtl8139.debugPrintState("NICINGRESS:RTL8139");

    fail("NICINGRESS:ARP:FAIL");
}
