const console = @import("../../utils/console.zig");
const e1000 = @import("../../drivers/e1000.zig");
const network = @import("../../net/network.zig");
const socket = @import("../../net/socket.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const timer = @import("../../timer/timer.zig");
const common = @import("../common.zig");

const ingress_ip = network.ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
const ingress_gateway = network.ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 2 } };
const ingress_netmask = network.ipv4.IPv4Address{ .octets = .{ 255, 255, 255, 0 } };
fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("E1000INGRESS:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("e1000_ingress_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running E1000 ingress regression...\n");
    common.printBootMarker("E1000INGRESS:START");

    e1000.init();
    if (!e1000.isInitialized()) {
        fail("E1000INGRESS:DRIVER:FAIL");
    }
    common.printBootMarker("E1000INGRESS:DRIVER:PASS");

    network.setLocalIP(ingress_ip);
    network.setGateway(ingress_gateway);
    network.setNetmask(ingress_netmask);

    const sock = socket.createSocket(.DGRAM, .UDP) catch {
        fail("E1000INGRESS:SOCKET:FAIL");
    };
    defer sock.close();
    sock.bind(ingress_ip, 8081) catch {
        fail("E1000INGRESS:SOCKET:FAIL");
    };
    common.printBootMarker("E1000INGRESS:SOCKET:PASS");

    const deadline = timer.getTicks() + 800;
    while (timer.getTicks() < deadline) {
        if (network.receivePacket()) |packet| {
            network.processPacket(packet, network.getMacAddress());
            common.printBootMarker("E1000INGRESS:PACKET:PASS");
            common.printBootMarker("E1000INGRESS:PASS");
            qemu_exit.success();
        }
        asm volatile ("pause");
    }

    fail("E1000INGRESS:PACKET:FAIL");
}
