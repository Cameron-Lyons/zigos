const console = @import("../../utils/console.zig");
const network = @import("../../net/network.zig");
const icmp = @import("../../net/icmp.zig");
const ipv6 = @import("../../net/ipv6.zig");
const icmpv6 = @import("../../net/icmpv6.zig");

pub fn init() void {
    network.init();

    console.print("Initializing ICMP...\n");
    icmp.init();

    console.print("Initializing socket API...\n");
    const socket = @import("../../net/socket.zig");
    socket.init();

    console.print("Initializing DNS client...\n");
    const dns = @import("../../net/dns.zig");
    dns.init();

    console.print("Initializing DHCP client...\n");
    const dhcp = @import("../../net/dhcp.zig");
    dhcp.init();

    console.print("Initializing IPv6...\n");
    ipv6.init();

    console.print("Initializing ICMPv6...\n");
    icmpv6.init();
    icmpv6.sendRouterSolicitation();

    console.print("Initializing routing table...\n");
    const routing = @import("../../net/routing.zig");
    routing.init();
}
