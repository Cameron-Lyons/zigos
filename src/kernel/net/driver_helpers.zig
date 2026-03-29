const ethernet = @import("ethernet.zig");
const link_port = @import("link_port.zig");
const pci = @import("../drivers/pci.zig");
const vga = @import("../drivers/vga.zig");
const bootstrap_driver_port = @import("../process/native/bootstrap_driver_port.zig");

pub const ArpReplyHeader = packed struct {
    hardware_type: u16,
    protocol_type: u16,
    hardware_addr_len: u8,
    protocol_addr_len: u8,
    opcode: u16,
    sender_mac0: u8,
    sender_mac1: u8,
    sender_mac2: u8,
    sender_mac3: u8,
    sender_mac4: u8,
    sender_mac5: u8,
    sender_ip: u32,
    target_mac0: u8,
    target_mac1: u8,
    target_mac2: u8,
    target_mac3: u8,
    target_mac4: u8,
    target_mac5: u8,
    target_ip: u32,
};

pub fn writeSyntheticArpReply(frame: []u8, sender_ip: u32, target_ip: u32, sender_mac: [6]u8, target_mac: [6]u8) void {
    const eth_header: *align(1) ethernet.EthernetHeader = @ptrCast(frame.ptr);
    eth_header.dst_mac0 = target_mac[0];
    eth_header.dst_mac1 = target_mac[1];
    eth_header.dst_mac2 = target_mac[2];
    eth_header.dst_mac3 = target_mac[3];
    eth_header.dst_mac4 = target_mac[4];
    eth_header.dst_mac5 = target_mac[5];
    eth_header.src_mac0 = sender_mac[0];
    eth_header.src_mac1 = sender_mac[1];
    eth_header.src_mac2 = sender_mac[2];
    eth_header.src_mac3 = sender_mac[3];
    eth_header.src_mac4 = sender_mac[4];
    eth_header.src_mac5 = sender_mac[5];
    eth_header.ethertype = @byteSwap(@intFromEnum(ethernet.EtherType.ARP));

    const arp_header: *align(1) ArpReplyHeader = @ptrCast(frame[ethernet.ETH_HEADER_SIZE..].ptr);
    arp_header.hardware_type = @byteSwap(@as(u16, 1));
    arp_header.protocol_type = @byteSwap(@as(u16, 0x0800));
    arp_header.hardware_addr_len = 6;
    arp_header.protocol_addr_len = 4;
    arp_header.opcode = @byteSwap(@as(u16, 2));
    arp_header.sender_mac0 = sender_mac[0];
    arp_header.sender_mac1 = sender_mac[1];
    arp_header.sender_mac2 = sender_mac[2];
    arp_header.sender_mac3 = sender_mac[3];
    arp_header.sender_mac4 = sender_mac[4];
    arp_header.sender_mac5 = sender_mac[5];
    arp_header.sender_ip = @byteSwap(sender_ip);
    arp_header.target_mac0 = target_mac[0];
    arp_header.target_mac1 = target_mac[1];
    arp_header.target_mac2 = target_mac[2];
    arp_header.target_mac3 = target_mac[3];
    arp_header.target_mac4 = target_mac[4];
    arp_header.target_mac5 = target_mac[5];
    arp_header.target_ip = @byteSwap(target_ip);
}

pub fn macEquals(a: [6]u8, b: [6]u8) bool {
    return a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[3] == b[3] and a[4] == b[4] and a[5] == b[5];
}

pub fn printMac(prefix: []const u8, mac: [6]u8) void {
    vga.print(prefix);
    for (mac, 0..) |byte, i| {
        const high = byte >> 4;
        const low = byte & 0x0F;
        vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
        vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
        if (i < 5) vga.print(":");
    }
    vga.print("\n");
}

pub fn publishBootstrapTransport(
    device_id: u64,
    publisher: []const u8,
    current_device: *const fn (u64) ?*const link_port.NetworkDevice,
    activate_device: *const fn (u64) ?*const link_port.NetworkDevice,
    is_supported: *const fn (pci.PCIDevice) bool,
) bool {
    if (current_device(device_id)) |device| {
        return bootstrap_driver_port.publishNetworkDevice(device_id, publisher, device, true);
    }

    const pci_device = pci.findDeviceByStableId(device_id) orelse return false;
    if (!is_supported(pci_device)) return false;
    return bootstrap_driver_port.publishNetworkActivator(device_id, publisher, activate_device, true);
}
