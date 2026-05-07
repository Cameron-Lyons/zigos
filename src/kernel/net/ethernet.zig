pub const kernel_boundary_role = "bootstrap_network_shim";
pub const publishes_full_network_service = false;
pub const network_data_plane_exports_fail_closed = true;

pub const ETH_HEADER_SIZE = 14;
pub const ETH_MTU = 1500;

pub const EtherType = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
};

pub const EthernetHeader = packed struct {
    dst_mac0: u8,
    dst_mac1: u8,
    dst_mac2: u8,
    dst_mac3: u8,
    dst_mac4: u8,
    dst_mac5: u8,
    src_mac0: u8,
    src_mac1: u8,
    src_mac2: u8,
    src_mac3: u8,
    src_mac4: u8,
    src_mac5: u8,
    ethertype: u16,
};

pub const EthernetFrameView = struct {
    header: EthernetHeader,
    payload: []const u8,
};

pub fn parseInventoryFrame(packet: []const u8) ?EthernetFrameView {
    if (packet.len < ETH_HEADER_SIZE) return null;
    const header: *align(1) const EthernetHeader = @ptrCast(packet.ptr);
    return .{
        .header = header.*,
        .payload = packet[ETH_HEADER_SIZE..],
    };
}
