const vga = @import("../drivers/vga.zig");

pub const kernel_boundary_role = "bootstrap_network_shim";
pub const publishes_full_network_service = false;

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

pub const EthernetFrame = struct {
    header: EthernetHeader,
    data: []u8,
};

var rx_handlers: [3]?*const fn (frame: *const EthernetFrame) void = [_]?*const fn (frame: *const EthernetFrame) void{null} ** 3;
var tx_hook: ?*const fn (frame: []const u8) void = null;
var tx_sender: ?*const fn (frame: []const u8) void = null;
var mac_provider: ?*const fn () [6]u8 = null;

pub fn init() void {
    vga.print("Ethernet layer initialized\n");
}

pub fn registerHandler(ethertype: EtherType, handler: *const fn (frame: *const EthernetFrame) void) void {
    const index: usize = switch (ethertype) {
        .IPv4 => 0,
        .ARP => 1,
        .IPv6 => 2,
    };
    rx_handlers[index] = handler;
}

pub fn setTxHook(hook: ?*const fn (frame: []const u8) void) void {
    tx_hook = hook;
}

pub fn setTxSender(sender: ?*const fn (frame: []const u8) void) void {
    tx_sender = sender;
}

pub fn setMacProvider(provider: ?*const fn () [6]u8) void {
    mac_provider = provider;
}

pub fn getSourceMac() ?[6]u8 {
    return if (mac_provider) |provider|
        provider()
    else if (tx_hook != null)
        [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }
    else
        null;
}

pub fn sendFrame(dst_mac: [6]u8, ethertype: EtherType, data: []const u8) !void {
    if (data.len > ETH_MTU) {
        return error.FrameTooLarge;
    }

    // SAFETY: header and data portions filled before the buffer is sent
    var frame_buf: [ETH_HEADER_SIZE + ETH_MTU]u8 = undefined;
    var frame: *align(1) EthernetHeader = @ptrCast(&frame_buf[0]);

    frame.dst_mac0 = dst_mac[0];
    frame.dst_mac1 = dst_mac[1];
    frame.dst_mac2 = dst_mac[2];
    frame.dst_mac3 = dst_mac[3];
    frame.dst_mac4 = dst_mac[4];
    frame.dst_mac5 = dst_mac[5];

    const src_mac = getSourceMac() orelse return error.NoMACAddress;
    frame.src_mac0 = src_mac[0];
    frame.src_mac1 = src_mac[1];
    frame.src_mac2 = src_mac[2];
    frame.src_mac3 = src_mac[3];
    frame.src_mac4 = src_mac[4];
    frame.src_mac5 = src_mac[5];

    frame.ethertype = @byteSwap(@intFromEnum(ethertype));

    @memcpy(frame_buf[ETH_HEADER_SIZE .. ETH_HEADER_SIZE + data.len], data);

    if (tx_hook) |hook| {
        hook(frame_buf[0 .. ETH_HEADER_SIZE + data.len]);
        return;
    }

    if (tx_sender) |sender| {
        sender(frame_buf[0 .. ETH_HEADER_SIZE + data.len]);
        return;
    }

    return error.NoTransmitter;
}

pub fn handleRxPacket(packet: []u8) void {
    if (packet.len < ETH_HEADER_SIZE) {
        return;
    }

    const header: *align(1) const EthernetHeader = @ptrCast(packet.ptr);
    const ethertype = @byteSwap(header.ethertype);

    const frame = EthernetFrame{
        .header = header.*,
        .data = packet[ETH_HEADER_SIZE..],
    };

    // SAFETY: assigned in every branch of the if/else chain below; function returns on else
    var handler_index: usize = undefined;
    if (ethertype == @intFromEnum(EtherType.IPv4)) {
        handler_index = 0;
    } else if (ethertype == @intFromEnum(EtherType.ARP)) {
        handler_index = 1;
    } else if (ethertype == @intFromEnum(EtherType.IPv6)) {
        handler_index = 2;
    } else {
        return;
    }

    if (handler_index < rx_handlers.len) {
        if (rx_handlers[handler_index]) |handler| {
            handler(&frame);
        }
    }
}
