const std = @import("std");
const vga = @import("vga.zig");
const rtl8139 = @import("rtl8139.zig");

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

pub fn sendFrame(dst_mac: [6]u8, ethertype: EtherType, data: []const u8) !void {
    if (data.len > ETH_MTU) {
        return error.FrameTooLarge;
    }

    var frame_buf: [ETH_HEADER_SIZE + ETH_MTU]u8 = undefined;
    var frame = @as(*EthernetHeader, @ptrCast(@alignCast(&frame_buf[0])));

    frame.dst_mac0 = dst_mac[0];
    frame.dst_mac1 = dst_mac[1];
    frame.dst_mac2 = dst_mac[2];
    frame.dst_mac3 = dst_mac[3];
    frame.dst_mac4 = dst_mac[4];
    frame.dst_mac5 = dst_mac[5];

    if (rtl8139.getMACAddress()) |src_mac| {
        frame.src_mac0 = src_mac[0];
        frame.src_mac1 = src_mac[1];
        frame.src_mac2 = src_mac[2];
        frame.src_mac3 = src_mac[3];
        frame.src_mac4 = src_mac[4];
        frame.src_mac5 = src_mac[5];
    } else {
        return error.NoMACAddress;
    }

    frame.ethertype = @byteSwap(@intFromEnum(ethertype));

    @memcpy(frame_buf[ETH_HEADER_SIZE .. ETH_HEADER_SIZE + data.len], data);

    try rtl8139.sendPacket(frame_buf[0 .. ETH_HEADER_SIZE + data.len]);
}

pub fn handleRxPacket(packet: []u8) void {
    if (packet.len < ETH_HEADER_SIZE) {
        return;
    }

    const header = @as(*const EthernetHeader, @ptrCast(@alignCast(packet.ptr)));
    const ethertype = @byteSwap(header.ethertype);

    const frame = EthernetFrame{
        .header = header.*,
        .data = packet[ETH_HEADER_SIZE..],
    };

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

