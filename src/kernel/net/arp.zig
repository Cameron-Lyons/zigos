const std = @import("std");
const vga = @import("../drivers/vga.zig");
const ethernet = @import("ethernet.zig");
const rtl8139 = @import("../drivers/rtl8139.zig");

const ARP_HARDWARE_ETHERNET = 1;
const ARP_PROTOCOL_IP = 0x0800;
const ARP_OPCODE_REQUEST = 1;
const ARP_OPCODE_REPLY = 2;

pub const ARPHeader = packed struct {
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

const ARPEntry = struct {
    ip: u32,
    mac: [6]u8,
    valid: bool,
};

fn getMacFromArp(arp: *const ARPHeader, which: enum { sender, target }) [6]u8 {
    var mac: [6]u8 = undefined;
    if (which == .sender) {
        mac[0] = arp.sender_mac0;
        mac[1] = arp.sender_mac1;
        mac[2] = arp.sender_mac2;
        mac[3] = arp.sender_mac3;
        mac[4] = arp.sender_mac4;
        mac[5] = arp.sender_mac5;
    } else {
        mac[0] = arp.target_mac0;
        mac[1] = arp.target_mac1;
        mac[2] = arp.target_mac2;
        mac[3] = arp.target_mac3;
        mac[4] = arp.target_mac4;
        mac[5] = arp.target_mac5;
    }
    return mac;
}

fn setMacInArp(arp: *ARPHeader, which: enum { sender, target }, mac: [6]u8) void {
    if (which == .sender) {
        arp.sender_mac0 = mac[0];
        arp.sender_mac1 = mac[1];
        arp.sender_mac2 = mac[2];
        arp.sender_mac3 = mac[3];
        arp.sender_mac4 = mac[4];
        arp.sender_mac5 = mac[5];
    } else {
        arp.target_mac0 = mac[0];
        arp.target_mac1 = mac[1];
        arp.target_mac2 = mac[2];
        arp.target_mac3 = mac[3];
        arp.target_mac4 = mac[4];
        arp.target_mac5 = mac[5];
    }
}

const ARP_TABLE_SIZE = 64;
var arp_table: [ARP_TABLE_SIZE]ARPEntry = undefined;
var arp_table_init = false;

pub fn init() void {
    if (!arp_table_init) {
        for (&arp_table) |*entry| {
            entry.valid = false;
        }
        arp_table_init = true;
    }

    ethernet.registerHandler(.ARP, handleARPPacket);
    vga.print("ARP initialized\n");
}

fn handleARPPacket(frame: *const ethernet.EthernetFrame) void {
    if (frame.data.len < @sizeOf(ARPHeader)) {
        return;
    }

    const arp = @as(*const ARPHeader, @ptrCast(@alignCast(frame.data.ptr)));

    if (@byteSwap(arp.hardware_type) != ARP_HARDWARE_ETHERNET or
        @byteSwap(arp.protocol_type) != ARP_PROTOCOL_IP)
    {
        return;
    }

    const opcode = @byteSwap(arp.opcode);

    const sender_mac = getMacFromArp(arp, .sender);
    addToTable(@byteSwap(arp.sender_ip), sender_mac);

    if (opcode == ARP_OPCODE_REQUEST) {
        if (isOurIP(@byteSwap(arp.target_ip))) {
            sendARPReply(arp);
        }
    }
}

fn sendARPReply(request: *const ARPHeader) void {
    var reply: ARPHeader = undefined;

    reply.hardware_type = @byteSwap(@as(u16, ARP_HARDWARE_ETHERNET));
    reply.protocol_type = @byteSwap(@as(u16, ARP_PROTOCOL_IP));
    reply.hardware_addr_len = 6;
    reply.protocol_addr_len = 4;
    reply.opcode = @byteSwap(@as(u16, ARP_OPCODE_REPLY));

    if (rtl8139.getMACAddress()) |mac| {
        setMacInArp(&reply, .sender, mac);
    } else {
        return;
    }

    reply.sender_ip = request.target_ip;
    const requester_mac = getMacFromArp(request, .sender);
    setMacInArp(&reply, .target, requester_mac);
    reply.target_ip = request.sender_ip;

    const reply_bytes = @as([*]const u8, @ptrCast(&reply))[0..@sizeOf(ARPHeader)];
    ethernet.sendFrame(requester_mac, .ARP, reply_bytes) catch {
        vga.print("Failed to send ARP reply\n");
    };
}

pub fn sendARPRequest(target_ip: u32) !void {
    var request: ARPHeader = undefined;

    request.hardware_type = @byteSwap(@as(u16, ARP_HARDWARE_ETHERNET));
    request.protocol_type = @byteSwap(@as(u16, ARP_PROTOCOL_IP));
    request.hardware_addr_len = 6;
    request.protocol_addr_len = 4;
    request.opcode = @byteSwap(@as(u16, ARP_OPCODE_REQUEST));

    if (rtl8139.getMACAddress()) |mac| {
        setMacInArp(&request, .sender, mac);
    } else {
        return error.NoMACAddress;
    }

    request.sender_ip = @byteSwap(@as(u32, 0xC0A80102));
    const broadcast_mac_local = [_]u8{0xFF} ** 6;
    setMacInArp(&request, .target, broadcast_mac_local);
    request.target_ip = @byteSwap(target_ip);

    const broadcast_mac = [_]u8{0xFF} ** 6;
    const request_bytes = @as([*]const u8, @ptrCast(&request))[0..@sizeOf(ARPHeader)];
    try ethernet.sendFrame(broadcast_mac, .ARP, request_bytes);
}

pub fn resolve(ip: u32) ?[6]u8 {
    for (arp_table) |entry| {
        if (entry.valid and entry.ip == ip) {
            return entry.mac;
        }
    }
    return null;
}

fn addToTable(ip: u32, mac: [6]u8) void {
    for (&arp_table) |*entry| {
        if (entry.valid and entry.ip == ip) {
            @memcpy(&entry.mac, &mac);
            return;
        }
    }

    for (&arp_table) |*entry| {
        if (!entry.valid) {
            entry.ip = ip;
            @memcpy(&entry.mac, &mac);
            entry.valid = true;
            return;
        }
    }

    arp_table[0].ip = ip;
    @memcpy(&arp_table[0].mac, &mac);
    arp_table[0].valid = true;
}

fn isOurIP(ip: u32) bool {
    return ip == 0xC0A80102;
}

