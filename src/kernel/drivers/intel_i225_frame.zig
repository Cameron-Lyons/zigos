const std = @import("std");

pub const ETHERNET_HEADER_BYTES: usize = 14;
pub const MIN_ETHERNET_FRAME_BYTES: usize = 60;
pub const MAX_PAYLOAD_BYTES: usize = 1500;
pub const MAX_ETHERNET_FRAME_BYTES: usize = ETHERNET_HEADER_BYTES + MAX_PAYLOAD_BYTES;
pub const LOCAL_EXPERIMENTAL_ETHERTYPE: u16 = 0x88B5;
pub const BROADCAST_MAC: [6]u8 = [_]u8{0xFF} ** 6;

pub const FrameView = struct {
    source: [6]u8,
    payload: []const u8,
    broadcast_destination: bool,
};

pub const ParseError = error{
    FrameTooShort,
    FrameTooLarge,
    DestinationMismatch,
    InvalidSource,
    EtherTypeMismatch,
};

pub const BuildError = error{
    InvalidDestination,
    InvalidSource,
    InvalidPayload,
};

pub fn decodeMac(ral: u32, rah: u32) [6]u8 {
    return .{
        @truncate(ral),
        @truncate(ral >> 8),
        @truncate(ral >> 16),
        @truncate(ral >> 24),
        @truncate(rah),
        @truncate(rah >> 8),
    };
}

pub fn validUnicastMac(mac: [6]u8) bool {
    if ((mac[0] & 1) != 0) return false;
    var any_nonzero = false;
    var any_not_ff = false;
    for (mac) |byte| {
        any_nonzero = any_nonzero or byte != 0;
        any_not_ff = any_not_ff or byte != 0xFF;
    }
    return any_nonzero and any_not_ff;
}

pub fn validDestinationMac(mac: [6]u8) bool {
    return std.mem.eql(u8, &mac, &BROADCAST_MAC) or validUnicastMac(mac);
}

pub fn buildEthernetFrame(output: []u8, destination: [6]u8, source: [6]u8, payload: []const u8) BuildError!usize {
    if (!validDestinationMac(destination)) return error.InvalidDestination;
    if (!validUnicastMac(source)) return error.InvalidSource;
    if (payload.len == 0 or payload.len > MAX_PAYLOAD_BYTES or output.len < ETHERNET_HEADER_BYTES + payload.len) {
        return error.InvalidPayload;
    }
    @memcpy(output[0..6], &destination);
    @memcpy(output[6..12], &source);
    output[12] = @truncate(LOCAL_EXPERIMENTAL_ETHERTYPE >> 8);
    output[13] = @truncate(LOCAL_EXPERIMENTAL_ETHERTYPE);
    @memcpy(output[ETHERNET_HEADER_BYTES .. ETHERNET_HEADER_BYTES + payload.len], payload);
    const frame_len = @max(MIN_ETHERNET_FRAME_BYTES, ETHERNET_HEADER_BYTES + payload.len);
    if (output.len < frame_len) return error.InvalidPayload;
    @memset(output[ETHERNET_HEADER_BYTES + payload.len .. frame_len], 0);
    return frame_len;
}

pub fn parseEthernetFrame(frame: []const u8, local_mac: [6]u8) ParseError!FrameView {
    if (frame.len < MIN_ETHERNET_FRAME_BYTES) return error.FrameTooShort;
    if (frame.len > MAX_ETHERNET_FRAME_BYTES) return error.FrameTooLarge;

    const destination = frame[0..6];
    const broadcast = allBytes(destination, 0xFF);
    if (!broadcast and !std.mem.eql(u8, destination, &local_mac)) return error.DestinationMismatch;

    var source: [6]u8 = undefined;
    @memcpy(&source, frame[6..12]);
    if (!validUnicastMac(source)) return error.InvalidSource;

    const ether_type = (@as(u16, frame[12]) << 8) | frame[13];
    if (ether_type != LOCAL_EXPERIMENTAL_ETHERTYPE) return error.EtherTypeMismatch;
    return .{
        .source = source,
        .payload = frame[ETHERNET_HEADER_BYTES..],
        .broadcast_destination = broadcast,
    };
}

fn allBytes(bytes: []const u8, expected: u8) bool {
    for (bytes) |byte| {
        if (byte != expected) return false;
    }
    return true;
}

test "I225 permanent MAC decoding rejects invalid addresses" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x15, 0xF2, 0x12, 0x34, 0x56 }, &decodeMac(0x12F2_1502, 0x0000_5634));
    try std.testing.expect(validUnicastMac(.{ 0x02, 0x15, 0xF2, 0x12, 0x34, 0x56 }));
    try std.testing.expect(!validUnicastMac([_]u8{0} ** 6));
    try std.testing.expect(!validUnicastMac([_]u8{0xFF} ** 6));
    try std.testing.expect(!validUnicastMac(.{ 0x01, 0, 0, 0, 0, 1 }));
}

test "I225 Ethernet envelope uses the local experimental EtherType and pads short frames" {
    var frame: [128]u8 = undefined;
    const source = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 1 };
    const length = try buildEthernetFrame(&frame, BROADCAST_MAC, source, "ZGND");
    try std.testing.expectEqual(@as(usize, MIN_ETHERNET_FRAME_BYTES), length);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 6, frame[0..6]);
    try std.testing.expectEqualSlices(u8, &source, frame[6..12]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x88, 0xB5 }, frame[12..14]);
    try std.testing.expectEqualStrings("ZGND", frame[14..18]);
    for (frame[18..length]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "I225 Ethernet envelope rejects empty and oversized payloads" {
    var frame: [2048]u8 = undefined;
    const source = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 1 };
    try std.testing.expectError(error.InvalidPayload, buildEthernetFrame(&frame, BROADCAST_MAC, source, ""));
    const oversized = [_]u8{0xA5} ** (MAX_PAYLOAD_BYTES + 1);
    try std.testing.expectError(error.InvalidPayload, buildEthernetFrame(&frame, BROADCAST_MAC, source, &oversized));
}

test "I225 Ethernet envelope addresses peer traffic without broadcasting" {
    var frame: [128]u8 = undefined;
    const source = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 1 };
    const destination = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 2 };
    const length = try buildEthernetFrame(&frame, destination, source, "ZGST");
    try std.testing.expectEqualSlices(u8, &destination, frame[0..6]);
    try std.testing.expectEqualSlices(u8, &source, frame[6..12]);
    try std.testing.expectEqual(@as(usize, MIN_ETHERNET_FRAME_BYTES), length);

    try std.testing.expectError(error.InvalidDestination, buildEthernetFrame(&frame, [_]u8{0} ** 6, source, "ZGST"));
    try std.testing.expectError(error.InvalidDestination, buildEthernetFrame(&frame, .{ 0x01, 0, 0, 0, 0, 1 }, source, "ZGST"));
    try std.testing.expectError(error.InvalidSource, buildEthernetFrame(&frame, destination, [_]u8{0} ** 6, "ZGST"));
}

test "I225 receive parser accepts directed and broadcast local frames" {
    const local = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 7 };
    const peer = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 8 };
    var directed = [_]u8{0} ** MIN_ETHERNET_FRAME_BYTES;
    @memcpy(directed[0..6], &local);
    @memcpy(directed[6..12], &peer);
    directed[12] = 0x88;
    directed[13] = 0xB5;
    @memcpy(directed[14..18], "ZGST");

    const directed_view = try parseEthernetFrame(&directed, local);
    try std.testing.expect(!directed_view.broadcast_destination);
    try std.testing.expectEqualSlices(u8, &peer, &directed_view.source);
    try std.testing.expectEqualStrings("ZGST", directed_view.payload[0..4]);
    try std.testing.expectEqual(@as(usize, MIN_ETHERNET_FRAME_BYTES - ETHERNET_HEADER_BYTES), directed_view.payload.len);

    @memset(directed[0..6], 0xFF);
    const broadcast_view = try parseEthernetFrame(&directed, local);
    try std.testing.expect(broadcast_view.broadcast_destination);
}

test "I225 receive parser rejects unrelated, malformed, and oversized frames" {
    const local = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 7 };
    const peer = [_]u8{ 0x02, 0x15, 0xF2, 0, 0, 8 };
    var frame = [_]u8{0} ** MIN_ETHERNET_FRAME_BYTES;
    @memcpy(frame[0..6], &peer);
    @memcpy(frame[6..12], &peer);
    frame[12] = 0x88;
    frame[13] = 0xB5;
    @memcpy(frame[14..18], "ZGST");
    try std.testing.expectError(error.DestinationMismatch, parseEthernetFrame(&frame, local));

    @memcpy(frame[0..6], &local);
    frame[13] = 0xB6;
    try std.testing.expectError(error.EtherTypeMismatch, parseEthernetFrame(&frame, local));
    frame[13] = 0xB5;
    @memset(frame[6..12], 0);
    try std.testing.expectError(error.InvalidSource, parseEthernetFrame(&frame, local));
    try std.testing.expectError(error.FrameTooShort, parseEthernetFrame(frame[0 .. MIN_ETHERNET_FRAME_BYTES - 1], local));

    const oversized = [_]u8{0} ** (MAX_ETHERNET_FRAME_BYTES + 1);
    try std.testing.expectError(error.FrameTooLarge, parseEthernetFrame(&oversized, local));
}
