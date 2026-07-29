const std = @import("std");

const ETHERNET_HEADER_BYTES: usize = 14;
const MIN_ETHERNET_FRAME_BYTES: usize = 60;
pub const MAX_PAYLOAD_BYTES: usize = 1500;
pub const LOCAL_EXPERIMENTAL_ETHERTYPE: u16 = 0x88B5;

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

pub fn buildEthernetFrame(output: []u8, source: [6]u8, payload: []const u8) error{InvalidPayload}!usize {
    if (payload.len == 0 or payload.len > MAX_PAYLOAD_BYTES or output.len < ETHERNET_HEADER_BYTES + payload.len) {
        return error.InvalidPayload;
    }
    @memset(output[0..6], 0xFF);
    @memcpy(output[6..12], &source);
    output[12] = @truncate(LOCAL_EXPERIMENTAL_ETHERTYPE >> 8);
    output[13] = @truncate(LOCAL_EXPERIMENTAL_ETHERTYPE);
    @memcpy(output[ETHERNET_HEADER_BYTES .. ETHERNET_HEADER_BYTES + payload.len], payload);
    const frame_len = @max(MIN_ETHERNET_FRAME_BYTES, ETHERNET_HEADER_BYTES + payload.len);
    if (output.len < frame_len) return error.InvalidPayload;
    @memset(output[ETHERNET_HEADER_BYTES + payload.len .. frame_len], 0);
    return frame_len;
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
    const length = try buildEthernetFrame(&frame, source, "ZGND");
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
    try std.testing.expectError(error.InvalidPayload, buildEthernetFrame(&frame, source, ""));
    const oversized = [_]u8{0xA5} ** (MAX_PAYLOAD_BYTES + 1);
    try std.testing.expectError(error.InvalidPayload, buildEthernetFrame(&frame, source, &oversized));
}
