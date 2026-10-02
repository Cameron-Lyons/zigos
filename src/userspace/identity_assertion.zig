//! Public, canonical assertion bytes. Decoding is not signature verification:
//! the relying party must verify against its independently registered public key.
const std = @import("std");
pub const MAX_BYTES = 380;
pub const Error = error{InvalidIdentityAssertion};
pub const Assertion = struct {
    credential_id: u64,
    owner_id: u64,
    device_id: u64,
    generation: u32,
    counter: u64,
    device_trust_generation: u32,
    unlock_age_ticks: u64,
    flags: u8,
    relying_party_id: []const u8,
    origin: []const u8,
    challenge: []const u8,
    public_key: [32]u8,
    signature: [64]u8,

    fn validate(self: Assertion) Error!void {
        if (self.credential_id == 0 or self.owner_id == 0 or self.device_id == 0 or self.generation == 0 or self.counter == 0 or
            self.device_trust_generation == 0 or self.flags & 0xe0 != 0 or
            self.relying_party_id.len == 0 or self.relying_party_id.len > 64 or self.origin.len == 0 or self.origin.len > 96 or
            self.challenge.len == 0 or self.challenge.len > 64) return error.InvalidIdentityAssertion;
    }
};

pub fn encode(value: Assertion, out: *[MAX_BYTES]u8) Error![]const u8 {
    try value.validate();
    @memset(out, 0);
    @memcpy(out[0..8], "ZGIDAS01");
    put(u64, out[8..], value.credential_id);
    put(u64, out[16..], value.owner_id);
    put(u64, out[24..], value.device_id);
    put(u32, out[32..], value.generation);
    put(u64, out[36..], value.counter);
    put(u32, out[44..], value.device_trust_generation);
    put(u64, out[48..], value.unlock_age_ticks);
    out[56] = value.flags;
    out[57] = @intCast(value.relying_party_id.len);
    out[58] = @intCast(value.origin.len);
    out[59] = @intCast(value.challenge.len);
    @memcpy(out[60..92], &value.public_key);
    @memcpy(out[92..156], &value.signature);
    var position: usize = 156;
    for ([_][]const u8{ value.relying_party_id, value.origin, value.challenge }) |bytes| {
        @memcpy(out[position..][0..bytes.len], bytes);
        position += bytes.len;
    }
    return out[0..position];
}

pub fn decode(bytes: []const u8) Error!Assertion {
    if (bytes.len < 156 or bytes.len > MAX_BYTES or !std.mem.eql(u8, bytes[0..8], "ZGIDAS01") or
        @as(usize, 156) + bytes[57] + bytes[58] + bytes[59] != bytes.len) return error.InvalidIdentityAssertion;
    const rp_end = 156 + @as(usize, bytes[57]);
    const origin_end = rp_end + bytes[58];
    const value = Assertion{
        .credential_id = get(u64, bytes[8..]),
        .owner_id = get(u64, bytes[16..]),
        .device_id = get(u64, bytes[24..]),
        .generation = get(u32, bytes[32..]),
        .counter = get(u64, bytes[36..]),
        .device_trust_generation = get(u32, bytes[44..]),
        .unlock_age_ticks = get(u64, bytes[48..]),
        .flags = bytes[56],
        .public_key = bytes[60..92].*,
        .signature = bytes[92..156].*,
        .relying_party_id = bytes[156..rp_end],
        .origin = bytes[rp_end..origin_end],
        .challenge = bytes[origin_end..],
    };
    try value.validate();
    return value;
}

fn put(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, out[0..@sizeOf(T)], value, .little);
}
fn get(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
}

test "identity assertion wire rejects truncated oversized and ambiguous payloads" {
    var buffer: [MAX_BYTES]u8 = undefined;
    const bytes = try encode(.{ .credential_id = 1, .owner_id = 2, .device_id = 3, .generation = 1, .counter = 9, .device_trust_generation = 1, .unlock_age_ticks = 20, .flags = 7, .public_key = @splat(4), .signature = @splat(5), .relying_party_id = "example.test", .origin = "https://example.test", .challenge = "challenge" }, &buffer);
    var copy: [MAX_BYTES]u8 = undefined;
    try std.testing.expectEqualSlices(u8, bytes, try encode(try decode(bytes), &copy));
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidIdentityAssertion, decode(bytes[0..len]));
    try std.testing.expectError(error.InvalidIdentityAssertion, decode(buffer[0 .. bytes.len + 1]));
    buffer[56] |= 0x80;
    try std.testing.expectError(error.InvalidIdentityAssertion, decode(bytes));
}
