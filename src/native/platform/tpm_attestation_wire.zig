//! Canonical, bounded v1 wire records. Keys, deadlines and verifier state are
//! never decoded from the network. The local enrollment validates a challenge.
const std = @import("std");
const cursor = @import("binary_cursor");
const attest = @import("tpm_attestation.zig");
const service = @import("attestation_service.zig");
pub const MAX_BYTES = 402;
const Error = error{InvalidAttestationWire};
const Writer = cursor.Writer(Error, error.InvalidAttestationWire);
const Reader = cursor.Reader(Error, error.InvalidAttestationWire);
const challenge_header = "ZGTA\x01\x01";
const response_header = "ZGTA\x01\x02";

pub fn encodeChallenge(out: []u8, challenge: *const attest.Challenge, enrollment: *const attest.Enrollment) ![]const u8 {
    errdefer @memset(out[0..@min(out.len, MAX_BYTES)], 0);
    try challenge.validate(enrollment);
    if (std.mem.allEqual(u8, &challenge.channel_binding, 0)) return error.InvalidAttestationWire;
    var w = Writer{ .buffer = out[0..@min(out.len, MAX_BYTES)] };
    try w.writeBytes(challenge_header);
    try w.writeBytes(&challenge.request.nonce);
    try w.writeBytes(&challenge.approved_pcr11);
    try w.writeBytes(&challenge.channel_binding);
    try w.writeBytes(&challenge.request.attestation_verifier_metadata_digest);
    for ([_][]const u8{ challenge.request.remotePartySlice(), challenge.request.policyLabelSlice(), challenge.request.rootKeyIdSlice() }) |text| {
        try w.writeByte(@intCast(text.len));
        try w.writeBytes(text);
    }
    try w.writeU64(challenge.request.minimum_root_generation);
    try w.writeByte(challenge.request.revoked_root_generation_count);
    for (challenge.request.revokedRootGenerationsSlice()) |generation| try w.writeU64(generation);
    return out[0..w.offset];
}

pub fn decodeChallenge(bytes: []const u8, enrollment: *const attest.Enrollment) !attest.Challenge {
    if (bytes.len > MAX_BYTES) return error.InvalidAttestationWire;
    var r = Reader{ .buffer = bytes };
    if (!std.mem.eql(u8, try r.readSlice(challenge_header.len), challenge_header)) return error.InvalidAttestationWire;
    var result = attest.Challenge{ .request = .{ .nonce_len = 32, .expected_key_origin = .tpm, .attestation_verifier_metadata_digest_required = true }, .approved_pcr11 = undefined };
    try r.readBytes(&result.request.nonce);
    try r.readBytes(&result.approved_pcr11);
    try r.readBytes(&result.channel_binding);
    try r.readBytes(&result.request.attestation_verifier_metadata_digest);
    inline for (.{ "remote_party", "policy_label", "root_key_id" }) |field| {
        const length = try r.readByte();
        if (length > @field(result.request, field).len) return error.InvalidAttestationWire;
        @field(result.request, field ++ "_len") = length;
        try r.readBytes(@field(result.request, field)[0..length]);
    }
    result.request.minimum_root_generation = try r.readU64();
    result.request.revoked_root_generation_count = try r.readByte();
    if (result.request.revoked_root_generation_count > service.MAX_REVOKED_ROOT_GENERATIONS) return error.InvalidAttestationWire;
    for (result.request.revoked_root_generations[0..result.request.revoked_root_generation_count]) |*generation| generation.* = try r.readU64();
    if (!r.eof() or std.mem.allEqual(u8, &result.channel_binding, 0)) return error.InvalidAttestationWire;
    try result.validate(enrollment);
    return result;
}

pub fn encodeResponse(out: []u8, response: *const attest.Response) ![]const u8 {
    errdefer @memset(out[0..@min(out.len, MAX_BYTES)], 0);
    if (response.len == 0 or response.len > response.bytes.len or !std.mem.allEqual(u8, response.bytes[response.len..], 0)) return error.InvalidAttestationWire;
    var w = Writer{ .buffer = out[0..@min(out.len, MAX_BYTES)] };
    try w.writeBytes(response_header);
    try w.writeU16(response.len);
    try w.writeBytes(response.bytes[0..response.len]);
    return out[0..w.offset];
}

pub fn decodeResponse(bytes: []const u8) !attest.Response {
    if (bytes.len > MAX_BYTES) return error.InvalidAttestationWire;
    var r = Reader{ .buffer = bytes };
    if (!std.mem.eql(u8, try r.readSlice(response_header.len), response_header)) return error.InvalidAttestationWire;
    var result = attest.Response{ .len = try r.readU16() };
    if (result.len == 0 or result.len > result.bytes.len) return error.InvalidAttestationWire;
    try r.readBytes(result.bytes[0..result.len]);
    if (!r.eof()) return error.InvalidAttestationWire;
    return result;
}

const Entropy = struct {
    pub fn random(_: *@This(), out: []u8) !void {
        @memset(out, 0x64);
    }
};

test "TPM wire challenge is canonical bounded and validated against local enrollment" {
    const quote = @import("tpm2_quote.zig");
    const fixture = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
    const text: [64]u8 = @splat('a');
    const enrollment = try attest.Enrollment.init(.{ .kind = .device, .serial = 22 }, fixture.identity, 9, &text);
    var entropy = Entropy{};
    var pending = try attest.Pending.init(&entropy, enrollment, @splat(2), .{
        .remote_party = &text,
        .policy_label = &text,
        .revoked_generations = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
    }, 100, 1000);
    try pending.bindChannel(@splat(3), 101);
    var bytes: [MAX_BYTES + 1]u8 = @splat(0xa5);
    const encoded = try encodeChallenge(&bytes, &pending.challenge, &enrollment);
    try std.testing.expectEqual(MAX_BYTES, encoded.len);
    try std.testing.expectEqualDeep(pending.challenge, try decodeChallenge(encoded, &enrollment));
    for (0..encoded.len) |length| {
        try std.testing.expectError(error.InvalidAttestationWire, decodeChallenge(encoded[0..length], &enrollment));
        var small: [MAX_BYTES]u8 = @splat(0xa5);
        try std.testing.expectError(error.InvalidAttestationWire, encodeChallenge(small[0..length], &pending.challenge, &enrollment));
        try std.testing.expect(std.mem.allEqual(u8, small[0..length], 0));
    }
    try std.testing.expectError(error.InvalidAttestationWire, decodeChallenge(&bytes, &enrollment));
    for ([_]usize{ 0, 4, 5, 134, 199, 264, 337 }) |offset| {
        var changed = bytes;
        changed[offset] = 0xff;
        try std.testing.expectError(error.InvalidAttestationWire, decodeChallenge(changed[0..encoded.len], &enrollment));
    }
    var changed_enrollment = enrollment;
    changed_enrollment.device.serial += 1;
    try std.testing.expectError(error.InvalidTpmChallenge, decodeChallenge(encoded, &changed_enrollment));
    pending.challenge.channel_binding = @splat(0);
    try std.testing.expectError(error.InvalidAttestationWire, encodeChallenge(&bytes, &pending.challenge, &enrollment));
    try std.testing.expect(std.mem.allEqual(u8, bytes[0..MAX_BYTES], 0));
}

test "TPM wire response rejects malformed lengths headers tails and truncation" {
    const quote = @import("tpm2_quote.zig");
    const fixture = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
    var bytes: [MAX_BYTES]u8 = @splat(0);
    const encoded = try encodeResponse(&bytes, &fixture.evidence);
    try std.testing.expectEqualDeep(fixture.evidence, try decodeResponse(encoded));
    for (0..encoded.len) |length| try std.testing.expectError(error.InvalidAttestationWire, decodeResponse(encoded[0..length]));
    try std.testing.expectError(error.InvalidAttestationWire, decodeResponse(bytes[0 .. encoded.len + 1]));
    for ([_]usize{ 0, 4, 5, 6, 7 }) |offset| {
        var changed = bytes;
        changed[offset] = 0xff;
        try std.testing.expectError(error.InvalidAttestationWire, decodeResponse(changed[0..encoded.len]));
    }
    var bad = fixture.evidence;
    bad.len = 0;
    try std.testing.expectError(error.InvalidAttestationWire, encodeResponse(&bytes, &bad));
    try std.testing.expect(std.mem.allEqual(u8, &bytes, 0));
    bad = fixture.evidence;
    bad.len -= 1;
    bad.bytes[bad.len] = 1;
    try std.testing.expectError(error.InvalidAttestationWire, encodeResponse(&bytes, &bad));
    bad.len = std.math.maxInt(u16);
    try std.testing.expectError(error.InvalidAttestationWire, encodeResponse(&bytes, &bad));
}
