const identity = @import("../platform/os_identity.zig");
pub const wire = @import("../../userspace/identity_assertion.zig");

// This reconstructs signed fields only. Callers must verify against the
// independently registered credential public key before trusting them.
pub fn decode(bytes: []const u8) !identity.Assertion {
    const value = try wire.decode(bytes);
    var assertion = identity.Assertion{
        .credential_id = value.credential_id,
        .owner = .{ .kind = .user, .serial = value.owner_id },
        .device = .{ .kind = .device, .serial = value.device_id },
        .credential_generation = value.generation,
        .assertion_counter = value.counter,
        .device_trust_generation = value.device_trust_generation,
        .unlock_age_ticks = value.unlock_age_ticks,
        .local_unlock_verified = value.flags & 1 != 0,
        .phishing_resistant = value.flags & 2 != 0,
        .hardware_backed_credential = value.flags & 4 != 0,
        .device_platform_backed = value.flags & 8 != 0,
        .primary_device_assertion = value.flags & 16 != 0,
        .relying_party_id_len = @intCast(value.relying_party_id.len),
        .relying_party_id = @splat(0),
        .origin_len = @intCast(value.origin.len),
        .origin = @splat(0),
        .challenge_len = @intCast(value.challenge.len),
        .challenge = @splat(0),
        .signature = .{ .public_key = value.public_key, .public_key_len = 32, .value = value.signature, .value_len = 64 },
    };
    @memcpy(assertion.relying_party_id[0..value.relying_party_id.len], value.relying_party_id);
    @memcpy(assertion.origin[0..value.origin.len], value.origin);
    @memcpy(assertion.challenge[0..value.challenge.len], value.challenge);
    return assertion;
}

pub fn encode(assertion: *const identity.Assertion, out: *[wire.MAX_BYTES]u8) ![]const u8 {
    if (assertion.owner.kind != .user or assertion.device.kind != .device or !assertion.signature.isComplete() or
        assertion.signature.format != .ed25519) return error.InvalidIdentityAssertion;
    return wire.encode(.{
        .credential_id = assertion.credential_id,
        .owner_id = assertion.owner.serial,
        .device_id = assertion.device.serial,
        .generation = assertion.credential_generation,
        .counter = assertion.assertion_counter,
        .device_trust_generation = assertion.device_trust_generation,
        .unlock_age_ticks = assertion.unlock_age_ticks,
        .flags = @as(u8, @intFromBool(assertion.local_unlock_verified)) | (@as(u8, @intFromBool(assertion.phishing_resistant)) << 1) |
            (@as(u8, @intFromBool(assertion.hardware_backed_credential)) << 2) | (@as(u8, @intFromBool(assertion.device_platform_backed)) << 3) |
            (@as(u8, @intFromBool(assertion.primary_device_assertion)) << 4),
        .relying_party_id = assertion.relyingPartySlice(),
        .origin = assertion.originSlice(),
        .challenge = assertion.challengeSlice(),
        .public_key = assertion.signature.public_key,
        .signature = assertion.signature.value,
    }, out);
}
