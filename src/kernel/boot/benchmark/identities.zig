const principal = @import("../../../native/core/principal.zig");
const signing = @import("../../../native/core/signing.zig");

pub fn signer(label: []const u8, seed_byte: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = signing.seedFromByte(seed_byte),
    };
}

pub fn user(serial: u64) principal.PrincipalId {
    return .{ .kind = .user, .serial = serial };
}

pub fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

pub fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

pub fn device(serial: u64) principal.PrincipalId {
    return .{ .kind = .device, .serial = serial };
}

pub fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}
