//! Public enrollment, pinned independently of the disk that carries it. This
//! record carries no PIN verifier or administrator secret. Provisioning must
//! retain its digest through a separate trusted enrollment channel.
const std = @import("std");
const tpm = @import("../platform/tpm2_sealing.zig");
const pin = @import("../platform/tpm2_pin.zig");
const principal = @import("../core/principal.zig");
const wire = @import("../platform/tpm2_wire.zig");

pub const MAX_BYTES = 124 + pin.MAX_BYTES;

pub const Enrollment = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    capsule_digest: tpm.Key,
    parent: tpm.PersistentParent,
    catalog_object_id: u64,
    anchor_index: u32,
    catalog_secret_id: u64,
    device_secret_id: u64,

    pub fn validate(self: Enrollment) !void {
        try self.parent.validate();
        if (self.owner.kind != .user or self.owner.serial == 0 or self.device.kind != .device or self.device.serial == 0 or
            self.catalog_object_id == 0 or self.catalog_secret_id == 0 or self.device_secret_id == 0 or self.catalog_secret_id == self.device_secret_id or
            self.anchor_index < 0x0180_0000 or self.anchor_index > 0x0180_ffff or std.mem.allEqual(u8, &self.capsule_digest, 0)) return error.InvalidIdentityEnrollment;
    }
};

pub const Record = struct {
    enrollment: Enrollment,
    capsule: pin.Capsule,

    pub fn validate(self: *const Record) !void {
        try self.enrollment.validate();
        if (!self.capsule.owner.eql(self.enrollment.owner) or !self.capsule.device.eql(self.enrollment.device) or
            !std.crypto.timing_safe.eql(tpm.Key, try self.capsule.digest(), self.enrollment.capsule_digest)) return error.UntrustedPinCapsule;
    }

    pub fn encode(self: *const Record, out: *[MAX_BYTES]u8) ![]const u8 {
        @memset(out, 0);
        errdefer @memset(out, 0);
        try self.validate();
        const e = self.enrollment;
        var w = wire.Writer{ .bytes = out };
        try w.put("ZGIDEN01");
        try w.int(u64, e.owner.serial);
        try w.int(u64, e.device.serial);
        try w.put(&e.capsule_digest);
        try w.int(u32, e.parent.handle);
        try w.put(&e.parent.name);
        try w.int(u64, e.catalog_object_id);
        try w.int(u32, e.anchor_index);
        try w.int(u64, e.catalog_secret_id);
        try w.int(u64, e.device_secret_id);
        var capsule: [pin.MAX_BYTES]u8 = undefined;
        try w.sized(try self.capsule.encode(&capsule));
        return out[0..w.pos];
    }

    pub fn digest(self: *const Record) !tpm.Key {
        var bytes: [MAX_BYTES]u8 = undefined;
        return hash(try self.encode(&bytes));
    }

    pub fn decode(bytes: []const u8, trusted_digest: *const tpm.Key) !Record {
        if (bytes.len > MAX_BYTES or bytes.len < 124 or std.mem.allEqual(u8, trusted_digest, 0)) return error.InvalidIdentityEnrollment;
        if (!std.crypto.timing_safe.eql(tpm.Key, hash(bytes), trusted_digest.*)) return error.UntrustedIdentityEnrollment;
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGIDEN01")) return error.InvalidIdentityEnrollment;
        const owner = try r.int(u64);
        const device = try r.int(u64);
        const capsule_digest = (try r.take(32))[0..32].*;
        const handle = try r.int(u32);
        const name = (try r.take(34))[0..34].*;
        const object = try r.int(u64);
        const index = try r.int(u32);
        const catalog_key = try r.int(u64);
        const device_key = try r.int(u64);
        const result = Record{ .enrollment = .{
            .owner = .{ .kind = .user, .serial = owner },
            .device = .{ .kind = .device, .serial = device },
            .capsule_digest = capsule_digest,
            .parent = .{ .handle = handle, .name = name },
            .catalog_object_id = object,
            .anchor_index = index,
            .catalog_secret_id = catalog_key,
            .device_secret_id = device_key,
        }, .capsule = try pin.Capsule.decode(try r.sized(), &capsule_digest) };
        try r.end();
        try result.validate();
        return result;
    }
};

fn hash(bytes: []const u8) tpm.Key {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zigos:identity-enrollment:v1\x00");
    h.update(bytes);
    return h.finalResult();
}

test "identity enrollment requires an independent digest and canonical complete binding" {
    const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    const trusted = try record.digest();
    var bytes: [MAX_BYTES]u8 = undefined;
    const encoded = try record.encode(&bytes);
    try std.testing.expectEqualDeep(record, try Record.decode(encoded, &trusted));
    for (0..encoded.len) |i| {
        bytes[i] ^= 1;
        try std.testing.expectError(error.UntrustedIdentityEnrollment, Record.decode(encoded, &trusted));
        bytes[i] ^= 1;
    }
    for (0..encoded.len) |length| {
        if (Record.decode(encoded[0..length], &trusted)) |_| return error.AcceptedTruncatedEnrollment else |_| {}
    }
    try std.testing.expectError(error.UntrustedIdentityEnrollment, Record.decode(bytes[0 .. encoded.len + 1], &trusted));
    try std.testing.expectError(error.InvalidResponse, Record.decode(bytes[0 .. encoded.len + 1], &hash(bytes[0 .. encoded.len + 1])));
    var changed = record;
    changed.enrollment.parent.handle += 1;
    try std.testing.expect(!std.mem.eql(u8, &(try changed.digest()), &trusted));
    changed = record;
    changed.enrollment.owner.serial += 1;
    try std.testing.expectError(error.UntrustedPinCapsule, changed.digest());
    changed = record;
    changed.enrollment.catalog_secret_id = changed.enrollment.device_secret_id;
    try std.testing.expectError(error.InvalidIdentityEnrollment, changed.encode(&bytes));
    try std.testing.expect(std.mem.allEqual(u8, &bytes, 0));
}
