//! Public enrollment exchange. Publications require an independently supplied
//! root pin and preserve every locally known device and revocation. Transport,
//! user approval and rollback-resistant pin storage belong to the caller.
const std = @import("std");
const cursor = @import("binary_cursor");
const graph = @import("device_graph.zig");
const snapshot = @import("device_graph_snapshot.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const sealed = @import("../services/sealed_signing_key.zig");
const manifest = @import("../policy/manifest.zig");

pub const MAX_PROPOSAL_BYTES = 5 + 16 + 1 + graph.MAX_LABEL_BYTES + 8 + 32 + 32 + 64 + 64;
pub const MAX_PUBLICATION_BYTES = 5 + 8 + 2 + snapshot.MAX_BYTES + 64;
pub const Error = snapshot.Error || error{ InvalidEnrollment, EnrollmentTooLarge, EnrollmentRollback };
const Writer = cursor.Writer(Error, error.EnrollmentTooLarge);
const Reader = cursor.Reader(Error, error.InvalidEnrollment);

comptime {
    if (MAX_PROPOSAL_BYTES > 270 or MAX_PUBLICATION_BYTES > 5043 or @sizeOf(graph.EnrollmentProposal) > 384)
        @compileError("public enrollment exceeds its bounded exchange state");
}

pub fn encodeProposal(proposal: *const graph.EnrollmentProposal, buffer: []u8) Error![]const u8 {
    try proposal.validate();
    var writer = Writer{ .buffer = buffer };
    try writer.writeBytes("ZGER1");
    try writer.writeU64(proposal.owner.serial);
    try writer.writeU64(proposal.device.serial);
    try writer.writeByte(proposal.label_len);
    try writer.writeBytes(proposal.label[0..proposal.label_len]);
    try writer.writeU64(proposal.overlay_id);
    try writer.writeBytes(&proposal.root_pin);
    try writer.writeBytes(&proposal.device_signature.public_key);
    try writer.writeBytes(&proposal.device_signature.value);
    try writer.writeBytes(&proposal.consent_signature.value);
    return buffer[0..writer.offset];
}

pub fn decodeProposal(bytes: []const u8) Error!graph.EnrollmentProposal {
    if (bytes.len > MAX_PROPOSAL_BYTES) return error.InvalidEnrollment;
    var reader = Reader{ .buffer = bytes };
    if (!std.mem.eql(u8, try reader.readSlice(5), "ZGER1")) return error.InvalidEnrollment;
    var proposal = graph.EnrollmentProposal{
        .owner = .{ .kind = .user, .serial = try reader.readU64() },
        .device = .{ .kind = .device, .serial = try reader.readU64() },
        .label_len = try reader.readByte(),
        .label = @splat(0),
        .overlay_id = 0,
        .root_pin = undefined,
        .device_signature = signature(),
        .consent_signature = signature(),
    };
    if (proposal.label_len > graph.MAX_LABEL_BYTES) return error.InvalidEnrollment;
    try reader.readBytes(proposal.label[0..proposal.label_len]);
    proposal.overlay_id = try reader.readU64();
    try reader.readBytes(&proposal.root_pin);
    try reader.readBytes(&proposal.device_signature.public_key);
    try reader.readBytes(&proposal.device_signature.value);
    proposal.consent_signature.public_key = proposal.device_signature.public_key;
    try reader.readBytes(&proposal.consent_signature.value);
    if (!reader.eof()) return error.InvalidEnrollment;
    try proposal.validate();
    return proposal;
}

pub fn publish(devices: *const graph.Graph, owner: principal.PrincipalId, root_key: sealed.Key, now: u64, buffer: []u8) Error![]const u8 {
    try root_key.validate(now);
    if (!root_key.authority.?.owner.eql(owner)) return error.SecretOwnerMismatch;
    const pin = try root_key.publicKey(now);
    _ = try devices.authenticatedRoot(owner, pin);
    var writer = Writer{ .buffer = buffer };
    try writer.writeBytes("ZGEP1");
    try writer.writeU64(owner.serial);
    const size_offset = writer.offset;
    try writer.writeU16(0);
    const payload = try snapshot.encode(devices, owner, buffer[writer.offset..]);
    writer.offset += payload.len;
    std.mem.writeInt(u16, buffer[size_offset..][0..2], @intCast(payload.len), .little);
    const signed = try root_key.signMessage(&publicationDigest(buffer[0..writer.offset]), now);
    try writer.writeBytes(&signed.value);
    return buffer[0..writer.offset];
}

pub fn readPublication(destination: *graph.Graph, owner: principal.PrincipalId, pin: signing.PublicKey, bytes: []const u8) Error!void {
    if (!snapshot.empty(destination)) return error.GraphNotEmpty;
    if (bytes.len > MAX_PUBLICATION_BYTES or bytes.len < 15 + 64) return error.InvalidEnrollment;
    var reader = Reader{ .buffer = bytes };
    if (!std.mem.eql(u8, try reader.readSlice(5), "ZGEP1") or owner.kind != .user or owner.serial == 0 or try reader.readU64() != owner.serial) return error.InvalidEnrollment;
    const payload = try reader.readSlice(try reader.readU16());
    const signed_length = reader.offset;
    var signed = signature();
    signed.public_key = pin;
    try reader.readBytes(&signed.value);
    if (!reader.eof() or !signing.verify(signed, &publicationDigest(bytes[0..signed_length]))) return error.InvalidEnrollment;
    try snapshot.decode(destination, owner, pin, payload);
}

// Signed publications are not permission to forget an observed revocation or
// return to an older key. No destination state changes during this check.
pub fn requireExtension(current: *const graph.Graph, next: *const graph.Graph, owner: principal.PrincipalId, pin: signing.PublicKey) Error!bool {
    _ = try next.authenticatedRoot(owner, pin);
    if (next.user_roots.countInUse() != 1) return error.EnrollmentRollback;
    if (snapshot.empty(current)) return true;
    if (current.user_roots.countInUse() != 1) return error.EnrollmentRollback;
    const old_root = try current.authenticatedRoot(owner, pin);
    const new_root = try next.authenticatedRoot(owner, pin);
    if (!std.mem.eql(u8, old_root.labelSlice(), new_root.labelSlice())) return error.EnrollmentRollback;
    var changed = current.devices.countInUse() != next.devices.countInUse();
    for (current.devices.slots) |slot| {
        if (!slot.in_use) continue;
        const old = try current.authenticatedRecord(slot.device.principal_id, pin);
        if (!old.owner.eql(owner)) return error.EnrollmentRollback;
        const new = next.findDeviceConst(old.principal_id) orelse return error.EnrollmentRollback;
        _ = try next.authenticatedRecord(new.principal_id, pin);
        if (!new.owner.eql(old.owner) or new.overlay_id != old.overlay_id or !std.mem.eql(u8, old.labelSlice(), new.labelSlice()) or
            new.key_rotation_generation < old.key_rotation_generation or new.trust_generation < old.trust_generation) return error.EnrollmentRollback;
        if (old.usesPlatformBackedKey() and !new.usesPlatformBackedKey()) return error.PlatformKeyDowngradeDenied;
        if (new.key_rotation_generation != old.key_rotation_generation or new.trust_generation != old.trust_generation) changed = true;
        if (old.status == .revoked and !sameRecord(old.*, new.*)) return error.EnrollmentRollback;
        if (new.key_rotation_generation == old.key_rotation_generation) {
            var normalized = new.*;
            if (old.status == .trusted and new.status == .revoked) {
                normalized.status = old.status;
                normalized.trust_generation = old.trust_generation;
                normalized.revocation_signature = old.revocation_signature;
                normalized.revoked_at_ticks = old.revoked_at_ticks;
            }
            if (!sameRecord(old.*, normalized)) return error.EnrollmentRollback;
        }
    }
    return changed;
}

fn sameRecord(a: graph.DeviceRecord, b: graph.DeviceRecord) bool {
    var left = a;
    var right = b;
    inline for (.{ "device_signature", "enrollment_signature", "rotation_signature", "revocation_signature" }) |field| {
        @field(left, field).signer = "";
        @field(right, field).signer = "";
    }
    return std.meta.eql(left, right);
}

fn signature() manifest.Signature {
    return .{ .format = .ed25519, .signer = "device-graph", .public_key_len = 32, .value_len = 64 };
}

fn publicationDigest(bytes: []const u8) crypto_hash.Digest {
    var hash = crypto_hash.init();
    crypto_hash.updateBytes(&hash, "zigos.device-publication.v1", bytes);
    return crypto_hash.finalize(&hash);
}
