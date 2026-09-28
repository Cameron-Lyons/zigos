//! Canonical, single-owner enrollment state inside an authenticated checkpoint.
//! Root pins come from the restore caller, never from this snapshot.
const std = @import("std");
const cursor = @import("binary_cursor");
const graph_mod = @import("device_graph.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const manifest = @import("../policy/manifest.zig");
const measured = @import("../platform/measured_boot.zig");

const signature_bytes = 1 + signing.PUBLIC_KEY_BYTES + signing.SIGNATURE_BYTES;
const text_bytes = 1 + graph_mod.MAX_LABEL_BYTES;
pub const MAX_BYTES = 2 + text_bytes + signature_bytes + graph_mod.MAX_DEVICES *
    (8 + text_bytes + 8 + 1 + 4 + 4 + 4 * signature_bytes + 16 + 2 + text_bytes + 73);
pub const Error = graph_mod.Error || error{ InvalidGraphSnapshot, GraphSnapshotTooLarge, GraphNotEmpty, RootPinRequired };
const Writer = cursor.Writer(Error, error.GraphSnapshotTooLarge);
const Reader = cursor.Reader(Error, error.InvalidGraphSnapshot);

pub fn empty(graph: *const graph_mod.Graph) bool {
    return graph.user_roots.countInUse() == 0 and graph.devices.countInUse() == 0;
}

// Untrusted enrollment metadata only. Self-consistency is not authority: the
// caller must independently authenticate the candidate before using this pin.
pub fn enrollmentCandidatePin(owner: principal.PrincipalId, bytes: []const u8) Error!?signing.PublicKey {
    var reader = Reader{ .buffer = bytes };
    const present = try reader.readByte();
    var pin: ?signing.PublicKey = null;
    if (present == 1) {
        var label: [graph_mod.MAX_LABEL_BYTES]u8 = undefined;
        _ = try readText(&reader, &label);
        const signature = try readSignature(&reader);
        if (!signature.isPresent()) return error.InvalidGraphSnapshot;
        pin = signature.public_key;
    }
    var candidate = graph_mod.Graph.init();
    try decode(&candidate, owner, pin, bytes);
    return pin;
}

pub fn encode(graph: ?*const graph_mod.Graph, owner: principal.PrincipalId, buffer: []u8) Error![]const u8 {
    var writer = Writer{ .buffer = buffer };
    if (graph == null or empty(graph.?)) {
        try writer.writeByte(0);
        return buffer[0..writer.offset];
    }
    const g = graph.?;
    if (g.user_roots.countInUse() != 1) return error.InvalidGraphSnapshot;
    const root = g.findUserRootConst(owner) orelse return error.InvalidGraphSnapshot;
    _ = try g.authenticatedRoot(owner, root.root_signature.public_key);
    try writer.writeByte(1);
    try writeText(&writer, root.labelSlice());
    try writeSignature(&writer, root.root_signature);
    try writer.writeByte(@intCast(g.devices.countInUse()));
    // Device serial order is independent of allocation history and indexes.
    var previous: u64 = 0;
    for (0..g.devices.countInUse()) |_| {
        var next: ?*const graph_mod.DeviceRecord = null;
        for (&g.devices.slots) |*slot| {
            if (!slot.in_use or slot.device.principal_id.serial <= previous) continue;
            if (next == null or slot.device.principal_id.serial < next.?.principal_id.serial) next = &slot.device;
        }
        const device = next orelse return error.InvalidGraphSnapshot;
        if (!device.owner.eql(owner)) return error.InvalidGraphSnapshot;
        _ = try g.authenticatedRecord(device.principal_id, root.root_signature.public_key);
        try writeDevice(&writer, device);
        previous = device.principal_id.serial;
    }
    return buffer[0..writer.offset];
}

// The destination is caller-owned scratch until this returns successfully.
// No pointer in a decoded graph refers to the input buffer.
pub fn decode(destination: *graph_mod.Graph, owner: principal.PrincipalId, root_pin: ?signing.PublicKey, bytes: []const u8) Error!void {
    if (!empty(destination)) return error.GraphNotEmpty;
    errdefer destination.* = .init();
    var reader = Reader{ .buffer = bytes };
    const present = try reader.readByte();
    if (present == 0) {
        if (!reader.eof()) return error.InvalidGraphSnapshot;
        return;
    }
    if (present != 1 or owner.kind != .user or owner.serial == 0) return error.InvalidGraphSnapshot;
    const pin = root_pin orelse return error.RootPinRequired;
    var root = graph_mod.UserRootRecord{ .principal_id = owner, .label_len = 0, .label = @splat(0) };
    root.label_len = try readText(&reader, &root.label);
    root.root_signature = try readSignature(&reader);
    _ = destination.installUserRootRecord(root) orelse return error.InvalidGraphSnapshot;
    const count = try reader.readByte();
    if (count > graph_mod.MAX_DEVICES) return error.InvalidGraphSnapshot;
    var previous: u64 = 0;
    for (0..count) |_| {
        const device = try readDevice(&reader, owner);
        if (device.principal_id.serial <= previous) return error.InvalidGraphSnapshot;
        previous = device.principal_id.serial;
        _ = destination.installDeviceRecord(device) orelse return error.InvalidGraphSnapshot;
    }
    if (!reader.eof()) return error.InvalidGraphSnapshot;
    _ = try destination.authenticatedRoot(owner, pin);
    for (&destination.devices.slots) |*slot| {
        if (slot.in_use) _ = try destination.authenticatedRecord(slot.device.principal_id, pin);
    }
}

fn writeText(writer: *Writer, text: []const u8) Error!void {
    if (text.len > graph_mod.MAX_LABEL_BYTES) return error.InvalidGraphSnapshot;
    try writer.writeByte(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readText(reader: *Reader, buffer: *[graph_mod.MAX_LABEL_BYTES]u8) Error!u8 {
    const len = try reader.readByte();
    if (len > buffer.len) return error.InvalidGraphSnapshot;
    @memset(buffer, 0);
    try reader.readBytes(buffer[0..len]);
    return len;
}

fn writeSignature(writer: *Writer, signature: manifest.Signature) Error!void {
    if (!signature.isPresent()) return writer.writeByte(0);
    if (signature.format != .ed25519 or signature.public_key_len != 32 or signature.value_len != 64) return error.InvalidGraphSnapshot;
    try writer.writeByte(1);
    try writer.writeBytes(&signature.public_key);
    try writer.writeBytes(&signature.value);
}

fn readSignature(reader: *Reader) Error!manifest.Signature {
    const present = try reader.readByte();
    if (present == 0) return .{};
    if (present != 1) return error.InvalidGraphSnapshot;
    var signature = manifest.Signature{ .format = .ed25519, .signer = "device-graph", .public_key_len = 32, .value_len = 64 };
    try reader.readBytes(&signature.public_key);
    try reader.readBytes(&signature.value);
    return signature;
}

fn writeDevice(writer: *Writer, device: *const graph_mod.DeviceRecord) Error!void {
    if (device.label_len > graph_mod.MAX_LABEL_BYTES or device.platform_key_label_len > graph_mod.MAX_LABEL_BYTES) return error.InvalidGraphSnapshot;
    try writer.writeU64(device.principal_id.serial);
    try writeText(writer, device.labelSlice());
    try writer.writeU64(device.overlay_id);
    try writer.writeByte(@intFromEnum(device.status));
    try writer.writeU32(device.trust_generation);
    try writer.writeU32(device.key_rotation_generation);
    try writeSignature(writer, device.device_signature);
    try writeSignature(writer, device.enrollment_signature);
    try writeSignature(writer, device.rotation_signature);
    try writeSignature(writer, device.revocation_signature);
    try writer.writeU64(device.last_rotated_at_ticks);
    try writer.writeU64(device.revoked_at_ticks);
    try writer.writeByte(@intFromEnum(device.device_key_origin));
    try writer.writeByte(@intFromBool(device.platform_key_bound));
    try writeText(writer, device.platformKeyLabelSlice());
    try writer.writeBytes(&device.platform_key_digest);
    try writer.writeU64(device.platform_root_generation);
    try writer.writeByte(@intFromEnum(device.platform_root_provenance));
    try writer.writeBytes(&device.platform_root_digest);
}

fn readDevice(reader: *Reader, owner: principal.PrincipalId) Error!graph_mod.DeviceRecord {
    var device = graph_mod.DeviceRecord{ .principal_id = .{ .kind = .device, .serial = try reader.readU64() }, .owner = owner, .label_len = 0, .label = @splat(0), .overlay_id = 0 };
    device.label_len = try readText(reader, &device.label);
    device.overlay_id = try reader.readU64();
    device.status = std.enums.fromInt(graph_mod.DeviceStatus, try reader.readByte()) orelse return error.InvalidGraphSnapshot;
    device.trust_generation = try reader.readU32();
    device.key_rotation_generation = try reader.readU32();
    device.device_signature = try readSignature(reader);
    device.enrollment_signature = try readSignature(reader);
    device.rotation_signature = try readSignature(reader);
    device.revocation_signature = try readSignature(reader);
    device.last_rotated_at_ticks = try reader.readU64();
    device.revoked_at_ticks = try reader.readU64();
    device.device_key_origin = std.enums.fromInt(graph_mod.DeviceKeyOrigin, try reader.readByte()) orelse return error.InvalidGraphSnapshot;
    const bound = try reader.readByte();
    if (bound > 1) return error.InvalidGraphSnapshot;
    device.platform_key_bound = bound == 1;
    device.platform_key_label_len = try readText(reader, &device.platform_key_label);
    try reader.readBytes(&device.platform_key_digest);
    device.platform_root_generation = try reader.readU64();
    device.platform_root_provenance = std.enums.fromInt(measured.RootProvenance, try reader.readByte()) orelse return error.InvalidGraphSnapshot;
    try reader.readBytes(&device.platform_root_digest);
    return device;
}
