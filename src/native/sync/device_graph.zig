const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_USER_ROOTS: usize = 4;
pub const MAX_DEVICES: usize = 8;
pub const MAX_LABEL_BYTES: usize = 48;

pub const DeviceStatus = enum(u8) {
    trusted,
    revoked,
};

pub const UserRootRecord = struct {
    principal_id: principal.PrincipalId,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    root_signature: manifest.Signature = .{},

    pub fn labelSlice(self: *const UserRootRecord) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const DeviceRecord = struct {
    principal_id: principal.PrincipalId,
    owner: principal.PrincipalId,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    overlay_id: u64,
    status: DeviceStatus = .trusted,
    trust_generation: u32 = 1,
    key_rotation_generation: u32 = 1,
    device_signature: manifest.Signature = .{},
    enrollment_signature: manifest.Signature = .{},
    rotation_signature: manifest.Signature = .{},
    revocation_signature: manifest.Signature = .{},
    last_rotated_at_ticks: u64 = 0,
    revoked_at_ticks: u64 = 0,

    pub fn labelSlice(self: *const DeviceRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn isTrusted(self: *const DeviceRecord) bool {
        return self.status == .trusted;
    }
};

pub const Error = error{
    AlreadyRevoked,
    DeviceNotFound,
    DeviceTableFull,
    InvalidEnrollmentSignature,
    InvalidPrincipalKind,
    InvalidRootSignature,
    InvalidRotationSignature,
    InvalidDeviceSignature,
    LabelTooLong,
    RootNotFound,
    UserRootTableFull,
};

const UserRootSlot = struct {
    in_use: bool = false,
    root: UserRootRecord = zeroUserRoot(),
};

const DeviceSlot = struct {
    in_use: bool = false,
    device: DeviceRecord = zeroDevice(),
};

pub const Graph = struct {
    user_roots: [MAX_USER_ROOTS]UserRootSlot = [_]UserRootSlot{UserRootSlot{}} ** MAX_USER_ROOTS,
    devices: [MAX_DEVICES]DeviceSlot = [_]DeviceSlot{DeviceSlot{}} ** MAX_DEVICES,

    pub fn init() Graph {
        return .{};
    }

    pub fn reset(self: *Graph) void {
        for (&self.user_roots) |*slot| {
            slot.* = .{};
        }
        for (&self.devices) |*slot| {
            slot.* = .{};
        }
    }

    pub fn ensureUserRoot(
        self: *Graph,
        user_principal: principal.PrincipalId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*UserRootRecord {
        if (user_principal.kind != .user) return error.InvalidPrincipalKind;
        if (self.findUserRoot(user_principal)) |existing| return existing;

        const slot = self.allocateUserRoot() orelse return error.UserRootTableFull;
        slot.in_use = true;
        slot.root = zeroUserRoot();
        slot.root.principal_id = user_principal;
        slot.root.label_len = native_util.copyTextExact(&slot.root.label, label) catch return error.LabelTooLong;

        var message_buffer: [128]u8 = undefined;
        const message = rootMessage(&message_buffer, user_principal, label) catch return error.InvalidRootSignature;
        slot.root.root_signature = signing.sign(identity, message) catch return error.InvalidRootSignature;
        if (!signing.verify(slot.root.root_signature, message)) return error.InvalidRootSignature;

        return &slot.root;
    }

    pub fn enrollDevice(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        tick: u64,
    ) Error!*DeviceRecord {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = self.findUserRoot(user_principal) orelse return error.RootNotFound;

        if (self.findDevice(device_principal)) |existing| {
            if (existing.status == .revoked) return error.AlreadyRevoked;
            return existing;
        }

        const slot = self.allocateDevice() orelse return error.DeviceTableFull;
        const overlay_id = deriveOverlayId(device_principal, device_identity.label);
        slot.in_use = true;
        slot.device = zeroDevice();
        slot.device.principal_id = device_principal;
        slot.device.owner = user_principal;
        slot.device.label_len = native_util.copyTextExact(&slot.device.label, label) catch return error.LabelTooLong;
        slot.device.overlay_id = overlay_id;

        var device_message_buffer: [192]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            label,
            overlay_id,
            1,
        ) catch return error.InvalidDeviceSignature;
        slot.device.device_signature = signing.sign(device_identity, device_message) catch return error.InvalidDeviceSignature;
        if (!signing.verify(slot.device.device_signature, device_message)) return error.InvalidDeviceSignature;

        var enrollment_message_buffer: [256]u8 = undefined;
        const enrollment_message = enrollmentMessage(
            &enrollment_message_buffer,
            user_principal,
            device_principal,
            label,
            overlay_id,
            1,
            slot.device.device_signature.publicKeySlice(),
        ) catch return error.InvalidEnrollmentSignature;
        slot.device.enrollment_signature = signing.sign(authorizer, enrollment_message) catch return error.InvalidEnrollmentSignature;
        if (!signing.verify(slot.device.enrollment_signature, enrollment_message)) return error.InvalidEnrollmentSignature;

        slot.device.last_rotated_at_ticks = tick;
        return &slot.device;
    }

    pub fn rotateDeviceKey(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        tick: u64,
    ) Error!*DeviceRecord {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = self.findUserRoot(user_principal) orelse return error.RootNotFound;
        const record = self.findDevice(device_principal) orelse return error.DeviceNotFound;
        if (record.status == .revoked) return error.AlreadyRevoked;

        const next_generation = record.key_rotation_generation + 1;
        var device_message_buffer: [192]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            record.labelSlice(),
            record.overlay_id,
            next_generation,
        ) catch return error.InvalidDeviceSignature;
        const device_signature = signing.sign(next_device_identity, device_message) catch return error.InvalidDeviceSignature;
        if (!signing.verify(device_signature, device_message)) return error.InvalidDeviceSignature;

        var rotation_message_buffer: [256]u8 = undefined;
        const rotation_message = rotationMessage(
            &rotation_message_buffer,
            user_principal,
            device_principal,
            record.overlay_id,
            next_generation,
            device_signature.publicKeySlice(),
        ) catch return error.InvalidRotationSignature;
        const rotation_signature = signing.sign(authorizer, rotation_message) catch return error.InvalidRotationSignature;
        if (!signing.verify(rotation_signature, rotation_message)) return error.InvalidRotationSignature;

        record.device_signature = device_signature;
        record.rotation_signature = rotation_signature;
        record.key_rotation_generation = next_generation;
        record.last_rotated_at_ticks = tick;
        return record;
    }

    pub fn revokeDevice(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        tick: u64,
    ) Error!void {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = self.findUserRoot(user_principal) orelse return error.RootNotFound;
        const record = self.findDevice(device_principal) orelse return error.DeviceNotFound;
        if (record.status == .revoked) return error.AlreadyRevoked;

        var message_buffer: [160]u8 = undefined;
        const message = revocationMessage(
            &message_buffer,
            user_principal,
            device_principal,
            record.overlay_id,
            tick,
        ) catch return error.InvalidEnrollmentSignature;
        record.revocation_signature = signing.sign(authorizer, message) catch return error.InvalidEnrollmentSignature;
        if (!signing.verify(record.revocation_signature, message)) return error.InvalidEnrollmentSignature;

        record.status = .revoked;
        record.trust_generation += 1;
        record.revoked_at_ticks = tick;
    }

    pub fn findUserRoot(self: *Graph, user_principal: principal.PrincipalId) ?*UserRootRecord {
        for (&self.user_roots) |*slot| {
            if (slot.in_use and slot.root.principal_id.eql(user_principal)) return &slot.root;
        }
        return null;
    }

    pub fn findDevice(self: *Graph, device_principal: principal.PrincipalId) ?*DeviceRecord {
        for (&self.devices) |*slot| {
            if (slot.in_use and slot.device.principal_id.eql(device_principal)) return &slot.device;
        }
        return null;
    }

    pub fn findDeviceConst(self: *const Graph, device_principal: principal.PrincipalId) ?*const DeviceRecord {
        for (&self.devices) |*slot| {
            if (slot.in_use and slot.device.principal_id.eql(device_principal)) return &slot.device;
        }
        return null;
    }

    pub fn isTrusted(self: *const Graph, device_principal: principal.PrincipalId) bool {
        const record = self.findDeviceConst(device_principal) orelse return false;
        return record.isTrusted();
    }

    pub fn overlayIdFor(self: *const Graph, device_principal: principal.PrincipalId) ?u64 {
        const record = self.findDeviceConst(device_principal) orelse return null;
        if (!record.isTrusted()) return null;
        return record.overlay_id;
    }

    pub fn trustedDeviceCount(self: *const Graph) usize {
        var count: usize = 0;
        for (self.devices) |slot| {
            if (slot.in_use and slot.device.status == .trusted) count += 1;
        }
        return count;
    }

    fn allocateUserRoot(self: *Graph) ?*UserRootSlot {
        for (&self.user_roots) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }

    fn allocateDevice(self: *Graph) ?*DeviceSlot {
        for (&self.devices) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }
};

fn zeroUserRoot() UserRootRecord {
    return .{
        .principal_id = .{ .kind = .service, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .root_signature = .{},
    };
}

fn zeroDevice() DeviceRecord {
    return .{
        .principal_id = .{ .kind = .device, .serial = 0 },
        .owner = .{ .kind = .user, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .overlay_id = 0,
        .status = .trusted,
        .trust_generation = 1,
        .key_rotation_generation = 1,
        .device_signature = .{},
        .enrollment_signature = .{},
        .rotation_signature = .{},
        .revocation_signature = .{},
        .last_rotated_at_ticks = 0,
        .revoked_at_ticks = 0,
    };
}

fn rootMessage(
    buffer: []u8,
    user_principal: principal.PrincipalId,
    label: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buffer, "user-root:{d}:{s}", .{ user_principal.serial, label }) catch error.NoSpaceLeft;
}

fn deviceMessage(
    buffer: []u8,
    device_principal: principal.PrincipalId,
    label: []const u8,
    overlay_id: u64,
    rotation_generation: u32,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "device:{d}:{s}:{d}:{d}",
        .{ device_principal.serial, label, overlay_id, rotation_generation },
    ) catch error.NoSpaceLeft;
}

fn enrollmentMessage(
    buffer: []u8,
    user_principal: principal.PrincipalId,
    device_principal: principal.PrincipalId,
    label: []const u8,
    overlay_id: u64,
    generation: u32,
    device_public_key: []const u8,
) error{NoSpaceLeft}![]const u8 {
    const prefix = std.fmt.bufPrint(
        buffer,
        "enroll:{d}:{d}:{s}:{d}:{d}:",
        .{ user_principal.serial, device_principal.serial, label, overlay_id, generation },
    ) catch return error.NoSpaceLeft;
    return appendHex(buffer, prefix.len, device_public_key);
}

fn rotationMessage(
    buffer: []u8,
    user_principal: principal.PrincipalId,
    device_principal: principal.PrincipalId,
    overlay_id: u64,
    generation: u32,
    device_public_key: []const u8,
) error{NoSpaceLeft}![]const u8 {
    const prefix = std.fmt.bufPrint(
        buffer,
        "rotate:{d}:{d}:{d}:{d}:",
        .{ user_principal.serial, device_principal.serial, overlay_id, generation },
    ) catch return error.NoSpaceLeft;
    return appendHex(buffer, prefix.len, device_public_key);
}

fn revocationMessage(
    buffer: []u8,
    user_principal: principal.PrincipalId,
    device_principal: principal.PrincipalId,
    overlay_id: u64,
    tick: u64,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "revoke:{d}:{d}:{d}:{d}",
        .{ user_principal.serial, device_principal.serial, overlay_id, tick },
    ) catch error.NoSpaceLeft;
}

fn appendHex(buffer: []u8, offset: usize, bytes: []const u8) error{NoSpaceLeft}![]const u8 {
    if (offset + (bytes.len * 2) > buffer.len) return error.NoSpaceLeft;
    var cursor = offset;
    for (bytes) |byte| {
        const high = byte >> 4;
        const low = byte & 0x0F;
        buffer[cursor] = hexDigit(high);
        buffer[cursor + 1] = hexDigit(low);
        cursor += 2;
    }
    return buffer[0..cursor];
}

fn hexDigit(value: u8) u8 {
    return if (value < 10) '0' + value else 'a' + (value - 10);
}

fn deriveOverlayId(device_principal: principal.PrincipalId, label: []const u8) u64 {
    var hash = native_util.fnv1a64AppendByte(
        0xCBF29CE484222325,
        @as(u8, @intCast(@intFromEnum(device_principal.kind))),
    );
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, device_principal.serial);
    hash = native_util.fnv1a64WithSeed(hash, label);
    return hash;
}

test "device graph roots user principals and manages enrollment rotation and revocation" {
    var graph = Graph.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 11 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 12 };
    const user_identity = signing.SignerIdentity{
        .label = "zigos-user-root",
        .seed = [_]u8{0x41} ** 32,
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "laptop-device",
        .seed = [_]u8{0x42} ** 32,
    };
    const tablet_identity = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = [_]u8{0x43} ** 32,
    };
    const rotated_tablet_identity = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = [_]u8{0x44} ** 32,
    };

    const root = try graph.ensureUserRoot(user, "cameron", user_identity);
    try std.testing.expectEqualStrings("cameron", root.labelSlice());
    try std.testing.expect(root.root_signature.isComplete());

    const laptop_record = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 10);
    const tablet_record = try graph.enrollDevice(user, tablet, "tablet", user_identity, tablet_identity, 11);
    try std.testing.expect(laptop_record.isTrusted());
    try std.testing.expect(tablet_record.isTrusted());
    try std.testing.expectEqual(@as(usize, 2), graph.trustedDeviceCount());
    try std.testing.expect(graph.overlayIdFor(laptop) != null);

    const rotated = try graph.rotateDeviceKey(user, tablet, user_identity, rotated_tablet_identity, 20);
    try std.testing.expectEqual(@as(u32, 2), rotated.key_rotation_generation);
    try std.testing.expect(rotated.rotation_signature.isComplete());

    try graph.revokeDevice(user, tablet, user_identity, 30);
    try std.testing.expect(!graph.isTrusted(tablet));
    try std.testing.expectEqual(@as(usize, 1), graph.trustedDeviceCount());
    try std.testing.expectEqual(@as(?u64, null), graph.overlayIdFor(tablet));
    try std.testing.expectEqual(@as(u64, 30), graph.findDevice(tablet).?.revoked_at_ticks);
}
