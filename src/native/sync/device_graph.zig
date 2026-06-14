const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const hex = @import("../core/hex.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

const addDeviceGraphMeasuredArtifact = measured_boot.addMeasuredArtifact;

pub const MAX_USER_ROOTS: usize = 4;
pub const MAX_DEVICES: usize = 8;
pub const MAX_LABEL_BYTES: usize = 48;
const ROOT_MESSAGE_BUFFER_BYTES: usize = 128;
const DEVICE_MESSAGE_BUFFER_BYTES: usize = 192;
const ENROLLMENT_MESSAGE_BUFFER_BYTES: usize = 256;
const ROTATION_MESSAGE_BUFFER_BYTES: usize = 256;
const REVOCATION_MESSAGE_BUFFER_BYTES: usize = 160;

pub const DeviceStatus = enum(u8) {
    trusted,
    revoked,
};

pub const DeviceKeyOrigin = enum(u8) {
    software,
    secure_enclave,
    tpm,
};

pub const PlatformDeviceRoot = struct {
    origin: DeviceKeyOrigin,
    device_principal: principal.PrincipalId,
    boot_generation: u64,
    root_provenance: measured_boot.RootProvenance,
    root_digest: crypto_hash.Digest,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,

    pub fn fromBootRecord(
        device_principal: principal.PrincipalId,
        origin: DeviceKeyOrigin,
        label: []const u8,
        boot: *const measured_boot.BootRecord,
    ) Error!PlatformDeviceRoot {
        if (device_principal.kind != .device) return error.InvalidPrincipalKind;
        if (!isPlatformBackedOrigin(origin)) return error.SoftwareDeviceKeyRejected;
        if (!boot.hasVerifiedRoot() or !boot.isInternallyConsistent()) return error.UnverifiedPlatformRoot;
        if (boot.root_provenance != .bootloader_provided) return error.SyntheticPlatformRoot;

        var root = PlatformDeviceRoot{
            .origin = origin,
            .device_principal = device_principal,
            .boot_generation = boot.generation,
            .root_provenance = boot.root_provenance,
            .root_digest = boot.root_digest,
            .label_len = 0,
            .label = [_]u8{0} ** MAX_LABEL_BYTES,
        };
        root.label_len = native_util.copyTextExact(&root.label, label) catch return error.LabelTooLong;
        return root;
    }

    pub fn labelSlice(self: *const PlatformDeviceRoot) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const PlatformKeyBindingRequest = struct {
    root: PlatformDeviceRoot,
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
    device_key_origin: DeviceKeyOrigin = .software,
    platform_key_bound: bool = false,
    platform_key_label_len: usize = 0,
    platform_key_label: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    platform_key_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    platform_root_generation: u64 = 0,
    platform_root_provenance: measured_boot.RootProvenance = .synthetic_host,
    platform_root_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn labelSlice(self: *const DeviceRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn platformKeyLabelSlice(self: *const DeviceRecord) []const u8 {
        return self.platform_key_label[0..self.platform_key_label_len];
    }

    pub fn isTrusted(self: *const DeviceRecord) bool {
        return self.status == .trusted;
    }

    pub fn usesPlatformBackedKey(self: *const DeviceRecord) bool {
        return self.platform_key_bound and isPlatformBackedOrigin(self.device_key_origin);
    }

    pub fn hasBootloaderBackedPlatformRoot(self: *const DeviceRecord) bool {
        return self.usesPlatformBackedKey() and
            self.platform_root_provenance == .bootloader_provided and
            self.platform_root_generation != 0 and
            !std.mem.allEqual(u8, &self.platform_root_digest, 0);
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
    InvalidPlatformKeyBinding,
    LabelTooLong,
    PlatformKeyDowngradeDenied,
    PlatformRootDeviceMismatch,
    RootNotFound,
    SoftwareDeviceKeyRejected,
    SyntheticPlatformRoot,
    UnverifiedPlatformRoot,
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
        var root = zeroUserRoot();
        root.principal_id = user_principal;
        root.label_len = native_util.copyTextExact(&root.label, label) catch return error.LabelTooLong;

        var message_buffer: [ROOT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = rootMessage(&message_buffer, user_principal, label) catch return error.InvalidRootSignature;
        root.root_signature = signing.sign(identity, message) catch return error.InvalidRootSignature;
        if (!signing.verify(root.root_signature, message)) return error.InvalidRootSignature;

        slot.in_use = true;
        slot.root = root;
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
        return self.enrollDeviceInternal(user_principal, device_principal, label, authorizer, device_identity, null, tick);
    }

    pub fn enrollPlatformBackedDevice(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        platform_key: PlatformKeyBindingRequest,
        tick: u64,
    ) Error!*DeviceRecord {
        return self.enrollDeviceInternal(user_principal, device_principal, label, authorizer, device_identity, platform_key, tick);
    }

    fn enrollDeviceInternal(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: signing.SignerIdentity,
        device_identity: signing.SignerIdentity,
        platform_key: ?PlatformKeyBindingRequest,
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
        var device = zeroDevice();
        device.principal_id = device_principal;
        device.owner = user_principal;
        device.label_len = native_util.copyTextExact(&device.label, label) catch return error.LabelTooLong;
        device.overlay_id = overlay_id;

        var device_message_buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            label,
            overlay_id,
            1,
        ) catch return error.InvalidDeviceSignature;
        device.device_signature = signing.sign(device_identity, device_message) catch return error.InvalidDeviceSignature;
        if (!signing.verify(device.device_signature, device_message)) return error.InvalidDeviceSignature;
        if (platform_key) |binding_request| {
            applyPlatformKeyBinding(&device, try buildPlatformKeyBinding(device_principal, device_identity, device.device_signature, binding_request));
        }

        var enrollment_message_buffer: [ENROLLMENT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const enrollment_message = enrollmentMessage(
            &enrollment_message_buffer,
            user_principal,
            device_principal,
            label,
            overlay_id,
            1,
            device.device_signature.publicKeySlice(),
        ) catch return error.InvalidEnrollmentSignature;
        device.enrollment_signature = signing.sign(authorizer, enrollment_message) catch return error.InvalidEnrollmentSignature;
        if (!signing.verify(device.enrollment_signature, enrollment_message)) return error.InvalidEnrollmentSignature;

        device.last_rotated_at_ticks = tick;
        slot.in_use = true;
        slot.device = device;
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
        return self.rotateDeviceKeyInternal(user_principal, device_principal, authorizer, next_device_identity, null, tick);
    }

    pub fn rotatePlatformBackedDeviceKey(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        platform_key: PlatformKeyBindingRequest,
        tick: u64,
    ) Error!*DeviceRecord {
        return self.rotateDeviceKeyInternal(user_principal, device_principal, authorizer, next_device_identity, platform_key, tick);
    }

    fn rotateDeviceKeyInternal(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: signing.SignerIdentity,
        next_device_identity: signing.SignerIdentity,
        platform_key: ?PlatformKeyBindingRequest,
        tick: u64,
    ) Error!*DeviceRecord {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = self.findUserRoot(user_principal) orelse return error.RootNotFound;
        const record = self.findDevice(device_principal) orelse return error.DeviceNotFound;
        if (record.status == .revoked) return error.AlreadyRevoked;
        if (record.usesPlatformBackedKey() and platform_key == null) return error.PlatformKeyDowngradeDenied;

        const next_generation = record.key_rotation_generation + 1;
        var device_message_buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            record.labelSlice(),
            record.overlay_id,
            next_generation,
        ) catch return error.InvalidDeviceSignature;
        const device_signature = signing.sign(next_device_identity, device_message) catch return error.InvalidDeviceSignature;
        if (!signing.verify(device_signature, device_message)) return error.InvalidDeviceSignature;
        const next_platform_key = if (platform_key) |binding_request|
            try buildPlatformKeyBinding(device_principal, next_device_identity, device_signature, binding_request)
        else
            null;

        var rotation_message_buffer: [ROTATION_MESSAGE_BUFFER_BYTES]u8 = undefined;
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
        if (next_platform_key) |binding| {
            applyPlatformKeyBinding(record, binding);
        } else {
            clearPlatformKeyBinding(record);
        }
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

        var message_buffer: [REVOCATION_MESSAGE_BUFFER_BYTES]u8 = undefined;
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
        .device_key_origin = .software,
        .platform_key_bound = false,
        .platform_key_label_len = 0,
        .platform_key_label = [_]u8{0} ** MAX_LABEL_BYTES,
        .platform_key_digest = crypto_hash.zero_digest,
        .platform_root_generation = 0,
        .platform_root_provenance = .synthetic_host,
        .platform_root_digest = crypto_hash.zero_digest,
    };
}

const ResolvedPlatformKeyBinding = struct {
    origin: DeviceKeyOrigin,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    digest: crypto_hash.Digest,
    root_generation: u64,
    root_provenance: measured_boot.RootProvenance,
    root_digest: crypto_hash.Digest,
};

fn buildPlatformKeyBinding(
    device_principal: principal.PrincipalId,
    device_identity: signing.SignerIdentity,
    device_signature: manifest.Signature,
    request: PlatformKeyBindingRequest,
) Error!ResolvedPlatformKeyBinding {
    if (!isPlatformBackedOrigin(request.root.origin)) return error.SoftwareDeviceKeyRejected;
    if (!request.root.device_principal.eql(device_principal)) return error.PlatformRootDeviceMismatch;
    if (request.root.root_provenance != .bootloader_provided) return error.SyntheticPlatformRoot;
    if (std.mem.allEqual(u8, &request.root.root_digest, 0)) return error.UnverifiedPlatformRoot;
    const public_key = signing.publicKey(device_identity) catch return error.InvalidPlatformKeyBinding;
    if (!std.mem.eql(u8, device_signature.publicKeySlice(), &public_key)) return error.InvalidPlatformKeyBinding;
    const sealed_digest = platformRootSealDigest(device_principal, &request.root, &public_key, device_signature.valueSlice());

    var binding = ResolvedPlatformKeyBinding{
        .origin = request.root.origin,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .digest = platformKeyBindingDigest(device_principal, request.root.origin, request.root.labelSlice(), &public_key, &sealed_digest),
        .root_generation = request.root.boot_generation,
        .root_provenance = request.root.root_provenance,
        .root_digest = request.root.root_digest,
    };
    binding.label_len = native_util.copyTextExact(&binding.label, request.root.labelSlice()) catch return error.LabelTooLong;
    return binding;
}

fn applyPlatformKeyBinding(record: *DeviceRecord, binding: ResolvedPlatformKeyBinding) void {
    record.device_key_origin = binding.origin;
    record.platform_key_bound = true;
    record.platform_key_label_len = binding.label_len;
    record.platform_key_label = binding.label;
    record.platform_key_digest = binding.digest;
    record.platform_root_generation = binding.root_generation;
    record.platform_root_provenance = binding.root_provenance;
    record.platform_root_digest = binding.root_digest;
}

fn clearPlatformKeyBinding(record: *DeviceRecord) void {
    record.device_key_origin = .software;
    record.platform_key_bound = false;
    record.platform_key_label_len = 0;
    @memset(&record.platform_key_label, 0);
    @memset(&record.platform_key_digest, 0);
    record.platform_root_generation = 0;
    record.platform_root_provenance = .synthetic_host;
    @memset(&record.platform_root_digest, 0);
}

fn isPlatformBackedOrigin(origin: DeviceKeyOrigin) bool {
    return origin != .software;
}

fn platformKeyBindingDigest(
    device_principal: principal.PrincipalId,
    origin: DeviceKeyOrigin,
    label: []const u8,
    public_key: []const u8,
    sealed_digest: *const crypto_hash.Digest,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "device-kind", device_principal.kind);
    crypto_hash.updateInt(&hasher, "device-serial", device_principal.serial);
    crypto_hash.updateEnum(&hasher, "device-key-origin", origin);
    crypto_hash.updateBytes(&hasher, "binding-label", label);
    crypto_hash.updateBytes(&hasher, "device-public-key", public_key);
    crypto_hash.updateBytes(&hasher, "sealed-key-digest", sealed_digest);
    return crypto_hash.finalize(&hasher);
}

fn platformRootSealDigest(
    device_principal: principal.PrincipalId,
    root: *const PlatformDeviceRoot,
    public_key: []const u8,
    device_signature: []const u8,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "device-kind", device_principal.kind);
    crypto_hash.updateInt(&hasher, "device-serial", device_principal.serial);
    crypto_hash.updateEnum(&hasher, "device-key-origin", root.origin);
    crypto_hash.updateBytes(&hasher, "platform-root-label", root.labelSlice());
    crypto_hash.updateInt(&hasher, "boot-generation", root.boot_generation);
    crypto_hash.updateEnum(&hasher, "boot-root-provenance", root.root_provenance);
    crypto_hash.updateBytes(&hasher, "boot-root-digest", &root.root_digest);
    crypto_hash.updateBytes(&hasher, "device-public-key", public_key);
    crypto_hash.updateBytes(&hasher, "device-signature", device_signature);
    return crypto_hash.finalize(&hasher);
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
    const encoded = hex.encodeLower(bytes, buffer[offset..]) catch return error.NoSpaceLeft;
    return buffer[0 .. offset + encoded.len];
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
        .seed = signing.seedFromByte(0x41),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "laptop-device",
        .seed = signing.seedFromByte(0x42),
    };
    const tablet_identity = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = signing.seedFromByte(0x43),
    };
    const rotated_tablet_identity = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = signing.seedFromByte(0x44),
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

test "device graph binds platform-backed device keys and rejects synthetic downgrade" {
    var graph = Graph.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 101 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 111 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 112 };
    const user_identity = signing.SignerIdentity{
        .label = "platform-user-root",
        .seed = signing.seedFromByte(0x61),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "laptop-platform-key",
        .seed = signing.seedFromByte(0x62),
    };
    const rotated_laptop_identity = signing.SignerIdentity{
        .label = "laptop-platform-key-v2",
        .seed = signing.seedFromByte(0x63),
    };
    const boot = try verifiedDeviceGraphBoot(61, .bootloader_provided);
    const rotated_boot = try verifiedDeviceGraphBoot(62, .bootloader_provided);
    const emulator_boot = try verifiedDeviceGraphBoot(63, .emulator_provided);
    const unverified_boot = unverifiedDeviceGraphBoot(64);

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    try std.testing.expectError(error.SoftwareDeviceKeyRejected, PlatformDeviceRoot.fromBootRecord(phone, .software, "phone-key", &boot));
    try std.testing.expectError(error.SyntheticPlatformRoot, PlatformDeviceRoot.fromBootRecord(phone, .secure_enclave, "phone-key", &emulator_boot));
    try std.testing.expectError(error.UnverifiedPlatformRoot, PlatformDeviceRoot.fromBootRecord(phone, .secure_enclave, "phone-key", &unverified_boot));

    const laptop_root = try PlatformDeviceRoot.fromBootRecord(laptop, .secure_enclave, "laptop-bootloader-key", &boot);
    const phone_root = try PlatformDeviceRoot.fromBootRecord(phone, .secure_enclave, "phone-bootloader-key", &boot);
    try std.testing.expectError(error.PlatformRootDeviceMismatch, graph.enrollPlatformBackedDevice(user, laptop, "laptop", user_identity, laptop_identity, .{
        .root = phone_root,
    }, 19));

    const laptop_record = try graph.enrollPlatformBackedDevice(user, laptop, "laptop", user_identity, laptop_identity, .{
        .root = laptop_root,
    }, 20);
    try std.testing.expect(laptop_record.usesPlatformBackedKey());
    try std.testing.expect(laptop_record.hasBootloaderBackedPlatformRoot());
    try std.testing.expectEqual(DeviceKeyOrigin.secure_enclave, laptop_record.device_key_origin);
    try std.testing.expectEqualStrings("laptop-bootloader-key", laptop_record.platformKeyLabelSlice());
    try std.testing.expectEqual(measured_boot.RootProvenance.bootloader_provided, laptop_record.platform_root_provenance);
    try std.testing.expectEqual(@as(u64, 61), laptop_record.platform_root_generation);
    try std.testing.expectEqualSlices(u8, boot.root_digest[0..], laptop_record.platform_root_digest[0..]);
    const first_digest = laptop_record.platform_key_digest;

    try std.testing.expectError(error.PlatformKeyDowngradeDenied, graph.rotateDeviceKey(user, laptop, user_identity, rotated_laptop_identity, 30));
    const rotated_root = try PlatformDeviceRoot.fromBootRecord(laptop, .tpm, "laptop-tpm-key", &rotated_boot);
    const rotated = try graph.rotatePlatformBackedDeviceKey(user, laptop, user_identity, rotated_laptop_identity, .{
        .root = rotated_root,
    }, 40);
    try std.testing.expect(rotated.usesPlatformBackedKey());
    try std.testing.expect(rotated.hasBootloaderBackedPlatformRoot());
    try std.testing.expectEqual(DeviceKeyOrigin.tpm, rotated.device_key_origin);
    try std.testing.expectEqualStrings("laptop-tpm-key", rotated.platformKeyLabelSlice());
    try std.testing.expectEqual(@as(u64, 62), rotated.platform_root_generation);
    try std.testing.expectEqualSlices(u8, rotated_boot.root_digest[0..], rotated.platform_root_digest[0..]);
    try std.testing.expect(!std.mem.eql(u8, first_digest[0..], rotated.platform_key_digest[0..]));
    try std.testing.expectEqual(@as(u32, 2), rotated.key_rotation_generation);
}

fn verifiedDeviceGraphBoot(generation: u64, provenance: measured_boot.RootProvenance) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos", "kernel=device-graph");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-device-graph", "image=device-graph");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "sync", "healthy");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .policy, "device-graph-policy", "strict");
    try addDeviceGraphMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "device-graph-drivers", "drivers");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, provenance);
    return boot;
}

fn unverifiedDeviceGraphBoot(generation: u64) measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(generation);
    recorder.add(.kernel, "kernel-zigos", "kernel=device-graph") catch unreachable;
    recorder.add(.base_image, "stable-device-graph", "image=device-graph") catch unreachable;
    recorder.add(.critical_service, "policy", "healthy") catch unreachable;
    recorder.add(.critical_service, "storage", "healthy") catch unreachable;
    recorder.add(.critical_service, "sync", "healthy") catch unreachable;
    recorder.add(.critical_service, "network", "healthy") catch unreachable;
    recorder.add(.policy, "device-graph-policy", "strict") catch unreachable;
    recorder.add(.driver_set, "device-graph-drivers", "drivers") catch unreachable;
    return recorder.finalize();
}
