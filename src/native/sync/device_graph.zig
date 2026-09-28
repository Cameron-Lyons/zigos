const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const hex = @import("../core/hex.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sealed = @import("../services/sealed_signing_key.zig");

const addDeviceGraphMeasuredArtifact = measured_boot.addMeasuredArtifact;

pub const MAX_USER_ROOTS: usize = 4;
pub const MAX_DEVICES: usize = 8;
pub const MAX_LABEL_BYTES: usize = 48;
pub const COMPACT_IDENTITY_METADATA = true;
pub const PLATFORM_DEVICE_ROOT_SIZE_CEILING_BYTES: usize = 112;
pub const USER_ROOT_RECORD_SIZE_CEILING_BYTES: usize = 192;
pub const DEVICE_RECORD_SIZE_CEILING_BYTES: usize = 720;
pub const GRAPH_SIZE_CEILING_BYTES: usize = 7_040;
const ROOT_MESSAGE_BUFFER_BYTES: usize = 128;
const DEVICE_MESSAGE_BUFFER_BYTES: usize = 192;
const ENROLLMENT_MESSAGE_BUFFER_BYTES: usize = 256;
const ROTATION_MESSAGE_BUFFER_BYTES: usize = 256;
const REVOCATION_MESSAGE_BUFFER_BYTES: usize = 160;

comptime {
    if (MAX_USER_ROOTS > std.math.maxInt(u8) or
        MAX_DEVICES > std.math.maxInt(u8) or
        MAX_LABEL_BYTES > std.math.maxInt(u8))
    {
        @compileError("device graph metadata no longer fits compact counters");
    }
}

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
    label_len: u8,
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
        root.label_len = @intCast(native_util.copyTextExact(&root.label, label) catch return error.LabelTooLong);
        return root;
    }

    pub fn labelSlice(self: *const PlatformDeviceRoot) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    comptime {
        if (@sizeOf(@This()) > PLATFORM_DEVICE_ROOT_SIZE_CEILING_BYTES) {
            @compileError("platform device root exceeds its compact size ceiling");
        }
    }
};

pub const PlatformKeyBindingRequest = struct {
    root: PlatformDeviceRoot,
};

// Public proof of possession and consent to this owner's independently pinned
// root. Approval still requires that root's local sealed signing authority.
pub const EnrollmentProposal = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    overlay_id: u64,
    root_pin: signing.PublicKey,
    device_signature: manifest.Signature,
    consent_signature: manifest.Signature,

    pub fn create(owner: principal.PrincipalId, device: principal.PrincipalId, label: []const u8, root_pin: signing.PublicKey, key: sealed.Key, now: u64) Error!EnrollmentProposal {
        try requireSealedOwner(key, owner, now);
        if (owner.kind != .user or owner.serial == 0 or device.kind != .device or device.serial == 0) return error.InvalidPrincipalKind;
        var result = EnrollmentProposal{ .owner = owner, .device = device, .label_len = 0, .label = @splat(0), .overlay_id = deriveOverlayId(device, try key.label(now)), .root_pin = root_pin, .device_signature = .{}, .consent_signature = .{} };
        result.label_len = @intCast(native_util.copyTextExact(&result.label, label) catch return error.LabelTooLong);
        var buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        result.device_signature = try signIdentity(key, deviceMessage(&buffer, device, label, result.overlay_id, 1) catch return error.InvalidDeviceSignature, now);
        result.consent_signature = try signIdentity(key, &result.consentDigest(), now);
        return result;
    }

    pub fn validate(self: *const EnrollmentProposal) Error!void {
        if (self.owner.kind != .user or self.owner.serial == 0 or self.device.kind != .device or self.device.serial == 0) return error.InvalidPrincipalKind;
        if (self.label_len > MAX_LABEL_BYTES or self.overlay_id == 0) return error.InvalidDeviceSignature;
        var buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = deviceMessage(&buffer, self.device, self.label[0..self.label_len], self.overlay_id, 1) catch return error.InvalidDeviceSignature;
        if (!verifyPinnedSignature(self.device_signature, message, self.device_signature.public_key) or
            !verifyPinnedSignature(self.consent_signature, &self.consentDigest(), self.device_signature.public_key)) return error.InvalidDeviceSignature;
    }

    fn consentDigest(self: *const EnrollmentProposal) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        crypto_hash.updateBytes(&hasher, "protocol", "zigos.device-enrollment.v1");
        crypto_hash.updateInt(&hasher, "owner", self.owner.serial);
        crypto_hash.updateInt(&hasher, "device", self.device.serial);
        crypto_hash.updateBytes(&hasher, "root-pin", &self.root_pin);
        crypto_hash.updateBytes(&hasher, "label", self.label[0..self.label_len]);
        crypto_hash.updateInt(&hasher, "overlay", self.overlay_id);
        crypto_hash.updateBytes(&hasher, "device-key", &self.device_signature.public_key);
        crypto_hash.updateBytes(&hasher, "device-signature", &self.device_signature.value);
        return crypto_hash.finalize(&hasher);
    }
};

// Continuity from the current device key, plus possession of its successor.
// The owner still approves the change with the independently pinned root key.
pub const RotationProposal = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    overlay_id: u64,
    previous_generation: u32,
    root_pin: signing.PublicKey,
    previous_key: signing.PublicKey,
    device_signature: manifest.Signature,
    consent_signature: manifest.Signature,

    pub fn create(devices: *const Graph, device: principal.PrincipalId, pin: signing.PublicKey, current_key: sealed.Key, next_key: sealed.Key, now: u64) Error!RotationProposal {
        const record = try devices.authenticatedDevice(device, pin);
        if (record.usesPlatformBackedKey()) return error.PlatformKeyDowngradeDenied;
        try requireSealedOwner(current_key, record.owner, now);
        try requireSealedOwner(next_key, record.owner, now);
        const current_public = try current_key.publicKey(now);
        if (!std.mem.eql(u8, &current_public, &record.device_signature.public_key)) return error.InvalidRotationSignature;
        const next_generation = std.math.add(u32, record.key_rotation_generation, 1) catch return error.DeviceGenerationExhausted;
        var result = RotationProposal{ .owner = record.owner, .device = device, .label_len = record.label_len, .label = record.label, .overlay_id = record.overlay_id, .previous_generation = record.key_rotation_generation, .root_pin = pin, .previous_key = current_public, .device_signature = .{}, .consent_signature = .{} };
        var buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        result.device_signature = try signIdentity(next_key, deviceMessage(&buffer, device, record.labelSlice(), record.overlay_id, next_generation) catch return error.InvalidDeviceSignature, now);
        if (std.mem.eql(u8, &result.previous_key, &result.device_signature.public_key)) return error.DeviceEnrollmentMismatch;
        result.consent_signature = try signIdentity(current_key, &result.consentDigest(), now);
        return result;
    }

    pub fn validate(self: *const RotationProposal) Error!void {
        if (self.owner.kind != .user or self.owner.serial == 0 or self.device.kind != .device or self.device.serial == 0) return error.InvalidPrincipalKind;
        if (self.label_len > MAX_LABEL_BYTES or self.overlay_id == 0 or self.previous_generation == 0) return error.InvalidRotationSignature;
        const next_generation = std.math.add(u32, self.previous_generation, 1) catch return error.DeviceGenerationExhausted;
        if (std.mem.eql(u8, &self.previous_key, &self.device_signature.public_key)) return error.DeviceEnrollmentMismatch;
        var buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = deviceMessage(&buffer, self.device, self.label[0..self.label_len], self.overlay_id, next_generation) catch return error.InvalidDeviceSignature;
        if (!verifyPinnedSignature(self.device_signature, message, self.device_signature.public_key) or
            !verifyPinnedSignature(self.consent_signature, &self.consentDigest(), self.previous_key)) return error.InvalidRotationSignature;
    }

    fn consentDigest(self: *const RotationProposal) crypto_hash.Digest {
        var hash = crypto_hash.init();
        crypto_hash.updateBytes(&hash, "protocol", "zigos.device-key-rotation.v1");
        crypto_hash.updateInt(&hash, "owner", self.owner.serial);
        crypto_hash.updateInt(&hash, "device", self.device.serial);
        crypto_hash.updateBytes(&hash, "root-pin", &self.root_pin);
        crypto_hash.updateBytes(&hash, "label", self.label[0..self.label_len]);
        crypto_hash.updateInt(&hash, "overlay", self.overlay_id);
        crypto_hash.updateInt(&hash, "previous-generation", self.previous_generation);
        crypto_hash.updateBytes(&hash, "previous-key", &self.previous_key);
        crypto_hash.updateBytes(&hash, "next-key", &self.device_signature.public_key);
        crypto_hash.updateBytes(&hash, "next-proof", &self.device_signature.value);
        return crypto_hash.finalize(&hash);
    }
};

pub const UserRootRecord = struct {
    principal_id: principal.PrincipalId,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    root_signature: manifest.Signature = .{},

    pub fn labelSlice(self: *const UserRootRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    comptime {
        if (@sizeOf(@This()) > USER_ROOT_RECORD_SIZE_CEILING_BYTES) {
            @compileError("user root record exceeds its compact size ceiling");
        }
    }
};

pub const DeviceRecord = struct {
    principal_id: principal.PrincipalId,
    owner: principal.PrincipalId,
    label_len: u8,
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
    platform_key_label_len: u8 = 0,
    platform_key_label: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    platform_key_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    platform_root_generation: u64 = 0,
    platform_root_provenance: measured_boot.RootProvenance = .synthetic_host,
    platform_root_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn labelSlice(self: *const DeviceRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    pub fn platformKeyLabelSlice(self: *const DeviceRecord) []const u8 {
        return self.platform_key_label[0..@as(usize, self.platform_key_label_len)];
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

    comptime {
        if (@sizeOf(@This()) > DEVICE_RECORD_SIZE_CEILING_BYTES) {
            @compileError("device graph record exceeds its compact size ceiling");
        }
    }
};

pub const Error = sealed.Error || error{
    AlreadyRevoked,
    DeviceNotFound,
    DeviceTableFull,
    DeviceOwnerMismatch,
    DeviceEnrollmentMismatch,
    DeviceGenerationExhausted,
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
    RootAuthorityMismatch,
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

const USER_ROOT_INDEX_CAPACITY = MAX_USER_ROOTS * 2;
const DEVICE_INDEX_CAPACITY = MAX_DEVICES * 2;

fn graphPrincipalKey(id: principal.PrincipalId) u64 {
    const bytes = id.keyBytes();
    return indexed_arena.nonZeroKey(native_util.fnv1a64(&bytes));
}

fn userRootSlotKey(slot: *const UserRootSlot) u64 {
    return graphPrincipalKey(slot.root.principal_id);
}

fn deviceSlotKey(slot: *const DeviceSlot) u64 {
    return graphPrincipalKey(slot.device.principal_id);
}

const UserRootArena = indexed_arena.IndexedArenaWithKey(u64, UserRootSlot, MAX_USER_ROOTS, USER_ROOT_INDEX_CAPACITY, userRootSlotKey);
const DeviceArena = indexed_arena.IndexedArenaWithKey(u64, DeviceSlot, MAX_DEVICES, DEVICE_INDEX_CAPACITY, deviceSlotKey);

pub const Graph = struct {
    user_roots: UserRootArena = UserRootArena.init(),
    devices: DeviceArena = DeviceArena.init(),
    trusted_device_count: u8 = 0,

    pub fn init() Graph {
        return .{};
    }

    pub fn reset(self: *Graph) void {
        self.user_roots.reset();
        self.devices.reset();
        self.trusted_device_count = 0;
    }

    pub fn rebuildIndexes(self: *Graph) void {
        self.user_roots.rebuildPrimaryIndex();
        self.devices.rebuildPrimaryIndex();
        self.trusted_device_count = 0;
        for (self.devices.slots) |slot| {
            if (slot.in_use and slot.device.status == .trusted) self.trusted_device_count += 1;
        }
    }

    pub fn ensureUserRoot(
        self: *Graph,
        user_principal: principal.PrincipalId,
        label: []const u8,
        identity: signing.SignerIdentity,
    ) Error!*UserRootRecord {
        return self.ensureUserRootInternal(user_principal, label, identity, 0);
    }

    pub fn ensureSealedUserRoot(self: *Graph, user: principal.PrincipalId, label: []const u8, key: sealed.Key, now_ticks: u64) Error!*UserRootRecord {
        try requireSealedOwner(key, user, now_ticks);
        return self.ensureUserRootInternal(user, label, key, now_ticks);
    }

    fn ensureUserRootInternal(self: *Graph, user_principal: principal.PrincipalId, label: []const u8, identity: anytype, tick: u64) Error!*UserRootRecord {
        if (user_principal.kind != .user) return error.InvalidPrincipalKind;
        if (self.findUserRoot(user_principal) != null) return self.requireRootAuthority(user_principal, identity, tick);
        if (self.user_roots.countInUse() >= MAX_USER_ROOTS) return error.UserRootTableFull;

        var root = zeroUserRoot();
        root.principal_id = user_principal;
        root.label_len = @intCast(native_util.copyTextExact(&root.label, label) catch return error.LabelTooLong);

        var message_buffer: [ROOT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = rootMessage(&message_buffer, user_principal, label) catch return error.InvalidRootSignature;
        root.root_signature = try signIdentity(identity, message, tick);
        if (!signing.verify(root.root_signature, message)) return error.InvalidRootSignature;

        const slot_index = self.installUserRootRecord(root) orelse return error.UserRootTableFull;
        return &self.user_roots.slots[slot_index].root;
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

    pub fn enrollSealedDevice(self: *Graph, user: principal.PrincipalId, device: principal.PrincipalId, label: []const u8, root_key: sealed.Key, device_key: sealed.Key, now_ticks: u64) Error!*DeviceRecord {
        try requireSealedOwner(root_key, user, now_ticks);
        try requireSealedOwner(device_key, user, now_ticks);
        return self.enrollDeviceInternal(user, device, label, root_key, device_key, null, now_ticks);
    }

    pub fn approveEnrollment(self: *Graph, proposal: *const EnrollmentProposal, root_key: sealed.Key, now: u64) Error!*DeviceRecord {
        try proposal.validate();
        try requireSealedOwner(root_key, proposal.owner, now);
        const root = try self.requireRootAuthority(proposal.owner, root_key, now);
        if (!std.mem.eql(u8, &root.root_signature.public_key, &proposal.root_pin)) return error.RootAuthorityMismatch;
        if (self.findDevice(proposal.device)) |existing| {
            _ = try self.authenticatedDevice(proposal.device, proposal.root_pin);
            if (!existing.owner.eql(proposal.owner)) return error.DeviceOwnerMismatch;
            if (existing.usesPlatformBackedKey()) return error.PlatformKeyDowngradeDenied;
            if (existing.key_rotation_generation != 1 or existing.overlay_id != proposal.overlay_id or
                !std.mem.eql(u8, existing.labelSlice(), proposal.label[0..proposal.label_len]) or
                !std.mem.eql(u8, &existing.device_signature.public_key, &proposal.device_signature.public_key) or
                !std.mem.eql(u8, &existing.device_signature.value, &proposal.device_signature.value)) return error.DeviceEnrollmentMismatch;
            return existing;
        }
        if (self.devices.countInUse() >= MAX_DEVICES) return error.DeviceTableFull;
        var record = zeroDevice();
        record.principal_id = proposal.device;
        record.owner = proposal.owner;
        record.label_len = proposal.label_len;
        @memcpy(record.label[0..record.label_len], proposal.label[0..proposal.label_len]);
        record.overlay_id = proposal.overlay_id;
        record.device_signature = proposal.device_signature;
        record.device_signature.signer = "device-graph";
        var buffer: [ENROLLMENT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = enrollmentMessage(&buffer, proposal.owner, proposal.device, record.labelSlice(), record.overlay_id, 1, &record.device_signature.public_key) catch return error.InvalidEnrollmentSignature;
        record.enrollment_signature = try signIdentity(root_key, message, now);
        record.last_rotated_at_ticks = now;
        const index = self.installDeviceRecord(record) orelse return error.DeviceTableFull;
        return &self.devices.slots[index].device;
    }

    fn enrollDeviceInternal(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        label: []const u8,
        authorizer: anytype,
        device_identity: anytype,
        platform_key: ?PlatformKeyBindingRequest,
        tick: u64,
    ) Error!*DeviceRecord {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = try self.requireRootAuthority(user_principal, authorizer, tick);

        if (self.findDevice(device_principal)) |existing| {
            if (!existing.owner.eql(user_principal)) return error.DeviceOwnerMismatch;
            if (existing.status == .revoked) return error.AlreadyRevoked;
            try requireSameEnrollment(existing, label, device_identity, platform_key, tick);
            return existing;
        }
        if (self.devices.countInUse() >= MAX_DEVICES) return error.DeviceTableFull;

        const overlay_id = deriveOverlayId(device_principal, try identityLabel(device_identity, tick));
        var device = zeroDevice();
        device.principal_id = device_principal;
        device.owner = user_principal;
        device.label_len = @intCast(native_util.copyTextExact(&device.label, label) catch return error.LabelTooLong);
        device.overlay_id = overlay_id;

        var device_message_buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            label,
            overlay_id,
            1,
        ) catch return error.InvalidDeviceSignature;
        device.device_signature = try signIdentity(device_identity, device_message, tick);
        if (!signing.verify(device.device_signature, device_message)) return error.InvalidDeviceSignature;
        if (platform_key) |binding_request| {
            applyPlatformKeyBinding(&device, try buildPlatformKeyBinding(device_principal, device_identity, device.device_signature, binding_request, tick));
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
        device.enrollment_signature = try signIdentity(authorizer, enrollment_message, tick);
        if (!signing.verify(device.enrollment_signature, enrollment_message)) return error.InvalidEnrollmentSignature;

        device.last_rotated_at_ticks = tick;
        const slot_index = self.installDeviceRecord(device) orelse return error.DeviceTableFull;
        return &self.devices.slots[slot_index].device;
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

    pub fn rotateSealedDeviceKey(self: *Graph, user: principal.PrincipalId, device: principal.PrincipalId, root_key: sealed.Key, device_key: sealed.Key, now_ticks: u64) Error!*DeviceRecord {
        try requireSealedOwner(root_key, user, now_ticks);
        try requireSealedOwner(device_key, user, now_ticks);
        return self.rotateDeviceKeyInternal(user, device, root_key, device_key, null, now_ticks);
    }

    pub fn approveRotation(self: *Graph, proposal: *const RotationProposal, root_key: sealed.Key, now: u64) Error!bool {
        try proposal.validate();
        try requireSealedOwner(root_key, proposal.owner, now);
        const root = try self.requireRootAuthority(proposal.owner, root_key, now);
        if (!std.mem.eql(u8, &root.root_signature.public_key, &proposal.root_pin)) return error.RootAuthorityMismatch;
        const current = try self.authenticatedDevice(proposal.device, proposal.root_pin);
        if (!current.owner.eql(proposal.owner)) return error.DeviceOwnerMismatch;
        if (current.usesPlatformBackedKey()) return error.PlatformKeyDowngradeDenied;
        if (current.overlay_id != proposal.overlay_id or !std.mem.eql(u8, current.labelSlice(), proposal.label[0..proposal.label_len])) return error.DeviceEnrollmentMismatch;
        const next_generation = proposal.previous_generation + 1; // validate rejects exhaustion.
        // An authenticated successor already installed by this root requires
        // no second mutation; older requests cannot advance it again.
        if (current.key_rotation_generation == next_generation and
            std.mem.eql(u8, &current.device_signature.public_key, &proposal.device_signature.public_key) and
            std.mem.eql(u8, &current.device_signature.value, &proposal.device_signature.value)) return false;
        if (current.key_rotation_generation != proposal.previous_generation or
            !std.mem.eql(u8, &current.device_signature.public_key, &proposal.previous_key)) return error.InvalidRotationSignature;
        var buffer: [ROTATION_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = rotationMessage(&buffer, proposal.owner, proposal.device, proposal.overlay_id, next_generation, &proposal.device_signature.public_key) catch return error.InvalidRotationSignature;
        const signature = try signIdentity(root_key, message, now);
        const record = self.findDevice(proposal.device).?;
        record.device_signature = proposal.device_signature;
        record.device_signature.signer = "device-graph";
        record.rotation_signature = signature;
        clearPlatformKeyBinding(record);
        record.key_rotation_generation = next_generation;
        record.last_rotated_at_ticks = now;
        return true;
    }

    fn rotateDeviceKeyInternal(
        self: *Graph,
        user_principal: principal.PrincipalId,
        device_principal: principal.PrincipalId,
        authorizer: anytype,
        next_device_identity: anytype,
        platform_key: ?PlatformKeyBindingRequest,
        tick: u64,
    ) Error!*DeviceRecord {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = try self.requireRootAuthority(user_principal, authorizer, tick);
        const record = self.findDevice(device_principal) orelse return error.DeviceNotFound;
        if (!record.owner.eql(user_principal)) return error.DeviceOwnerMismatch;
        if (record.status == .revoked) return error.AlreadyRevoked;
        if (record.usesPlatformBackedKey() and platform_key == null) return error.PlatformKeyDowngradeDenied;

        const next_generation = std.math.add(u32, record.key_rotation_generation, 1) catch return error.DeviceGenerationExhausted;
        var device_message_buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const device_message = deviceMessage(
            &device_message_buffer,
            device_principal,
            record.labelSlice(),
            record.overlay_id,
            next_generation,
        ) catch return error.InvalidDeviceSignature;
        const device_signature = try signIdentity(next_device_identity, device_message, tick);
        if (!signing.verify(device_signature, device_message)) return error.InvalidDeviceSignature;
        const next_platform_key = if (platform_key) |binding_request|
            try buildPlatformKeyBinding(device_principal, next_device_identity, device_signature, binding_request, tick)
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
        const rotation_signature = try signIdentity(authorizer, rotation_message, tick);
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
        return self.revokeDeviceInternal(user_principal, device_principal, authorizer, tick);
    }

    pub fn revokeSealedDevice(self: *Graph, user: principal.PrincipalId, device: principal.PrincipalId, root_key: sealed.Key, now_ticks: u64) Error!void {
        try requireSealedOwner(root_key, user, now_ticks);
        return self.revokeDeviceInternal(user, device, root_key, now_ticks);
    }

    fn revokeDeviceInternal(self: *Graph, user_principal: principal.PrincipalId, device_principal: principal.PrincipalId, authorizer: anytype, tick: u64) Error!void {
        if (user_principal.kind != .user or device_principal.kind != .device) return error.InvalidPrincipalKind;
        _ = try self.requireRootAuthority(user_principal, authorizer, tick);
        const record = self.findDevice(device_principal) orelse return error.DeviceNotFound;
        if (!record.owner.eql(user_principal)) return error.DeviceOwnerMismatch;
        if (record.status == .revoked) return error.AlreadyRevoked;
        const next_generation = std.math.add(u32, record.trust_generation, 1) catch return error.DeviceGenerationExhausted;

        var message_buffer: [REVOCATION_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = revocationMessage(
            &message_buffer,
            user_principal,
            device_principal,
            record.overlay_id,
            tick,
        ) catch return error.InvalidEnrollmentSignature;
        const signature = try signIdentity(authorizer, message, tick);
        if (!signing.verify(signature, message)) return error.InvalidEnrollmentSignature;

        record.revocation_signature = signature;
        record.status = .revoked;
        record.trust_generation = next_generation;
        record.revoked_at_ticks = tick;
        if (self.trusted_device_count == 0) native_util.impossibleByInvariant("trusted device count covers trusted records");
        self.trusted_device_count -= 1;
    }

    pub fn findUserRoot(self: *Graph, user_principal: principal.PrincipalId) ?*UserRootRecord {
        const slot = self.user_roots.get(graphPrincipalKey(user_principal)) orelse return null;
        if (!slot.root.principal_id.eql(user_principal)) return null;
        return &slot.root;
    }

    // Service capabilities authorize access to this graph, not control over
    // every enrolled user. Every mutation must also prove the user's root key.
    fn requireRootAuthority(self: *Graph, user: principal.PrincipalId, authorizer: anytype, tick: u64) Error!*UserRootRecord {
        const root = self.findUserRoot(user) orelse return error.RootNotFound;
        if (root.label_len > MAX_LABEL_BYTES or root.root_signature.format != .ed25519 or
            root.root_signature.public_key_len != signing.PUBLIC_KEY_BYTES or
            root.root_signature.value_len != signing.SIGNATURE_BYTES) return error.InvalidRootSignature;
        var message_buffer: [ROOT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = rootMessage(&message_buffer, user, root.labelSlice()) catch return error.InvalidRootSignature;
        if (!signing.verify(root.root_signature, message)) return error.InvalidRootSignature;
        const public_key = try identityPublicKey(authorizer, tick);
        if (!std.mem.eql(u8, &public_key, &root.root_signature.public_key)) return error.RootAuthorityMismatch;
        return root;
    }

    pub fn findDevice(self: *Graph, device_principal: principal.PrincipalId) ?*DeviceRecord {
        const slot = self.devices.get(graphPrincipalKey(device_principal)) orelse return null;
        if (!slot.device.principal_id.eql(device_principal)) return null;
        return &slot.device;
    }

    pub fn findDeviceConst(self: *const Graph, device_principal: principal.PrincipalId) ?*const DeviceRecord {
        const slot = self.devices.getConst(graphPrincipalKey(device_principal)) orelse return null;
        if (!slot.device.principal_id.eql(device_principal)) return null;
        return &slot.device;
    }

    pub fn findUserRootConst(self: *const Graph, user_principal: principal.PrincipalId) ?*const UserRootRecord {
        const slot = self.user_roots.getConst(graphPrincipalKey(user_principal)) orelse return null;
        if (!slot.root.principal_id.eql(user_principal)) return null;
        return &slot.root;
    }

    // The root pin comes from the caller's trusted enrollment boundary, never
    // from a remote certificate or the record being verified.
    pub fn authenticatedDevice(self: *const Graph, device_principal: principal.PrincipalId, root_pin: signing.PublicKey) Error!*const DeviceRecord {
        const record = try self.authenticatedRecord(device_principal, root_pin);
        if (!record.isTrusted()) return error.AlreadyRevoked;
        return record;
    }

    pub fn authenticatedRoot(self: *const Graph, owner: principal.PrincipalId, root_pin: signing.PublicKey) Error!*const UserRootRecord {
        const root = self.findUserRootConst(owner) orelse return error.RootNotFound;
        if (owner.kind != .user or owner.serial == 0 or root.label_len > MAX_LABEL_BYTES) return error.InvalidRootSignature;
        var buffer: [ROOT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const message = rootMessage(&buffer, owner, root.labelSlice()) catch return error.InvalidRootSignature;
        if (!verifyPinnedSignature(root.root_signature, message, root_pin)) return error.InvalidRootSignature;
        return root;
    }

    // Snapshot restoration must authenticate revoked records too, without
    // granting them permission to open a live channel.
    pub fn authenticatedRecord(self: *const Graph, device_principal: principal.PrincipalId, root_pin: signing.PublicKey) Error!*const DeviceRecord {
        const record = self.findDeviceConst(device_principal) orelse return error.DeviceNotFound;
        if (record.principal_id.kind != .device or record.principal_id.serial == 0 or record.owner.kind != .user or record.owner.serial == 0) return error.InvalidPrincipalKind;
        if (record.label_len > MAX_LABEL_BYTES or record.key_rotation_generation == 0 or record.trust_generation == 0 or record.overlay_id == 0) return error.InvalidDeviceSignature;
        _ = try self.authenticatedRoot(record.owner, root_pin);
        var buffer: [ENROLLMENT_MESSAGE_BUFFER_BYTES]u8 = undefined;
        const device_message = deviceMessage(&buffer, record.principal_id, record.labelSlice(), record.overlay_id, record.key_rotation_generation) catch return error.InvalidDeviceSignature;
        if (!verifyPinnedSignature(record.device_signature, device_message, record.device_signature.public_key)) return error.InvalidDeviceSignature;
        if (record.key_rotation_generation == 1) {
            const message = enrollmentMessage(&buffer, record.owner, record.principal_id, record.labelSlice(), record.overlay_id, 1, &record.device_signature.public_key) catch return error.InvalidEnrollmentSignature;
            if (!verifyPinnedSignature(record.enrollment_signature, message, root_pin)) return error.InvalidEnrollmentSignature;
        } else {
            const message = rotationMessage(&buffer, record.owner, record.principal_id, record.overlay_id, record.key_rotation_generation, &record.device_signature.public_key) catch return error.InvalidRotationSignature;
            if (!verifyPinnedSignature(record.rotation_signature, message, root_pin)) return error.InvalidRotationSignature;
        }
        if (record.status == .revoked) {
            if (record.trust_generation != 2) return error.InvalidEnrollmentSignature;
            const message = revocationMessage(&buffer, record.owner, record.principal_id, record.overlay_id, record.revoked_at_ticks) catch return error.InvalidEnrollmentSignature;
            if (!verifyPinnedSignature(record.revocation_signature, message, root_pin)) return error.InvalidEnrollmentSignature;
        } else if (record.trust_generation != 1 or record.revoked_at_ticks != 0 or record.revocation_signature.isPresent()) return error.InvalidEnrollmentSignature;
        return record;
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
        return @intCast(self.trusted_device_count);
    }

    pub fn installUserRootRecord(self: *Graph, root: UserRootRecord) ?usize {
        const slot_index = self.user_roots.reserveIndex(graphPrincipalKey(root.principal_id)) orelse return null;
        self.user_roots.slots[slot_index].root = root;
        return slot_index;
    }

    pub fn installDeviceRecord(self: *Graph, device: DeviceRecord) ?usize {
        const slot_index = self.devices.reserveIndex(graphPrincipalKey(device.principal_id)) orelse return null;
        self.devices.slots[slot_index].device = device;
        if (device.status == .trusted) self.trusted_device_count += 1;
        return slot_index;
    }

    comptime {
        if (@sizeOf(@This()) > GRAPH_SIZE_CEILING_BYTES) {
            @compileError("device graph exceeds its compact size ceiling");
        }
    }
};

fn verifyPinnedSignature(signature: manifest.Signature, message: []const u8, key: signing.PublicKey) bool {
    return signature.format == .ed25519 and signature.public_key_len == signing.PUBLIC_KEY_BYTES and
        signature.value_len == signing.SIGNATURE_BYTES and std.mem.eql(u8, &signature.public_key, &key) and
        signing.verify(signature, message);
}

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

fn requireSealedOwner(key: sealed.Key, owner: principal.PrincipalId, tick: u64) Error!void {
    try key.validate(tick);
    if (!key.authority.?.owner.eql(owner)) return error.SecretOwnerMismatch;
}

fn signIdentity(identity: anytype, message: []const u8, tick: u64) Error!manifest.Signature {
    var signature = if (@TypeOf(identity) == sealed.Key) try identity.signMessage(message, tick) else signing.sign(identity, message) catch return error.InvalidSigningKey;
    // The diagnostic label is not signed authority. Keep graph records valid
    // after a temporary signing lease or its vault has been retired.
    signature.signer = "device-graph";
    return signature;
}

fn identityPublicKey(identity: anytype, tick: u64) Error!signing.PublicKey {
    if (@TypeOf(identity) == sealed.Key) return identity.publicKey(tick);
    return signing.publicKey(identity) catch error.InvalidSigningKey;
}

fn identityLabel(identity: anytype, tick: u64) Error![]const u8 {
    if (@TypeOf(identity) == sealed.Key) return identity.label(tick);
    return identity.label;
}

const ResolvedPlatformKeyBinding = struct {
    origin: DeviceKeyOrigin,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    digest: crypto_hash.Digest,
    root_generation: u64,
    root_provenance: measured_boot.RootProvenance,
    root_digest: crypto_hash.Digest,
};

// Enrollment retries may repeat the current binding. Key changes require the
// rotation path so generations, signatures and platform custody stay coherent.
fn requireSameEnrollment(record: *const DeviceRecord, label: []const u8, identity: anytype, platform_key: ?PlatformKeyBindingRequest, tick: u64) Error!void {
    if (record.label_len > MAX_LABEL_BYTES or !std.mem.eql(u8, record.labelSlice(), label)) return error.DeviceEnrollmentMismatch;
    const key = try identityPublicKey(identity, tick);
    if (record.device_signature.format != .ed25519 or record.device_signature.public_key_len != signing.PUBLIC_KEY_BYTES or
        !std.mem.eql(u8, &record.device_signature.public_key, &key)) return error.DeviceEnrollmentMismatch;
    var message_buffer: [DEVICE_MESSAGE_BUFFER_BYTES]u8 = undefined;
    const message = deviceMessage(&message_buffer, record.principal_id, label, record.overlay_id, record.key_rotation_generation) catch return error.InvalidDeviceSignature;
    if (record.device_signature.value_len != signing.SIGNATURE_BYTES or !signing.verify(record.device_signature, message)) return error.InvalidDeviceSignature;
    if (record.usesPlatformBackedKey() and platform_key == null) return error.PlatformKeyDowngradeDenied;
    if (platform_key) |request| {
        const binding = try buildPlatformKeyBinding(record.principal_id, identity, record.device_signature, request, tick);
        if (!record.platform_key_bound or record.device_key_origin != binding.origin or
            record.platform_key_label_len != binding.label_len or !std.mem.eql(u8, &record.platform_key_label, &binding.label) or
            !std.mem.eql(u8, &record.platform_key_digest, &binding.digest) or
            record.platform_root_generation != binding.root_generation or record.platform_root_provenance != binding.root_provenance or
            !std.mem.eql(u8, &record.platform_root_digest, &binding.root_digest)) return error.DeviceEnrollmentMismatch;
    }
}

fn buildPlatformKeyBinding(
    device_principal: principal.PrincipalId,
    device_identity: anytype,
    device_signature: manifest.Signature,
    request: PlatformKeyBindingRequest,
    tick: u64,
) Error!ResolvedPlatformKeyBinding {
    if (!isPlatformBackedOrigin(request.root.origin)) return error.SoftwareDeviceKeyRejected;
    if (!request.root.device_principal.eql(device_principal)) return error.PlatformRootDeviceMismatch;
    if (request.root.root_provenance != .bootloader_provided) return error.SyntheticPlatformRoot;
    if (request.root.boot_generation == 0 or std.mem.allEqual(u8, &request.root.root_digest, 0)) return error.UnverifiedPlatformRoot;
    if (request.root.label_len > MAX_LABEL_BYTES) return error.LabelTooLong;
    const public_key = try identityPublicKey(device_identity, tick);
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
    binding.label_len = @intCast(native_util.copyTextExact(&binding.label, request.root.labelSlice()) catch return error.LabelTooLong);
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

test "device graph rejects rotation signed by a different user root" {
    var graph = Graph.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const root_key = signing.SignerIdentity{ .label = "root", .seed = @splat(0x21) };
    const device_key = signing.SignerIdentity{ .label = "device", .seed = @splat(0x22) };
    const attacker = signing.SignerIdentity{ .label = "root", .seed = @splat(0x23) };
    _ = try graph.ensureUserRoot(owner, "owner", root_key);
    _ = try graph.enrollDevice(owner, device, "device", root_key, device_key, 1);
    const before = graph;
    try std.testing.expectError(error.RootAuthorityMismatch, graph.rotateDeviceKey(owner, device, attacker, attacker, 2));
    try std.testing.expectEqualDeep(before, graph);
}

const MutationFixture = if (@import("builtin").is_test) struct {
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const other_owner = principal.PrincipalId{ .kind = .user, .serial = 3 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const other_device = principal.PrincipalId{ .kind = .device, .serial = 4 };
    const root_key = signing.SignerIdentity{ .label = "root", .seed = @splat(0x21) };
    const device_key = signing.SignerIdentity{ .label = "device", .seed = @splat(0x22) };
    // A matching signer label conveys no root authority.
    const other_key = signing.SignerIdentity{ .label = "root", .seed = @splat(0x23) };

    fn init() !Graph {
        var graph = Graph.init();
        _ = try graph.ensureUserRoot(owner, "owner", root_key);
        _ = try graph.ensureUserRoot(other_owner, "other", other_key);
        _ = try graph.enrollDevice(owner, device, "device", root_key, device_key, 1);
        return graph;
    }
} else struct {};

test "device graph requires root authority for enrollment retries and revocation" {
    const f = MutationFixture;
    var graph = try f.init();
    const before = graph;
    try std.testing.expectError(error.RootAuthorityMismatch, graph.ensureUserRoot(f.owner, "owner", f.other_key));
    try std.testing.expectError(error.RootAuthorityMismatch, graph.enrollDevice(f.owner, f.other_device, "other", f.other_key, f.other_key, 2));
    try std.testing.expectError(error.RootAuthorityMismatch, graph.enrollDevice(f.owner, f.device, "device", f.other_key, f.device_key, 2));
    try std.testing.expectError(error.RootAuthorityMismatch, graph.revokeDevice(f.owner, f.device, f.other_key, 2));
    try std.testing.expectEqualDeep(before, graph);
    // Labels may change without changing authority; the cryptographic key is pinned.
    var alias = f.root_key;
    alias.label = "renamed signer";
    _ = try graph.ensureUserRoot(f.owner, "owner", alias);
    _ = try graph.enrollDevice(f.owner, f.device, "device", alias, f.device_key, 2);
    try std.testing.expectEqualDeep(before, graph);
    try graph.revokeDevice(f.owner, f.device, alias, 3);
    try std.testing.expectEqual(@as(usize, 0), graph.trustedDeviceCount());
}

test "device graph denies cross owner enrollment rotation and revocation" {
    const f = MutationFixture;
    var graph = try f.init();
    const before = graph;
    try std.testing.expectError(error.DeviceOwnerMismatch, graph.enrollDevice(f.other_owner, f.device, "device", f.other_key, f.device_key, 2));
    try std.testing.expectError(error.DeviceOwnerMismatch, graph.rotateDeviceKey(f.other_owner, f.device, f.other_key, f.other_key, 2));
    try std.testing.expectError(error.DeviceOwnerMismatch, graph.revokeDevice(f.other_owner, f.device, f.other_key, 2));
    try std.testing.expectEqualDeep(before, graph);
}

test "device graph rejects conflicting enrollment without replacing keys or labels" {
    const f = MutationFixture;
    var graph = try f.init();
    const before = graph;
    try std.testing.expectError(error.DeviceEnrollmentMismatch, graph.enrollDevice(f.owner, f.device, "device", f.root_key, f.other_key, 2));
    try std.testing.expectError(error.DeviceEnrollmentMismatch, graph.enrollDevice(f.owner, f.device, "renamed", f.root_key, f.device_key, 2));
    try std.testing.expectEqualDeep(before, graph);
    _ = try graph.rotateDeviceKey(f.owner, f.device, f.root_key, f.other_key, 3);
    const rotated = graph;
    _ = try graph.enrollDevice(f.owner, f.device, "device", f.root_key, f.other_key, 4);
    try std.testing.expectEqualDeep(rotated, graph);
    graph.findDevice(f.device).?.device_signature.value[0] ^= 1;
    const malformed = graph;
    try std.testing.expectError(error.InvalidDeviceSignature, graph.enrollDevice(f.owner, f.device, "device", f.root_key, f.other_key, 4));
    try std.testing.expectEqualDeep(malformed, graph);
}

test "device graph rejects exhausted generations before changing signed state" {
    const f = MutationFixture;
    var graph = try f.init();
    const device = graph.findDevice(f.device).?;
    device.key_rotation_generation = std.math.maxInt(u32);
    device.trust_generation = std.math.maxInt(u32);
    const before = graph;
    try std.testing.expectError(error.DeviceGenerationExhausted, graph.rotateDeviceKey(f.owner, f.device, f.root_key, f.other_key, 2));
    try std.testing.expectError(error.DeviceGenerationExhausted, graph.revokeDevice(f.owner, f.device, f.root_key, 2));
    try std.testing.expectEqualDeep(before, graph);
}

test "device graph rejects malformed root metadata before trusting its authorizer" {
    const f = MutationFixture;
    for (0..4) |variant| {
        var graph = try f.init();
        const root = graph.findUserRoot(f.owner).?;
        switch (variant) {
            0 => root.root_signature.value[0] ^= 1,
            1 => root.root_signature.public_key_len = 255,
            2 => root.root_signature.value_len = 255,
            else => root.label_len = 255,
        }
        const before = graph;
        try std.testing.expectError(error.InvalidRootSignature, graph.ensureUserRoot(f.owner, "owner", f.root_key));
        try std.testing.expectError(error.InvalidRootSignature, graph.enrollDevice(f.owner, f.other_device, "other", f.root_key, f.other_key, 2));
        try std.testing.expectError(error.InvalidRootSignature, graph.rotateDeviceKey(f.owner, f.device, f.root_key, f.other_key, 2));
        try std.testing.expectError(error.InvalidRootSignature, graph.revokeDevice(f.owner, f.device, f.root_key, 2));
        try std.testing.expectEqualDeep(before, graph);
    }
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

test "compact device graph metadata preserves exact label capacities" {
    const full_label = [_]u8{'d'} ** MAX_LABEL_BYTES;
    const user = principal.PrincipalId{ .kind = .user, .serial = 21 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 22 };
    const user_identity = signing.SignerIdentity{
        .label = "compact-user-root",
        .seed = signing.seedFromByte(0x71),
    };
    const device_identity = signing.SignerIdentity{
        .label = "compact-device-key",
        .seed = signing.seedFromByte(0x72),
    };

    var graph = Graph.init();
    const root = try graph.ensureUserRoot(user, &full_label, user_identity);
    const record = try graph.enrollDevice(user, device, &full_label, user_identity, device_identity, 1);
    record.platform_key_label_len = @intCast(try native_util.copyTextExact(&record.platform_key_label, &full_label));

    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), root.label_len);
    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), record.label_len);
    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), record.platform_key_label_len);
    try std.testing.expectEqualSlices(u8, &full_label, root.labelSlice());
    try std.testing.expectEqualSlices(u8, &full_label, record.labelSlice());
    try std.testing.expectEqualSlices(u8, &full_label, record.platformKeyLabelSlice());
    try std.testing.expectEqual(@as(u8, 1), graph.trusted_device_count);
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

    const enrolled = graph;
    _ = try graph.enrollPlatformBackedDevice(user, laptop, "laptop", user_identity, laptop_identity, .{ .root = laptop_root }, 21);
    try std.testing.expectError(error.PlatformKeyDowngradeDenied, graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 21));
    const changed_root = try PlatformDeviceRoot.fromBootRecord(laptop, .secure_enclave, "laptop-bootloader-key", &rotated_boot);
    try std.testing.expectError(error.DeviceEnrollmentMismatch, graph.enrollPlatformBackedDevice(user, laptop, "laptop", user_identity, laptop_identity, .{ .root = changed_root }, 21));
    var malformed_root = laptop_root;
    malformed_root.label_len = 255;
    try std.testing.expectError(error.LabelTooLong, graph.enrollPlatformBackedDevice(user, laptop, "laptop", user_identity, laptop_identity, .{ .root = malformed_root }, 21));
    malformed_root = laptop_root;
    malformed_root.boot_generation = 0;
    try std.testing.expectError(error.UnverifiedPlatformRoot, graph.rotatePlatformBackedDeviceKey(user, laptop, user_identity, rotated_laptop_identity, .{ .root = malformed_root }, 21));
    try std.testing.expectEqualDeep(enrolled, graph);

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
    recorder.add(.kernel, "kernel-zigos", "kernel=device-graph") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.base_image, "stable-device-graph", "image=device-graph") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.critical_service, "policy", "healthy") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.critical_service, "storage", "healthy") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.critical_service, "sync", "healthy") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.critical_service, "network", "healthy") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.policy, "device-graph-policy", "strict") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    recorder.add(.driver_set, "device-graph-drivers", "drivers") catch |err| native_util.impossibleByInvariantError("fresh recorder holds the fixed device-graph artifact set", err);
    return recorder.finalize();
}
