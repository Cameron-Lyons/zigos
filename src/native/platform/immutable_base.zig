const std = @import("std");
const binary_cursor = @import("binary_cursor");
const crypto_hash = @import("../core/crypto_hash.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");

pub const MAX_SYSTEM_IMAGES: usize = 2;
pub const MAX_LABEL_BYTES: usize = 48;
pub const state_workspace_label = "system-base";
pub const COMPACT_IMMUTABLE_BASE_METADATA = true;
pub const SYSTEM_IMAGE_SIZE_CEILING_BYTES: usize = 160;
pub const BOOT_SELECTION_SIZE_CEILING_BYTES: usize = 120;
pub const MANAGER_SIZE_CEILING_BYTES: usize = 424;

comptime {
    if (MAX_SYSTEM_IMAGES > std.math.maxInt(u8) or MAX_LABEL_BYTES > std.math.maxInt(u8)) {
        @compileError("immutable base metadata exceeds compact field capacity");
    }
}

const PERSISTED_STATE_PAYLOAD_BUFFER_BYTES: usize = 512;
const state_entry_path = "state/activation";
const empty_slot: u8 = 0xFF;

pub const HealthFailure = enum(u8) {
    none,
    boot,
    core_service,
    ui,
    storage,
    network,
};

pub const HealthReport = struct {
    boot_ok: bool = true,
    core_services_ok: bool = true,
    ui_ok: bool = true,
    storage_ok: bool = true,
    network_ok: bool = true,

    pub fn failure(self: HealthReport) HealthFailure {
        if (!self.boot_ok) return .boot;
        if (!self.core_services_ok) return .core_service;
        if (!self.ui_ok) return .ui;
        if (!self.storage_ok) return .storage;
        if (!self.network_ok) return .network;
        return .none;
    }

    pub fn isHealthy(self: HealthReport) bool {
        return self.failure() == .none;
    }
};

pub const SystemImage = struct {
    slot_index: u8,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    object_id: u64,
    version_id: u64,
    read_only: bool,
    activation_generation: u64,
    signer_len: u8,
    signer: [MAX_LABEL_BYTES]u8,
    measurement: object_store.BlobAddress,

    pub fn labelSlice(self: *const SystemImage) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    pub fn signerSlice(self: *const SystemImage) []const u8 {
        return self.signer[0..@as(usize, self.signer_len)];
    }
};

pub const ActivationResult = struct {
    active_slot: ?usize,
    activation_generation: u64,
    rollback_generation: u64,
    failure: HealthFailure,
    rolled_back: bool,
};

pub const BootSelection = struct {
    slot_index: u8,
    object_id: u64,
    version_id: u64,
    activation_generation: u64,
    rollback_generation: u64,
    measurement: object_store.BlobAddress,
    signer_len: u8,
    signer: [MAX_LABEL_BYTES]u8,

    pub fn signerSlice(self: *const BootSelection) []const u8 {
        return self.signer[0..@as(usize, self.signer_len)];
    }
};

pub const Error = anyerror;

pub const Manager = struct {
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    state_signer: signing.SignerIdentity,
    workspace_id: u64,
    loaded_existing_state: bool = false,
    active_slot: u8 = empty_slot,
    last_good_slot: u8 = empty_slot,
    pending_slot: u8 = empty_slot,
    activation_generation: u64 = 0,
    rollback_generation: u64 = 0,
    slots: [MAX_SYSTEM_IMAGES]SystemImage = [_]SystemImage{zeroImage()} ** MAX_SYSTEM_IMAGES,

    pub fn init(
        storage: *storage_service.Service,
        owner: principal.PrincipalId,
        state_signer: signing.SignerIdentity,
    ) Error!Manager {
        const record = storage.findWorkspace(owner, state_workspace_label) orelse try storage.createWorkspace(.{
            .owner = owner,
            .label = state_workspace_label,
        });
        return initWithWorkspace(storage, owner, state_signer, record.id);
    }

    pub fn initWithWorkspace(
        storage: *storage_service.Service,
        owner: principal.PrincipalId,
        state_signer: signing.SignerIdentity,
        workspace_id: anytype,
    ) Error!Manager {
        var manager = Manager{
            .storage = storage,
            .owner = owner,
            .state_signer = state_signer,
            .workspace_id = object_store.ids.raw(workspace_id),
        };

        if (storage.resolve(manager.workspace_id, state_entry_path)) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            try manager.decode(try storage.versionPayload(version));
            manager.loaded_existing_state = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        }

        return manager;
    }

    pub fn stageImage(
        self: *Manager,
        slot_index: usize,
        label: []const u8,
        payload: []const u8,
        signer: signing.SignerIdentity,
        tick: u64,
    ) Error!*SystemImage {
        if (slot_index >= MAX_SYSTEM_IMAGES) return error.InvalidSlot;

        const result = try self.storage.putLocallySignedVersion(.{
            .preferred_object_id = object_store.ids.object(imageObjectId(slot_index)),
            .object_type = .model_artifact,
            .payload = payload,
            .signer = signer,
            .label = label,
            .content_type = "application/zigos-system-image",
            .created_at_ticks = tick,
        });

        const slot = &self.slots[slot_index];
        slot.* = zeroImage();
        slot.slot_index = @intCast(slot_index);
        slot.label_len = @intCast(try native_util.copyTextExact(&slot.label, label));
        slot.object_id = result.object_id.raw();
        slot.version_id = result.version_id.raw();
        slot.read_only = true;
        slot.activation_generation = self.activation_generation;
        slot.signer_len = @intCast(try native_util.copyTextExact(&slot.signer, signer.label));
        slot.measurement = result.blob_address;
        try self.persist(tick);
        return slot;
    }

    pub fn activate(
        self: *Manager,
        slot_index: usize,
        report: HealthReport,
        tick: u64,
    ) Error!ActivationResult {
        try self.beginActivation(slot_index, tick);
        return self.finalizeActivation(report, tick + 1);
    }

    pub fn beginActivation(
        self: *Manager,
        slot_index: usize,
        tick: u64,
    ) Error!void {
        if (slot_index >= MAX_SYSTEM_IMAGES) return error.InvalidSlot;
        if (self.slots[slot_index].version_id == 0) return error.ImageNotPresent;
        if (self.pending_slot != empty_slot) return error.ActivationInProgress;

        self.activation_generation += 1;
        self.pending_slot = @intCast(slot_index);
        if (self.active_slot != empty_slot and self.active_slot != slot_index) {
            self.last_good_slot = self.active_slot;
        }
        self.active_slot = @intCast(slot_index);
        self.slots[slot_index].activation_generation = self.activation_generation;
        try self.persist(tick);
    }

    pub fn finalizeActivation(
        self: *Manager,
        report: HealthReport,
        tick: u64,
    ) Error!ActivationResult {
        if (self.pending_slot == empty_slot) return error.NoPendingActivation;

        const pending_slot = self.pending_slot;
        const failure = report.failure();
        self.pending_slot = empty_slot;
        if (failure != .none) {
            self.rollback_generation += 1;
            self.active_slot = self.last_good_slot;
            try self.persist(tick);
            return .{
                .active_slot = if (self.active_slot == empty_slot) null else @as(usize, self.active_slot),
                .activation_generation = self.activation_generation,
                .rollback_generation = self.rollback_generation,
                .failure = failure,
                .rolled_back = true,
            };
        }

        self.active_slot = pending_slot;
        self.last_good_slot = self.active_slot;
        try self.persist(tick);
        return .{
            .active_slot = pending_slot,
            .activation_generation = self.activation_generation,
            .rollback_generation = self.rollback_generation,
            .failure = .none,
            .rolled_back = false,
        };
    }

    pub fn pendingSlotIndex(self: *const Manager) ?usize {
        if (self.pending_slot == empty_slot) return null;
        return self.pending_slot;
    }

    pub fn activeImage(self: *const Manager) ?*const SystemImage {
        if (self.active_slot == empty_slot) return null;
        return &self.slots[self.active_slot];
    }

    pub fn inactiveSlotIndex(self: *const Manager) usize {
        return if (self.active_slot == 0) 1 else 0;
    }

    pub fn verifyActiveImage(self: *const Manager) bool {
        const image = self.activeImage() orelse return false;
        return self.verifySlot(image.slot_index);
    }

    pub fn verifySlot(self: *const Manager, slot_index: usize) bool {
        if (slot_index >= MAX_SYSTEM_IMAGES) return false;
        const image = &self.slots[slot_index];
        if (image.version_id == 0 or !image.read_only) return false;
        const version = self.storage.version(image.version_id) orelse return false;
        if (version.object_id.raw() != image.object_id or version.object_type != .model_artifact) return false;
        if (!version.metadata.isSigned() or !version.metadata.signature.isComplete()) return false;
        const payload = self.storage.versionPayload(version) catch return false;
        if (!version.metadata.verifyFor(.model_artifact, payload)) return false;
        if (!std.mem.eql(u8, version.metadata.signature.signer, image.signerSlice())) return false;
        const blob = self.storage.versionBlob(version) orelse return false;
        return std.mem.eql(u8, &blob.address, &image.measurement);
    }

    pub fn selectVerifiedBootImage(self: *const Manager) Error!BootSelection {
        const image = self.activeImage() orelse return error.ImageNotPresent;
        if (!self.verifySlot(image.slot_index)) return error.ImageVerificationFailed;
        return .{
            .slot_index = image.slot_index,
            .object_id = image.object_id,
            .version_id = image.version_id,
            .activation_generation = self.activation_generation,
            .rollback_generation = self.rollback_generation,
            .measurement = image.measurement,
            .signer_len = image.signer_len,
            .signer = image.signer,
        };
    }

    fn persist(self: *Manager, tick: u64) Error!void {
        var payload: [PERSISTED_STATE_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const encoded = try self.encode(payload[0..]);
        const existing_entry = self.storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const result = try self.storage.putLocallySignedVersion(.{
            .preferred_object_id = object_store.ids.object(stateObjectId()),
            .object_type = .document,
            .payload = encoded,
            .signer = self.state_signer,
            .label = "immutable-base-state",
            .content_type = "application/zigos-immutable-base",
            .created_at_ticks = tick,
            .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
        });
        try self.storage.beginTransaction(self.workspace_id);
        try self.storage.stagePut(self.workspace_id, state_entry_path, result.object_id, result.version_id, .document);
        _ = try self.storage.commit(self.workspace_id, tick);
    }

    fn encode(self: *const Manager, buffer: []u8) Error![]const u8 {
        var writer = BinaryWriter{ .buffer = buffer };
        try writer.writeBytes("zigos.immutable-base.state");
        try writer.writeByte(self.active_slot);
        try writer.writeByte(self.last_good_slot);
        try writer.writeByte(self.pending_slot);
        try writer.writeU64(self.activation_generation);
        try writer.writeU64(self.rollback_generation);
        try writer.writeByte(@intCast(self.slots.len));
        for (self.slots, 0..) |slot, index| {
            try writer.writeByte(@intCast(index));
            try writeLengthPrefixed(&writer, slot.labelSlice());
            try writer.writeU64(slot.object_id);
            try writer.writeU64(slot.version_id);
            try writer.writeByte(@intFromBool(slot.read_only));
        }
        return buffer[0..writer.offset];
    }

    fn decode(self: *Manager, payload: []const u8) Error!void {
        self.active_slot = empty_slot;
        self.last_good_slot = empty_slot;
        self.pending_slot = empty_slot;
        self.activation_generation = 0;
        self.rollback_generation = 0;
        self.slots = [_]SystemImage{zeroImage()} ** MAX_SYSTEM_IMAGES;

        var reader = BinaryReader{ .buffer = payload };
        const domain = try reader.readSlice("zigos.immutable-base.state".len);
        if (!std.mem.eql(u8, domain, "zigos.immutable-base.state")) return error.CorruptState;
        self.active_slot = try readSlot(&reader);
        self.last_good_slot = try readSlot(&reader);
        self.pending_slot = try readSlot(&reader);
        self.activation_generation = try reader.readU64();
        self.rollback_generation = try reader.readU64();
        const slot_count = try reader.readByte();
        if (slot_count != MAX_SYSTEM_IMAGES) return error.CorruptState;
        for (0..slot_count) |_| {
            const slot_index = try reader.readByte();
            if (slot_index >= MAX_SYSTEM_IMAGES) return error.CorruptState;
            try self.decodeSlot(slot_index, &reader);
        }
        if (reader.offset != payload.len) return error.CorruptState;

        for (0..MAX_SYSTEM_IMAGES) |slot_index| {
            if (self.slots[slot_index].version_id == 0) continue;
            try self.hydrateSlot(slot_index);
        }
    }

    fn decodeSlot(self: *Manager, slot_index: usize, reader: *BinaryReader) Error!void {
        const label = try readLengthPrefixed(reader);
        const slot = &self.slots[slot_index];
        slot.* = zeroImage();
        slot.slot_index = @intCast(slot_index);
        slot.label_len = @intCast(try native_util.copyTextExact(&slot.label, label));
        slot.object_id = try reader.readU64();
        slot.version_id = try reader.readU64();
        slot.read_only = switch (try reader.readByte()) {
            0 => false,
            1 => true,
            else => return error.CorruptState,
        };
        slot.activation_generation = self.activation_generation;
    }

    fn hydrateSlot(self: *Manager, slot_index: usize) Error!void {
        const slot = &self.slots[slot_index];
        const version = self.storage.version(slot.version_id) orelse return error.CorruptState;
        const blob = self.storage.versionBlob(version) orelse return error.CorruptState;
        slot.signer_len = @intCast(try native_util.copyTextExact(&slot.signer, version.metadata.signature.signer));
        slot.measurement = blob.address;
    }
};

comptime {
    if (@sizeOf(SystemImage) > SYSTEM_IMAGE_SIZE_CEILING_BYTES or
        @sizeOf(BootSelection) > BOOT_SELECTION_SIZE_CEILING_BYTES or
        @sizeOf(Manager) > MANAGER_SIZE_CEILING_BYTES)
    {
        @compileError("immutable base state exceeds compact layout ceilings");
    }
}

fn zeroImage() SystemImage {
    return .{
        .slot_index = empty_slot,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .object_id = 0,
        .version_id = 0,
        .read_only = false,
        .activation_generation = 0,
        .signer_len = 0,
        .signer = [_]u8{0} ** MAX_LABEL_BYTES,
        .measurement = crypto_hash.zero_digest,
    };
}

const BinaryWriter = binary_cursor.Writer(Error, error.NoSpaceLeft);
const BinaryReader = binary_cursor.Reader(Error, error.CorruptState);

fn writeLengthPrefixed(writer: *BinaryWriter, bytes: []const u8) Error!void {
    if (bytes.len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    try writer.writeU16(@intCast(bytes.len));
    try writer.writeBytes(bytes);
}

fn readLengthPrefixed(reader: *BinaryReader) Error![]const u8 {
    const len = try reader.readU16();
    return reader.readSlice(len);
}

fn readSlot(reader: *BinaryReader) Error!u8 {
    const value = try reader.readByte();
    if (value == empty_slot) return empty_slot;
    if (value >= MAX_SYSTEM_IMAGES) return error.CorruptState;
    return value;
}

fn hashId(seed: u64, text: []const u8) u64 {
    return native_util.fnv1a64WithSeed(seed, text);
}

fn stateObjectId() u64 {
    return hashId(0xB66D4D66A5A5C001, "platform:immutable-base:state");
}

test "immutable base metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(SystemImage, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(SystemImage, "signer_len"));
    try std.testing.expectEqual(u8, @FieldType(BootSelection, "signer_len"));
    try std.testing.expectEqual(@as(usize, 160), @sizeOf(SystemImage));
    try std.testing.expectEqual(@as(usize, 120), @sizeOf(BootSelection));
    try std.testing.expectEqual(@as(usize, 424), @sizeOf(Manager));
}

fn imageObjectId(slot_index: usize) u64 {
    return hashId(0xB66D4D66A5A5C101 + @as(u64, @intCast(slot_index)), "platform:immutable-base:image");
}

test "immutable base persists signed read-only image activation and rollback metadata" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 61 };
    const state_signer = signing.SignerIdentity{
        .label = "platform-state",
        .seed = signing.seedFromByte(0x61),
    };
    const image_signer = signing.SignerIdentity{
        .label = "platform-image",
        .seed = signing.seedFromByte(0x62),
    };

    var storage = storage_service.Service.initWithStore(901, 41, owner, &storage_checkpoint_store);
    var manager = try Manager.init(&storage, owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    try manager.beginActivation(0, 11);
    try std.testing.expectEqualStrings("stable-a", manager.activeImage().?.labelSlice());
    const stable = try manager.finalizeActivation(.{}, 12);
    try std.testing.expectEqual(@as(?usize, 0), stable.active_slot);

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 12);
    try manager.beginActivation(1, 13);
    try std.testing.expectEqualStrings("stable-b", manager.activeImage().?.labelSlice());
    const failed = try manager.finalizeActivation(.{ .ui_ok = false }, 14);
    try std.testing.expect(failed.rolled_back);
    try std.testing.expectEqual(HealthFailure.ui, failed.failure);
    try std.testing.expectEqual(@as(?usize, 0), failed.active_slot);

    const activated = try manager.activate(1, .{}, 15);
    try std.testing.expect(!activated.rolled_back);
    try std.testing.expectEqual(@as(?usize, 1), activated.active_slot);
    try std.testing.expect(manager.verifyActiveImage());
    const selected = try manager.selectVerifiedBootImage();
    try std.testing.expectEqual(@as(u8, 1), selected.slot_index);
    try std.testing.expectEqual(manager.activeImage().?.version_id, selected.version_id);
    try std.testing.expectEqualStrings("platform-image", selected.signerSlice());

    var restarted_storage = storage_service.Service.initWithStore(901, 42, owner, &storage_checkpoint_store);
    var restarted = try Manager.init(&restarted_storage, owner, state_signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(u8, 1), restarted.active_slot);
    try std.testing.expectEqual(@as(u64, 1), restarted.rollback_generation);
    try std.testing.expect(restarted.verifyActiveImage());
    try std.testing.expectEqual(@as(u8, 1), (try restarted.selectVerifiedBootImage()).slot_index);

    storage_checkpoint_store.resetPersistent();
}

test "immutable base verification rejects mutable signer and measurement tampering" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 62 };
    const state_signer = signing.SignerIdentity{
        .label = "platform-state",
        .seed = signing.seedFromByte(0x63),
    };
    const image_signer = signing.SignerIdentity{
        .label = "platform-image",
        .seed = signing.seedFromByte(0x64),
    };

    var storage = storage_service.Service.initWithStore(902, 43, owner, &storage_checkpoint_store);
    var manager = try Manager.init(&storage, owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);
    try std.testing.expect(manager.verifyActiveImage());

    manager.slots[0].read_only = false;
    try std.testing.expect(!manager.verifyActiveImage());
    manager.slots[0].read_only = true;
    try std.testing.expect(manager.verifyActiveImage());

    manager.slots[0].measurement[0] ^= 0xFF;
    try std.testing.expect(!manager.verifyActiveImage());
    manager.slots[0].measurement[0] ^= 0xFF;
    try std.testing.expect(manager.verifyActiveImage());

    manager.slots[0].signer[0] = 'x';
    try std.testing.expect(!manager.verifyActiveImage());
    try std.testing.expectError(error.ImageVerificationFailed, manager.selectVerifiedBootImage());

    storage_checkpoint_store.resetPersistent();
}
