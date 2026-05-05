const std = @import("std");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const copyText = native_util.copyText;

pub const MAX_SYSTEM_IMAGES: usize = 2;
pub const MAX_LABEL_BYTES: usize = 48;
pub const state_workspace_label = "system-base";

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
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    object_id: u64,
    version_id: u64,
    read_only: bool,
    activation_generation: u64,
    signer_len: usize,
    signer: [MAX_LABEL_BYTES]u8,
    measurement: object_store.BlobAddress,

    pub fn labelSlice(self: *const SystemImage) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn signerSlice(self: *const SystemImage) []const u8 {
        return self.signer[0..self.signer_len];
    }
};

pub const ActivationResult = struct {
    active_slot: ?usize,
    activation_generation: u64,
    rollback_generation: u64,
    failure: HealthFailure,
    rolled_back: bool,
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
        workspace_id: u64,
    ) Error!Manager {
        var manager = Manager{
            .storage = storage,
            .owner = owner,
            .state_signer = state_signer,
            .workspace_id = workspace_id,
        };

        if (storage.resolve(workspace_id, state_entry_path)) |entry| {
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

        const result = try self.storage.putVersion(.{
            .preferred_object_id = imageObjectId(slot_index),
            .object_type = .model_artifact,
            .payload = payload,
            .metadata = try object_store.signMetadata(
                signer,
                label,
                "application/zigos-system-image",
                .model_artifact,
                payload,
                tick,
            ),
        });

        const slot = &self.slots[slot_index];
        slot.* = zeroImage();
        slot.slot_index = @intCast(slot_index);
        slot.label_len = copyText(&slot.label, label);
        slot.object_id = result.object_id;
        slot.version_id = result.version_id;
        slot.read_only = true;
        slot.activation_generation = self.activation_generation;
        slot.signer_len = copyText(&slot.signer, signer.label);
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
        if (version.object_id != image.object_id or version.object_type != .model_artifact) return false;
        if (!version.metadata.isSigned() or !version.metadata.signature.isComplete()) return false;
        const payload = self.storage.versionPayload(version) catch return false;
        if (!version.metadata.verifyFor(.model_artifact, payload)) return false;
        if (!std.mem.eql(u8, version.metadata.signature.signer, image.signerSlice())) return false;
        return std.mem.eql(u8, &version.blob_address, &image.measurement);
    }

    fn persist(self: *Manager, tick: u64) Error!void {
        var payload: [512]u8 = undefined;
        const encoded = try self.encode(payload[0..]);
        const existing_entry = self.storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const result = try self.storage.putVersion(.{
            .preferred_object_id = stateObjectId(),
            .object_type = .document,
            .payload = encoded,
            .metadata = try object_store.signMetadata(
                self.state_signer,
                "immutable-base-state",
                "application/zigos-immutable-base",
                .document,
                encoded,
                tick,
            ),
            .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
        });
        try self.storage.beginTransaction(self.workspace_id);
        try self.storage.stagePut(self.workspace_id, state_entry_path, result.object_id, result.version_id, .document);
        _ = try self.storage.commit(self.workspace_id, tick);
    }

    fn encode(self: *const Manager, buffer: []u8) Error![]const u8 {
        var written = try std.fmt.bufPrint(
            buffer,
            "v1|a={d}|l={d}|p={d}|ag={d}|rg={d}",
            .{
                self.active_slot,
                self.last_good_slot,
                self.pending_slot,
                self.activation_generation,
                self.rollback_generation,
            },
        );
        for (self.slots, 0..) |slot, index| {
            const suffix = try std.fmt.bufPrint(
                buffer[written.len..],
                "|s{d}={s},{d},{d},{d}",
                .{
                    index,
                    slot.labelSlice(),
                    slot.object_id,
                    slot.version_id,
                    @intFromBool(slot.read_only),
                },
            );
            written = buffer[0 .. written.len + suffix.len];
        }
        return written;
    }

    fn decode(self: *Manager, payload: []const u8) Error!void {
        self.active_slot = empty_slot;
        self.last_good_slot = empty_slot;
        self.pending_slot = empty_slot;
        self.activation_generation = 0;
        self.rollback_generation = 0;
        self.slots = [_]SystemImage{zeroImage()} ** MAX_SYSTEM_IMAGES;

        var parts = std.mem.splitScalar(u8, payload, '|');
        const version = parts.next() orelse return error.CorruptState;
        if (!std.mem.eql(u8, version, "v1")) return error.CorruptState;

        while (parts.next()) |part| {
            if (part.len == 0) continue;
            if (std.mem.startsWith(u8, part, "a=")) {
                self.active_slot = try parseSlot(part[2..]);
                continue;
            }
            if (std.mem.startsWith(u8, part, "l=")) {
                self.last_good_slot = try parseSlot(part[2..]);
                continue;
            }
            if (std.mem.startsWith(u8, part, "p=")) {
                self.pending_slot = try parseSlot(part[2..]);
                continue;
            }
            if (std.mem.startsWith(u8, part, "ag=")) {
                self.activation_generation = try std.fmt.parseInt(u64, part[3..], 10);
                continue;
            }
            if (std.mem.startsWith(u8, part, "rg=")) {
                self.rollback_generation = try std.fmt.parseInt(u64, part[3..], 10);
                continue;
            }
            if (part.len >= 4 and part[0] == 's' and part[2] == '=') {
                const slot_index = parseSlotIndex(part[1]) orelse return error.CorruptState;
                try self.decodeSlot(slot_index, part[3..]);
                continue;
            }
            return error.CorruptState;
        }

        for (0..MAX_SYSTEM_IMAGES) |slot_index| {
            if (self.slots[slot_index].version_id == 0) continue;
            try self.hydrateSlot(slot_index);
        }
    }

    fn decodeSlot(self: *Manager, slot_index: usize, payload: []const u8) Error!void {
        var field_iter = std.mem.splitScalar(u8, payload, ',');
        const label = field_iter.next() orelse return error.CorruptState;
        const object_id_text = field_iter.next() orelse return error.CorruptState;
        const version_id_text = field_iter.next() orelse return error.CorruptState;
        const read_only_text = field_iter.next() orelse return error.CorruptState;
        if (field_iter.next() != null) return error.CorruptState;

        const slot = &self.slots[slot_index];
        slot.* = zeroImage();
        slot.slot_index = @intCast(slot_index);
        slot.label_len = copyText(&slot.label, label);
        slot.object_id = try std.fmt.parseInt(u64, object_id_text, 10);
        slot.version_id = try std.fmt.parseInt(u64, version_id_text, 10);
        slot.read_only = try std.fmt.parseInt(u8, read_only_text, 10) != 0;
        slot.activation_generation = self.activation_generation;
    }

    fn hydrateSlot(self: *Manager, slot_index: usize) Error!void {
        const slot = &self.slots[slot_index];
        const version = self.storage.version(slot.version_id) orelse return error.CorruptState;
        slot.signer_len = copyText(&slot.signer, version.metadata.signature.signer);
        slot.measurement = version.blob_address;
    }
};

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
        .measurement = [_]u8{0} ** 32,
    };
}

fn parseSlot(text: []const u8) Error!u8 {
    const value = try std.fmt.parseInt(u16, text, 10);
    if (value == empty_slot) return empty_slot;
    if (value >= MAX_SYSTEM_IMAGES) return error.CorruptState;
    return @intCast(value);
}

fn parseSlotIndex(ascii_digit: u8) ?usize {
    if (ascii_digit < '0' or ascii_digit > '9') return null;
    const value = ascii_digit - '0';
    if (value >= MAX_SYSTEM_IMAGES) return null;
    return value;
}

fn hashId(seed: u64, text: []const u8) u64 {
    return native_util.fnv1a64WithSeed(seed, text);
}

fn stateObjectId() u64 {
    return hashId(0xB66D4D66A5A5C001, "platform:immutable-base:state");
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
        .seed = [_]u8{0x61} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "platform-image",
        .seed = [_]u8{0x62} ** 32,
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

    var restarted_storage = storage_service.Service.initWithStore(901, 42, owner, &storage_checkpoint_store);
    var restarted = try Manager.init(&restarted_storage, owner, state_signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(u8, 1), restarted.active_slot);
    try std.testing.expectEqual(@as(u64, 1), restarted.rollback_generation);
    try std.testing.expect(restarted.verifyActiveImage());

    storage_checkpoint_store.resetPersistent();
}

test "immutable base verification rejects mutable signer and measurement tampering" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 62 };
    const state_signer = signing.SignerIdentity{
        .label = "platform-state",
        .seed = [_]u8{0x63} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "platform-image",
        .seed = [_]u8{0x64} ** 32,
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

    storage_checkpoint_store.resetPersistent();
}
