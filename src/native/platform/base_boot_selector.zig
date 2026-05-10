const builtin = @import("builtin");
const std = @import("std");
const immutable_base = @import("immutable_base.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");

pub const sector_lba: u64 = 1792;
pub const sector_size: usize = 512;
pub const active_slot_line_prefix = "ZIGOS:PLATFORM:BASE_SELECTOR:ACTIVE_SLOT ";

const magic = "ZBOS";
const version: u16 = 1;
const empty_slot: u8 = 0xFF;
const selection_record_size: usize = 128;
const magic_offset: usize = 0;
const version_offset: usize = 4;
const state_offset: usize = 6;
const active_slot_offset: usize = 7;
const pending_slot_offset: usize = 8;
const last_good_slot_offset: usize = 9;
const service_use_started_offset: usize = 10;
const activation_generation_offset: usize = 16;
const rollback_generation_offset: usize = 24;
const last_tick_offset: usize = 32;
const active_selection_offset: usize = 48;
const pending_selection_offset: usize = active_selection_offset + selection_record_size;

const root_storage = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapAtaRead(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        extern fn zigosStorageBootstrapAtaWrite(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]const u8,
            buffer_len: usize,
        ) callconv(.c) bool;
    }
else
    struct {};

pub const Error = error{
    ActivationSlotMismatch,
    CorruptSelectorRecord,
    ImageVerificationFailed,
    MissingPendingSelection,
    MissingStableSelection,
    NoSelectorRecord,
    RollbackAfterServiceUse,
    SelectorReadFailed,
    SelectorWriteFailed,
};

pub const State = enum(u8) {
    empty,
    stable,
    pending,
};

pub const Decision = struct {
    active_slot: ?usize,
    candidate_slot: ?usize = null,
    failure: immutable_base.HealthFailure,
    rolled_back: bool = false,
    promoted: bool = false,
    activation_generation: u64,
    rollback_generation: u64,
    service_use_started: bool = false,
};

pub const MemorySector = struct {
    bytes: [sector_size]u8 = [_]u8{0} ** sector_size,
    present: bool = false,

    pub fn init() MemorySector {
        return .{};
    }

    pub fn read(self: *const MemorySector, out: *[sector_size]u8) bool {
        if (!self.present) return false;
        out.* = self.bytes;
        return true;
    }

    pub fn write(self: *MemorySector, bytes: *const [sector_size]u8) bool {
        self.bytes = bytes.*;
        self.present = true;
        return true;
    }
};

pub const Selector = struct {
    state: State = .empty,
    active: ?immutable_base.BootSelection = null,
    pending: ?immutable_base.BootSelection = null,
    last_good_slot: u8 = empty_slot,
    service_use_started: bool = false,
    activation_generation: u64 = 0,
    rollback_generation: u64 = 0,
    last_tick: u64 = 0,

    pub fn init() Selector {
        return .{};
    }

    pub fn bindStable(
        self: *Selector,
        manager: *const immutable_base.Manager,
        selection: immutable_base.BootSelection,
        tick: u64,
    ) Error!Decision {
        if (!verifiedManagerSelection(manager, selection)) return error.ImageVerificationFailed;
        self.state = .stable;
        self.active = selection;
        self.pending = null;
        self.last_good_slot = selection.slot_index;
        self.service_use_started = false;
        self.activation_generation = selection.activation_generation;
        self.rollback_generation = selection.rollback_generation;
        self.last_tick = tick;
        return self.decision(.none, false, true);
    }

    pub fn stageCandidate(
        self: *Selector,
        manager: *const immutable_base.Manager,
        selection: immutable_base.BootSelection,
        tick: u64,
    ) Error!Decision {
        const active = self.active orelse return error.MissingStableSelection;
        if (!verifiedManagerSelection(manager, selection)) return error.ImageVerificationFailed;
        if (active.slot_index == selection.slot_index) return error.ActivationSlotMismatch;

        self.state = .pending;
        self.pending = selection;
        self.last_good_slot = active.slot_index;
        self.service_use_started = false;
        self.activation_generation = selection.activation_generation;
        self.rollback_generation = selection.rollback_generation;
        self.last_tick = tick;
        return self.decision(.none, false, false);
    }

    pub fn selectBootCandidate(
        self: *const Selector,
        manager: *const immutable_base.Manager,
    ) Error!immutable_base.BootSelection {
        if (self.state == .pending) {
            const pending = self.pending orelse return error.MissingPendingSelection;
            if (!verifiedManagerSelection(manager, pending)) return error.ImageVerificationFailed;
            return pending;
        }
        const active = self.active orelse return error.MissingStableSelection;
        if (!verifiedManagerSelection(manager, active)) return error.ImageVerificationFailed;
        return active;
    }

    pub fn markServiceUseStarted(self: *Selector) void {
        self.service_use_started = true;
    }

    pub fn finalizeBoot(
        self: *Selector,
        report: immutable_base.HealthReport,
        service_use_started: bool,
        tick: u64,
    ) Error!Decision {
        if (self.state != .pending) {
            const active = self.active orelse return error.MissingStableSelection;
            self.activation_generation = active.activation_generation;
            self.rollback_generation = active.rollback_generation;
            self.last_tick = tick;
            return self.decision(report.failure(), false, false);
        }

        const candidate = self.pending orelse return error.MissingPendingSelection;
        const failure = report.failure();
        if (failure != .none) {
            if (service_use_started or self.service_use_started) return error.RollbackAfterServiceUse;
            var active = self.active orelse return error.MissingStableSelection;
            self.rollback_generation = candidate.rollback_generation + 1;
            self.activation_generation = candidate.activation_generation;
            active.activation_generation = self.activation_generation;
            active.rollback_generation = self.rollback_generation;
            self.active = active;
            self.pending = null;
            self.state = .stable;
            self.service_use_started = false;
            self.last_tick = tick;
            return self.decision(failure, true, false);
        }

        self.active = candidate;
        self.pending = null;
        self.state = .stable;
        self.last_good_slot = candidate.slot_index;
        self.service_use_started = false;
        self.activation_generation = candidate.activation_generation;
        self.rollback_generation = candidate.rollback_generation;
        self.last_tick = tick;
        return self.decision(.none, false, true);
    }

    pub fn activeSelection(self: *const Selector) ?immutable_base.BootSelection {
        return self.active;
    }

    pub fn activeSlotIndex(self: *const Selector) ?usize {
        const active = self.active orelse return null;
        return active.slot_index;
    }

    pub fn coldRebootVerified(self: *const Selector, expected_slot: usize, expected_generation: u64) bool {
        const active = self.active orelse return false;
        return self.state == .stable and
            active.slot_index == expected_slot and
            self.activation_generation == expected_generation and
            active.activation_generation == expected_generation and
            self.pending == null;
    }

    pub fn persistToMemory(self: *const Selector, store: *MemorySector) Error!void {
        var sector = [_]u8{0} ** sector_size;
        try self.encode(&sector);
        if (!store.write(&sector)) return error.SelectorWriteFailed;
    }

    pub fn loadFromMemory(self: *Selector, store: *const MemorySector) Error!void {
        var sector = [_]u8{0} ** sector_size;
        if (!store.read(&sector)) return error.NoSelectorRecord;
        try self.decode(&sector);
    }

    pub fn persistToRootVolume(self: *const Selector) Error!void {
        var sector = [_]u8{0} ** sector_size;
        try self.encode(&sector);
        if (!writeRootVolumeSector(&sector)) return error.SelectorWriteFailed;
    }

    pub fn loadFromRootVolume(self: *Selector) Error!void {
        var sector = [_]u8{0} ** sector_size;
        if (!readRootVolumeSector(&sector)) return error.SelectorReadFailed;
        try self.decode(&sector);
    }

    fn decision(
        self: *const Selector,
        failure: immutable_base.HealthFailure,
        rolled_back: bool,
        promoted: bool,
    ) Error!Decision {
        const active = self.active orelse return error.MissingStableSelection;
        return .{
            .active_slot = active.slot_index,
            .candidate_slot = if (self.pending) |pending| pending.slot_index else null,
            .failure = failure,
            .rolled_back = rolled_back,
            .promoted = promoted,
            .activation_generation = self.activation_generation,
            .rollback_generation = self.rollback_generation,
            .service_use_started = self.service_use_started,
        };
    }

    fn encode(self: *const Selector, sector: *[sector_size]u8) Error!void {
        @memset(sector[0..], 0);
        @memcpy(sector[magic_offset..][0..magic.len], magic);
        std.mem.writeInt(u16, sector[version_offset..][0..@sizeOf(u16)], version, .little);
        sector[state_offset] = @intFromEnum(self.state);
        sector[active_slot_offset] = if (self.active) |active| active.slot_index else empty_slot;
        sector[pending_slot_offset] = if (self.pending) |pending| pending.slot_index else empty_slot;
        sector[last_good_slot_offset] = self.last_good_slot;
        sector[service_use_started_offset] = @intFromBool(self.service_use_started);
        std.mem.writeInt(u64, sector[activation_generation_offset..][0..@sizeOf(u64)], self.activation_generation, .little);
        std.mem.writeInt(u64, sector[rollback_generation_offset..][0..@sizeOf(u64)], self.rollback_generation, .little);
        std.mem.writeInt(u64, sector[last_tick_offset..][0..@sizeOf(u64)], self.last_tick, .little);
        if (self.active) |active| encodeSelection(sector[active_selection_offset..][0..selection_record_size], active);
        if (self.pending) |pending| encodeSelection(sector[pending_selection_offset..][0..selection_record_size], pending);
    }

    fn decode(self: *Selector, sector: *const [sector_size]u8) Error!void {
        if (std.mem.allEqual(u8, sector[0..], 0)) return error.NoSelectorRecord;
        if (!std.mem.eql(u8, sector[magic_offset..][0..magic.len], magic)) return error.CorruptSelectorRecord;
        if (std.mem.readInt(u16, sector[version_offset..][0..@sizeOf(u16)], .little) != version) return error.CorruptSelectorRecord;

        const decoded_state: State = switch (sector[state_offset]) {
            @intFromEnum(State.empty) => .empty,
            @intFromEnum(State.stable) => .stable,
            @intFromEnum(State.pending) => .pending,
            else => return error.CorruptSelectorRecord,
        };
        const decoded_active_slot = try decodeSlotByte(sector[active_slot_offset]);
        const decoded_pending_slot = try decodeSlotByte(sector[pending_slot_offset]);
        const decoded_last_good_slot = try decodeSlotByte(sector[last_good_slot_offset]);
        const decoded_service_use_started = switch (sector[service_use_started_offset]) {
            0 => false,
            1 => true,
            else => return error.CorruptSelectorRecord,
        };

        const decoded_active = if (decoded_active_slot == empty_slot)
            null
        else
            try decodeSelection(sector[active_selection_offset..][0..selection_record_size]);
        const decoded_pending = if (decoded_pending_slot == empty_slot)
            null
        else
            try decodeSelection(sector[pending_selection_offset..][0..selection_record_size]);

        if (decoded_active) |active| {
            if (active.slot_index != decoded_active_slot) return error.CorruptSelectorRecord;
        }
        if (decoded_pending) |pending| {
            if (pending.slot_index != decoded_pending_slot) return error.CorruptSelectorRecord;
        }
        switch (decoded_state) {
            .empty => {
                if (decoded_active != null or decoded_pending != null) return error.CorruptSelectorRecord;
            },
            .stable => {
                if (decoded_active == null or decoded_pending != null) return error.CorruptSelectorRecord;
            },
            .pending => {
                if (decoded_active == null or decoded_pending == null) return error.CorruptSelectorRecord;
            },
        }

        self.* = .{
            .state = decoded_state,
            .active = decoded_active,
            .pending = decoded_pending,
            .last_good_slot = decoded_last_good_slot,
            .service_use_started = decoded_service_use_started,
            .activation_generation = std.mem.readInt(u64, sector[activation_generation_offset..][0..@sizeOf(u64)], .little),
            .rollback_generation = std.mem.readInt(u64, sector[rollback_generation_offset..][0..@sizeOf(u64)], .little),
            .last_tick = std.mem.readInt(u64, sector[last_tick_offset..][0..@sizeOf(u64)], .little),
        };
    }
};

pub fn verifiedManagerSelection(
    manager: *const immutable_base.Manager,
    selection: immutable_base.BootSelection,
) bool {
    if (selection.slot_index >= immutable_base.MAX_SYSTEM_IMAGES) return false;
    if (!manager.verifySlot(selection.slot_index)) return false;
    const image = &manager.slots[selection.slot_index];
    return image.object_id == selection.object_id and
        image.version_id == selection.version_id and
        image.activation_generation <= selection.activation_generation and
        std.mem.eql(u8, &image.measurement, &selection.measurement) and
        image.signer_len == selection.signer_len and
        std.mem.eql(u8, image.signerSlice(), selection.signerSlice());
}

fn encodeSelection(bytes: []u8, selection: immutable_base.BootSelection) void {
    @memset(bytes[0..selection_record_size], 0);
    bytes[0] = selection.slot_index;
    bytes[1] = @intCast(selection.signer_len);
    std.mem.writeInt(u64, bytes[8..16], selection.object_id, .little);
    std.mem.writeInt(u64, bytes[16..24], selection.version_id, .little);
    std.mem.writeInt(u64, bytes[24..32], selection.activation_generation, .little);
    std.mem.writeInt(u64, bytes[32..40], selection.rollback_generation, .little);
    @memcpy(bytes[40..72], &selection.measurement);
    @memcpy(bytes[72..][0..selection.signer_len], selection.signer[0..selection.signer_len]);
}

fn decodeSelection(bytes: []const u8) Error!immutable_base.BootSelection {
    const slot_index = try decodeSlotByte(bytes[0]);
    if (slot_index == empty_slot) return error.CorruptSelectorRecord;
    const signer_len = bytes[1];
    if (signer_len > immutable_base.MAX_LABEL_BYTES) return error.CorruptSelectorRecord;

    var measurement = [_]u8{0} ** 32;
    var signer = [_]u8{0} ** immutable_base.MAX_LABEL_BYTES;
    @memcpy(&measurement, bytes[40..72]);
    @memcpy(signer[0..signer_len], bytes[72..][0..signer_len]);
    return .{
        .slot_index = slot_index,
        .object_id = std.mem.readInt(u64, bytes[8..16], .little),
        .version_id = std.mem.readInt(u64, bytes[16..24], .little),
        .activation_generation = std.mem.readInt(u64, bytes[24..32], .little),
        .rollback_generation = std.mem.readInt(u64, bytes[32..40], .little),
        .measurement = measurement,
        .signer_len = signer_len,
        .signer = signer,
    };
}

fn decodeSlotByte(value: u8) Error!u8 {
    if (value == empty_slot) return empty_slot;
    if (value >= immutable_base.MAX_SYSTEM_IMAGES) return error.CorruptSelectorRecord;
    return value;
}

fn readRootVolumeSector(buffer: *[sector_size]u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_backend_sector_count <= sector_lba) return false;
    if (root_volume.attached_ata_device) |device| {
        return root_storage.zigosStorageBootstrapAtaRead(device, sector_lba, buffer.ptr, buffer.len);
    }
    return root_volume.attached_backend_read(sector_lba, buffer.ptr, buffer.len);
}

fn writeRootVolumeSector(buffer: *const [sector_size]u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_backend_sector_count <= sector_lba) return false;
    if (root_volume.attached_ata_device) |device| {
        return root_storage.zigosStorageBootstrapAtaWrite(device, sector_lba, buffer.ptr, buffer.len);
    }
    return root_volume.attached_backend_write(sector_lba, buffer.ptr, buffer.len);
}

test "freestanding base boot selector promotes and rolls back signed artifacts across reboot" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 71 };
    const state_signer = signing.SignerIdentity{
        .label = "selector-state",
        .seed = [_]u8{0x71} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "selector-image",
        .seed = [_]u8{0x72} ** 32,
    };

    var storage = storage_service.Service.initWithStore(971, 81, owner, &storage_checkpoint_store);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);
    var store = MemorySector.init();
    var selector = Selector.init();

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    const stable_activation = try manager.activate(0, .{}, 11);
    try std.testing.expectEqual(@as(?usize, 0), stable_activation.active_slot);
    _ = try selector.bindStable(&manager, try manager.selectVerifiedBootImage(), 12);
    try selector.persistToMemory(&store);

    var rebooted = Selector.init();
    try rebooted.loadFromMemory(&store);
    try std.testing.expect(rebooted.coldRebootVerified(0, stable_activation.activation_generation));

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 13);
    try manager.beginActivation(1, 14);
    const candidate = try manager.selectVerifiedBootImage();
    _ = try rebooted.stageCandidate(&manager, candidate, 14);
    try rebooted.persistToMemory(&store);
    try std.testing.expectEqual(@as(u8, 1), (try rebooted.selectBootCandidate(&manager)).slot_index);

    const promoted_manager = try manager.finalizeActivation(.{}, 15);
    const promoted_selector = try rebooted.finalizeBoot(.{}, false, 15);
    try std.testing.expect(!promoted_manager.rolled_back);
    try std.testing.expect(promoted_selector.promoted);
    try std.testing.expectEqual(promoted_manager.active_slot, promoted_selector.active_slot);
    try rebooted.persistToMemory(&store);

    var after_promote_reboot = Selector.init();
    try after_promote_reboot.loadFromMemory(&store);
    try std.testing.expect(after_promote_reboot.coldRebootVerified(1, promoted_manager.activation_generation));

    _ = try manager.stageImage(0, "stable-a", "kernel=v3", image_signer, 16);
    try manager.beginActivation(0, 17);
    const failed_candidate = try manager.selectVerifiedBootImage();
    _ = try after_promote_reboot.stageCandidate(&manager, failed_candidate, 17);
    const failed_manager = try manager.finalizeActivation(.{ .network_ok = false }, 18);
    const failed_selector = try after_promote_reboot.finalizeBoot(.{ .network_ok = false }, false, 18);
    try std.testing.expect(failed_manager.rolled_back);
    try std.testing.expect(failed_selector.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.network, failed_selector.failure);
    try std.testing.expectEqual(failed_manager.active_slot, failed_selector.active_slot);
    try std.testing.expectEqual(failed_manager.activation_generation, failed_selector.activation_generation);
    try std.testing.expectEqual(failed_manager.rollback_generation, failed_selector.rollback_generation);
    try after_promote_reboot.persistToMemory(&store);

    var after_rollback_reboot = Selector.init();
    try after_rollback_reboot.loadFromMemory(&store);
    try std.testing.expect(after_rollback_reboot.coldRebootVerified(1, failed_manager.activation_generation));

    _ = try manager.stageImage(0, "stable-a", "kernel=v4", image_signer, 19);
    try manager.beginActivation(0, 20);
    _ = try after_rollback_reboot.stageCandidate(&manager, try manager.selectVerifiedBootImage(), 20);
    after_rollback_reboot.markServiceUseStarted();
    try std.testing.expectError(
        error.RollbackAfterServiceUse,
        after_rollback_reboot.finalizeBoot(.{ .storage_ok = false }, false, 21),
    );
}

test "base boot selector rejects tampered manager slot before boot handoff" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 72 };
    const state_signer = signing.SignerIdentity{
        .label = "selector-state",
        .seed = [_]u8{0x73} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "selector-image",
        .seed = [_]u8{0x74} ** 32,
    };

    var storage = storage_service.Service.initWithStore(972, 82, owner, &storage_checkpoint_store);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const selected = try manager.selectVerifiedBootImage();
    manager.slots[0].measurement[0] ^= 0xFF;

    var selector = Selector.init();
    try std.testing.expectError(
        error.ImageVerificationFailed,
        selector.bindStable(&manager, selected, 12),
    );
}
