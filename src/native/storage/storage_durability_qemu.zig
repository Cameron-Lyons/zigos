const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("storage_service.zig");
const storage_volume = @import("storage_volume.zig");
const volume_backend = @import("volume/backend.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const proof_lba: u64 = storage_volume.required_device_sectors + @as(u64, storage_volume.slot_sectors) * @as(u64, storage_volume.slot_count);
const proof_magic = "ZSDP";
const proof_version: u16 = 1;
const proof_sector_size: usize = storage_volume.sector_size;
const proof_version_offset: usize = proof_magic.len;
const proof_phase_offset: usize = proof_version_offset + @sizeOf(u16);
const proof_reserved_bytes_after_phase: usize = 1;
const proof_checksum_offset: usize = proof_phase_offset + @sizeOf(u8) + proof_reserved_bytes_after_phase;

const owner = principal.PrincipalId{ .kind = .user, .serial = 44_200 };
const workspace_label = "durability-workspace";
const baseline_path = "documents/durable.md";
const interrupted_path = "documents/interrupted.md";
const final_path = "documents/final.md";
const baseline_payload = "baseline checkpointed before forced reboot";
const interrupted_payload = "dirty write staged before forced reboot";
const final_payload = "final checkpointed before root-slot fault";
const baseline_object_id = object_store.ids.object(0xD00D_0001);
const interrupted_object_id = object_store.ids.object(0xD00D_0002);
const final_object_id = object_store.ids.object(0xD00D_0003);
const signer = signing.SignerIdentity{
    .label = "zigos-storage-durability",
    .seed = signing.seedFromByte(0xD4),
};

const Phase = enum(u8) {
    empty = 0,
    baseline_checkpointed = 1,
    dirty_write_staged = 2,
    final_checkpointed = 3,
};

pub fn run(storage: *storage_service.Service) bool {
    common.printBootMarker(boot_markers.storage_durability_start);

    return switch (loadPhase()) {
        .empty => checkpointBaseline(storage),
        .baseline_checkpointed => stageInterruptedWrite(storage),
        .dirty_write_staged => recoverInterruptedBootAndCheckpointFinal(storage),
        .final_checkpointed => recoverAfterBadRootSlot(storage),
    };
}

fn checkpointBaseline(storage: *storage_service.Service) bool {
    if (storage.loaded_from_volume) return false;
    const workspace_id = ensureWorkspace(storage) catch return false;
    _ = putDocument(storage, baseline_object_id, "baseline", baseline_payload, null, 10) catch return false;
    if (!putPath(storage, workspace_id, baseline_path, baseline_object_id, 10)) return false;
    storage.checkpoint();
    if (!storage.checkpoint_store.checkpointHealthy()) return false;
    if (!storePhase(.baseline_checkpointed)) return false;
    common.printBootMarker(boot_markers.storage_durability_baseline_checkpointed);
    return true;
}

fn stageInterruptedWrite(storage: *storage_service.Service) bool {
    if (!storage.loaded_from_volume) return false;
    const workspace_id = validateBaseline(storage) catch return false;
    _ = putDocument(storage, interrupted_object_id, "interrupted", interrupted_payload, null, 20) catch return false;
    if (!putPath(storage, workspace_id, interrupted_path, interrupted_object_id, 20)) return false;
    if (!storePhase(.dirty_write_staged)) return false;
    common.printBootMarker(boot_markers.storage_durability_interrupted_write_staged);
    return true;
}

fn recoverInterruptedBootAndCheckpointFinal(storage: *storage_service.Service) bool {
    if (!storage.loaded_from_volume) return false;
    const workspace_id = validateBaseline(storage) catch return false;
    if (!entryAbsent(storage, workspace_id, interrupted_path)) return false;
    if (storage.latestVersion(interrupted_object_id) != null) return false;
    common.printBootMarker(boot_markers.storage_durability_interrupted_boot_recovered);

    _ = putDocument(storage, final_object_id, "final", final_payload, null, 30) catch return false;
    if (!putPath(storage, workspace_id, final_path, final_object_id, 30)) return false;
    storage.checkpoint();
    if (!storage.checkpoint_store.checkpointHealthy()) return false;
    if (!storePhase(.final_checkpointed)) return false;
    common.printBootMarker(boot_markers.storage_durability_final_checkpointed);
    return true;
}

fn recoverAfterBadRootSlot(storage: *storage_service.Service) bool {
    if (!storage.loaded_from_volume) return false;
    const workspace_id = validateBaseline(storage) catch return false;
    if (!entryAbsent(storage, workspace_id, final_path)) return false;
    if (storage.latestVersion(final_object_id) != null) return false;
    common.printBootMarker(boot_markers.storage_durability_bad_root_slot_fallback);
    common.printBootMarker(boot_markers.storage_durability_deterministic_recovery);
    return true;
}

fn ensureWorkspace(storage: *storage_service.Service) !u64 {
    if (storage.findWorkspace(owner, workspace_label)) |record| return record.id.raw();
    const record = try storage.createWorkspace(.{
        .owner = owner,
        .label = workspace_label,
    });
    return record.id.raw();
}

fn validateBaseline(storage: *storage_service.Service) !u64 {
    const record = storage.findWorkspace(owner, workspace_label) orelse return error.WorkspaceNotFound;
    try validateEntry(storage, record.id.raw(), baseline_path, baseline_object_id, baseline_payload);
    return record.id.raw();
}

fn putDocument(
    storage: *storage_service.Service,
    object_id: object_store.ids.ObjectId,
    label: []const u8,
    payload: []const u8,
    parent_version_id: ?object_store.ids.VersionId,
    tick: u64,
) !object_store.PutResult {
    return storage.putVersion(.{
        .preferred_object_id = object_id,
        .object_type = .document,
        .payload = payload,
        .metadata = try object_store.signMetadata(signer, label, "text/plain", .document, payload, tick),
        .parent_version_id = parent_version_id,
    });
}

fn putPath(
    storage: *storage_service.Service,
    workspace_id: u64,
    path: []const u8,
    object_id: object_store.ids.ObjectId,
    tick: u64,
) bool {
    const version = storage.latestVersion(object_id) orelse return false;
    storage.beginTransaction(workspace_id) catch return false;
    storage.stagePut(workspace_id, path, object_id, version.id, .document) catch return false;
    _ = storage.commit(workspace_id, tick) catch return false;
    return true;
}

fn validateEntry(
    storage: *storage_service.Service,
    workspace_id: u64,
    path: []const u8,
    object_id: object_store.ids.ObjectId,
    payload: []const u8,
) !void {
    const entry = try storage.resolve(workspace_id, path);
    if (!entry.object_id.eql(object_id)) return error.ObjectMismatch;
    const version = storage.version(entry.version_id) orelse return error.VersionMissing;
    if (!version.object_id.eql(object_id)) return error.ObjectMismatch;
    if (!std.mem.eql(u8, try storage.versionPayload(version), payload)) return error.PayloadMismatch;
}

fn entryAbsent(storage: *storage_service.Service, workspace_id: u64, path: []const u8) bool {
    if (storage.resolve(workspace_id, path)) |_| {
        return false;
    } else |err| switch (err) {
        error.EntryNotFound => return true,
        else => return false,
    }
}

fn loadPhase() Phase {
    var sector = [_]u8{0} ** proof_sector_size;
    if (!readProofSector(&sector)) return .empty;
    if (!std.mem.eql(u8, sector[0..proof_magic.len], proof_magic)) return .empty;
    if (std.mem.readInt(u16, sector[proof_version_offset..][0..@sizeOf(u16)], .little) != proof_version) return .empty;
    const expected = std.mem.readInt(u64, sector[proof_checksum_offset..][0..8], .little);
    const actual = native_util.fnv1a64(sector[0..proof_checksum_offset]);
    if (expected != actual) return .empty;
    return switch (sector[proof_phase_offset]) {
        @intFromEnum(Phase.baseline_checkpointed) => .baseline_checkpointed,
        @intFromEnum(Phase.dirty_write_staged) => .dirty_write_staged,
        @intFromEnum(Phase.final_checkpointed) => .final_checkpointed,
        else => .empty,
    };
}

fn storePhase(phase: Phase) bool {
    var sector = [_]u8{0} ** proof_sector_size;
    @memcpy(sector[0..proof_magic.len], proof_magic);
    std.mem.writeInt(u16, sector[proof_version_offset..][0..@sizeOf(u16)], proof_version, .little);
    sector[proof_phase_offset] = @intFromEnum(phase);
    std.mem.writeInt(u64, sector[proof_checksum_offset..][0..8], native_util.fnv1a64(sector[0..proof_checksum_offset]), .little);
    return writeProofSector(&sector);
}

fn readProofSector(buffer: *[proof_sector_size]u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_backend_sector_count <= proof_lba) return false;
    if (root_volume.attached_ata_device) |device| {
        return volume_backend.readAtaBootstrap(device, proof_lba, buffer[0..]);
    }
    return root_volume.attached_backend_read(proof_lba, buffer.ptr, buffer.len);
}

fn writeProofSector(buffer: *const [proof_sector_size]u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_backend_sector_count <= proof_lba) return false;
    return volume_backend.writeAttachedDurableRange(root_volume, proof_lba, buffer[0..]);
}
