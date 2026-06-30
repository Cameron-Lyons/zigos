const std = @import("std");
const binary_cursor = @import("binary_cursor");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("device_graph.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const network_policy = @import("network_policy.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const state_support = @import("sync_state_support.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");

const Error = state_support.Error;
const CursorWriter = binary_cursor.Writer(Error, error.StateTooLarge);
const CursorReader = binary_cursor.Reader(Error, error.CorruptState);

const record_magic = "ZGSYNCR";
const record_version: u16 = 5;
const record_prefix = "state/";
const record_content_type = "application/zigos-sync-record";
const record_metadata_label = "sync-state-record";
const max_record_bytes: usize = 2048;

const RecordKind = enum(u8) {
    user_root = 1,
    device = 2,
    network_policy = 3,
    workspace_policy = 4,
    replica = 5,
    conflict = 6,
    database_contract = 7,
    overlay = 8,
    transport_frame = 9,
};

const Envelope = struct {
    kind: RecordKind,
};

const PathSet = struct {
    paths: [workspace.MAX_WORKSPACE_ENTRIES][workspace.MAX_ENTRY_PATH_BYTES]u8 =
        [_][workspace.MAX_ENTRY_PATH_BYTES]u8{[_]u8{0} ** workspace.MAX_ENTRY_PATH_BYTES} ** workspace.MAX_WORKSPACE_ENTRIES,
    lens: [workspace.MAX_WORKSPACE_ENTRIES]usize = [_]usize{0} ** workspace.MAX_WORKSPACE_ENTRIES,
    count: usize = 0,

    fn add(self: *PathSet, path: []const u8) Error!void {
        if (path.len > workspace.MAX_ENTRY_PATH_BYTES) return error.PathTooLong;
        if (self.contains(path)) return;
        if (self.count >= workspace.MAX_WORKSPACE_ENTRIES) return error.StateTooLarge;
        @memset(self.paths[self.count][0..], 0);
        @memcpy(self.paths[self.count][0..path.len], path);
        self.lens[self.count] = path.len;
        self.count += 1;
    }

    fn contains(self: *const PathSet, path: []const u8) bool {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            if (std.mem.eql(u8, self.paths[index][0..self.lens[index]], path)) return true;
        }
        return false;
    }
};

pub fn ensureWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId) Error!u64 {
    const existing = storage.findWorkspace(owner, state_support.state_workspace_label) orelse try storage.createWorkspace(.{
        .owner = owner,
        .label = state_support.state_workspace_label,
    });
    return existing.id.raw();
}

pub fn load(
    storage: *storage_service.Service,
    workspace_id: u64,
    resident: *state_support.ResidentState,
) Error!bool {
    resident.resetForServiceInit();

    var loaded = false;
    const entries = try storage.entries(workspace_id);
    for (entries) |entry| {
        const path = entry.pathSlice();
        if (!isRecordPath(path)) continue;
        const version = storage.version(entry.version_id) orelse return error.CorruptState;
        try decodeRecordInto(resident, try storage.versionPayload(version));
        loaded = true;
    }

    if (!loaded) return false;
    repairNextIds(resident);
    resident.has_persisted_state = true;
    return true;
}

pub fn persist(
    storage: *storage_service.Service,
    workspace_id: u64,
    resident: *state_support.ResidentState,
) Error!void {
    var live_paths = PathSet{};
    try collectLivePaths(resident, &live_paths);

    try deleteStaleRecords(storage, workspace_id, &live_paths, resident);
    if (live_paths.count == 0) return;

    const tick = resident.nextPersistTick();
    try storage.beginTransaction(workspace_id);
    try persistUserRoots(storage, workspace_id, resident, tick);
    try persistDevices(storage, workspace_id, resident, tick);
    try persistNetworkPolicies(storage, workspace_id, resident, tick);
    try persistWorkspacePolicies(storage, workspace_id, resident, tick);
    try persistReplicas(storage, workspace_id, resident, tick);
    try persistConflicts(storage, workspace_id, resident, tick);
    try persistDatabaseContracts(storage, workspace_id, resident, tick);
    try persistOverlays(storage, workspace_id, resident, tick);
    try persistTransportFrames(storage, workspace_id, resident, tick);
    _ = try storage.commit(workspace_id, tick);
    resident.has_persisted_state = true;
}

fn collectLivePaths(resident: *const state_support.ResidentState, out: *PathSet) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;

    for (resident.persisted_state.graph.user_roots) |slot| {
        if (!slot.in_use) continue;
        try out.add(try userRootPath(path_buffer[0..], slot.root.principal_id));
    }
    for (resident.persisted_state.graph.devices) |slot| {
        if (!slot.in_use) continue;
        try out.add(try devicePath(path_buffer[0..], slot.device.principal_id));
    }
    for (resident.persisted_state.network_policies.policies.slots) |slot| {
        if (!slot.in_use) continue;
        try out.add(try networkPolicyPath(path_buffer[0..], slot.policy.id));
    }
    for (resident.persisted_state.workspace_policies) |slot| {
        if (!slot.in_use) continue;
        try out.add(try workspacePolicyPath(path_buffer[0..], slot.policy.workspace_id));
    }
    for (resident.persisted_state.replica_entries) |slot| {
        if (!slot.in_use) continue;
        try out.add(try replicaPath(path_buffer[0..], slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash()));
    }
    for (resident.persisted_state.conflicts) |slot| {
        if (!slot.in_use) continue;
        try out.add(try conflictPath(path_buffer[0..], slot.conflict.workspace_id, slot.conflict.device_id, workspace.pathHash(slot.conflict.pathSlice())));
    }
    for (resident.persisted_state.database_contracts) |slot| {
        if (!slot.in_use) continue;
        try out.add(try databaseContractPath(path_buffer[0..], slot.contract.id));
    }
    for (resident.persisted_state.overlays) |slot| {
        if (!slot.in_use) continue;
        try out.add(try overlayPath(path_buffer[0..], slot.overlay.workspace_id));
    }
    for (resident.persisted_state.outbound_transport_frames) |slot| {
        if (!slot.in_use) continue;
        try out.add(try transportFramePath(path_buffer[0..], .outbound, slot.frame.id));
    }
    for (resident.persisted_state.inbound_transport_frames) |slot| {
        if (!slot.in_use) continue;
        try out.add(try transportFramePath(path_buffer[0..], .inbound, slot.frame.id));
    }
}

fn deleteStaleRecords(
    storage: *storage_service.Service,
    workspace_id: u64,
    live_paths: *const PathSet,
    resident: *state_support.ResidentState,
) Error!void {
    var stale = PathSet{};
    const entries = try storage.entries(workspace_id);
    for (entries) |entry| {
        const path = entry.pathSlice();
        if (!isRecordPath(path) or live_paths.contains(path)) continue;
        try stale.add(path);
    }
    if (stale.count == 0) return;

    const tick = resident.nextPersistTick();
    try storage.beginTransaction(workspace_id);
    var index: usize = 0;
    while (index < stale.count) : (index += 1) {
        try storage.stageDelete(workspace_id, stale.paths[index][0..stale.lens[index]]);
    }
    _ = try storage.commit(workspace_id, tick);
}

fn persistUserRoots(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.graph.user_roots) |slot| {
        if (!slot.in_use) continue;
        const path = try userRootPath(path_buffer[0..], slot.root.principal_id);
        const bytes = try encodeUserRoot(payload[0..], &slot.root);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistDevices(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.graph.devices) |slot| {
        if (!slot.in_use) continue;
        const path = try devicePath(path_buffer[0..], slot.device.principal_id);
        const bytes = try encodeDevice(payload[0..], &slot.device);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistNetworkPolicies(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.network_policies.policies.slots) |slot| {
        if (!slot.in_use) continue;
        const path = try networkPolicyPath(path_buffer[0..], slot.policy.id);
        const bytes = try encodeNetworkPolicy(payload[0..], &slot.policy);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistWorkspacePolicies(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.workspace_policies) |slot| {
        if (!slot.in_use) continue;
        const path = try workspacePolicyPath(path_buffer[0..], slot.policy.workspace_id);
        const bytes = try encodeWorkspacePolicy(payload[0..], &slot.policy);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistReplicas(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.replica_entries) |slot| {
        if (!slot.in_use) continue;
        const path = try replicaPath(path_buffer[0..], slot.entry.workspace_id, slot.entry.device_id, slot.entry.pathHash());
        const bytes = try encodeReplica(payload[0..], &slot.entry);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistConflicts(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.conflicts) |slot| {
        if (!slot.in_use) continue;
        const path = try conflictPath(path_buffer[0..], slot.conflict.workspace_id, slot.conflict.device_id, workspace.pathHash(slot.conflict.pathSlice()));
        const bytes = try encodeConflict(payload[0..], &slot.conflict);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistDatabaseContracts(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.database_contracts) |slot| {
        if (!slot.in_use) continue;
        const path = try databaseContractPath(path_buffer[0..], slot.contract.id);
        const bytes = try encodeDatabaseContract(payload[0..], &slot.contract);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistOverlays(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.overlays) |slot| {
        if (!slot.in_use) continue;
        const path = try overlayPath(path_buffer[0..], slot.overlay.workspace_id);
        const bytes = try encodeOverlay(payload[0..], &slot.overlay);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn persistTransportFrames(storage: *storage_service.Service, workspace_id: u64, resident: *const state_support.ResidentState, tick: u64) Error!void {
    var path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    var payload: [max_record_bytes]u8 = undefined;
    for (resident.persisted_state.outbound_transport_frames) |slot| {
        if (!slot.in_use) continue;
        const path = try transportFramePath(path_buffer[0..], .outbound, slot.frame.id);
        const bytes = try encodeTransportFrame(payload[0..], .outbound, &slot);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
    for (resident.persisted_state.inbound_transport_frames) |slot| {
        if (!slot.in_use) continue;
        const path = try transportFramePath(path_buffer[0..], .inbound, slot.frame.id);
        const bytes = try encodeTransportFrame(payload[0..], .inbound, &slot);
        try putRecord(storage, workspace_id, path, bytes, tick);
    }
}

fn putRecord(
    storage: *storage_service.Service,
    workspace_id: u64,
    path: []const u8,
    payload: []const u8,
    tick: u64,
) Error!void {
    const existing_entry = storage.resolve(workspace_id, path) catch |err| switch (err) {
        error.EntryNotFound => null,
        else => return err,
    };
    if (existing_entry) |entry| {
        const existing_version = storage.version(entry.version_id) orelse return error.CorruptState;
        const existing_payload = try storage.versionPayload(existing_version);
        if (std.mem.eql(u8, existing_payload, payload)) return;
    }
    const result = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(recordObjectId(workspace_id, path)),
        .object_type = .blob,
        .payload = payload,
        .metadata = object_store.signMetadata(
            state_support.state_signer,
            record_metadata_label,
            record_content_type,
            .blob,
            payload,
            tick,
        ) catch return error.StateSigningFailed,
        .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
    });
    try storage.stagePut(workspace_id, path, result.object_id, result.version_id, .blob);
}

fn decodeRecordInto(resident: *state_support.ResidentState, payload: []const u8) Error!void {
    var reader = CursorReader{ .buffer = payload };
    const envelope = try readEnvelope(&reader);
    switch (envelope.kind) {
        .user_root => try decodeUserRoot(resident, &reader),
        .device => try decodeDevice(resident, &reader),
        .network_policy => try decodeNetworkPolicy(resident, &reader),
        .workspace_policy => try decodeWorkspacePolicy(resident, &reader),
        .replica => try decodeReplica(resident, &reader),
        .conflict => try decodeConflict(resident, &reader),
        .database_contract => try decodeDatabaseContract(resident, &reader),
        .overlay => try decodeOverlay(resident, &reader),
        .transport_frame => try decodeTransportFrame(resident, &reader),
    }
    if (reader.offset != payload.len) return error.CorruptState;
}

pub fn validateRecordPayloadForReleaseGate(payload: []const u8) Error!void {
    var resident = state_support.ResidentState{};
    resident.resetForServiceInit();
    try decodeRecordInto(&resident, payload);
}

fn encodeUserRoot(buffer: []u8, root: *const device_graph.UserRootRecord) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .user_root);
    try writePrincipal(&writer, root.principal_id);
    try writeText(&writer, root.labelSlice());
    try writeSignature(&writer, root.root_signature);
    return buffer[0..writer.offset];
}

fn encodeDevice(buffer: []u8, device: *const device_graph.DeviceRecord) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .device);
    try writePrincipal(&writer, device.principal_id);
    try writePrincipal(&writer, device.owner);
    try writeText(&writer, device.labelSlice());
    try writer.writeU64(device.overlay_id);
    try writer.writeByte(@intFromEnum(device.status));
    try writer.writeU32(device.trust_generation);
    try writer.writeU32(device.key_rotation_generation);
    try writeSignature(&writer, device.device_signature);
    try writeSignature(&writer, device.enrollment_signature);
    try writeSignature(&writer, device.rotation_signature);
    try writeSignature(&writer, device.revocation_signature);
    try writer.writeU64(device.last_rotated_at_ticks);
    try writer.writeU64(device.revoked_at_ticks);
    try writer.writeByte(@intFromEnum(device.device_key_origin));
    try writer.writeByte(@intFromBool(device.platform_key_bound));
    try writeText(&writer, device.platformKeyLabelSlice());
    if (device.platform_key_bound) {
        try writer.writeBytes(&device.platform_key_digest);
        try writer.writeU64(device.platform_root_generation);
        try writer.writeByte(@intFromEnum(device.platform_root_provenance));
        try writer.writeBytes(&device.platform_root_digest);
    }
    return buffer[0..writer.offset];
}

fn encodeNetworkPolicy(buffer: []u8, policy: *const network_policy.PolicyRecord) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .network_policy);
    try writer.writeU64(policy.id);
    try writePrincipal(&writer, policy.owner);
    try writer.writeU64(policy.workspace_id orelse 0);
    try writeText(&writer, policy.labelSlice());
    try writer.writeByte(@intFromEnum(policy.mode));
    try writeText(&writer, policy.targetSlice());
    try writer.writeByte(@intFromBool(policy.explicit_internet_grant));
    try writer.writeByte(@intFromBool(policy.require_remote_attestation));
    try writer.writeByte(@intFromBool(policy.pinned_root_digest_present));
    if (policy.pinned_root_digest_present) try writer.writeBytes(&policy.pinned_root_digest);
    try writer.writeByte(@intFromBool(policy.pinned_attestation_verifier_metadata_digest_present));
    if (policy.pinned_attestation_verifier_metadata_digest_present) {
        try writer.writeBytes(&policy.pinned_attestation_verifier_metadata_digest);
    }
    return buffer[0..writer.offset];
}

fn encodeWorkspacePolicy(buffer: []u8, policy: *const state_support.WorkspacePolicy) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .workspace_policy);
    try writer.writeU64(policy.workspace_id);
    try writePrincipal(&writer, policy.owner);
    try writer.writeByte(@intFromBool(policy.offline_first));
    try writer.writeByte(@intFromBool(policy.personal_e2ee));
    try writer.writeU64(policy.device_to_device_policy_id orelse 0);
    try writer.writeU64(policy.relay_policy_id orelse 0);
    try writer.writeU64(policy.overlay_policy_id orelse 0);
    try writeText(&writer, policy.relayDomainSlice());
    try writer.writeU16(@intCast(policy.selective_prefix_count));
    var prefix_index: usize = 0;
    while (prefix_index < policy.selective_prefix_count) : (prefix_index += 1) {
        try writeText(&writer, policy.selective_prefixes[prefix_index][0..policy.selective_prefix_lens[prefix_index]]);
    }
    try writer.writeByte(@intFromBool(policy.require_shared_access));
    return buffer[0..writer.offset];
}

fn encodeReplica(buffer: []u8, replica: *const state_support.ReplicaEntry) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .replica);
    try writer.writeU64(replica.workspace_id);
    try writePrincipal(&writer, replica.device_id);
    try writer.writeU32(replica.workspace_generation);
    try writeText(&writer, replica.pathSlice());
    try writer.writeU64(replica.object_id);
    try writer.writeU64(replica.version_id);
    return buffer[0..writer.offset];
}

fn encodeConflict(buffer: []u8, conflict: *const state_support.ConflictRecord) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .conflict);
    try writer.writeU64(conflict.workspace_id);
    try writePrincipal(&writer, conflict.device_id);
    try writer.writeU64(conflict.object_id);
    try writeText(&writer, conflict.pathSlice());
    try writer.writeU64(conflict.local_version_id);
    try writer.writeU64(conflict.remote_version_id);
    try writer.writeByte(@intFromEnum(conflict.semantic));
    return buffer[0..writer.offset];
}

fn encodeDatabaseContract(buffer: []u8, contract: *const state_support.DatabaseContract) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .database_contract);
    try writer.writeU64(contract.id);
    try writer.writeU64(contract.workspace_id);
    try writeText(&writer, contract.bundleIdSlice());
    try writeText(&writer, contract.labelSlice());
    try writeSignature(&writer, contract.signature);
    return buffer[0..writer.offset];
}

fn encodeOverlay(buffer: []u8, overlay: *const state_support.OverlayRecord) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .overlay);
    try writer.writeU64(overlay.id);
    try writer.writeU64(overlay.workspace_id);
    try writePrincipal(&writer, overlay.home_device);
    try writeText(&writer, overlay.serviceIdentitySlice());
    try writer.writeByte(@intFromBool(overlay.remote_access_enabled));
    try writer.writeU16(@intCast(overlay.private_service_count));
    var service_index: usize = 0;
    while (service_index < overlay.private_service_count) : (service_index += 1) {
        try writeText(&writer, overlay.private_services[service_index][0..overlay.private_service_lens[service_index]]);
    }
    return buffer[0..writer.offset];
}

fn encodeTransportFrame(
    buffer: []u8,
    queue_kind: state_support.TransportQueueKind,
    slot: *const state_support.DurableTransportFrameSlot,
) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writeEnvelope(&writer, .transport_frame);
    try writer.writeByte(@intFromEnum(queue_kind));
    try writer.writeByte(@intFromBool(slot.acked));
    try writer.writeU16(slot.duplicate_count);
    try writeTransportFrame(&writer, &slot.frame);
    return buffer[0..writer.offset];
}

fn decodeUserRoot(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeUserRootIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.graph.user_roots[slot_index];
    slot.in_use = true;
    slot.root = .{
        .principal_id = try readPrincipal(reader),
        .label_len = 0,
        .label = [_]u8{0} ** device_graph.MAX_LABEL_BYTES,
        .root_signature = .{},
    };
    try readTextInto(reader, &slot.root.label, &slot.root.label_len);
    slot.root.root_signature = try readSignature(reader, &resident.user_root_signers[slot_index]);
}

fn decodeDevice(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeDeviceIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.graph.devices[slot_index];
    slot.in_use = true;
    slot.device = state_support.zeroDeviceGraphRecord();
    slot.device.principal_id = try readPrincipal(reader);
    slot.device.owner = try readPrincipal(reader);
    try readTextInto(reader, &slot.device.label, &slot.device.label_len);
    slot.device.overlay_id = try reader.readU64();
    slot.device.status = try parseDeviceStatus(try reader.readByte());
    slot.device.trust_generation = try reader.readU32();
    slot.device.key_rotation_generation = try reader.readU32();
    slot.device.device_signature = try readSignature(reader, &resident.device_signature_signers[slot_index][0]);
    slot.device.enrollment_signature = try readSignature(reader, &resident.device_signature_signers[slot_index][1]);
    slot.device.rotation_signature = try readSignature(reader, &resident.device_signature_signers[slot_index][2]);
    slot.device.revocation_signature = try readSignature(reader, &resident.device_signature_signers[slot_index][3]);
    slot.device.last_rotated_at_ticks = try reader.readU64();
    slot.device.revoked_at_ticks = try reader.readU64();
    slot.device.device_key_origin = try parseDeviceKeyOrigin(try reader.readByte());
    slot.device.platform_key_bound = (try reader.readByte()) != 0;
    try readTextInto(reader, &slot.device.platform_key_label, &slot.device.platform_key_label_len);
    if (slot.device.platform_key_bound) {
        try reader.readBytes(&slot.device.platform_key_digest);
        slot.device.platform_root_generation = try reader.readU64();
        slot.device.platform_root_provenance = try parseRootProvenance(try reader.readByte());
        try reader.readBytes(&slot.device.platform_root_digest);
        if (!slot.device.hasBootloaderBackedPlatformRoot()) return error.CorruptState;
    } else if (slot.device.device_key_origin != .software or slot.device.platform_key_label_len != 0) {
        return error.CorruptState;
    }
}

fn decodeNetworkPolicy(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeNetworkPolicyIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.network_policies.policies.slots[slot_index];
    slot.in_use = true;
    slot.policy = .{
        .id = try reader.readU64(),
        .owner = try readPrincipal(reader),
        .workspace_id = null,
        .label_len = 0,
        .label = [_]u8{0} ** network_policy.MAX_LABEL_BYTES,
        .mode = .none,
        .target_len = 0,
        .target = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
        .explicit_internet_grant = false,
        .require_remote_attestation = false,
        .pinned_root_digest_present = false,
        .pinned_root_digest = crypto_hash.zero_digest,
        .pinned_attestation_verifier_metadata_digest_present = false,
        .pinned_attestation_verifier_metadata_digest = crypto_hash.zero_digest,
    };
    const workspace_id = try reader.readU64();
    slot.policy.workspace_id = if (workspace_id == 0) null else workspace_id;
    try readTextInto(reader, &slot.policy.label, &slot.policy.label_len);
    slot.policy.mode = try parsePolicyMode(try reader.readByte());
    try readTextInto(reader, &slot.policy.target, &slot.policy.target_len);
    slot.policy.explicit_internet_grant = (try reader.readByte()) != 0;
    slot.policy.require_remote_attestation = (try reader.readByte()) != 0;
    slot.policy.pinned_root_digest_present = (try reader.readByte()) != 0;
    if (slot.policy.pinned_root_digest_present) try reader.readBytes(&slot.policy.pinned_root_digest);
    slot.policy.pinned_attestation_verifier_metadata_digest_present = (try reader.readByte()) != 0;
    if (slot.policy.pinned_attestation_verifier_metadata_digest_present) {
        try reader.readBytes(&slot.policy.pinned_attestation_verifier_metadata_digest);
    }
}

fn decodeWorkspacePolicy(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeWorkspacePolicyIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.workspace_policies[slot_index];
    slot.in_use = true;
    slot.policy = state_support.zeroWorkspacePolicy();
    slot.policy.workspace_id = try reader.readU64();
    slot.policy.owner = try readPrincipal(reader);
    slot.policy.offline_first = (try reader.readByte()) != 0;
    slot.policy.personal_e2ee = (try reader.readByte()) != 0;
    slot.policy.device_to_device_policy_id = state_support.readOptionalU64(try reader.readU64());
    slot.policy.relay_policy_id = state_support.readOptionalU64(try reader.readU64());
    slot.policy.overlay_policy_id = state_support.readOptionalU64(try reader.readU64());
    try readTextInto(reader, &slot.policy.relay_domain, &slot.policy.relay_domain_len);
    const prefix_count = try reader.readU16();
    if (prefix_count > state_support.MAX_SELECTIVE_PREFIXES) return error.CorruptState;
    slot.policy.selective_prefix_count = prefix_count;
    var prefix_index: usize = 0;
    while (prefix_index < prefix_count) : (prefix_index += 1) {
        try readTextInto(reader, &slot.policy.selective_prefixes[prefix_index], &slot.policy.selective_prefix_lens[prefix_index]);
    }
    slot.policy.require_shared_access = (try reader.readByte()) != 0;
}

fn decodeReplica(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeReplicaIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.replica_entries[slot_index];
    slot.in_use = true;
    slot.entry = state_support.zeroReplicaEntry();
    slot.entry.workspace_id = try reader.readU64();
    slot.entry.device_id = try readPrincipal(reader);
    slot.entry.workspace_generation = try reader.readU32();
    try readTextInto(reader, &slot.entry.path, &slot.entry.path_len);
    slot.entry.object_id = try reader.readU64();
    slot.entry.version_id = try reader.readU64();
}

fn decodeConflict(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeConflictIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.conflicts[slot_index];
    slot.in_use = true;
    slot.conflict = state_support.zeroConflict();
    slot.conflict.workspace_id = try reader.readU64();
    slot.conflict.device_id = try readPrincipal(reader);
    slot.conflict.object_id = try reader.readU64();
    try readTextInto(reader, &slot.conflict.path, &slot.conflict.path_len);
    slot.conflict.local_version_id = try reader.readU64();
    slot.conflict.remote_version_id = try reader.readU64();
    slot.conflict.semantic = try parseSyncSemantic(try reader.readByte());
}

fn decodeDatabaseContract(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeDatabaseContractIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.database_contracts[slot_index];
    slot.in_use = true;
    slot.contract = state_support.zeroDatabaseContract();
    slot.contract.id = try reader.readU64();
    slot.contract.workspace_id = try reader.readU64();
    try readTextInto(reader, &slot.contract.bundle_id, &slot.contract.bundle_id_len);
    try readTextInto(reader, &slot.contract.label, &slot.contract.label_len);
    slot.contract.signature = try readSignature(reader, &resident.database_contract_signers[slot_index]);
}

fn decodeOverlay(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const slot_index = firstFreeOverlayIndex(resident) orelse return error.CorruptState;
    const slot = &resident.persisted_state.overlays[slot_index];
    slot.in_use = true;
    slot.overlay = state_support.zeroOverlay();
    slot.overlay.id = try reader.readU64();
    slot.overlay.workspace_id = try reader.readU64();
    slot.overlay.home_device = try readPrincipal(reader);
    try readTextInto(reader, &slot.overlay.service_identity, &slot.overlay.service_identity_len);
    slot.overlay.remote_access_enabled = (try reader.readByte()) != 0;
    const private_service_count = try reader.readU16();
    if (private_service_count > state_support.MAX_PRIVATE_SERVICES) return error.CorruptState;
    slot.overlay.private_service_count = private_service_count;
    var service_index: usize = 0;
    while (service_index < private_service_count) : (service_index += 1) {
        try readTextInto(reader, &slot.overlay.private_services[service_index], &slot.overlay.private_service_lens[service_index]);
    }
}

fn decodeTransportFrame(resident: *state_support.ResidentState, reader: *CursorReader) Error!void {
    const queue_kind = try parseTransportQueueKind(try reader.readByte());
    const slot = switch (queue_kind) {
        .outbound => blk: {
            const slot_index = firstFreeOutboundTransportFrameIndex(resident) orelse return error.CorruptState;
            break :blk &resident.persisted_state.outbound_transport_frames[slot_index];
        },
        .inbound => blk: {
            const slot_index = firstFreeInboundTransportFrameIndex(resident) orelse return error.CorruptState;
            break :blk &resident.persisted_state.inbound_transport_frames[slot_index];
        },
    };
    slot.in_use = true;
    slot.acked = (try reader.readByte()) != 0;
    slot.duplicate_count = try reader.readU16();
    slot.frame = try readTransportFrame(reader);
}

fn writeTransportFrame(writer: *CursorWriter, frame: *const state_support.TransportFrame) Error!void {
    try writer.writeU64(frame.id);
    try writer.writeU64(frame.source_frame_id);
    try writer.writeU64(frame.workspace_id);
    try writer.writeU64(frame.object_id);
    try writer.writeU64(frame.version_id);
    try writePrincipal(writer, frame.source_device);
    try writePrincipal(writer, frame.target_device);
    try writer.writeByte(@intFromEnum(frame.transport));
    try writer.writeByte(@intFromEnum(frame.semantic));
    try writer.writeByte(@intFromBool(frame.encrypted));
    try writer.writeU32(frame.workspace_generation);
    try writeText(writer, frame.pathSlice());
}

fn readTransportFrame(reader: *CursorReader) Error!state_support.TransportFrame {
    var frame = state_support.TransportFrame{};
    frame.id = try reader.readU64();
    frame.source_frame_id = try reader.readU64();
    frame.workspace_id = try reader.readU64();
    frame.object_id = try reader.readU64();
    frame.version_id = try reader.readU64();
    frame.source_device = try readPrincipal(reader);
    frame.target_device = try readPrincipal(reader);
    frame.transport = try parseTransportMode(try reader.readByte());
    frame.semantic = try parseSyncSemantic(try reader.readByte());
    frame.encrypted = (try reader.readByte()) != 0;
    frame.workspace_generation = try reader.readU32();
    try readTextInto(reader, &frame.path, &frame.path_len);
    return frame;
}

fn writeEnvelope(writer: *CursorWriter, kind: RecordKind) Error!void {
    try writer.writeBytes(record_magic);
    try writer.writeU16(record_version);
    try writer.writeByte(@intFromEnum(kind));
}

fn readEnvelope(reader: *CursorReader) Error!Envelope {
    var magic_buffer: [record_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, record_magic)) return error.CorruptState;
    const version = try reader.readU16();
    // Single-version on-disk format: only the current record_version is accepted.
    if (version != record_version) return error.UnsupportedStateVersion;
    return .{
        .kind = try parseRecordKind(try reader.readByte()),
    };
}

fn writePrincipal(writer: *CursorWriter, id: principal.PrincipalId) Error!void {
    try writer.writeByte(@intFromEnum(id.kind));
    try writer.writeU64(id.serial);
}

fn readPrincipal(reader: *CursorReader) Error!principal.PrincipalId {
    return .{
        .kind = try parsePrincipalKind(try reader.readByte()),
        .serial = try reader.readU64(),
    };
}

fn writeText(writer: *CursorWriter, text: []const u8) Error!void {
    if (text.len > std.math.maxInt(u16)) return error.StateTooLarge;
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readTextInto(reader: *CursorReader, buffer: []u8, out_len: *usize) Error!void {
    const text_len = try reader.readU16();
    if (text_len > buffer.len) return error.CorruptState;
    @memset(buffer, 0);
    try reader.readBytes(buffer[0..text_len]);
    out_len.* = text_len;
}

fn writeSignature(writer: *CursorWriter, signature: manifest.Signature) Error!void {
    if (!signature.isPresent()) {
        try writer.writeByte(0);
        return;
    }
    if (signature.signer.len > state_support.MAX_LABEL_BYTES) return error.StateTooLarge;
    try writer.writeByte(1);
    try writeText(writer, signature.signer);
    try writer.writeU16(@intCast(signature.public_key_len));
    try writer.writeBytes(signature.public_key[0..signature.public_key_len]);
    try writer.writeU16(@intCast(signature.value_len));
    try writer.writeBytes(signature.value[0..signature.value_len]);
}

fn readSignature(reader: *CursorReader, signer_storage: *[state_support.MAX_LABEL_BYTES]u8) Error!manifest.Signature {
    if ((try reader.readByte()) == 0) return .{};

    var signature = manifest.Signature{
        .format = manifest.SIGNATURE_FORMAT_ED25519,
        .signer = signer_storage[0..0],
    };
    var signer_len: usize = 0;
    try readTextInto(reader, signer_storage, &signer_len);
    signature.signer = signer_storage[0..signer_len];
    signature.public_key_len = try reader.readU16();
    if (signature.public_key_len > signature.public_key.len) return error.InvalidStateSignatureEncoding;
    try reader.readBytes(signature.public_key[0..signature.public_key_len]);
    signature.value_len = try reader.readU16();
    if (signature.value_len > signature.value.len) return error.InvalidStateSignatureEncoding;
    try reader.readBytes(signature.value[0..signature.value_len]);
    return signature;
}

fn userRootPath(buffer: []u8, user: principal.PrincipalId) Error![]const u8 {
    return principalPath(buffer, "u", user);
}

fn devicePath(buffer: []u8, device: principal.PrincipalId) Error![]const u8 {
    return principalPath(buffer, "d", device);
}

fn networkPolicyPath(buffer: []u8, policy_id: u64) Error![]const u8 {
    return idPath(buffer, "p", policy_id);
}

fn workspacePolicyPath(buffer: []u8, workspace_id: u64) Error![]const u8 {
    return idPath(buffer, "w", workspace_id);
}

fn databaseContractPath(buffer: []u8, contract_id: u64) Error![]const u8 {
    return idPath(buffer, "t", contract_id);
}

fn overlayPath(buffer: []u8, workspace_id: u64) Error![]const u8 {
    return idPath(buffer, "o", workspace_id);
}

fn transportFramePath(buffer: []u8, queue_kind: state_support.TransportQueueKind, frame_id: u64) Error![]const u8 {
    return switch (queue_kind) {
        .outbound => idPath(buffer, "qo", frame_id),
        .inbound => idPath(buffer, "qi", frame_id),
    };
}

fn replicaPath(buffer: []u8, workspace_id: u64, device: principal.PrincipalId, path_hash: u64) Error![]const u8 {
    return devicePathWithHash(buffer, "r", workspace_id, device, path_hash);
}

fn conflictPath(buffer: []u8, workspace_id: u64, device: principal.PrincipalId, path_hash: u64) Error![]const u8 {
    return devicePathWithHash(buffer, "c", workspace_id, device, path_hash);
}

fn idPath(buffer: []u8, comptime tag: []const u8, id: u64) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}/{d}", .{ record_prefix, tag, id }) catch error.PathTooLong;
}

fn principalPath(buffer: []u8, comptime tag: []const u8, id: principal.PrincipalId) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}/{d}-{d}", .{ record_prefix, tag, @intFromEnum(id.kind), id.serial }) catch error.PathTooLong;
}

fn devicePathWithHash(
    buffer: []u8,
    comptime tag: []const u8,
    workspace_id: u64,
    device: principal.PrincipalId,
    path_hash: u64,
) Error![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}/{d}/{d}-{d}/{x}", .{
        record_prefix,
        tag,
        workspace_id,
        @intFromEnum(device.kind),
        device.serial,
        path_hash,
    }) catch error.PathTooLong;
}

fn isRecordPath(path: []const u8) bool {
    return std.mem.startsWith(u8, path, record_prefix);
}

fn recordObjectId(workspace_id: u64, path: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(hash_seeds.sync_state_record_key);
    var workspace_bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, workspace_bytes[0..], workspace_id, .little);
    hasher.update(workspace_bytes[0..]);
    hasher.update(path);
    const value = hasher.final();
    return 0x8000_0000_0000_0000 | (value & 0x7FFF_FFFF_FFFF_FFFF);
}

fn repairNextIds(resident: *state_support.ResidentState) void {
    var next_overlay_id: u64 = 1;
    for (resident.persisted_state.overlays) |slot| {
        if (slot.in_use) next_overlay_id = @max(next_overlay_id, slot.overlay.id + 1);
    }
    resident.persisted_state.next_overlay_id = next_overlay_id;

    var next_contract_id: u64 = 1;
    for (resident.persisted_state.database_contracts) |slot| {
        if (slot.in_use) next_contract_id = @max(next_contract_id, slot.contract.id + 1);
    }
    resident.persisted_state.next_contract_id = next_contract_id;
    resident.persisted_state.network_policies.next_policy_id = resident.nextPersistedPolicyId();
    resident.persisted_state.network_policies.rebuildIndexes();
    var next_transport_frame_id: u64 = 1;
    for (resident.persisted_state.outbound_transport_frames) |slot| {
        if (slot.in_use) next_transport_frame_id = @max(next_transport_frame_id, slot.frame.id + 1);
    }
    for (resident.persisted_state.inbound_transport_frames) |slot| {
        if (slot.in_use) next_transport_frame_id = @max(next_transport_frame_id, slot.frame.id + 1);
    }
    resident.persisted_state.next_transport_frame_id = next_transport_frame_id;
}

fn firstFreeUserRootIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.graph.user_roots, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeDeviceIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.graph.devices, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeNetworkPolicyIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.network_policies.policies.slots, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeWorkspacePolicyIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.workspace_policies, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeReplicaIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.replica_entries, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeConflictIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.conflicts, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeDatabaseContractIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.database_contracts, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeOverlayIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.overlays, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeOutboundTransportFrameIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.outbound_transport_frames, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn firstFreeInboundTransportFrameIndex(resident: *const state_support.ResidentState) ?usize {
    for (resident.persisted_state.inbound_transport_frames, 0..) |slot, index| {
        if (!slot.in_use) return index;
    }
    return null;
}

fn parseRecordKind(raw: u8) Error!RecordKind {
    return switch (raw) {
        1 => .user_root,
        2 => .device,
        3 => .network_policy,
        4 => .workspace_policy,
        5 => .replica,
        6 => .conflict,
        7 => .database_contract,
        8 => .overlay,
        9 => .transport_frame,
        else => error.CorruptState,
    };
}

fn parsePrincipalKind(raw: u8) Error!principal.PrincipalKind {
    return switch (raw) {
        0 => .user,
        1 => .device,
        2 => .app,
        3 => .service,
        4 => .policy_authority,
        else => error.CorruptState,
    };
}

fn parseDeviceStatus(raw: u8) Error!device_graph.DeviceStatus {
    return switch (raw) {
        0 => .trusted,
        1 => .revoked,
        else => error.CorruptState,
    };
}

fn parseDeviceKeyOrigin(raw: u8) Error!device_graph.DeviceKeyOrigin {
    return switch (raw) {
        0 => .software,
        1 => .secure_enclave,
        2 => .tpm,
        else => error.CorruptState,
    };
}

fn parseRootProvenance(raw: u8) Error!measured_boot.RootProvenance {
    return switch (raw) {
        0 => .synthetic_host,
        1 => .bootloader_provided,
        2 => .emulator_provided,
        else => error.CorruptState,
    };
}

fn parsePolicyMode(raw: u8) Error!network_policy.PolicyMode {
    return switch (raw) {
        0 => .none,
        1 => .local_network,
        2 => .local_subnet_discovery,
        3 => .named_service_identity,
        4 => .named_domain,
        5 => .inbound_collaborative_session,
        6 => .unrestricted_internet,
        else => error.CorruptState,
    };
}

fn parseSyncSemantic(raw: u8) Error!state_support.SyncSemantic {
    return switch (raw) {
        0 => .mergeable_crdt,
        1 => .chunked_snapshot,
        2 => .secure_transfer,
        3 => .transactional_contract,
        else => error.CorruptState,
    };
}

fn parseTransportMode(raw: u8) Error!state_support.TransportMode {
    return switch (raw) {
        0 => .device_to_device,
        1 => .relay_assisted,
        else => error.CorruptState,
    };
}

fn parseTransportQueueKind(raw: u8) Error!state_support.TransportQueueKind {
    return switch (raw) {
        0 => .outbound,
        1 => .inbound,
        else => error.CorruptState,
    };
}
