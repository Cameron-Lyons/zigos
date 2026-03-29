const std = @import("std");
const device_graph = @import("device_graph.zig");
const manifest = @import("../policy/manifest.zig");
const network_policy = @import("network_policy.zig");
const principal = @import("../core/principal.zig");
const state_support = @import("sync_state_support.zig");

const Error = state_support.Error;
const SyncSemantic = state_support.SyncSemantic;
const MAX_WORKSPACE_POLICIES = state_support.MAX_WORKSPACE_POLICIES;
const MAX_SELECTIVE_PREFIXES = state_support.MAX_SELECTIVE_PREFIXES;
const MAX_REPLICA_ENTRIES = state_support.MAX_REPLICA_ENTRIES;
const MAX_CONFLICTS = state_support.MAX_CONFLICTS;
const MAX_DATABASE_CONTRACTS = state_support.MAX_DATABASE_CONTRACTS;
const MAX_OVERLAYS = state_support.MAX_OVERLAYS;
const MAX_PRIVATE_SERVICES = state_support.MAX_PRIVATE_SERVICES;
const MAX_LABEL_BYTES = state_support.MAX_LABEL_BYTES;

const persisted_state = &state_support.persisted_state;

const CursorWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn writeByte(self: *CursorWriter, value: u8) Error!void {
        if (self.offset >= self.buffer.len) return error.StateTooLarge;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn writeBytes(self: *CursorWriter, bytes: []const u8) Error!void {
        if (self.offset + bytes.len > self.buffer.len) return error.StateTooLarge;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeU16(self: *CursorWriter, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU32(self: *CursorWriter, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU64(self: *CursorWriter, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

const CursorReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn readByte(self: *CursorReader) Error!u8 {
        if (self.offset >= self.buffer.len) return error.CorruptState;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    fn readBytes(self: *CursorReader, dest: []u8) Error!void {
        if (self.offset + dest.len > self.buffer.len) return error.CorruptState;
        @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
        self.offset += dest.len;
    }

    fn readU16(self: *CursorReader) Error!u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u16, &bytes, .little);
    }

    fn readU32(self: *CursorReader) Error!u32 {
        var bytes: [4]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u32, &bytes, .little);
    }

    fn readU64(self: *CursorReader) Error!u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};

pub const StateIndex = struct {
    total_len: usize,
    chunk_count: usize,
    digest: [32]u8,
};

pub fn serialize(buffer: []u8) Error!usize {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(state_support.state_magic);
    try writer.writeU16(state_support.state_version);
    try writer.writeU64(persisted_state.next_overlay_id);
    try writer.writeU64(persisted_state.next_contract_id);
    try writer.writeU16(@intCast(state_support.userRootCount()));
    try writer.writeU16(@intCast(state_support.deviceCount()));
    try writer.writeU16(@intCast(state_support.networkPolicyCount()));
    try writer.writeU16(@intCast(state_support.workspacePolicyCount()));
    try writer.writeU16(@intCast(state_support.replicaCount()));
    try writer.writeU16(@intCast(state_support.conflictCount()));
    try writer.writeU16(@intCast(state_support.databaseContractCount()));
    try writer.writeU16(@intCast(state_support.overlayCount()));

    for (persisted_state.graph.user_roots) |slot| {
        if (!slot.in_use) continue;
        try writePrincipal(&writer, slot.root.principal_id);
        try writeText(&writer, slot.root.labelSlice());
        try writeSignature(&writer, slot.root.root_signature);
    }
    for (persisted_state.graph.devices) |slot| {
        if (!slot.in_use) continue;
        try writePrincipal(&writer, slot.device.principal_id);
        try writePrincipal(&writer, slot.device.owner);
        try writeText(&writer, slot.device.labelSlice());
        try writer.writeU64(slot.device.overlay_id);
        try writer.writeByte(@intFromEnum(slot.device.status));
        try writer.writeU32(slot.device.trust_generation);
        try writer.writeU32(slot.device.key_rotation_generation);
        try writeSignature(&writer, slot.device.device_signature);
        try writeSignature(&writer, slot.device.enrollment_signature);
        try writeSignature(&writer, slot.device.rotation_signature);
        try writeSignature(&writer, slot.device.revocation_signature);
        try writer.writeU64(slot.device.last_rotated_at_ticks);
        try writer.writeU64(slot.device.revoked_at_ticks);
    }
    for (persisted_state.network_policies.policies) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.policy.id);
        try writePrincipal(&writer, slot.policy.owner);
        try writer.writeU64(slot.policy.workspace_id orelse 0);
        try writeText(&writer, slot.policy.labelSlice());
        try writer.writeByte(@intFromEnum(slot.policy.mode));
        try writeText(&writer, slot.policy.targetSlice());
        try writer.writeByte(@intFromBool(slot.policy.explicit_internet_grant));
        try writer.writeByte(@intFromBool(slot.policy.require_remote_attestation));
        try writer.writeByte(@intFromBool(slot.policy.pinned_root_digest_present));
        if (slot.policy.pinned_root_digest_present) {
            try writer.writeBytes(&slot.policy.pinned_root_digest);
        }
    }
    for (persisted_state.workspace_policies) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.policy.workspace_id);
        try writePrincipal(&writer, slot.policy.owner);
        try writer.writeByte(@intFromBool(slot.policy.offline_first));
        try writer.writeByte(@intFromBool(slot.policy.personal_e2ee));
        try writer.writeU64(slot.policy.device_to_device_policy_id orelse 0);
        try writer.writeU64(slot.policy.relay_policy_id orelse 0);
        try writer.writeU64(slot.policy.overlay_policy_id orelse 0);
        try writeText(&writer, slot.policy.relayDomainSlice());
        try writer.writeU16(@intCast(slot.policy.selective_prefix_count));
        var prefix_index: usize = 0;
        while (prefix_index < slot.policy.selective_prefix_count) : (prefix_index += 1) {
            const prefix = slot.policy.selective_prefixes[prefix_index][0..slot.policy.selective_prefix_lens[prefix_index]];
            try writeText(&writer, prefix);
        }
    }
    for (persisted_state.replica_entries) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.entry.workspace_id);
        try writePrincipal(&writer, slot.entry.device_id);
        try writeText(&writer, slot.entry.pathSlice());
        try writer.writeU64(slot.entry.object_id);
        try writer.writeU64(slot.entry.version_id);
    }
    for (persisted_state.conflicts) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.conflict.workspace_id);
        try writePrincipal(&writer, slot.conflict.device_id);
        try writer.writeU64(slot.conflict.object_id);
        try writeText(&writer, slot.conflict.pathSlice());
        try writer.writeU64(slot.conflict.local_version_id);
        try writer.writeU64(slot.conflict.remote_version_id);
        try writer.writeByte(@intFromEnum(slot.conflict.semantic));
    }
    for (persisted_state.database_contracts) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.contract.id);
        try writer.writeU64(slot.contract.workspace_id);
        try writeText(&writer, slot.contract.bundleIdSlice());
        try writeText(&writer, slot.contract.labelSlice());
        try writeSignature(&writer, slot.contract.signature);
    }
    for (persisted_state.overlays) |slot| {
        if (!slot.in_use) continue;
        try writer.writeU64(slot.overlay.id);
        try writer.writeU64(slot.overlay.workspace_id);
        try writePrincipal(&writer, slot.overlay.home_device);
        try writeText(&writer, slot.overlay.serviceIdentitySlice());
        try writer.writeByte(@intFromBool(slot.overlay.remote_access_enabled));
        try writer.writeU16(@intCast(slot.overlay.private_service_count));
        var service_index: usize = 0;
        while (service_index < slot.overlay.private_service_count) : (service_index += 1) {
            const label = slot.overlay.private_services[service_index][0..slot.overlay.private_service_lens[service_index]];
            try writeText(&writer, label);
        }
    }

    return writer.offset;
}

pub fn deserialize(payload: []const u8) Error!void {
    state_support.resident_state.resetForServiceInit();

    var reader = CursorReader{ .buffer = payload };
    var magic_buffer: [state_support.state_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, state_support.state_magic)) return error.CorruptState;
    if ((try reader.readU16()) != state_support.state_version) return error.UnsupportedStateVersion;

    persisted_state.next_overlay_id = try reader.readU64();
    persisted_state.next_contract_id = try reader.readU64();
    const root_count = try reader.readU16();
    const device_count_value = try reader.readU16();
    const network_policy_count = try reader.readU16();
    const workspace_policy_count = try reader.readU16();
    const replica_count_value = try reader.readU16();
    const conflict_count_value = try reader.readU16();
    const contract_count = try reader.readU16();
    const overlay_count_value = try reader.readU16();

    if (root_count > device_graph.MAX_USER_ROOTS or
        device_count_value > device_graph.MAX_DEVICES or
        network_policy_count > network_policy.MAX_POLICIES or
        workspace_policy_count > MAX_WORKSPACE_POLICIES or
        replica_count_value > MAX_REPLICA_ENTRIES or
        conflict_count_value > MAX_CONFLICTS or
        contract_count > MAX_DATABASE_CONTRACTS or
        overlay_count_value > MAX_OVERLAYS)
    {
        return error.CorruptState;
    }

    var index: usize = 0;
    while (index < root_count) : (index += 1) {
        persisted_state.graph.user_roots[index].in_use = true;
        persisted_state.graph.user_roots[index].root = .{
            .principal_id = try readPrincipal(&reader),
            .label_len = 0,
            .label = [_]u8{0} ** device_graph.MAX_LABEL_BYTES,
            .root_signature = .{},
        };
        try readTextInto(&reader, &persisted_state.graph.user_roots[index].root.label, &persisted_state.graph.user_roots[index].root.label_len);
        persisted_state.graph.user_roots[index].root.root_signature = try readSignature(&reader, &state_support.user_root_signers[index]);
    }

    index = 0;
    while (index < device_count_value) : (index += 1) {
        persisted_state.graph.devices[index].in_use = true;
        persisted_state.graph.devices[index].device = state_support.zeroDeviceGraphRecord();
        persisted_state.graph.devices[index].device.principal_id = try readPrincipal(&reader);
        persisted_state.graph.devices[index].device.owner = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.graph.devices[index].device.label, &persisted_state.graph.devices[index].device.label_len);
        persisted_state.graph.devices[index].device.overlay_id = try reader.readU64();
        persisted_state.graph.devices[index].device.status = try parseDeviceStatus(try reader.readByte());
        persisted_state.graph.devices[index].device.trust_generation = try reader.readU32();
        persisted_state.graph.devices[index].device.key_rotation_generation = try reader.readU32();
        persisted_state.graph.devices[index].device.device_signature = try readSignature(&reader, &state_support.device_signature_signers[index][0]);
        persisted_state.graph.devices[index].device.enrollment_signature = try readSignature(&reader, &state_support.device_signature_signers[index][1]);
        persisted_state.graph.devices[index].device.rotation_signature = try readSignature(&reader, &state_support.device_signature_signers[index][2]);
        persisted_state.graph.devices[index].device.revocation_signature = try readSignature(&reader, &state_support.device_signature_signers[index][3]);
        persisted_state.graph.devices[index].device.last_rotated_at_ticks = try reader.readU64();
        persisted_state.graph.devices[index].device.revoked_at_ticks = try reader.readU64();
    }

    index = 0;
    while (index < network_policy_count) : (index += 1) {
        persisted_state.network_policies.policies[index].in_use = true;
        persisted_state.network_policies.policies[index].policy = .{
            .id = try reader.readU64(),
            .owner = try readPrincipal(&reader),
            .workspace_id = null,
            .label_len = 0,
            .label = [_]u8{0} ** network_policy.MAX_LABEL_BYTES,
            .mode = .none,
            .target_len = 0,
            .target = [_]u8{0} ** network_policy.MAX_TARGET_BYTES,
            .explicit_internet_grant = false,
            .require_remote_attestation = false,
            .pinned_root_digest_present = false,
            .pinned_root_digest = [_]u8{0} ** 32,
        };
        const workspace_id = try reader.readU64();
        persisted_state.network_policies.policies[index].policy.workspace_id = if (workspace_id == 0) null else workspace_id;
        try readTextInto(&reader, &persisted_state.network_policies.policies[index].policy.label, &persisted_state.network_policies.policies[index].policy.label_len);
        persisted_state.network_policies.policies[index].policy.mode = try parsePolicyMode(try reader.readByte());
        try readTextInto(&reader, &persisted_state.network_policies.policies[index].policy.target, &persisted_state.network_policies.policies[index].policy.target_len);
        persisted_state.network_policies.policies[index].policy.explicit_internet_grant = (try reader.readByte()) != 0;
        persisted_state.network_policies.policies[index].policy.require_remote_attestation = (try reader.readByte()) != 0;
        persisted_state.network_policies.policies[index].policy.pinned_root_digest_present = (try reader.readByte()) != 0;
        if (persisted_state.network_policies.policies[index].policy.pinned_root_digest_present) {
            try reader.readBytes(&persisted_state.network_policies.policies[index].policy.pinned_root_digest);
        }
    }
    persisted_state.network_policies.next_policy_id = state_support.nextPersistedPolicyId();

    index = 0;
    while (index < workspace_policy_count) : (index += 1) {
        persisted_state.workspace_policies[index].in_use = true;
        persisted_state.workspace_policies[index].policy = state_support.zeroWorkspacePolicy();
        persisted_state.workspace_policies[index].policy.workspace_id = try reader.readU64();
        persisted_state.workspace_policies[index].policy.owner = try readPrincipal(&reader);
        persisted_state.workspace_policies[index].policy.offline_first = (try reader.readByte()) != 0;
        persisted_state.workspace_policies[index].policy.personal_e2ee = (try reader.readByte()) != 0;
        persisted_state.workspace_policies[index].policy.device_to_device_policy_id = state_support.readOptionalU64(try reader.readU64());
        persisted_state.workspace_policies[index].policy.relay_policy_id = state_support.readOptionalU64(try reader.readU64());
        persisted_state.workspace_policies[index].policy.overlay_policy_id = state_support.readOptionalU64(try reader.readU64());
        try readTextInto(&reader, &persisted_state.workspace_policies[index].policy.relay_domain, &persisted_state.workspace_policies[index].policy.relay_domain_len);
        const prefix_count = try reader.readU16();
        if (prefix_count > MAX_SELECTIVE_PREFIXES) return error.CorruptState;
        persisted_state.workspace_policies[index].policy.selective_prefix_count = prefix_count;
        var prefix_index: usize = 0;
        while (prefix_index < prefix_count) : (prefix_index += 1) {
            try readTextInto(
                &reader,
                &persisted_state.workspace_policies[index].policy.selective_prefixes[prefix_index],
                &persisted_state.workspace_policies[index].policy.selective_prefix_lens[prefix_index],
            );
        }
    }

    index = 0;
    while (index < replica_count_value) : (index += 1) {
        persisted_state.replica_entries[index].in_use = true;
        persisted_state.replica_entries[index].entry = state_support.zeroReplicaEntry();
        persisted_state.replica_entries[index].entry.workspace_id = try reader.readU64();
        persisted_state.replica_entries[index].entry.device_id = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.replica_entries[index].entry.path, &persisted_state.replica_entries[index].entry.path_len);
        persisted_state.replica_entries[index].entry.object_id = try reader.readU64();
        persisted_state.replica_entries[index].entry.version_id = try reader.readU64();
    }

    index = 0;
    while (index < conflict_count_value) : (index += 1) {
        persisted_state.conflicts[index].in_use = true;
        persisted_state.conflicts[index].conflict = state_support.zeroConflict();
        persisted_state.conflicts[index].conflict.workspace_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.device_id = try readPrincipal(&reader);
        persisted_state.conflicts[index].conflict.object_id = try reader.readU64();
        try readTextInto(&reader, &persisted_state.conflicts[index].conflict.path, &persisted_state.conflicts[index].conflict.path_len);
        persisted_state.conflicts[index].conflict.local_version_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.remote_version_id = try reader.readU64();
        persisted_state.conflicts[index].conflict.semantic = try parseSyncSemantic(try reader.readByte());
    }

    index = 0;
    while (index < contract_count) : (index += 1) {
        persisted_state.database_contracts[index].in_use = true;
        persisted_state.database_contracts[index].contract = state_support.zeroDatabaseContract();
        persisted_state.database_contracts[index].contract.id = try reader.readU64();
        persisted_state.database_contracts[index].contract.workspace_id = try reader.readU64();
        try readTextInto(&reader, &persisted_state.database_contracts[index].contract.bundle_id, &persisted_state.database_contracts[index].contract.bundle_id_len);
        try readTextInto(&reader, &persisted_state.database_contracts[index].contract.label, &persisted_state.database_contracts[index].contract.label_len);
        persisted_state.database_contracts[index].contract.signature = try readSignature(&reader, &state_support.database_contract_signers[index]);
    }

    index = 0;
    while (index < overlay_count_value) : (index += 1) {
        persisted_state.overlays[index].in_use = true;
        persisted_state.overlays[index].overlay = state_support.zeroOverlay();
        persisted_state.overlays[index].overlay.id = try reader.readU64();
        persisted_state.overlays[index].overlay.workspace_id = try reader.readU64();
        persisted_state.overlays[index].overlay.home_device = try readPrincipal(&reader);
        try readTextInto(&reader, &persisted_state.overlays[index].overlay.service_identity, &persisted_state.overlays[index].overlay.service_identity_len);
        persisted_state.overlays[index].overlay.remote_access_enabled = (try reader.readByte()) != 0;
        const private_service_count = try reader.readU16();
        if (private_service_count > MAX_PRIVATE_SERVICES) return error.CorruptState;
        persisted_state.overlays[index].overlay.private_service_count = private_service_count;
        var service_index: usize = 0;
        while (service_index < private_service_count) : (service_index += 1) {
            try readTextInto(
                &reader,
                &persisted_state.overlays[index].overlay.private_services[service_index],
                &persisted_state.overlays[index].overlay.private_service_lens[service_index],
            );
        }
    }
}

pub fn encodeStateIndex(
    buffer: []u8,
    total_len: usize,
    chunk_count: usize,
    digest: [32]u8,
) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(state_support.state_index_magic);
    try writer.writeU16(state_support.state_version);
    try writer.writeU16(@intCast(total_len));
    try writer.writeByte(@intCast(chunk_count));
    try writer.writeBytes(&digest);
    return buffer[0..writer.offset];
}

pub fn decodeStateIndex(payload: []const u8) Error!StateIndex {
    var reader = CursorReader{ .buffer = payload };
    var magic_buffer: [state_support.state_index_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, state_support.state_index_magic)) return error.CorruptState;
    if ((try reader.readU16()) != state_support.state_version) return error.UnsupportedStateVersion;
    const total_len = try reader.readU16();
    const chunk_count = try reader.readByte();
    var digest: [32]u8 = undefined;
    try reader.readBytes(&digest);
    return .{
        .total_len = total_len,
        .chunk_count = chunk_count,
        .digest = digest,
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
    if (signature.signer.len > MAX_LABEL_BYTES) return error.StateTooLarge;
    try writer.writeByte(1);
    try writeText(writer, signature.signer);
    try writer.writeU16(@intCast(signature.public_key_len));
    try writer.writeBytes(signature.public_key[0..signature.public_key_len]);
    try writer.writeU16(@intCast(signature.value_len));
    try writer.writeBytes(signature.value[0..signature.value_len]);
}

fn readSignature(reader: *CursorReader, signer_storage: *[MAX_LABEL_BYTES]u8) Error!manifest.Signature {
    if ((try reader.readByte()) == 0) return .{};

    var signature = manifest.Signature{
        .format = "ed25519",
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

fn parseSyncSemantic(raw: u8) Error!SyncSemantic {
    return switch (raw) {
        0 => .mergeable_crdt,
        1 => .chunked_snapshot,
        2 => .secure_transfer,
        3 => .transactional_contract,
        else => error.CorruptState,
    };
}
