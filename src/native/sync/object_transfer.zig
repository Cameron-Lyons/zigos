//! One bounded inbound object transfer. Network callers supply ciphertext only;
//! the receiving service owns routing, capabilities, clock, storage and signer.
const std = @import("std");
const channel_mod = @import("peer_channel.zig");
const capability = @import("../kernel_api/capability.zig");
const service_authority = @import("../services/service_authority.zig");
const sync_service = @import("sync_service.zig");
const storage = @import("../storage/storage_service.zig");
const objects = @import("../storage/object_store.zig");
const workspace = @import("../storage/workspace.zig");
const sealed_signer = @import("../storage/sealed_object_signer.zig");
const signing = @import("../core/signing.zig");
const cursor = @import("binary_cursor");
const Hash = std.crypto.hash.sha2.Sha256;
const WireError = error{MalformedTransfer};
const Reader = cursor.Reader(WireError, error.MalformedTransfer);
const Writer = cursor.Writer(WireError, error.MalformedTransfer);
pub const MAX_CHUNK = channel_mod.MAX_PAYLOAD - 13;
pub const MAX_IDLE_TICKS = 30_000;

pub const Begin = struct {
    id: u64,
    workspace_id: u64,
    object_id: u64,
    expected_version: u64,
    length: u32,
    digest: [32]u8,
};

pub const Offer = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    limit: u32,
};

pub const Progress = struct {
    id: u64,
    received: u32,
    version_id: u64 = 0,
    checkpoint_generation: u64 = 0,

    pub fn durable(self: Progress) bool {
        return self.version_id != 0 and self.checkpoint_generation != 0;
    }
};

pub const Binding = struct {
    workspace_id: u64,
    object_id: u64,
    local_device: u64,
    peer_device: u64,
    peer_capability_id: u64,
    transport: sync_service.TransportMode = .device_to_device,
};

const Transfer = struct {
    request: Begin,
    session: [16]u8,
    received: u32 = 0,
    applied_version: u64 = 0,
    checkpoint_generation: u64 = 0,
    deadline: u64,
};

// Storage, sync and caller-owned scratch must stay at stable addresses. One
// service serializes calls and invokes expire() from its own monotonic clock.
// The buffer limits the admitted payload; there is no allocation on the wire.
pub const Receiver = struct {
    store: *storage.Service,
    sync: *sync_service.Service,
    capabilities: *const capability.CapabilityTable,
    binding: Binding,
    scratch: []u8,
    transfer: ?Transfer = null,

    pub fn receive(self: *Receiver, channel: *channel_mod.Channel, authority: service_authority.Context, signer: sealed_signer.Signer, frame: []const u8) !Progress {
        const entry = try self.validate(channel, authority, signer);
        return self.receiveImpl(channel, authority, signer, frame, entry);
    }

    // Admission and cached reply transmission use the same local authority
    // checks as writes. No peer-selected capability or object enters here.
    pub fn validate(self: *Receiver, channel: *channel_mod.Channel, authority: service_authority.Context, signer: sealed_signer.Signer) !workspace.Entry {
        errdefer self.reset();
        try signer.validateService(self.store.owner, self.store.task_id, authority.now_ticks);
        const owner = (self.store.findWorkspaceRecordConst(self.binding.workspace_id) orelse return error.WorkspaceNotFound).owner;
        if (!signer.key.authority.?.owner.eql(owner) or authority.now_ticks == 0 or
            authority.task_id != self.sync.task_id or !authority.principal.eql(self.sync.owner)) return error.PermissionDenied;
        _ = try service_authority.requireServiceAuthority(self.capabilities, self.sync.service_id, authority, .endpoint_connect);
        try channel.validate(authority.now_ticks);
        if (!channel.established()) return error.InvalidState;
        const entry = try self.authorize(channel, authority.now_ticks);
        try self.store.requireDurableBoundary();
        return entry;
    }

    pub fn receiveForVerification(self: *Receiver, channel: *channel_mod.Channel, authority: service_authority.Context, signer: signing.SignerIdentity, frame: []const u8) !Progress {
        if (comptime @import("builtin").os.tag == .freestanding) {
            if (comptime !@import("../../kernel/config.zig").includesVerificationEvidence()) return error.SealedSigningKeyRequired;
        }
        errdefer self.reset();
        if (authority.now_ticks == 0 or authority.task_id != self.sync.task_id or !authority.principal.eql(self.sync.owner)) {
            self.reset();
            return error.PermissionDenied;
        }
        _ = service_authority.requireServiceAuthority(self.capabilities, self.sync.service_id, authority, .endpoint_connect) catch |err| {
            self.reset();
            return err;
        };
        const entry = try self.authorize(channel, authority.now_ticks);
        try self.store.requireDurableBoundary();
        return self.receiveImpl(channel, authority, signer, frame, entry);
    }

    fn receiveImpl(self: *Receiver, channel: *channel_mod.Channel, authority: service_authority.Context, signer: anytype, frame: []const u8, entry: workspace.Entry) !Progress {
        self.expire(authority.now_ticks);
        var plaintext: [channel_mod.MAX_PAYLOAD]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        const message = channel.open(&plaintext, frame, authority.now_ticks) catch |err| {
            if (!channel.established()) self.reset();
            return err;
        };
        var reader = Reader{ .buffer = message };
        const kind = try reader.readByte();
        const id = try reader.readU64();
        if (id == 0) return error.MalformedTransfer;
        const session = channel.crypto.transport.hash[0..16].*;
        if (self.transfer) |transfer| {
            if (!std.mem.eql(u8, &transfer.session, &session)) self.reset();
        }
        switch (kind) {
            1 => {
                var request = Begin{ .id = id, .workspace_id = try reader.readU64(), .object_id = try reader.readU64(), .expected_version = try reader.readU64(), .length = try reader.readU32(), .digest = undefined };
                try reader.readBytes(&request.digest);
                if (!reader.eof() or request.expected_version == 0 or request.workspace_id != self.binding.workspace_id or request.object_id != self.binding.object_id) return error.MalformedTransfer;
                if (request.length > self.scratch.len or request.length > objects.MAX_PAYLOAD_BYTES) return error.TransferTooLarge;
                if (self.transfer) |*active| {
                    if (active.request.id == request.id) {
                        if (!std.meta.eql(active.request, request)) return error.TransferMismatch;
                        return progress(active.*);
                    }
                    if (active.checkpoint_generation == 0) return error.TransferBusy;
                }
                self.reset();
                self.transfer = .{ .request = request, .session = session, .deadline = try deadline(authority.now_ticks) };
            },
            2 => {
                const transfer = try self.current(id);
                if (transfer.checkpoint_generation != 0 or transfer.applied_version != 0) return error.TransferBusy;
                const offset = try reader.readU32();
                const bytes = try reader.readSlice(reader.remaining());
                if (bytes.len == 0 or bytes.len > MAX_CHUNK or offset > transfer.request.length or bytes.len > transfer.request.length - offset) return error.MalformedTransfer;
                if (offset > transfer.received) return error.TransferOutOfOrder;
                if (offset < transfer.received) {
                    if (bytes.len > transfer.received - offset or !std.mem.eql(u8, self.scratch[offset..][0..bytes.len], bytes)) return error.TransferMismatch;
                } else {
                    @memcpy(self.scratch[offset..][0..bytes.len], bytes);
                    transfer.received += @intCast(bytes.len);
                }
                transfer.deadline = try deadline(authority.now_ticks);
            },
            3 => {
                if (!reader.eof()) return error.MalformedTransfer;
                const transfer = try self.current(id);
                if (transfer.checkpoint_generation != 0) return progress(transfer.*);
                if (transfer.received != transfer.request.length) return error.TransferIncomplete;
                if (transfer.applied_version == 0) {
                    const payload = self.scratch[0..transfer.request.length];
                    if (!std.mem.eql(u8, &digest(payload), &transfer.request.digest)) return error.TransferMismatch;
                    const current_version = self.store.version(entry.version_id) orelse return error.VersionNotFound;
                    // A retry after process loss recognizes content that is
                    // already committed, without appending another version.
                    if (std.mem.eql(u8, &(try versionDigest(self.store, current_version)), &transfer.request.digest)) {
                        transfer.applied_version = entry.version_id.raw();
                    } else {
                        if (entry.version_id.raw() != transfer.request.expected_version) return error.ObjectChanged;
                        const metadata = if (@TypeOf(signer) == sealed_signer.Signer)
                            try signer.signObjectMetadata(current_version.metadata.labelSlice(), current_version.metadata.contentTypeSlice(), entry.object_type, payload, authority.now_ticks)
                        else
                            try objects.signMetadata(signer, current_version.metadata.labelSlice(), current_version.metadata.contentTypeSlice(), entry.object_type, payload, authority.now_ticks);
                        const parent = self.store.latestVersion(entry.object_id) orelse return error.VersionNotFound;
                        self.store.beginCheckpointBatch();
                        defer self.store.endCheckpointBatch();
                        try self.store.beginTransaction(self.binding.workspace_id);
                        errdefer self.store.abortTransaction(self.binding.workspace_id) catch {};
                        try self.store.stagePut(self.binding.workspace_id, entry.pathSlice(), entry.object_id, entry.version_id, entry.object_type);
                        const written = try self.store.putVersion(.{ .preferred_object_id = entry.object_id, .object_type = entry.object_type, .payload = payload, .metadata = metadata, .parent_version_id = parent.id });
                        try self.store.stagePut(self.binding.workspace_id, entry.pathSlice(), written.object_id, written.version_id, entry.object_type);
                        _ = try self.store.commit(self.binding.workspace_id, authority.now_ticks);
                        transfer.applied_version = written.version_id.raw();
                    }
                } else if (entry.version_id.raw() != transfer.applied_version) return error.ObjectChanged;
                // No receipt or checkpoint generation is returned until both
                // the object bytes and workspace pointer cross the barrier.
                transfer.checkpoint_generation = try self.store.checkpointDurable();
                std.crypto.secureZero(u8, self.scratch[0..transfer.request.length]);
            },
            else => return error.MalformedTransfer,
        }
        return progress(self.transfer.?);
    }

    fn authorize(self: *Receiver, channel: *const channel_mod.Channel, now: u64) !workspace.Entry {
        return authorizeObject(self.store, self.sync, self.capabilities, self.binding, channel, now, true);
    }

    pub fn currentProgress(self: *const Receiver) ?Progress {
        return if (self.transfer) |active| progress(active) else null;
    }

    pub fn offer(self: *Receiver, channel: *channel_mod.Channel, authority: service_authority.Context, signer: sealed_signer.Signer) !Offer {
        const entry = try self.validate(channel, authority, signer);
        return .{ .workspace_id = self.binding.workspace_id, .object_id = self.binding.object_id, .version_id = entry.version_id.raw(), .limit = @intCast(@min(self.scratch.len, objects.MAX_PAYLOAD_BYTES)) };
    }

    fn current(self: *Receiver, id: u64) !*Transfer {
        const transfer = if (self.transfer) |*value| value else return error.TransferMissing;
        if (transfer.request.id != id) return error.TransferMismatch;
        return transfer;
    }

    pub fn expire(self: *Receiver, now: u64) void {
        if (self.transfer) |transfer| if (now >= transfer.deadline) self.reset();
    }

    pub fn reset(self: *Receiver) void {
        if (self.transfer) |transfer| std.crypto.secureZero(u8, self.scratch[0..@min(self.scratch.len, transfer.request.length)]);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.transfer));
        self.transfer = null;
    }
};

// Both directions bind the local object and peer before reading or writing.
pub fn authorizeObject(store: *storage.Service, service: *sync_service.Service, capabilities: *const capability.CapabilityTable, binding: Binding, channel: *const channel_mod.Channel, now: u64, wants_write: bool) !workspace.Entry {
    if (channel.graph != service.deviceGraph() or channel.local != binding.local_device or channel.remote != binding.peer_device) return error.PermissionDenied;
    const grant = try capabilities.requireUsable(binding.peer_capability_id, now);
    if (grant.holder.kind != .device or grant.holder.serial != channel.remote or grant.target.kind != .object or grant.target.id != binding.object_id or
        grant.scope.workspace_id == null or grant.scope.workspace_id.? != binding.workspace_id or !grant.scope.broker_only or grant.scope.local_only or !grant.rights.has(if (wants_write) .object_write else .object_read)) return error.PermissionDenied;
    if (grant.scope.task_id) |task| if (task != service.task_id) return error.PermissionDenied;
    const record = store.findWorkspaceRecordConst(binding.workspace_id) orelse return error.WorkspaceNotFound;
    const policy = service.findWorkspacePolicy(binding.workspace_id) orelse return error.WorkspacePolicyNotFound;
    const peer = service.findDeviceRecord(.{ .kind = .device, .serial = channel.remote }) orelse return error.DeviceNotFound;
    if (!policy.owner.eql(record.owner) or !peer.owner.eql(record.owner)) return error.PermissionDenied;
    try service.authorizeTransport(policy, binding.transport, null);
    const entry = try store.findEntryForObject(binding.workspace_id, binding.object_id);
    if (!policy.matchesPath(entry.pathSlice()) or !store.workspaceHasAccess(binding.workspace_id, .{
        .principal_id = grant.holder,
        .object_id = entry.object_id,
        .path = entry.pathSlice(),
        .wants_write = wants_write,
        .network_scope = if (binding.transport == .relay_assisted) .relay_assisted else .trusted_overlay,
        .now_ticks = now,
    })) return error.PermissionDenied;
    // Collections, event streams and secret objects require their typed
    // transactional/secret protocols; byte replacement cannot invoke them.
    switch (entry.object_type) {
        .blob, .document, .media_asset, .model_artifact => {},
        else => return error.UnsupportedObjectType,
    }
    return entry;
}

fn deadline(now: u64) !u64 {
    return std.math.add(u64, now, MAX_IDLE_TICKS) catch error.TransferExpired;
}

fn progress(transfer: Transfer) Progress {
    return .{ .id = transfer.request.id, .received = transfer.received, .version_id = if (transfer.checkpoint_generation != 0) transfer.applied_version else 0, .checkpoint_generation = transfer.checkpoint_generation };
}

pub fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Hash.hash(bytes, &result, .{});
    return result;
}

pub fn versionDigest(store: *const storage.Service, version: *const objects.VersionRecord) ![32]u8 {
    var chunks = try store.versionChunkCursor(version);
    var hasher = Hash.init(.{});
    while (try chunks.next()) |chunk| hasher.update(chunk.bytes);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

pub fn encodeOffer(buffer: []u8, offer: Offer) WireError![]const u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.writeByte(5);
    try writer.writeU64(offer.workspace_id);
    try writer.writeU64(offer.object_id);
    try writer.writeU64(offer.version_id);
    try writer.writeU32(offer.limit);
    return buffer[0..writer.offset];
}

pub fn decodeOffer(bytes: []const u8) WireError!Offer {
    var reader = Reader{ .buffer = bytes };
    if (try reader.readByte() != 5) return error.MalformedTransfer;
    const offer = Offer{ .workspace_id = try reader.readU64(), .object_id = try reader.readU64(), .version_id = try reader.readU64(), .limit = try reader.readU32() };
    if (!reader.eof() or offer.workspace_id == 0 or offer.object_id == 0 or offer.version_id == 0 or offer.limit > objects.MAX_PAYLOAD_BYTES) return error.MalformedTransfer;
    return offer;
}

pub fn encodeBegin(buffer: []u8, request: Begin) WireError![]const u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.writeByte(1);
    try writer.writeU64(request.id);
    try writer.writeU64(request.workspace_id);
    try writer.writeU64(request.object_id);
    try writer.writeU64(request.expected_version);
    try writer.writeU32(request.length);
    try writer.writeBytes(&request.digest);
    return buffer[0..writer.offset];
}

pub fn encodeChunk(buffer: []u8, id: u64, offset: u32, bytes: []const u8) WireError![]const u8 {
    if (bytes.len == 0 or bytes.len > MAX_CHUNK) return error.MalformedTransfer;
    var writer = Writer{ .buffer = buffer };
    try writer.writeByte(2);
    try writer.writeU64(id);
    try writer.writeU32(offset);
    try writer.writeBytes(bytes);
    return buffer[0..writer.offset];
}

pub fn encodeCommit(buffer: []u8, id: u64) WireError![]const u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.writeByte(3);
    try writer.writeU64(id);
    return buffer[0..writer.offset];
}

pub fn encodeProgress(buffer: []u8, value: Progress) WireError![]const u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.writeByte(4);
    try writer.writeU64(value.id);
    try writer.writeU32(value.received);
    try writer.writeU64(value.version_id);
    try writer.writeU64(value.checkpoint_generation);
    return buffer[0..writer.offset];
}

pub fn decodeProgress(bytes: []const u8) WireError!Progress {
    var reader = Reader{ .buffer = bytes };
    if (try reader.readByte() != 4) return error.MalformedTransfer;
    const value = Progress{ .id = try reader.readU64(), .received = try reader.readU32(), .version_id = try reader.readU64(), .checkpoint_generation = try reader.readU64() };
    if (!reader.eof() or value.id == 0 or (value.version_id == 0) != (value.checkpoint_generation == 0)) return error.MalformedTransfer;
    return value;
}

comptime {
    if (@sizeOf(Receiver) > 240) @compileError("object receiver exceeds bounded coordination state");
}
