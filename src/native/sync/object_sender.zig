//! Read-authorized object transmission. Retains identities and offsets, never
//! borrowed payload pointers or a second object-sized plaintext snapshot.
const std = @import("std");
const peer = @import("peer_channel.zig");
const transfer = @import("object_transfer.zig");
const storage = @import("../storage/storage_service.zig");
const sync = @import("sync_service.zig");
const capability = @import("../kernel_api/capability.zig");
const authority_mod = @import("../services/service_authority.zig");

const Phase = enum { offer, begin, chunk, commit, complete, closed };
pub const Sender = struct {
    store: *storage.Service,
    sync: *sync.Service,
    capabilities: *const capability.CapabilityTable,
    binding: transfer.Binding,
    version_id: u64,
    blob_address: [32]u8,
    session: [16]u8,
    request: transfer.Begin,
    acknowledged: u32 = 0,
    sent_end: u32 = 0,
    sent: bool = false,
    phase: Phase = .offer,
    receipt: ?transfer.Progress = null,

    pub fn init(store: *storage.Service, service: *sync.Service, capabilities: *const capability.CapabilityTable, binding: transfer.Binding, channel: *peer.Channel, authority: authority_mod.Context) !Sender {
        try requireChannel(service, capabilities, channel, authority);
        const entry = try transfer.authorizeObject(store, service, capabilities, binding, channel, authority.now_ticks, false);
        const version = store.version(entry.version_id) orelse return error.VersionNotFound;
        const blob = store.versionBlob(version) orelse return error.BlobNotFound;
        return .{ .store = store, .sync = service, .capabilities = capabilities, .binding = binding, .version_id = entry.version_id.raw(), .blob_address = blob.address, .session = channel.crypto.transport.hash[0..16].*, .request = .{ .id = 0, .workspace_id = 0, .object_id = 0, .expected_version = 0, .length = @intCast(blob.payloadLen()), .digest = try transfer.versionDigest(store, version) } };
    }

    fn requireChannel(service: *sync.Service, capabilities: *const capability.CapabilityTable, channel: *peer.Channel, authority: authority_mod.Context) !void {
        if (authority.now_ticks == 0 or authority.task_id != service.task_id or !authority.principal.eql(service.owner)) return error.PermissionDenied;
        _ = try authority_mod.requireServiceAuthority(capabilities, service.service_id, authority, .endpoint_connect);
        try channel.signer.validateService(service.owner, service.task_id, authority.now_ticks);
        try channel.validate(authority.now_ticks);
        if (!channel.established()) return error.InvalidState;
    }

    pub fn validate(self: *Sender, channel: *peer.Channel, authority: authority_mod.Context) !void {
        if (self.phase == .closed) return error.InvalidState;
        try requireChannel(self.sync, self.capabilities, channel, authority);
        if (!std.mem.eql(u8, &self.session, channel.crypto.transport.hash[0..16])) return error.SessionChanged;
        const entry = try transfer.authorizeObject(self.store, self.sync, self.capabilities, self.binding, channel, authority.now_ticks, false);
        if (entry.version_id.raw() != self.version_id) return error.ObjectChanged;
        const version = self.store.version(self.version_id) orelse return error.VersionNotFound;
        const blob = self.store.versionBlob(version) orelse return error.BlobNotFound;
        if (!std.mem.eql(u8, &self.blob_address, &blob.address) or blob.payloadLen() != self.request.length) return error.ObjectChanged;
    }

    pub fn waitingForOffer(self: *const Sender) bool {
        return self.phase == .offer;
    }

    pub fn hasRequest(self: *const Sender) bool {
        return self.phase == .begin or self.phase == .chunk or self.phase == .commit;
    }

    pub fn complete(self: *const Sender) bool {
        return self.phase == .complete;
    }

    // Returns true only when a new authenticated offer or receipt advances the
    // transfer. Stale receipts never trigger an immediate retransmission.
    pub fn receive(self: *Sender, channel: *peer.Channel, authority: authority_mod.Context, frame: []const u8) !bool {
        try self.validate(channel, authority);
        var plaintext: [peer.MAX_PAYLOAD]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        const message = try channel.open(&plaintext, frame, authority.now_ticks);
        if (message[0] == 5) {
            const offer = try transfer.decodeOffer(message);
            if (!self.waitingForOffer()) return false;
            if (self.request.length > offer.limit) return error.TransferTooLarge;
            // The sole serialized channel owner allocates an ID immediately
            // before its first request. Every published begin consumes a nonce,
            // so a later transfer on this channel cannot reuse an earlier ID.
            self.request.id = std.math.add(u64, channel.crypto.transport.send.nonce, 1) catch return error.NonceExhausted;
            self.request.workspace_id = offer.workspace_id;
            self.request.object_id = offer.object_id;
            self.request.expected_version = offer.version_id;
            self.phase = .begin;
            return true;
        }
        const progress = try transfer.decodeProgress(message);
        if (!self.hasRequest() or progress.id != self.request.id or progress.received > self.request.length) return error.InvalidReceipt;
        if (progress.durable()) {
            if (self.phase != .commit or !self.sent or progress.received != self.request.length) return error.InvalidReceipt;
            self.receipt = progress;
            self.phase = .complete;
            return true;
        }
        if (progress.received < self.acknowledged) return false;
        switch (self.phase) {
            .begin => if (progress.received != 0 or !self.sent) return error.InvalidReceipt,
            .chunk => {
                if (progress.received == self.acknowledged) return false;
                if (!self.sent or progress.received != self.sent_end) return error.InvalidReceipt;
            },
            .commit => return false,
            else => return error.InvalidReceipt,
        }
        self.acknowledged = progress.received;
        self.phase = if (self.acknowledged == self.request.length) .commit else .chunk;
        self.sent = false;
        return true;
    }

    pub fn encode(self: *Sender, channel: *peer.Channel, authority: authority_mod.Context, output: []u8) ![]const u8 {
        try self.validate(channel, authority);
        return switch (self.phase) {
            .begin => transfer.encodeBegin(output, self.request),
            .commit => transfer.encodeCommit(output, self.request.id),
            .chunk => blk: {
                var bytes: [transfer.MAX_CHUNK]u8 = undefined;
                defer std.crypto.secureZero(u8, &bytes);
                const payload = try self.readChunk(&bytes);
                self.sent_end = self.acknowledged + @as(u32, @intCast(payload.len));
                break :blk transfer.encodeChunk(output, self.request.id, self.acknowledged, payload);
            },
            else => error.InvalidState,
        };
    }

    fn readChunk(self: *Sender, output: []u8) ![]const u8 {
        const version = self.store.version(self.version_id) orelse return error.VersionNotFound;
        var chunks = try self.store.versionChunkCursorAt(version, self.acknowledged);
        const length = @min(output.len, self.request.length - self.acknowledged);
        var copied: usize = 0;
        // Verified page lengths locate the first chunk directly. A transport
        // frame visits only its containing page and any page it crosses; no
        // storage pointer survives the synchronous cursor walk.
        while (try chunks.next()) |chunk| {
            const position = self.acknowledged + copied;
            if (position >= chunk.offset + chunk.bytes.len) continue;
            if (position < chunk.offset) return error.CorruptBlob;
            const offset = position - chunk.offset;
            const amount = @min(length - copied, chunk.bytes.len - offset);
            @memcpy(output[copied..][0..amount], chunk.bytes[offset..][0..amount]);
            copied += amount;
            if (copied == length) return output[0..copied];
        }
        return error.CorruptBlob;
    }

    pub fn markSent(self: *Sender) void {
        if (self.hasRequest()) self.sent = true;
    }

    pub fn reset(self: *Sender) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.request));
        std.crypto.secureZero(u8, &self.blob_address);
        std.crypto.secureZero(u8, &self.session);
        self.receipt = null;
        self.sent = false;
        self.phase = .closed;
    }
};

comptime {
    if (@sizeOf(Sender) > 288) @compileError("object sender exceeds bounded coordination state");
}
