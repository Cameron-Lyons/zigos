const std = @import("std");
const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const operation_guard = @import("../platform/operation_guard.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const component_port = @import("../kernel_api/component_port.zig");
const document_save = @import("document_save.zig");
const object_signer = @import("sealed_object_signer.zig");
const storage_service = @import("storage_service.zig");
pub const protocol = @import("../../userspace/document_protocol.zig");

// The broker binds this channel to an already-opened document. No path,
// principal, signer, or authority identifier comes from a save frame.
// The path and session signing authority must outlive this channel.
pub const Binding = struct {
    client_endpoint_id: u64,
    server_endpoint_capability_id: u64,
    authority: storage_service.AuthorityContext,
    workspace_id: u64,
    path: []const u8,
    object_id: u64,
    signer: object_signer.Signer,
};

const Attempt = struct {
    request_id: u64,
    begin: protocol.Begin,
    received: u16 = 0,
    bytes: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined,
    saved: ?struct { version_id: u64, checkpoint_generation: u64 } = null,
};

const PendingReply = struct {
    endpoint_id: u64,
    request_id: u64,
    length: u8,
    bytes: [protocol.MAX_FRAME_BYTES]u8,
};

pub const Server = struct {
    kernel: *component_port.KernelPort,
    storage: *storage_service.StoragePort,
    binding: Binding,
    attempt: ?Attempt = null,
    saver: document_save.Session = .{},
    pending_reply: ?PendingReply = null,
    running: bool = false,
    closing: bool = false,

    const DispatchGuard = struct {
        server: *Server,
        observed_ticks: u64,
        write: bool,

        fn check(context: *anyopaque) operation_guard.Error!u64 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const server = self.server;
            if (server.closing) return error.Cancelled;
            if (cooperative.current()) |worker| if (worker.cancel_requested) return error.Cancelled;
            const live_ticks = if (comptime builtin.os.tag == .freestanding) blk: {
                const timer = @import("../../kernel/timer/timer.zig");
                timer.synchronize();
                break :blk timer.getTicks();
            } else self.observed_ticks;
            if (live_ticks < self.observed_ticks) return error.OperationClockRollback;
            const owner_guard = if (server.binding.signer.key.authority) |authority| authority.publication_guard else null;
            const now = try operation_guard.currentTicks(owner_guard, live_ticks);
            const runtime = server.kernel.kernel.runtime;
            const client = runtime.findConst(server.binding.authority.task_id) orelse return error.OperationAuthorityChanged;
            const service = runtime.findConst(server.storage.core.task_id) orelse return error.OperationAuthorityChanged;
            if (client.state != .active or !client.owner.eql(server.binding.authority.principal) or
                !client.hasCapability(server.binding.authority.capability_id) or service.state != .active or
                !service.owner.eql(server.storage.core.owner) or !service.hasCapability(server.binding.server_endpoint_capability_id))
                return error.OperationAuthorityChanged;
            const endpoints = server.kernel.kernel.endpoint_table;
            const client_endpoint = endpoints.descriptor(ids.endpoint(server.binding.client_endpoint_id)) catch return error.OperationAuthorityChanged;
            if (client_endpoint.owner_task_id != client.id) return error.OperationAuthorityChanged;
            // endpointRecv/Send check the service endpoint grant; also reject a
            // removed endpoint before publishing any storage mutation.
            const resolved = server.kernel.kernel.capability_table.resolveUsable(server.binding.server_endpoint_capability_id, now) catch return error.OperationAuthorityChanged;
            const grant = resolved.capability;
            if (grant.target.kind != .endpoint or !grant.holder.eql(service.owner) or grant.scope.task_id != service.id)
                return error.OperationAuthorityChanged;
            if (grant.rights != .endpoint or !grant.rights.endpoint.endpoint_send or !grant.rights.endpoint.endpoint_recv)
                return error.OperationAuthorityChanged;
            const service_endpoint = endpoints.descriptor(ids.endpoint(grant.target.id)) catch return error.OperationAuthorityChanged;
            if (service_endpoint.owner_task_id != service.id) return error.OperationAuthorityChanged;
            var authority = server.binding.authority;
            authority.now_ticks = now;
            const entry = server.storage.openEntry(authority, server.binding.workspace_id, server.binding.path, if (self.write) .write else .read) catch return error.OperationPolicyDenied;
            if (entry.object_type != .document or entry.object_id.raw() != server.binding.object_id) return error.OperationAuthorityChanged;
            server.binding.signer.validateService(server.storage.core.owner, service.id, now) catch return error.OperationPolicyDenied;
            return now;
        }
    };

    // At most one frame or reply per dispatch. Backpressure retains the receipt
    // and prevents consuming more requests until that response is published.
    pub fn runOnce(self: *Server, now_ticks: u64) !bool {
        if (self.running) return error.DocumentOperationBusy;
        if (self.closing) return false;
        self.running = true;
        defer self.running = false;
        // The protocol and hardware provider can suspend with these task IDs
        // borrowed. Pressure reaping cannot recycle either incarnation then.
        const runtime = self.kernel.kernel.runtime;
        var client_borrow = if (runtime.find(self.binding.authority.task_id)) |task| runtime.borrowResolvedTask(task) else null;
        defer if (client_borrow) |*borrow| borrow.release();
        const service = runtime.find(self.storage.core.task_id) orelse return error.TaskNotFound;
        var service_borrow = runtime.borrowResolvedTask(service);
        defer service_borrow.release();
        if (self.pending_reply != null) return self.flushReply(now_ticks);
        var payload: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        var attached: abi.CapabilityDescriptor = undefined;
        const received = (try self.kernel.endpointRecv(.{
            .header = component_port.makeHeader(.endpoint_recv, self.storage.core.task_id),
            .endpoint_capability_id = self.binding.server_endpoint_capability_id,
            .receiver_task_id = self.storage.core.task_id,
            .payload_out = &payload,
            .attached_capability_out = &attached,
        }, now_ticks)) orelse return false;
        if (received.attached_capability) |attached_grant| {
            // This native backend owns the received grant. Reject and release
            // unexpected transfers before parsing, including malformed frames.
            _ = try self.kernel.kernel.runtime.revokeCapability(self.storage.core.task_id, attached_grant.capability_id);
            try self.kernel.kernel.capability_table.revokeGrant(attached_grant.capability_id);
        }
        const frame = protocol.decode(payload[0..received.message.payload_len]) catch return true;
        if (frame.request_id != received.message.correlation_id) return true;
        const sender = self.kernel.kernel.runtime.find(received.message.sender_task_id);
        const response: ?protocol.Body = if (sender == null or sender.?.state != .active or
            !sender.?.hasCapability(self.binding.authority.capability_id) or
            received.message.sender_endpoint_id != self.binding.client_endpoint_id or
            received.message.sender_task_id != self.binding.authority.task_id or received.attached_capability != null)
            .{ .receipt = .{ .status = .permission_denied } }
        else if (frame.body == .read)
            self.read(frame.body.read.version_id, frame.body.read.offset, now_ticks)
        else if (self.handle(frame, now_ticks)) |receipt| .{ .receipt = receipt } else null;
        if (response) |value| {
            var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
            const encoded = try protocol.encode(&bytes, .{ .request_id = frame.request_id, .body = value });
            self.pending_reply = .{ .endpoint_id = received.message.sender_endpoint_id, .request_id = frame.request_id, .length = @intCast(encoded.len), .bytes = bytes };
            _ = try self.flushReply(now_ticks);
        }
        return true;
    }

    fn flushReply(self: *Server, now_ticks: u64) !bool {
        var pending = self.pending_reply orelse return false;
        var send_ticks = now_ticks;
        const frame = try protocol.decode(pending.bytes[0..pending.length]);
        // Retained results are advisory. Revalidate at the actual endpoint
        // enqueue, including replies delayed by client queue backpressure.
        if (frame.body == .read_data or (frame.body == .receipt and frame.body.receipt.status == .saved)) {
            var context = DispatchGuard{ .server = self, .observed_ticks = now_ticks, .write = frame.body == .receipt };
            send_ticks = DispatchGuard.check(&context) catch blk: {
                const bytes = try protocol.encode(&pending.bytes, .{ .request_id = pending.request_id, .body = .{ .receipt = .{ .status = .permission_denied } } });
                pending.length = @intCast(bytes.len);
                self.pending_reply = pending;
                break :blk now_ticks;
            };
        }
        if (self.closing) {
            self.pending_reply = null;
            return true;
        }
        self.kernel.endpointSend(.{
            .header = component_port.makeHeader(.endpoint_send, self.storage.core.task_id),
            .correlation_id = pending.request_id,
            .endpoint_capability_id = self.binding.server_endpoint_capability_id,
            .reply_endpoint_id = pending.endpoint_id,
            .payload = pending.bytes[0..pending.length],
        }, send_ticks) catch |err| switch (err) {
            error.RingFull => return false,
            error.EndpointNotFound => {
                // Generational handles forbid delivery to a replacement task.
                self.pending_reply = null;
                return true;
            },
            else => return err,
        };
        self.pending_reply = null;
        return true;
    }

    fn read(self: *Server, version_id: u64, offset: u16, now_ticks: u64) protocol.Body {
        var context = DispatchGuard{ .server = self, .observed_ticks = now_ticks, .write = false };
        const actual_ticks = DispatchGuard.check(&context) catch return .{ .receipt = .{ .status = .permission_denied } };
        var authority = self.binding.authority;
        authority.now_ticks = actual_ticks;
        const view = self.storage.openEntry(authority, self.binding.workspace_id, self.binding.path, .read) catch return .{ .receipt = .{ .status = .permission_denied } };
        if (view.object_id.raw() != self.binding.object_id or view.object_type != .document) return .{ .receipt = .{ .status = .permission_denied } };
        if (view.version_id.raw() != version_id) return .{ .receipt = .{ .status = .document_changed } };
        const version = self.storage.core.version(version_id) orelse return .{ .receipt = .{ .status = .document_changed } };
        if (version.object_id.raw() != self.binding.object_id) return .{ .receipt = .{ .status = .document_changed } };
        const blob = self.storage.core.versionBlob(version) orelse return .{ .receipt = .{ .status = .storage_failed } };
        if (blob.payloadLen() > protocol.MAX_DOCUMENT_BYTES) return .{ .receipt = .{ .status = .too_large } };
        const bytes = self.storage.core.versionPayload(version) catch return .{ .receipt = .{ .status = .storage_failed } };
        if (offset > bytes.len or (bytes.len != 0 and offset == bytes.len)) return .{ .receipt = .{ .status = .invalid_request } };
        return .{ .read_data = .{
            .version_id = version_id,
            .total_length = @intCast(bytes.len),
            .offset = offset,
            .bytes = bytes[offset..@min(bytes.len, offset + protocol.READ_CHUNK_BYTES)],
        } };
    }

    fn handle(self: *Server, frame: protocol.Frame, now_ticks: u64) ?protocol.Receipt {
        var context = DispatchGuard{ .server = self, .observed_ticks = now_ticks, .write = true };
        const actual_ticks = DispatchGuard.check(&context) catch return .{ .status = .permission_denied };
        const guard = operation_guard.Guard{ .context = &context, .check_fn = DispatchGuard.check };

        if (frame.body == .begin) {
            if (self.attempt) |*attempt| {
                if (frame.request_id < attempt.request_id) return .{ .status = .stale_request };
                if (frame.request_id == attempt.request_id) {
                    if (!attempt.begin.eql(frame.body.begin)) return .{ .status = .request_conflict };
                    return self.savedReceipt(attempt);
                }
                if (attempt.saved == null) return .{ .status = .busy };
            }
            self.attempt = .{ .request_id = frame.request_id, .begin = frame.body.begin };
            return null;
        }

        const attempt = if (self.attempt) |*value| value else return .{ .status = .incomplete };
        if (frame.request_id != attempt.request_id) return .{ .status = .stale_request };
        switch (frame.body) {
            .chunk => |chunk| {
                if (attempt.saved != null) return null;
                const end = @as(usize, chunk.offset) + chunk.bytes.len;
                if (end > attempt.begin.length or chunk.offset > attempt.received) return .{ .status = .incomplete };
                if (chunk.offset < attempt.received) {
                    if (end > attempt.received or !std.mem.eql(u8, attempt.bytes[chunk.offset..end], chunk.bytes)) return .{ .status = .request_conflict };
                    return null;
                }
                @memcpy(attempt.bytes[chunk.offset..end], chunk.bytes);
                attempt.received = @intCast(end);
                return null;
            },
            .commit => {
                if (self.savedReceipt(attempt)) |saved| return saved;
                if (attempt.received != attempt.begin.length) return .{ .status = .incomplete };
                const text = attempt.bytes[0..attempt.received];
                const digest = protocol.digest(text);
                if (!std.mem.eql(u8, &digest, &attempt.begin.digest)) return .{ .status = .request_conflict };
                const saved = self.saver.save(self.storage.core, .{
                    .workspace_id = self.binding.workspace_id,
                    .path = self.binding.path,
                    .expected_version_id = attempt.begin.expected_version_id,
                    .payload = text,
                    .signer = self.binding.signer,
                    .tick = actual_ticks,
                    .publication_guard = &guard,
                }) catch |err| return .{ .status = switch (err) {
                    error.PolicyDenied,
                    error.HandleRevoked,
                    error.HandleExpired,
                    error.HandleHolderMismatch,
                    error.VaultHandleNotFound,
                    error.SecretOwnerMismatch,
                    error.SigningKeyChanged,
                    error.SigningAuthorityUnavailable,
                    error.InvalidSigningAuthority,
                    error.SealedSigningKeyRequired,
                    error.Cancelled,
                    error.OperationExpired,
                    error.OperationClockRollback,
                    error.OperationAuthorityChanged,
                    error.OperationPolicyDenied,
                    => .permission_denied,
                    error.DocumentChanged, error.NotDocument, error.ObjectMissing => .document_changed,
                    error.DurabilityBarrierFailed, error.NoBackingDevice, error.CheckpointDeferred, error.CorruptImage => .durability_failed,
                    else => .storage_failed,
                } };
                const receipt = protocol.Receipt{
                    .status = .saved,
                    .object_id = saved.object_id,
                    .previous_version_id = saved.previous_version_id,
                    .version_id = saved.version_id,
                    .checkpoint_generation = saved.checkpoint_generation,
                };
                attempt.saved = .{ .version_id = saved.version_id, .checkpoint_generation = saved.checkpoint_generation };
                return receipt;
            },
            .begin, .read => unreachable,
            .receipt, .read_data => return .{ .status = .invalid_request },
        }
    }

    fn savedReceipt(self: *const Server, attempt: *const Attempt) ?protocol.Receipt {
        const saved = attempt.saved orelse return null;
        return .{
            .status = .saved,
            .object_id = self.binding.object_id,
            .previous_version_id = attempt.begin.expected_version_id,
            .version_id = saved.version_id,
            .checkpoint_generation = saved.checkpoint_generation,
        };
    }
};

comptime {
    if (protocol.MAX_FRAME_BYTES > abi.ENDPOINT_INLINE_BYTES) @compileError("document frames exceed the native endpoint payload");
    if (@sizeOf(Server) > 1024) @compileError("document channel exceeds its bounded storage");
}
