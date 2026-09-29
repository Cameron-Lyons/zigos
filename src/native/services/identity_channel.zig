const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const principal = @import("../core/principal.zig");
const port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const executor = @import("../task/userspace_executor.zig");
const request_mod = @import("identity_request.zig");
const assertion_wire = @import("identity_assertion_wire.zig");
pub const protocol = @import("../../userspace/identity_protocol.zig");

// Retain at a stable address. One explicitly approved, short-lived credential
// grant yields at most one assertion. No application-supplied authority is used.
pub const Channel = struct {
    kernel: ?*port.KernelPort = null,
    backend: request_mod.Backend = undefined,
    grant: request_mod.Grant = undefined,
    task_id: u64 = 0,
    task_owner: principal.PrincipalId = undefined,
    service_task_id: u64 = 0,
    task_generation: u32 = 0,
    service_generation: u32 = 0,
    client_endpoint: u64 = 0,
    server_endpoint: u64 = 0,
    client_capability: u64 = 0,
    server_capability: u64 = 0,
    rp: [64]u8 = @splat(0),
    origin: [96]u8 = @splat(0),
    request_id: u64 = 0,
    pending_challenge: [protocol.MAX_CHALLENGE_BYTES]u8 = @splat(0),
    pending_len: u8 = 0,
    running: bool = false,
    retiring: bool = false,
    complete: bool = false,
    result: [assertion_wire.wire.MAX_BYTES]u8 = @splat(0),
    result_len: u16 = 0,
    sent: u16 = 0,
    outgoing: [protocol.MAX_FRAME_BYTES]u8 = @splat(0),
    outgoing_len: u8 = 0,
    last_ticks: u64 = 0,
    worker_wake: u64 = 0,

    pub fn open(self: *Channel, kernel: *port.KernelPort, backend: request_mod.Backend, task_id: u64, service_task_id: u64, grant: request_mod.Grant, now: u64) !protocol.Binding {
        if (self.kernel != null) return error.IdentityChannelAlreadyOpen;
        if (!backend.authorized(backend.context, grant, now) or grant.relying_party_id.len > self.rp.len or grant.origin.len > self.origin.len)
            return error.IdentityRequestDenied;
        const task = kernel.kernel.runtime.find(task_id) orelse return error.TaskNotFound;
        const service_task = kernel.kernel.runtime.find(service_task_id) orelse return error.TaskNotFound;
        if (task.state != .active or service_task.state != .active or task_id == service_task_id) return error.PermissionDenied;
        const client = try kernel.endpointCreate(.{
            .header = port.makeHeader(.endpoint_create, task_id),
            .authority_capability_id = executor.resolveMailboxAuthorities(task, kernel.kernel.capability_table, now).bootstrap_capability_id,
            .owner_task_id = task_id,
            .label = "identity-client",
            .flags = .{ .local_only = true },
        }, now);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(client.endpoint.endpoint_id), now) catch unreachable;
        const server = try kernel.endpointCreate(.{
            .header = port.makeHeader(.endpoint_create, service_task_id),
            .authority_capability_id = executor.resolveMailboxAuthorities(service_task, kernel.kernel.capability_table, now).bootstrap_capability_id,
            .owner_task_id = service_task_id,
            .label = "identity-session",
            .flags = .{ .local_only = true, .service_port = true },
        }, now);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(server.endpoint.endpoint_id), now) catch unreachable;
        _ = try kernel.endpointConnect(.{
            .header = port.makeHeader(.endpoint_connect, task_id),
            .endpoint_capability_id = client.capability_id,
            .peer_endpoint_capability_id = server.capability_id,
            .peer_endpoint_id = server.endpoint.endpoint_id,
        }, now);
        self.* = .{ .kernel = kernel, .backend = backend, .grant = grant, .task_id = task_id, .task_owner = task.owner, .service_task_id = service_task_id, .client_endpoint = client.endpoint.endpoint_id, .server_endpoint = server.endpoint.endpoint_id, .client_capability = client.capability_id, .server_capability = server.capability_id, .last_ticks = now };
        self.task_generation = task.process_generation;
        self.service_generation = service_task.process_generation;
        @memcpy(self.rp[0..grant.relying_party_id.len], grant.relying_party_id);
        @memcpy(self.origin[0..grant.origin.len], grant.origin);
        self.grant.relying_party_id = self.rp[0..grant.relying_party_id.len];
        self.grant.origin = self.origin[0..grant.origin.len];
        return .{ .endpoint_capability_id = client.capability_id, .service_endpoint_id = server.endpoint.endpoint_id, .credential_id = grant.credential_id };
    }

    pub fn valid(self: *const Channel, now: u64) bool {
        const kernel = self.kernel orelse return false;
        if (now < self.last_ticks or !self.backend.authorized(self.backend.context, self.grant, now)) return false;
        const task = kernel.kernel.runtime.findConst(self.task_id) orelse return false;
        const service_task = kernel.kernel.runtime.findConst(self.service_task_id) orelse return false;
        if (task.state != .active or service_task.state != .active or !task.owner.eql(self.task_owner) or
            task.process_generation != self.task_generation or service_task.process_generation != self.service_generation or
            !task.hasCapability(self.client_capability) or !service_task.hasCapability(self.server_capability)) return false;
        _ = kernel.kernel.capability_table.requireUsable(self.client_capability, now) catch return false;
        _ = kernel.kernel.capability_table.requireUsable(self.server_capability, now) catch return false;
        const client = kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.client_endpoint)) catch return false;
        const server = kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.server_endpoint)) catch return false;
        return client.owner_task_id == self.task_id and server.owner_task_id == self.service_task_id;
    }

    pub fn hasPendingWork(self: *const Channel) bool {
        const kernel = self.kernel orelse return false;
        if (self.running) return false;
        if (self.pending_len != 0) return self.worker_wake <= self.last_ticks;
        const task = kernel.kernel.runtime.findConst(self.task_id) orelse return true;
        if (task.state != .active) return true;
        if (self.outgoing_len != 0) {
            const client = kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.client_endpoint)) catch return true;
            return client.queued_messages < endpoint.MAX_ENDPOINT_QUEUE;
        }
        const server = kernel.kernel.endpoint_table.descriptor(ids.endpoint(self.server_endpoint)) catch return true;
        return server.queued_messages != 0;
    }

    pub fn nextWake(self: *const Channel) ?u64 {
        if (self.kernel == null) return null;
        return if (self.running or self.pending_len != 0) @min(self.grant.expires_at_ticks, self.worker_wake) else self.grant.expires_at_ticks;
    }

    pub fn service(self: *Channel, now: u64) bool {
        if (self.kernel == null) return false;
        if (self.retiring or !self.valid(now)) {
            self.retiring = true;
            if (self.running) {
                self.backend.cancel(self.backend.context);
                if (now < self.worker_wake and now >= self.last_ticks) return false;
                self.worker_wake = now +| 1;
                if (!self.cancelStep(now)) return true;
            }
            self.close(now);
            return true;
        }
        self.last_ticks = now;
        return self.step(now) catch {
            self.retiring = true;
            if (!self.running) self.close(now);
            return true;
        };
    }

    fn step(self: *Channel, now: u64) !bool {
        const kernel = self.kernel.?;
        if (self.pending_len != 0) {
            if (now < self.worker_wake) return false;
            self.backend.start(self.backend.context, .{ .grant = self.grant, .challenge = self.pending_challenge[0..self.pending_len] }, now) catch |err| {
                if (err == error.WorkerBusy) {
                    self.worker_wake = now +| 1;
                    return false;
                }
                return err;
            };
            @memset(&self.pending_challenge, 0);
            self.pending_len = 0;
            self.running = true;
            self.worker_wake = now;
            return true;
        }
        if (self.outgoing_len != 0) {
            kernel.endpointSend(.{
                .header = port.makeHeader(.endpoint_send, self.service_task_id),
                .endpoint_capability_id = self.server_capability,
                .reply_endpoint_id = self.client_endpoint,
                .correlation_id = self.request_id,
                .payload = self.outgoing[0..self.outgoing_len],
            }, now) catch |err| {
                if (err == error.RingFull) return false;
                return err;
            };
            self.sent += self.outgoing_len - 20;
            @memset(&self.outgoing, 0);
            self.outgoing_len = 0;
            return true;
        }
        if (self.running) {
            if (now < self.worker_wake) return false;
            self.worker_wake = now +| 1;
            const assertion = (try self.backend.poll(self.backend.context, now)) orelse return true;
            self.running = false;
            if (assertion.credential_id != self.grant.credential_id or
                !std.mem.eql(u8, assertion.relyingPartySlice(), self.grant.relying_party_id) or
                !std.mem.eql(u8, assertion.originSlice(), self.grant.origin)) return error.IdentityRequestDenied;
            self.result_len = @intCast((try assertion_wire.encode(&assertion, &self.result)).len);
            self.complete = true;
            try self.queueChunk();
            return true;
        }
        var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        var attached: abi.CapabilityDescriptor = undefined;
        const received = (try kernel.endpointRecv(.{
            .header = port.makeHeader(.endpoint_recv, self.service_task_id),
            .endpoint_capability_id = self.server_capability,
            .receiver_task_id = self.service_task_id,
            .payload_out = &bytes,
            .attached_capability_out = &attached,
        }, now)) orelse return false;
        if (received.attached_capability) |cap| {
            _ = kernel.kernel.runtime.revokeCapability(self.service_task_id, cap.capability_id) catch {};
            kernel.kernel.capability_table.revokeGrant(cap.capability_id) catch {};
            return error.UnexpectedAuthority;
        }
        if (received.message.sender_task_id != self.task_id or received.message.sender_endpoint_id != self.client_endpoint) return error.UnexpectedPeer;
        const frame = try protocol.decode(bytes[0..received.message.payload_len]);
        if (frame.request_id != received.message.correlation_id or (self.request_id != 0 and frame.request_id != self.request_id)) return error.InvalidIdentityRequest;
        switch (frame.body) {
            .assert => |challenge| {
                if (self.request_id != 0) return error.IdentityGrantConsumed;
                self.request_id = frame.request_id;
                @memcpy(self.pending_challenge[0..challenge.len], challenge);
                self.pending_len = @intCast(challenge.len);
            },
            .read => |offset| {
                if (!self.complete or offset != self.sent or self.sent >= self.result_len) return error.InvalidIdentityRequest;
                try self.queueChunk();
            },
            .finish => {
                if (!self.complete or self.sent != self.result_len) return error.InvalidIdentityRequest;
                self.close(now);
            },
            .reply => return error.InvalidIdentityRequest,
        }
        return true;
    }

    fn queueChunk(self: *Channel) !void {
        const end = @min(@as(usize, self.sent) + protocol.CHUNK_BYTES, self.result_len);
        self.outgoing_len = @intCast((try protocol.encode(&self.outgoing, .{ .request_id = self.request_id, .body = .{ .reply = .{ .status = .ok, .total = self.result_len, .offset = self.sent, .bytes = self.result[self.sent..end] } } })).len);
    }

    pub fn close(self: *Channel, now: u64) void {
        const kernel = self.kernel orelse return;
        // Exclusive teardown only. Ordinary revocation drains one worker step
        // per service visit so lock and expiry do not block userspace dispatch.
        while (self.running and !self.cancelStep(now)) {}
        for ([_]u64{ self.server_endpoint, self.client_endpoint }) |id| kernel.kernel.retireEndpoint(ids.endpoint(id), now) catch |err| switch (err) {
            error.EndpointNotFound => {},
            else => unreachable,
        };
        @memset(std.mem.asBytes(self), 0);
        self.kernel = null;
    }

    fn cancelStep(self: *Channel, now: u64) bool {
        self.backend.cancel(self.backend.context);
        if (self.backend.poll(self.backend.context, now)) |result| {
            if (result == null) return false;
        } else |_| {}
        self.backend.cancel(self.backend.context);
        self.running = false;
        return true;
    }

    comptime {
        if (@sizeOf(@This()) > 1024) @compileError("identity channel exceeds bounded storage");
    }
};
