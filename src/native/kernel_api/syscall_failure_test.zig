const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const shared_memory = @import("shared_memory.zig");
const syscall_surface = @import("syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_executor = @import("../task/userspace_executor.zig");

const RESPONSE_OFFSET = 1024;
const LABEL_OFFSET = 512;
const CAPABILITY_OFFSET = 2048;
const Failure = enum { invalid_pointer, short, readonly, unmapped_tail, end_overflow };
const failures = std.enums.values(Failure);

const Fixture = struct {
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    task_id: u64 = 0,
    authority_id: u64 = 0,
    user: [4096]u8 align(16) = @splat(0xA5),

    fn create() !*Fixture {
        const self = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(self);
        self.* = .{};
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        const task = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 2 },
            .component_class = .session_manager,
            .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 4096 },
            .local_only = true,
        });
        self.task_id = task.id;
        const authority = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{ .service = .{ .endpoint_create = true, .time_query = true } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.authority_id = authority.id;
        try self.runtime.grantCapability(task.id, authority.id);
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.kernel.deinit();
        std.testing.allocator.destroy(self);
    }

    fn request(self: *Fixture, value: anytype) usize {
        const bytes = std.mem.asBytes(&value);
        std.debug.assert(bytes.len <= LABEL_OFFSET);
        @memcpy(self.user[0..bytes.len], bytes);
        return @intFromPtr(&self.user);
    }

    fn responseAddress(self: *Fixture) usize {
        return @intFromPtr(&self.user) + RESPONSE_OFFSET;
    }

    fn response(self: *Fixture, comptime T: type) T {
        return @as(*const T, @ptrFromInt(self.responseAddress())).*;
    }

    fn mapResponse(self: *Fixture, comptime T: type, writable: bool) void {
        const task = self.runtime.find(self.task_id).?;
        const space = self.runtime.findAddressSpace(task.address_space_id).?;
        space.region_count = 2;
        space.regions[0] = .{
            .kind = .load_segment,
            .virtual_address = @intFromPtr(&self.user),
            .size_bytes = RESPONSE_OFFSET,
            .file_offset = 0,
            .file_size = 0,
            .access = .{ .read = true, .write = true },
        };
        space.regions[1] = .{
            .kind = .load_segment,
            .virtual_address = self.responseAddress(),
            .size_bytes = @sizeOf(T),
            .file_offset = 0,
            .file_size = 0,
            .access = .{ .read = true, .write = writable },
        };
    }

    fn mapUser(self: *Fixture) void {
        const task = self.runtime.find(self.task_id).?;
        const space = self.runtime.findAddressSpace(task.address_space_id).?;
        space.region_count = 1;
        space.regions[0] = .{
            .kind = .load_segment,
            .virtual_address = @intFromPtr(&self.user),
            .size_bytes = self.user.len,
            .file_offset = 0,
            .file_size = 0,
            .access = .{ .read = true, .write = true },
        };
    }

    fn queueAttachedMessage(self: *Fixture) !struct { endpoint_id: u64, endpoint_capability_id: u64, attached_capability_id: u64 } {
        self.mapUser();
        const create_addr = self.request(self.endpointRequest());
        try std.testing.expectEqual(abi.SyscallStatus.success, self.call(.endpoint_create, 10, create_addr, self.responseAddress(), @sizeOf(abi.EndpointCreateResponse)).status);
        const created = self.response(abi.EndpointCreateResponse);
        const peer = try self.endpoints.create(ids.task(self.task_id), "staged-peer", .{ .local_only = true });
        try self.endpoints.connect(peer.id, ids.endpoint(created.endpoint.endpoint_id));
        const task = self.runtime.find(self.task_id).?;
        const sender = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = peer.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        const attached = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 43 },
            .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try self.runtime.grantCapability(task.id, sender.id);
        try self.runtime.grantCapability(task.id, attached.id);
        const expected = stagedPayload();
        @memcpy(self.user[LABEL_OFFSET..][0..expected.len], &expected);
        const send_addr = self.request(component_port.EndpointSendRequest{
            .header = component_port.makeHeader(.endpoint_send, task.id),
            .endpoint_capability_id = sender.id,
            .correlation_id = 91,
            .payload = self.user[LABEL_OFFSET..][0..expected.len],
            .attached_capability_id = attached.id,
        });
        const sent = self.call(.endpoint_send, 11, send_addr, std.math.maxInt(usize), std.math.maxInt(usize));
        try std.testing.expectEqual(abi.SyscallStatus.success, sent.status);
        try std.testing.expectEqual(@as(u32, 0), sent.bytes_written);
        try std.testing.expectEqual(@as(u16, 1), (try self.endpoints.descriptor(ids.endpoint(created.endpoint.endpoint_id))).queued_messages);
        // Reusing the caller's source storage cannot change the queued snapshot.
        @memset(self.user[LABEL_OFFSET..][0..expected.len], 0xEE);
        @memset(self.user[RESPONSE_OFFSET..], 0xA5);
        return .{ .endpoint_id = created.endpoint.endpoint_id, .endpoint_capability_id = created.capability_id, .attached_capability_id = attached.id };
    }

    fn call(self: *Fixture, comptime operation: abi.NativeOperation, now: u64, request_addr: usize, response_addr: usize, response_len: usize) syscall_surface.DispatchResult {
        return syscall_surface.dispatch(&self.port, self.task_id, now, abi.opcode(operation), request_addr, response_addr, response_len);
    }

    fn badResponse(self: *Fixture, comptime T: type, failure: Failure) struct { address: usize, length: usize } {
        self.mapResponse(T, failure != .readonly);
        return .{
            .address = switch (failure) {
                .invalid_pointer => 0x1000,
                .end_overflow => std.math.maxInt(usize) - @sizeOf(T) + 1,
                else => self.responseAddress(),
            },
            .length = switch (failure) {
                .short => @sizeOf(T) - 1,
                .unmapped_tail => @sizeOf(T) + 1,
                else => @sizeOf(T),
            },
        };
    }

    fn endpointRequest(self: *Fixture) component_port.EndpointCreateRequest {
        const label = "failure-response";
        @memcpy(self.user[LABEL_OFFSET..][0..label.len], label);
        return .{
            .header = component_port.makeHeader(.endpoint_create, self.task_id),
            .authority_capability_id = self.authority_id,
            .owner_task_id = self.task_id,
            .label = self.user[LABEL_OFFSET..][0..label.len],
            .flags = .{ .local_only = true },
        };
    }

    fn inputAuthority(self: *Fixture, expires: u64) !u64 {
        const task = self.runtime.find(self.task_id).?;
        const grant = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .task, .id = task.id },
            .rights = .{ .task = .{ .input_recv = true } },
            .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = expires },
        });
        try self.runtime.grantCapability(task.id, grant.id);
        return grant.id;
    }
};

fn stagedPayload() [endpoint.MAX_MESSAGE_BYTES]u8 {
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index + 1);
    return payload;
}

const InputQueue = struct {
    pending: ?abi.InputEventDescriptor,
    polls: usize = 0,

    fn poll(context: *anyopaque, _: u64) ?abi.InputEventDescriptor {
        const self: *InputQueue = @ptrCast(@alignCast(context));
        self.polls += 1;
        const event = self.pending;
        self.pending = null;
        return event;
    }

    fn init(task_id: u64) InputQueue {
        return .{ .pending = .{
            .sequence = 9,
            .tick = 10,
            .task_id = task_id,
            .window_id = 7,
            .surface_id = 12,
            .port_id = 1,
            .slot_id = 2,
            .length = 2,
            .bytes = abi.inputPacket(abi.InputByte.text, 'x'),
        } };
    }
};

fn expectFailure(failure: Failure, result: syscall_surface.DispatchResult) !void {
    try std.testing.expectEqual(if (failure == .short) abi.SyscallStatus.buffer_too_small else abi.SyscallStatus.invalid_response_buffer, result.status);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}

test "syscall failure endpoint output validation preserves grants and the last quota slot" {
    for (failures) |failure| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const request_addr = fixture.request(fixture.endpointRequest());
        const output = fixture.badResponse(abi.EndpointCreateResponse, failure);
        const grants_before = fixture.capabilities.activeCount();
        const task_grants_before = fixture.runtime.find(fixture.task_id).?.capability_count;
        const rejected = fixture.call(.endpoint_create, 10, request_addr, output.address, output.length);
        try expectFailure(failure, rejected);
        try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
        try std.testing.expectEqual(@as(u16, 0), fixture.endpoints.activeForTask(ids.task(fixture.task_id)));
        try std.testing.expectEqual(grants_before, fixture.capabilities.activeCount());
        try std.testing.expectEqual(task_grants_before, fixture.runtime.find(fixture.task_id).?.capability_count);
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET..][0..@sizeOf(abi.EndpointCreateResponse)], 0xA5));

        fixture.mapResponse(abi.EndpointCreateResponse, true);
        const retried = fixture.call(.endpoint_create, 11, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, retried.status);
        try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointCreateResponse)), retried.bytes_written);
        const created = fixture.response(abi.EndpointCreateResponse);
        try std.testing.expect(created.endpoint.endpoint_id != 0 and created.capability_id != 0);
        try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
        try std.testing.expectEqual(grants_before + 1, fixture.capabilities.activeCount());
        try std.testing.expectEqual(task_grants_before + 1, fixture.runtime.find(fixture.task_id).?.capability_count);
        const exhausted = fixture.call(.endpoint_create, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse));
        try std.testing.expectEqual(abi.SyscallStatus.conflict, exhausted.status);
        try std.testing.expectEqual(abi.DenialReason.budget_exhausted, exhausted.denial_reason);
        try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
        try std.testing.expectEqual(grants_before + 1, fixture.capabilities.activeCount());
    }
}

test "syscall failure input output validation preserves the focused event for retry" {
    for (failures) |failure| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        var queue = InputQueue.init(fixture.task_id);
        const expected = queue.pending.?;
        fixture.kernel.bindFocusedInputReceiver(.{ .context = &queue, .poll = InputQueue.poll });
        const authority = try fixture.inputAuthority(100);
        const request_addr = fixture.request(component_port.InputRecvRequest{
            .header = component_port.makeHeader(.input_recv, fixture.task_id),
            .input_capability_id = authority,
            .receiver_task_id = fixture.task_id,
        });
        const output = fixture.badResponse(abi.InputRecvResponse, failure);
        try expectFailure(failure, fixture.call(.input_recv, 10, request_addr, output.address, output.length));
        try std.testing.expectEqual(@as(usize, 0), queue.polls);
        try std.testing.expectEqualDeep(expected, queue.pending.?);
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET..][0..@sizeOf(abi.InputRecvResponse)], 0xA5));

        fixture.mapResponse(abi.InputRecvResponse, true);
        const retried = fixture.call(.input_recv, 11, request_addr, fixture.responseAddress(), @sizeOf(abi.InputRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, retried.status);
        try std.testing.expectEqual(@as(usize, 1), queue.polls);
        try std.testing.expect(queue.pending == null);
        const received = fixture.response(abi.InputRecvResponse);
        try std.testing.expectEqual(@as(u8, 1), received.present);
        try std.testing.expectEqualDeep(expected, received.event);
    }
}

test "syscall failure invalid request outranks invalid response and cannot consume an endpoint" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    fixture.mapResponse(abi.EndpointCreateResponse, false);
    const invalid = fixture.call(.endpoint_create, 10, 0x1000, 0x1000, 0);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, invalid.status);
    const misaligned = fixture.call(.endpoint_create, 10, @intFromPtr(&fixture.user) + 1, fixture.responseAddress(), 0);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, misaligned.status);
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
    try std.testing.expectEqual(@as(usize, 1), fixture.capabilities.activeCount());
}

test "syscall failure zero response close ignores an unusable advertised result range" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const create_addr = fixture.request(fixture.endpointRequest());
    fixture.mapResponse(abi.EndpointCreateResponse, true);
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_create, 10, create_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse)).status);
    const created = fixture.response(abi.EndpointCreateResponse);
    const close_addr = fixture.request(component_port.EndpointCloseRequest{
        .header = component_port.makeHeader(.endpoint_close, fixture.task_id),
        .endpoint_capability_id = created.capability_id,
    });
    const result = fixture.call(.endpoint_close, 11, close_addr, std.math.maxInt(usize), std.math.maxInt(usize));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
    try std.testing.expect(!fixture.runtime.hasCapability(fixture.task_id, created.capability_id));
}

test "syscall failure self termination returns only register status after retiring mapped memory" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const task = fixture.runtime.find(fixture.task_id).?;
    const address_space_id = task.address_space_id;
    const termination = try fixture.capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = task.id },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    try fixture.runtime.grantCapability(task.id, termination.id);
    const request_addr = fixture.request(component_port.TaskTerminateRequest{
        .header = component_port.makeHeader(.task_terminate, task.id),
        .task_capability_id = termination.id,
    });
    fixture.mapResponse(abi.BoolResponse, true);
    try std.testing.expect(fixture.runtime.findAddressSpaceConst(address_space_id).?.region_count != 0);
    // The advertised range overflows. The void wire operation must never
    // validate it or touch the caller's retired address-space record afterward.
    const result = fixture.call(.task_terminate, 11, request_addr, std.math.maxInt(usize), std.math.maxInt(usize));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
    try std.testing.expect(fixture.runtime.findAddressSpaceConst(address_space_id) == null);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, fixture.runtime.find(fixture.task_id).?.state);
    try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET..], 0xA5));
}

test "syscall failure expired or foreign input authority cannot consume the focused event" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    var queue = InputQueue.init(fixture.task_id);
    const expected = queue.pending.?;
    fixture.kernel.bindFocusedInputReceiver(.{ .context = &queue, .poll = InputQueue.poll });
    const expired_authority = try fixture.inputAuthority(10);
    const valid_authority = try fixture.inputAuthority(100);
    fixture.mapResponse(abi.InputRecvResponse, true);
    const expired_addr = fixture.request(component_port.InputRecvRequest{
        .header = component_port.makeHeader(.input_recv, fixture.task_id),
        .input_capability_id = expired_authority,
        .receiver_task_id = fixture.task_id,
    });
    const expired = fixture.call(.input_recv, 11, expired_addr, fixture.responseAddress(), @sizeOf(abi.InputRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.denied, expired.status);
    try std.testing.expectEqual(abi.DenialReason.capability_revoked, expired.denial_reason);
    const foreign_addr = fixture.request(component_port.InputRecvRequest{
        .header = component_port.makeHeader(.input_recv, fixture.task_id),
        .input_capability_id = valid_authority,
        .receiver_task_id = fixture.task_id + 1,
    });
    const foreign = fixture.call(.input_recv, 12, foreign_addr, fixture.responseAddress(), @sizeOf(abi.InputRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.denied, foreign.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, foreign.denial_reason);
    try std.testing.expectEqual(@as(usize, 0), queue.polls);
    try std.testing.expectEqualDeep(expected, queue.pending.?);
    const valid_addr = fixture.request(component_port.InputRecvRequest{
        .header = component_port.makeHeader(.input_recv, fixture.task_id),
        .input_capability_id = valid_authority,
        .receiver_task_id = fixture.task_id,
    });
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.input_recv, 13, valid_addr, fixture.responseAddress(), @sizeOf(abi.InputRecvResponse)).status);
    try std.testing.expectEqualDeep(expected, fixture.response(abi.InputRecvResponse).event);
}

test "syscall failure overlapping receive outputs preserve the queued capability for retry" {
    const Overlap = enum { primary_payload, primary_capability, payload_capability, advertised_primary_tail };
    for (std.enums.values(Overlap)) |overlap| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const queued = try fixture.queueAttachedMessage();
        const payload_address = switch (overlap) {
            .primary_payload => fixture.responseAddress() + 8,
            .advertised_primary_tail => fixture.responseAddress() + 64,
            else => @intFromPtr(&fixture.user) + LABEL_OFFSET,
        };
        const capability_address = switch (overlap) {
            .primary_capability => fixture.responseAddress(),
            .payload_capability => payload_address,
            else => @intFromPtr(&fixture.user) + CAPABILITY_OFFSET,
        };
        const request_addr = fixture.request(component_port.EndpointRecvRequest{
            .header = component_port.makeHeader(.endpoint_recv, fixture.task_id),
            .endpoint_capability_id = queued.endpoint_capability_id,
            .receiver_task_id = fixture.task_id,
            .payload_out = @as([*]u8, @ptrFromInt(payload_address))[0..endpoint.MAX_MESSAGE_BYTES],
            .attached_capability_out = @ptrFromInt(capability_address),
        });
        const grants_before = fixture.capabilities.activeCount();
        const task_grants_before = fixture.runtime.find(fixture.task_id).?.capability_count;
        const rejected = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), if (overlap == .advertised_primary_tail) 128 else @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, rejected.status);
        try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
        try std.testing.expectEqual(@as(u16, 1), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
        try std.testing.expectEqual(grants_before, fixture.capabilities.activeCount());
        try std.testing.expectEqual(task_grants_before, fixture.runtime.find(fixture.task_id).?.capability_count);
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET..], 0xA5));

        const retry_addr = fixture.request(component_port.EndpointRecvRequest{
            .header = component_port.makeHeader(.endpoint_recv, fixture.task_id),
            .endpoint_capability_id = queued.endpoint_capability_id,
            .receiver_task_id = fixture.task_id,
            .payload_out = fixture.user[LABEL_OFFSET..][0..endpoint.MAX_MESSAGE_BYTES],
            .attached_capability_out = @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET),
        });
        const retried = fixture.call(.endpoint_recv, 13, retry_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, retried.status);
        const received = fixture.response(abi.EndpointRecvResponse);
        try std.testing.expectEqual(@as(u8, 1), received.present);
        try std.testing.expectEqual(@as(u8, 1), received.has_attached_capability);
        try std.testing.expectEqual(@as(u16, endpoint.MAX_MESSAGE_BYTES), received.message.payload_len);
        try std.testing.expectEqual(@as(u64, 91), received.message.correlation_id);
        try std.testing.expectEqual(queued.attached_capability_id, received.message.attached_capability_id);
        const expected = stagedPayload();
        try std.testing.expectEqualSlices(u8, &expected, fixture.user[LABEL_OFFSET..][0..expected.len]);
        const attached = @as(*const abi.CapabilityDescriptor, @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET)).*;
        try std.testing.expect(attached.capability_id != 0 and attached.capability_id != queued.attached_capability_id);
        try std.testing.expectEqual(@as(u64, 43), attached.target_id);
        try std.testing.expectEqual(fixture.task_id, attached.scope_task_id);
        try std.testing.expect(fixture.runtime.hasCapability(fixture.task_id, attached.capability_id));
        try std.testing.expectEqual(grants_before + 1, fixture.capabilities.activeCount());
        try std.testing.expectEqual(task_grants_before + 1, fixture.runtime.find(fixture.task_id).?.capability_count);
        try std.testing.expectEqual(@as(u16, 0), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
    }
}

test "syscall failure receive snapshots the request before aliased payload writes" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const queued = try fixture.queueAttachedMessage();
    const request_addr = fixture.request(component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, fixture.task_id),
        .endpoint_capability_id = queued.endpoint_capability_id,
        .receiver_task_id = fixture.task_id,
        .payload_out = fixture.user[0..endpoint.MAX_MESSAGE_BYTES],
        .attached_capability_out = @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET),
    });
    const result = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    const received = fixture.response(abi.EndpointRecvResponse);
    const expected = stagedPayload();
    try std.testing.expectEqualSlices(u8, &expected, fixture.user[0..expected.len]);
    try std.testing.expectEqual(@as(u8, 1), received.has_attached_capability);
    try std.testing.expectEqual(queued.endpoint_id, received.message.endpoint_id);
    try std.testing.expectEqual(@as(u64, 91), received.message.correlation_id);
    const attached = @as(*const abi.CapabilityDescriptor, @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET)).*;
    try std.testing.expect(fixture.runtime.hasCapability(fixture.task_id, attached.capability_id));
    try std.testing.expectEqual(@as(u64, 43), attached.target_id);
}

// The executor's local test registers its private instance, so this helper
// exercises the real wait handler without adding a production registration API.
pub fn expectWaitResponseFailures(executor: *userspace_executor.Executor) !void {
    for (failures) |failure| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const request_addr = fixture.request(component_port.WaitRequest{
            .header = component_port.makeHeader(.wait, fixture.task_id),
            .authority_capability_id = fixture.authority_id,
        });
        executor.last_yield_disposition = .runnable;
        const output = fixture.badResponse(abi.BoolResponse, failure);
        try expectFailure(failure, fixture.call(.wait, 10, request_addr, output.address, output.length));
        try std.testing.expectEqual(@as(@TypeOf(executor.last_yield_disposition), .runnable), executor.last_yield_disposition);
        fixture.mapResponse(abi.BoolResponse, true);
        const retried = fixture.call(.wait, 11, request_addr, fixture.responseAddress(), @sizeOf(abi.BoolResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, retried.status);
        try std.testing.expectEqual(@as(@TypeOf(executor.last_yield_disposition), .wait_for_event), executor.last_yield_disposition);
        try std.testing.expectEqual(abi.boolResponse(true), fixture.response(abi.BoolResponse));
    }
}
