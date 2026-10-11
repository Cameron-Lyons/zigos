const std = @import("std");
const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const capability = @import("capability.zig");
const capability_wire = @import("capability_wire.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const shared_memory = @import("shared_memory.zig");
const syscall_surface = @import("syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");

const RESPONSE_OFFSET = 1024;
const LABEL_OFFSET = 512;
const CAPABILITY_OFFSET = 2048;
const Failure = enum { invalid_pointer, short, readonly, unmapped_tail, end_overflow };
const failures = std.enums.values(Failure);
const Transfer = enum { copy, move };
const QueuedMessage = struct {
    endpoint_id: u64,
    endpoint_capability_id: u64,
    attached_capability_id: u64,
    transfer: Transfer,
    unscoped: bool = false,
};
const ConstructionFailure = enum { none, after_task, after_authority, after_queued_move };

const CleanupObservation = struct {
    tasks: usize,
    grants: usize,
    endpoints: usize,
    shared_objects: usize,
    owned_rings: usize,
    pending: bool,

    fn capture(fixture: *Fixture) CleanupObservation {
        var rings: usize = 0;
        for (&fixture.endpoints.arena.slots) |*slot| {
            if (slot.endpoint.data_ring.len != 0) rings += 1;
        }
        return .{
            .tasks = fixture.runtime.taskCount(),
            .grants = fixture.capabilities.activeCount(),
            .endpoints = fixture.endpoints.activeCount(),
            .shared_objects = fixture.shared.activeCount(),
            .owned_rings = rings,
            .pending = fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)),
        };
    }

    fn expectRetired(self: CleanupObservation) !void {
        try std.testing.expectEqualDeep(CleanupObservation{
            .tasks = 0,
            .grants = 0,
            .endpoints = 0,
            .shared_objects = 0,
            .owned_rings = 0,
            .pending = false,
        }, self);
    }
};

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
        return createWithFailure(.none, null);
    }

    fn createWithFailure(failure: ConstructionFailure, cleanup: ?*CleanupObservation) !*Fixture {
        const self = try std.testing.allocator.create(Fixture);
        self.* = .{};
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        errdefer self.destroyObserved(cleanup);
        const task = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 2 },
            .component_class = .session_manager,
            .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 4096 },
            .local_only = true,
        });
        self.task_id = task.id;
        if (failure == .after_task) return error.InjectedConstructionFailure;
        const authority = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{ .service = .{ .endpoint_create = true, .time_query = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.authority_id = authority.id;
        try self.runtime.grantCapability(task.id, authority.id);
        if (failure == .after_authority) return error.InjectedConstructionFailure;
        if (failure == .after_queued_move) {
            _ = try self.queueAttachedMessage(.move);
            return error.InjectedConstructionFailure;
        }
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.destroyObserved(null);
    }

    fn destroyObserved(self: *Fixture, cleanup: ?*CleanupObservation) void {
        // Runtime retirement owns queued moves and task resources. Unbinding
        // the stable Kernel first would bypass that cleanup.
        self.kernel.focused_input_receiver = null;
        self.runtime.reset();
        if (cleanup) |out| out.* = CleanupObservation.capture(self);
        self.endpoints.deinit();
        self.shared.deinit();
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

    fn restrictUserBytes(self: *Fixture, offset: usize, length: usize, readonly: bool) void {
        std.debug.assert(offset != 0 and length != 0 and offset + length < self.user.len);
        self.mapUser();
        const task = self.runtime.find(self.task_id).?;
        const space = self.runtime.findAddressSpace(task.address_space_id).?;
        const whole = space.regions[0];
        space.regions[0].size_bytes = @intCast(offset);
        const tail_index: usize = if (readonly) 2 else 1;
        if (readonly) {
            space.regions[1] = whole;
            space.regions[1].virtual_address += offset;
            space.regions[1].size_bytes = @intCast(length);
            space.regions[1].access.write = false;
        }
        space.regions[tail_index] = whole;
        space.regions[tail_index].virtual_address += offset + length;
        space.regions[tail_index].size_bytes -= @intCast(offset + length);
        space.region_count = @intCast(tail_index + 1);
    }

    fn queueAttachedMessage(self: *Fixture, transfer: Transfer) !QueuedMessage {
        return self.queueAttachedMessageWithScope(transfer, false, null);
    }

    fn queueAttachedMessageWithScope(self: *Fixture, transfer: Transfer, unscoped: bool, shared_holder_task_id: ?u64) !QueuedMessage {
        const queued = try self.prepareAttachedMessageWithScope(transfer, unscoped, shared_holder_task_id);
        const sent = self.call(.endpoint_send, 11, @intFromPtr(&self.user), std.math.maxInt(usize), std.math.maxInt(usize));
        try std.testing.expectEqual(abi.SyscallStatus.success, sent.status);
        try std.testing.expectEqual(@as(u32, 0), sent.bytes_written);
        try std.testing.expectEqual(@as(u16, 1), (try self.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
        if (!unscoped) try std.testing.expectEqual(transfer == .copy, self.runtime.hasCapability(self.task_id, queued.attached_capability_id));
        try std.testing.expect(self.capabilities.query(queued.attached_capability_id) != null);
        // Reusing the caller's source storage cannot change the queued snapshot.
        @memset(self.user[LABEL_OFFSET..][0..endpoint.MAX_MESSAGE_BYTES], 0xEE);
        @memset(self.user[RESPONSE_OFFSET..], 0xA5);
        return queued;
    }

    fn prepareAttachedMessageWithScope(self: *Fixture, transfer: Transfer, unscoped: bool, shared_holder_task_id: ?u64) !QueuedMessage {
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
            .scope = .{ .task_id = if (unscoped) null else task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        const boot_attachment = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 43 },
            .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
            .scope = .{ .task_id = if (unscoped) null else task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        try self.runtime.grantCapability(task.id, sender.id);
        const attached = if (unscoped) blk: {
            // Produce the task's unscoped attachment through an admitted
            // caller-zero COPY, rather than inventing its authority in bytes.
            const received = try self.kernel.capabilityPass(.{
                .caller_task_id = 0,
                .presented_capability_id = boot_attachment.id,
                .target = .none,
            }, task.id, 10, false);
            break :blk self.capabilities.query(received.capability_id).?;
        } else blk: {
            try self.runtime.grantCapability(task.id, boot_attachment.id);
            break :blk boot_attachment;
        };
        if (shared_holder_task_id) |shared_holder| try self.runtime.grantCapability(shared_holder, attached.id);
        const expected = stagedPayload();
        @memcpy(self.user[LABEL_OFFSET..][0..expected.len], &expected);
        _ = self.request(abi.EndpointSendWireRequest{
            .header = component_port.makeHeader(.endpoint_send, task.id),
            .endpoint_capability_id = sender.id,
            .correlation_id = 91,
            .payload_address = @intFromPtr(&self.user) + LABEL_OFFSET,
            .payload_bytes = expected.len,
            .attached_capability_id = attached.id,
            .flags = if (transfer == .move) abi.ENDPOINT_SEND_MOVE_ATTACHMENT else 0,
        });
        return .{ .endpoint_id = created.endpoint.endpoint_id, .endpoint_capability_id = created.capability_id, .attached_capability_id = attached.id, .transfer = transfer, .unscoped = unscoped };
    }

    fn receiveRequest(self: *Fixture, queued: QueuedMessage) abi.EndpointRecvWireRequest {
        return .{
            .header = component_port.makeHeader(.endpoint_recv, self.task_id),
            .endpoint_capability_id = queued.endpoint_capability_id,
            .receiver_task_id = self.task_id,
            .payload_address = @intFromPtr(&self.user) + LABEL_OFFSET,
            .payload_capacity = endpoint.MAX_MESSAGE_BYTES,
            .attached_capability_address = @intFromPtr(&self.user) + CAPABILITY_OFFSET,
        };
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

    fn endpointRequest(self: *Fixture) abi.EndpointCreateWireRequest {
        const label = "failure-response";
        @memcpy(self.user[LABEL_OFFSET..][0..label.len], label);
        return .{
            .header = component_port.makeHeader(.endpoint_create, self.task_id),
            .authority_capability_id = self.authority_id,
            .owner_task_id = self.task_id,
            .label_address = @intFromPtr(&self.user) + LABEL_OFFSET,
            .label_bytes = label.len,
            .flags = 1,
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

test "syscall failure shared mapping outputs precede budget and preserve mapping ownership" {
    inline for (.{ abi.NativeOperation.shared_memory_map, abi.NativeOperation.shared_memory_unmap }) |operation| {
        const Response = if (operation == .shared_memory_map) abi.SharedMemoryDescriptor else abi.BoolResponse;
        const fixture = try Fixture.create();
        defer fixture.destroy();
        fixture.mapUser();
        const task = fixture.runtime.find(fixture.task_id).?;
        const object = try fixture.shared.create(ids.task(task.id), shared_memory.PAGE_SIZE);
        const grant = try fixture.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .shared_memory, .id = object.id.raw() },
            .rights = .{ .shared_memory = .{ .shared_memory_map = true, .shared_memory_unmap = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.runtime.grantCapability(task.id, grant.id);
        if (operation == .shared_memory_unmap) try fixture.shared.map(object.id, ids.task(task.id));
        // A fresh map with no budget must still reject unusable outputs first;
        // an unmap must retain the previously published mapping on refusal.
        task.budget.shared_memory_bytes = 0;
        const address = if (operation == .shared_memory_map)
            fixture.request(abi.SharedMemoryMapWireRequest{
                .header = component_port.makeHeader(operation, task.id),
                .shared_memory_capability_id = grant.id,
                .task_id = task.id,
            })
        else
            fixture.request(abi.SharedMemoryUnmapWireRequest{
                .header = component_port.makeHeader(operation, task.id),
                .shared_memory_capability_id = grant.id,
                .task_id = task.id,
            });
        for (failures) |failure| {
            const output = fixture.badResponse(Response, failure);
            const user_before = fixture.user;
            const shared_before = fixture.shared;
            const capabilities_before = fixture.capabilities;
            const task_before = task.*;
            const task_generation = task.capabilityGeneration();
            const result = fixture.call(operation, 10, address, output.address, output.length);
            try std.testing.expectEqual(if (failure == .short) abi.SyscallStatus.buffer_too_small else abi.SyscallStatus.invalid_response_buffer, result.status);
            try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
            try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
            try std.testing.expectEqualDeep(shared_before, fixture.shared);
            try std.testing.expectEqualDeep(capabilities_before, fixture.capabilities);
            try std.testing.expectEqualDeep(task_before, task.*);
            try std.testing.expectEqual(task_generation, task.capabilityGeneration());
            try std.testing.expect(task.hasCapability(grant.id));
        }
        fixture.mapUser();
        if (operation == .shared_memory_map) {
            const shared_before = fixture.shared;
            const user_before = fixture.user;
            const denied = fixture.call(operation, 11, address, fixture.responseAddress(), @sizeOf(Response));
            try std.testing.expectEqual(abi.SyscallStatus.conflict, denied.status);
            try std.testing.expectEqual(abi.DenialReason.budget_exhausted, denied.denial_reason);
            try std.testing.expectEqualDeep(shared_before, fixture.shared);
            try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
            task.budget.shared_memory_bytes = shared_memory.PAGE_SIZE;
        }
        const result = fixture.call(operation, 12, address, fixture.responseAddress(), @sizeOf(Response));
        try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
        try std.testing.expectEqual(@as(u32, @sizeOf(Response)), result.bytes_written);
        if (operation == .shared_memory_map) {
            try std.testing.expectEqualDeep(try fixture.shared.descriptor(object.id), fixture.response(Response));
            try std.testing.expect(fixture.shared.hasMapping(object.id, ids.task(task.id)));
        } else {
            try std.testing.expectEqualDeep(abi.boolResponse(true), fixture.response(Response));
            try std.testing.expect(!fixture.shared.hasMapping(object.id, ids.task(task.id)));
        }
    }
}

fn stagedPayload() [endpoint.MAX_MESSAGE_BYTES]u8 {
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index + 1);
    return payload;
}

test "syscall failure terminal target epochs revoke exact attachments and reject mint atomically until drained" {
    const Boundary = struct {
        const target = capability.CapabilityTarget{ .kind = .service, .id = 777 };

        fn targetIndex(fixture: *Fixture) !usize {
            for (fixture.capabilities.target_generations.slots, 0..) |entry, index| {
                if (entry.in_use and entry.target.eql(target)) return index;
            }
            return error.MissingTargetGeneration;
        }

        fn request(fixture: *Fixture, policy_id: u64, unscoped: bool) abi.CapabilityMintWireRequest {
            var wire: abi.CapabilityMintWireRequest = undefined;
            capability_wire.mintToWireInto(component_port.makeHeader(.capability_mint, fixture.task_id), policy_id, .{
                .holder = fixture.runtime.find(fixture.task_id).?.owner,
                .issuer = fixture.kernel.policy_authority,
                .target = target,
                .rights = .{ .service = .{ .time_query = true, .capability_revoke = true } },
                .scope = .{ .task_id = if (unscoped) null else fixture.task_id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            }, &wire);
            return wire;
        }

        fn mint(fixture: *Fixture, policy_id: u64, unscoped: bool, peer: *task_runtime.TaskRecord, epoch: u32) !u64 {
            @memset(&fixture.user, 0xa5);
            const address = fixture.request(request(fixture, policy_id, unscoped));
            const user_before = fixture.user;
            const port_before = fixture.port;
            const count = fixture.capabilities.activeCount();
            const generation = fixture.capabilities.mutationGeneration();
            const task_count = fixture.runtime.find(fixture.task_id).?.capability_count;
            const result = fixture.call(.capability_mint, 20, address, fixture.responseAddress(), @sizeOf(abi.CapabilityDescriptor));
            try std.testing.expectEqualDeep(syscall_surface.DispatchResult{ .status = .success, .bytes_written = @sizeOf(abi.CapabilityDescriptor) }, result);
            const descriptor = fixture.response(abi.CapabilityDescriptor);
            try std.testing.expectEqual(epoch, descriptor.revocation_generation);
            try std.testing.expectEqual(@as(u32, 0), descriptor._reserved_generation);
            try std.testing.expectEqual(@as(u32, 0), descriptor._reserved_tail);
            try std.testing.expectEqual(count + 1, fixture.capabilities.activeCount());
            try std.testing.expectEqual(generation + 1, fixture.capabilities.mutationGeneration());
            try std.testing.expectEqualSlices(u8, user_before[0..RESPONSE_OFFSET], fixture.user[0..RESPONSE_OFFSET]);
            const response_end = RESPONSE_OFFSET + @sizeOf(abi.CapabilityDescriptor);
            try std.testing.expectEqualSlices(u8, user_before[response_end..], fixture.user[response_end..]);
            try std.testing.expect(std.meta.eql(port_before, fixture.port));
            if (unscoped) {
                // Public mint does not attach a null-scoped grant. Trusted
                // setup gives the same exact grant to two same-owner holders,
                // exercising the public revoke's everywhere-detach path.
                try std.testing.expectEqual(task_count, fixture.runtime.find(fixture.task_id).?.capability_count);
                try fixture.runtime.grantCapability(fixture.task_id, descriptor.capability_id);
                try fixture.runtime.grantCapability(peer.id, descriptor.capability_id);
            }
            try std.testing.expectEqual(task_count + 1, fixture.runtime.find(fixture.task_id).?.capability_count);
            _ = try fixture.capabilities.requireUsable(descriptor.capability_id, 20);
            return descriptor.capability_id;
        }

        fn revoke(fixture: *Fixture, peer: *task_runtime.TaskRecord, id: u64, unscoped: bool) !void {
            const caller = fixture.runtime.find(fixture.task_id).?;
            const slot = task_runtime.cspaceSlotForCapability(caller, id).?;
            const peer_slot = task_runtime.cspaceSlotForCapability(peer, id);
            const caller_count = caller.capability_count;
            const caller_generation = caller.capabilityGeneration();
            const peer_before = TaskAuthoritySnapshot.capture(peer);
            const count = fixture.capabilities.activeCount();
            const generation = fixture.capabilities.mutationGeneration();
            @memset(&fixture.user, 0xa5);
            const address = fixture.request(abi.CapabilityRevokeWireRequest{
                .header = component_port.makeHeader(.capability_revoke, fixture.task_id),
                .authority_capability_id = id,
                .capability_id = id,
            });
            const user_before = fixture.user;
            const port_before = fixture.port;
            const result = fixture.call(.capability_revoke, 20, address, fixture.responseAddress(), fixture.user.len - RESPONSE_OFFSET);
            try std.testing.expectEqualDeep(syscall_surface.DispatchResult{ .status = .success }, result);
            try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
            try std.testing.expect(std.meta.eql(port_before, fixture.port));
            try std.testing.expect(fixture.capabilities.query(id) == null);
            try std.testing.expectEqual(count - 1, fixture.capabilities.activeCount());
            try std.testing.expectEqual(generation + 1, fixture.capabilities.mutationGeneration());
            try std.testing.expectEqual(caller_count - 1, caller.capability_count);
            try std.testing.expectEqual(caller_generation + 1, caller.capabilityGeneration());
            try std.testing.expect(task_runtime.capabilityIdAtCspaceSlot(caller, slot) == null);
            try std.testing.expect(!caller.hasCapability(id));
            if (unscoped) {
                try std.testing.expectEqual(peer_before.record.capability_count - 1, peer.capability_count);
                try std.testing.expectEqual(peer_before.generation + 1, peer.capabilityGeneration());
                try std.testing.expect(task_runtime.capabilityIdAtCspaceSlot(peer, peer_slot.?) == null);
                try std.testing.expect(!peer.hasCapability(id));
            } else try peer_before.expectPreserved(peer);
        }
    };

    for ([_]bool{ false, true }) |unscoped| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        fixture.mapUser();
        fixture.port.syscall_caller_task_id = 0xfeed;
        const caller = fixture.runtime.find(fixture.task_id).?;
        const peer = try fixture.runtime.createTask(.{
            .owner = caller.owner,
            .component_class = .session_manager,
            .budget = caller.budget,
            .local_only = true,
        });
        const policy = try fixture.capabilities.mintBootRoot(.{
            .holder = caller.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .policy, .id = 1 },
            .rights = .{ .policy = .{ .capability_mint = true } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.runtime.grantCapability(caller.id, policy.id);
        const sibling = try Boundary.mint(fixture, policy.id, unscoped, peer, 1);
        const sibling_record = fixture.capabilities.query(sibling).?;
        const sibling_slot = task_runtime.cspaceSlotForCapability(caller, sibling).?;
        const target_index = try Boundary.targetIndex(fixture);
        // Seed only the private target counter. The epoch1 record is an actual
        // retained sibling tombstone; no billions-of-operations claim is made.
        fixture.capabilities.target_generations.slots[target_index].generation = std.math.maxInt(u32) - 1;
        while (caller.capability_count < task_runtime.MAX_TASK_CAPABILITIES - 1) {
            const filler = try fixture.capabilities.mintBootRoot(.{
                .holder = caller.owner,
                .issuer = fixture.kernel.policy_authority,
                .target = .{ .kind = .service, .id = 778 },
                .rights = .{ .service = .{ .time_query = true } },
                .scope = .{ .task_id = caller.id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            try fixture.runtime.grantCapability(caller.id, filler.id);
        }
        const penultimate = try Boundary.mint(fixture, policy.id, unscoped, peer, std.math.maxInt(u32) - 1);
        try Boundary.revoke(fixture, peer, penultimate, unscoped);
        try std.testing.expectEqual(std.math.maxInt(u32), fixture.capabilities.target_generations.slots[target_index].generation);
        const terminal = try Boundary.mint(fixture, policy.id, unscoped, peer, std.math.maxInt(u32));
        try Boundary.revoke(fixture, peer, terminal, unscoped);
        try std.testing.expectEqual(@as(u32, 0), fixture.capabilities.target_generations.slots[target_index].generation);
        try std.testing.expectEqualDeep(sibling_record, fixture.capabilities.query(sibling).?);
        try std.testing.expectEqual(sibling, task_runtime.capabilityIdAtCspaceSlot(caller, sibling_slot).?);
        try std.testing.expectError(error.CapabilityRevoked, fixture.capabilities.requireUsable(sibling, 20));
        try std.testing.expectEqualDeep(policy, (try fixture.capabilities.requireUsable(policy.id, 20)).*);

        // Both denied operations have completely valid request/output storage
        // and one free task slot: denial must be epoch admission, not quota.
        inline for (.{ abi.NativeOperation.capability_mint, abi.NativeOperation.time_query }) |operation| {
            @memset(&fixture.user, 0xa5);
            const address = if (operation == .capability_mint)
                fixture.request(Boundary.request(fixture, policy.id, unscoped))
            else
                fixture.request(abi.TimeQueryWireRequest{ .header = component_port.makeHeader(.time_query, caller.id), .authority_capability_id = sibling });
            const user_before = fixture.user;
            const table_before = fixture.capabilities;
            const caller_before = TaskAuthoritySnapshot.capture(caller);
            const caller_cold = caller.cold_state.?.*;
            const peer_before = TaskAuthoritySnapshot.capture(peer);
            const peer_cold = peer.cold_state.?.*;
            const space_before = fixture.runtime.findAddressSpace(caller.address_space_id).?.*;
            const port_before = fixture.port;
            const task_count = fixture.runtime.taskCount();
            const result = fixture.call(operation, 20, address, fixture.responseAddress(), @sizeOf(abi.CapabilityDescriptor));
            try std.testing.expectEqualDeep(syscall_surface.DispatchResult{ .status = .denied, .denial_reason = .capability_revoked }, result);
            try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
            try std.testing.expectEqualDeep(table_before, fixture.capabilities);
            try caller_before.expectPreserved(caller);
            try peer_before.expectPreserved(peer);
            try std.testing.expectEqualDeep(caller_cold, caller.cold_state.?.*);
            try std.testing.expectEqualDeep(peer_cold, peer.cold_state.?.*);
            try std.testing.expectEqualDeep(space_before, fixture.runtime.findAddressSpace(caller.address_space_id).?.*);
            try std.testing.expect(std.meta.eql(port_before, fixture.port));
            try std.testing.expectEqual(task_count, fixture.runtime.taskCount());
            try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
            try std.testing.expectEqual(@as(usize, 0), fixture.shared.activeCount());
        }
        const live_time_address = fixture.request(abi.TimeQueryWireRequest{ .header = component_port.makeHeader(.time_query, caller.id), .authority_capability_id = fixture.authority_id });
        try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.time_query, 20, live_time_address, fixture.responseAddress(), @sizeOf(abi.TimeQueryResponse)).status);
        try std.testing.expectEqual(@as(u64, 20), fixture.response(abi.TimeQueryResponse).now_ticks);

        // Raw trusted cancellation is permitted even for an exhausted sibling.
        // Explicitly clear its Runtime attachments before reopening the target.
        try fixture.capabilities.revokeTargetAuthority(sibling);
        try std.testing.expectEqual(@as(u16, if (unscoped) 2 else 1), fixture.runtime.revokeCapabilityEverywhere(sibling));
        try std.testing.expectError(error.MissingTargetGeneration, Boundary.targetIndex(fixture));
        const reopened = try Boundary.mint(fixture, policy.id, unscoped, peer, 1);
        try std.testing.expect(reopened != sibling and reopened != penultimate and reopened != terminal);
        for ([_]u64{ sibling, penultimate, terminal }) |old_id| {
            try std.testing.expect(fixture.capabilities.query(old_id) == null);
            try std.testing.expect(!caller.hasCapability(old_id));
            try std.testing.expect(!peer.hasCapability(old_id));
        }
        try std.testing.expectEqualDeep(policy, (try fixture.capabilities.requireUsable(policy.id, 20)).*);
        try Boundary.revoke(fixture, peer, reopened, unscoped);
    }
}

const ReceiveSnapshot = struct {
    user: [4096]u8,
    endpoint_descriptor: abi.EndpointDescriptor,
    attached: capability.Capability,
    grants: usize,
    grant_generation: u64,
    task_grants: usize,
    task_grant_generation: u64,
    task_capabilities: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0),

    // Stage the request first: its intentional writes are not syscall output.
    fn capture(fixture: *Fixture, queued: QueuedMessage) !ReceiveSnapshot {
        const task = fixture.runtime.find(fixture.task_id).?;
        var snapshot = ReceiveSnapshot{
            .user = fixture.user,
            .endpoint_descriptor = try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id)),
            .attached = fixture.capabilities.query(queued.attached_capability_id).?,
            .grants = fixture.capabilities.activeCount(),
            .grant_generation = fixture.capabilities.mutationGeneration(),
            .task_grants = task.capability_count,
            .task_grant_generation = task.capabilityGeneration(),
        };
        @memcpy(snapshot.task_capabilities[0..snapshot.task_grants], task.capabilityIds());
        return snapshot;
    }

    fn expectPreserved(self: *const ReceiveSnapshot, fixture: *Fixture, queued: QueuedMessage) !void {
        try std.testing.expectEqualSlices(u8, &self.user, &fixture.user);
        try std.testing.expectEqualDeep(self.endpoint_descriptor, try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id)));
        try std.testing.expect(fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));
        try std.testing.expectEqualDeep(self.attached, fixture.capabilities.query(queued.attached_capability_id).?);
        try std.testing.expectEqual(self.grants, fixture.capabilities.activeCount());
        try std.testing.expectEqual(self.grant_generation, fixture.capabilities.mutationGeneration());
        try self.expectTaskPreserved(fixture);
        try std.testing.expectEqual(queued.transfer == .copy, fixture.runtime.hasCapability(fixture.task_id, queued.attached_capability_id));
    }

    fn expectTaskPreserved(self: *const ReceiveSnapshot, fixture: *Fixture) !void {
        const task = fixture.runtime.find(fixture.task_id).?;
        try std.testing.expectEqual(self.task_grants, task.capabilityIds().len);
        try std.testing.expectEqual(self.task_grant_generation, task.capabilityGeneration());
        try std.testing.expectEqualSlices(u64, self.task_capabilities[0..self.task_grants], task.capabilityIds());
    }

    fn expectRetry(self: *const ReceiveSnapshot, fixture: *Fixture, queued: QueuedMessage) !void {
        fixture.mapUser();
        const request_addr = fixture.request(fixture.receiveRequest(queued));
        const user_before = fixture.user;
        const result = fixture.call(.endpoint_recv, 13, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
        try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), result.bytes_written);
        const received = fixture.response(abi.EndpointRecvResponse);
        try std.testing.expectEqual(@as(u8, 1), received.present);
        try std.testing.expectEqual(@as(u8, 1), received.has_attached_capability);
        try std.testing.expectEqual(queued.endpoint_id, received.message.endpoint_id);
        try std.testing.expectEqual(fixture.task_id, received.message.sender_task_id);
        try std.testing.expectEqual(@as(u16, endpoint.MAX_MESSAGE_BYTES), received.message.payload_len);
        try std.testing.expectEqual(@as(u64, 91), received.message.correlation_id);
        // Transport metadata identifies the original in-flight grant; the
        // separate descriptor publishes the recipient's usable new grant.
        try std.testing.expectEqual(queued.attached_capability_id, received.message.attached_capability_id);
        const expected = stagedPayload();
        try std.testing.expectEqualSlices(u8, &expected, fixture.user[LABEL_OFFSET..][0..expected.len]);
        const attached = @as(*const abi.CapabilityDescriptor, @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET)).*;
        try std.testing.expect(attached.capability_id != 0 and attached.capability_id != queued.attached_capability_id);
        try std.testing.expectEqual(self.attached.target.id, attached.target_id);
        try std.testing.expectEqual(self.attached.rights.toBits(), attached.rights);
        try std.testing.expectEqual(self.attached.revocation_generation, attached.revocation_generation);
        try std.testing.expectEqual(self.attached.lease.expires_at_ticks, attached.expires_at_ticks);
        try std.testing.expectEqual(if (queued.unscoped) @as(u64, 0) else fixture.task_id, attached.scope_task_id);
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[CAPABILITY_OFFSET + 28 ..][0..4], 0));
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[CAPABILITY_OFFSET + 60 ..][0..4], 0));
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET + @offsetOf(abi.EndpointRecvResponse, "message") + 44 ..][0..4], 0));
        const passed = fixture.capabilities.query(attached.capability_id).?;
        try std.testing.expectEqualDeep(self.attached.target, passed.target);
        try std.testing.expectEqualDeep(self.attached.rights, passed.rights);
        try std.testing.expectEqualDeep(self.attached.lease, passed.lease);
        try std.testing.expectEqualDeep(fixture.runtime.find(fixture.task_id).?.owner, passed.holder);
        try std.testing.expect(fixture.runtime.hasCapability(fixture.task_id, attached.capability_id));
        try std.testing.expectEqual(queued.transfer == .copy, fixture.capabilities.query(queued.attached_capability_id) != null);
        try std.testing.expectEqual(queued.transfer == .copy, fixture.runtime.hasCapability(fixture.task_id, queued.attached_capability_id));
        try std.testing.expectEqual(self.grants + @intFromBool(queued.transfer == .copy), fixture.capabilities.activeCount());
        try std.testing.expectEqual(self.task_grants + 1, fixture.runtime.find(fixture.task_id).?.capabilityIds().len);
        for (user_before, 0..) |byte, index| {
            if ((index >= LABEL_OFFSET and index < LABEL_OFFSET + expected.len) or
                (index >= RESPONSE_OFFSET and index < RESPONSE_OFFSET + @sizeOf(abi.EndpointRecvResponse)) or
                (index >= CAPABILITY_OFFSET and index < CAPABILITY_OFFSET + @sizeOf(abi.CapabilityDescriptor))) continue;
            try std.testing.expectEqual(byte, fixture.user[index]);
        }
        try std.testing.expectEqual(@as(u16, 0), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
        try std.testing.expect(!fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));

        const empty_before = fixture.user;
        const grants_after = fixture.capabilities.activeCount();
        const generation_after = fixture.capabilities.mutationGeneration();
        const task_generation_after = fixture.runtime.find(fixture.task_id).?.capabilityGeneration();
        try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_recv, 14, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse)).status);
        const empty = fixture.response(abi.EndpointRecvResponse);
        try std.testing.expectEqual(@as(u8, 0), empty.present);
        try std.testing.expectEqual(@as(u8, 0), empty.has_attached_capability);
        try std.testing.expect(std.mem.allEqual(u8, fixture.user[RESPONSE_OFFSET..][0..@sizeOf(abi.EndpointRecvResponse)], 0));
        try std.testing.expectEqualDeep(std.mem.zeroes(abi.EndpointMessageDescriptor), empty.message);
        try std.testing.expectEqual(grants_after, fixture.capabilities.activeCount());
        try std.testing.expectEqual(generation_after, fixture.capabilities.mutationGeneration());
        try std.testing.expectEqual(task_generation_after, fixture.runtime.find(fixture.task_id).?.capabilityGeneration());
        try std.testing.expectEqualSlices(u8, empty_before[0..RESPONSE_OFFSET], fixture.user[0..RESPONSE_OFFSET]);
        try std.testing.expectEqualSlices(u8, empty_before[RESPONSE_OFFSET + @sizeOf(abi.EndpointRecvResponse) ..], fixture.user[RESPONSE_OFFSET + @sizeOf(abi.EndpointRecvResponse) ..]);
    }
};

const TaskAuthoritySnapshot = struct {
    record: task_runtime.TaskRecord,
    generation: u64,
    ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0),
    cspace: [task_runtime.MAX_TASK_CAPABILITIES]?u64 = @splat(null),

    fn capture(task: *const task_runtime.TaskRecord) TaskAuthoritySnapshot {
        var out = TaskAuthoritySnapshot{ .record = task.*, .generation = task.capabilityGeneration() };
        @memcpy(out.ids[0..task.capability_count], task.capabilityIds());
        for (&out.cspace, 0..) |*id, slot| id.* = task_runtime.capabilityIdAtCspaceSlot(task, @intCast(slot));
        return out;
    }

    fn expectPreserved(self: *const TaskAuthoritySnapshot, task: *const task_runtime.TaskRecord) !void {
        try std.testing.expectEqualDeep(self.record, task.*);
        try std.testing.expectEqual(self.generation, task.capabilityGeneration());
        try std.testing.expectEqualSlices(u64, self.ids[0..task.capability_count], task.capabilityIds());
        for (self.cspace, 0..) |id, slot| try std.testing.expectEqual(id, task_runtime.capabilityIdAtCspaceSlot(task, @intCast(slot)));
    }
};

const EndpointSendSnapshot = struct {
    user: [4096]u8,
    grants: capability.CapabilityTable,
    endpoints: endpoint.Table,
    source: TaskAuthoritySnapshot,
    shared_holder: TaskAuthoritySnapshot,
    ring_ids: [2]ids.EndpointId,
    ring_present: [2]bool = @splat(false),
    rings: [2][@import("ipc_ring.zig").minimumBytes(endpoint.MAX_ENDPOINT_QUEUE)]u8 = undefined,

    fn capture(fixture: *Fixture, source: *const task_runtime.TaskRecord, shared_holder: *const task_runtime.TaskRecord, sending: abi.EndpointSendWireRequest, queued: QueuedMessage) !EndpointSendSnapshot {
        const send_capability = fixture.capabilities.query(sending.endpoint_capability_id).?;
        var out = EndpointSendSnapshot{
            .user = fixture.user,
            .grants = fixture.capabilities,
            .endpoints = fixture.endpoints,
            .source = .capture(source),
            .shared_holder = .capture(shared_holder),
            .ring_ids = .{ ids.endpoint(send_capability.target.id), ids.endpoint(queued.endpoint_id) },
        };
        for (out.ring_ids, 0..) |id, index| {
            const slot = fixture.endpoints.arena.getByHandle(.{ .value = id.raw() }) orelse continue;
            const ring = slot.endpoint.data_ring;
            out.ring_present[index] = true;
            try std.testing.expectEqual(out.rings[index].len, ring.len);
            @memcpy(&out.rings[index], ring);
        }
        return out;
    }

    fn expectPreserved(self: *const EndpointSendSnapshot, fixture: *Fixture, source: *const task_runtime.TaskRecord, shared_holder: *const task_runtime.TaskRecord) !void {
        try std.testing.expectEqualSlices(u8, &self.user, &fixture.user);
        try std.testing.expectEqualDeep(self.grants, fixture.capabilities);
        try std.testing.expectEqualDeep(self.endpoints, fixture.endpoints);
        try self.source.expectPreserved(source);
        try self.shared_holder.expectPreserved(shared_holder);
        for (self.ring_ids, 0..) |id, index| {
            const slot = fixture.endpoints.arena.getByHandle(.{ .value = id.raw() });
            if (!self.ring_present[index]) {
                try std.testing.expect(slot == null);
                continue;
            }
            const ring = slot.?.endpoint.data_ring;
            try std.testing.expectEqualSlices(u8, &self.rings[index], ring);
        }
    }
};

const QueuedWakeObserver = struct {
    fixture: *Fixture,
    source: *const task_runtime.TaskRecord,
    shared_holder: *const task_runtime.TaskRecord,
    gift_id: u64,
    count: usize = 0,
    exclusive: bool = true,

    fn wake(context: *anyopaque, _: u64, _: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.count += 1;
        if (self.fixture.capabilities.requireUsable(self.gift_id, 12)) |_| {
            self.exclusive = false;
        } else |err| {
            if (err != error.CapabilityRevoked) self.exclusive = false;
        }
        if (self.source.hasCapability(self.gift_id) or self.shared_holder.hasCapability(self.gift_id)) self.exclusive = false;
    }
};

fn sameOwnerTask(fixture: *Fixture) !*task_runtime.TaskRecord {
    return fixture.runtime.createTask(.{
        .owner = fixture.runtime.find(fixture.task_id).?.owner,
        .component_class = .session_manager,
        .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 4096 },
        .local_only = true,
    });
}

const DelegatedEndpointRoute = struct {
    source_owner: *task_runtime.TaskRecord,
    receiver: *task_runtime.TaskRecord,
    source: ids.EndpointId,
    queued: QueuedMessage,
    wire: abi.EndpointSendWireRequest,

    fn create(fixture: *Fixture, transfer: Transfer) !DelegatedEndpointRoute {
        fixture.mapUser();
        const caller = fixture.runtime.find(fixture.task_id).?;
        const source_owner = try fixture.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 3 },
            .component_class = .session_manager,
            .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        const receiver = try fixture.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 4 },
            .component_class = .session_manager,
            .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        // The hosted receiver uses the same initialized backing, with its own
        // explicit address-space metadata and authenticated Surface caller.
        const receiver_space = fixture.runtime.findAddressSpace(receiver.address_space_id).?;
        receiver_space.region_count = 1;
        receiver_space.regions[0] = fixture.runtime.findAddressSpace(caller.address_space_id).?.regions[0];
        const source = try fixture.endpoints.create(ids.task(source_owner.id), "delegated-source", .{ .local_only = true });
        const destination = try fixture.endpoints.create(ids.task(receiver.id), "delegated-destination", .{ .local_only = true });
        try fixture.endpoints.connect(source.id, destination.id);
        const owned = try fixture.capabilities.mintBootRoot(.{
            .holder = source_owner.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = source.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true, .capability_pass = true } },
            .scope = .{ .task_id = source_owner.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.runtime.grantCapability(source_owner.id, owned.id);
        const delegated = try fixture.kernel.capabilityPass(.{
            .caller_task_id = source_owner.id,
            .presented_capability_id = owned.id,
            .target = .none,
        }, caller.id, 10, false);
        const receiving = try fixture.capabilities.mintBootRoot(.{
            .holder = receiver.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = destination.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_recv = true } },
            .scope = .{ .task_id = receiver.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.runtime.grantCapability(receiver.id, receiving.id);
        const gift = try fixture.capabilities.mintBootRoot(.{
            .holder = caller.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 43 },
            .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
            .scope = .{ .task_id = caller.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.runtime.grantCapability(caller.id, gift.id);
        const payload = stagedPayload();
        @memcpy(fixture.user[LABEL_OFFSET..][0..payload.len], &payload);
        return .{
            .source_owner = source_owner,
            .receiver = receiver,
            .source = source.id,
            .queued = .{ .endpoint_id = destination.id.raw(), .endpoint_capability_id = receiving.id, .attached_capability_id = gift.id, .transfer = transfer },
            .wire = .{
                .header = component_port.makeHeader(.endpoint_send, caller.id),
                .endpoint_capability_id = delegated.capability_id,
                .correlation_id = 91,
                .payload_address = @intFromPtr(&fixture.user) + LABEL_OFFSET,
                .payload_bytes = payload.len,
                .attached_capability_id = gift.id,
                .flags = if (transfer == .move) abi.ENDPOINT_SEND_MOVE_ATTACHMENT else 0,
            },
        };
    }
};

const RoutingWakeObserver = struct {
    count: usize = 0,
    task_id: u64 = 0,
    tick: u64 = 0,

    fn wake(context: *anyopaque, task_id: u64, tick: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.count += 1;
        self.task_id = task_id;
        self.tick = tick;
    }
};

test "syscall failure delegated endpoint routing admits distinct live owners through Surface" {
    for (std.enums.values(Transfer)) |transfer| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const route = try DelegatedEndpointRoute.create(fixture, transfer);
        const caller = fixture.runtime.find(fixture.task_id).?;
        try std.testing.expect(caller.id != route.source_owner.id and caller.id != route.receiver.id);
        const source_before = TaskAuthoritySnapshot.capture(route.source_owner);
        const receiver_before = TaskAuthoritySnapshot.capture(route.receiver);
        var wake = RoutingWakeObserver{};
        fixture.kernel.bindEndpointWakeSink(.{ .context = &wake, .wake = RoutingWakeObserver.wake });
        defer fixture.kernel.clearEndpointWakeSink();
        const request = fixture.request(route.wire);
        const user_before = fixture.user;
        const sent = fixture.call(.endpoint_send, 12, request, std.math.maxInt(usize), std.math.maxInt(usize));
        try std.testing.expectEqual(abi.SyscallStatus.success, sent.status);
        try std.testing.expectEqual(abi.DenialReason.none, sent.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), sent.bytes_written);
        try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
        try source_before.expectPreserved(route.source_owner);
        try receiver_before.expectPreserved(route.receiver);
        try std.testing.expectEqual(@as(usize, 1), wake.count);
        try std.testing.expectEqual(route.receiver.id, wake.task_id);
        try std.testing.expectEqual(@as(u64, 12), wake.tick);
        try std.testing.expectEqual(@as(u16, 1), (try fixture.endpoints.descriptor(ids.endpoint(route.queued.endpoint_id))).queued_messages);
        try std.testing.expectEqual(transfer == .copy, caller.hasCapability(route.queued.attached_capability_id));
        if (transfer == .move) try std.testing.expectError(error.CapabilityRevoked, fixture.capabilities.requireUsable(route.queued.attached_capability_id, 12));
        @memset(fixture.user[LABEL_OFFSET..][0..endpoint.MAX_MESSAGE_BYTES], 0xee);
        var receive_wire = fixture.receiveRequest(route.queued);
        receive_wire.header = component_port.makeHeader(.endpoint_recv, route.receiver.id);
        receive_wire.receiver_task_id = route.receiver.id;
        const receive = fixture.request(receive_wire);
        const received = syscall_surface.dispatch(&fixture.port, route.receiver.id, 13, abi.opcode(.endpoint_recv), receive, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, received.status);
        try std.testing.expectEqual(abi.DenialReason.none, received.denial_reason);
        try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), received.bytes_written);
        const response = fixture.response(abi.EndpointRecvResponse);
        try std.testing.expectEqual(@as(u8, 1), response.present);
        try std.testing.expectEqual(@as(u8, 1), response.has_attached_capability);
        try std.testing.expectEqual(route.source.raw(), response.message.sender_endpoint_id);
        try std.testing.expectEqual(caller.id, response.message.sender_task_id);
        try std.testing.expectEqual(@as(u64, 91), response.message.correlation_id);
        const payload = stagedPayload();
        try std.testing.expectEqualSlices(u8, &payload, fixture.user[LABEL_OFFSET..][0..payload.len]);
        const attached = @as(*const abi.CapabilityDescriptor, @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET)).*;
        try std.testing.expect(attached.capability_id != route.queued.attached_capability_id);
        try std.testing.expectEqual(route.receiver.id, attached.scope_task_id);
        try std.testing.expect(route.receiver.hasCapability(attached.capability_id));
        try std.testing.expectEqual(transfer == .copy, fixture.capabilities.query(route.queued.attached_capability_id) != null);
        try std.testing.expectEqual(@as(u16, 0), (try fixture.endpoints.descriptor(ids.endpoint(route.queued.endpoint_id))).queued_messages);
        try std.testing.expect(!fixture.endpoints.hasPendingForTask(ids.task(route.receiver.id)));
        const generation_after = fixture.capabilities.mutationGeneration();
        const empty = syscall_surface.dispatch(&fixture.port, route.receiver.id, 14, abi.opcode(.endpoint_recv), receive, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, empty.status);
        try std.testing.expectEqual(@as(u8, 0), fixture.response(abi.EndpointRecvResponse).present);
        try std.testing.expectEqual(generation_after, fixture.capabilities.mutationGeneration());
    }
}

test "syscall failure delegated routing rejects retained terminated source and destination before gifts or backpressure" {
    const cpu_identity = @import("../../kernel/cpu_identity.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]bool{ true, false }) |stop_source| {
        for (std.enums.values(Transfer)) |transfer| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const route = try DelegatedEndpointRoute.create(fixture, transfer);
            const caller = fixture.runtime.find(fixture.task_id).?;
            var fill = route.wire;
            fill.attached_capability_id = 0;
            fill.flags = 0;
            for (0..endpoint.MAX_ENDPOINT_QUEUE) |_| {
                const sent = fixture.call(.endpoint_send, 11, fixture.request(fill), 0, 0);
                try std.testing.expectEqual(abi.SyscallStatus.success, sent.status);
            }
            const owner = if (stop_source) route.source_owner else route.receiver;
            const ticket = try fixture.runtime.reserveExecution(owner, 1);
            try fixture.runtime.execution.bindOwnedRoot(ticket, 1, 0x1000);
            cpu_identity.setIndexForTest(1);
            _ = try fixture.runtime.execution.start(ticket);
            cpu_identity.setIndexForTest(0);
            defer {
                cpu_identity.setIndexForTest(1);
                fixture.runtime.execution.acknowledgeOwnedRootReturn(ticket) catch @panic("routing fixture returns its owned root");
                cpu_identity.setIndexForTest(0);
                fixture.runtime.collectExecution(ticket) catch @panic("routing fixture releases retained owner");
            }
            try std.testing.expect(try fixture.runtime.terminateTask(owner.id, 12));
            try std.testing.expectEqual(task_runtime.TaskState.terminated, owner.state);
            try std.testing.expectEqual(task_runtime.TaskState.active, caller.state);
            try std.testing.expectEqual(@as(u16, endpoint.MAX_ENDPOINT_QUEUE), (try fixture.endpoints.descriptor(ids.endpoint(route.queued.endpoint_id))).queued_messages);
            var wake = RoutingWakeObserver{};
            fixture.kernel.bindEndpointWakeSink(.{ .context = &wake, .wake = RoutingWakeObserver.wake });
            defer fixture.kernel.clearEndpointWakeSink();
            for ([_]enum { valid_gift, absent_gift, malformed_wire }{ .valid_gift, .absent_gift, .malformed_wire }) |case| {
                var wire = route.wire;
                if (case == .absent_gift) wire.attached_capability_id = std.math.maxInt(u64);
                if (case == .malformed_wire) wire.flags |= 0x8000;
                const request = fixture.request(wire);
                const before = try EndpointSendSnapshot.capture(fixture, caller, route.source_owner, wire, route.queued);
                const receiver_before = TaskAuthoritySnapshot.capture(route.receiver);
                const result = fixture.call(.endpoint_send, 13, request, std.math.maxInt(usize), std.math.maxInt(usize));
                // Fixed-wire rejection precedes Kernel admission; admitted
                // wires fail on the actual owner before gift lookup/RingFull.
                try std.testing.expectEqual(if (case == .malformed_wire) abi.SyscallStatus.invalid_request_pointer else abi.SyscallStatus.not_found, result.status);
                try std.testing.expectEqual(abi.DenialReason.invalid_target, result.denial_reason);
                try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
                try before.expectPreserved(fixture, caller, route.source_owner);
                try receiver_before.expectPreserved(route.receiver);
                try std.testing.expectEqual(@as(usize, 0), wake.count);
                try std.testing.expect(caller.hasCapability(route.queued.attached_capability_id));
                _ = try fixture.capabilities.requireUsable(route.queued.attached_capability_id, 13);
            }
        }
    }
}

test "syscall failure unscoped endpoint MOVE queues exclusive authority and receives once" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const source = fixture.runtime.find(fixture.task_id).?;
    const shared_holder = try sameOwnerTask(fixture);
    const queued = try fixture.queueAttachedMessageWithScope(.move, true, shared_holder.id);
    const send = @as(*const abi.EndpointSendWireRequest, @ptrCast(&fixture.user)).*;
    // Metadata stays allocated for the sealed record; ordinary authority,
    // including trusted caller zero, must already have left the sender.
    try std.testing.expect(fixture.capabilities.query(queued.attached_capability_id) != null);
    try std.testing.expectError(error.CapabilityRevoked, fixture.capabilities.requireUsable(queued.attached_capability_id, 12));
    try std.testing.expect(!source.hasCapability(queued.attached_capability_id));
    try std.testing.expect(!shared_holder.hasCapability(queued.attached_capability_id));
    const before = try ReceiveSnapshot.capture(fixture, queued);
    const grants_before = fixture.capabilities;
    try std.testing.expectError(error.CapabilityRevoked, fixture.kernel.timeQuery(.{
        .caller_task_id = 0,
        .presented_capability_id = queued.attached_capability_id,
        .target = .none,
    }, 12));
    try std.testing.expectError(error.CapabilityRevoked, fixture.kernel.capabilityPass(.{
        .caller_task_id = 0,
        .presented_capability_id = queued.attached_capability_id,
        .target = .none,
    }, source.id, 12, false));
    try std.testing.expectEqualDeep(grants_before, fixture.capabilities);
    try before.expectPreserved(fixture, queued);

    // A repeated scalar MOVE cannot publish another ownership claim for the
    // same full generational grant ID.
    const payload = stagedPayload();
    @memcpy(fixture.user[LABEL_OFFSET..][0..payload.len], &payload);
    const repeated = fixture.request(send);
    const repeated_before = try ReceiveSnapshot.capture(fixture, queued);
    const rejected = fixture.call(.endpoint_send, 12, repeated, 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.denied, rejected.status);
    try std.testing.expectEqual(abi.DenialReason.capability_revoked, rejected.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
    try std.testing.expectEqualDeep(grants_before, fixture.capabilities);
    try repeated_before.expectPreserved(fixture, queued);
    try repeated_before.expectRetry(fixture, queued);
    try std.testing.expect(!shared_holder.hasCapability(queued.attached_capability_id));
}

test "syscall failure endpoint MOVE send failures preserve all holders rings and wake state" {
    const SendFailure = enum { ring_full, peer_closed, malformed, unauthorized };
    for (std.enums.values(SendFailure)) |failure| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const source = fixture.runtime.find(fixture.task_id).?;
        const shared_holder = try sameOwnerTask(fixture);
        const queued = try fixture.prepareAttachedMessageWithScope(.move, true, shared_holder.id);
        const valid = @as(*const abi.EndpointSendWireRequest, @ptrCast(&fixture.user)).*;
        if (failure == .ring_full) {
            for (0..endpoint.MAX_ENDPOINT_QUEUE) |index| try fixture.kernel.endpointSend(.{
                .caller_task_id = source.id,
                .presented_capability_id = valid.endpoint_capability_id,
                .target = .none,
            }, index, "occupancy", 0, null, false, 11);
        } else if (failure == .peer_closed) {
            try fixture.kernel.retireEndpoint(ids.endpoint(queued.endpoint_id), 11);
        }
        var wire = valid;
        if (failure == .malformed) wire.reserved = 1;
        if (failure == .unauthorized) wire.endpoint_capability_id = fixture.authority_id;
        const address = fixture.request(wire);
        const before = try EndpointSendSnapshot.capture(fixture, source, shared_holder, valid, queued);
        var observer = QueuedWakeObserver{ .fixture = fixture, .source = source, .shared_holder = shared_holder, .gift_id = queued.attached_capability_id };
        fixture.kernel.bindEndpointWakeSink(.{ .context = &observer, .wake = QueuedWakeObserver.wake });
        defer fixture.kernel.clearEndpointWakeSink();
        const result = fixture.call(.endpoint_send, 12, address, 0, 0);
        try std.testing.expectEqual(switch (failure) {
            .ring_full => abi.SyscallStatus.would_block,
            .peer_closed => .peer_closed,
            .malformed => .invalid_request_pointer,
            .unauthorized => .denied,
        }, result.status);
        try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
        try before.expectPreserved(fixture, source, shared_holder);
        try std.testing.expectEqual(@as(usize, 0), observer.count);
        _ = try fixture.capabilities.requireUsable(queued.attached_capability_id, 12);
        try std.testing.expect(source.hasCapability(queued.attached_capability_id));
        try std.testing.expect(shared_holder.hasCapability(queued.attached_capability_id));

        if (failure == .peer_closed) continue; // A closed connection is terminal.
        if (failure == .ring_full) {
            var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
            _ = (try fixture.kernel.endpointRecv(.{
                .caller_task_id = source.id,
                .presented_capability_id = queued.endpoint_capability_id,
                .target = .none,
            }, source.id, &payload, 13)).?;
        }
        const retry = fixture.request(valid);
        const retry_user = fixture.user;
        try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_send, 13, retry, 0, 0).status);
        try std.testing.expectEqualSlices(u8, &retry_user, &fixture.user);
        try std.testing.expectEqual(@as(usize, 1), observer.count);
        try std.testing.expect(observer.exclusive);
        try std.testing.expectError(error.CapabilityRevoked, fixture.capabilities.requireUsable(queued.attached_capability_id, 13));
        try std.testing.expect(!source.hasCapability(queued.attached_capability_id));
        try std.testing.expect(!shared_holder.hasCapability(queued.attached_capability_id));
    }
}

test "syscall failure unscoped endpoint COPY retains source authority after receive" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const shared_holder = try sameOwnerTask(fixture);
    const queued = try fixture.queueAttachedMessageWithScope(.copy, true, shared_holder.id);
    const peer_before = TaskAuthoritySnapshot.capture(shared_holder);
    _ = try fixture.capabilities.requireUsable(queued.attached_capability_id, 12);
    try std.testing.expect(shared_holder.hasCapability(queued.attached_capability_id));
    const before = try ReceiveSnapshot.capture(fixture, queued);
    try before.expectRetry(fixture, queued);
    _ = try fixture.capabilities.requireUsable(queued.attached_capability_id, 14);
    try peer_before.expectPreserved(shared_holder);
}

test "syscall failure endpoint scalar wire rejects malformed bytes before queue or grant mutation" {
    const WireFailure = enum {
        operation,
        header_flags,
        zero_subject,
        foreign_subject,
        unknown_flags,
        raw_boolean_tag,
        reserved,
        move_without_attachment,
        oversize,
        maximum_length,
        null_payload,
        low_payload,
        noncanonical_payload,
        payload_end_overflow,
        unmapped_payload_tail,
        request_unaligned,
        request_tail,
        low_request,
        request_end_overflow,
        absent_attachment,
    };
    for ([_]Transfer{ .copy, .move }) |transfer| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const queued = try fixture.queueAttachedMessage(transfer);
        const original = @as(*const abi.EndpointSendWireRequest, @ptrCast(&fixture.user)).*;
        var last_snapshot: ReceiveSnapshot = undefined;
        for (std.enums.values(WireFailure)) |failure| {
            fixture.mapUser();
            var wire = original;
            // Retain the legitimate queued capability independently of these
            // new attempted sends, including its moved attachment lifetime.
            const payload = stagedPayload();
            @memcpy(fixture.user[LABEL_OFFSET..][0..payload.len], &payload);
            switch (failure) {
                .operation => wire.header.operation = abi.opcode(.endpoint_close),
                .header_flags => wire.header.flags = 1,
                .zero_subject => wire.header.subject_task_id = 0,
                .foreign_subject => wire.header.subject_task_id += 1,
                .unknown_flags => wire.flags |= 2,
                .raw_boolean_tag => wire.flags = 0xff,
                .reserved => wire.reserved = 1,
                .move_without_attachment => {
                    wire.flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT;
                    wire.attached_capability_id = 0;
                },
                .oversize => wire.payload_bytes = endpoint.MAX_MESSAGE_BYTES + 1,
                .maximum_length => wire.payload_bytes = std.math.maxInt(u32),
                .null_payload => wire.payload_address = 0,
                .low_payload => wire.payload_address = 0x1000,
                .noncanonical_payload => wire.payload_address = 0x0000_8000_0000_0000,
                .payload_end_overflow => wire.payload_address = std.math.maxInt(u64) - 4,
                .unmapped_payload_tail => wire.payload_address = @intFromPtr(&fixture.user) + fixture.user.len - 8,
                .absent_attachment => wire.attached_capability_id = std.math.maxInt(u64),
                .request_unaligned, .request_tail, .low_request, .request_end_overflow => {},
            }
            var address = fixture.request(wire);
            switch (failure) {
                .request_unaligned => {
                    @memcpy(fixture.user[1..][0..@sizeOf(@TypeOf(wire))], std.mem.asBytes(&wire));
                    address += 1;
                },
                .request_tail => {
                    const bytes = std.mem.asBytes(&wire);
                    @memcpy(fixture.user[fixture.user.len - bytes.len ..], bytes);
                    address = @intFromPtr(&fixture.user) + fixture.user.len - bytes.len;
                    const task = fixture.runtime.find(fixture.task_id).?;
                    fixture.runtime.findAddressSpace(task.address_space_id).?.regions[0].size_bytes -= 1;
                },
                .low_request => address = 0x1000,
                .request_end_overflow => address = std.math.maxInt(usize) - 4,
                else => {},
            }
            last_snapshot = try ReceiveSnapshot.capture(fixture, queued);
            var rings: [endpoint.MAX_ENDPOINTS]?[]u8 = @splat(null);
            defer for (rings) |ring| if (ring) |bytes| std.testing.allocator.free(bytes);
            for (&fixture.endpoints.arena.slots, 0..) |*slot, index| {
                if (slot.in_use) rings[index] = try std.testing.allocator.dupe(u8, slot.endpoint.data_ring);
            }
            const result = fixture.call(.endpoint_send, 12, address, std.math.maxInt(usize), std.math.maxInt(usize));
            const expected: abi.SyscallStatus = if (failure == .absent_attachment) .not_found else .invalid_request_pointer;
            try std.testing.expectEqual(expected, result.status);
            try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
            try last_snapshot.expectPreserved(fixture, queued);
            for (rings, 0..) |ring, index| if (ring) |bytes|
                try std.testing.expectEqualSlices(u8, bytes, fixture.endpoints.arena.slots[index].endpoint.data_ring);
        }
        // Valid scalar send already staged the complete payload. Neither the
        // caller reuse nor any rejected wire can corrupt its later copy/move.
        try last_snapshot.expectRetry(fixture, queued);
    }
}

test "syscall failure endpoint empty scalar payload ignores address and grants no attachment" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const queued = try fixture.queueAttachedMessage(.copy);
    var wire = @as(*const abi.EndpointSendWireRequest, @ptrCast(&fixture.user)).*;
    const first = try ReceiveSnapshot.capture(fixture, queued);
    try first.expectRetry(fixture, queued);
    wire.correlation_id = 92;
    wire.payload_address = std.math.maxInt(u64);
    wire.payload_bytes = 0;
    wire.flags = 0;
    wire.attached_capability_id = 0;
    const address = fixture.request(wire);
    const user = fixture.user;
    const grants = fixture.capabilities.activeCount();
    const generation = fixture.capabilities.mutationGeneration();
    const task_generation = fixture.runtime.find(fixture.task_id).?.capabilityGeneration();
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_send, 15, address, 0, 0).status);
    try std.testing.expectEqualSlices(u8, &user, &fixture.user);
    try std.testing.expectEqual(@as(u16, 1), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
    try std.testing.expect(fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));
    var receive_wire = fixture.receiveRequest(queued);
    receive_wire.payload_capacity = 0;
    receive_wire.payload_address = std.math.maxInt(u64);
    const receive = fixture.request(receive_wire);
    const before_receive = fixture.user;
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_recv, 16, receive, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse)).status);
    const response = fixture.response(abi.EndpointRecvResponse);
    try std.testing.expectEqual(@as(u8, 1), response.present);
    try std.testing.expectEqual(@as(u8, 0), response.has_attached_capability);
    try std.testing.expectEqual(@as(u16, 0), response.message.payload_len);
    try std.testing.expectEqual(@as(u64, 92), response.message.correlation_id);
    try std.testing.expectEqual(@as(u64, 0), response.message.attached_capability_id);
    try std.testing.expectEqualSlices(u8, before_receive[0..RESPONSE_OFFSET], fixture.user[0..RESPONSE_OFFSET]);
    try std.testing.expectEqualSlices(u8, before_receive[RESPONSE_OFFSET + @sizeOf(abi.EndpointRecvResponse) ..], fixture.user[RESPONSE_OFFSET + @sizeOf(abi.EndpointRecvResponse) ..]);
    try std.testing.expectEqual(grants, fixture.capabilities.activeCount());
    try std.testing.expectEqual(generation, fixture.capabilities.mutationGeneration());
    try std.testing.expectEqual(task_generation, fixture.runtime.find(fixture.task_id).?.capabilityGeneration());
    try std.testing.expectEqual(@as(u16, 0), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
    try std.testing.expect(!fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));
}

fn expectHostRingMapped(address: usize, mapped: bool) !void {
    if (comptime builtin.os.tag == .macos) {
        var region_address: std.c.mach_vm_address_t = address;
        var region_bytes: std.c.mach_vm_size_t = 0;
        var info: std.c.vm_region_basic_info_64 = undefined;
        var info_count = std.c.VM.REGION.BASIC_INFO_COUNT;
        var object: std.c.mach_port_t = 0;
        const task = std.c.mach_task_self();
        const result = std.c.mach_vm_region(task, &region_address, &region_bytes, std.c.VM.REGION.BASIC_INFO_64, @ptrCast(&info), &info_count, &object);
        defer if (object != 0) {
            _ = std.c.mach_port_deallocate(task, object);
        };
        // A hole returns the next mapping, or KERN_INVALID_ADDRESS (1) when
        // none follows. Any other error must not masquerade as a freed ring.
        if (result != 0) {
            try std.testing.expectEqual(@as(std.c.kern_return_t, 1), result);
            try std.testing.expect(!mapped);
            return;
        }
        const contains = region_address <= address and address - region_address < region_bytes;
        try std.testing.expectEqual(mapped, contains);
    } else if (comptime builtin.os.tag == .linux) {
        var residency: [1]u8 = undefined;
        const query = std.posix.mincore(@ptrFromInt(address), std.heap.pageSize(), &residency);
        if (mapped) try query else try std.testing.expectError(error.OutOfMemory, query);
    } else unreachable;
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

test "syscall failure fixture construction unwinds task authority and queued move rings" {
    for ([_]ConstructionFailure{ .after_task, .after_authority, .after_queued_move }) |failure| {
        var cleanup: CleanupObservation = undefined;
        try std.testing.expectError(error.InjectedConstructionFailure, Fixture.createWithFailure(failure, &cleanup));
        // Captured immediately after Runtime.reset, before table deinit can
        // mask a skipped Kernel retirement sink or a still-owned ring.
        try cleanup.expectRetired();
    }
}

test "syscall failure fixture reset releases both owned rings and undelivered attachments" {
    for (std.enums.values(Transfer)) |transfer| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        _ = try fixture.queueAttachedMessage(transfer);
        const before = CleanupObservation.capture(fixture);
        try std.testing.expectEqual(@as(usize, 1), before.tasks);
        try std.testing.expectEqual(@as(usize, 2), before.endpoints);
        try std.testing.expectEqual(@as(usize, 2), before.owned_rings);
        try std.testing.expect(before.pending);
        fixture.runtime.reset();
        try CleanupObservation.capture(fixture).expectRetired();
        fixture.runtime.reset();
        try CleanupObservation.capture(fixture).expectRetired();
    }
}

test "syscall failure fixture reset returns both ring allocations to the host" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    for (std.enums.values(Transfer)) |transfer| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        _ = try fixture.queueAttachedMessage(transfer);
        var allocations: [2]usize = undefined;
        var count: usize = 0;
        for (&fixture.endpoints.arena.slots) |*slot| {
            if (slot.endpoint.data_ring.len == 0) continue;
            try std.testing.expect(slot.endpoint.ring_allocation_offset != std.math.maxInt(u8));
            try std.testing.expect(count < allocations.len);
            allocations[count] = @intFromPtr(slot.endpoint.data_ring.ptr) - slot.endpoint.ring_allocation_offset;
            count += 1;
        }
        try std.testing.expectEqual(allocations.len, count);
        // Hosted table backing creates independent page_allocator mappings.
        // Observe their mapping lifetime without reading freed ring storage;
        // testing.allocator alone cannot detect these allocations leaking.
        for (allocations) |address| {
            try expectHostRingMapped(address, true);
        }
        fixture.runtime.reset();
        // No intervening allocation can reuse either retired virtual page.
        for (allocations) |address| {
            try expectHostRingMapped(address, false);
        }
        try CleanupObservation.capture(fixture).expectRetired();
    }
}

test "syscall failure scalar endpoint create rejects malformed fields and label spans before publication" {
    const Malformed = enum {
        flags,
        reserved,
        header_flags,
        header_reserved,
        subject,
        label_too_large,
        label_below_floor,
        label_high_half,
        label_end_overflow,
        label_canonical_tail,
        label_foreign,
        label_unmapped_tail,
    };
    const fixture = try Fixture.create();
    defer fixture.destroy();
    // Fixed request, nested label and complete response all have declared
    // writable storage. These refusals must come from scalar admission or the
    // hostile nested span, rather than an unrelated output preflight failure.
    fixture.mapUser();
    const task = fixture.runtime.find(fixture.task_id).?;
    for (std.enums.values(Malformed)) |failure| {
        @memset(&fixture.user, 0xA5);
        var request = fixture.endpointRequest();
        switch (failure) {
            .flags => request.flags = 0x8000,
            .reserved => request.reserved = 1,
            .header_flags => request.header.flags = 1,
            .header_reserved => request.header.reserved = 1,
            .subject => request.header.subject_task_id = fixture.task_id + 1,
            .label_too_large => request.label_bytes = endpoint.MAX_ENDPOINT_LABEL_BYTES + 1,
            .label_below_floor => request.label_address = 0x1000,
            .label_high_half => request.label_address = 0xffff_8000_0000_0000,
            .label_end_overflow => {
                request.label_address = std.math.maxInt(u64) - 7;
                request.label_bytes = 16;
            },
            .label_canonical_tail => {
                request.label_address = 0x0000_7fff_ffff_fffc;
                request.label_bytes = 8;
            },
            .label_foreign => request.label_address = @intFromPtr(&fixture.kernel),
            .label_unmapped_tail => {
                request.label_address = @intFromPtr(&fixture.user) + fixture.user.len - 3;
                request.label_bytes = 4;
            },
        }
        const request_addr = fixture.request(request);
        const user_before = fixture.user;
        const resources_before = CleanupObservation.capture(fixture);
        const endpoints_before = fixture.endpoints;
        const capabilities_before = fixture.capabilities;
        const task_before = task.*;
        const task_generation = task.capabilityGeneration();
        var task_capabilities: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
        @memcpy(task_capabilities[0..task.capability_count], task.capabilityIds());
        const authority_slot = task_runtime.cspaceSlotForCapability(task, fixture.authority_id);
        const rejected = fixture.call(.endpoint_create, 10, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse));
        if (rejected.status != .invalid_request_pointer) std.debug.print("endpoint create malformed case: {s}\n", .{@tagName(failure)});
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, rejected.status);
        try std.testing.expectEqual(abi.DenialReason.invalid_target, rejected.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
        try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
        // Equality inspects initialized semantic fields, including allocator
        // cursors, slot generations and owner/grant indexes, not raw padding.
        try std.testing.expectEqualDeep(resources_before, CleanupObservation.capture(fixture));
        try std.testing.expectEqualDeep(endpoints_before, fixture.endpoints);
        try std.testing.expectEqualDeep(capabilities_before, fixture.capabilities);
        try std.testing.expectEqualDeep(task_before, task.*);
        try std.testing.expectEqual(task_generation, task.capabilityGeneration());
        try std.testing.expectEqualSlices(u64, task_capabilities[0..task.capability_count], task.capabilityIds());
        try std.testing.expectEqual(authority_slot, task_runtime.cspaceSlotForCapability(task, fixture.authority_id));
    }
    @memset(&fixture.user, 0xA5);
    const request_addr = fixture.request(fixture.endpointRequest());
    const user_before = fixture.user;
    const grants_before = fixture.capabilities.activeCount();
    const task_grants_before = task.capability_count;
    const created_result = fixture.call(.endpoint_create, 11, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, created_result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointCreateResponse)), created_result.bytes_written);
    const created = fixture.response(abi.EndpointCreateResponse);
    try std.testing.expect(created.endpoint.endpoint_id != 0 and created.capability_id != 0);
    try std.testing.expectEqual(fixture.task_id, created.endpoint.owner_task_id);
    try std.testing.expect(task.hasCapability(created.capability_id));
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
    try std.testing.expectEqual(@as(u16, 1), fixture.endpoints.activeForTask(ids.task(fixture.task_id)));
    try std.testing.expectEqual(grants_before + 1, fixture.capabilities.activeCount());
    try std.testing.expectEqual(task_grants_before + 1, task.capability_count);
    const output_end = RESPONSE_OFFSET + @sizeOf(abi.EndpointCreateResponse);
    try std.testing.expectEqualSlices(u8, user_before[0..RESPONSE_OFFSET], fixture.user[0..RESPONSE_OFFSET]);
    try std.testing.expectEqualSlices(u8, user_before[output_end..], fixture.user[output_end..]);
    const after_create = fixture.user;
    const exhausted = fixture.call(.endpoint_create, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointCreateResponse));
    try std.testing.expectEqual(abi.SyscallStatus.conflict, exhausted.status);
    try std.testing.expectEqual(@as(u32, 0), exhausted.bytes_written);
    try std.testing.expectEqualSlices(u8, &after_create, &fixture.user);
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
    try std.testing.expectEqual(grants_before + 1, fixture.capabilities.activeCount());
    try std.testing.expectEqual(task_grants_before + 1, task.capability_count);
}

test "syscall failure endpoint output validation preserves grants and the last quota slot" {
    for (failures) |failure| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const request_addr = fixture.request(fixture.endpointRequest());
        const output = fixture.badResponse(abi.EndpointCreateResponse, failure);
        const grants_before = fixture.capabilities.activeCount();
        const task_grants_before = fixture.runtime.find(fixture.task_id).?.capability_count;
        const user_before = fixture.user;
        const rejected = fixture.call(.endpoint_create, 10, request_addr, output.address, output.length);
        try expectFailure(failure, rejected);
        try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
        try std.testing.expectEqual(@as(u16, 0), fixture.endpoints.activeForTask(ids.task(fixture.task_id)));
        try std.testing.expectEqual(grants_before, fixture.capabilities.activeCount());
        try std.testing.expectEqual(task_grants_before, fixture.runtime.find(fixture.task_id).?.capability_count);
        try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);

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
        const user_before = fixture.user;
        try expectFailure(failure, fixture.call(.input_recv, 10, request_addr, output.address, output.length));
        try std.testing.expectEqual(@as(usize, 0), queue.polls);
        try std.testing.expectEqualDeep(expected, queue.pending.?);
        try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);

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

test "syscall failure close rejects reserved header flags before queued authority retirement" {
    const InvalidHeader = enum { low_flag, high_flag, all_flags, opcode, opcode_and_flags };
    for ([_]bool{ false, true }) |unscoped| {
        for (std.enums.values(Transfer)) |transfer| {
            for (std.enums.values(InvalidHeader)) |case| {
                const fixture = try Fixture.create();
                defer fixture.destroy();
                const queued = try fixture.queueAttachedMessageWithScope(transfer, unscoped, null);
                var request = component_port.EndpointCloseRequest{
                    .header = component_port.makeHeader(.endpoint_close, fixture.task_id),
                    .endpoint_capability_id = queued.endpoint_capability_id,
                };
                switch (case) {
                    .low_flag => request.header.flags = 1,
                    .high_flag => request.header.flags = 0x8000,
                    .all_flags => request.header.flags = 0xffff,
                    .opcode => request.header.operation = abi.opcode(.endpoint_send),
                    .opcode_and_flags => {
                        request.header.operation = abi.opcode(.endpoint_send);
                        request.header.flags = 0xffff;
                    },
                }
                const request_addr = fixture.request(request);
                const before = try ReceiveSnapshot.capture(fixture, queued);
                const slot = fixture.endpoints.arena.getByHandle(.{ .value = queued.endpoint_id }).?;
                const ring_address = @intFromPtr(slot.endpoint.data_ring.ptr);
                const ring_before = try std.testing.allocator.dupe(u8, slot.endpoint.data_ring);
                defer std.testing.allocator.free(ring_before);
                const result = fixture.call(.endpoint_close, 12, request_addr, std.math.maxInt(usize), std.math.maxInt(usize));
                const opcode_wrong = case == .opcode or case == .opcode_and_flags;
                try std.testing.expectEqual(if (opcode_wrong) abi.SyscallStatus.unsupported_operation else abi.SyscallStatus.invalid_request_pointer, result.status);
                try std.testing.expectEqual(if (opcode_wrong) abi.DenialReason.unsupported_operation else abi.DenialReason.invalid_target, result.denial_reason);
                try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
                try before.expectPreserved(fixture, queued);
                const retained = fixture.endpoints.arena.getByHandle(.{ .value = queued.endpoint_id }).?;
                try std.testing.expectEqual(ring_address, @intFromPtr(retained.endpoint.data_ring.ptr));
                try std.testing.expectEqualSlices(u8, ring_before, retained.endpoint.data_ring);

                request.header = component_port.makeHeader(.endpoint_close, fixture.task_id);
                const retry_addr = fixture.request(request);
                const user_before = fixture.user;
                const closed = fixture.call(.endpoint_close, 13, retry_addr, std.math.maxInt(usize), std.math.maxInt(usize));
                try std.testing.expectEqual(abi.SyscallStatus.success, closed.status);
                try std.testing.expectEqual(@as(u32, 0), closed.bytes_written);
                try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
                try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
                try std.testing.expect(!fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));
                try std.testing.expect(fixture.capabilities.query(queued.endpoint_capability_id) == null);
                try std.testing.expect(!fixture.runtime.hasCapability(fixture.task_id, queued.endpoint_capability_id));
                try std.testing.expectEqual(transfer == .copy, fixture.capabilities.query(queued.attached_capability_id) != null);
                try std.testing.expectEqual(before.grants - 1 - @as(usize, @intFromBool(transfer == .move)), fixture.capabilities.activeCount());
                const grants_after = fixture.capabilities.mutationGeneration();
                const repeated = fixture.call(.endpoint_close, 14, retry_addr, 0, 0);
                try std.testing.expectEqual(abi.SyscallStatus.not_found, repeated.status);
                try std.testing.expectEqual(grants_after, fixture.capabilities.mutationGeneration());
            }
        }
    }
}

test "syscall failure generated response admission rejects reserved header flags before publication" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    fixture.mapResponse(abi.TimeQueryResponse, true);
    var request = component_port.TimeQueryRequest{
        .header = component_port.makeHeader(.time_query, fixture.task_id),
        .authority_capability_id = fixture.authority_id,
    };
    request.header.flags = 0x8000;
    const request_addr = fixture.request(request);
    const user_before = fixture.user;
    const grant_generation = fixture.capabilities.mutationGeneration();
    const denied = fixture.call(.time_query, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.TimeQueryResponse));
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, denied.status);
    try std.testing.expectEqual(abi.DenialReason.invalid_target, denied.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), denied.bytes_written);
    try std.testing.expectEqualSlices(u8, &user_before, &fixture.user);
    try std.testing.expectEqual(grant_generation, fixture.capabilities.mutationGeneration());
    request.header.flags = 0;
    const retried = fixture.call(.time_query, 13, fixture.request(request), fixture.responseAddress(), @sizeOf(abi.TimeQueryResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, retried.status);
    try std.testing.expectEqual(@as(u64, 13), fixture.response(abi.TimeQueryResponse).now_ticks);
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

test "syscall failure receive primary preflight preserves copied and moved attachments" {
    for (std.enums.values(Transfer)) |transfer| {
        for (failures) |failure| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const queued = try fixture.queueAttachedMessage(transfer);
            const request_addr = fixture.request(fixture.receiveRequest(queued));
            const output = fixture.badResponse(abi.EndpointRecvResponse, failure);
            const before = try ReceiveSnapshot.capture(fixture, queued);
            try expectFailure(failure, fixture.call(.endpoint_recv, 12, request_addr, output.address, output.length));
            try before.expectPreserved(fixture, queued);
            try before.expectRetry(fixture, queued);
        }
    }
}

test "syscall failure receive payload preflight preserves copied and moved attachments" {
    const PayloadFailure = enum { invalid_pointer, short, readonly, unmapped_tail, end_overflow, noncanonical, oversized };
    for (std.enums.values(Transfer)) |transfer| {
        for (std.enums.values(PayloadFailure)) |failure| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const queued = try fixture.queueAttachedMessage(transfer);
            var request = fixture.receiveRequest(queued);
            switch (failure) {
                .invalid_pointer => request.payload_address = 0x1000,
                .short => request.payload_capacity -= 1,
                .readonly => fixture.restrictUserBytes(LABEL_OFFSET, endpoint.MAX_MESSAGE_BYTES, true),
                .unmapped_tail => fixture.restrictUserBytes(LABEL_OFFSET + endpoint.MAX_MESSAGE_BYTES - 1, 1, false),
                .end_overflow => request.payload_address = std.math.maxInt(u64) - endpoint.MAX_MESSAGE_BYTES + 1,
                .noncanonical => request.payload_address = 0x0000_8000_0000_0000,
                .oversized => request.payload_capacity += 1,
            }
            const request_addr = fixture.request(request);
            const before = try ReceiveSnapshot.capture(fixture, queued);
            const rejected = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
            try std.testing.expectEqual(if (failure == .short) abi.SyscallStatus.buffer_too_small else if (failure == .oversized) abi.SyscallStatus.invalid_request_pointer else abi.SyscallStatus.invalid_response_buffer, rejected.status);
            try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
            try before.expectPreserved(fixture, queued);
            try before.expectRetry(fixture, queued);
        }
    }
}

test "syscall failure receive capability preflight preserves copied and moved attachments" {
    const CapabilityFailure = enum { invalid_pointer, readonly, unmapped_tail, end_overflow, noncanonical, misaligned };
    for (std.enums.values(Transfer)) |transfer| {
        for (std.enums.values(CapabilityFailure)) |failure| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const queued = try fixture.queueAttachedMessage(transfer);
            var request = fixture.receiveRequest(queued);
            switch (failure) {
                .invalid_pointer => request.attached_capability_address = 0x1000,
                .readonly => fixture.restrictUserBytes(CAPABILITY_OFFSET, @sizeOf(abi.CapabilityDescriptor), true),
                .unmapped_tail => fixture.restrictUserBytes(CAPABILITY_OFFSET + @sizeOf(abi.CapabilityDescriptor) - 1, 1, false),
                .end_overflow => request.attached_capability_address = std.math.maxInt(u64) - @sizeOf(abi.CapabilityDescriptor) + 1,
                .noncanonical => request.attached_capability_address = 0xffff_8000_0000_0000,
                .misaligned => request.attached_capability_address += 1,
            }
            const request_addr = fixture.request(request);
            const before = try ReceiveSnapshot.capture(fixture, queued);
            const rejected = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
            try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, rejected.status);
            try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
            try before.expectPreserved(fixture, queued);
            try before.expectRetry(fixture, queued);
        }
    }
}

test "syscall failure malformed receive requests preserve copied and moved attachments" {
    const RequestFailure = enum { invalid_pointer, misaligned, unmapped_tail, end_overflow, foreign_receiver, foreign_subject, zero_subject, wrong_opcode, header_flags, reserved_low, reserved_high, oversized_capacity };
    for (std.enums.values(Transfer)) |transfer| {
        for (std.enums.values(RequestFailure)) |failure| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const queued = try fixture.queueAttachedMessage(transfer);
            var request = fixture.receiveRequest(queued);
            switch (failure) {
                .foreign_receiver => request.receiver_task_id += 1,
                .foreign_subject => request.header.subject_task_id += 1,
                .zero_subject => request.header.subject_task_id = 0,
                .wrong_opcode => request.header.operation = abi.opcode(.endpoint_send),
                .header_flags => request.header.flags = 1,
                .reserved_low => request.reserved = 1,
                .reserved_high => request.reserved = 0x8000_0000,
                .oversized_capacity => request.payload_capacity = std.math.maxInt(u32),
                else => {},
            }
            const staged_address = fixture.request(request);
            if (failure == .unmapped_tail) fixture.restrictUserBytes(@sizeOf(abi.EndpointRecvWireRequest) - 1, 1, false);
            const request_addr = switch (failure) {
                .invalid_pointer => 0x1000,
                .misaligned => staged_address + 1,
                .end_overflow => std.math.maxInt(usize) - @sizeOf(abi.EndpointRecvWireRequest) + 1,
                else => staged_address,
            };
            const before = try ReceiveSnapshot.capture(fixture, queued);
            const rejected = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
            try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, rejected.status);
            try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
            // Fixed-wire admission precedes even a short or invalid response;
            // otherwise generic output preparation would mask this rejection.
            const bad_output = fixture.call(.endpoint_recv, 12, request_addr, 0x1000, 0);
            try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, bad_output.status);
            try std.testing.expectEqual(@as(u32, 0), bad_output.bytes_written);
            try before.expectPreserved(fixture, queued);
            try before.expectRetry(fixture, queued);
        }
    }
}

test "syscall failure overlapping receive outputs preserve copied and moved attachments" {
    const Overlap = enum { primary_payload, primary_capability, payload_capability, advertised_primary_tail };
    for (std.enums.values(Transfer)) |transfer| {
        for (std.enums.values(Overlap)) |overlap| {
            const fixture = try Fixture.create();
            defer fixture.destroy();
            const queued = try fixture.queueAttachedMessage(transfer);
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
            var request = fixture.receiveRequest(queued);
            request.payload_address = payload_address;
            request.attached_capability_address = capability_address;
            const request_addr = fixture.request(request);
            const before = try ReceiveSnapshot.capture(fixture, queued);
            const rejected = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), if (overlap == .advertised_primary_tail) 128 else @sizeOf(abi.EndpointRecvResponse));
            try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, rejected.status);
            try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
            try before.expectPreserved(fixture, queued);
            try before.expectRetry(fixture, queued);
        }
    }
}

test "syscall failure receive snapshots the request before aliased payload writes" {
    for (std.enums.values(Transfer)) |transfer| {
        const fixture = try Fixture.create();
        defer fixture.destroy();
        const queued = try fixture.queueAttachedMessage(transfer);
        var request = fixture.receiveRequest(queued);
        request.payload_address = @intFromPtr(&fixture.user);
        const request_addr = fixture.request(request);
        const before = try ReceiveSnapshot.capture(fixture, queued);
        const result = fixture.call(.endpoint_recv, 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
        try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
        try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), result.bytes_written);
        const received = fixture.response(abi.EndpointRecvResponse);
        const expected = stagedPayload();
        try std.testing.expectEqualSlices(u8, &expected, fixture.user[0..expected.len]);
        try std.testing.expectEqual(@as(u8, 1), received.has_attached_capability);
        try std.testing.expectEqual(queued.endpoint_id, received.message.endpoint_id);
        try std.testing.expectEqual(@as(u64, 91), received.message.correlation_id);
        const attached = @as(*const abi.CapabilityDescriptor, @ptrFromInt(@intFromPtr(&fixture.user) + CAPABILITY_OFFSET)).*;
        try std.testing.expect(fixture.runtime.hasCapability(fixture.task_id, attached.capability_id));
        try std.testing.expectEqual(@as(u64, 43), attached.target_id);
        try std.testing.expectEqual(transfer == .copy, fixture.capabilities.query(queued.attached_capability_id) != null);
        try std.testing.expectEqual(transfer == .copy, fixture.runtime.hasCapability(fixture.task_id, queued.attached_capability_id));
        try std.testing.expectEqual(before.grants + @intFromBool(transfer == .copy), fixture.capabilities.activeCount());
        try std.testing.expectEqual(before.task_grants + 1, fixture.runtime.find(fixture.task_id).?.capabilityIds().len);
    }
}

test "syscall failure receive grant errors consume the record and dispose only moved attachments" {
    const GrantFailure = enum { task_full, table_full, expired };
    for ([_]bool{ false, true }) |unscoped| {
        for (std.enums.values(Transfer)) |transfer| {
            for (std.enums.values(GrantFailure)) |failure| {
                const fixture = try Fixture.create();
                defer fixture.destroy();
                const queued = try fixture.queueAttachedMessageWithScope(transfer, unscoped, null);
                const task = fixture.runtime.find(fixture.task_id).?;
                if (failure != .expired) {
                    const filler = capability.MintRequest{
                        .holder = task.owner,
                        .issuer = fixture.kernel.policy_authority,
                        .target = .{ .kind = .service, .id = 44 },
                        .rights = .{ .service = .{ .time_query = true } },
                        .scope = .{ .task_id = task.id, .local_only = true },
                        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
                    };
                    while (if (failure == .task_full) task.capability_count < task_runtime.MAX_TASK_CAPABILITIES else fixture.capabilities.activeCount() < capability.MAX_CAPABILITIES) {
                        const grant = try fixture.capabilities.mintBootRoot(filler);
                        if (failure == .task_full) try fixture.runtime.grantCapability(task.id, grant.id);
                    }
                }
                const request_addr = fixture.request(fixture.receiveRequest(queued));
                const before = try ReceiveSnapshot.capture(fixture, queued);
                const result = fixture.call(.endpoint_recv, if (failure == .expired) 101 else 12, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse));
                try std.testing.expectEqual(if (failure == .expired) abi.SyscallStatus.denied else abi.SyscallStatus.conflict, result.status);
                try std.testing.expectEqual(if (failure == .expired) abi.DenialReason.capability_revoked else abi.DenialReason.budget_exhausted, result.denial_reason);
                try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
                try std.testing.expectEqualSlices(u8, &before.user, &fixture.user);
                try std.testing.expectEqual(@as(u16, 0), (try fixture.endpoints.descriptor(ids.endpoint(queued.endpoint_id))).queued_messages);
                try std.testing.expect(!fixture.endpoints.hasPendingForTask(ids.task(fixture.task_id)));
                try std.testing.expectEqual(before.grants - @intFromBool(transfer == .move), fixture.capabilities.activeCount());
                try before.expectTaskPreserved(fixture);
                try std.testing.expectEqual(transfer == .copy, fixture.capabilities.query(queued.attached_capability_id) != null);
                try std.testing.expectEqual(transfer == .copy, fixture.runtime.hasCapability(fixture.task_id, queued.attached_capability_id));
                if (transfer == .copy) try std.testing.expectEqualDeep(before.attached, fixture.capabilities.query(queued.attached_capability_id).?);

                const grants_after = fixture.capabilities.activeCount();
                const generation_after = fixture.capabilities.mutationGeneration();
                try std.testing.expectEqual(abi.SyscallStatus.success, fixture.call(.endpoint_recv, 102, request_addr, fixture.responseAddress(), @sizeOf(abi.EndpointRecvResponse)).status);
                try std.testing.expectEqual(@as(u8, 0), fixture.response(abi.EndpointRecvResponse).present);
                try std.testing.expectEqual(@as(u8, 0), fixture.response(abi.EndpointRecvResponse).has_attached_capability);
                try std.testing.expectEqualSlices(u8, before.user[LABEL_OFFSET..][0..endpoint.MAX_MESSAGE_BYTES], fixture.user[LABEL_OFFSET..][0..endpoint.MAX_MESSAGE_BYTES]);
                try std.testing.expectEqualSlices(u8, before.user[CAPABILITY_OFFSET..][0..@sizeOf(abi.CapabilityDescriptor)], fixture.user[CAPABILITY_OFFSET..][0..@sizeOf(abi.CapabilityDescriptor)]);
                try std.testing.expectEqual(grants_after, fixture.capabilities.activeCount());
                try std.testing.expectEqual(generation_after, fixture.capabilities.mutationGeneration());
                try before.expectTaskPreserved(fixture);
            }
        }
    }
}
