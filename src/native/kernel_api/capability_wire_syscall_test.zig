const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const wire = @import("../core/capability_wire.zig");
const scalar = @import("capability_wire.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const shared_memory = @import("shared_memory.zig");
const surface = @import("syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");

const RESPONSE_OFFSET = 1024;
const Fixture = struct {
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    tasks: [3]*task_runtime.TaskRecord = undefined,
    policy_id: u64 = 0,
    parent_id: u64 = 0,
    user: [4096]u8 align(16) = @splat(0xa5),

    fn create(parent_expires: u64) !*Fixture {
        return createWithSharedHolder(parent_expires, false);
    }

    fn createWithSharedHolder(parent_expires: u64, shared_holder: bool) !*Fixture {
        const self = try std.testing.allocator.create(Fixture);
        self.* = .{};
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        errdefer self.destroy();
        self.port = .init(&self.kernel);
        for (&self.tasks, 0..) |*task, index| task.* = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = if (shared_holder and index == 2) 2 else 2 + index },
            .component_class = .session_manager,
            .budget = .{ .cpu_time_ticks = 10_000, .memory_bytes = 4096, .endpoint_slots = 1, .shared_memory_bytes = 4096 },
            .local_only = true,
        });
        const policy = try self.capabilities.mintBootRoot(.{
            .holder = self.tasks[0].owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .policy, .id = 1 },
            .rights = .{ .policy = .{ .capability_mint = true } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.policy_id = policy.id;
        const parent = try self.capabilities.mintBootRoot(.{
            .holder = self.tasks[0].owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{ .service = .{ .capability_derive = true, .capability_pass = true, .time_query = true } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = parent_expires },
        });
        self.parent_id = parent.id;
        try self.runtime.grantCapability(self.tasks[0].id, policy.id);
        try self.runtime.grantCapability(self.tasks[0].id, parent.id);
        for (self.tasks) |task| {
            const space = self.runtime.findAddressSpace(task.address_space_id).?;
            space.region_count = 1;
            space.regions[0] = .{ .kind = .load_segment, .virtual_address = @intFromPtr(&self.user), .size_bytes = self.user.len, .file_offset = 0, .file_size = 0, .access = .{ .read = true, .write = true } };
        }
        self.port.syscall_caller_task_id = 0xdead;
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.runtime.reset();
        self.endpoints.deinit();
        self.shared.deinit();
        self.kernel.deinit();
        std.testing.allocator.destroy(self);
    }

    fn stage(self: *Fixture, request: anytype) void {
        @memset(&self.user, 0xa5);
        const bytes = std.mem.asBytes(&request);
        @memcpy(self.user[0..bytes.len], bytes);
    }

    fn invoke(self: *Fixture, operation: abi.NativeOperation, caller: usize, now_ticks: u64) surface.DispatchResult {
        return surface.dispatch(&self.port, self.tasks[caller].id, now_ticks, abi.opcode(operation), @intFromPtr(&self.user), @intFromPtr(&self.user) + RESPONSE_OFFSET, @sizeOf(abi.CapabilityDescriptor));
    }

    fn response(self: *Fixture) abi.CapabilityDescriptor {
        return std.mem.bytesToValue(abi.CapabilityDescriptor, self.user[RESPONSE_OFFSET..][0..@sizeOf(abi.CapabilityDescriptor)]);
    }

    fn expectResponseExtent(self: *Fixture, before: *const [4096]u8) !void {
        const end = RESPONSE_OFFSET + @sizeOf(abi.CapabilityDescriptor);
        try std.testing.expectEqualSlices(u8, before[0..RESPONSE_OFFSET], self.user[0..RESPONSE_OFFSET]);
        try std.testing.expectEqualSlices(u8, before[end..], self.user[end..]);
        const received = self.response();
        try std.testing.expectEqual(@as(u32, 0), received._reserved_generation);
        try std.testing.expectEqual(@as(u32, 0), received._reserved_tail);
    }

    fn mint(self: *Fixture) abi.CapabilityMintWireRequest {
        var out: abi.CapabilityMintWireRequest = undefined;
        scalar.mintToWireInto(component_port.makeHeader(.capability_mint, self.tasks[0].id), self.policy_id, .{
            .holder = self.tasks[1].owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .object, .id = 77 },
            .rights = .{ .object = .{ .object_read = true } },
            .scope = .{ .task_id = self.tasks[1].id, .local_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 100 },
        }, &out);
        return out;
    }

    fn derive(self: *Fixture) abi.CapabilityDeriveWireRequest {
        var out: abi.CapabilityDeriveWireRequest = undefined;
        scalar.deriveToWireInto(component_port.makeHeader(.capability_derive, self.tasks[0].id), .{
            .parent_capability_id = self.parent_id,
            .holder = self.tasks[1].owner,
            .rights = .{ .service = .{ .time_query = true } },
            .scope = .{ .task_id = self.tasks[1].id, .local_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 40 },
        }, &out);
        return out;
    }

    fn produceUnscopedPassGrant(self: *Fixture) !capability.Capability {
        const boot = try self.capabilities.mintBootRoot(.{
            .holder = .{ .kind = .service, .serial = 90 },
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 43 },
            .rights = .{ .service = .{ .capability_pass = true, .capability_revoke = true, .time_query = true } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 1000 },
        });
        // A trusted caller-zero copy pass produces a live task attachment
        // through the normal Kernel path, without inventing scoped authority.
        const received = try self.kernel.capabilityPass(.{
            .caller_task_id = 0,
            .presented_capability_id = boot.id,
            .target = .none,
        }, self.tasks[0].id, 20, false);
        try std.testing.expectEqualDeep(boot, self.capabilities.query(boot.id).?);
        const grant = self.capabilities.query(received.capability_id).?;
        try std.testing.expectEqual(@as(?u64, null), grant.scope.task_id);
        try std.testing.expect(grant.holder.eql(self.tasks[0].owner));
        try std.testing.expect(self.tasks[0].hasCapability(grant.id));
        try std.testing.expect(self.tasks[0].owner.eql(self.tasks[2].owner));
        try self.runtime.grantCapability(self.tasks[2].id, grant.id);
        return grant;
    }

    fn fillAttachments(self: *Fixture, task: *task_runtime.TaskRecord) !void {
        while (task.capability_count < task_runtime.MAX_TASK_CAPABILITIES) {
            const grant = try self.mintQuotaGrant(task);
            try self.runtime.grantCapability(task.id, grant.id);
        }
    }

    fn mintQuotaGrant(self: *Fixture, task: *const task_runtime.TaskRecord) !capability.Capability {
        return self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 100 + task.id },
            .rights = .{ .service = .{ .time_query = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 1000 },
        });
    }
};

const Snapshot = struct {
    user: [4096]u8,
    capabilities: capability.CapabilityTable,
    tasks: [3]task_runtime.TaskRecord,
    attachments: [3][task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(@splat(0)),
    cspace_slots: [3][task_runtime.MAX_TASK_CAPABILITIES]?u8 = @splat(@splat(null)),
    cspace_ids: [3][task_runtime.MAX_TASK_CAPABILITIES]?u64 = @splat(@splat(null)),
    capability_generations: [3]u64 = undefined,

    fn capture(fixture: *Fixture) Snapshot {
        var out = Snapshot{ .user = fixture.user, .capabilities = fixture.capabilities, .tasks = undefined };
        for (fixture.tasks, 0..) |task, index| {
            out.tasks[index] = task.*;
            @memcpy(out.attachments[index][0..task.capability_count], task.capabilityIds());
            for (task.capabilityIds(), 0..) |id, slot| out.cspace_slots[index][slot] = task_runtime.cspaceSlotForCapability(task, id);
            out.capability_generations[index] = task.capabilityGeneration();
            for (&out.cspace_ids[index], 0..) |*id, slot| id.* = task_runtime.capabilityIdAtCspaceSlot(task, @intCast(slot));
        }
        return out;
    }

    fn expectPreserved(self: *const Snapshot, fixture: *Fixture) !void {
        // Compare initialized semantic fields, not representation padding.
        try std.testing.expectEqualSlices(u8, &self.user, &fixture.user);
        try std.testing.expectEqualDeep(self.capabilities, fixture.capabilities);
        for (fixture.tasks, 0..) |task, index| {
            try std.testing.expectEqualDeep(self.tasks[index], task.*);
            try std.testing.expectEqual(self.capability_generations[index], task.capabilityGeneration());
            try std.testing.expectEqualSlices(u64, self.attachments[index][0..task.capability_count], task.capabilityIds());
            for (task.capabilityIds(), 0..) |id, slot| try std.testing.expectEqual(self.cspace_slots[index][slot], task_runtime.cspaceSlotForCapability(task, id));
            for (self.cspace_ids[index], 0..) |id, slot| try std.testing.expectEqual(id, task_runtime.capabilityIdAtCspaceSlot(task, @intCast(slot)));
        }
        try std.testing.expectEqual(@as(u64, 0xdead), fixture.port.syscall_caller_task_id);
    }

    fn expectOtherAttachmentsPreserved(self: *const Snapshot, fixture: *Fixture, removed_id: u64) !void {
        for (fixture.tasks, 0..) |task, index| {
            for (self.attachments[index][0..self.tasks[index].capability_count], 0..) |id, dense| {
                if (id == removed_id) continue;
                const slot = self.cspace_slots[index][dense].?;
                try std.testing.expect(task.hasCapability(id));
                try std.testing.expectEqual(@as(?u8, slot), task_runtime.cspaceSlotForCapability(task, id));
                try std.testing.expectEqual(@as(?u64, id), task_runtime.capabilityIdAtCspaceSlot(task, slot));
                try std.testing.expectEqualDeep(self.capabilities.query(id), fixture.capabilities.query(id));
            }
        }
    }
};

test "capability scalar Surface mint rejects malformed encodings without grant or user output mutation" {
    const fixture = try Fixture.create(1000);
    defer fixture.destroy();
    const valid = fixture.mint();
    inline for (.{ "holder_kind", "issuer_kind", "target_kind", "rights_kind", "reserved", "flags", "scope_flags", "rights_bits" }) |field| {
        var bad = valid;
        @field(bad, field) = if (comptime std.mem.endsWith(u8, field, "kind")) 255 else if (comptime std.mem.eql(u8, field, "rights_bits")) @as(u64, 1) << 63 else 0x8000;
        fixture.stage(bad);
        const before = Snapshot.capture(fixture);
        const result = fixture.invoke(.capability_mint, 0, 20);
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, result.status);
        try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
        try before.expectPreserved(fixture);
    }
    var absent = valid;
    absent.scope_flags &= ~wire.SCOPE_TASK_PRESENT;
    fixture.stage(absent);
    const absent_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_mint, 0, 20).status);
    try absent_before.expectPreserved(fixture);
    inline for (.{ "flags", "reserved" }) |field| {
        var bad = valid;
        @field(bad.header, field) = 1;
        fixture.stage(bad);
        const before = Snapshot.capture(fixture);
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_mint, 0, 20).status);
        try before.expectPreserved(fixture);
        bad.header.operation = abi.opcode(.capability_pass);
        fixture.stage(bad);
        const wrong_operation = Snapshot.capture(fixture);
        try std.testing.expectEqual(abi.SyscallStatus.unsupported_operation, fixture.invoke(.capability_mint, 0, 20).status);
        try wrong_operation.expectPreserved(fixture);
    }
    fixture.stage(valid);
    const foreign_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_mint, 2, 20).status);
    try foreign_before.expectPreserved(fixture);
    const count = fixture.capabilities.activeCount();
    const received_before = fixture.tasks[1].capability_count;
    const user_before = fixture.user;
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_mint, 0, 20).status);
    const received = fixture.response();
    try fixture.expectResponseExtent(&user_before);
    try std.testing.expect(fixture.tasks[1].hasCapability(received.capability_id));
    try std.testing.expectEqual(@as(u64, 77), received.target_id);
    try std.testing.expectEqual(valid.rights_bits, received.rights);
    try std.testing.expectEqual(fixture.tasks[1].id, received.scope_task_id);
    try std.testing.expectEqual(count + 1, fixture.capabilities.activeCount());
    try std.testing.expectEqual(received_before + 1, fixture.tasks[1].capability_count);
}

test "capability scalar Surface derive rejects forged representation and expired parent at trusted time atomically" {
    const fixture = try Fixture.create(50);
    defer fixture.destroy();
    const valid = fixture.derive();
    inline for (.{ "holder_kind", "rights_kind", "reserved", "flags", "scope_flags", "rights_bits" }) |field| {
        var bad = valid;
        @field(bad, field) = if (comptime std.mem.endsWith(u8, field, "kind")) 255 else if (comptime std.mem.eql(u8, field, "rights_bits")) @as(u64, 1) << 63 else 0x8000;
        fixture.stage(bad);
        const before = Snapshot.capture(fixture);
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_derive, 0, 20).status);
        try before.expectPreserved(fixture);
    }
    fixture.stage(valid);
    const before = Snapshot.capture(fixture);
    for ([_]u64{ 9, 51, 100 }) |tick| {
        const rejected = fixture.invoke(.capability_derive, 0, tick);
        try std.testing.expectEqual(abi.SyscallStatus.denied, rejected.status);
        try std.testing.expectEqual(abi.DenialReason.capability_revoked, rejected.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), rejected.bytes_written);
        try before.expectPreserved(fixture);
    }
    const count = fixture.capabilities.activeCount();
    const user_before = fixture.user;
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_derive, 0, 20).status);
    const received = fixture.response();
    try fixture.expectResponseExtent(&user_before);
    try std.testing.expect(fixture.tasks[1].hasCapability(received.capability_id));
    try std.testing.expect(fixture.tasks[0].hasCapability(fixture.parent_id));
    try std.testing.expectEqual(count + 1, fixture.capabilities.activeCount());
}

test "capability scalar Surface pass rejects unknown flags and moves exactly once after valid retry" {
    const fixture = try Fixture.create(1000);
    defer fixture.destroy();
    const moving = try fixture.capabilities.mintBootRoot(.{
        .holder = fixture.tasks[0].owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 43 },
        .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
        .scope = .{ .task_id = fixture.tasks[0].id, .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 1000 },
    });
    try fixture.runtime.grantCapability(fixture.tasks[0].id, moving.id);
    var valid: abi.CapabilityPassWireRequest = undefined;
    scalar.passToWireInto(component_port.makeHeader(.capability_pass, fixture.tasks[0].id), moving.id, fixture.tasks[1].id, true, &valid);
    inline for (.{ "flags", "reserved" }) |field| {
        var bad = valid;
        @field(bad, field) = 2;
        fixture.stage(bad);
        const before = Snapshot.capture(fixture);
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_pass, 0, 20).status);
        try before.expectPreserved(fixture);
    }
    fixture.stage(valid);
    const foreign_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_pass, 2, 20).status);
    try foreign_before.expectPreserved(fixture);
    const count = fixture.capabilities.activeCount();
    const user_before = fixture.user;
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_pass, 0, 20).status);
    const received = fixture.response();
    try fixture.expectResponseExtent(&user_before);
    try std.testing.expect(fixture.capabilities.query(moving.id) == null);
    try std.testing.expect(!fixture.tasks[0].hasCapability(moving.id));
    try std.testing.expect(fixture.tasks[1].hasCapability(received.capability_id));
    try std.testing.expectEqual(count, fixture.capabilities.activeCount());
    fixture.stage(valid);
    const moved_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_pass, 0, 20).status);
    try moved_before.expectPreserved(fixture);
}

test "capability scalar Surface unscoped move retires every attachment and reuses full Cspace quotas" {
    const fixture = try Fixture.createWithSharedHolder(1000, true);
    defer fixture.destroy();
    const moving = try fixture.produceUnscopedPassGrant();
    const source_indices = [_]usize{ 0, 2 };
    var old_slots: [2]u8 = undefined;
    var replacements: [2]capability.Capability = undefined;
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        old_slots[source] = task_runtime.cspaceSlotForCapability(task, moving.id).?;
        try fixture.fillAttachments(task);
        replacements[source] = try fixture.mintQuotaGrant(task);
        try std.testing.expectError(error.CapabilityTableFull, fixture.runtime.grantCapability(task.id, replacements[source].id));
        try std.testing.expectEqual(task_runtime.MAX_TASK_CAPABILITIES, task.capability_count);
    }

    var valid: abi.CapabilityPassWireRequest = undefined;
    scalar.passToWireInto(component_port.makeHeader(.capability_pass, fixture.tasks[0].id), moving.id, fixture.tasks[1].id, true, &valid);
    inline for (.{ "flags", "reserved" }) |field| {
        var bad = valid;
        @field(bad, field) = 2;
        fixture.stage(bad);
        const before = Snapshot.capture(fixture);
        try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_pass, 0, 20).status);
        try before.expectPreserved(fixture);
    }
    fixture.stage(valid);
    const foreign_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_pass, 1, 20).status);
    try foreign_before.expectPreserved(fixture);
    var bad_receiver = valid;
    bad_receiver.receiver_task_id = std.math.maxInt(u64);
    fixture.stage(bad_receiver);
    const receiver_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_pass, 0, 20).status);
    try receiver_before.expectPreserved(fixture);

    fixture.stage(valid);
    const before = Snapshot.capture(fixture);
    const result = fixture.invoke(.capability_pass, 0, 20);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.CapabilityDescriptor)), result.bytes_written);
    try fixture.expectResponseExtent(&before.user);
    const received = fixture.response();
    const passed = fixture.capabilities.query(received.capability_id).?;
    try std.testing.expect(passed.id != moving.id);
    try std.testing.expect(passed.holder.eql(fixture.tasks[1].owner));
    try std.testing.expectEqualDeep(moving.target, passed.target);
    try std.testing.expectEqualDeep(moving.rights, passed.rights);
    try std.testing.expectEqualDeep(moving.scope, passed.scope);
    try std.testing.expectEqualDeep(moving.lease, passed.lease);
    try std.testing.expect(fixture.capabilities.query(moving.id) == null);
    try std.testing.expectEqual(before.capabilities.activeCount(), fixture.capabilities.activeCount());
    try before.expectOtherAttachmentsPreserved(fixture, moving.id);
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        try std.testing.expect(!task.hasCapability(moving.id));
        try std.testing.expectEqual(@as(?u8, null), task_runtime.cspaceSlotForCapability(task, moving.id));
        try std.testing.expectEqual(@as(?u64, null), task_runtime.capabilityIdAtCspaceSlot(task, old_slots[source]));
        try std.testing.expectEqual(before.tasks[index].capability_count - 1, task.capability_count);
        try std.testing.expectEqual(before.capability_generations[index] + 1, task.capabilityGeneration());
    }
    try std.testing.expect(fixture.tasks[1].hasCapability(passed.id));
    try std.testing.expectEqual(before.tasks[1].capability_count + 1, fixture.tasks[1].capability_count);
    try std.testing.expectEqual(before.capability_generations[1] + 1, fixture.tasks[1].capabilityGeneration());

    fixture.stage(valid);
    const moved_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_pass, 0, 20).status);
    try moved_before.expectPreserved(fixture);
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        try fixture.runtime.grantCapability(task.id, replacements[source].id);
        try std.testing.expectEqual(task_runtime.MAX_TASK_CAPABILITIES, task.capability_count);
        try std.testing.expectEqual(@as(?u8, old_slots[source]), task_runtime.cspaceSlotForCapability(task, replacements[source].id));
        try std.testing.expectEqual(@as(?u64, replacements[source].id), task_runtime.capabilityIdAtCspaceSlot(task, old_slots[source]));
    }
}

test "capability scalar Surface unscoped copy preserves shared source attachments and self move retains its new grant" {
    const fixture = try Fixture.createWithSharedHolder(1000, true);
    defer fixture.destroy();
    const original = try fixture.produceUnscopedPassGrant();
    var copying: abi.CapabilityPassWireRequest = undefined;
    scalar.passToWireInto(component_port.makeHeader(.capability_pass, fixture.tasks[0].id), original.id, fixture.tasks[1].id, false, &copying);
    fixture.stage(copying);
    const before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_pass, 0, 20).status);
    try fixture.expectResponseExtent(&before.user);
    const copied = fixture.capabilities.query(fixture.response().capability_id).?;
    try std.testing.expect(copied.id != original.id);
    try std.testing.expect(copied.holder.eql(fixture.tasks[1].owner));
    try std.testing.expectEqualDeep(original.scope, copied.scope);
    try std.testing.expectEqualDeep(original, fixture.capabilities.query(original.id).?);
    try before.expectOtherAttachmentsPreserved(fixture, 0);
    for ([_]usize{ 0, 2 }) |index| {
        try std.testing.expectEqualDeep(before.tasks[index], fixture.tasks[index].*);
        try std.testing.expectEqual(before.capability_generations[index], fixture.tasks[index].capabilityGeneration());
    }
    try std.testing.expectEqual(before.capabilities.activeCount() + 1, fixture.capabilities.activeCount());
    try std.testing.expectEqual(before.tasks[1].capability_count + 1, fixture.tasks[1].capability_count);
    try std.testing.expectEqual(before.capability_generations[1] + 1, fixture.tasks[1].capabilityGeneration());

    var self_move: abi.CapabilityPassWireRequest = undefined;
    scalar.passToWireInto(component_port.makeHeader(.capability_pass, fixture.tasks[1].id), copied.id, fixture.tasks[1].id, true, &self_move);
    fixture.stage(self_move);
    const self_before = Snapshot.capture(fixture);
    const old_slot = task_runtime.cspaceSlotForCapability(fixture.tasks[1], copied.id).?;
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_pass, 1, 20).status);
    try fixture.expectResponseExtent(&self_before.user);
    const moved = fixture.capabilities.query(fixture.response().capability_id).?;
    try std.testing.expect(moved.id != copied.id);
    try std.testing.expect(moved.holder.eql(fixture.tasks[1].owner));
    try std.testing.expect(fixture.capabilities.query(copied.id) == null);
    try std.testing.expect(!fixture.tasks[1].hasCapability(copied.id));
    try std.testing.expectEqual(@as(?u64, null), task_runtime.capabilityIdAtCspaceSlot(fixture.tasks[1], old_slot));
    try std.testing.expect(fixture.tasks[1].hasCapability(moved.id));
    try std.testing.expectEqual(self_before.tasks[1].capability_count, fixture.tasks[1].capability_count);
    try std.testing.expectEqual(self_before.capability_generations[1] + 2, fixture.tasks[1].capabilityGeneration());
    try std.testing.expectEqual(self_before.capabilities.activeCount(), fixture.capabilities.activeCount());
    try self_before.expectOtherAttachmentsPreserved(fixture, copied.id);
    for ([_]usize{ 0, 2 }) |index| {
        try std.testing.expectEqualDeep(self_before.tasks[index], fixture.tasks[index].*);
        try std.testing.expectEqual(self_before.capability_generations[index], fixture.tasks[index].capabilityGeneration());
    }
}

test "capability scalar Surface unscoped revoke detaches its exact ID while retaining unusable sibling tombstones" {
    const fixture = try Fixture.createWithSharedHolder(1000, true);
    defer fixture.destroy();
    const revoking = try fixture.produceUnscopedPassGrant();
    var copy: abi.CapabilityPassWireRequest = undefined;
    scalar.passToWireInto(component_port.makeHeader(.capability_pass, fixture.tasks[0].id), revoking.id, fixture.tasks[1].id, false, &copy);
    fixture.stage(copy);
    try std.testing.expectEqual(abi.SyscallStatus.success, fixture.invoke(.capability_pass, 0, 20).status);
    const sibling = fixture.capabilities.query(fixture.response().capability_id).?;
    try std.testing.expectEqualDeep(revoking.target, sibling.target);

    const source_indices = [_]usize{ 0, 2 };
    var old_slots: [2]u8 = undefined;
    var replacements: [2]capability.Capability = undefined;
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        old_slots[source] = task_runtime.cspaceSlotForCapability(task, revoking.id).?;
        try fixture.fillAttachments(task);
        replacements[source] = try fixture.mintQuotaGrant(task);
        try std.testing.expectError(error.CapabilityTableFull, fixture.runtime.grantCapability(task.id, replacements[source].id));
    }
    const valid = abi.CapabilityRevokeWireRequest{
        .header = component_port.makeHeader(.capability_revoke, fixture.tasks[0].id),
        .authority_capability_id = revoking.id,
        .capability_id = revoking.id,
    };
    var malformed = valid;
    malformed.header.flags = 1;
    fixture.stage(malformed);
    const malformed_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, fixture.invoke(.capability_revoke, 0, 20).status);
    try malformed_before.expectPreserved(fixture);
    fixture.stage(valid);
    const foreign_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_revoke, 1, 20).status);
    try foreign_before.expectPreserved(fixture);

    fixture.stage(valid);
    const before = Snapshot.capture(fixture);
    const result = fixture.invoke(.capability_revoke, 0, 20);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
    try std.testing.expectEqualSlices(u8, &before.user, &fixture.user);
    try std.testing.expect(fixture.capabilities.query(revoking.id) == null);
    try std.testing.expectEqual(before.capabilities.activeCount() - 1, fixture.capabilities.activeCount());
    try before.expectOtherAttachmentsPreserved(fixture, revoking.id);
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        try std.testing.expect(!task.hasCapability(revoking.id));
        try std.testing.expectEqual(@as(?u8, null), task_runtime.cspaceSlotForCapability(task, revoking.id));
        try std.testing.expectEqual(@as(?u64, null), task_runtime.capabilityIdAtCspaceSlot(task, old_slots[source]));
        try std.testing.expectEqual(before.tasks[index].capability_count - 1, task.capability_count);
        try std.testing.expectEqual(before.capability_generations[index] + 1, task.capabilityGeneration());
    }
    try std.testing.expectEqualDeep(sibling, fixture.capabilities.query(sibling.id).?);
    try std.testing.expectError(error.CapabilityRevoked, fixture.capabilities.resolveUsable(sibling.id, 20));
    try std.testing.expectEqualDeep(before.tasks[1], fixture.tasks[1].*);
    try std.testing.expectEqual(before.capability_generations[1], fixture.tasks[1].capabilityGeneration());

    fixture.stage(valid);
    const revoked_before = Snapshot.capture(fixture);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, fixture.invoke(.capability_revoke, 0, 20).status);
    try revoked_before.expectPreserved(fixture);
    // The sibling remains allocated and attached, but its old target epoch
    // cannot authorize an ordinary scalar syscall after revocation.
    fixture.stage(abi.TimeQueryWireRequest{
        .header = component_port.makeHeader(.time_query, fixture.tasks[1].id),
        .authority_capability_id = sibling.id,
    });
    const sibling_before = Snapshot.capture(fixture);
    const denied = fixture.invoke(.time_query, 1, 20);
    try std.testing.expectEqual(abi.SyscallStatus.denied, denied.status);
    try std.testing.expectEqual(abi.DenialReason.capability_revoked, denied.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), denied.bytes_written);
    try sibling_before.expectPreserved(fixture);
    for (source_indices, 0..) |index, source| {
        const task = fixture.tasks[index];
        try fixture.runtime.grantCapability(task.id, replacements[source].id);
        try std.testing.expectEqual(task_runtime.MAX_TASK_CAPABILITIES, task.capability_count);
        try std.testing.expectEqual(@as(?u8, old_slots[source]), task_runtime.cspaceSlotForCapability(task, replacements[source].id));
        try std.testing.expectEqual(@as(?u64, replacements[source].id), task_runtime.capabilityIdAtCspaceSlot(task, old_slots[source]));
    }
}
