// Hosted software-path fixture. No hardware syscall entry is replaced here.
const std = @import("std");
const builtin = @import("builtin");
const abi = @import("native/core/abi.zig");
const ids = @import("native/core/ids.zig");
const capability = @import("native/kernel_api/capability.zig");
const capability_wire = @import("native/kernel_api/capability_wire.zig");
const capability_wire_schema = @import("native/core/capability_wire.zig");
const component_port = @import("native/kernel_api/component_port.zig");
const endpoint = @import("native/kernel_api/endpoint.zig");
const descriptors = @import("native/kernel_api/native_kernel_descriptors.zig");
const native_kernel = @import("native/kernel_api/native_kernel.zig");
const shared_memory = @import("native/kernel_api/shared_memory.zig");
const surface = @import("native/kernel_api/syscall_surface.zig");
const task_runtime = @import("native/task/task_runtime.zig");

comptime {
    if (builtin.target.os.tag == .freestanding) @compileError("this fixture measures hosted dispatch only");
}

pub const Workload = enum {
    time_query,
    capability_query,
    resource_query,
    accounting_query,
    endpoint_pair_0,
    endpoint_pair_17,
    endpoint_pair_88,
    endpoint_prefilled_pair_0,
    endpoint_prefilled_pair_17,
    endpoint_prefilled_pair_88,
    capability_mint_revoke_pair,
    capability_mint_move_revoke_cycle,
    shared_memory_map_unmap_pair,

    pub fn payloadBytes(self: Workload) ?usize {
        return switch (self) {
            .endpoint_pair_0, .endpoint_prefilled_pair_0 => 0,
            .endpoint_pair_17, .endpoint_prefilled_pair_17 => 17,
            .endpoint_pair_88, .endpoint_prefilled_pair_88 => 88,
            else => null,
        };
    }

    fn payloadPrefilled(self: Workload) bool {
        return switch (self) {
            .endpoint_prefilled_pair_0, .endpoint_prefilled_pair_17, .endpoint_prefilled_pair_88 => true,
            else => false,
        };
    }

    pub fn dispatchesPerIteration(self: Workload) u64 {
        return if (self.payloadBytes() != null) 2 else switch (self) {
            .capability_mint_revoke_pair, .shared_memory_map_unmap_pair => 2,
            .capability_mint_move_revoke_cycle => 3,
            else => 1,
        };
    }

    pub fn iterationsPerSample(self: Workload, requested: usize) usize {
        // Hosted mapping metadata advances the ordinary virtual cursor even
        // after unmap. A fresh fixture per sample stays within its 256 MiB
        // aperture, including untimed verification and warmup, without resets.
        return if (self == .shared_memory_map_unmap_pair) @min(requested, 50_000) else requested;
    }

    fn capabilityLifecycle(self: Workload) bool {
        return self == .capability_mint_revoke_pair or self == .capability_mint_move_revoke_cycle;
    }
};

pub const Strategy = enum { compact, explicit_detailed };

pub fn abiVersion() u16 {
    return abi.ABI_VERSION;
}

const REQUEST_OFFSET = 0;
const RESPONSE_OFFSET = 1024;
const PAYLOAD_OFFSET = 2048;
const CAPABILITY_OFFSET = 3072;
const CANARY: u8 = 0xa5;
const UserPage = struct { bytes: [4096]u8 align(4096) = @splat(CANARY) };
const TaskBaseline = struct {
    state: task_runtime.TaskState,
    budget: task_runtime.ResourceBudget,
    capabilities: u8,
    audits: u8,
};

// The Kernel's retirement callback retains this address until destroy().
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    pages: [2]UserPage = .{ .{}, .{} },
    task_ids: [2]u64 = @splat(0),
    authority_ids: [2]u64 = @splat(0),
    endpoint_ids: [2]u64 = @splat(0),
    endpoint_capabilities: [2]u64 = @splat(0),
    policy_capabilities: [2]u64 = @splat(0),
    shared_object_ids: [2]u64 = @splat(0),
    shared_capabilities: [2]u64 = @splat(0),
    shared_descriptors: [2]abi.SharedMemoryDescriptor = undefined,
    last_retired_capabilities: [2]u64 = @splat(0),
    completed_lifecycles: u64 = 0,
    expected_capabilities: [2]abi.CapabilityDescriptor = undefined,
    expected_resources: [2]abi.ResourceDescriptor = undefined,
    expected_accounting: [2]abi.AccountingDescriptor = undefined,
    task_baselines: [2]TaskBaseline = undefined,
    expected_port: component_port.KernelPort = undefined,
    grant_count: usize = 0,
    grant_generation: u64 = 0,
    detailed: surface.DetailedResult = undefined,

    pub fn create(allocator: std.mem.Allocator, comptime workload: Workload) !*Fixture {
        const self = try allocator.create(Fixture);
        self.* = .{ .allocator = allocator };
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        errdefer self.destroy();
        for (0..2) |index| {
            const task = try self.runtime.createTask(.{
                .owner = .{ .kind = .service, .serial = 2 + index },
                .component_class = .session_manager,
                .budget = .{ .cpu_time_ticks = 10_000 + index, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 4096 },
                .local_only = true,
            });
            self.task_ids[index] = task.id;
            const space = self.runtime.findAddressSpace(task.address_space_id) orelse return error.MissingAddressSpace;
            space.region_count = 1;
            space.regions[0] = .{
                .kind = .load_segment,
                .virtual_address = self.address(index, 0),
                .size_bytes = self.pages[index].bytes.len,
                .file_offset = 0,
                .file_size = 0,
                .access = .{ .read = true, .write = true },
            };
            const granted = try self.capabilities.mintBootRoot(.{
                .holder = task.owner,
                .issuer = self.kernel.policy_authority,
                .target = .{ .kind = .service, .id = 42 },
                .rights = .{ .service = .{
                    .time_query = true,
                    .capability_query = true,
                    .resource_query = true,
                    .accounting_query = true,
                    .endpoint_create = true,
                    .shared_memory_create = workload == .shared_memory_map_unmap_pair,
                } },
                .scope = .{ .task_id = task.id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
            });
            self.authority_ids[index] = granted.id;
            try self.runtime.grantCapability(task.id, granted.id);
            self.expected_capabilities[index] = descriptors.capabilityDescriptor(&granted);
            if (workload.capabilityLifecycle()) {
                const policy = try self.capabilities.mintBootRoot(.{
                    .holder = task.owner,
                    .issuer = self.kernel.policy_authority,
                    .target = .{ .kind = .policy, .id = 100 + index },
                    .rights = .{ .policy = .{ .capability_mint = true } },
                    .scope = .{ .task_id = task.id, .local_only = true },
                    .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
                });
                self.policy_capabilities[index] = policy.id;
                try self.runtime.grantCapability(task.id, policy.id);
            }
            if (workload == .shared_memory_map_unmap_pair) {
                var setup_port = self.port;
                setup_port.syscall_caller_task_id = task.id;
                const created = try setup_port.sharedMemoryCreate(.{
                    .header = component_port.makeHeader(.shared_memory_create, task.id),
                    .authority_capability_id = granted.id,
                    .owner_task_id = task.id,
                    .size_bytes = 4096,
                }, 1);
                self.shared_object_ids[index] = created.object.object_id;
                self.shared_capabilities[index] = created.capability_id;
                self.shared_descriptors[index] = created.object;
            }
            if (workload.payloadBytes() != null) {
                // Trusted setup is outside clocks; measured send/receive still
                // go through the ordinary scalar Surface and real authority.
                var setup_port = self.port;
                setup_port.syscall_caller_task_id = task.id;
                const created = try setup_port.endpointCreate(.{
                    .header = component_port.makeHeader(.endpoint_create, task.id),
                    .authority_capability_id = granted.id,
                    .owner_task_id = task.id,
                    .label = if (index == 0) "benchmark-left" else "benchmark-right",
                    .flags = .{ .local_only = true },
                }, 1);
                self.endpoint_ids[index] = created.endpoint.endpoint_id;
                self.endpoint_capabilities[index] = created.capability_id;
            }
        }
        if (workload.payloadBytes() != null) try self.endpoints.connect(ids.endpoint(self.endpoint_ids[0]), ids.endpoint(self.endpoint_ids[1]));
        self.port.syscall_caller_task_id = 0xfedcba98;
        self.expected_port = self.port;
        for (0..2) |index| {
            const task = self.runtime.find(self.task_ids[index]).?;
            self.expected_resources[index] = .{
                .task_id = task.id,
                .state = @backingInt(task.state),
                .capability_count = task.capability_count,
                .endpoint_count = if (workload.payloadBytes() != null) 1 else 0,
                .flags = descriptors.taskFlags(task),
                .cpu_time_ticks = task.budget.cpu_time_ticks,
                .memory_bytes = task.budget.memory_bytes,
                .shared_memory_bytes = task.budget.shared_memory_bytes,
            };
            self.expected_accounting[index] = .{
                .task_id = task.id,
                .audit_event_count = task.audit_count,
                .capability_count = task.capability_count,
                .component_count = task.execution_component_count,
                .endpoint_count = if (workload.payloadBytes() != null) 1 else 0,
                .shared_memory_mappings = 0,
                .ui_surface_id = task.ui_surface_id orelse 0,
            };
            self.task_baselines[index] = .{ .state = task.state, .budget = task.budget, .capabilities = task.capability_count, .audits = task.audit_count };
            self.stageRequests(workload, index);
        }
        self.grant_count = self.capabilities.activeCount();
        self.grant_generation = self.capabilities.mutationGeneration();
        return self;
    }

    pub fn destroy(self: *Fixture) void {
        const allocator = self.allocator;
        self.runtime.reset();
        self.endpoints.deinit();
        self.shared.deinit();
        self.kernel.deinit();
        allocator.destroy(self);
    }

    pub fn opaqueSeed(self: *Fixture) u64 {
        std.mem.doNotOptimizeAway(self);
        return (@as(u64, @intFromPtr(self)) >> 12) ^ 0x9e3779b97f4a7c15;
    }

    pub fn checkStable(self: *Fixture, comptime workload: Workload) !void {
        const expected_generation = self.grant_generation +% (self.completed_lifecycles *% (if (workload == .capability_mint_move_revoke_cycle) @as(u64, 4) else 2));
        if (self.runtime.taskCount() != 2 or self.capabilities.activeCount() != self.grant_count or
            self.capabilities.mutationGeneration() != expected_generation or !std.meta.eql(self.port, self.expected_port) or
            self.endpoints.activeCount() != (if (workload.payloadBytes() != null) @as(usize, 2) else 0) or
            self.shared.activeCount() != (if (workload == .shared_memory_map_unmap_pair) @as(usize, 2) else 0)) return error.FixtureMutation;
        for (0..2) |index| {
            const task = self.runtime.find(self.task_ids[index]) orelse return error.MissingTask;
            const baseline = self.task_baselines[index];
            if (task.state != baseline.state or !std.meta.eql(task.budget, baseline.budget) or
                task.capability_count != baseline.capabilities or task.audit_count != baseline.audits or
                !task.hasCapability(self.authority_ids[index]) or self.endpoints.hasPendingForTask(ids.task(task.id))) return error.FixtureMutation;
            if (workload.capabilityLifecycle() and !task.hasCapability(self.policy_capabilities[index])) return error.FixtureMutation;
            if (workload == .shared_memory_map_unmap_pair and
                (!task.hasCapability(self.shared_capabilities[index]) or self.shared.mappingsForTask(ids.task(task.id)) != 0 or
                    !std.meta.eql(try self.shared.descriptor(ids.sharedMemory(self.shared_object_ids[index])), self.shared_descriptors[index]))) return error.FixtureMutation;
            for (self.last_retired_capabilities) |retired| {
                if (retired != 0 and (task.hasCapability(retired) or self.capabilities.query(retired) != null)) return error.FixtureMutation;
            }
        }
    }

    // Untimed: compare all named wire fields (including explicit reserved
    // bytes), every payload byte, and all successful detailed defaults.
    pub fn verify(self: *Fixture, comptime workload: Workload, seed: u64) !void {
        for (0..32) |index| {
            const input = inputFor(seed, index);
            const compact = try self.run(workload, .compact, true, input);
            const detailed = try self.run(workload, .explicit_detailed, true, input);
            if (compact != detailed) return error.ChecksumMismatch;
        }
        try self.checkStable(workload);
        if (workload.dispatchesPerIteration() == 1) try self.verifyRejectedQueries(workload);
    }

    pub fn verifyAfterSample(self: *Fixture, comptime workload: Workload, comptime strategy: Strategy, input: u64) !void {
        _ = try self.run(workload, strategy, true, input);
        try self.checkStable(workload);
    }

    // Equal outer call shape. The timed path checks scalar success and consumes
    // representative output fields; full-output barriers keep every copy live.
    pub noinline fn iteration(self: *Fixture, comptime workload: Workload, comptime strategy: Strategy, input: u64) !u64 {
        std.mem.doNotOptimizeAway(self);
        std.mem.doNotOptimizeAway(input);
        return self.run(workload, strategy, false, input);
    }

    fn run(self: *Fixture, comptime workload: Workload, comptime strategy: Strategy, comptime check_full: bool, input: u64) !u64 {
        const selected: usize = @intCast(input & 1);
        const ticks = 1 + (input >> 17);
        if (comptime workload.capabilityLifecycle()) return self.runCapabilityLifecycle(workload, strategy, check_full, selected, input, ticks);
        if (comptime workload == .shared_memory_map_unmap_pair) return self.runSharedMemoryPair(strategy, check_full, selected, ticks);
        if (comptime workload.payloadBytes()) |length| {
            const receiver = selected ^ 1;
            var send = self.read(abi.EndpointSendWireRequest, selected, REQUEST_OFFSET);
            send.correlation_id = input;
            self.write(selected, REQUEST_OFFSET, send);
            if (!workload.payloadPrefilled()) {
                for (self.pages[selected].bytes[PAYLOAD_OFFSET..][0..length], 0..) |*byte, index| byte.* = payloadByte(input, index);
            } else if (length != 0) {
                // A completed receive restores these bytes to the stable
                // source pattern. Poison only the destination edges to witness
                // a fresh copy without regenerating the whole source payload.
                self.pages[receiver].bytes[PAYLOAD_OFFSET] = payloadByte(0, 0) ^ 0xff;
                self.pages[receiver].bytes[PAYLOAD_OFFSET + length - 1] = payloadByte(0, length - 1) ^ 0xff;
            }
            const sent = try self.invoke(strategy, check_full, selected, .endpoint_send, self.address(selected, REQUEST_OFFSET), 0, 0, ticks);
            const received = try self.invoke(strategy, check_full, receiver, .endpoint_recv, self.address(receiver, REQUEST_OFFSET + 128), self.address(receiver, RESPONSE_OFFSET), @sizeOf(abi.EndpointRecvResponse), ticks);
            const response = self.read(abi.EndpointRecvResponse, receiver, RESPONSE_OFFSET);
            if (response.present != 1 or response.has_attached_capability != 0 or response.message.correlation_id != input or response.message.payload_len != length) return error.ResponseMismatch;
            if (check_full) {
                const expected = abi.EndpointRecvResponse{
                    .present = 1,
                    .has_attached_capability = 0,
                    ._reserved = @splat(0),
                    .message = .{
                        .endpoint_id = self.endpoint_ids[receiver],
                        .sender_endpoint_id = self.endpoint_ids[selected],
                        .sender_task_id = self.task_ids[selected],
                        .correlation_id = input,
                        .attached_capability_id = 0,
                        .payload_len = @intCast(length),
                        .flags = @bitCast(endpoint.EndpointFlags{ .local_only = true }),
                    },
                };
                if (!std.meta.eql(expected, response)) return error.ResponseMismatch;
                for (self.pages[receiver].bytes[PAYLOAD_OFFSET..][0..length], 0..) |byte, index| if (byte != payloadByte(if (workload.payloadPrefilled()) 0 else input, index)) return error.PayloadMismatch;
                for (self.pages[receiver].bytes[CAPABILITY_OFFSET..][0..@sizeOf(abi.CapabilityDescriptor)]) |byte| if (byte != CANARY) return error.UnexpectedCapabilityOutput;
            }
            const edges: u64 = if (length == 0) 0 else @as(u64, self.pages[receiver].bytes[PAYLOAD_OFFSET]) | (@as(u64, self.pages[receiver].bytes[PAYLOAD_OFFSET + length - 1]) << 8);
            if (workload.payloadPrefilled() and length != 0) {
                const expected_edges = @as(u64, payloadByte(0, 0)) | (@as(u64, payloadByte(0, length - 1)) << 8);
                if (edges != expected_edges) return error.PayloadMismatch;
            }
            return scalarChecksum(sent) +% scalarChecksum(received) +% response.message.correlation_id +% edges +% response.message.sender_task_id;
        } else {
            const operation: abi.NativeOperation = switch (workload) {
                .time_query => .time_query,
                .capability_query => .capability_query,
                .resource_query => .resource_query,
                .accounting_query => .accounting_query,
                else => unreachable,
            };
            const Response = switch (workload) {
                .time_query => abi.TimeQueryResponse,
                .capability_query => abi.CapabilityDescriptor,
                .resource_query => abi.ResourceDescriptor,
                .accounting_query => abi.AccountingDescriptor,
                else => unreachable,
            };
            const result = try self.invoke(strategy, check_full, selected, operation, self.address(selected, REQUEST_OFFSET), self.address(selected, RESPONSE_OFFSET), @sizeOf(Response), ticks);
            const response = self.read(Response, selected, RESPONSE_OFFSET);
            const value = switch (workload) {
                .time_query => blk: {
                    if (response.now_ticks != ticks) return error.ResponseMismatch;
                    break :blk response.now_ticks;
                },
                .capability_query => blk: {
                    if (response.capability_id != self.authority_ids[selected]) return error.ResponseMismatch;
                    if (check_full and !std.meta.eql(response, self.expected_capabilities[selected])) return error.ResponseMismatch;
                    break :blk response.capability_id ^ response.rights ^ response.scope_task_id;
                },
                .resource_query => blk: {
                    if (response.task_id != self.task_ids[selected]) return error.ResponseMismatch;
                    if (check_full and !std.meta.eql(response, self.expected_resources[selected])) return error.ResponseMismatch;
                    break :blk response.task_id +% response.cpu_time_ticks +% response.memory_bytes;
                },
                .accounting_query => blk: {
                    if (response.task_id != self.task_ids[selected]) return error.ResponseMismatch;
                    if (check_full and !std.meta.eql(response, self.expected_accounting[selected])) return error.ResponseMismatch;
                    break :blk response.task_id +% response.audit_event_count +% response.capability_count +% response.endpoint_count;
                },
                else => unreachable,
            };
            return scalarChecksum(result) +% value;
        }
    }

    fn invoke(self: *Fixture, comptime strategy: Strategy, comptime check_full: bool, index: usize, comptime operation: abi.NativeOperation, request: usize, response: usize, bytes: usize, ticks: u64) !surface.DispatchResult {
        var opcode = abi.opcode(operation);
        var caller = self.task_ids[index];
        var port = &self.port;
        var request_address = request;
        var response_address = response;
        var response_bytes = bytes;
        var now_ticks = ticks;
        // Match the runtime register inputs of the real syscall handler, rather
        // than allowing an operation-specialized Surface lookup.
        std.mem.doNotOptimizeAway(&opcode);
        std.mem.doNotOptimizeAway(&caller);
        std.mem.doNotOptimizeAway(&port);
        std.mem.doNotOptimizeAway(&request_address);
        std.mem.doNotOptimizeAway(&response_address);
        std.mem.doNotOptimizeAway(&response_bytes);
        std.mem.doNotOptimizeAway(&now_ticks);
        std.mem.doNotOptimizeAway(&self.pages[index]);
        const result = if (strategy == .compact)
            surface.dispatch(port, caller, now_ticks, opcode, request_address, response_address, response_bytes)
        else blk: {
            surface.dispatchDetailedInto(port, caller, now_ticks, opcode, request_address, response_address, response_bytes, &self.detailed);
            // Pointer+memory barrier: successful744B output remains observable.
            std.mem.doNotOptimizeAway(&self.detailed);
            if (check_full and !std.meta.eql(self.detailed.diagnostics, surface.Diagnostics{})) return error.DiagnosticsMismatch;
            break :blk self.detailed.result;
        };
        std.mem.doNotOptimizeAway(&self.pages[index]);
        if (result.status != .success or result.denial_reason != .none or result.bytes_written != bytes) return error.UnexpectedSyscallFailure;
        return result;
    }

    fn runCapabilityLifecycle(self: *Fixture, comptime workload: Workload, comptime strategy: Strategy, comptime check_full: bool, selected: usize, input: u64, ticks: u64) !u64 {
        const receiver = selected ^ 1;
        var request = self.read(abi.CapabilityMintWireRequest, selected, REQUEST_OFFSET);
        request.target_id = input | 0x8000_0000_0000_0000;
        request.issued_at_ticks = ticks;
        self.write(selected, REQUEST_OFFSET, request);
        const minted_result = try self.invokePreservingPages(strategy, check_full, selected, .capability_mint, REQUEST_OFFSET, RESPONSE_OFFSET, @sizeOf(abi.CapabilityDescriptor), ticks);
        const minted = self.read(abi.CapabilityDescriptor, selected, RESPONSE_OFFSET);
        if (minted.capability_id == 0 or minted.capability_id == self.last_retired_capabilities[0] or minted.capability_id == self.last_retired_capabilities[1] or
            minted.target_id != request.target_id or minted.scope_task_id != self.task_ids[selected]) return error.ResponseMismatch;
        if (check_full) {
            const expected = abi.CapabilityDescriptor{
                .capability_id = minted.capability_id,
                .target_id = request.target_id,
                .rights = request.rights_bits,
                .revocation_generation = 1,
                .expires_at_ticks = request.expires_at_ticks,
                .scope_task_id = self.task_ids[selected],
                .scope_workspace_id = 0,
                .scope_flags = @bitCast(abi.ScopeFlags{ .task_scoped = true, .local_only = true, .ephemeral = true }),
            };
            if (!std.meta.eql(minted, expected) or !self.runtime.find(self.task_ids[selected]).?.hasCapability(minted.capability_id)) return error.ResponseMismatch;
            const current = self.capabilities.query(minted.capability_id) orelse return error.ResponseMismatch;
            if (!current.holder.eql(self.runtime.find(self.task_ids[selected]).?.owner) or current.lease.issued_at_ticks != ticks or current.audit.delegation_depth != 0) return error.ResponseMismatch;
        }
        var owner = selected;
        var final_capability = minted;
        var checksum = scalarChecksum(minted_result) +% minted.target_id +% minted.rights +% minted.scope_task_id;
        if (workload == .capability_mint_move_revoke_cycle) {
            self.write(selected, REQUEST_OFFSET + 256, abi.CapabilityPassWireRequest{
                .header = component_port.makeHeader(.capability_pass, self.task_ids[selected]),
                .capability_id = minted.capability_id,
                .receiver_task_id = self.task_ids[receiver],
                .flags = capability_wire_schema.PASS_REVOKE_SOURCE,
            });
            const moved_result = try self.invokePreservingPages(strategy, check_full, selected, .capability_pass, REQUEST_OFFSET + 256, RESPONSE_OFFSET, @sizeOf(abi.CapabilityDescriptor), ticks);
            final_capability = self.read(abi.CapabilityDescriptor, selected, RESPONSE_OFFSET);
            if (final_capability.capability_id == 0 or final_capability.capability_id == minted.capability_id or
                final_capability.scope_task_id != self.task_ids[receiver] or final_capability.target_id != minted.target_id) return error.ResponseMismatch;
            if (check_full) {
                var expected = minted;
                expected.capability_id = final_capability.capability_id;
                expected.scope_task_id = self.task_ids[receiver];
                const current = self.capabilities.query(final_capability.capability_id) orelse return error.ResponseMismatch;
                if (!std.meta.eql(final_capability, expected) or self.capabilities.query(minted.capability_id) != null or
                    self.runtime.find(self.task_ids[selected]).?.hasCapability(minted.capability_id) or
                    !self.runtime.find(self.task_ids[receiver]).?.hasCapability(final_capability.capability_id) or
                    !current.holder.eql(self.runtime.find(self.task_ids[receiver]).?.owner) or current.audit.delegation_depth != 1) return error.ResponseMismatch;
            }
            owner = receiver;
            checksum +%= scalarChecksum(moved_result) +% final_capability.target_id +% final_capability.rights +% final_capability.scope_task_id;
        }
        self.write(owner, REQUEST_OFFSET + 384, abi.CapabilityRevokeWireRequest{
            .header = component_port.makeHeader(.capability_revoke, self.task_ids[owner]),
            .authority_capability_id = final_capability.capability_id,
            .capability_id = final_capability.capability_id,
        });
        const revoked_result = try self.invokePreservingPages(strategy, check_full, owner, .capability_revoke, REQUEST_OFFSET + 384, 0, 0, ticks);
        self.last_retired_capabilities = .{ minted.capability_id, final_capability.capability_id };
        self.completed_lifecycles += 1;
        return checksum +% scalarChecksum(revoked_result);
    }

    fn runSharedMemoryPair(self: *Fixture, comptime strategy: Strategy, comptime check_full: bool, selected: usize, ticks: u64) !u64 {
        // Witness a new response on each successful operation even though this
        // bounded fixture repeatedly maps the same object to its own task.
        self.pages[selected].bytes[RESPONSE_OFFSET + @offsetOf(abi.SharedMemoryDescriptor, "mapped_task_count")] = 0;
        const mapped_result = try self.invokePreservingPages(strategy, check_full, selected, .shared_memory_map, REQUEST_OFFSET, RESPONSE_OFFSET, @sizeOf(abi.SharedMemoryDescriptor), ticks);
        const mapped = self.read(abi.SharedMemoryDescriptor, selected, RESPONSE_OFFSET);
        if (mapped.object_id != self.shared_object_ids[selected] or mapped.mapped_task_count != 1) return error.ResponseMismatch;
        if (check_full) {
            var expected = self.shared_descriptors[selected];
            expected.mapped_task_count = 1;
            if (!std.meta.eql(mapped, expected) or !self.shared.hasMapping(ids.sharedMemory(mapped.object_id), ids.task(self.task_ids[selected])) or
                self.shared.mappingsForTask(ids.task(self.task_ids[selected])) != 1) return error.ResponseMismatch;
            try self.shared.validateTaskMappingDescriptor(try self.shared.taskMappingDescriptor(ids.sharedMemory(mapped.object_id), ids.task(self.task_ids[selected])));
        }
        self.pages[selected].bytes[RESPONSE_OFFSET] = 0;
        const unmapped_result = try self.invokePreservingPages(strategy, check_full, selected, .shared_memory_unmap, REQUEST_OFFSET + 256, RESPONSE_OFFSET, @sizeOf(abi.BoolResponse), ticks);
        const unmapped = self.read(abi.BoolResponse, selected, RESPONSE_OFFSET);
        if (unmapped.value != 1 or (check_full and !std.meta.eql(unmapped, abi.boolResponse(true)))) return error.ResponseMismatch;
        return scalarChecksum(mapped_result) +% scalarChecksum(unmapped_result) +% mapped.object_id +% mapped.owner_task_id +% mapped.size_bytes +% mapped.mapped_task_count +% unmapped.value;
    }

    fn invokePreservingPages(self: *Fixture, comptime strategy: Strategy, comptime check_full: bool, index: usize, comptime operation: abi.NativeOperation, request_offset: usize, response_offset: usize, bytes: usize, ticks: u64) !surface.DispatchResult {
        var expected: [2]UserPage = undefined;
        if (check_full) expected = self.pages;
        const result = try self.invoke(strategy, check_full, index, operation, self.address(index, request_offset), if (bytes == 0) 0 else self.address(index, response_offset), bytes, ticks);
        if (check_full) {
            if (bytes != 0) @memcpy(expected[index].bytes[response_offset..][0..bytes], self.pages[index].bytes[response_offset..][0..bytes]);
            if (!std.meta.eql(expected, self.pages)) return error.UnexpectedUserMemoryMutation;
        }
        return result;
    }

    fn stageRequests(self: *Fixture, comptime workload: Workload, index: usize) void {
        const task_id = self.task_ids[index];
        const authority_id = self.authority_ids[index];
        switch (workload) {
            .time_query => self.write(index, REQUEST_OFFSET, abi.TimeQueryWireRequest{ .header = component_port.makeHeader(.time_query, task_id), .authority_capability_id = authority_id }),
            .capability_query => self.write(index, REQUEST_OFFSET, abi.CapabilityQueryWireRequest{ .header = component_port.makeHeader(.capability_query, task_id), .authority_capability_id = authority_id, .capability_id = authority_id }),
            .resource_query => self.write(index, REQUEST_OFFSET, abi.ResourceQueryWireRequest{ .header = component_port.makeHeader(.resource_query, task_id), .authority_capability_id = authority_id, .task_id = task_id }),
            .accounting_query => self.write(index, REQUEST_OFFSET, abi.AccountingQueryWireRequest{ .header = component_port.makeHeader(.accounting_query, task_id), .authority_capability_id = authority_id, .task_id = task_id }),
            .capability_mint_revoke_pair, .capability_mint_move_revoke_cycle => {
                var request: abi.CapabilityMintWireRequest = undefined;
                capability_wire.mintToWireInto(component_port.makeHeader(.capability_mint, task_id), self.policy_capabilities[index], .{
                    .holder = self.runtime.find(task_id).?.owner,
                    .issuer = self.kernel.policy_authority,
                    .target = .{ .kind = .object, .id = 0x8000_0000_0000_0000 },
                    .rights = .{ .object = .{ .object_read = true, .capability_revoke = true, .capability_pass = workload == .capability_mint_move_revoke_cycle } },
                    .scope = .{ .task_id = task_id, .local_only = true },
                    .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
                }, &request);
                self.write(index, REQUEST_OFFSET, request);
            },
            .shared_memory_map_unmap_pair => {
                self.write(index, REQUEST_OFFSET, abi.SharedMemoryMapWireRequest{
                    .header = component_port.makeHeader(.shared_memory_map, task_id),
                    .shared_memory_capability_id = self.shared_capabilities[index],
                    .task_id = task_id,
                });
                self.write(index, REQUEST_OFFSET + 256, abi.SharedMemoryUnmapWireRequest{
                    .header = component_port.makeHeader(.shared_memory_unmap, task_id),
                    .shared_memory_capability_id = self.shared_capabilities[index],
                    .task_id = task_id,
                });
            },
            else => {
                const length = workload.payloadBytes().?;
                // Both task pages start with the same stable source pattern.
                // Only these workloads omit byte generation inside clocks;
                // ordinary Surface send/receive copies and barriers stay live.
                if (workload.payloadPrefilled()) {
                    for (self.pages[index].bytes[PAYLOAD_OFFSET..][0..length], 0..) |*byte, byte_index| byte.* = payloadByte(0, byte_index);
                }
                self.write(index, REQUEST_OFFSET, abi.EndpointSendWireRequest{
                    .header = component_port.makeHeader(.endpoint_send, task_id),
                    .endpoint_capability_id = self.endpoint_capabilities[index],
                    .payload_address = self.address(index, PAYLOAD_OFFSET),
                    .payload_bytes = @intCast(length),
                });
                self.write(index, REQUEST_OFFSET + 128, abi.EndpointRecvWireRequest{
                    .header = component_port.makeHeader(.endpoint_recv, task_id),
                    .endpoint_capability_id = self.endpoint_capabilities[index],
                    .receiver_task_id = task_id,
                    .payload_address = self.address(index, PAYLOAD_OFFSET),
                    .payload_capacity = @intCast(length),
                    .attached_capability_address = self.address(index, CAPABILITY_OFFSET),
                });
            },
        }
    }

    fn verifyRejectedQueries(self: *Fixture, comptime workload: Workload) !void {
        const saved_page = self.pages[0];
        const generation = self.capabilities.mutationGeneration();
        // A valid response cannot make an unreadable fixed request succeed.
        const invalid = surface.dispatch(&self.port, self.task_ids[0], 1, abi.opcode(.time_query), 0, self.address(0, RESPONSE_OFFSET), @sizeOf(abi.TimeQueryResponse));
        if (invalid.status != .invalid_request_pointer or invalid.bytes_written != 0 or !std.meta.eql(saved_page, self.pages[0])) return error.NegativeControlMismatch;
        // An attached, right-kind authority with no time_query right must deny.
        // Keep this separate setup/control outside every measurement.
        const task = self.runtime.find(self.task_ids[0]).?;
        const wrong = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 43 },
            .rights = .{ .service = .{ .resource_query = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
        });
        try self.runtime.grantCapability(task.id, wrong.id);
        self.write(0, REQUEST_OFFSET, abi.TimeQueryWireRequest{ .header = component_port.makeHeader(.time_query, task.id), .authority_capability_id = wrong.id });
        const staged = self.pages[0];
        const denied = surface.dispatch(&self.port, task.id, 1, abi.opcode(.time_query), self.address(0, REQUEST_OFFSET), self.address(0, RESPONSE_OFFSET), @sizeOf(abi.TimeQueryResponse));
        if (denied.status != .denied or denied.bytes_written != 0 or !std.meta.eql(staged, self.pages[0])) return error.NegativeControlMismatch;
        _ = self.runtime.revokeCapabilityEverywhere(wrong.id);
        try self.capabilities.revokeTargetAuthority(wrong.id);
        self.pages[0] = saved_page;
        // Grant generation legitimately changed only in untimed control setup.
        if (self.capabilities.mutationGeneration() <= generation) return error.NegativeControlMismatch;
        self.grant_generation = self.capabilities.mutationGeneration();
        self.stageRequests(workload, 0);
        try self.checkStable(workload);
    }

    fn address(self: *Fixture, index: usize, offset: usize) usize {
        return @intFromPtr(&self.pages[index].bytes) + offset;
    }

    fn write(self: *Fixture, index: usize, offset: usize, value: anytype) void {
        const bytes = std.mem.asBytes(&value);
        @memcpy(self.pages[index].bytes[offset..][0..bytes.len], bytes);
    }

    fn read(self: *Fixture, comptime T: type, index: usize, offset: usize) T {
        return std.mem.bytesToValue(T, self.pages[index].bytes[offset..][0..@sizeOf(T)]);
    }
};

pub fn inputFor(seed: u64, iteration: usize) u64 {
    return seed +% (@as(u64, @intCast(iteration)) *% 0x9e3779b97f4a7c15);
}

fn payloadByte(input: u64, index: usize) u8 {
    return @truncate((input >> @intCast((index & 7) * 8)) +% (index * 29));
}

fn scalarChecksum(result: surface.DispatchResult) u64 {
    return @as(u64, @backingInt(result.status)) +% (@as(u64, result.bytes_written) << 16) +% (@as(u64, @backingInt(result.denial_reason)) << 48);
}
