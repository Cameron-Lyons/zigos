const abi = @import("../core/abi.zig");
const builtin = @import("builtin");
const component_port = @import("component_port.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const dispatch_ownership = @import("../task/dispatch_ownership.zig");
const endpoint = @import("endpoint.zig");
const std = @import("std");
const syscall_dispatch = @import("syscall_dispatch.zig");
const syscall_surface = @import("syscall_surface.zig");
const x86 = @import("../../arch/x86.zig");

pub const Error = dispatch_ownership.Error || error{
    InterruptsEnabled,
    InvalidCopySession,
    ReentrantService,
};

// Trusted BSP adapter, borrowed for one synchronous service call. Neither the
// callback context nor this key/bound authority may survive a yield or IRQ
// enable. The callback reauthenticates the claim and its exact prepared mapping.
pub const CopySession = struct {
    context: *anyopaque,
    key: dispatch_ownership.RequestKey,
    bound: dispatch_ownership.BoundIdentity,
    read: *const fn (*anyopaque, *const dispatch_ownership.ClaimedSyscall, usize, []u8) bool,
    prepare_output: *const fn (*anyopaque, *const dispatch_ownership.ClaimedSyscall, OutputRange) bool,
    write_outputs: *const fn (*anyopaque, *const dispatch_ownership.ClaimedSyscall, []const Output) bool,
};

// Declared tails are checked as writable metadata, while only the required
// prefix is materialized. No destination alias may survive either callback.
pub const OutputRange = struct {
    address: usize,
    declared_bytes: usize,
    prepared_bytes: usize,
    alignment: usize,
};

// The adapter resolves every destination before the first write. A false
// return leaves all outputs untouched; commit cannot yield or call out.
pub const Output = struct { address: usize, bytes: []const u8 };
pub const MAX_OUTPUTS: usize = 3;
pub const MAX_OUTPUT_BYTES: usize = endpoint.MAX_MESSAGE_BYTES + @sizeOf(abi.CapabilityDescriptor) + @sizeOf(abi.EndpointRecvResponse);

// Runtime and Kernel mutation have one BSP owner. Architecture interrupt
// handlers only latch/ack work; they never recursively drain this service.
var servicing = false;

pub fn serviceClaim(
    port: *const component_port.KernelPort,
    claim: *const dispatch_ownership.ClaimedSyscall,
    copy: *const CopySession,
    now_ticks: u64,
) Error!void {
    const interrupts_enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    try serviceClaimWith(port, claim, copy, now_ticks, interrupts_enabled);
}

fn serviceClaimWith(
    port: *const component_port.KernelPort,
    claim: *const dispatch_ownership.ClaimedSyscall,
    copy: *const CopySession,
    now_ticks: u64,
    interrupts_enabled: bool,
) Error!void {
    if (cpu_identity.currentIndex() != 0) return error.WrongCpu;
    if (interrupts_enabled) return error.InterruptsEnabled;
    if (servicing) return error.ReentrantService;
    const admitted = try copyAdmission(port, claim, copy);
    servicing = true;
    defer servicing = false;
    var reply = dispatch_ownership.Reply{ .status = @intCast(@backingInt(abi.SyscallStatus.unavailable)), .denial_reason = @intCast(@backingInt(abi.DenialReason.none)), .bytes_written = 0 };
    if (admitted) {
        const caller = claim.bound.identity.task_id;
        if (claim.envelope.opcode == abi.opcode(.task_terminate)) {
            var request: abi.TaskTerminateWireRequest = undefined;
            const read = try readStaged(port, claim, copy, claim.envelope.request_addr, @alignOf(@TypeOf(request)), std.mem.asBytes(&request));
            if (read != .stopped) {
                var result: syscall_dispatch.DispatchResult = undefined;
                if (read == .read) {
                    syscall_surface.dispatchCopiedTaskTerminateInto(port, caller, now_ticks, request, &result);
                } else {
                    result = syscall_dispatch.normalizeResult(syscall_dispatch.invalidRequest());
                }
                reply = .{ .status = @intCast(@backingInt(result.status)), .denial_reason = @intCast(@backingInt(result.denial_reason)), .bytes_written = result.bytes_written };
            }
        } else if (claim.envelope.opcode == abi.opcode(.endpoint_send)) {
            var wire: abi.EndpointSendWireRequest = undefined;
            const fixed = try readStaged(port, claim, copy, claim.envelope.request_addr, @alignOf(@TypeOf(wire)), std.mem.asBytes(&wire));
            if (fixed != .stopped) {
                var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
                const encoding_valid = fixed == .read and wire.validEncoding() and wire.header.subject_task_id == caller;
                const staged: Read = if (!encoding_valid)
                    .invalid
                else if (wire.payload_bytes == 0)
                    if (try copyAdmission(port, claim, copy)) .read else .stopped
                else
                    try readStaged(port, claim, copy, @intCast(wire.payload_address), 1, payload[0..wire.payload_bytes]);
                if (staged != .stopped) {
                    var result: syscall_dispatch.DispatchResult = undefined;
                    if (staged == .read) {
                        syscall_surface.dispatchCopiedEndpointSendInto(port, caller, now_ticks, wire, payload[0..wire.payload_bytes], &result);
                    } else {
                        result = syscall_dispatch.normalizeResult(syscall_dispatch.invalidRequest());
                    }
                    reply = .{ .status = @intCast(@backingInt(result.status)), .denial_reason = @intCast(@backingInt(result.denial_reason)), .bytes_written = result.bytes_written };
                }
            }
        } else if (claim.envelope.opcode == abi.opcode(.endpoint_recv)) {
            try receiveClaimInto(port, claim, copy, now_ticks, &reply);
        } else if (claim.envelope.opcode == abi.opcode(.endpoint_close)) {
            try closeClaimInto(port, claim, copy, now_ticks, &reply);
        } else {
            reply.status = @intCast(@backingInt(abi.SyscallStatus.unsupported_operation));
            reply.denial_reason = @intCast(@backingInt(abi.DenialReason.unsupported_operation));
        }
    }
    // Self termination can publish STOP here. Finish this claimed request once
    // without inspecting caller bytes again; return ACK remains the AP's job.
    try port.kernel.runtime.execution.completeSyscall(claim.key, reply);
}

fn copyAdmission(port: *const component_port.KernelPort, claim: *const dispatch_ownership.ClaimedSyscall, copy: *const CopySession) Error!bool {
    const runtime = port.kernel.runtime;
    var bound: dispatch_ownership.BoundIdentity = undefined;
    var stopped: bool = undefined;
    try runtime.execution.validateClaimInto(claim, &bound, &stopped);
    if (!std.meta.eql(copy.key, claim.key) or !std.meta.eql(copy.bound, bound)) return error.InvalidCopySession;
    const identity = bound.identity;
    const task = runtime.findConstByHandle(.{ .value = identity.task_handle }, identity.task_id) orelse return error.InvalidIdentity;
    const borrow = runtime.execution_borrows[claim.key.ticket.cpu] orelse return error.InvalidIdentity;
    if (borrow.runtime != runtime or borrow.handle.value != identity.task_handle or borrow.task_id != identity.task_id or
        task.process_generation != identity.process_generation or task.address_space_id != identity.address_space_id)
        return error.InvalidIdentity;
    return !stopped and task.state == .active;
}

const Read = enum { read, invalid, stopped };

inline fn replyFromResult(result: syscall_dispatch.DispatchResult) dispatch_ownership.Reply {
    return replyFromStatus(result.status, result.denial_reason, result.bytes_written);
}

// The mailbox carries only these scalars. Reuse the ordinary denial mapping
// without building explanation/provenance records that cannot be returned.
inline fn replyFromStatus(status: abi.SyscallStatus, denial_reason: abi.DenialReason, bytes_written: u32) dispatch_ownership.Reply {
    const reason = if (denial_reason == .none) syscall_dispatch.defaultDenialReasonForStatus(status) else denial_reason;
    return .{ .status = @intCast(@backingInt(status)), .denial_reason = @intCast(@backingInt(reason)), .bytes_written = bytes_written };
}

fn closeClaimInto(port: *const component_port.KernelPort, claim: *const dispatch_ownership.ClaimedSyscall, copy: *const CopySession, now_ticks: u64, out: *dispatch_ownership.Reply) Error!void {
    var request: abi.EndpointCloseWireRequest = undefined;
    const fixed = try readStaged(port, claim, copy, claim.envelope.request_addr, @alignOf(@TypeOf(request)), std.mem.asBytes(&request));
    if (fixed == .stopped) return;
    const caller = claim.bound.identity.task_id;
    if (fixed != .read or request.header.subject_task_id != caller) {
        out.* = replyFromStatus(.invalid_request_pointer, .none, 0);
        return;
    }
    var local_port = port.*;
    local_port.syscall_caller_task_id = caller;
    local_port.syscall_header_prevalidated = false;
    local_port.endpointClose(request, now_ticks) catch |err| {
        out.* = replyFromResult(syscall_dispatch.mapError(err));
        return;
    };
    // Retirement and peer wakeups have committed. A wake may publish STOP;
    // preserve success without reading caller bytes or touching output memory.
    out.* = replyFromStatus(.success, .none, 0);
}

fn receiveClaimInto(port: *const component_port.KernelPort, claim: *const dispatch_ownership.ClaimedSyscall, copy: *const CopySession, now_ticks: u64, out: *dispatch_ownership.Reply) Error!void {
    const caller = claim.bound.identity.task_id;
    var wire: abi.EndpointRecvWireRequest = undefined;
    const fixed = try readStaged(port, claim, copy, claim.envelope.request_addr, @alignOf(@TypeOf(wire)), std.mem.asBytes(&wire));
    if (fixed == .stopped) return;
    var result: dispatch_ownership.Reply = undefined;
    if (fixed != .read or !wire.validEncoding() or wire.header.subject_task_id != caller or wire.receiver_task_id != caller) {
        result = replyFromStatus(.invalid_request_pointer, .none, 0);
    } else if (claim.envelope.response_len < @sizeOf(abi.EndpointRecvResponse)) {
        result = replyFromStatus(.buffer_too_small, .none, 0);
    } else {
        const response = OutputRange{ .address = claim.envelope.response_addr, .declared_bytes = claim.envelope.response_len, .prepared_bytes = @sizeOf(abi.EndpointRecvResponse), .alignment = 1 };
        const payload = OutputRange{ .address = @intCast(wire.payload_address), .declared_bytes = wire.payload_capacity, .prepared_bytes = wire.payload_capacity, .alignment = 1 };
        const capability = OutputRange{ .address = @intCast(wire.attached_capability_address), .declared_bytes = @sizeOf(abi.CapabilityDescriptor), .prepared_bytes = @sizeOf(abi.CapabilityDescriptor), .alignment = @alignOf(abi.CapabilityDescriptor) };
        if (!validOutputRange(response) or !validOutputRange(payload) or !validOutputRange(capability) or
            outputRangesOverlap(response, payload) or outputRangesOverlap(response, capability) or outputRangesOverlap(payload, capability))
        {
            result = replyFromStatus(.invalid_response_buffer, .none, 0);
        } else {
            for ([_]OutputRange{ response, payload, capability }) |range| {
                const prepared = try prepareOutput(port, claim, copy, range);
                if (prepared == .stopped) return;
                if (prepared == .invalid) {
                    out.* = replyFromStatus(.invalid_response_buffer, .none, 0);
                    return;
                }
            }
            if (!try copyAdmission(port, claim, copy)) return;
            var staged_payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
            var staged_capability: abi.CapabilityDescriptor = undefined;
            var request: component_port.EndpointRecvRequest = undefined;
            if (!component_port.endpointRecvFromWireInto(wire, staged_payload[0..wire.payload_capacity], &staged_capability, &request)) unreachable;
            var local_port = port.*;
            local_port.syscall_caller_task_id = caller;
            local_port.syscall_header_prevalidated = false;
            const received = local_port.endpointRecv(request, now_ticks) catch |err| {
                out.* = replyFromResult(syscall_dispatch.mapError(err));
                return;
            };
            // Dequeue and capability transfer now belong to this request once.
            // STOP or failed output cannot retry or recreate those effects.
            if (!try copyAdmission(port, claim, copy)) return;
            var staged_response = std.mem.zeroes(abi.EndpointRecvResponse);
            var outputs: [MAX_OUTPUTS]Output = undefined;
            var count: usize = 0;
            if (received) |message| {
                staged_response.present = 1;
                staged_response.has_attached_capability = @intFromBool(message.attached_capability != null);
                staged_response.message = message.message;
                if (message.message.payload_len != 0) {
                    outputs[count] = .{ .address = payload.address, .bytes = staged_payload[0..message.message.payload_len] };
                    count += 1;
                }
                if (message.attached_capability != null) {
                    outputs[count] = .{ .address = capability.address, .bytes = std.mem.asBytes(&staged_capability) };
                    count += 1;
                }
            }
            outputs[count] = .{ .address = response.address, .bytes = std.mem.asBytes(&staged_response) };
            count += 1;
            const written = copy.write_outputs(copy.context, claim, outputs[0..count]);
            if (!try copyAdmission(port, claim, copy)) return;
            result = replyFromStatus(if (written) .success else .invalid_response_buffer, .none, if (written) @sizeOf(abi.EndpointRecvResponse) else 0);
        }
    }
    out.* = result;
}

inline fn validOutputRange(range: OutputRange) bool {
    if (range.prepared_bytes > range.declared_bytes or range.prepared_bytes > endpoint.MAX_MESSAGE_BYTES or
        range.alignment == 0 or !std.math.isPowerOfTwo(range.alignment)) return false;
    if (range.declared_bytes == 0) return true;
    const end = std.math.add(usize, range.address, range.declared_bytes) catch return false;
    return range.address >= 0x10000 and range.address % range.alignment == 0 and end > range.address and end <= 0x0000_8000_0000_0000;
}

inline fn outputRangesOverlap(first: OutputRange, second: OutputRange) bool {
    if (first.declared_bytes == 0 or second.declared_bytes == 0) return false;
    // Called only after both complete extents passed overflow admission.
    return first.address < second.address + second.declared_bytes and second.address < first.address + first.declared_bytes;
}

inline fn prepareOutput(port: *const component_port.KernelPort, claim: *const dispatch_ownership.ClaimedSyscall, copy: *const CopySession, range: OutputRange) Error!Read {
    if (!try copyAdmission(port, claim, copy)) return .stopped;
    if (range.declared_bytes == 0) return .read;
    const prepared = copy.prepare_output(copy.context, claim, range);
    if (!try copyAdmission(port, claim, copy)) return .stopped;
    return if (prepared) .read else .invalid;
}

fn rejectOutput(_: *anyopaque, _: *const dispatch_ownership.ClaimedSyscall, _: OutputRange) bool {
    return false;
}

fn rejectOutputs(_: *anyopaque, _: *const dispatch_ownership.ClaimedSyscall, _: []const Output) bool {
    return false;
}

fn readStaged(port: *const component_port.KernelPort, claim: *const dispatch_ownership.ClaimedSyscall, copy: *const CopySession, address: usize, alignment: usize, destination: []u8) Error!Read {
    if (!try copyAdmission(port, claim, copy)) return .stopped;
    const end = std.math.add(usize, address, destination.len) catch return .invalid;
    if (address < 0x10000 or address % alignment != 0 or end <= address or end > 0x0000_8000_0000_0000) return .invalid;
    const readable = copy.read(copy.context, claim, address, destination);
    // A trusted adapter may observe STOP or a synchronous lifecycle callback.
    // Reauthenticate before another read or any operation can publish effects.
    if (!try copyAdmission(port, claim, copy)) return .stopped;
    return if (readable) .read else .invalid;
}

const TestFixture = if (builtin.is_test) struct {
    const task_runtime = @import("../task/task_runtime.zig");
    const capability = @import("capability.zig");
    const ids = @import("../core/ids.zig");
    const native_kernel = @import("native_kernel.zig");
    const shared_memory = @import("shared_memory.zig");

    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    tasks: [cpu_identity.MAX_CPUS]?*task_runtime.TaskRecord = @splat(null),
    owned_endpoints: [cpu_identity.MAX_CPUS]u64 = @splat(0),
    tickets: [cpu_identity.MAX_CPUS]?dispatch_ownership.Ticket = @splat(null),
    keys: [cpu_identity.MAX_CPUS]?dispatch_ownership.RequestKey = @splat(null),
    requests: [cpu_identity.MAX_CPUS]abi.TaskTerminateWireRequest = undefined,
    behavior: enum { copy, partial, erase, stop, reenter } = .copy,
    reads: usize = 0,
    nested_rejections: usize = 0,

    fn init(self: *@This()) void {
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        // The broker must override this only on its private port copy.
        self.port.syscall_caller_task_id = 999;
        self.port.syscall_header_prevalidated = true;
    }

    fn deinit(self: *@This()) void {
        cpu_identity.setIndexForTest(0);
        for (self.tickets, 0..) |optional_ticket, index| {
            const ticket = optional_ticket orelse continue;
            if (self.keys[index]) |key| {
                cpu_identity.setIndexForTest(ticket.cpu);
                _ = self.runtime.execution.cancelPendingSyscall(key);
                var reply: dispatch_ownership.Reply = undefined;
                self.runtime.execution.consumeSyscallInto(key, &reply) catch {};
                cpu_identity.setIndexForTest(0);
                self.runtime.execution.completeSyscall(key, .{ .status = @intCast(@backingInt(abi.SyscallStatus.unavailable)), .denial_reason = 0, .bytes_written = 0 }) catch {};
                cpu_identity.setIndexForTest(ticket.cpu);
                self.runtime.execution.consumeSyscallInto(key, &reply) catch {};
                cpu_identity.setIndexForTest(0);
            }
            const phase = self.runtime.execution.phase(ticket) catch continue;
            if (phase == .running) {
                cpu_identity.setIndexForTest(ticket.cpu);
                self.runtime.execution.acknowledgeOwnedRootReturn(ticket) catch @panic("fixture drains its syscall before return");
                cpu_identity.setIndexForTest(0);
            } else if (phase == .reserved or phase == .ready) {
                self.runtime.cancelUnstartedExecution(ticket) catch unreachable;
            }
            self.runtime.collectExecution(ticket) catch unreachable;
        }
        // Keep the real Kernel resource-retirement owner alive during reset.
        self.runtime.reset();
        self.endpoints.deinit();
        self.shared.deinit();
        self.kernel.deinit();
    }

    fn add(self: *@This(), cpu: u8) !void {
        const task = try self.runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = @as(u64, cpu) + 2 },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = shared_memory.PAGE_SIZE, .endpoint_slots = 2, .shared_memory_bytes = 2 * shared_memory.PAGE_SIZE },
            .local_only = true,
        });
        self.tasks[cpu] = task;
        const authority = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel.policy_authority,
            .target = .{ .kind = .task, .id = task.id },
            .rights = .{ .task = .{ .task_terminate = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try self.runtime.grantCapability(task.id, authority.id);
        const owned_endpoint = try self.endpoints.create(ids.task(task.id), "broker-owned", .{});
        self.owned_endpoints[cpu] = owned_endpoint.id.raw();
        const object = try self.shared.create(ids.task(task.id), shared_memory.PAGE_SIZE + 37);
        try self.shared.map(object.id, ids.task(task.id));
        self.requests[cpu] = .{ .header = component_port.makeHeader(.task_terminate, task.id), .task_capability_id = authority.id };
        const ticket = try self.runtime.reserveExecution(task, cpu);
        self.tickets[cpu] = ticket;
        // These addresses are hosted transport model identities. The callback
        // below copies only its owned request array; it never dereferences them.
        try self.runtime.execution.bindOwnedRoot(ticket, @as(u64, cpu) + 1, (@as(u64, cpu) + 1) * 4096);
        cpu_identity.setIndexForTest(cpu);
        _ = try self.runtime.execution.start(ticket);
        cpu_identity.setIndexForTest(0);
    }

    fn submit(self: *@This(), cpu: u8, opcode: u16) !dispatch_ownership.RequestKey {
        return self.submitEnvelope(cpu, .{
            .opcode = opcode,
            .request_addr = @intFromPtr(&self.requests[cpu]),
            .response_addr = std.math.maxInt(usize),
            .response_len = std.math.maxInt(usize),
        });
    }

    fn submitEnvelope(self: *@This(), cpu: u8, envelope: dispatch_ownership.Envelope) !dispatch_ownership.RequestKey {
        var key: dispatch_ownership.RequestKey = undefined;
        cpu_identity.setIndexForTest(cpu);
        defer cpu_identity.setIndexForTest(0);
        try self.runtime.execution.submitSyscallInto(self.tickets[cpu].?, envelope, &key);
        self.keys[cpu] = key;
        return key;
    }

    fn claimInto(self: *@This(), cpu: u8, out: *dispatch_ownership.ClaimedSyscall) !void {
        try self.runtime.execution.claimSyscallInto(cpu, out);
    }

    fn session(self: *@This(), claim: *const dispatch_ownership.ClaimedSyscall) CopySession {
        return .{ .context = self, .key = claim.key, .bound = claim.bound, .read = read, .prepare_output = rejectOutput, .write_outputs = rejectOutputs };
    }

    fn read(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, destination: []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        var bound: dispatch_ownership.BoundIdentity = undefined;
        var stopped: bool = undefined;
        self.runtime.execution.validateClaimInto(claim, &bound, &stopped) catch return false;
        if (stopped or !std.meta.eql(bound, claim.bound)) return false;
        const request = &self.requests[claim.key.ticket.cpu];
        if (address != @intFromPtr(request) or destination.len != @sizeOf(@TypeOf(request.*))) return false;
        self.reads += 1;
        if (self.behavior == .partial) {
            @memcpy(destination[0..8], std.mem.asBytes(request)[0..8]);
            return false;
        }
        @memcpy(destination, std.mem.asBytes(request));
        switch (self.behavior) {
            .erase => @memset(std.mem.asBytes(request), 0),
            .stop => self.runtime.requestExecutionStop(claim.key.ticket) catch unreachable,
            .reenter => {
                const copy = self.session(claim);
                std.testing.expectError(error.ReentrantService, serviceClaim(&self.port, claim, &copy, 20)) catch @panic("broker rejects callback service reentry");
                self.nested_rejections += 1;
            },
            else => {},
        }
        return true;
    }

    fn consume(self: *@This(), key: dispatch_ownership.RequestKey, out: *dispatch_ownership.Reply) !void {
        cpu_identity.setIndexForTest(key.ticket.cpu);
        defer cpu_identity.setIndexForTest(0);
        try self.runtime.execution.consumeSyscallInto(key, out);
    }
} else struct {};

const EndpointFixture = if (builtin.is_test) struct {
    const sender_cpu: u8 = 3;
    const receiver_cpu: u8 = 4;
    base: TestFixture = .{},
    wire: abi.EndpointSendWireRequest = undefined,
    payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined,
    send_capability: u64 = 0,
    recv_capability: u64 = 0,
    gift: u64 = 0,
    behavior: enum { copy, erase, partial_fixed, partial_payload, stop_fixed, stop_payload, reenter_payload } = .copy,
    reads: usize = 0,
    wakes: usize = 0,
    reentries: usize = 0,
    wake_stops: bool = false,
    active_claim: ?*const dispatch_ownership.ClaimedSyscall = null,

    fn create() !*@This() {
        const self = try std.testing.allocator.create(@This());
        errdefer std.testing.allocator.destroy(self);
        self.* = .{};
        self.base.init();
        errdefer self.deinit();
        try self.base.add(sender_cpu);
        try self.base.add(receiver_cpu);
        const sender = self.base.tasks[sender_cpu].?;
        const receiver = self.base.tasks[receiver_cpu].?;
        try self.base.endpoints.connect(TestFixture.ids.endpoint(self.source()), TestFixture.ids.endpoint(self.destination()));
        const sending = try self.base.capabilities.mintBootRoot(.{
            .holder = sender.owner,
            .issuer = self.base.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = self.source() },
            .rights = .{ .endpoint = .{ .endpoint_send = true } },
            .scope = .{ .task_id = sender.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.send_capability = sending.id;
        try self.base.runtime.grantCapability(sender.id, sending.id);
        const receiving = try self.base.capabilities.mintBootRoot(.{
            .holder = receiver.owner,
            .issuer = self.base.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = self.destination() },
            .rights = .{ .endpoint = .{ .endpoint_recv = true } },
            .scope = .{ .task_id = receiver.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.recv_capability = receiving.id;
        try self.base.runtime.grantCapability(receiver.id, receiving.id);
        const gift = try self.base.capabilities.mintBootRoot(.{
            .holder = sender.owner,
            .issuer = self.base.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 901 },
            .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
            .scope = .{ .task_id = sender.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.gift = gift.id;
        try self.base.runtime.grantCapability(sender.id, gift.id);
        for (&self.payload, 0..) |*byte, index| byte.* = @truncate(index * 19 + 3);
        self.wire = .{
            .header = component_port.makeHeader(.endpoint_send, sender.id),
            .correlation_id = 77,
            .endpoint_capability_id = self.send_capability,
            .payload_address = @intFromPtr(&self.payload),
            .payload_bytes = self.payload.len,
            .attached_capability_id = self.gift,
        };
        self.base.kernel.bindEndpointWakeSink(.{ .context = self, .wake = wake });
        return self;
    }

    fn deinit(self: *@This()) void {
        self.base.kernel.clearEndpointWakeSink();
        self.base.deinit();
    }

    fn destroy(self: *@This()) void {
        self.deinit();
        std.testing.allocator.destroy(self);
    }

    fn source(self: *@This()) u64 {
        return self.base.owned_endpoints[sender_cpu];
    }

    fn destination(self: *@This()) u64 {
        return self.base.owned_endpoints[receiver_cpu];
    }

    fn session(self: *@This(), claim: *const dispatch_ownership.ClaimedSyscall) CopySession {
        return .{ .context = self, .key = claim.key, .bound = claim.bound, .read = read, .prepare_output = rejectOutput, .write_outputs = rejectOutputs };
    }

    fn submit(self: *@This(), address: usize) !dispatch_ownership.RequestKey {
        return self.base.submitEnvelope(sender_cpu, .{
            .opcode = abi.opcode(.endpoint_send),
            .request_addr = address,
            .response_addr = std.math.maxInt(usize),
            .response_len = std.math.maxInt(usize),
        });
    }

    fn roundTrip(self: *@This(), address: usize) !dispatch_ownership.Reply {
        const key = try self.submit(address);
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try self.base.claimInto(sender_cpu, &claim);
        self.active_claim = &claim;
        defer self.active_claim = null;
        const copy = self.session(&claim);
        try serviceClaim(&self.base.port, &claim, &copy, 19);
        try std.testing.expectError(error.WrongPhase, serviceClaim(&self.base.port, &claim, &copy, 20));
        cpu_identity.setIndexForTest(sender_cpu);
        try std.testing.expectError(error.SyscallInFlight, self.base.runtime.execution.acknowledgeOwnedRootReturn(key.ticket));
        cpu_identity.setIndexForTest(0);
        var reply: dispatch_ownership.Reply = undefined;
        try self.base.consume(key, &reply);
        return reply;
    }

    fn read(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, destination_bytes: []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        var bound: dispatch_ownership.BoundIdentity = undefined;
        var stopped: bool = undefined;
        self.base.runtime.execution.validateClaimInto(claim, &bound, &stopped) catch return false;
        if (stopped or !std.meta.eql(bound, claim.bound)) return false;
        self.reads += 1;
        const fixed = address == @intFromPtr(&self.wire) and destination_bytes.len == @sizeOf(@TypeOf(self.wire));
        const nested = address == @intFromPtr(&self.payload) and destination_bytes.len <= self.payload.len;
        if (!fixed and !nested) return false;
        const bytes = if (fixed) std.mem.asBytes(&self.wire) else self.payload[0..destination_bytes.len];
        if ((fixed and self.behavior == .partial_fixed) or (nested and self.behavior == .partial_payload)) {
            const prefix = @min(@as(usize, 8), destination_bytes.len);
            @memcpy(destination_bytes[0..prefix], bytes[0..prefix]);
            return false;
        }
        @memcpy(destination_bytes, bytes);
        if (self.behavior == .erase) @memset(bytes, 0);
        if ((fixed and self.behavior == .stop_fixed) or (nested and self.behavior == .stop_payload))
            self.base.runtime.requestExecutionStop(claim.key.ticket) catch unreachable;
        if (nested and self.behavior == .reenter_payload) {
            const copy = self.session(claim);
            std.testing.expectError(error.ReentrantService, serviceClaim(&self.base.port, claim, &copy, 20)) catch @panic("nested payload copy cannot service again");
            self.reentries += 1;
        }
        return true;
    }

    fn wake(context: *anyopaque, task_id: u64, now_ticks: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        std.testing.expectEqual(self.base.tasks[receiver_cpu].?.id, task_id) catch @panic("wake names the actual endpoint receiver");
        self.wakes += 1;
        if (!self.wake_stops) return;
        std.testing.expectEqual(@as(u64, 19), now_ticks) catch @panic("wake follows the completed send");
        const claim = self.active_claim orelse @panic("wake has synchronous processing lifetime");
        const copy = self.session(claim);
        std.testing.expectError(error.ReentrantService, serviceClaim(&self.base.port, claim, &copy, now_ticks)) catch @panic("endpoint wake cannot service again");
        self.reentries += 1;
        std.testing.expect(self.base.runtime.terminateTask(self.base.tasks[sender_cpu].?.id, now_ticks) catch false) catch @panic("wake can logically terminate its sender after enqueue");
    }

    fn receive(self: *@This(), out: []u8) !?TestFixture.native_kernel.EndpointReceiveResult {
        return self.base.kernel.endpointRecv(.{
            .caller_task_id = self.base.tasks[receiver_cpu].?.id,
            .presented_capability_id = self.recv_capability,
            .target = .none,
        }, self.base.tasks[receiver_cpu].?.id, out, 20);
    }

    const Snapshot = struct {
        sender: TestFixture.task_runtime.TaskRecord,
        receiver: TestFixture.task_runtime.TaskRecord,
        source_descriptor: abi.EndpointDescriptor,
        destination_descriptor: abi.EndpointDescriptor,
        grants: usize,
        generation: u64,
        gift: ?TestFixture.capability.Capability,
        pending: @TypeOf(@as(endpoint.Table, undefined).pending_endpoint_counts),
        ring: []u8,
        source_ring: []u8,
        port: component_port.KernelPort,
        wakes: usize,
        payload: [endpoint.MAX_MESSAGE_BYTES]u8,

        fn capture(self: *EndpointFixture) !@This() {
            const destination_slot = self.base.endpoints.arena.getByHandle(.{ .value = self.destination() }).?;
            const source_slot = self.base.endpoints.arena.getByHandle(.{ .value = self.source() }).?;
            const ring = try std.testing.allocator.dupe(u8, destination_slot.endpoint.data_ring);
            errdefer std.testing.allocator.free(ring);
            return .{
                .sender = self.base.tasks[sender_cpu].?.*,
                .receiver = self.base.tasks[receiver_cpu].?.*,
                .source_descriptor = try self.base.endpoints.descriptor(TestFixture.ids.endpoint(self.source())),
                .destination_descriptor = try self.base.endpoints.descriptor(TestFixture.ids.endpoint(self.destination())),
                .grants = self.base.capabilities.activeCount(),
                .generation = self.base.capabilities.mutationGeneration(),
                .gift = self.base.capabilities.query(self.gift),
                .pending = self.base.endpoints.pending_endpoint_counts,
                .ring = ring,
                .source_ring = try std.testing.allocator.dupe(u8, source_slot.endpoint.data_ring),
                .port = self.base.port,
                .wakes = self.wakes,
                .payload = self.payload,
            };
        }

        fn deinit(self: @This()) void {
            std.testing.allocator.free(self.ring);
            std.testing.allocator.free(self.source_ring);
        }

        fn expectUnchanged(self: *const @This(), fixture: *EndpointFixture) !void {
            try std.testing.expect(std.meta.eql(self.sender, fixture.base.tasks[sender_cpu].?.*));
            try std.testing.expect(std.meta.eql(self.receiver, fixture.base.tasks[receiver_cpu].?.*));
            try std.testing.expect(std.meta.eql(self.source_descriptor, try fixture.base.endpoints.descriptor(TestFixture.ids.endpoint(fixture.source()))));
            try std.testing.expect(std.meta.eql(self.destination_descriptor, try fixture.base.endpoints.descriptor(TestFixture.ids.endpoint(fixture.destination()))));
            try std.testing.expectEqual(self.grants, fixture.base.capabilities.activeCount());
            try std.testing.expectEqual(self.generation, fixture.base.capabilities.mutationGeneration());
            try std.testing.expect(std.meta.eql(self.gift, fixture.base.capabilities.query(fixture.gift)));
            try std.testing.expectEqualSlices(@TypeOf(self.pending[0]), &self.pending, &fixture.base.endpoints.pending_endpoint_counts);
            const destination_slot = fixture.base.endpoints.arena.getByHandle(.{ .value = fixture.destination() }).?;
            try std.testing.expectEqualSlices(u8, self.ring, destination_slot.endpoint.data_ring);
            const source_slot = fixture.base.endpoints.arena.getByHandle(.{ .value = fixture.source() }).?;
            try std.testing.expectEqualSlices(u8, self.source_ring, source_slot.endpoint.data_ring);
            try std.testing.expect(std.meta.eql(self.port, fixture.base.port));
            try std.testing.expectEqual(self.wakes, fixture.wakes);
            try std.testing.expectEqualSlices(u8, &self.payload, &fixture.payload);
        }
    };
} else struct {};

const CloseFixture = if (builtin.is_test) struct {
    endpoint_fixture: *EndpointFixture,
    request: abi.EndpointCloseWireRequest = undefined,
    moved_gift: u64 = 0,
    behavior: enum { copy, erase, partial, stop, reenter } = .copy,
    reads: usize = 0,
    outputs: usize = 0,
    wakes: usize = 0,
    reentries: usize = 0,
    terminate_on_wake: bool = false,
    active_claim: ?*const dispatch_ownership.ClaimedSyscall = null,

    fn create() !*@This() {
        const fixture = try EndpointFixture.create();
        errdefer fixture.destroy();
        const self = try std.testing.allocator.create(@This());
        errdefer std.testing.allocator.destroy(self);
        self.* = .{ .endpoint_fixture = fixture };
        fixture.base.kernel.clearEndpointWakeSink();
        const receiver = fixture.base.tasks[EndpointFixture.receiver_cpu].?;
        const closing = try fixture.base.capabilities.mintBootRoot(.{
            .holder = receiver.owner,
            .issuer = fixture.base.kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = fixture.destination() },
            .rights = .{ .endpoint = .{ .endpoint_close = true, .endpoint_send = true } },
            .scope = .{ .task_id = receiver.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        try fixture.base.runtime.grantCapability(receiver.id, closing.id);
        self.request = .{ .header = component_port.makeHeader(.endpoint_close, receiver.id), .endpoint_capability_id = closing.id };
        const sender = fixture.base.tasks[EndpointFixture.sender_cpu].?;
        const moved = try fixture.base.capabilities.mintBootRoot(.{
            .holder = sender.owner,
            .issuer = fixture.base.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 902 },
            .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
            .scope = .{ .task_id = sender.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        });
        self.moved_gift = moved.id;
        try fixture.base.runtime.grantCapability(sender.id, moved.id);
        for ([_]bool{ false, true }) |move| try fixture.base.kernel.endpointSend(.{
            .caller_task_id = sender.id,
            .presented_capability_id = fixture.send_capability,
            .target = .none,
        }, 77, &fixture.payload, 0, if (move) moved.id else fixture.gift, move, 18);
        // A reply already queued on the surviving peer must remain drainable.
        try fixture.base.kernel.endpointSend(.{
            .caller_task_id = receiver.id,
            .presented_capability_id = closing.id,
            .target = .none,
        }, 91, "surviving reply", 0, null, false, 18);
        fixture.base.kernel.bindEndpointWakeSink(.{ .context = self, .wake = wake });
        return self;
    }

    fn destroy(self: *@This()) void {
        self.endpoint_fixture.destroy();
        std.testing.allocator.destroy(self);
    }

    fn session(self: *@This(), claim: *const dispatch_ownership.ClaimedSyscall) CopySession {
        return .{ .context = self, .key = claim.key, .bound = claim.bound, .read = read, .prepare_output = prepare, .write_outputs = write };
    }

    fn submit(self: *@This(), address: usize) !dispatch_ownership.RequestKey {
        return self.endpoint_fixture.base.submitEnvelope(EndpointFixture.receiver_cpu, .{
            .opcode = abi.opcode(.endpoint_close),
            .request_addr = address,
            .response_addr = std.math.maxInt(usize),
            .response_len = std.math.maxInt(usize),
        });
    }

    fn roundTrip(self: *@This(), address: usize) !dispatch_ownership.Reply {
        const base = &self.endpoint_fixture.base;
        const key = try self.submit(address);
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try base.claimInto(EndpointFixture.receiver_cpu, &claim);
        self.active_claim = &claim;
        defer self.active_claim = null;
        const copy = self.session(&claim);
        try serviceClaim(&base.port, &claim, &copy, 19);
        const generation = base.capabilities.mutationGeneration();
        try std.testing.expectError(error.WrongPhase, serviceClaim(&base.port, &claim, &copy, 20));
        try std.testing.expectEqual(generation, base.capabilities.mutationGeneration());
        cpu_identity.setIndexForTest(key.ticket.cpu);
        try std.testing.expectError(error.SyscallInFlight, base.runtime.execution.acknowledgeOwnedRootReturn(key.ticket));
        cpu_identity.setIndexForTest(0);
        var reply: dispatch_ownership.Reply = undefined;
        try base.consume(key, &reply);
        return reply;
    }

    fn read(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, destination: []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.reads += 1;
        if (address != @intFromPtr(&self.request) or destination.len != @sizeOf(abi.EndpointCloseWireRequest)) return false;
        if (self.behavior == .partial) {
            @memcpy(destination[0..8], std.mem.asBytes(&self.request)[0..8]);
            return false;
        }
        @memcpy(destination, std.mem.asBytes(&self.request));
        switch (self.behavior) {
            .erase => @memset(std.mem.asBytes(&self.request), 0),
            .stop => self.endpoint_fixture.base.runtime.requestExecutionStop(claim.key.ticket) catch unreachable,
            .reenter => {
                const copy = self.session(claim);
                std.testing.expectError(error.ReentrantService, serviceClaim(&self.endpoint_fixture.base.port, claim, &copy, 20)) catch @panic("close copy rejects reentry");
                self.reentries += 1;
            },
            else => {},
        }
        return true;
    }

    fn prepare(context: *anyopaque, _: *const dispatch_ownership.ClaimedSyscall, _: OutputRange) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.outputs += 1;
        return false;
    }

    fn write(context: *anyopaque, _: *const dispatch_ownership.ClaimedSyscall, _: []const Output) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.outputs += 1;
        return false;
    }

    fn expectRetired(self: *@This()) !void {
        const fixture = self.endpoint_fixture;
        const base = &fixture.base;
        const receiver = base.tasks[EndpointFixture.receiver_cpu].?;
        try std.testing.expectError(error.EndpointNotFound, base.endpoints.descriptor(TestFixture.ids.endpoint(fixture.destination())));
        try std.testing.expect(!base.endpoints.hasPendingForTask(TestFixture.ids.task(receiver.id)));
        var grants: [8]TestFixture.capability.Capability = undefined;
        try std.testing.expectEqual(@as(usize, 0), base.capabilities.queryByTarget(.{ .kind = .endpoint, .id = fixture.destination() }, &grants).len);
        try std.testing.expect(base.capabilities.query(self.moved_gift) == null);
        try std.testing.expect(base.capabilities.query(fixture.gift) != null);
        try std.testing.expect(base.tasks[EndpointFixture.sender_cpu].?.hasCapability(fixture.gift));
        const peer = try base.endpoints.descriptor(TestFixture.ids.endpoint(fixture.source()));
        try std.testing.expect(base.endpoints.arena.getByHandle(.{ .value = fixture.source() }).?.endpoint.peer_closed);
        try std.testing.expectEqual(@as(u64, 0), peer.peer_endpoint_id);
        try std.testing.expectEqual(@as(u16, 1), peer.queued_messages);
    }

    fn wake(context: *anyopaque, task_id: u64, now_ticks: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const fixture = self.endpoint_fixture;
        std.testing.expectEqual(fixture.base.tasks[EndpointFixture.sender_cpu].?.id, task_id) catch @panic("close wakes surviving peer owner");
        std.testing.expectEqual(@as(u64, 19), now_ticks) catch @panic("close wake uses committed operation tick");
        self.expectRetired() catch @panic("complete close retirement precedes wake");
        self.wakes += 1;
        const claim = self.active_claim orelse @panic("close wake borrows processing claim");
        const copy = self.session(claim);
        std.testing.expectError(error.ReentrantService, serviceClaim(&fixture.base.port, claim, &copy, now_ticks)) catch @panic("close wake rejects reentry");
        self.reentries += 1;
        if (self.terminate_on_wake)
            std.testing.expect(fixture.base.runtime.terminateTask(fixture.base.tasks[EndpointFixture.receiver_cpu].?.id, now_ticks) catch false) catch @panic("close wake may terminate caller");
    }
} else struct {};

test "syscall broker close retires unread moves and exact target grants before waking surviving peers once" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try CloseFixture.create();
    defer fixture.destroy();
    const base = &fixture.endpoint_fixture.base;
    const task = base.tasks[EndpointFixture.receiver_cpu].?;
    const original_port = base.port;
    const original_request = fixture.request;
    const grants = base.capabilities.activeCount();
    const address_space = task.address_space_id;
    fixture.behavior = .erase;
    const reply = try fixture.roundTrip(@intFromPtr(&fixture.request));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(u16, 0), reply.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
    try std.testing.expectEqual(@as(usize, 1), fixture.reads);
    try std.testing.expectEqual(@as(usize, 0), fixture.outputs);
    try std.testing.expectEqual(@as(usize, 1), fixture.wakes);
    try std.testing.expectEqual(@as(usize, 1), fixture.reentries);
    try fixture.expectRetired();
    try std.testing.expectEqual(grants - 3, base.capabilities.activeCount());
    try std.testing.expectEqual(@as(usize, 1), base.endpoints.activeCount());
    try std.testing.expectEqual(@as(usize, 2), base.shared.activeCount());
    try std.testing.expectEqual(TestFixture.task_runtime.TaskState.active, task.state);
    try std.testing.expect(base.runtime.findAddressSpaceConst(address_space) != null);
    try std.testing.expectEqual(@as(u8, 1), base.runtime.task_borrow_counts[task.arena_slot_index]);
    try std.testing.expect(std.meta.eql(original_port, base.port));
    try std.testing.expectEqual(@as(u64, 0), fixture.request.endpoint_capability_id);
    fixture.request = original_request;
    fixture.behavior = .copy;
    const generation = base.capabilities.mutationGeneration();
    const first_key = base.keys[EndpointFixture.receiver_cpu].?;
    const repeated = try fixture.roundTrip(@intFromPtr(&fixture.request));
    try std.testing.expect(base.keys[EndpointFixture.receiver_cpu].?.sequence > first_key.sequence);
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.not_found))), repeated.status);
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.DenialReason.capability_missing))), repeated.denial_reason);
    try std.testing.expectEqual(generation, base.capabilities.mutationGeneration());
    try std.testing.expectEqual(@as(usize, 1), fixture.wakes);
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const queued = (try base.endpoints.recvInto(TestFixture.ids.endpoint(fixture.endpoint_fixture.source()), &payload)).?;
    try std.testing.expectEqual(@as(u64, 91), queued.correlation_id);
    try std.testing.expectEqualSlices(u8, "surviving reply", payload[0..queued.len]);
    try std.testing.expectError(error.PeerClosed, base.endpoints.recvInto(TestFixture.ids.endpoint(fixture.endpoint_fixture.source()), &payload));
}

test "syscall broker close malformed staging and denied authority preserve complete queues and grants" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try CloseFixture.create();
    defer fixture.destroy();
    const endpoint_fixture = fixture.endpoint_fixture;
    const base = &endpoint_fixture.base;
    const receiver = base.tasks[EndpointFixture.receiver_cpu].?;
    const expired = try base.capabilities.mintBootRoot(.{
        .holder = receiver.owner,
        .issuer = base.kernel.policy_authority,
        .target = .{ .kind = .endpoint, .id = endpoint_fixture.destination() },
        .rights = .{ .endpoint = .{ .endpoint_close = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 18 },
    });
    try base.runtime.grantCapability(receiver.id, expired.id);
    const original = fixture.request;
    const snapshot = try EndpointFixture.Snapshot.capture(endpoint_fixture);
    defer snapshot.deinit();
    const Case = enum { floor, alignment, overflow, canonical_tail, high, inaccessible, partial, absent_subject, foreign_subject, opcode, flags, missing, foreign_capability, denied_right, expired, reenter };
    for (std.meta.tags(Case)) |case| {
        fixture.request = original;
        fixture.behavior = .copy;
        var address = @intFromPtr(&fixture.request);
        var status: abi.SyscallStatus = .invalid_request_pointer;
        var reason: abi.DenialReason = .invalid_target;
        var reads: usize = 1;
        switch (case) {
            .floor => {
                address = 0xfff8;
                reads = 0;
            },
            .alignment => {
                address += 1;
                reads = 0;
            },
            .overflow => {
                address = std.math.maxInt(usize) - 7;
                reads = 0;
            },
            .canonical_tail => {
                address = 0x0000_8000_0000_0000 - 8;
                reads = 0;
            },
            .high => {
                address = 0xffff_8000_0000_0000;
                reads = 0;
            },
            .inaccessible => address = 0x1fff8,
            .partial => fixture.behavior = .partial,
            .absent_subject => fixture.request.header.subject_task_id = 0,
            .foreign_subject => fixture.request.header.subject_task_id = base.tasks[EndpointFixture.sender_cpu].?.id,
            .opcode => {
                fixture.request.header.operation = abi.opcode(.endpoint_send);
                status = .unsupported_operation;
                reason = .unsupported_operation;
            },
            .flags => fixture.request.header.flags = 1,
            .missing, .foreign_capability => {
                fixture.request.endpoint_capability_id = if (case == .missing) std.math.maxInt(u64) else endpoint_fixture.send_capability;
                status = .not_found;
                reason = .capability_missing;
            },
            .denied_right => {
                fixture.request.endpoint_capability_id = endpoint_fixture.recv_capability;
                status = .denied;
                reason = .policy_denied;
            },
            .expired => {
                fixture.request.endpoint_capability_id = expired.id;
                status = .denied;
                reason = .capability_revoked;
            },
            .reenter => {
                fixture.behavior = .reenter;
                fixture.request.endpoint_capability_id = std.math.maxInt(u64);
                status = .not_found;
                reason = .capability_missing;
            },
        }
        const before_reads = fixture.reads;
        const reply = try fixture.roundTrip(address);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(status))), reply.status);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(reason))), reply.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(before_reads + reads, fixture.reads);
        try snapshot.expectUnchanged(endpoint_fixture);
        try std.testing.expect(base.capabilities.query(fixture.moved_gift) != null);
        try std.testing.expectEqual(@as(usize, 0), fixture.outputs);
        try std.testing.expectEqual(@as(usize, 0), fixture.wakes);
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.reentries);
}

test "syscall broker close cancellation and revoked sibling authority preserve queued gifts" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try CloseFixture.create();
    defer fixture.destroy();
    const endpoint_fixture = fixture.endpoint_fixture;
    const base = &endpoint_fixture.base;
    const key = try fixture.submit(@intFromPtr(&fixture.request));
    cpu_identity.setIndexForTest(key.ticket.cpu);
    try std.testing.expect(base.runtime.execution.cancelPendingSyscall(key));
    cpu_identity.setIndexForTest(0);
    var claim: dispatch_ownership.ClaimedSyscall = undefined;
    try std.testing.expectError(error.NoRequest, base.claimInto(key.ticket.cpu, &claim));
    try std.testing.expectEqual(@as(usize, 0), fixture.reads);
    // Revoking one target authority invalidates surviving siblings by epoch.
    try base.capabilities.revokeTargetAuthority(endpoint_fixture.recv_capability);
    const snapshot = try EndpointFixture.Snapshot.capture(endpoint_fixture);
    defer snapshot.deinit();
    const reply = try fixture.roundTrip(@intFromPtr(&fixture.request));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.denied))), reply.status);
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.DenialReason.capability_revoked))), reply.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
    try snapshot.expectUnchanged(endpoint_fixture);
    try std.testing.expect(base.capabilities.query(fixture.moved_gift) != null);
    try std.testing.expectEqual(@as(usize, 0), fixture.outputs);
    try std.testing.expectEqual(@as(usize, 0), fixture.wakes);
}

test "syscall broker close STOP before commit preserves resources and wake termination pins them until ACK" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]bool{ false, true }) |during_copy| {
        const fixture = try CloseFixture.create();
        defer fixture.destroy();
        const base = &fixture.endpoint_fixture.base;
        const snapshot = try EndpointFixture.Snapshot.capture(fixture.endpoint_fixture);
        defer snapshot.deinit();
        const key = try fixture.submit(@intFromPtr(&fixture.request));
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try base.claimInto(EndpointFixture.receiver_cpu, &claim);
        if (during_copy) fixture.behavior = .stop else try base.runtime.requestExecutionStop(key.ticket);
        const copy = fixture.session(&claim);
        try serviceClaim(&base.port, &claim, &copy, 19);
        var reply: dispatch_ownership.Reply = undefined;
        try base.consume(key, &reply);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.unavailable))), reply.status);
        try std.testing.expectEqual(@as(usize, @intFromBool(during_copy)), fixture.reads);
        try snapshot.expectUnchanged(fixture.endpoint_fixture);
        try std.testing.expectEqual(@as(usize, 0), fixture.wakes);
        try std.testing.expectEqual(@as(usize, 0), fixture.outputs);
    }
    const fixture = try CloseFixture.create();
    defer fixture.destroy();
    const base = &fixture.endpoint_fixture.base;
    const receiver = base.tasks[EndpointFixture.receiver_cpu].?;
    const address_space = receiver.address_space_id;
    const termination_capability = base.requests[EndpointFixture.receiver_cpu].task_capability_id;
    fixture.terminate_on_wake = true;
    const reply = try fixture.roundTrip(@intFromPtr(&fixture.request));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
    try std.testing.expectEqual(TestFixture.task_runtime.TaskState.terminated, receiver.state);
    try std.testing.expectEqual(@as(u8, 1), base.runtime.task_borrow_counts[receiver.arena_slot_index]);
    try std.testing.expect(base.runtime.findAddressSpaceConst(address_space) != null);
    try std.testing.expect(base.capabilities.query(termination_capability) != null);
    try std.testing.expectEqual(@as(usize, 2), base.shared.activeCount());
    const key = base.keys[EndpointFixture.receiver_cpu].?;
    cpu_identity.setIndexForTest(key.ticket.cpu);
    try std.testing.expect(base.runtime.execution.stopRequested(key.ticket));
    cpu_identity.setIndexForTest(0);
    try std.testing.expectError(error.WrongPhase, base.runtime.collectExecution(key.ticket));
    cpu_identity.setIndexForTest(key.ticket.cpu);
    var duplicate: dispatch_ownership.Reply = undefined;
    try std.testing.expectError(error.StaleRequest, base.runtime.execution.consumeSyscallInto(key, &duplicate));
    try base.runtime.execution.acknowledgeOwnedRootReturn(key.ticket);
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(base.capabilities.query(termination_capability) != null);
    try base.runtime.collectExecution(key.ticket);
    base.keys[EndpointFixture.receiver_cpu] = null;
    base.tickets[EndpointFixture.receiver_cpu] = null;
    try std.testing.expect(base.runtime.findAddressSpaceConst(address_space) == null);
    try std.testing.expect(base.capabilities.query(termination_capability) == null);
    try std.testing.expectEqual(@as(usize, 1), base.shared.activeCount());
    try std.testing.expectEqual(@as(usize, 1), fixture.wakes);
    try std.testing.expectEqual(@as(usize, 1), fixture.reentries);
}

const ReceiveFixture = if (builtin.is_test) struct {
    const Behavior = enum { copy, erase_fixed, partial_fixed, stop_fixed, deny_prepare, stop_prepare, fail_write, stop_write, reenter_write };
    endpoint_fixture: *EndpointFixture,
    wire: abi.EndpointRecvWireRequest = undefined,
    output: [512]u8 align(8) = @splat(0xa5),
    response_len: usize = @sizeOf(abi.EndpointRecvResponse),
    request_address: usize = 0,
    behavior: Behavior = .copy,
    fault_prepare: usize = 3,
    reads: usize = 0,
    prepares: usize = 0,
    writes: usize = 0,
    reentries: usize = 0,
    declared_response: usize = 0,
    prepared_response: usize = 0,

    fn create() !*@This() {
        const endpoint_fixture = try EndpointFixture.create();
        errdefer endpoint_fixture.destroy();
        const self = try std.testing.allocator.create(@This());
        self.* = .{ .endpoint_fixture = endpoint_fixture };
        self.wire = .{
            .header = component_port.makeHeader(.endpoint_recv, self.receiver().id),
            .endpoint_capability_id = endpoint_fixture.recv_capability,
            .receiver_task_id = self.receiver().id,
            .payload_address = @intFromPtr(&self.output[160]),
            .payload_capacity = endpoint.MAX_MESSAGE_BYTES,
            .attached_capability_address = @intFromPtr(&self.output[256]),
        };
        self.request_address = @intFromPtr(&self.wire);
        return self;
    }

    fn destroy(self: *@This()) void {
        self.endpoint_fixture.destroy();
        std.testing.allocator.destroy(self);
    }

    fn receiver(self: *@This()) *TestFixture.task_runtime.TaskRecord {
        return self.endpoint_fixture.base.tasks[EndpointFixture.receiver_cpu].?;
    }

    fn enqueue(self: *@This(), moved: bool, has_attachment: bool) !void {
        const fixture = self.endpoint_fixture;
        try fixture.base.kernel.endpointSend(.{
            .caller_task_id = fixture.base.tasks[EndpointFixture.sender_cpu].?.id,
            .presented_capability_id = fixture.send_capability,
            .target = .none,
        }, 77, &fixture.payload, 0, if (has_attachment) fixture.gift else null, moved, 18);
    }

    fn session(self: *@This(), claim: *const dispatch_ownership.ClaimedSyscall) CopySession {
        return .{ .context = self, .key = claim.key, .bound = claim.bound, .read = read, .prepare_output = prepare, .write_outputs = write };
    }

    fn roundTrip(self: *@This()) !dispatch_ownership.Reply {
        const base = &self.endpoint_fixture.base;
        const key = try base.submitEnvelope(EndpointFixture.receiver_cpu, .{
            .opcode = abi.opcode(.endpoint_recv),
            .request_addr = self.request_address,
            .response_addr = @intFromPtr(&self.output[0]),
            .response_len = self.response_len,
        });
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try base.claimInto(EndpointFixture.receiver_cpu, &claim);
        const copy = self.session(&claim);
        try serviceClaim(&base.port, &claim, &copy, 19);
        try std.testing.expectError(error.WrongPhase, serviceClaim(&base.port, &claim, &copy, 20));
        cpu_identity.setIndexForTest(key.ticket.cpu);
        try std.testing.expectError(error.SyscallInFlight, base.runtime.execution.acknowledgeOwnedRootReturn(key.ticket));
        cpu_identity.setIndexForTest(0);
        var reply: dispatch_ownership.Reply = undefined;
        try base.consume(key, &reply);
        return reply;
    }

    fn read(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, destination: []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (address != self.request_address or destination.len != @sizeOf(abi.EndpointRecvWireRequest)) return false;
        self.reads += 1;
        const source = if (address == @intFromPtr(&self.wire)) std.mem.asBytes(&self.wire) else self.output[0..@sizeOf(abi.EndpointRecvWireRequest)];
        if (self.behavior == .partial_fixed) {
            @memcpy(destination[0..8], source[0..8]);
            return false;
        }
        @memcpy(destination, source);
        if (self.behavior == .erase_fixed) @memset(source, 0);
        if (self.behavior == .stop_fixed) self.endpoint_fixture.base.runtime.requestExecutionStop(claim.key.ticket) catch unreachable;
        return true;
    }

    fn outputOffset(self: *@This(), address: usize, length: usize) ?usize {
        const base = @intFromPtr(&self.output);
        if (address < base) return null;
        const offset = address - base;
        if (offset > self.output.len or length > self.output.len - offset) return null;
        return offset;
    }

    fn prepare(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, range: OutputRange) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.prepares += 1;
        if (range.address == @intFromPtr(&self.output)) {
            self.declared_response = range.declared_bytes;
            self.prepared_response = range.prepared_bytes;
        }
        if (self.prepares == self.fault_prepare) {
            if (self.behavior == .deny_prepare) return false;
            if (self.behavior == .stop_prepare) self.endpoint_fixture.base.runtime.requestExecutionStop(claim.key.ticket) catch unreachable;
        }
        return self.outputOffset(range.address, range.declared_bytes) != null and range.prepared_bytes <= range.declared_bytes;
    }

    fn write(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, outputs: []const Output) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.writes += 1;
        if (self.behavior == .fail_write) return false;
        if (self.behavior == .stop_write) {
            self.endpoint_fixture.base.runtime.requestExecutionStop(claim.key.ticket) catch unreachable;
            return false;
        }
        if (self.behavior == .reenter_write) {
            const copy = self.session(claim);
            std.testing.expectError(error.ReentrantService, serviceClaim(&self.endpoint_fixture.base.port, claim, &copy, 20)) catch @panic("output commit cannot reenter the broker");
            self.reentries += 1;
        }
        for (outputs) |output| if (self.outputOffset(output.address, output.bytes.len) == null) return false;
        for (outputs) |output| {
            const offset = self.outputOffset(output.address, output.bytes.len).?;
            @memcpy(self.output[offset..][0..output.bytes.len], output.bytes);
        }
        return true;
    }

    fn response(self: *@This()) abi.EndpointRecvResponse {
        return @as(*const abi.EndpointRecvResponse, @ptrCast(@alignCast(&self.output[0]))).*;
    }

    fn attached(self: *@This()) abi.CapabilityDescriptor {
        return @as(*const abi.CapabilityDescriptor, @ptrCast(@alignCast(&self.output[256]))).*;
    }
} else struct {};

test "syscall broker receive stages deterministic outputs and transfers copied or moved grants once" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]bool{ false, true }) |moved| {
        const fixture = try ReceiveFixture.create();
        defer fixture.destroy();
        const endpoint_fixture = fixture.endpoint_fixture;
        const original_port = endpoint_fixture.base.port;
        try fixture.enqueue(moved, true);
        const grants = endpoint_fixture.base.capabilities.activeCount();
        const receiver_caps = fixture.receiver().capability_count;
        fixture.response_len = 128;
        fixture.behavior = .erase_fixed;
        const reply = try fixture.roundTrip();
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
        try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), reply.bytes_written);
        try std.testing.expectEqual(@as(usize, 1), fixture.reads);
        try std.testing.expectEqual(@as(usize, 3), fixture.prepares);
        try std.testing.expectEqual(@as(usize, 1), fixture.writes);
        try std.testing.expectEqual(@as(usize, 128), fixture.declared_response);
        try std.testing.expectEqual(@as(usize, 56), fixture.prepared_response);
        const response = fixture.response();
        const attached = fixture.attached();
        try std.testing.expectEqual(@as(u8, 1), response.present);
        try std.testing.expectEqual(@as(u8, 1), response.has_attached_capability);
        try std.testing.expectEqual(endpoint_fixture.base.tasks[EndpointFixture.sender_cpu].?.id, response.message.sender_task_id);
        try std.testing.expectEqual(@as(u64, 77), response.message.correlation_id);
        try std.testing.expectEqual(endpoint_fixture.gift, response.message.attached_capability_id);
        try std.testing.expectEqual(@as(u16, endpoint.MAX_MESSAGE_BYTES), response.message.payload_len);
        try std.testing.expectEqualSlices(u8, &endpoint_fixture.payload, fixture.output[160..248]);
        try std.testing.expectEqual(@as(u32, 0), response.message._reserved);
        try std.testing.expectEqualSlices(u8, &@as([6]u8, @splat(0)), &response._reserved);
        try std.testing.expectEqual(@as(u32, 0), attached._reserved_generation);
        try std.testing.expectEqual(@as(u32, 0), attached._reserved_tail);
        try std.testing.expectEqual(fixture.receiver().id, attached.scope_task_id);
        try std.testing.expect(fixture.receiver().hasCapability(attached.capability_id));
        try std.testing.expect(attached.capability_id != endpoint_fixture.gift);
        try std.testing.expectEqual(receiver_caps + 1, fixture.receiver().capability_count);
        try std.testing.expectEqual(grants + @as(usize, if (moved) 0 else 1), endpoint_fixture.base.capabilities.activeCount());
        try std.testing.expectEqual(!moved, endpoint_fixture.base.capabilities.query(endpoint_fixture.gift) != null);
        try std.testing.expect(std.meta.eql(original_port, endpoint_fixture.base.port));
        for (fixture.output, 0..) |byte, index| {
            if (index < 56 or (index >= 160 and index < 248) or (index >= 256 and index < 320)) continue;
            try std.testing.expectEqual(@as(u8, 0xa5), byte);
        }
        try std.testing.expect(!endpoint_fixture.base.endpoints.hasPendingForTask(TestFixture.ids.task(fixture.receiver().id)));
    }
}

test "syscall broker empty receive writes only its zero response and ignores an empty payload address" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try ReceiveFixture.create();
    defer fixture.destroy();
    fixture.wire.payload_capacity = 0;
    fixture.wire.payload_address = std.math.maxInt(u64);
    const before_grants = fixture.endpoint_fixture.base.capabilities.activeCount();
    const reply = try fixture.roundTrip();
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(u32, 56), reply.bytes_written);
    try std.testing.expectEqual(@as(usize, 2), fixture.prepares);
    try std.testing.expectEqual(@as(usize, 1), fixture.writes);
    try std.testing.expectEqualSlices(u8, &@as([56]u8, @splat(0)), fixture.output[0..56]);
    try std.testing.expectEqualSlices(u8, &@as([456]u8, @splat(0xa5)), fixture.output[56..]);
    try std.testing.expectEqual(before_grants, fixture.endpoint_fixture.base.capabilities.activeCount());
}

test "syscall broker receive rejects malformed identity geometry and advertised overlap before output callbacks" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try ReceiveFixture.create();
    defer fixture.destroy();
    try fixture.enqueue(false, true);
    const original = fixture.wire;
    const snapshot = try EndpointFixture.Snapshot.capture(fixture.endpoint_fixture);
    defer snapshot.deinit();
    const Case = enum { operation, flags, reserved, subject, receiver, capacity, short_response, overflow_response, payload_floor, payload_overflow, payload_high, capability_floor, capability_alignment, capability_overflow, capability_high, response_payload, response_capability, payload_capability, advertised_tail, partial_fixed };
    for (std.enums.values(Case)) |case| {
        fixture.wire = original;
        fixture.response_len = 56;
        fixture.behavior = .copy;
        switch (case) {
            .operation => fixture.wire.header.operation = abi.opcode(.endpoint_send),
            .flags => fixture.wire.header.flags = 1,
            .reserved => fixture.wire.reserved = 1,
            .subject => fixture.wire.header.subject_task_id += 1,
            .receiver => fixture.wire.receiver_task_id += 1,
            .capacity => fixture.wire.payload_capacity += 1,
            .short_response => fixture.response_len = 55,
            .overflow_response => fixture.response_len = std.math.maxInt(usize),
            .payload_floor => fixture.wire.payload_address = 0xfff8,
            .payload_overflow => fixture.wire.payload_address = std.math.maxInt(u64) - 16,
            .payload_high => fixture.wire.payload_address = 0x0000_8000_0000_0000 - 16,
            .capability_floor => fixture.wire.attached_capability_address = 0,
            .capability_alignment => fixture.wire.attached_capability_address += 1,
            .capability_overflow => fixture.wire.attached_capability_address = std.math.maxInt(u64) - 7,
            .capability_high => fixture.wire.attached_capability_address = 0x0000_8000_0000_0000 - 32,
            .response_payload => fixture.wire.payload_address = @intFromPtr(&fixture.output[8]),
            .response_capability => fixture.wire.attached_capability_address = @intFromPtr(&fixture.output[16]),
            .payload_capability => fixture.wire.attached_capability_address = @intFromPtr(&fixture.output[168]),
            .advertised_tail => fixture.response_len = 200,
            .partial_fixed => fixture.behavior = .partial_fixed,
        }
        const reply = try fixture.roundTrip();
        const expected: abi.SyscallStatus = switch (case) {
            .operation, .flags, .reserved, .subject, .receiver, .capacity, .partial_fixed => .invalid_request_pointer,
            .short_response => .buffer_too_small,
            else => .invalid_response_buffer,
        };
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(expected))), reply.status);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(@as(usize, 0), fixture.prepares);
        try std.testing.expectEqual(@as(usize, 0), fixture.writes);
        try std.testing.expectEqualSlices(u8, &@as([512]u8, @splat(0xa5)), &fixture.output);
        try snapshot.expectUnchanged(fixture.endpoint_fixture);
    }
}

test "syscall broker receive output preparation and short payload preserve queue and permit exact retry" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try ReceiveFixture.create();
    defer fixture.destroy();
    try fixture.enqueue(true, true);
    const snapshot = try EndpointFixture.Snapshot.capture(fixture.endpoint_fixture);
    defer snapshot.deinit();
    for (1..4) |fault| {
        fixture.prepares = 0;
        fixture.fault_prepare = fault;
        fixture.behavior = .deny_prepare;
        const reply = try fixture.roundTrip();
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.invalid_response_buffer))), reply.status);
        try std.testing.expectEqual(fault, fixture.prepares);
        try std.testing.expectEqual(@as(usize, 0), fixture.writes);
        try snapshot.expectUnchanged(fixture.endpoint_fixture);
    }
    fixture.behavior = .copy;
    fixture.wire.payload_capacity -= 1;
    const short = try fixture.roundTrip();
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.buffer_too_small))), short.status);
    try std.testing.expectEqual(@as(usize, 0), fixture.writes);
    try snapshot.expectUnchanged(fixture.endpoint_fixture);
    fixture.wire.payload_capacity += 1;
    const accepted = try fixture.roundTrip();
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), accepted.status);
    try std.testing.expectEqual(@as(u8, 1), fixture.response().present);
    const attached = fixture.attached();
    try std.testing.expect(fixture.receiver().hasCapability(attached.capability_id));
    try std.testing.expect(fixture.endpoint_fixture.base.capabilities.query(fixture.endpoint_fixture.gift) == null);
    @memset(&fixture.output, 0xa5);
    const empty = try fixture.roundTrip();
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), empty.status);
    try std.testing.expectEqual(@as(u8, 0), fixture.response().present);
    try std.testing.expectEqualSlices(u8, &@as([456]u8, @splat(0xa5)), fixture.output[56..]);
}

test "syscall broker receive keeps ordinary Kernel capability authorization before dequeue" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try ReceiveFixture.create();
    defer fixture.destroy();
    try fixture.enqueue(true, true);
    const endpoint_fixture = fixture.endpoint_fixture;
    const snapshot = try EndpointFixture.Snapshot.capture(endpoint_fixture);
    defer snapshot.deinit();
    const cases = [_]struct { id: u64, status: abi.SyscallStatus, reason: abi.DenialReason }{
        .{ .id = std.math.maxInt(u64), .status = .not_found, .reason = .capability_missing },
        .{ .id = endpoint_fixture.send_capability, .status = .not_found, .reason = .capability_missing },
        .{ .id = endpoint_fixture.base.requests[EndpointFixture.receiver_cpu].task_capability_id, .status = .denied, .reason = .policy_denied },
    };
    for (cases) |case| {
        fixture.wire.endpoint_capability_id = case.id;
        const reply = try fixture.roundTrip();
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(case.status))), reply.status);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(case.reason))), reply.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(@as(usize, 0), fixture.writes);
        try std.testing.expectEqualSlices(u8, &@as([512]u8, @splat(0xa5)), &fixture.output);
        try snapshot.expectUnchanged(endpoint_fixture);
    }
}

test "syscall broker receive STOP around staging and output never retries a consumed moved grant" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]ReceiveFixture.Behavior{ .stop_fixed, .stop_prepare, .fail_write, .stop_write }) |behavior| {
        const fixture = try ReceiveFixture.create();
        defer fixture.destroy();
        try fixture.enqueue(true, true);
        const before_caps = fixture.receiver().capability_count;
        fixture.behavior = behavior;
        const reply = try fixture.roundTrip();
        const consumed = behavior == .fail_write or behavior == .stop_write;
        const status: abi.SyscallStatus = if (behavior == .fail_write) .invalid_response_buffer else .unavailable;
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(status))), reply.status);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqualSlices(u8, &@as([512]u8, @splat(0xa5)), &fixture.output);
        try std.testing.expectEqual(before_caps + @as(u8, if (consumed) 1 else 0), fixture.receiver().capability_count);
        try std.testing.expectEqual(!consumed, fixture.endpoint_fixture.base.endpoints.hasPendingForTask(TestFixture.ids.task(fixture.receiver().id)));
        try std.testing.expectEqual(!consumed, fixture.endpoint_fixture.base.capabilities.query(fixture.endpoint_fixture.gift) != null);
        if (behavior == .fail_write) {
            fixture.behavior = .copy;
            const empty = try fixture.roundTrip();
            try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), empty.status);
            try std.testing.expectEqual(@as(u8, 0), fixture.response().present);
            try std.testing.expectEqual(before_caps + 1, fixture.receiver().capability_count);
        }
    }
}

test "syscall broker receive permits input response reuse and rejects output callback service reentry" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try ReceiveFixture.create();
    defer fixture.destroy();
    try fixture.enqueue(false, false);
    @memcpy(fixture.output[0..@sizeOf(abi.EndpointRecvWireRequest)], std.mem.asBytes(&fixture.wire));
    fixture.request_address = @intFromPtr(&fixture.output[0]);
    fixture.behavior = .reenter_write;
    const reply = try fixture.roundTrip();
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(usize, 1), fixture.reentries);
    try std.testing.expectEqual(@as(u8, 1), fixture.response().present);
    try std.testing.expectEqual(@as(u8, 0), fixture.response().has_attached_capability);
    try std.testing.expectEqualSlices(u8, &fixture.endpoint_fixture.payload, fixture.output[160..248]);
    try std.testing.expectEqualSlices(u8, &@as([64]u8, @splat(0xa5)), fixture.output[256..320]);
}

test "syscall broker copies all CPU termination requests once and pins real Kernel resources until consume and ACK" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try std.testing.allocator.create(TestFixture);
    defer std.testing.allocator.destroy(fixture);
    fixture.* = .{};
    fixture.init();
    defer fixture.deinit();
    for (0..cpu_identity.MAX_CPUS) |cpu| try fixture.add(@intCast(cpu));
    fixture.behavior = .erase;
    const saved_port = fixture.port;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const cpu: u8 = @intCast(index);
        const task = fixture.tasks[index].?;
        const address_space = task.address_space_id;
        const authority = fixture.requests[index].task_capability_id;
        const before_grants = fixture.capabilities.activeCount();
        const before_endpoints = fixture.endpoints.activeCount();
        const before_shared = fixture.shared.activeCount();
        const key = try fixture.submit(cpu, abi.opcode(.task_terminate));
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try fixture.claimInto(cpu, &claim);
        const copy = fixture.session(&claim);
        try serviceClaim(&fixture.port, &claim, &copy, 19);
        try std.testing.expectEqual(TestFixture.task_runtime.TaskState.terminated, task.state);
        try std.testing.expectEqual(@as(u64, 0), fixture.requests[index].task_capability_id);
        try std.testing.expectEqual(index + 1, fixture.reads);
        try std.testing.expect(std.meta.eql(saved_port, fixture.port));
        try std.testing.expectEqual(before_grants, fixture.capabilities.activeCount());
        try std.testing.expectEqual(before_endpoints, fixture.endpoints.activeCount());
        try std.testing.expectEqual(before_shared, fixture.shared.activeCount());
        try std.testing.expect(fixture.capabilities.query(authority) != null);
        try std.testing.expect(fixture.runtime.findAddressSpaceConst(address_space) != null);
        try std.testing.expectEqual(@as(u8, 1), fixture.runtime.task_borrow_counts[task.arena_slot_index]);
        try std.testing.expectError(error.WrongPhase, serviceClaim(&fixture.port, &claim, &copy, 20));
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expectError(error.SyscallInFlight, fixture.runtime.execution.acknowledgeOwnedRootReturn(key.ticket));
        cpu_identity.setIndexForTest(0);
        try std.testing.expectError(error.WrongPhase, fixture.runtime.collectExecution(key.ticket));
        var reply: dispatch_ownership.Reply = undefined;
        try fixture.consume(key, &reply);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
        try std.testing.expectEqual(@as(u16, 0), reply.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(before_grants, fixture.capabilities.activeCount());
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(fixture.runtime.execution.stopRequested(key.ticket));
        try std.testing.expectError(error.StaleRequest, fixture.runtime.execution.consumeSyscallInto(key, &reply));
        try fixture.runtime.execution.acknowledgeOwnedRootReturn(key.ticket);
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(before_grants, fixture.capabilities.activeCount());
        try fixture.runtime.collectExecution(key.ticket);
        fixture.tickets[index] = null;
        fixture.keys[index] = null;
        try std.testing.expectEqual(before_grants - 1, fixture.capabilities.activeCount());
        try std.testing.expectEqual(before_endpoints - 1, fixture.endpoints.activeCount());
        try std.testing.expectEqual(before_shared - 1, fixture.shared.activeCount());
        try std.testing.expect(fixture.capabilities.query(authority) == null);
        try std.testing.expect(fixture.runtime.findAddressSpaceConst(address_space) == null);
        try std.testing.expectError(error.StaleTicket, fixture.runtime.collectExecution(key.ticket));
    }
}

test "syscall broker malformed copied headers denied capabilities and unsupported operations preserve authority" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try std.testing.allocator.create(TestFixture);
    defer std.testing.allocator.destroy(fixture);
    fixture.* = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.add(3);
    try fixture.add(4);
    const task = fixture.tasks[3].?;
    const query_only = try fixture.capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = fixture.kernel.policy_authority,
        .target = .{ .kind = .task, .id = task.id },
        .rights = .{ .task = .{ .task_create = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    try fixture.runtime.grantCapability(task.id, query_only.id);
    const original_request = fixture.requests[3];
    const saved_task = task.*;
    const saved_port = fixture.port;
    const grants = fixture.capabilities.activeCount();
    const generation = fixture.capabilities.mutationGeneration();
    const cases = [_]enum { unsupported, header_operation, header_subject, foreign_capability, denied_right, missing_capability, partial_copy, reenter }{ .unsupported, .header_operation, .header_subject, .foreign_capability, .denied_right, .missing_capability, .partial_copy, .reenter };
    for (cases) |case| {
        fixture.requests[3] = original_request;
        fixture.behavior = .copy;
        switch (case) {
            .header_operation => fixture.requests[3].header.operation = abi.opcode(.endpoint_close),
            .header_subject => fixture.requests[3].header.subject_task_id = 0,
            .foreign_capability => fixture.requests[3].task_capability_id = fixture.requests[4].task_capability_id,
            .denied_right => fixture.requests[3].task_capability_id = query_only.id,
            .missing_capability, .reenter => fixture.requests[3].task_capability_id = std.math.maxInt(u64),
            .partial_copy => fixture.behavior = .partial,
            else => {},
        }
        if (case == .reenter) fixture.behavior = .reenter;
        const before_reads = fixture.reads;
        const key = try fixture.submit(3, abi.opcode(if (case == .unsupported) .time_query else .task_terminate));
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try fixture.claimInto(3, &claim);
        const copy = fixture.session(&claim);
        try serviceClaim(&fixture.port, &claim, &copy, 19);
        var reply: dispatch_ownership.Reply = undefined;
        try fixture.consume(key, &reply);
        const expected: abi.SyscallStatus = switch (case) {
            .unsupported, .header_operation => .unsupported_operation,
            .header_subject, .denied_right => .denied,
            .foreign_capability, .missing_capability, .reenter => .not_found,
            .partial_copy => .invalid_request_pointer,
        };
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(expected))), reply.status);
        const reason: abi.DenialReason = switch (case) {
            .unsupported, .header_operation => .unsupported_operation,
            .header_subject => .scope_violation,
            .denied_right => .policy_denied,
            .foreign_capability, .missing_capability, .reenter => .capability_missing,
            .partial_copy => .invalid_target,
        };
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(reason))), reply.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(before_reads + @as(usize, if (case == .unsupported) 0 else 1), fixture.reads);
        try std.testing.expect(std.meta.eql(saved_task, task.*));
        try std.testing.expect(std.meta.eql(saved_port, fixture.port));
        try std.testing.expectEqual(grants, fixture.capabilities.activeCount());
        try std.testing.expectEqual(generation, fixture.capabilities.mutationGeneration());
        try std.testing.expectEqual(@as(usize, 2), fixture.endpoints.activeCount());
        try std.testing.expectEqual(@as(usize, 2), fixture.shared.activeCount());
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.nested_rejections);
}

test "syscall broker rejects fixed request geometry before its trusted copy callback" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try std.testing.allocator.create(TestFixture);
    defer std.testing.allocator.destroy(fixture);
    fixture.* = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.add(3);
    const saved_task = fixture.tasks[3].?.*;
    const saved_request = fixture.requests[3];
    const saved_port = fixture.port;
    const generation = fixture.capabilities.mutationGeneration();
    const addresses = [_]usize{
        0,
        0xfff8,
        @intFromPtr(&fixture.requests[3]) + 1,
        std.math.maxInt(usize) - 7,
        0x0000_8000_0000_0000 - 8,
        0xffff_8000_0000_0000,
    };
    for (addresses) |address| {
        const key = try fixture.submitEnvelope(3, .{
            .opcode = abi.opcode(.task_terminate),
            .request_addr = address,
            .response_addr = 0,
            .response_len = 0,
        });
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try fixture.claimInto(3, &claim);
        const copy = fixture.session(&claim);
        try serviceClaim(&fixture.port, &claim, &copy, 19);
        var reply: dispatch_ownership.Reply = undefined;
        try fixture.consume(key, &reply);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.invalid_request_pointer))), reply.status);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.DenialReason.invalid_target))), reply.denial_reason);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(@as(usize, 0), fixture.reads);
        try std.testing.expect(std.meta.eql(saved_task, fixture.tasks[3].?.*));
        try std.testing.expect(std.meta.eql(saved_request, fixture.requests[3]));
        try std.testing.expect(std.meta.eql(saved_port, fixture.port));
        try std.testing.expectEqual(generation, fixture.capabilities.mutationGeneration());
        try std.testing.expectEqual(@as(usize, 1), fixture.endpoints.activeCount());
        try std.testing.expectEqual(@as(usize, 1), fixture.shared.activeCount());
    }
}

test "syscall broker authenticates processing receipt and copy session before reading or invoking" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try std.testing.allocator.create(TestFixture);
    defer std.testing.allocator.destroy(fixture);
    fixture.* = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.add(3);
    const task_before = fixture.tasks[3].?.*;
    const key = try fixture.submit(3, abi.opcode(.task_terminate));
    var claim: dispatch_ownership.ClaimedSyscall = undefined;
    try fixture.claimInto(3, &claim);
    const copy = fixture.session(&claim);
    cpu_identity.setIndexForTest(3);
    try std.testing.expectError(error.WrongCpu, serviceClaim(&fixture.port, &claim, &copy, 19));
    cpu_identity.setIndexForTest(0);
    try std.testing.expectError(error.InterruptsEnabled, serviceClaimWith(&fixture.port, &claim, &copy, 19, true));
    var wrong_claim = claim;
    wrong_claim.envelope.request_addr += 8;
    try std.testing.expectError(error.StaleRequest, serviceClaim(&fixture.port, &wrong_claim, &copy, 19));
    wrong_claim = claim;
    wrong_claim.bound.physical_root += 4096;
    try std.testing.expectError(error.StaleRequest, serviceClaim(&fixture.port, &wrong_claim, &copy, 19));
    var wrong_copy = copy;
    wrong_copy.bound.mapping_handle += 1;
    try std.testing.expectError(error.InvalidCopySession, serviceClaim(&fixture.port, &claim, &wrong_copy, 19));
    wrong_copy = copy;
    wrong_copy.key.sequence += 1;
    try std.testing.expectError(error.InvalidCopySession, serviceClaim(&fixture.port, &claim, &wrong_copy, 19));
    var foreign: dispatch_ownership.Coordinator = .{};
    wrong_claim = claim;
    wrong_claim.key.ticket.issuer = &foreign;
    try std.testing.expectError(error.WrongCoordinator, serviceClaim(&fixture.port, &wrong_claim, &copy, 19));
    const borrow = fixture.runtime.execution_borrows[3];
    fixture.runtime.execution_borrows[3] = null;
    try std.testing.expectError(error.InvalidIdentity, serviceClaim(&fixture.port, &claim, &copy, 19));
    fixture.runtime.execution_borrows[3] = borrow;
    try std.testing.expectEqual(@as(usize, 0), fixture.reads);
    try std.testing.expect(std.meta.eql(task_before, fixture.tasks[3].?.*));
    cpu_identity.setIndexForTest(3);
    var reply = dispatch_ownership.Reply{ .status = 0xFFFF, .denial_reason = 0xFFFF, .bytes_written = 0xFFFF_FFFF };
    const reply_before = reply;
    try std.testing.expectError(error.NotReady, fixture.runtime.execution.consumeSyscallInto(key, &reply));
    try std.testing.expect(std.meta.eql(reply_before, reply));
    cpu_identity.setIndexForTest(0);
    // All rejected receipts left the exact real claim available for a retry.
    try serviceClaim(&fixture.port, &claim, &copy, 20);
    try fixture.consume(key, &reply);
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(usize, 1), fixture.reads);
}

test "syscall broker cancellation and STOP before or during copy never invoke task termination" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try std.testing.allocator.create(TestFixture);
    defer std.testing.allocator.destroy(fixture);
    fixture.* = .{};
    fixture.init();
    defer fixture.deinit();
    for (1..5) |cpu| try fixture.add(@intCast(cpu));
    const cancelled = try fixture.submit(1, abi.opcode(.task_terminate));
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(fixture.runtime.execution.cancelPendingSyscall(cancelled));
    cpu_identity.setIndexForTest(0);
    var claim: dispatch_ownership.ClaimedSyscall = undefined;
    try std.testing.expectError(error.NoRequest, fixture.claimInto(1, &claim));
    const pending = try fixture.submit(2, abi.opcode(.task_terminate));
    try fixture.runtime.requestExecutionStop(pending.ticket);
    try std.testing.expectError(error.StopRequested, fixture.claimInto(2, &claim));
    cpu_identity.setIndexForTest(2);
    try std.testing.expect(fixture.runtime.execution.cancelPendingSyscall(pending));
    cpu_identity.setIndexForTest(0);
    for (3..5) |index| {
        const cpu: u8 = @intCast(index);
        const key = try fixture.submit(cpu, abi.opcode(.task_terminate));
        try fixture.claimInto(cpu, &claim);
        const copy = fixture.session(&claim);
        if (cpu == 3) try fixture.runtime.requestExecutionStop(key.ticket) else fixture.behavior = .stop;
        try serviceClaim(&fixture.port, &claim, &copy, 19);
        var reply: dispatch_ownership.Reply = undefined;
        try fixture.consume(key, &reply);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.unavailable))), reply.status);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.reads);
    for (fixture.tasks) |optional_task| {
        const task = optional_task orelse continue;
        try std.testing.expectEqual(TestFixture.task_runtime.TaskState.active, task.state);
        try std.testing.expectEqual(@as(u8, 1), task.capability_count);
        try std.testing.expect(fixture.runtime.findAddressSpaceConst(task.address_space_id) != null);
    }
    try std.testing.expectEqual(@as(usize, 4), fixture.capabilities.activeCount());
    try std.testing.expectEqual(@as(usize, 4), fixture.endpoints.activeCount());
    try std.testing.expectEqual(@as(usize, 4), fixture.shared.activeCount());
}

test "syscall broker endpoint send owns its staged bytes and transfers copy or moved gifts once" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]bool{ false, true }) |moved| {
        const fixture = try EndpointFixture.create();
        defer fixture.destroy();
        const expected = fixture.payload;
        const source = fixture.source();
        const sender = fixture.base.tasks[EndpointFixture.sender_cpu].?;
        const receiver = fixture.base.tasks[EndpointFixture.receiver_cpu].?;
        const saved_port = fixture.base.port;
        if (moved) fixture.wire.flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT;
        fixture.behavior = .erase;
        const reply = try fixture.roundTrip(@intFromPtr(&fixture.wire));
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(@as(usize, 2), fixture.reads);
        try std.testing.expectEqual(@as(usize, 1), fixture.wakes);
        try std.testing.expect(std.mem.allEqual(u8, &fixture.payload, 0));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&fixture.wire), 0));
        try std.testing.expect(std.meta.eql(saved_port, fixture.base.port));
        try std.testing.expectEqual(!moved, sender.hasCapability(fixture.gift));
        try std.testing.expect(!receiver.hasCapability(fixture.gift));
        try std.testing.expect(fixture.base.capabilities.query(fixture.gift) != null);
        var out: [endpoint.MAX_MESSAGE_BYTES]u8 = @splat(0xa5);
        const received = (try fixture.receive(&out)).?;
        try std.testing.expectEqual(source, received.message.sender_endpoint_id);
        try std.testing.expectEqual(sender.id, received.message.sender_task_id);
        try std.testing.expectEqual(@as(u64, 77), received.message.correlation_id);
        try std.testing.expectEqual(@as(u32, expected.len), received.message.payload_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
        const passed = received.attached_capability.?;
        try std.testing.expect(passed.capability_id != fixture.gift);
        try std.testing.expect(receiver.hasCapability(passed.capability_id));
        try std.testing.expectEqual(!moved, fixture.base.capabilities.query(fixture.gift) != null);
        const grants = fixture.base.capabilities.activeCount();
        const generation = fixture.base.capabilities.mutationGeneration();
        try std.testing.expect(try fixture.receive(&out) == null);
        try std.testing.expectEqual(grants, fixture.base.capabilities.activeCount());
        try std.testing.expectEqual(generation, fixture.base.capabilities.mutationGeneration());
        try std.testing.expect(!fixture.base.endpoints.hasPendingForTask(TestFixture.ids.task(receiver.id)));
    }
}

test "syscall broker endpoint send ignores an empty payload address without a callback" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try EndpointFixture.create();
    defer fixture.destroy();
    fixture.wire.payload_bytes = 0;
    fixture.wire.payload_address = std.math.maxInt(u64);
    fixture.wire.attached_capability_id = 0;
    const reply = try fixture.roundTrip(@intFromPtr(&fixture.wire));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(usize, 1), fixture.reads);
    var out: [endpoint.MAX_MESSAGE_BYTES]u8 = @splat(0xa5);
    const received = (try fixture.receive(&out)).?;
    try std.testing.expectEqual(@as(u32, 0), received.message.payload_len);
    try std.testing.expect(received.attached_capability == null);
    try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
}

test "syscall broker endpoint backpressure preserves the moved grant and supports an exact retry" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try EndpointFixture.create();
    defer fixture.destroy();
    const sender = fixture.base.tasks[EndpointFixture.sender_cpu].?;
    for (0..endpoint.MAX_ENDPOINT_QUEUE) |index| try fixture.base.kernel.endpointSend(.{
        .caller_task_id = sender.id,
        .presented_capability_id = fixture.send_capability,
        .target = .none,
    }, @intCast(index), "filler", 0, null, false, 18);
    fixture.wire.flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT;
    const snapshot = try EndpointFixture.Snapshot.capture(fixture);
    defer snapshot.deinit();
    const rejected = try fixture.roundTrip(@intFromPtr(&fixture.wire));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.would_block))), rejected.status);
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.DenialReason.budget_exhausted))), rejected.denial_reason);
    try snapshot.expectUnchanged(fixture);
    var out: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    _ = (try fixture.base.endpoints.recvInto(TestFixture.ids.endpoint(fixture.destination()), &out)).?;
    const accepted = try fixture.roundTrip(@intFromPtr(&fixture.wire));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), accepted.status);
    try std.testing.expect(!sender.hasCapability(fixture.gift));
    for (0..endpoint.MAX_ENDPOINT_QUEUE - 1) |_| _ = (try fixture.base.endpoints.recvInto(TestFixture.ids.endpoint(fixture.destination()), &out)).?;
    const received = (try fixture.receive(&out)).?;
    try std.testing.expectEqualSlices(u8, &fixture.payload, &out);
    try std.testing.expect(received.attached_capability != null);
    try std.testing.expect(fixture.base.capabilities.query(fixture.gift) == null);
    try std.testing.expect(try fixture.receive(&out) == null);
}

test "syscall broker endpoint malformed staging and denied authority preserve full queue and grants" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const fixture = try EndpointFixture.create();
    defer fixture.destroy();
    const original = fixture.wire;
    const snapshot = try EndpointFixture.Snapshot.capture(fixture);
    defer snapshot.deinit();
    const Case = enum {
        zero_fixed,
        unaligned_fixed,
        overflowing_fixed,
        high_fixed,
        flags,
        reserved,
        oversized,
        absent_subject,
        foreign_subject,
        operation,
        header_flags,
        move_without_gift,
        zero_payload,
        low_payload,
        overflowing_payload,
        high_payload,
        crossing_payload,
        partial_fixed,
        partial_payload,
        foreign_authority,
        denied_right,
        denied_gift,
        missing_gift,
    };
    for (std.meta.tags(Case)) |case| {
        fixture.wire = original;
        fixture.behavior = .copy;
        var address = @intFromPtr(&fixture.wire);
        var expected: abi.SyscallStatus = .invalid_request_pointer;
        var reads: usize = 1;
        switch (case) {
            .zero_fixed => {
                address = 0;
                reads = 0;
            },
            .unaligned_fixed => {
                address += 1;
                reads = 0;
            },
            .overflowing_fixed => {
                address = std.math.maxInt(usize) - 7;
                reads = 0;
            },
            .high_fixed => {
                address = 0xffff_8000_0000_0000;
                reads = 0;
            },
            .flags => fixture.wire.flags = 2,
            .reserved => fixture.wire.reserved = 1,
            .oversized => fixture.wire.payload_bytes = endpoint.MAX_MESSAGE_BYTES + 1,
            .absent_subject => fixture.wire.header.subject_task_id = 0,
            .foreign_subject => fixture.wire.header.subject_task_id = fixture.base.tasks[EndpointFixture.receiver_cpu].?.id,
            .operation => fixture.wire.header.operation = abi.opcode(.endpoint_close),
            .header_flags => fixture.wire.header.flags = 1,
            .move_without_gift => {
                fixture.wire.flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT;
                fixture.wire.attached_capability_id = 0;
            },
            .zero_payload => fixture.wire.payload_address = 0,
            .low_payload => fixture.wire.payload_address = 0xffff,
            .overflowing_payload => fixture.wire.payload_address = std.math.maxInt(u64) - 7,
            .high_payload => fixture.wire.payload_address = 0xffff_8000_0000_0000,
            .crossing_payload => fixture.wire.payload_address = 0x0000_8000_0000_0000 - 8,
            .partial_fixed => fixture.behavior = .partial_fixed,
            .partial_payload => {
                fixture.behavior = .partial_payload;
                reads = 2;
            },
            .foreign_authority => {
                fixture.wire.endpoint_capability_id = fixture.recv_capability;
                expected = .not_found;
                reads = 2;
            },
            .denied_right => {
                fixture.wire.endpoint_capability_id = fixture.base.requests[EndpointFixture.sender_cpu].task_capability_id;
                expected = .denied;
                reads = 2;
            },
            .denied_gift => {
                fixture.wire.attached_capability_id = fixture.send_capability;
                expected = .denied;
                reads = 2;
            },
            .missing_gift => {
                fixture.wire.attached_capability_id = std.math.maxInt(u64);
                expected = .not_found;
                reads = 2;
            },
        }
        const before_reads = fixture.reads;
        const reply = try fixture.roundTrip(address);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(expected))), reply.status);
        try std.testing.expectEqual(@as(u32, 0), reply.bytes_written);
        try std.testing.expectEqual(before_reads + reads, fixture.reads);
        try snapshot.expectUnchanged(fixture);
    }
    fixture.wire = original;
    const accepted = try fixture.roundTrip(@intFromPtr(&fixture.wire));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), accepted.status);
    var out: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    try std.testing.expect(try fixture.receive(&out) != null);
    try std.testing.expectEqualSlices(u8, &fixture.payload, &out);
}

test "syscall broker endpoint STOP around staging suppresses effects and wake STOP preserves committed send" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    for ([_]bool{ false, true }) |stop_payload| {
        const fixture = try EndpointFixture.create();
        defer fixture.destroy();
        const snapshot = try EndpointFixture.Snapshot.capture(fixture);
        defer snapshot.deinit();
        fixture.behavior = if (stop_payload) .stop_payload else .stop_fixed;
        const reply = try fixture.roundTrip(@intFromPtr(&fixture.wire));
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.unavailable))), reply.status);
        try std.testing.expectEqual(@as(usize, if (stop_payload) 2 else 1), fixture.reads);
        try snapshot.expectUnchanged(fixture);
    }
    const fixture = try EndpointFixture.create();
    defer fixture.destroy();
    const sender = fixture.base.tasks[EndpointFixture.sender_cpu].?;
    const address_space_id = sender.address_space_id;
    const saved_port = fixture.base.port;
    fixture.behavior = .reenter_payload;
    fixture.wake_stops = true;
    fixture.wire.flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT;
    const expected = fixture.payload;
    const reply = try fixture.roundTrip(@intFromPtr(&fixture.wire));
    try std.testing.expectEqual(@as(u16, @intCast(@backingInt(abi.SyscallStatus.success))), reply.status);
    try std.testing.expectEqual(@as(usize, 2), fixture.reads);
    try std.testing.expectEqual(@as(usize, 2), fixture.reentries);
    try std.testing.expectEqual(@as(usize, 1), fixture.wakes);
    try std.testing.expectEqual(TestFixture.task_runtime.TaskState.terminated, sender.state);
    try std.testing.expect(!sender.hasCapability(fixture.gift));
    try std.testing.expect(fixture.base.runtime.findAddressSpaceConst(address_space_id) != null);
    try std.testing.expectEqual(@as(usize, 2), fixture.base.endpoints.activeCount());
    try std.testing.expectEqual(@as(usize, 2), fixture.base.shared.activeCount());
    try std.testing.expect(std.meta.eql(saved_port, fixture.base.port));
    var out: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try fixture.receive(&out)).?;
    try std.testing.expectEqualSlices(u8, &expected, &out);
    try std.testing.expect(received.attached_capability != null);
    const ticket = fixture.base.tickets[EndpointFixture.sender_cpu].?;
    cpu_identity.setIndexForTest(EndpointFixture.sender_cpu);
    try std.testing.expect(fixture.base.runtime.execution.stopRequested(ticket));
    try fixture.base.runtime.execution.acknowledgeOwnedRootReturn(ticket);
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(fixture.base.runtime.findAddressSpaceConst(address_space_id) != null);
    fixture.wake_stops = false;
    try fixture.base.runtime.collectExecution(ticket);
    fixture.base.tickets[EndpointFixture.sender_cpu] = null;
    fixture.base.keys[EndpointFixture.sender_cpu] = null;
    try std.testing.expect(fixture.base.runtime.findAddressSpaceConst(address_space_id) == null);
    try std.testing.expectEqual(@as(usize, 1), fixture.base.endpoints.activeCount());
    try std.testing.expectEqual(@as(usize, 1), fixture.base.shared.activeCount());
    try std.testing.expectEqual(@as(usize, 2), fixture.wakes);
    try std.testing.expectError(error.PeerClosed, fixture.receive(&out));
}
