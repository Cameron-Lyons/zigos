const builtin = @import("builtin");
pub const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
const service_protocol = @import("userspace_service_protocol");
const userspace_descriptor = @import("userspace_descriptor");

pub const Descriptor = userspace_descriptor.Descriptor;
pub const ELF_SECTION_NAME = userspace_descriptor.ELF_SECTION_NAME;
pub const ServiceKind = mailbox.ServiceKind;

const TimeQueryRequest = extern struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
};

const ResourceQueryRequest = extern struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    task_id: u64,
};

const AccountingQueryRequest = extern struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    task_id: u64,
};

const EndpointFlags = packed struct(u16) {
    local_only: bool = false,
    service_port: bool = false,
    carries_capability: bool = false,
    _reserved: u13 = 0,
};

const EndpointCreateRequest = struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: EndpointFlags,
};

const EndpointConnectRequest = extern struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
};

const EndpointSendRequest = struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    payload: []const u8,
    attached_capability_id: ?u64 = null,
    move_attached_capability: bool = false,
};

const EndpointRecvRequest = extern struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    receiver_task_id: u64,
};

const InputRecvRequest = extern struct {
    header: abi.RequestHeader,
    input_capability_id: u64,
    receiver_task_id: u64,
};

const INPUT_EVENTS_PER_DISPATCH: usize = 8;

const contract_bindings = if (builtin.target.os.tag == .freestanding)
    struct {
        extern var zigos_userspace_descriptor: Descriptor;
        extern var zigos_userspace_yield_counter: u32;
    }
else
    struct {
        pub var zigos_userspace_descriptor: Descriptor = std.mem.zeroes(Descriptor);
        pub var zigos_userspace_yield_counter: u32 = 0;
    };

const mailbox_section = if (builtin.target.ofmt == .macho) "__DATA,__zigos_boot" else mailbox.SECTION_NAME;

export var zigos_userspace_bootstrap: mailbox.Mailbox align(mailbox.ABI_ALIGNMENT) linksection(mailbox_section) = .{};

const freestanding_syscall = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn syscall3_asm(request_addr: usize, response_addr: usize, response_len: usize) callconv(.c) usize;
        extern fn syscall_yield_asm(counter: u32) callconv(.c) u32;
        extern fn zigos_probe_nx(target: usize) callconv(.c) void;

        fn call(request_addr: usize, response_addr: usize, response_len: usize) abi.SyscallStatus {
            return @enumFromInt(syscall3_asm(request_addr, response_addr, response_len));
        }
    }
else
    struct {
        fn call(_: usize, _: usize, _: usize) abi.SyscallStatus {
            return .unavailable;
        }
    };

pub fn initDescriptor(spec: userspace_descriptor.InitSpec) userspace_descriptor.InitError!Descriptor {
    return userspace_descriptor.init(spec);
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    const detail = mailbox.classifyDetail(
        contract_bindings.zigos_userspace_descriptor.component_class,
        contract_bindings.zigos_userspace_descriptor.contract_flags,
    );
    signalFault(detail, faultCode(msg));
}

pub fn zigos_userspace_contract_main(
    comptime run_mmu_isolation_probe: bool,
    comptime run_nx_isolation_probe: bool,
) noreturn {
    const descriptor = &contract_bindings.zigos_userspace_descriptor;
    userspace_descriptor.validate(descriptor) catch signalFault(.unknown, 1);

    const detail = mailbox.classifyDetail(descriptor.component_class, descriptor.contract_flags);
    publishState(.descriptor_ready, detail, 1);

    if (zigos_userspace_bootstrap.authority_capability_id != 0 and zigos_userspace_bootstrap.task_id != 0) {
        publishState(.mailbox_ready, detail, 2);
        runStartupQueries(detail);
    }

    if (comptime run_mmu_isolation_probe or run_nx_isolation_probe) {
        if (descriptor.role_tag != mailbox.MMU_ISOLATION_PROOF_ROLE_TAG) {
            signalFault(detail, mailbox.PROOF_FOREIGN_MEMORY_ACCESS_FAULT_CODE);
        }
    }
    if (comptime run_nx_isolation_probe) {
        runNxIsolationProbe();
    }
    if (comptime run_mmu_isolation_probe) {
        runMmuIsolationProbe(detail);
    }

    runSteadyState(
        detail,
        descriptor.heartbeat_increment,
        (descriptor.contract_flags & mailbox.FLAG_OWNS_UI_SURFACE) != 0,
    );
}

pub fn zigos_userspace_service_main(comptime service_kind: ServiceKind) noreturn {
    const descriptor = &contract_bindings.zigos_userspace_descriptor;
    userspace_descriptor.validate(descriptor) catch signalFault(.unknown, 1);

    const detail = mailbox.classifyDetail(descriptor.component_class, descriptor.contract_flags);
    publishState(.descriptor_ready, detail, 1);

    if (zigos_userspace_bootstrap.authority_capability_id != 0 and zigos_userspace_bootstrap.task_id != 0) {
        publishState(.mailbox_ready, detail, 2);
        runStartupQueries(detail);
    }

    publishServiceReady(service_kind, detail);
    runSteadyState(
        detail,
        descriptor.heartbeat_increment,
        (descriptor.contract_flags & mailbox.FLAG_OWNS_UI_SURFACE) != 0,
    );
}

fn runStartupQueries(detail: mailbox.Detail) void {
    var resource_mask = mailbox.ResourceMask{};
    const authority_capability_id = zigos_userspace_bootstrap.authority_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;

    _ = queryTime(authority_capability_id, task_id, &resource_mask);
    _ = queryResource(authority_capability_id, task_id, &resource_mask);
    _ = queryAccounting(authority_capability_id, task_id, &resource_mask);

    zigos_userspace_bootstrap.resource_mask = @bitCast(resource_mask);
    if (@as(u32, @bitCast(resource_mask)) != 0) {
        publishState(.syscall_ready, detail, 3);
    }
}

fn publishServiceReady(comptime service_kind: ServiceKind, detail: mailbox.Detail) void {
    const proof = runServiceStartupIpc(service_kind) orelse signalFault(detail, 0x21);
    zigos_userspace_bootstrap.service_kind = @intFromEnum(service_kind);
    zigos_userspace_bootstrap.service_ready = 1;
    zigos_userspace_bootstrap.service_operation_count = proof.operation_count;
    zigos_userspace_bootstrap.service_state_hash = proof.state_hash;
    zigos_userspace_bootstrap.service_endpoint_id = proof.service_endpoint_id;
    zigos_userspace_bootstrap.service_peer_endpoint_id = proof.peer_endpoint_id;
    zigos_userspace_bootstrap.service_ipc_roundtrips = proof.roundtrips;
    zigos_userspace_bootstrap.service_status_flags = @bitCast(proof.flags);
    publishState(.service_ready, detail, proof.operation_count);
}

const ServiceStartupProof = struct {
    operation_count: u16 = 0,
    roundtrips: u16 = 0,
    service_endpoint_id: u64 = 0,
    peer_endpoint_id: u64 = 0,
    state_hash: u64 = 0,
    flags: mailbox.ServiceStatusFlags = .{},
};

fn runServiceStartupIpc(comptime service_kind: ServiceKind) ?ServiceStartupProof {
    const authority_capability_id = zigos_userspace_bootstrap.authority_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;
    if (authority_capability_id == 0 or task_id == 0) return null;

    const service_plan = service_protocol.planFor(service_kind);
    const service_endpoint = endpointCreate(
        authority_capability_id,
        task_id,
        service_plan.endpoint_label,
        .{ .local_only = true, .service_port = true },
    ) orelse return null;
    const peer_endpoint = endpointCreate(
        authority_capability_id,
        task_id,
        "userspace-service-self-check",
        .{ .local_only = true },
    ) orelse return null;
    _ = endpointConnect(
        peer_endpoint.capability_id,
        service_endpoint.capability_id,
        service_endpoint.endpoint.endpoint_id,
    ) orelse return null;

    var proof = ServiceStartupProof{
        .service_endpoint_id = service_endpoint.endpoint.endpoint_id,
        .peer_endpoint_id = peer_endpoint.endpoint.endpoint_id,
        .state_hash = service_protocol.initialStateHash(service_kind),
        .flags = .{
            .endpoint_created = true,
            .loopback_connected = true,
        },
    };

    for (service_plan.slice(), 0..) |operation, index| {
        var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const request_payload = service_protocol.encodeRequest(
            &request_buffer,
            service_kind,
            operation,
            index,
        ) catch return null;
        if (!endpointSend(peer_endpoint.capability_id, request_payload)) return null;

        const received_request = endpointRecv(service_endpoint.capability_id, task_id) orelse return null;
        if (received_request.present == 0) return null;
        const received_request_len: usize = @intCast(received_request.message.payload_len);
        const decoded_request = service_protocol.decodeRequest(
            received_request.payload[0..received_request_len],
        ) catch return null;
        if (!service_protocol.requestMatchesOperation(decoded_request, service_kind, operation, index)) return null;
        proof.flags.request_received = true;

        proof.state_hash = service_protocol.foldOperation(proof.state_hash, operation, index);
        var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const response_payload = service_protocol.encodeResponse(
            &response_buffer,
            decoded_request,
            proof.state_hash,
        ) catch return null;
        if (!endpointSend(service_endpoint.capability_id, response_payload)) return null;

        const received_response = endpointRecv(peer_endpoint.capability_id, task_id) orelse return null;
        if (received_response.present == 0) return null;
        const received_response_len: usize = @intCast(received_response.message.payload_len);
        const decoded_response = service_protocol.decodeResponse(
            received_response.payload[0..received_response_len],
        ) catch return null;
        if (!service_protocol.requestMatchesOperation(decoded_response, service_kind, operation, index)) return null;
        if (decoded_response.state_hash != proof.state_hash) return null;
        proof.flags.response_received = true;
        proof.operation_count += 1;
        proof.roundtrips += 1;
    }

    proof.flags.all_operations_completed = proof.operation_count == @as(u16, @intCast(service_plan.operation_count));
    if (!proof.flags.all_operations_completed) return null;
    return proof;
}

fn runMmuIsolationProbe(detail: mailbox.Detail) noreturn {
    const pointer_probe_status = invalidSyscallPointerStatus();
    if (pointer_probe_status == .invalid_request_pointer) {
        publishState(.syscall_ready, detail, mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE);
    } else {
        signalFault(detail, @truncate(@intFromEnum(pointer_probe_status)));
    }

    const foreign_shared_memory: *volatile u8 = @ptrFromInt(@as(usize, mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR));
    _ = foreign_shared_memory.*;
    signalFault(detail, mailbox.PROOF_FOREIGN_MEMORY_ACCESS_FAULT_CODE);
}

fn runNxIsolationProbe() void {
    if (builtin.target.os.tag != .freestanding) return;
    freestanding_syscall.zigos_probe_nx(@intFromPtr(&zigos_userspace_bootstrap));
}

fn invalidSyscallPointerStatus() abi.SyscallStatus {
    var response = abi.TimeQueryResponse{ .now_ticks = 0 };
    return freestanding_syscall.call(
        mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR,
        @intFromPtr(&response),
        @sizeOf(abi.TimeQueryResponse),
    );
}

fn queryTime(authority_capability_id: u64, task_id: u64, mask: *mailbox.ResourceMask) bool {
    var response = abi.TimeQueryResponse{ .now_ticks = 0 };
    var request = TimeQueryRequest{
        .header = makeHeader(.time_query, nextCorrelationId(), task_id),
        .authority_capability_id = authority_capability_id,
    };
    if (trapCall(&request, &response) != .success) return false;
    mask.time_query = true;
    return true;
}

fn queryResource(authority_capability_id: u64, task_id: u64, mask: *mailbox.ResourceMask) bool {
    var response = std.mem.zeroes(abi.ResourceDescriptor);
    var request = ResourceQueryRequest{
        .header = makeHeader(.resource_query, nextCorrelationId(), task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    if (trapCall(&request, &response) != .success) return false;
    mask.resource_query = true;
    return response.task_id == task_id;
}

fn queryAccounting(authority_capability_id: u64, task_id: u64, mask: *mailbox.ResourceMask) bool {
    var response = std.mem.zeroes(abi.AccountingDescriptor);
    var request = AccountingQueryRequest{
        .header = makeHeader(.accounting_query, nextCorrelationId(), task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    if (trapCall(&request, &response) != .success) return false;
    mask.accounting_query = true;
    return response.task_id == task_id;
}

fn endpointCreate(
    authority_capability_id: u64,
    task_id: u64,
    label: []const u8,
    flags: EndpointFlags,
) ?abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    var request = EndpointCreateRequest{
        .header = makeHeader(.endpoint_create, nextCorrelationId(), task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = task_id,
        .label = label,
        .flags = flags,
    };
    if (trapCall(&request, &response) != .success) return null;
    if (response.endpoint.endpoint_id == 0 or response.capability_id == 0) return null;
    return response;
}

fn endpointConnect(
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
) ?abi.EndpointDescriptor {
    var response = std.mem.zeroes(abi.EndpointDescriptor);
    var request = EndpointConnectRequest{
        .header = makeHeader(.endpoint_connect, nextCorrelationId(), zigos_userspace_bootstrap.task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    if (trapCall(&request, &response) != .success) return null;
    if (response.peer_endpoint_id != peer_endpoint_id) return null;
    return response;
}

fn endpointSend(endpoint_capability_id: u64, payload: []const u8) bool {
    var request = EndpointSendRequest{
        .header = makeHeader(.endpoint_send, nextCorrelationId(), zigos_userspace_bootstrap.task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
    };
    return trapCallNoResponse(&request) == .success;
}

fn endpointRecv(endpoint_capability_id: u64, task_id: u64) ?abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var request = EndpointRecvRequest{
        .header = makeHeader(.endpoint_recv, nextCorrelationId(), task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = task_id,
    };
    if (trapCall(&request, &response) != .success) return null;
    return response;
}

fn inputRecv(input_capability_id: u64, task_id: u64) ?abi.InputRecvResponse {
    var response = std.mem.zeroes(abi.InputRecvResponse);
    var request = InputRecvRequest{
        .header = makeHeader(.input_recv, nextCorrelationId(), task_id),
        .input_capability_id = input_capability_id,
        .receiver_task_id = task_id,
    };
    if (trapCall(&request, &response) != .success) return null;
    return response;
}

fn drainFocusedInput() usize {
    const input_capability_id = zigos_userspace_bootstrap.input_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;
    if (input_capability_id == 0 or task_id == 0) return 0;

    var count: usize = 0;
    while (count < INPUT_EVENTS_PER_DISPATCH) : (count += 1) {
        const response = inputRecv(input_capability_id, task_id) orelse break;
        if (response.present == 0) break;
        if (!recordInputEvent(&zigos_userspace_bootstrap, response.event)) break;
    }
    return count;
}

fn recordInputEvent(state: *mailbox.Mailbox, event: abi.InputEventDescriptor) bool {
    _ = abi.inputEventKind(event.kind) orelse return false;
    if (event.sequence == 0 or event.task_id != state.task_id) return false;
    state.input_event_count +|= 1;
    state.last_input_sequence = event.sequence;
    state.last_input_window_id = event.window_id;
    state.last_input_surface_id = event.surface_id;
    state.last_input_kind = event.kind;
    state.last_input_text = event.text;
    state.last_input_port_id = event.port_id;
    state.last_input_slot_id = event.slot_id;
    return true;
}

fn runSteadyState(detail: mailbox.Detail, heartbeat_increment: u32, consumes_input: bool) noreturn {
    const increment: u16 = @truncate(if (heartbeat_increment == 0) 1 else heartbeat_increment);
    var pulse: u16 = 4;
    while (true) {
        if (consumes_input) _ = drainFocusedInput();
        publishState(.steady, detail, pulse);
        pulse +%= increment;
    }
}

fn publishState(stage: mailbox.Stage, detail: mailbox.Detail, pulse: u16) void {
    const counter = mailbox.packCounter(stage, detail, pulse);
    zigos_userspace_bootstrap.stage = @intFromEnum(stage);
    zigos_userspace_bootstrap.detail = @intFromEnum(detail);
    zigos_userspace_bootstrap.last_counter = counter;
    contract_bindings.zigos_userspace_yield_counter = counter;
    _ = yieldCounter(counter);
}

fn signalFault(detail: mailbox.Detail, code: u8) noreturn {
    zigos_userspace_bootstrap.fault_code = code;
    while (true) {
        publishState(.fault, detail, @as(u16, code));
    }
}

fn yieldCounter(value: u32) u32 {
    if (builtin.target.os.tag != .freestanding) return value;
    return freestanding_syscall.syscall_yield_asm(value);
}

fn trapCall(request: anytype, response: anytype) abi.SyscallStatus {
    return freestanding_syscall.call(
        @intFromPtr(request),
        @intFromPtr(response),
        @sizeOf(@TypeOf(response.*)),
    );
}

fn trapCallNoResponse(request: anytype) abi.SyscallStatus {
    return freestanding_syscall.call(@intFromPtr(request), 0, 0);
}

fn makeHeader(operation: abi.NativeOperation, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return .{
        .version = abi.ABI_VERSION,
        .operation = abi.opcode(operation),
        .flags = 0,
        .correlation_id = correlation_id,
        .subject_task_id = subject_task_id,
    };
}

fn nextCorrelationId() u64 {
    const id = next_correlation_id;
    next_correlation_id += 1;
    return id;
}

fn faultCode(msg: []const u8) u8 {
    var code: u8 = 0x40;
    for (msg) |byte| {
        code +%= byte;
    }
    return if (code == 0) 1 else code;
}

var next_correlation_id: u64 = 1;

test "fault codes stay stable for the same message" {
    try std.testing.expectEqual(faultCode("panic"), faultCode("panic"));
    try std.testing.expect(faultCode("panic") != faultCode("different"));
}

test "focused input telemetry rejects foreign events and records valid semantic input" {
    var state = mailbox.Mailbox{ .task_id = 41 };
    const event = abi.InputEventDescriptor{
        .sequence = 7,
        .tick = 90,
        .window_id = 12,
        .task_id = 41,
        .surface_id = 13,
        .kind = @intFromEnum(abi.InputEventKind.text),
        .text = 'x',
        .port_id = 2,
        .slot_id = 3,
    };
    try std.testing.expect(recordInputEvent(&state, event));
    try std.testing.expectEqual(@as(u64, 1), state.input_event_count);
    try std.testing.expectEqual(@as(u64, 7), state.last_input_sequence);
    try std.testing.expectEqual(@as(u8, 'x'), state.last_input_text);

    var foreign = event;
    foreign.task_id = 42;
    try std.testing.expect(!recordInputEvent(&state, foreign));
    foreign.task_id = 41;
    foreign.kind = 0xFF;
    try std.testing.expect(!recordInputEvent(&state, foreign));
    try std.testing.expectEqual(@as(u64, 1), state.input_event_count);
}

test "userspace service startup plans expose domain-specific endpoint operations" {
    const storage = service_protocol.planFor(.storage);
    const network = service_protocol.planFor(.network);
    const package = service_protocol.planFor(.package);
    const compositor = service_protocol.planFor(.compositor);
    const sync = service_protocol.planFor(.sync);

    try std.testing.expectEqual(@as(u8, @intFromEnum(ServiceKind.storage)), @as(u8, @intFromEnum(storage.kind)));
    try std.testing.expectEqual(@as(usize, 4), storage.operation_count);
    try std.testing.expectEqual(@as(usize, 3), network.operation_count);
    try std.testing.expectEqual(@as(usize, 4), package.operation_count);
    try std.testing.expectEqual(@as(usize, 4), compositor.operation_count);
    try std.testing.expectEqual(@as(usize, 4), sync.operation_count);
    try std.testing.expect(!std.mem.eql(u8, storage.endpoint_label, network.endpoint_label));
    try std.testing.expect(!std.mem.eql(u8, package.operations[0].name, compositor.operations[0].name));
}
