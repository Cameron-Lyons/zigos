const builtin = @import("builtin");
pub const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
const service_protocol = @import("userspace_service_protocol");
const ui_surface_state = @import("ui_surface_state.zig");
const document_editor = @import("document_editor.zig");

pub const ServiceKind = mailbox.ServiceKind;

const TimeQueryRequest = extern struct {
    header: abi.RequestHeader,
    authority_capability_id: u64,
};

const WaitRequest = extern struct {
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
    correlation_id: u64 = 0,
    endpoint_capability_id: u64,
    payload: []const u8,
    reply_endpoint_id: u64 = 0,
    attached_capability_id: ?u64 = null,
    move_attached_capability: bool = false,
};

const EndpointRecvRequest = struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
    receiver_task_id: u64,
    payload_out: []u8,
    attached_capability_out: *abi.CapabilityDescriptor,
};

const EndpointCloseRequest = extern struct {
    header: abi.RequestHeader,
    endpoint_capability_id: u64,
};

pub fn closeEndpoint(endpoint_capability_id: u64) abi.SyscallStatus {
    var request = EndpointCloseRequest{
        .header = makeHeader(.endpoint_close, zigos_userspace_bootstrap.task_id),
        .endpoint_capability_id = endpoint_capability_id,
    };
    return trapCallNoResponse(&request);
}

const InputRecvRequest = extern struct {
    header: abi.RequestHeader,
    input_capability_id: u64,
    receiver_task_id: u64,
};

const SurfacePresentRequest = struct {
    header: abi.RequestHeader,
    presentation_capability_id: u64,
    presenter_task_id: u64,
    surface_id: u64,
    fence: u64,
    buffer_object_id: u64,
    buffer_offset: u32,
    buffer_bytes: u32,
    text: ?*const abi.SurfaceText = null,
};

const INPUT_EVENTS_PER_DISPATCH: usize = 8;

const mailbox_section = if (builtin.target.ofmt == .macho) "__DATA,__zigos_boot" else mailbox.SECTION_NAME;

export var zigos_userspace_bootstrap: mailbox.Mailbox align(mailbox.ABI_ALIGNMENT) linksection(mailbox_section) = .{};
// Tasks in one address-space group share the ELF's writable pages. Keep
// editor state on each task's private stack; only the executor-managed mailbox
// is shared between dispatches.
const launcher_client = @import("launcher_client.zig");

const UiRuntime = struct {
    launcher: launcher_client.Client = .{},
    surface: ui_surface_state.State = .{},
    document: document_editor.Editor = .{},
    clipboard: @import("clipboard_client.zig").Client = .{},
};

const freestanding_syscall = if (builtin.target.os.tag == .freestanding)
    struct {
        const Outcome = extern struct {
            status: u32,
            bytes_written: u32,
            denial_reason: u16,
            _reserved: u16 = 0,
        };

        comptime {
            if (@sizeOf(Outcome) != 12 or
                @offsetOf(Outcome, "status") != 0 or
                @offsetOf(Outcome, "bytes_written") != 4 or
                @offsetOf(Outcome, "denial_reason") != 8)
            {
                @compileError("userspace syscall result no longer matches the assembly ABI");
            }
        }

        extern fn syscall3_asm(
            opcode: usize,
            request_addr: usize,
            response_addr: usize,
            response_len: usize,
            outcome: *Outcome,
        ) callconv(.c) usize;
        extern fn syscall_yield_asm(
            counter: u32,
            disposition: mailbox.YieldDisposition,
            ui_revision: u64,
        ) callconv(.c) u32;
        extern fn zigos_probe_nx(target: usize) callconv(.c) void;
        extern fn zigos_probe_gp() callconv(.c) void;

        fn call(opcode: abi.NativeOperation, request_addr: usize, response_addr: usize, response_len: usize) struct {
            status: abi.SyscallStatus,
            bytes_written: u32,
            denial_reason: abi.DenialReason,
        } {
            var outcome = Outcome{ .status = @intFromEnum(abi.SyscallStatus.internal_error), .bytes_written = 0, .denial_reason = 0 };
            _ = syscall3_asm(@intFromEnum(opcode), request_addr, response_addr, response_len, &outcome);
            return .{
                .status = @enumFromInt(outcome.status),
                .bytes_written = outcome.bytes_written,
                .denial_reason = @enumFromInt(outcome.denial_reason),
            };
        }
    }
else
    struct {
        fn zigos_probe_gp() void {}

        fn call(opcode: abi.NativeOperation, _: usize, _: usize, _: usize) struct {
            status: abi.SyscallStatus,
            bytes_written: u32,
            denial_reason: abi.DenialReason,
        } {
            _ = opcode;
            return .{ .status = .unavailable, .bytes_written = 0, .denial_reason = .none };
        }
    };

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    const detail = bootstrapDetail();
    signalFault(detail, faultCode(msg));
}

pub fn zigos_userspace_contract_main(
    comptime run_mmu_isolation_probe: bool,
    comptime run_nx_isolation_probe: bool,
    comptime run_gp_isolation_probe: bool,
    comptime bundle_id: []const u8,
    comptime contract_flags: u32,
) noreturn {
    const detail = bootstrapDetail();
    var ui = UiRuntime{};
    initializeUiState(&ui, bundle_id, contract_flags);
    publishState(.runtime_ready, detail, 1);

    if (zigos_userspace_bootstrap.authority_capability_id != 0 and zigos_userspace_bootstrap.task_id != 0) {
        publishState(.mailbox_ready, detail, 2);
        runStartupQueries(detail);
    }

    if (comptime run_mmu_isolation_probe or run_nx_isolation_probe) {
        if (detail != .proof) {
            signalFault(detail, mailbox.PROOF_FOREIGN_MEMORY_ACCESS_FAULT_CODE);
        }
    }
    if (comptime run_nx_isolation_probe) {
        runNxIsolationProbe();
    }
    if (comptime run_mmu_isolation_probe) {
        runMmuIsolationProbe(detail);
    }
    if (comptime run_gp_isolation_probe) {
        runGeneralProtectionIsolationProbe();
    }

    runSteadyState(
        &ui,
        detail,
        zigos_userspace_bootstrap.heartbeat_increment,
        comptime (contract_flags & mailbox.FLAG_OWNS_UI_SURFACE) != 0,
        comptime ui_surface_state.modelForBundle(bundle_id) == .notes,
        comptime std.mem.eql(u8, bundle_id, "zigos.system.service-client"),
    );
}

pub fn zigos_userspace_service_main(
    comptime service_kind: ServiceKind,
    comptime bundle_id: []const u8,
    comptime contract_flags: u32,
) noreturn {
    const detail = bootstrapDetail();
    var ui = UiRuntime{};
    initializeUiState(&ui, bundle_id, contract_flags);
    publishState(.runtime_ready, detail, 1);

    waitForServiceBootstrapAuthority(detail);
    publishState(.mailbox_ready, detail, 2);
    runStartupQueries(detail);

    publishServiceReady(service_kind, detail);
    runSteadyState(
        &ui,
        detail,
        zigos_userspace_bootstrap.heartbeat_increment,
        comptime (contract_flags & mailbox.FLAG_OWNS_UI_SURFACE) != 0,
        comptime ui_surface_state.modelForBundle(bundle_id) == .notes,
        false,
    );
}

fn bootstrapDetail() mailbox.Detail {
    return std.enums.fromInt(mailbox.Detail, zigos_userspace_bootstrap.detail) orelse .unknown;
}

fn waitForServiceBootstrapAuthority(detail: mailbox.Detail) void {
    var pulse: u16 = 1;
    while (zigos_userspace_bootstrap.authority_capability_id == 0 or zigos_userspace_bootstrap.task_id == 0) {
        publishStateWithDisposition(.mailbox_ready, detail, pulse, .runnable);
        pulse +%= 1;
    }
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
    var failure_code: u8 = 0x21;
    const proof = runServiceStartupIpc(service_kind, &failure_code) orelse signalFault(detail, failure_code);
    zigos_userspace_bootstrap.service_kind = @intFromEnum(service_kind);
    zigos_userspace_bootstrap.auxiliary_kind = .service;
    zigos_userspace_bootstrap.service_ready = 1;
    zigos_userspace_bootstrap.service_operation_count = proof.operation_count;
    zigos_userspace_bootstrap.auxiliary.service.state_hash = proof.state_hash;
    zigos_userspace_bootstrap.auxiliary.service.endpoint_id = proof.service_endpoint_id;
    zigos_userspace_bootstrap.auxiliary.service.peer_endpoint_id = proof.peer_endpoint_id;
    zigos_userspace_bootstrap.auxiliary.service.ipc_roundtrips = proof.roundtrips;
    zigos_userspace_bootstrap.auxiliary.service.status_flags = @bitCast(proof.flags);
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

fn runServiceStartupIpc(comptime service_kind: ServiceKind, failure_code: *u8) ?ServiceStartupProof {
    const authority_capability_id = zigos_userspace_bootstrap.authority_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;
    if (authority_capability_id == 0 or task_id == 0) return null;

    const service_plan = service_protocol.planFor(service_kind);
    failure_code.* = 0x22;
    const service_endpoint = endpointCreate(
        authority_capability_id,
        task_id,
        service_plan.endpoint_label,
        .{ .local_only = true, .service_port = true },
        failure_code,
    ) orelse return null;
    var service_live = true;
    defer if (service_live) {
        _ = closeEndpoint(service_endpoint.capability_id);
    };
    failure_code.* = 0x23;
    const peer_endpoint = endpointCreate(
        authority_capability_id,
        task_id,
        "userspace-service-self-check",
        .{ .local_only = true },
        failure_code,
    ) orelse return null;
    var peer_live = true;
    defer if (peer_live) {
        _ = closeEndpoint(peer_endpoint.capability_id);
    };
    failure_code.* = 0x24;
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
        failure_code.* = 0x25;
        var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const request_payload = service_protocol.encodeRequest(
            &request_buffer,
            service_kind,
            operation,
            index,
        ) catch return null;
        failure_code.* = 0x26;
        const correlation_id: u64 = @as(u64, @intCast(index)) + 1;
        if (!endpointSend(peer_endpoint.capability_id, request_payload, 0, correlation_id)) return null;

        failure_code.* = 0x27;
        const received_request = endpointRecv(service_endpoint.capability_id, task_id) orelse return null;
        failure_code.* = 0x28;
        if (received_request.present == 0) return null;
        const received_request_len: usize = @intCast(received_request.message.payload_len);
        failure_code.* = 0x29;
        const decoded_request = service_protocol.decodeRequest(
            received_request.payload[0..received_request_len],
        ) catch return null;
        failure_code.* = 0x2A;
        if (!service_protocol.requestMatchesOperation(decoded_request, service_kind, operation, index)) return null;
        proof.flags.request_received = true;

        proof.state_hash = service_protocol.foldOperation(proof.state_hash, operation, index);
        failure_code.* = 0x2B;
        var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const response_payload = service_protocol.encodeResponse(
            &response_buffer,
            decoded_request,
            proof.state_hash,
        ) catch return null;
        failure_code.* = 0x2C;
        if (!endpointSend(service_endpoint.capability_id, response_payload, received_request.message.sender_endpoint_id, received_request.message.correlation_id)) return null;

        failure_code.* = 0x2D;
        const received_response = endpointRecv(peer_endpoint.capability_id, task_id) orelse return null;
        failure_code.* = 0x2E;
        if (received_response.present == 0 or received_response.message.correlation_id != correlation_id or
            received_response.message.sender_endpoint_id != service_endpoint.endpoint.endpoint_id) return null;
        const received_response_len: usize = @intCast(received_response.message.payload_len);
        failure_code.* = 0x2F;
        const decoded_response = service_protocol.decodeResponse(
            received_response.payload[0..received_response_len],
        ) catch return null;
        failure_code.* = 0x30;
        if (!service_protocol.requestMatchesOperation(decoded_response, service_kind, operation, index)) return null;
        failure_code.* = 0x31;
        if (decoded_response.state_hash != proof.state_hash) return null;
        proof.flags.response_received = true;
        proof.operation_count += 1;
        proof.roundtrips += 1;
    }

    proof.flags.all_operations_completed = proof.operation_count == @as(u16, @intCast(service_plan.operation_count));
    failure_code.* = 0x32;
    if (!proof.flags.all_operations_completed) return null;
    // Both endpoints belong only to this startup check. The service's
    // published endpoint is provisioned separately by session bootstrap.
    failure_code.* = 0x33;
    if (closeEndpoint(peer_endpoint.capability_id) != .success) return null;
    peer_live = false;
    failure_code.* = 0x34;
    if (closeEndpoint(service_endpoint.capability_id) != .success) return null;
    service_live = false;
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

fn runGeneralProtectionIsolationProbe() void {
    if (builtin.target.os.tag != .freestanding) return;
    freestanding_syscall.zigos_probe_gp();
}

fn invalidSyscallPointerStatus() abi.SyscallStatus {
    var response = abi.TimeQueryResponse{ .now_ticks = 0 };
    return freestanding_syscall.call(
        .time_query,
        mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR,
        @intFromPtr(&response),
        @sizeOf(abi.TimeQueryResponse),
    ).status;
}

fn queryTime(authority_capability_id: u64, task_id: u64, mask: *mailbox.ResourceMask) bool {
    var response = abi.TimeQueryResponse{ .now_ticks = 0 };
    var request = TimeQueryRequest{
        .header = makeHeader(.time_query, task_id),
        .authority_capability_id = authority_capability_id,
    };
    if (trapCall(&request, &response) != .success) return false;
    mask.time_query = true;
    return true;
}

fn parkUntilEvent() void {
    const authority = zigos_userspace_bootstrap.authority_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;
    if (authority == 0 or task_id == 0) return;
    var response = std.mem.zeroes(abi.BoolResponse);
    var request = WaitRequest{
        .header = makeHeader(.wait, task_id),
        .authority_capability_id = authority,
    };
    _ = trapCall(&request, &response);
}

fn queryResource(authority_capability_id: u64, task_id: u64, mask: *mailbox.ResourceMask) bool {
    var response = std.mem.zeroes(abi.ResourceDescriptor);
    var request = ResourceQueryRequest{
        .header = makeHeader(.resource_query, task_id),
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
        .header = makeHeader(.accounting_query, task_id),
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
    failure_code: *u8,
) ?abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    var request = EndpointCreateRequest{
        .header = makeHeader(.endpoint_create, task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = task_id,
        .label = label,
        .flags = flags,
    };
    const result = freestanding_syscall.call(
        .endpoint_create,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(@TypeOf(response)),
    );
    if (result.status != .success) {
        failure_code.* = if (result.status == .denied)
            0x90 | @as(u8, @truncate(@intFromEnum(result.denial_reason)))
        else
            0x80 | @as(u8, @truncate(@intFromEnum(result.status)));
        return null;
    }
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
        .header = makeHeader(.endpoint_connect, zigos_userspace_bootstrap.task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    if (trapCall(&request, &response) != .success) return null;
    if (response.peer_endpoint_id != peer_endpoint_id) return null;
    return response;
}

fn endpointSend(endpoint_capability_id: u64, payload: []const u8, reply_endpoint_id: u64, correlation_id: u64) bool {
    var request = EndpointSendRequest{
        .header = makeHeader(.endpoint_send, zigos_userspace_bootstrap.task_id),
        .correlation_id = correlation_id,
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
        .reply_endpoint_id = reply_endpoint_id,
    };
    return trapCallNoResponse(&request) == .success;
}

fn endpointRecv(endpoint_capability_id: u64, task_id: u64) ?abi.EndpointRecvResult {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var received = std.mem.zeroes(abi.EndpointRecvResult);
    var request = EndpointRecvRequest{
        .header = makeHeader(.endpoint_recv, task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = task_id,
        .payload_out = &received.payload,
        .attached_capability_out = &received.attached_capability,
    };
    if (trapCall(&request, &response) != .success) return null;
    received.present = response.present;
    received.has_attached_capability = response.has_attached_capability;
    received.message = response.message;
    return received;
}

fn inputRecv(input_capability_id: u64, task_id: u64) ?abi.InputRecvResponse {
    var response = std.mem.zeroes(abi.InputRecvResponse);
    var request = InputRecvRequest{
        .header = makeHeader(.input_recv, task_id),
        .input_capability_id = input_capability_id,
        .receiver_task_id = task_id,
    };
    if (trapCall(&request, &response) != .success) return null;
    return response;
}

const SurfacePresentOutcome = struct {
    status: abi.SyscallStatus,
    accepted: bool = false,
};

fn surfacePresent(
    presentation_capability_id: u64,
    task_id: u64,
    presentation: abi.SurfacePresentation,
    text: *const abi.SurfaceText,
) SurfacePresentOutcome {
    var response = std.mem.zeroes(abi.BoolResponse);
    var request = SurfacePresentRequest{
        .header = makeHeader(.surface_present, task_id),
        .presentation_capability_id = presentation_capability_id,
        .presenter_task_id = task_id,
        .surface_id = presentation.surface_id,
        .fence = presentation.revision,
        .buffer_object_id = presentation.buffer_object_id,
        .buffer_offset = presentation.buffer_offset,
        .buffer_bytes = presentation.buffer_bytes,
        .text = text,
    };
    const status = trapCall(&request, &response);
    return .{
        .status = status,
        .accepted = status == .success and response.value != 0,
    };
}

const InputDrain = struct {
    exhausted: bool = true,
};

fn drainFocusedInput(ui: *UiRuntime, comptime saves_documents: bool) InputDrain {
    if (comptime saves_documents) {
        if (ui.clipboard.pending()) return .{};
        if (!ui.document.canEdit(zigos_userspace_bootstrap.documentBinding(), &ui.surface)) return .{};
    }
    const input_capability_id = zigos_userspace_bootstrap.input_capability_id;
    const task_id = zigos_userspace_bootstrap.task_id;
    if (input_capability_id == 0 or task_id == 0) return .{};

    var received: usize = 0;
    while (received < INPUT_EVENTS_PER_DISPATCH) {
        const response = inputRecv(input_capability_id, task_id) orelse return .{};
        if (response.present == 0) return .{};
        received += 1;
        _ = recordInputEvent(ui, &zigos_userspace_bootstrap, response.event, saves_documents);
        if (comptime saves_documents) {
            if (ui.clipboard.pending()) return .{};
        }
    }
    return .{ .exhausted = false };
}

fn initializeUiState(ui: *UiRuntime, comptime bundle_id: []const u8, comptime contract_flags: u32) void {
    if (comptime (contract_flags & mailbox.FLAG_OWNS_UI_SURFACE) == 0) return;
    ui.surface = ui_surface_state.State.init(bundle_id);
    publishUiState(&zigos_userspace_bootstrap, &ui.surface);
}

fn recordInputEvent(ui: *UiRuntime, state: *mailbox.Mailbox, event: abi.InputEventDescriptor, comptime saves_documents: bool) bool {
    if (ui.surface.model == .compositor and !ui.launcher.acceptsInput(event)) return false;
    if (!applyInputEvent(state, &ui.surface, event, if (ui.surface.model == .compositor) &ui.launcher else null)) return false;
    if (comptime saves_documents) {
        if (event.length != 0 and event.bytes[0] == abi.InputByte.commit_text) ui.document.requestSave(state.documentBinding(), &ui.surface);
        ui.clipboard.start(state.clipboardBinding(), &ui.surface, event);
    }
    return true;
}

fn applyInputEvent(
    state: *mailbox.Mailbox,
    surface: *ui_surface_state.State,
    event: abi.InputEventDescriptor,
    launcher: ?*launcher_client.Client,
) bool {
    if (event.sequence == 0 or event.task_id != state.task_id) return false;
    if (surface.apply(event) == .rejected) return false;
    if (launcher) |client| client.recordInput(event, surface);
    state.input_event_count +|= 1;
    state.last_input_sequence = event.sequence;
    state.last_input_window_id = event.window_id;
    state.last_input_surface_id = event.surface_id;
    state.last_input_kind = if (event.length > 0) event.bytes[0] else 0;
    state.last_input_text = if (event.length > 1) event.bytes[1] else 0;
    state.last_input_port_id = event.port_id;
    state.last_input_slot_id = event.slot_id;
    publishUiState(state, surface);
    return true;
}

fn publishUiState(state: *mailbox.Mailbox, surface: *const ui_surface_state.State) void {
    state.ui_model_kind = @intFromEnum(surface.model);
    state.ui_state_flags = @bitCast(surface.flags);
    state.ui_focus_index = surface.focus_index;
    state.ui_text_length = surface.text_length;
    std.crypto.hash.sha2.Sha256.hash(surface.textSlice(), &state.ui_text_digest, .{});
    state.ui_cursor = surface.cursor;
    state.ui_commit_count = surface.commit_count;
    state.ui_activation_count = surface.activation_count;
    state.ui_state_revision = surface.revision;
    state.ui_interaction_hash = surface.interaction_hash;
}

fn presentUiState(state: *mailbox.Mailbox, surface: *const ui_surface_state.State) bool {
    if (state.ui_presented_revision == surface.revision) return true;
    if (state.surface_presentation_capability_id == 0 or state.task_id == 0 or state.ui_surface_id == 0) return false;

    const presentation = surface.presentation(state.ui_surface_id);
    var text = surface.presentationText();
    const outcome = surfacePresent(
        state.surface_presentation_capability_id,
        state.task_id,
        presentation,
        &text,
    );
    state.ui_last_presentation_status = @intFromEnum(outcome.status);
    if (!outcome.accepted) {
        state.ui_presentation_failures +|= 1;
        return false;
    }
    state.ui_presented_revision = surface.revision;
    return true;
}

const DocumentTransport = struct {
    pub fn send(_: @This(), endpoint_capability_id: u64, correlation_id: u64, payload: []const u8) document_editor.SendResult {
        var request = EndpointSendRequest{
            .header = makeHeader(.endpoint_send, zigos_userspace_bootstrap.task_id),
            .correlation_id = correlation_id,
            .endpoint_capability_id = endpoint_capability_id,
            .payload = payload,
        };
        return switch (trapCallNoResponse(&request)) {
            .success => .sent,
            .would_block => .busy,
            else => .failed,
        };
    }

    pub fn receive(_: @This(), endpoint_capability_id: u64) document_editor.ReceiveResult {
        const received = endpointRecv(endpoint_capability_id, zigos_userspace_bootstrap.task_id) orelse return .failed;
        if (received.present == 0) return .empty;
        // The document service sends data-only replies over this dedicated
        // channel. Unexpected authority must never acknowledge a save.
        if (received.has_attached_capability != 0) {
            return .failed;
        }
        return .{ .reply = .{
            .sender_endpoint_id = received.message.sender_endpoint_id,
            .correlation_id = received.message.correlation_id,
            .length = received.message.payload_len,
            .bytes = received.payload,
        } };
    }
};

fn runSteadyState(ui: *UiRuntime, detail: mailbox.Detail, heartbeat_increment: u32, comptime consumes_input: bool, comptime saves_documents: bool, comptime identity_probe: bool) noreturn {
    var probe: if (identity_probe) @import("identity_client_proof.zig").Probe else void = if (identity_probe) .{} else {};
    const increment: u16 = @truncate(if (heartbeat_increment == 0) 1 else heartbeat_increment);
    var pulse: u16 = 4;
    while (true) {
        const identity_work = if (comptime identity_probe) probe.step(&zigos_userspace_bootstrap, DocumentTransport{}) else false;
        const disposition: mailbox.YieldDisposition = if (comptime consumes_input) wait: {
            const launcher_work = if (ui.surface.model == .compositor) ui.launcher.step(zigos_userspace_bootstrap.launcherBinding(), &ui.surface, DocumentTransport{}) else false;
            const input = drainFocusedInput(ui, saves_documents);
            const clipboard_work = if (comptime saves_documents) ui.clipboard.step(&ui.surface, DocumentTransport{}) else false;
            const document_work = if (comptime saves_documents) work: {
                const pending = ui.document.step(zigos_userspace_bootstrap.documentBinding(), &ui.surface, DocumentTransport{});
                break :work pending;
            } else false;
            if (zigos_userspace_bootstrap.ui_state_revision != ui.surface.revision) publishUiState(&zigos_userspace_bootstrap, &ui.surface);
            _ = presentUiState(&zigos_userspace_bootstrap, &ui.surface);
            break :wait if (input.exhausted and !document_work and !clipboard_work and !launcher_work and !identity_work and !ui.launcher.hasUnsentDecision()) blk: {
                parkUntilEvent();
                break :blk .wait_for_event;
            } else .runnable;
        } else .runnable;
        publishStateWithDisposition(.steady, detail, pulse, disposition);
        pulse +%= increment;
    }
}

fn publishState(stage: mailbox.Stage, detail: mailbox.Detail, pulse: u16) void {
    publishStateWithDisposition(stage, detail, pulse, .runnable);
}

fn publishStateWithDisposition(
    stage: mailbox.Stage,
    detail: mailbox.Detail,
    pulse: u16,
    disposition: mailbox.YieldDisposition,
) void {
    const counter = mailbox.packCounter(stage, detail, pulse);
    zigos_userspace_bootstrap.stage = @intFromEnum(stage);
    zigos_userspace_bootstrap.detail = @intFromEnum(detail);
    zigos_userspace_bootstrap.last_counter = counter;
    _ = yieldCounter(counter, disposition, zigos_userspace_bootstrap.ui_state_revision);
}

fn signalFault(detail: mailbox.Detail, code: u8) noreturn {
    zigos_userspace_bootstrap.fault_code = code;
    while (true) {
        publishState(.fault, detail, @as(u16, code));
    }
}

fn yieldCounter(value: u32, disposition: mailbox.YieldDisposition, ui_revision: u64) u32 {
    if (builtin.target.os.tag != .freestanding) return value;
    return freestanding_syscall.syscall_yield_asm(value, disposition, ui_revision);
}

fn trapCall(request: anytype, response: anytype) abi.SyscallStatus {
    return freestanding_syscall.call(
        @enumFromInt(request.header.operation),
        @intFromPtr(request),
        @intFromPtr(response),
        @sizeOf(@TypeOf(response.*)),
    ).status;
}

fn trapCallNoResponse(request: anytype) abi.SyscallStatus {
    return freestanding_syscall.call(@enumFromInt(request.header.operation), @intFromPtr(request), 0, 0).status;
}

fn makeHeader(operation: abi.NativeOperation, subject_task_id: u64) abi.RequestHeader {
    return .{
        .operation = abi.opcode(operation),
        .subject_task_id = subject_task_id,
    };
}

fn faultCode(msg: []const u8) u8 {
    var code: u8 = 0x40;
    for (msg) |byte| {
        code +%= byte;
    }
    return if (code == 0) 1 else code;
}

test "fault codes stay stable for the same message" {
    try std.testing.expectEqual(faultCode("panic"), faultCode("panic"));
    try std.testing.expect(faultCode("panic") != faultCode("different"));
}

test "Notes input snapshots a save before processing subsequent typing" {
    var ui = UiRuntime{ .surface = ui_surface_state.State.init("app.notes") };
    var state = mailbox.Mailbox{
        .task_id = 2,
        .ui_channel_kind = .document,
        .ui_channel = .{ .document = .{ .endpoint_capability_id = 10, .service_endpoint_id = 11, .object_id = 12, .version_id = 13 } },
    };
    ui.document = .{
        .binding = state.documentBinding(),
        .client = .{ .service_endpoint_id = 11, .object_id = 12, .version_id = 13 },
        .opened = true,
    };
    var event = std.mem.zeroes(abi.InputEventDescriptor);
    event.sequence = 1;
    event.task_id = 2;
    event.length = 2;
    event.bytes[0] = abi.InputByte.text;
    event.bytes[1] = 'a';
    try std.testing.expect(recordInputEvent(&ui, &state, event, true));
    event.sequence += 1;
    event.length = 2;
    event.bytes[0] = abi.InputByte.commit_text;
    event.bytes[1] = 0;
    try std.testing.expect(recordInputEvent(&ui, &state, event, true));
    event.sequence += 1;
    event.length = 2;
    event.bytes[0] = abi.InputByte.text;
    event.bytes[1] = 'b';
    try std.testing.expect(recordInputEvent(&ui, &state, event, true));
    try std.testing.expectEqualStrings("ab", ui.surface.textSlice());
    try std.testing.expectEqualStrings("a", ui.document.client.?.snapshot[0..ui.document.client.?.length]);
}

test "interleaved Notes editors retain their own text and pending save" {
    var editors = [_]UiRuntime{
        .{ .surface = ui_surface_state.State.init("app.notes") },
        .{ .surface = ui_surface_state.State.init("app.notes") },
    };
    var states = [_]mailbox.Mailbox{
        .{ .task_id = 1, .ui_channel_kind = .document, .ui_channel = .{ .document = .{ .endpoint_capability_id = 10, .service_endpoint_id = 11, .object_id = 12, .version_id = 13 } } },
        .{ .task_id = 2, .ui_channel_kind = .document, .ui_channel = .{ .document = .{ .endpoint_capability_id = 20, .service_endpoint_id = 21, .object_id = 22, .version_id = 23 } } },
    };
    for (&editors, &states) |*editor, *state| {
        editor.document = .{
            .binding = state.documentBinding(),
            .client = .{ .service_endpoint_id = state.documentBinding().service_endpoint_id, .object_id = state.documentBinding().object_id, .version_id = state.documentBinding().version_id },
            .opened = true,
        };
    }
    for (0..2) |round| {
        for (&editors, &states, "ab") |*editor, *state, byte| {
            var event = std.mem.zeroes(abi.InputEventDescriptor);
            event.task_id = state.task_id;
            event.sequence = round * 2 + 1;
            event.length = 2;
            event.bytes = abi.inputPacket(abi.InputByte.text, byte);
            try std.testing.expect(recordInputEvent(editor, state, event, true));
            event.sequence += 1;
            event.bytes = abi.inputPacket(abi.InputByte.commit_text, 0);
            try std.testing.expect(recordInputEvent(editor, state, event, true));
        }
    }
    for (&editors, &states, [_][]const u8{ "aa", "bb" }) |*editor, *state, expected| {
        try std.testing.expectEqualStrings(expected, editor.surface.textSlice());
        const client = &editor.document.client.?;
        try std.testing.expectEqualStrings(expected[0..1], client.snapshot[0..client.length]);
        try std.testing.expect(editor.document.has_queued);
        try std.testing.expectEqualStrings(expected, editor.document.queued[0..editor.document.queued_length]);
        try std.testing.expectEqual(state.documentBinding().object_id, client.object_id);
        try std.testing.expectEqual(@as(u64, 4), state.input_event_count);
    }
}

test "focused input telemetry rejects foreign events and records valid semantic input" {
    var state = mailbox.Mailbox{ .task_id = 41, .ui_surface_id = 13 };
    var surface = ui_surface_state.State.init("app.notes");
    const event = abi.InputEventDescriptor{
        .sequence = 7,
        .tick = 90,
        .window_id = 12,
        .task_id = 41,
        .surface_id = 13,
        .port_id = 2,
        .slot_id = 3,
        .length = 2,
        .bytes = abi.inputPacket(abi.InputByte.text, 'x'),
    };
    try std.testing.expect(applyInputEvent(&state, &surface, event, null));
    try std.testing.expectEqual(@as(u64, 1), state.input_event_count);
    try std.testing.expectEqual(@as(u64, 7), state.last_input_sequence);
    try std.testing.expectEqual(@as(u8, 'x'), state.last_input_text);
    try std.testing.expectEqualStrings("x", surface.textSlice());
    var expected_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("x", &expected_digest, .{});
    try std.testing.expectEqualSlices(u8, &expected_digest, &state.ui_text_digest);
    try std.testing.expectEqual(@as(u16, 1), state.ui_text_length);
    try std.testing.expectEqual(surface.revision, state.ui_state_revision);

    var foreign = event;
    foreign.task_id = 42;
    try std.testing.expect(!applyInputEvent(&state, &surface, foreign, null));
    foreign.task_id = 41;
    foreign.length = 0;
    try std.testing.expect(!applyInputEvent(&state, &surface, foreign, null));
    try std.testing.expectEqual(@as(u64, 1), state.input_event_count);
}

test "hosted UI presentation records unavailable transport without acknowledging revision" {
    var state = mailbox.Mailbox{
        .task_id = 41,
        .surface_presentation_capability_id = 99,
        .ui_surface_id = 13,
    };
    const surface = ui_surface_state.State.init("app.notes");

    try std.testing.expect(!presentUiState(&state, &surface));
    try std.testing.expectEqual(@as(u64, 0), state.ui_presented_revision);
    try std.testing.expectEqual(@as(u32, 1), state.ui_presentation_failures);
    try std.testing.expectEqual(@intFromEnum(abi.SyscallStatus.unavailable), state.ui_last_presentation_status);
}

test "userspace service startup plans expose domain-specific endpoint operations" {
    const storage = service_protocol.planFor(.storage);
    const network = service_protocol.planFor(.network);
    const package = service_protocol.planFor(.package);
    const compositor = service_protocol.planFor(.compositor);
    const sync = service_protocol.planFor(.sync);

    try std.testing.expectEqual(@as(u8, @intFromEnum(ServiceKind.storage)), @as(u8, @intFromEnum(storage.kind)));
    try std.testing.expectEqual(@as(u8, 4), storage.operation_count);
    try std.testing.expectEqual(@as(u8, 3), network.operation_count);
    try std.testing.expectEqual(@as(u8, 4), package.operation_count);
    try std.testing.expectEqual(@as(u8, 4), compositor.operation_count);
    try std.testing.expectEqual(@as(u8, 4), sync.operation_count);
    try std.testing.expect(!std.mem.eql(u8, storage.endpoint_label, network.endpoint_label));
    try std.testing.expect(!std.mem.eql(u8, package.operations[0].name, compositor.operations[0].name));
}

test "compositor picker navigation publishes its selected row through the mailbox" {
    std.testing.refAllDecls(launcher_client);
    var ui = UiRuntime{ .surface = ui_surface_state.State.init("zigos.system.display") };
    var state = mailbox.Mailbox{ .task_id = 2 };
    ui.launcher = .{ .binding = .{ .endpoint_capability_id = 3, .service_endpoint_id = 4 }, .window_id = 9, .token = 1, .finished = false, .page = .{ .window_id = 9, .text_length = 9, .count = 2, .previous = false, .next = false } };
    @memcpy(ui.launcher.labels[0..9], "a.md\nb.md");
    @memcpy(ui.surface.text[0..24], "a.md\nb.md\nOpen    Cancel");
    ui.surface.text_length = 24;
    ui.surface.window_id = 9;
    ui.surface.flags.active = true;
    var event = std.mem.zeroes(abi.InputEventDescriptor);
    event.task_id = 2;
    event.window_id = 9;
    event.sequence = 1;
    event.length = 2;
    event.bytes = abi.inputPacket(abi.InputByte.cursor_down, 0);
    try std.testing.expect(recordInputEvent(&ui, &state, event, false));
    try std.testing.expectEqual(@as(u16, 5), state.ui_cursor);
    try std.testing.expectEqual(ui.surface.revision, state.ui_state_revision);
    try std.testing.expect(ui.surface.presentationText().isCanonical());
}
