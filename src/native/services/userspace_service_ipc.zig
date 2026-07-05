const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const capability = @import("../kernel_api/capability.zig");
const component_abi_schema = @import("component_abi_schema.zig");
const component_port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const units = @import("../core/units.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const task_runtime = @import("../task/task_runtime.zig");
const service_protocol = @import("../task/userspace_service_protocol.zig");

pub const ServiceKind = service_protocol.ServiceKind;

const STARTUP_PROTOCOL_PROOF_TICK: u64 = 20;
const SERVICE_TASK_CREATE_TICK: u64 = 10;
const SESSION_AUTHORITY_SERVICE_ID: u64 = 99;
const SESSION_TASK_CPU_TICKS: u64 = 10_000;
const SESSION_TASK_MEMORY_BYTES: usize = shared_memory.PAGE_SIZE;
const SESSION_TASK_ENDPOINT_SLOTS: u16 = 8;
const SESSION_TASK_SHARED_MEMORY_BYTES: usize = shared_memory.PAGE_SIZE;
const SERVICE_TASK_CPU_TICKS: u64 = 6_000;
const SERVICE_TASK_MEMORY_BYTES: usize = units.kibibytes(256);
const SERVICE_TASK_ENDPOINT_SLOTS: u16 = 8;
const SERVICE_TASK_SHARED_MEMORY_BYTES: usize = units.kibibytes(16);
const EXPECTED_SERVICE_ENDPOINTS: u16 = 2;
const EXPECTED_SERVICE_CAPABILITIES: usize = 3;

pub const Error = error{
    ProtocolMismatch,
    SyscallFailed,
} || task_runtime.Error || capability.Error || native_kernel.Error || service_protocol.Error;

pub const ProofResult = struct {
    kind: ServiceKind,
    operation_count: u16,
    roundtrips: u16,
    service_endpoint_id: u64,
    peer_endpoint_id: u64,
    state_hash: u64,
};

pub fn proveCoreServiceStartupProtocolsUseEndpointSyscalls() !void {
    _ = try proveServiceStartupProtocol(.storage);
    _ = try proveServiceStartupProtocol(.sync);
    _ = try proveServiceStartupProtocol(.network);
    _ = try proveServiceStartupProtocol(.package);
    _ = try proveServiceStartupProtocol(.compositor);
}

pub fn proveServiceStartupProtocol(comptime kind: ServiceKind) !ProofResult {
    var harness = Harness{};
    try harness.init(kind);

    const result = try runStartupProtocol(
        kind,
        &harness.port,
        harness.service_task_id,
        harness.service_authority_capability_id,
        STARTUP_PROTOCOL_PROOF_TICK,
    );

    const service_plan = service_protocol.planFor(kind);
    try std.testing.expectEqual(kind, result.kind);
    try std.testing.expectEqual(@as(u16, @intCast(service_plan.operation_count)), result.operation_count);
    try std.testing.expectEqual(result.operation_count, result.roundtrips);
    try std.testing.expect(result.service_endpoint_id != 0);
    try std.testing.expect(result.peer_endpoint_id != 0);
    try std.testing.expect(result.state_hash != service_protocol.initialStateHash(kind));
    try std.testing.expectEqual(EXPECTED_SERVICE_ENDPOINTS, harness.endpoints.activeForTask(ids.task(harness.service_task_id)));

    const service_task = harness.runtime.find(harness.service_task_id).?;
    try std.testing.expect(service_task.runsAsUserspaceProcess());
    try std.testing.expect(service_task.hasLoadedExecutable());
    try std.testing.expect(service_task.zero_ambient_authority);
    try std.testing.expectEqual(EXPECTED_SERVICE_CAPABILITIES, service_task.capability_count);

    return result;
}

fn runStartupProtocol(
    comptime kind: ServiceKind,
    port: *component_port.KernelPort,
    task_id: u64,
    authority_capability_id: u64,
    now_ticks: u64,
) Error!ProofResult {
    const service_plan = service_protocol.planFor(kind);
    const service_endpoint = try syscallEndpointCreate(
        port,
        task_id,
        authority_capability_id,
        service_plan.endpoint_label,
        .{ .local_only = true, .service_port = true },
        now_ticks,
    );
    const peer_endpoint = try syscallEndpointCreate(
        port,
        task_id,
        authority_capability_id,
        "host-service-self-check",
        .{ .local_only = true },
        now_ticks,
    );
    _ = try syscallEndpointConnect(
        port,
        task_id,
        peer_endpoint.capability_id,
        service_endpoint.capability_id,
        service_endpoint.endpoint.endpoint_id,
        now_ticks,
    );

    var state_hash = service_protocol.initialStateHash(kind);
    var operation_count: u16 = 0;
    for (service_plan.slice(), 0..) |operation, index| {
        var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const request_payload = try service_protocol.encodeRequest(&request_buffer, kind, operation, index);
        try syscallEndpointSend(port, task_id, peer_endpoint.capability_id, request_payload, now_ticks);

        const received_request = try syscallEndpointRecv(port, task_id, service_endpoint.capability_id, now_ticks);
        if (received_request.present == 0) return error.ProtocolMismatch;
        const request_len: usize = @intCast(received_request.message.payload_len);
        if (request_len > received_request.payload.len) return error.ProtocolMismatch;
        const decoded_request = try service_protocol.decodeRequest(received_request.payload[0..request_len]);
        if (!service_protocol.requestMatchesOperation(decoded_request, kind, operation, index)) {
            return error.ProtocolMismatch;
        }

        state_hash = service_protocol.foldOperation(state_hash, operation, index);
        var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const response_payload = try service_protocol.encodeResponse(&response_buffer, decoded_request, state_hash);
        try syscallEndpointSend(port, task_id, service_endpoint.capability_id, response_payload, now_ticks);

        const received_response = try syscallEndpointRecv(port, task_id, peer_endpoint.capability_id, now_ticks);
        if (received_response.present == 0) return error.ProtocolMismatch;
        const response_len: usize = @intCast(received_response.message.payload_len);
        if (response_len > received_response.payload.len) return error.ProtocolMismatch;
        const decoded_response = try service_protocol.decodeResponse(received_response.payload[0..response_len]);
        if (!service_protocol.requestMatchesOperation(decoded_response, kind, operation, index)) {
            return error.ProtocolMismatch;
        }
        if (decoded_response.state_hash != state_hash) return error.ProtocolMismatch;
        operation_count += 1;
    }

    return .{
        .kind = kind,
        .operation_count = operation_count,
        .roundtrips = operation_count,
        .service_endpoint_id = service_endpoint.endpoint.endpoint_id,
        .peer_endpoint_id = peer_endpoint.endpoint.endpoint_id,
        .state_hash = state_hash,
    };
}

fn syscallEndpointCreate(
    port: *component_port.KernelPort,
    task_id: u64,
    authority_capability_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    now_ticks: u64,
) Error!abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    var request = component_port.EndpointCreateRequest{
        .header = component_port.makeHeader(.endpoint_create, nextCorrelationId(), task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = task_id,
        .label = label,
        .flags = flags,
    };
    const result = syscall_surface.dispatch(
        port,
        task_id,
        now_ticks,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointCreateResponse),
    );
    if (result.status != .success) return error.SyscallFailed;
    return response;
}

fn syscallEndpointConnect(
    port: *component_port.KernelPort,
    task_id: u64,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
    now_ticks: u64,
) Error!abi.EndpointDescriptor {
    var response = std.mem.zeroes(abi.EndpointDescriptor);
    var request = component_port.EndpointConnectRequest{
        .header = component_port.makeHeader(.endpoint_connect, nextCorrelationId(), task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    const result = syscall_surface.dispatch(
        port,
        task_id,
        now_ticks,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointDescriptor),
    );
    if (result.status != .success) return error.SyscallFailed;
    return response;
}

fn syscallEndpointSend(
    port: *component_port.KernelPort,
    task_id: u64,
    endpoint_capability_id: u64,
    payload: []const u8,
    now_ticks: u64,
) Error!void {
    var request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, nextCorrelationId(), task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
    };
    const result = syscall_surface.dispatch(
        port,
        task_id,
        now_ticks,
        @intFromPtr(&request),
        0,
        0,
    );
    if (result.status != .success) return error.SyscallFailed;
}

fn syscallEndpointRecv(
    port: *component_port.KernelPort,
    task_id: u64,
    endpoint_capability_id: u64,
    now_ticks: u64,
) Error!abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, nextCorrelationId(), task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = task_id,
    };
    const result = syscall_surface.dispatch(
        port,
        task_id,
        now_ticks,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );
    if (result.status != .success) return error.SyscallFailed;
    return response;
}

const Harness = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    policy_authority: principal.PrincipalId = .{ .kind = .policy_authority, .serial = 1 },
    session_owner: principal.PrincipalId = .{ .kind = .service, .serial = 2 },
    service_owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    session_task_id: u64 = 0,
    service_task_id: u64 = 0,
    session_authority_capability_id: u64 = 0,
    service_authority_capability_id: u64 = 0,

    fn init(self: *Harness, comptime kind: ServiceKind) !void {
        self.service_owner = .{ .kind = .service, .serial = serviceSerial(kind) };
        self.kernel = native_kernel.Kernel.init(
            self.policy_authority,
            &self.runtime,
            &self.capabilities,
            &self.endpoints,
            &self.shared,
        );
        self.port = component_port.KernelPort.init(&self.kernel);

        const session_task = try self.runtime.createTask(.{
            .owner = self.session_owner,
            .component_class = .session_manager,
            .budget = .{
                .cpu_time_ticks = SESSION_TASK_CPU_TICKS,
                .memory_bytes = SESSION_TASK_MEMORY_BYTES,
                .endpoint_slots = SESSION_TASK_ENDPOINT_SLOTS,
                .shared_memory_bytes = SESSION_TASK_SHARED_MEMORY_BYTES,
            },
            .local_only = true,
        });
        self.session_task_id = session_task.id;
        const session_authority = try self.capabilities.mintBootRoot(.{
            .holder = self.session_owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .service, .id = SESSION_AUTHORITY_SERVICE_ID },
            .rights = .{ .service = .{
                .task_create = true,
                .endpoint_create = true,
                .endpoint_connect = true,
                .capability_derive = true,
                .ipc_peer = true,
            } },
            .scope = .{ .local_only = true },
            .lease = .{
                .issued_at_ticks = 0,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = true,
            },
        });
        self.session_authority_capability_id = session_authority.id;
        try self.runtime.grantCapability(self.session_task_id, self.session_authority_capability_id);

        const image = try generated_image_fixtures.imageByBundleId(serviceBundle(kind));
        const service_task = try self.port.taskCreate(.{
            .header = component_port.makeHeader(.task_create, nextCorrelationId(), self.session_task_id),
            .authority_capability_id = self.session_authority_capability_id,
            .request = .{
                .owner = self.service_owner,
                .component_class = .service_component,
                .budget = .{
                    .cpu_time_ticks = SERVICE_TASK_CPU_TICKS,
                    .memory_bytes = SERVICE_TASK_MEMORY_BYTES,
                    .endpoint_slots = SERVICE_TASK_ENDPOINT_SLOTS,
                    .shared_memory_bytes = SERVICE_TASK_SHARED_MEMORY_BYTES,
                },
                .local_only = true,
                .initial_component = .{
                    .label = serviceLabel(kind),
                    .entry = serviceEntry(kind),
                },
                .launch = .{
                    .boundary = .userspace_process,
                    .image_id = serviceSerial(kind),
                    .component_abi_version = abi.ABI_VERSION,
                    .signed = true,
                    .bundle_id = serviceBundle(kind),
                },
                .userspace_image = &image,
            },
        }, SERVICE_TASK_CREATE_TICK);
        self.service_task_id = service_task.task_id;

        const service_authority = try self.capabilities.mintBootRoot(.{
            .holder = self.service_owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .service, .id = serviceSerial(kind) },
            .rights = .{ .service = .{
                .endpoint_create = true,
                .endpoint_connect = true,
                .ipc_peer = true,
            } },
            .scope = .{
                .task_id = self.service_task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = SERVICE_TASK_CREATE_TICK,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = false,
            },
        });
        self.service_authority_capability_id = service_authority.id;
        try self.runtime.grantCapability(self.service_task_id, self.service_authority_capability_id);
        self.runtime.allowHostPointerSyscallsForTask(self.service_task_id);
    }
};

fn serviceBundle(comptime kind: ServiceKind) []const u8 {
    return switch (kind) {
        .storage => "zigos.system.storage-object",
        .sync => "zigos.system.sync-service",
        .network => "zigos.system.network-stack",
        .package => "zigos.system.package-service",
        .compositor => "zigos.system.compositor",
        .generic => "zigos.system.generic-service",
    };
}

fn serviceLabel(comptime kind: ServiceKind) []const u8 {
    return switch (kind) {
        .storage => "workspace-storage",
        .sync => "sync-service",
        .network => "network-service",
        .package => "package-service",
        .compositor => "compositor-session",
        .generic => "generic-service",
    };
}

fn serviceEntry(comptime kind: ServiceKind) []const u8 {
    return switch (kind) {
        .storage => component_abi_schema.interfaceForService(.storage_object).name,
        .sync => component_abi_schema.interfaceForService(.sync_replication).name,
        .network => component_abi_schema.interfaceForService(.network_stack).name,
        .package => component_abi_schema.interfaceForService(.package_install_update).name,
        .compositor => component_abi_schema.interfaceForService(.compositor_ui_session).name,
        .generic => "zigos.service.generic",
    };
}

fn serviceSerial(comptime kind: ServiceKind) u64 {
    return switch (kind) {
        .storage => 401,
        .sync => 402,
        .network => 403,
        .package => 404,
        .compositor => 405,
        .generic => 400,
    };
}

fn nextCorrelationId() u64 {
    const id = next_correlation_id;
    next_correlation_id += 1;
    return id;
}

var next_correlation_id: u64 = 1;

test "core userspace service startup protocols run through endpoint syscalls" {
    try proveCoreServiceStartupProtocolsUseEndpointSyscalls();
}
