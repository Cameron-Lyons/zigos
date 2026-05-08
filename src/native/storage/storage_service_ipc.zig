const std = @import("std");
const abi = @import("../core/abi.zig");
const binary_cursor = @import("../core/binary_cursor.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const principal = @import("../core/principal.zig");
const service_catalog = @import("../session/service_catalog.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const storage_service = @import("storage_service.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");
const workspace = @import("workspace.zig");

pub const MAGIC: u32 = 0x53544731; // STG1
pub const WIRE_VERSION: u16 = 1;
pub const MAX_WORKSPACE_LABEL_BYTES: usize = 48;

const SESSION_AUTHORITY_SERVICE_ID: u64 = 99;
const STORAGE_SERVICE_ID: u64 = 404;
const STORAGE_IMAGE_ID: u64 = 401;
const CLIENT_IMAGE_ID: u64 = 402;
const STORAGE_TASK_CREATE_CORRELATION_ID: u64 = 101;
const CLIENT_TASK_CREATE_CORRELATION_ID: u64 = 102;
const STORAGE_ENDPOINT_CREATE_CORRELATION_ID: u64 = 103;
const CLIENT_ENDPOINT_CREATE_CORRELATION_ID: u64 = 104;
const ENDPOINT_CONNECT_CORRELATION_ID: u64 = 105;
const STORAGE_TASK_CREATE_TICK: u64 = 10;
const CLIENT_TASK_CREATE_TICK: u64 = 11;
const STORAGE_ENDPOINT_CREATE_TICK: u64 = 12;
const CLIENT_ENDPOINT_CREATE_TICK: u64 = 13;
const ENDPOINT_CONNECT_TICK: u64 = 14;
const SESSION_TASK_BUDGET = task_runtime.ResourceBudget{
    .cpu_time_ticks = 10_000,
    .memory_bytes = 4096,
    .endpoint_slots = 8,
    .shared_memory_bytes = 4096,
};
const STORAGE_TASK_BUDGET = task_runtime.ResourceBudget{
    .cpu_time_ticks = 5_000,
    .memory_bytes = 256 * 1024,
    .endpoint_slots = 8,
    .shared_memory_bytes = 16 * 1024,
    .resource_class = .emergency_system_critical,
};
const CLIENT_TASK_BUDGET = task_runtime.ResourceBudget{
    .cpu_time_ticks = 2_000,
    .memory_bytes = 128 * 1024,
    .endpoint_slots = 4,
    .shared_memory_bytes = 4096,
};

pub const Error = error{
    LabelTooLong,
    MalformedRequest,
    MalformedResponse,
    NoSpaceLeft,
    SyscallFailed,
};

pub const Operation = enum(u16) {
    create_workspace = 1,
};

pub const Status = enum(u16) {
    ok = 0,
    malformed_request,
    missing_authority,
    capability_revoked,
    permission_denied,
    scope_violation,
    label_too_long,
    workspace_table_full,
    storage_error,
    syscall_failed,
};

pub const CreateWorkspaceRequest = struct {
    owner: principal.PrincipalId,
    label: []const u8,
};

pub const CreateWorkspaceResult = struct {
    status: Status,
    denial_reason: abi.DenialReason = .none,
    workspace_id: u64 = 0,
    generation: u32 = 0,

    pub fn ok(workspace_record: *const workspace.WorkspaceRecord) CreateWorkspaceResult {
        return .{
            .status = .ok,
            .workspace_id = workspace_record.id.raw(),
            .generation = workspace_record.generation,
        };
    }
};

const RequestWriter = binary_cursor.Writer(error{NoSpaceLeft}, error.NoSpaceLeft);
const RequestReader = binary_cursor.Reader(error{MalformedRequest}, error.MalformedRequest);
const ResponseWriter = binary_cursor.Writer(error{NoSpaceLeft}, error.NoSpaceLeft);
const ResponseReader = binary_cursor.Reader(error{MalformedResponse}, error.MalformedResponse);

pub fn encodeCreateWorkspaceRequest(
    buffer: []u8,
    owner: principal.PrincipalId,
    label: []const u8,
) Error![]const u8 {
    if (label.len > MAX_WORKSPACE_LABEL_BYTES) return error.LabelTooLong;

    var writer = RequestWriter{ .buffer = buffer };
    try writer.writeU32(MAGIC);
    try writer.writeU16(WIRE_VERSION);
    try writer.writeU16(@intFromEnum(Operation.create_workspace));
    try writer.writeU16(@intFromEnum(owner.kind));
    try writer.writeU16(@intCast(label.len));
    try writer.writeU64(owner.serial);
    try writer.writeBytes(label);
    return buffer[0..writer.offset];
}

pub fn decodeCreateWorkspaceRequest(payload: []const u8) Error!CreateWorkspaceRequest {
    var reader = RequestReader{ .buffer = payload };
    if (try reader.readU32() != MAGIC) return error.MalformedRequest;
    if (try reader.readU16() != WIRE_VERSION) return error.MalformedRequest;
    const operation = std.enums.fromInt(Operation, try reader.readU16()) orelse return error.MalformedRequest;
    if (operation != .create_workspace) return error.MalformedRequest;

    const owner_kind_raw = try reader.readU16();
    if (owner_kind_raw > std.math.maxInt(u8)) return error.MalformedRequest;
    const owner_kind = std.enums.fromInt(principal.PrincipalKind, @as(u8, @intCast(owner_kind_raw))) orelse return error.MalformedRequest;
    const label_len = try reader.readU16();
    if (label_len > MAX_WORKSPACE_LABEL_BYTES) return error.MalformedRequest;
    const owner_serial = try reader.readU64();
    const label = try reader.readSlice(label_len);
    if (reader.offset != payload.len) return error.MalformedRequest;

    return .{
        .owner = .{
            .kind = owner_kind,
            .serial = owner_serial,
        },
        .label = label,
    };
}

pub fn encodeCreateWorkspaceResponse(buffer: []u8, result: CreateWorkspaceResult) Error![]const u8 {
    var writer = ResponseWriter{ .buffer = buffer };
    try writer.writeU32(MAGIC);
    try writer.writeU16(WIRE_VERSION);
    try writer.writeU16(@intFromEnum(Operation.create_workspace));
    try writer.writeU16(@intFromEnum(result.status));
    try writer.writeU16(@intFromEnum(result.denial_reason));
    try writer.writeU64(result.workspace_id);
    try writer.writeU32(result.generation);
    return buffer[0..writer.offset];
}

pub fn decodeCreateWorkspaceResponse(payload: []const u8) Error!CreateWorkspaceResult {
    var reader = ResponseReader{ .buffer = payload };
    if (try reader.readU32() != MAGIC) return error.MalformedResponse;
    if (try reader.readU16() != WIRE_VERSION) return error.MalformedResponse;
    const operation = std.enums.fromInt(Operation, try reader.readU16()) orelse return error.MalformedResponse;
    if (operation != .create_workspace) return error.MalformedResponse;

    const status = std.enums.fromInt(Status, try reader.readU16()) orelse return error.MalformedResponse;
    const denial_reason = std.enums.fromInt(abi.DenialReason, try reader.readU16()) orelse return error.MalformedResponse;
    const workspace_id = try reader.readU64();
    const generation = try reader.readU32();
    if (reader.offset != payload.len) return error.MalformedResponse;

    return .{
        .status = status,
        .denial_reason = denial_reason,
        .workspace_id = workspace_id,
        .generation = generation,
    };
}

pub const Client = struct {
    port: *component_port.KernelPort,
    task_id: u64,
    endpoint_capability_id: u64,
    storage_authority_capability_id: u64,

    pub fn sendCreateWorkspace(
        self: *const Client,
        correlation_id: u64,
        owner: principal.PrincipalId,
        label: []const u8,
        now_ticks: u64,
    ) Error!void {
        var payload_buffer: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
        const payload = try encodeCreateWorkspaceRequest(&payload_buffer, owner, label);
        try syscallEndpointSend(
            self.port,
            self.task_id,
            self.endpoint_capability_id,
            correlation_id,
            payload,
            self.storage_authority_capability_id,
            false,
            now_ticks,
        );
    }

    pub fn recvCreateWorkspace(
        self: *const Client,
        now_ticks: u64,
    ) Error!?CreateWorkspaceResult {
        const response = try syscallEndpointRecv(
            self.port,
            self.task_id,
            self.endpoint_capability_id,
            now_ticks,
        );
        if (response.present == 0) return null;
        const payload_len: usize = @intCast(response.message.payload_len);
        return try decodeCreateWorkspaceResponse(response.payload[0..payload_len]);
    }
};

pub const Server = struct {
    port: *component_port.KernelPort,
    service: *storage_service.Service,
    capability_table: *const capability.CapabilityTable,
    task_id: u64,
    endpoint_capability_id: u64,

    pub fn runOnce(self: *Server, now_ticks: u64) Error!bool {
        const received = try syscallEndpointRecv(
            self.port,
            self.task_id,
            self.endpoint_capability_id,
            now_ticks,
        );
        if (received.present == 0) return false;

        const payload_len: usize = @intCast(received.message.payload_len);
        const result = self.handleCreateWorkspace(
            received.payload[0..payload_len],
            received,
            now_ticks,
        );

        var response_buffer: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
        const response = try encodeCreateWorkspaceResponse(&response_buffer, result);
        try syscallEndpointSend(
            self.port,
            self.task_id,
            self.endpoint_capability_id,
            received.message.correlation_id,
            response,
            null,
            false,
            now_ticks,
        );
        return true;
    }

    fn handleCreateWorkspace(
        self: *Server,
        payload: []const u8,
        received: abi.EndpointRecvResponse,
        now_ticks: u64,
    ) CreateWorkspaceResult {
        const request = decodeCreateWorkspaceRequest(payload) catch return .{
            .status = .malformed_request,
            .denial_reason = .invalid_target,
        };
        if (received.has_attached_capability == 0 or received.attached_capability.capability_id == 0) return .{
            .status = .missing_authority,
            .denial_reason = .capability_missing,
        };

        var storage_port = storage_service.StoragePort.init(self.service, self.capability_table);
        const workspace_record = storage_port.createWorkspace(.{
            .task_id = self.task_id,
            .principal = self.service.owner,
            .capability_id = received.attached_capability.capability_id,
            .now_ticks = now_ticks,
        }, .{
            .owner = request.owner,
            .label = request.label,
        }) catch |err| return mapStorageError(err);

        return CreateWorkspaceResult.ok(workspace_record);
    }
};

fn mapStorageError(err: anyerror) CreateWorkspaceResult {
    return switch (err) {
        error.CapabilityNotFound, error.CapabilityRequired => .{
            .status = .missing_authority,
            .denial_reason = .capability_missing,
        },
        error.CapabilityRevoked => .{
            .status = .capability_revoked,
            .denial_reason = .capability_revoked,
        },
        error.PermissionDenied => .{
            .status = .permission_denied,
            .denial_reason = .policy_denied,
        },
        error.WorkspaceScopeViolation => .{
            .status = .scope_violation,
            .denial_reason = .scope_violation,
        },
        error.LabelTooLong => .{
            .status = .label_too_long,
            .denial_reason = .invalid_target,
        },
        error.WorkspaceTableFull => .{
            .status = .workspace_table_full,
            .denial_reason = .budget_exhausted,
        },
        else => .{
            .status = .storage_error,
            .denial_reason = .invalid_target,
        },
    };
}

fn syscallEndpointSend(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    correlation_id: u64,
    payload: []const u8,
    attached_capability_id: ?u64,
    move_attached_capability: bool,
    now_ticks: u64,
) Error!void {
    var request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, correlation_id, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
        .attached_capability_id = attached_capability_id,
        .move_attached_capability = move_attached_capability,
    };
    const result = syscall_surface.dispatch(
        port,
        caller_task_id,
        now_ticks,
        @intFromPtr(&request),
        0,
        0,
    );
    if (result.status != .success) return error.SyscallFailed;
}

fn syscallEndpointRecv(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    now_ticks: u64,
) Error!abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, 0, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = caller_task_id,
    };
    const result = syscall_surface.dispatch(
        port,
        caller_task_id,
        now_ticks,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );
    if (result.status != .success) return error.SyscallFailed;
    return response;
}

pub fn userspaceCreateWorkspaceRoundTripProof() !void {
    var harness = UserspaceStorageHarness{};
    try harness.init();

    const storage_task = harness.runtime.find(harness.storage_task_id).?;
    try std.testing.expect(storage_task.runsAsUserspaceProcess());
    try std.testing.expectEqualStrings("zigos.system.storage-object", storage_task.launchBundleIdSlice());

    const owner = principal.PrincipalId{ .kind = .user, .serial = 77 };
    var client = Client{
        .port = &harness.port,
        .task_id = harness.client_task_id,
        .endpoint_capability_id = harness.client_endpoint_capability_id,
        .storage_authority_capability_id = harness.storage_authority_capability_id,
    };
    var server = Server{
        .port = &harness.port,
        .service = &harness.storage,
        .capability_table = &harness.capabilities,
        .task_id = harness.storage_task_id,
        .endpoint_capability_id = harness.storage_endpoint_capability_id,
    };

    try client.sendCreateWorkspace(0x5A47, owner, "ipc-created-notes", 20);
    try std.testing.expect(try server.runOnce(21));
    const response = (try client.recvCreateWorkspace(22)).?;

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqual(abi.DenialReason.none, response.denial_reason);
    try std.testing.expect(response.workspace_id != 0);
    try std.testing.expect(harness.storage.findWorkspace(owner, "ipc-created-notes") != null);
    try std.testing.expect(harness.storage.findWorkspace(.{ .kind = .user, .serial = 78 }, "ipc-created-notes") == null);

    var service_caps: [8]capability.Capability = undefined;
    const passed_caps = harness.capabilities.queryByHolder(harness.storage_owner, &service_caps);
    var found_passed_storage_authority = false;
    for (passed_caps) |capability_record| {
        if (capability_record.target.kind == .service and
            capability_record.target.id == harness.storage_service_id and
            capability_record.scope.task_id == harness.storage_task_id and
            capability_record.rights.has(.object_write))
        {
            found_passed_storage_authority = true;
        }
    }
    try std.testing.expect(found_passed_storage_authority);
}

const UserspaceStorageHarness = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    policy_authority: principal.PrincipalId = .{ .kind = .policy_authority, .serial = 1 },
    session_owner: principal.PrincipalId = .{ .kind = .service, .serial = 2 },
    storage_owner: principal.PrincipalId = .{ .kind = .service, .serial = 4 },
    client_owner: principal.PrincipalId = .{ .kind = .app, .serial = 20 },
    session_task_id: u64 = 0,
    storage_task_id: u64 = 0,
    client_task_id: u64 = 0,
    session_authority_capability_id: u64 = 0,
    storage_authority_capability_id: u64 = 0,
    storage_endpoint_capability_id: u64 = 0,
    client_endpoint_capability_id: u64 = 0,
    storage_service_id: u64 = STORAGE_SERVICE_ID,

    fn init(self: *UserspaceStorageHarness) !void {
        self.checkpoint_store.resetPersistent();
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
            .budget = SESSION_TASK_BUDGET,
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
                .capability_query = true,
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

        const storage_bundle_id = service_catalog.bundleIdForServiceClass(.storage_object).?;
        const storage_image = task_runtime.syntheticUserspaceImage("workspace-storage", "zigos.object.workspace");
        const storage_task = try self.port.taskCreate(.{
            .header = component_port.makeHeader(.task_create, STORAGE_TASK_CREATE_CORRELATION_ID, self.session_task_id),
            .authority_capability_id = self.session_authority_capability_id,
            .request = .{
                .owner = self.storage_owner,
                .component_class = .service_component,
                .budget = STORAGE_TASK_BUDGET,
                .local_only = true,
                .initial_component = .{
                    .label = "workspace-storage",
                    .entry = "zigos.object.workspace",
                },
                .launch = .{
                    .boundary = .userspace_process,
                    .image_id = STORAGE_IMAGE_ID,
                    .component_abi_version = abi.ABI_VERSION,
                    .signed = true,
                    .bundle_id = storage_bundle_id,
                },
                .userspace_image = &storage_image,
            },
        }, STORAGE_TASK_CREATE_TICK);
        self.storage_task_id = storage_task.task_id;

        const client_image = task_runtime.syntheticUserspaceImage("storage-client", "app.storage-client");
        const client_task = try self.port.taskCreate(.{
            .header = component_port.makeHeader(.task_create, CLIENT_TASK_CREATE_CORRELATION_ID, self.session_task_id),
            .authority_capability_id = self.session_authority_capability_id,
            .request = .{
                .owner = self.client_owner,
                .component_class = .app_component,
                .budget = CLIENT_TASK_BUDGET,
                .local_only = true,
                .initial_component = .{
                    .label = "storage-client",
                    .entry = "app.storage-client",
                },
                .launch = .{
                    .boundary = .userspace_process,
                    .image_id = CLIENT_IMAGE_ID,
                    .component_abi_version = abi.ABI_VERSION,
                    .signed = true,
                    .bundle_id = "app.storage-client",
                },
                .userspace_image = &client_image,
            },
        }, CLIENT_TASK_CREATE_TICK);
        self.client_task_id = client_task.task_id;
        self.runtime.allowHostPointerSyscallsForTask(self.storage_task_id);
        self.runtime.allowHostPointerSyscallsForTask(self.client_task_id);

        self.storage = storage_service.Service.initWithStore(
            self.storage_service_id,
            self.storage_task_id,
            self.storage_owner,
            &self.checkpoint_store,
        );
        self.storage.bindCapabilityTable(&self.capabilities);
        self.storage.checkpoint_enabled = false;

        const storage_endpoint = try self.port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, STORAGE_ENDPOINT_CREATE_CORRELATION_ID, self.session_task_id),
            .authority_capability_id = self.session_authority_capability_id,
            .owner_task_id = self.storage_task_id,
            .label = "zigos.object.workspace",
            .flags = .{
                .local_only = true,
                .service_port = true,
                .carries_capability = true,
            },
        }, STORAGE_ENDPOINT_CREATE_TICK);
        self.storage_endpoint_capability_id = storage_endpoint.capability_id;

        const client_endpoint = try self.port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, CLIENT_ENDPOINT_CREATE_CORRELATION_ID, self.session_task_id),
            .authority_capability_id = self.session_authority_capability_id,
            .owner_task_id = self.client_task_id,
            .label = "storage-client",
            .flags = .{ .local_only = true },
        }, CLIENT_ENDPOINT_CREATE_TICK);
        self.client_endpoint_capability_id = client_endpoint.capability_id;

        _ = try self.port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, ENDPOINT_CONNECT_CORRELATION_ID, self.client_task_id),
            .endpoint_capability_id = self.client_endpoint_capability_id,
            .peer_endpoint_capability_id = self.storage_endpoint_capability_id,
            .peer_endpoint_id = storage_endpoint.endpoint.endpoint_id,
        }, ENDPOINT_CONNECT_TICK);

        const storage_authority = try self.capabilities.mintBootRoot(.{
            .holder = self.client_owner,
            .issuer = self.policy_authority,
            .target = .{ .kind = .service, .id = self.storage_service_id },
            .rights = .{ .service = .{
                .object_read = true,
                .object_write = true,
                .capability_pass = true,
            } },
            .scope = .{
                .task_id = self.client_task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = ENDPOINT_CONNECT_TICK,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = self.client_task_id,
                .broker_service_id = self.storage_service_id,
            },
        });
        self.storage_authority_capability_id = storage_authority.id;
        try self.runtime.grantCapability(self.client_task_id, self.storage_authority_capability_id);
    }
};

test "storage userspace service handles typed create-workspace ipc over endpoint syscalls" {
    try userspaceCreateWorkspaceRoundTripProof();
}
