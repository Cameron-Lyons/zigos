const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const debug_contract = @import("../security/debug_contract.zig");
const endpoint = @import("endpoint.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const ids = @import("../core/ids.zig");
const operation_metadata = @import("operation_metadata.zig");
const native_kernel = @import("native_kernel.zig");
const shared_memory = @import("shared_memory.zig");
const syscall_abi = @import("syscall_abi.zig");
const syscall_dispatch = @import("syscall_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");

pub const DispatchResult = syscall_dispatch.DispatchResult;
pub const UserMemoryAccess = syscall_dispatch.UserMemoryAccess;
pub const validateAddressSpaceRange = syscall_dispatch.validateAddressSpaceRange;

const DispatchHandler = *const fn (
    port: *component_port.KernelPort,
    memory: syscall_dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult;

const SyscallDescriptor = struct {
    operation: abi.NativeOperation,
    request_size: usize,
    response_size: usize,
    domain: syscall_abi.Domain,
    request_copy: syscall_abi.RequestCopyRule,
    required_right: capability.CapabilityRight,
    target_kind: operation_metadata.TargetKindRule,
    scope_rule: operation_metadata.ScopeRule,
    auto_grant_count: usize,
    handler: DispatchHandler,
};

fn syscallDescriptor(
    comptime declaration: syscall_abi.Operation,
) SyscallDescriptor {
    return .{
        .operation = declaration.operation,
        .request_size = declaration.requestSize(),
        .response_size = declaration.responseSize(),
        .domain = declaration.domain,
        .request_copy = declaration.request_copy,
        .required_right = declaration.required_right,
        .target_kind = declaration.target_kind,
        .scope_rule = declaration.scope_rule,
        .auto_grant_count = declaration.auto_grants.len,
        .handler = declaration.handler,
    };
}

fn buildSyscallTable() [syscall_abi.operations.len]SyscallDescriptor {
    var table: [syscall_abi.operations.len]SyscallDescriptor = undefined;
    inline for (syscall_abi.operations, 0..) |declaration, index| {
        table[index] = syscallDescriptor(declaration);
    }
    return table;
}

const syscall_table = buildSyscallTable();
const opcode_index = buildOpcodeIndex();
const native_opcode_base: u16 = abi.opcode(.task_create);
const native_opcode_count: usize = std.meta.fields(abi.NativeOperation).len;
const missing_opcode_index = std.math.maxInt(usize);

pub fn dispatch(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    if (caller_task_id == 0) return syscall_dispatch.explainedFailure(
        .denied,
        .scope_violation,
        "syscall-dispatch",
        "subject-task",
        caller_task_id,
        0,
        null,
        0,
        now_ticks,
    );
    const memory = syscall_dispatch.UserMemoryContext.init(port, caller_task_id);
    const header = syscall_dispatch.readRequest(abi.RequestHeader, memory, request_addr) orelse return syscall_dispatch.explainedFailure(
        .invalid_request_pointer,
        .invalid_target,
        "syscall-dispatch",
        "request-header",
        caller_task_id,
        0,
        null,
        0,
        now_ticks,
    );
    if (header.version != abi.ABI_VERSION) return syscall_dispatch.explainedFailure(
        .unsupported_abi_version,
        .unsupported_operation,
        "syscall-dispatch",
        "native-abi-version",
        caller_task_id,
        0,
        null,
        header.version,
        now_ticks,
    );
    if (header.subject_task_id == 0 or header.subject_task_id != caller_task_id) return syscall_dispatch.explainedFailure(
        .denied,
        .scope_violation,
        "syscall-dispatch",
        "matching-subject-task",
        caller_task_id,
        0,
        .task,
        header.subject_task_id,
        now_ticks,
    );

    const descriptor = syscallDescriptorFromOpcode(header.operation) orelse return syscall_dispatch.explainedFailure(
        .unsupported_operation,
        .unsupported_operation,
        "unsupported-operation",
        "declared-native-operation",
        caller_task_id,
        0,
        null,
        header.operation,
        now_ticks,
    );

    return syscall_dispatch.withSyscallContract(
        descriptor.handler(port, memory, now_ticks, request_addr, response_addr, response_len),
        descriptor.operation,
        descriptor.required_right,
        caller_task_id,
        now_ticks,
    );
}

fn syscallDescriptorFromOpcode(opcode: u16) ?*const SyscallDescriptor {
    if (opcode < native_opcode_base) return null;
    const offset = opcode - native_opcode_base;
    if (offset >= native_opcode_count) return null;
    const table_index = opcode_index[offset];
    if (table_index == missing_opcode_index) return null;
    return &syscall_table[table_index];
}

fn syscallDescriptorFor(operation: abi.NativeOperation) ?*const SyscallDescriptor {
    return syscallDescriptorFromOpcode(abi.opcode(operation));
}

fn buildOpcodeIndex() [native_opcode_count]usize {
    var index = [_]usize{missing_opcode_index} ** native_opcode_count;
    for (syscall_table, 0..) |descriptor, table_index| {
        const offset = abi.opcode(descriptor.operation) - native_opcode_base;
        index[offset] = table_index;
    }
    return index;
}

test "syscall descriptor table covers every native operation with ABI metadata" {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, syscall_table.len);

    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const descriptor = syscallDescriptorFor(operation) orelse return error.MissingSyscallDescriptor;
        try std.testing.expectEqual(operation, descriptor.operation);
        try std.testing.expect(descriptor.request_size >= @sizeOf(abi.RequestHeader));
    }

    try std.testing.expectEqual(@sizeOf(component_port.TaskCreateRequest), syscallDescriptorFor(.task_create).?.request_size);
    try std.testing.expectEqual(@sizeOf(abi.TaskDescriptor), syscallDescriptorFor(.task_create).?.response_size);
    try std.testing.expectEqual(syscall_abi.RequestCopyRule.embedded_user_buffers, syscallDescriptorFor(.task_create).?.request_copy);
    try std.testing.expectEqual(@as(usize, 0), syscallDescriptorFor(.endpoint_send).?.response_size);
    try std.testing.expectEqual(syscall_abi.RequestCopyRule.embedded_user_buffers, syscallDescriptorFor(.endpoint_send).?.request_copy);
    try std.testing.expectEqual(capability.CapabilityRight.endpoint_send, syscallDescriptorFor(.endpoint_send).?.required_right);
    try std.testing.expect(syscallDescriptorFor(.endpoint_create).?.scope_rule.task_scope_matches_request_task);
    try std.testing.expectEqual(@as(usize, 1), syscallDescriptorFor(.shared_memory_create).?.auto_grant_count);
    try std.testing.expectEqual(@sizeOf(component_port.InputRecvRequest), syscallDescriptorFor(.input_recv).?.request_size);
    try std.testing.expectEqual(@sizeOf(abi.InputRecvResponse), syscallDescriptorFor(.input_recv).?.response_size);
    try std.testing.expectEqual(capability.CapabilityRight.input_recv, syscallDescriptorFor(.input_recv).?.required_right);
    try std.testing.expectEqual(@sizeOf(component_port.SurfacePresentRequest), syscallDescriptorFor(.surface_present).?.request_size);
    try std.testing.expectEqual(@sizeOf(abi.BoolResponse), syscallDescriptorFor(.surface_present).?.response_size);
    try std.testing.expectEqual(capability.CapabilityRight.surface_present, syscallDescriptorFor(.surface_present).?.required_right);
    try std.testing.expect(switch (syscallDescriptorFor(.device_describe).?.target_kind) {
        .fixed => |kind| kind == .device,
        else => false,
    });
}

const TestKernel = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoints: endpoint.Table = endpoint.Table.init(),
    shared: shared_memory.Table = shared_memory.Table.init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    session_task_id: u64 = 0,
    authority_capability_id: u64 = 0,

    fn init(self: *TestKernel) !void {
        self.kernel = native_kernel.Kernel.init(
            .{ .kind = .policy_authority, .serial = 1 },
            &self.runtime,
            &self.capabilities,
            &self.endpoints,
            &self.shared,
        );
        self.port = component_port.KernelPort.init(&self.kernel);

        const session_task = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 2 },
            .component_class = .session_manager,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = shared_memory.PAGE_SIZE,
                .endpoint_slots = 8,
                .shared_memory_bytes = shared_memory.PAGE_SIZE,
            },
            .local_only = true,
        });
        const authority = try self.capabilities.mintBootRoot(.{
            .holder = session_task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = 42 },
            .rights = .{ .service = .{
                .task_create = true,
                .task_terminate = true,
                .endpoint_create = true,
                .endpoint_connect = true,
                .endpoint_send = true,
                .endpoint_recv = true,
                .shared_memory_create = true,
                .shared_memory_map = true,
                .shared_memory_unmap = true,
                .shared_memory_revoke = true,
                .resource_query = true,
                .accounting_query = true,
                .time_query = true,
                .ipc_peer = true,
                .capability_query = true,
            } },
            .scope = .{ .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        });
        self.session_task_id = session_task.id;
        self.authority_capability_id = authority.id;
        try self.runtime.grantCapability(self.session_task_id, self.authority_capability_id);
    }
};

const TestInputReceiver = struct {
    pending: ?abi.InputEventDescriptor = null,
    polls: usize = 0,

    fn poll(context: *anyopaque, task_id: u64) ?abi.InputEventDescriptor {
        const self: *TestInputReceiver = @ptrCast(@alignCast(context));
        _ = task_id;
        self.polls += 1;
        const event = self.pending;
        self.pending = null;
        return event;
    }
};

const TestSurfaceReceiver = struct {
    calls: usize = 0,
    last_task_id: u64 = 0,
    last_presentation: abi.SurfacePresentation = std.mem.zeroes(abi.SurfacePresentation),
    status: native_kernel.SurfacePresentStatus = .accepted,

    fn present(
        context: *anyopaque,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
    ) native_kernel.SurfacePresentStatus {
        const self: *TestSurfaceReceiver = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.last_task_id = task.id;
        self.last_presentation = presentation.*;
        return self.status;
    }
};

test "syscall surface dispatches typed task creation requests" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const syscall_test_image = try generated_image_fixtures.appImage();
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 77, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 9 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
                .resource_class = .batch_compute,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 21,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.syscall",
                .source_identity = "store://release/app.example.syscall/1",
            },
            .userspace_image = &syscall_test_image,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        5,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.TaskDescriptor)), result.bytes_written);
    try std.testing.expectEqual(abi.DenialReason.none, result.denial_reason);

    try std.testing.expectEqual(debug_contract.ProvenanceKind.none, result.provenance.kind);
    try std.testing.expect(response.task_id != 0);
    try std.testing.expectEqual(@as(u16, @intFromEnum(task_runtime.ComponentClass.app_component)), response.component_class);
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(response.flags));
    const created_task = test_kernel.runtime.find(response.task_id).?;
    try std.testing.expectEqualStrings("app.example.syscall", created_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("store://release/app.example.syscall/1", created_task.launchSourceIdentitySlice());
    try std.testing.expect(!test_kernel.port.syscall_header_prevalidated);
}

test "syscall surface explains preflight request failures" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        5,
        0,
        0,
        0,
    );

    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, result.status);
    try std.testing.expectEqual(abi.DenialReason.invalid_target, result.denial_reason);
    try std.testing.expectEqual(abi.DenialReason.invalid_target, result.explanation.reason);
    try std.testing.expectEqual(debug_contract.ProvenanceKind.syscall, result.provenance.kind);
    try std.testing.expectEqual(debug_contract.Decision.denied, result.provenance.decision);
    try std.testing.expect(result.provenance.trace_id != 0);
}

test "syscall surface validates compact endpoint receive outputs before dequeue" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const empty_queue_image = try generated_image_fixtures.appImage();
    const app_task = try test_kernel.port.taskCreate(.{
        .header = component_port.makeHeader(.task_create, 88, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 10 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 22,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.empty-queue",
            },
            .userspace_image = &empty_queue_image,
        },
    }, 6);
    const created = try test_kernel.port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 89, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .owner_task_id = app_task.task_id,
        .label = "empty-queue",
        .flags = .{ .local_only = true },
    }, 7);

    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    var payload: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    var attached_capability = std.mem.zeroes(abi.CapabilityDescriptor);
    var request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, 90, app_task.task_id),
        .endpoint_capability_id = created.capability_id,
        .receiver_task_id = app_task.task_id,
        .payload_out = &payload,
        .attached_capability_out = &attached_capability,
    };
    test_kernel.runtime.allowHostPointerSyscallsForTask(app_task.task_id);

    const result = dispatch(
        &test_kernel.port,
        app_task.task_id,
        8,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );

    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    try std.testing.expectEqual(@as(u32, @sizeOf(abi.EndpointRecvResponse)), result.bytes_written);
    try std.testing.expectEqual(@as(u8, 0), response.present);
    try std.testing.expectEqual(@as(u8, 0), response.has_attached_capability);

    const peer = try test_kernel.endpoints.create(ids.task(test_kernel.session_task_id), "receive-peer", .{ .local_only = true });
    try test_kernel.endpoints.connect(peer.id, ids.endpoint(created.endpoint.endpoint_id));
    try test_kernel.endpoints.send(peer.id, ids.task(test_kernel.session_task_id), 91, "hello", null, false);

    const short_response = dispatch(
        &test_kernel.port,
        app_task.task_id,
        9,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse) - 1,
    );
    try std.testing.expectEqual(abi.SyscallStatus.buffer_too_small, short_response.status);
    try std.testing.expectEqual(@as(u16, 1), (try test_kernel.endpoints.descriptor(ids.endpoint(created.endpoint.endpoint_id))).queued_messages);

    var short_payload: [4]u8 = undefined;
    request.payload_out = &short_payload;
    const short_payload_result = dispatch(
        &test_kernel.port,
        app_task.task_id,
        10,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.buffer_too_small, short_payload_result.status);
    try std.testing.expectEqual(@as(u16, 1), (try test_kernel.endpoints.descriptor(ids.endpoint(created.endpoint.endpoint_id))).queued_messages);

    request.payload_out = &payload;
    response = std.mem.zeroes(abi.EndpointRecvResponse);
    const received = dispatch(
        &test_kernel.port,
        app_task.task_id,
        11,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.EndpointRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, received.status);
    try std.testing.expectEqual(@as(u8, 1), response.present);
    try std.testing.expectEqual(@as(u16, 5), response.message.payload_len);
    try std.testing.expectEqualStrings("hello", payload[0..response.message.payload_len]);
    try std.testing.expectEqual(@as(u16, 0), (try test_kernel.endpoints.descriptor(ids.endpoint(created.endpoint.endpoint_id))).queued_messages);
}

test "syscall surface delivers focused input only through task-scoped authority" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const app_task = try test_kernel.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 11 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    const input_capability = try test_kernel.capabilities.mintBootRoot(.{
        .holder = app_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = app_task.id },
        .rights = .{ .task = .{ .input_recv = true } },
        .scope = .{ .task_id = app_task.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    try test_kernel.runtime.grantCapability(app_task.id, input_capability.id);
    test_kernel.runtime.allowHostPointerSyscallsForTask(app_task.id);

    var receiver = TestInputReceiver{ .pending = .{
        .sequence = 9,
        .tick = 40,
        .window_id = 7,
        .task_id = app_task.id,
        .surface_id = 12,
        .kind = @intFromEnum(abi.InputEventKind.text),
        .text = 'x',
        .port_id = 1,
        .slot_id = 2,
    } };
    test_kernel.kernel.bindFocusedInputReceiver(.{
        .context = &receiver,
        .poll = TestInputReceiver.poll,
    });

    const request = component_port.InputRecvRequest{
        .header = component_port.makeHeader(.input_recv, 93, app_task.id),
        .input_capability_id = input_capability.id,
        .receiver_task_id = app_task.id,
    };
    var response = std.mem.zeroes(abi.InputRecvResponse);
    const delivered = dispatch(
        &test_kernel.port,
        app_task.id,
        40,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.InputRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, delivered.status);
    try std.testing.expectEqual(@as(u8, 1), response.present);
    try std.testing.expectEqual(@as(u64, 9), response.event.sequence);
    try std.testing.expectEqual(app_task.id, response.event.task_id);
    try std.testing.expectEqual(@as(u8, 'x'), response.event.text);

    response = std.mem.zeroes(abi.InputRecvResponse);
    const empty = dispatch(
        &test_kernel.port,
        app_task.id,
        41,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.InputRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, empty.status);
    try std.testing.expectEqual(@as(u8, 0), response.present);
    try std.testing.expectEqual(@as(usize, 2), receiver.polls);

    const wrong_capability_request = component_port.InputRecvRequest{
        .header = component_port.makeHeader(.input_recv, 94, app_task.id),
        .input_capability_id = test_kernel.authority_capability_id,
        .receiver_task_id = app_task.id,
    };
    const denied = dispatch(
        &test_kernel.port,
        app_task.id,
        42,
        @intFromPtr(&wrong_capability_request),
        @intFromPtr(&response),
        @sizeOf(abi.InputRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.not_found, denied.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, denied.denial_reason);
    try std.testing.expectEqual(@as(usize, 2), receiver.polls);

    receiver.pending = .{
        .sequence = 10,
        .tick = 43,
        .window_id = 8,
        .task_id = app_task.id + 1,
        .surface_id = 13,
        .kind = @intFromEnum(abi.InputEventKind.activate),
        .text = 0,
        .port_id = 1,
        .slot_id = 2,
    };
    response = std.mem.zeroes(abi.InputRecvResponse);
    const foreign = dispatch(
        &test_kernel.port,
        app_task.id,
        43,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.InputRecvResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.denied, foreign.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, foreign.denial_reason);
    try std.testing.expectEqual(@as(u8, 0), response.present);
    try std.testing.expectEqual(@as(usize, 3), receiver.polls);
}

test "syscall surface copies bounded presentations through task-scoped authority" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const app_task = try test_kernel.runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .ui_surface_id = 12,
        .local_only = true,
    });
    const presentation_capability = try test_kernel.capabilities.mintBootRoot(.{
        .holder = app_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = app_task.id },
        .rights = .{ .task = .{ .surface_present = true } },
        .scope = .{ .task_id = app_task.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    try test_kernel.runtime.grantCapability(app_task.id, presentation_capability.id);
    test_kernel.runtime.allowHostPointerSyscallsForTask(app_task.id);

    var receiver = TestSurfaceReceiver{};
    test_kernel.kernel.bindSurfacePresentationReceiver(.{
        .context = &receiver,
        .present = TestSurfaceReceiver.present,
    });

    var presentation = std.mem.zeroes(abi.SurfacePresentation);
    presentation.surface_id = 12;
    presentation.revision = 3;
    presentation.interaction_hash = 0x1234;
    presentation.model_kind = @intFromEnum(abi.SurfaceModelKind.notes);
    @memcpy(presentation.text[0..5], "hello");
    presentation.text_length = 5;
    presentation.cursor = 5;
    const request = component_port.SurfacePresentRequest{
        .header = component_port.makeHeader(.surface_present, 95, app_task.id),
        .presentation_capability_id = presentation_capability.id,
        .presenter_task_id = app_task.id,
        .presentation = presentation,
    };
    var response = std.mem.zeroes(abi.BoolResponse);
    const presented = dispatch(
        &test_kernel.port,
        app_task.id,
        50,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, presented.status);
    try std.testing.expectEqual(@as(u8, 1), response.value);
    try std.testing.expectEqual(@as(usize, 1), receiver.calls);
    try std.testing.expectEqual(app_task.id, receiver.last_task_id);
    try std.testing.expectEqualStrings("hello", receiver.last_presentation.textSlice());

    receiver.status = .duplicate;
    response = std.mem.zeroes(abi.BoolResponse);
    const duplicate = dispatch(
        &test_kernel.port,
        app_task.id,
        51,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, duplicate.status);
    try std.testing.expectEqual(@as(u8, 1), response.value);

    receiver.status = .stale;
    const stale = dispatch(
        &test_kernel.port,
        app_task.id,
        52,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.conflict, stale.status);
    try std.testing.expectEqual(abi.DenialReason.invalid_target, stale.denial_reason);

    receiver.status = .full;
    const full = dispatch(
        &test_kernel.port,
        app_task.id,
        53,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.conflict, full.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, full.denial_reason);

    receiver.status = .accepted;

    var foreign_surface = request;
    foreign_surface.presentation.surface_id = 13;
    response = std.mem.zeroes(abi.BoolResponse);
    const denied = dispatch(
        &test_kernel.port,
        app_task.id,
        54,
        @intFromPtr(&foreign_surface),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.denied, denied.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, denied.denial_reason);
    try std.testing.expectEqual(@as(usize, 4), receiver.calls);

    var malformed = request;
    malformed.presentation.text[malformed.presentation.text.len - 1] = 1;
    const rejected = dispatch(
        &test_kernel.port,
        app_task.id,
        55,
        @intFromPtr(&malformed),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.not_found, rejected.status);
    try std.testing.expectEqual(abi.DenialReason.invalid_target, rejected.denial_reason);
    try std.testing.expectEqual(@as(usize, 4), receiver.calls);

    test_kernel.kernel.clearSurfacePresentationReceiver();
    const unavailable = dispatch(
        &test_kernel.port,
        app_task.id,
        56,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.BoolResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.unavailable, unavailable.status);
    try std.testing.expectEqual(abi.DenialReason.unsupported_operation, unavailable.denial_reason);
    try std.testing.expectEqual(@as(usize, 4), receiver.calls);
}

test "syscall surface denies task creation without signed userspace launch provenance" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 91, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 12 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        9,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, result.denial_reason);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, result.explanation.reason);
    try std.testing.expectEqualStrings("task_create", result.explanation.operationSlice());
    try std.testing.expect(result.explanation.fingerprint != 0);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);

    const unsigned_image = try generated_image_fixtures.appImage();
    var unsigned_response = std.mem.zeroes(abi.TaskDescriptor);
    const unsigned_request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 92, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 13 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 24,
                .component_abi_version = 1,
                .signed = false,
                .bundle_id = "app.example.unsigned-syscall",
            },
            .userspace_image = &unsigned_image,
        },
    };
    const unsigned_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&unsigned_request),
        @intFromPtr(&unsigned_response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.denied, unsigned_result.status);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, unsigned_result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), unsigned_result.bytes_written);
}

test "syscall surface rejects unsupported native operations" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const request = abi.RequestHeader{
        .operation = 0xFFFF,
        .correlation_id = 91,
        .subject_task_id = test_kernel.session_task_id,
    };
    const result = dispatch(&test_kernel.port, test_kernel.session_task_id, 9, @intFromPtr(&request), 0, 0);

    try std.testing.expectEqual(abi.SyscallStatus.unsupported_operation, result.status);
    try std.testing.expectEqual(abi.DenialReason.unsupported_operation, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
}

test "syscall surface rejects unsupported ABI versions before trusted port entry" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    var request = component_port.TimeQueryRequest{
        .header = component_port.makeHeader(.time_query, 911, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
    };
    request.header.version = abi.ABI_VERSION + 1;
    var response = std.mem.zeroes(abi.TimeQueryResponse);
    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        9,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TimeQueryResponse),
    );

    try std.testing.expectEqual(abi.SyscallStatus.unsupported_abi_version, result.status);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
    try std.testing.expect(!test_kernel.port.syscall_header_prevalidated);
}

test "syscall surface rejects invalid request and response pointer ranges" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const low_request = dispatch(&test_kernel.port, test_kernel.session_task_id, 9, 0x1000, 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, low_request.status);

    const request = component_port.TimeQueryRequest{
        .header = component_port.makeHeader(.time_query, 92, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
    };
    const bad_response = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        9,
        @intFromPtr(&request),
        std.math.maxInt(usize) - 4,
        16,
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_response_buffer, bad_response.status);
}

test "syscall surface rejects spoofed subject task ids" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const spoofed_subject_image = try generated_image_fixtures.appImage();
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 92, test_kernel.session_task_id + 1),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 99 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 23,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.spoofed-subject",
            },
            .userspace_image = &spoofed_subject_image,
        },
    };

    const result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );

    try std.testing.expectEqual(abi.SyscallStatus.denied, result.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, result.denial_reason);
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);

    var zero_caller_response = std.mem.zeroes(abi.TaskDescriptor);
    const zero_caller_result = dispatch(
        &test_kernel.port,
        0,
        10,
        @intFromPtr(&request),
        @intFromPtr(&zero_caller_response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.denied, zero_caller_result.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, zero_caller_result.denial_reason);

    const zero_subject_request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 93, 0),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = request.request,
    };
    var zero_subject_response = std.mem.zeroes(abi.TaskDescriptor);
    const zero_subject_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&zero_subject_request),
        @intFromPtr(&zero_subject_response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.denied, zero_subject_result.status);
    try std.testing.expectEqual(abi.DenialReason.scope_violation, zero_subject_result.denial_reason);
}

test "syscall surface validates and bounds embedded user buffers" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const bad_image_ptr: *const task_runtime.ExecutableImageSpec = @ptrFromInt(0x1000);
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const bad_image_request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 93, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 100 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
            .userspace_image = bad_image_ptr,
        },
    };
    const bad_image = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&bad_image_request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, bad_image.status);

    const valid_image = try generated_image_fixtures.appImage();
    const invalid_source_ptr: [*]const u8 = @ptrFromInt(0x1000);
    const bad_source_request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 94, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 101 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = units.kibibytes(1),
                .endpoint_slots = 4,
                .shared_memory_bytes = units.kibibytes(1),
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 25,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.invalid-source",
                .source_identity = invalid_source_ptr[0..1],
            },
            .userspace_image = &valid_image,
        },
    };
    const bad_source = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&bad_source_request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, bad_source.status);

    const oversized_source = [_]u8{'x'} ** (task_runtime.MAX_TASK_SOURCE_IDENTITY_BYTES + 1);
    var oversized_source_request = bad_source_request;
    oversized_source_request.request.launch.source_identity = &oversized_source;
    const oversized_identity = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&oversized_source_request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, oversized_identity.status);

    const oversized_payload = [_]u8{0xAB} ** (endpoint.MAX_MESSAGE_BYTES + 1);
    const send_request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, 94, test_kernel.session_task_id),
        .endpoint_capability_id = test_kernel.authority_capability_id,
        .payload = oversized_payload[0..],
    };
    const oversized = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&send_request),
        0,
        0,
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, oversized.status);

    const invalid_payload_ptr: [*]const u8 = @ptrFromInt(0x1000);
    const invalid_payload_request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, 95, test_kernel.session_task_id),
        .endpoint_capability_id = test_kernel.authority_capability_id,
        .payload = invalid_payload_ptr[0..1],
    };
    const invalid_payload = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        10,
        @intFromPtr(&invalid_payload_request),
        0,
        0,
    );
    try std.testing.expectEqual(abi.SyscallStatus.invalid_request_pointer, invalid_payload.status);
}

test "address-space range validation requires full mapped coverage and permissions" {
    var address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    address_space.region_count = 3;
    address_space.regions[0] = .{
        .kind = .load_segment,
        .virtual_address = 0x20000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true },
    };
    address_space.regions[1] = .{
        .kind = .load_segment,
        .virtual_address = 0x21000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };
    address_space.regions[2] = .{
        .kind = .stack,
        .virtual_address = 0x30000,
        .size_bytes = 0x2000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };

    try std.testing.expect(validateAddressSpaceRange(&address_space, 0x20020, 0x20080, .read));
    try std.testing.expect(validateAddressSpaceRange(&address_space, 0x20FF0, 0x21020, .read));
    try std.testing.expect(!validateAddressSpaceRange(&address_space, 0x20FF0, 0x21020, .write));
    try std.testing.expect(validateAddressSpaceRange(&address_space, 0x30010, 0x30100, .write));
    try std.testing.expect(!validateAddressSpaceRange(&address_space, 0x22000, 0x22020, .read));
    try std.testing.expect(!validateAddressSpaceRange(&address_space, 0x20FF0, 0x22010, .read));

    var unordered_address_space = address_space;
    unordered_address_space.regions[0] = address_space.regions[1];
    unordered_address_space.regions[1] = address_space.regions[0];
    try std.testing.expect(!validateAddressSpaceRange(&unordered_address_space, 0x20020, 0x20080, .read));
}

test "syscall surface dispatches typed PCI device broker requests" {
    const device_broker = @import("device_broker.zig");

    var test_kernel = TestKernel{};
    try test_kernel.init();
    device_broker.reset();
    defer device_broker.reset();

    const device_capability = try test_kernel.capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 2 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device = .{ .device_use = true } },
        .scope = .{
            .task_id = test_kernel.session_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 12,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    try test_kernel.runtime.grantCapability(test_kernel.session_task_id, device_capability.id);
    try std.testing.expect(device_broker.publishPciController(0x1F001));

    const describe_request = component_port.DeviceDescribeRequest{
        .header = component_port.makeHeader(.device_describe, 101, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
    };
    var describe_response = std.mem.zeroes(abi.DeviceDescriptor);
    const describe_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&describe_request),
        @intFromPtr(&describe_response),
        @sizeOf(abi.DeviceDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, describe_result.status);
    try std.testing.expectEqual(@as(u64, 0x1F001), describe_response.device_id);
}
