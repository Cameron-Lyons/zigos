const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const endpoint = @import("endpoint.zig");
const native_kernel = @import("native_kernel.zig");
const shared_memory = @import("shared_memory.zig");
const syscall_abi = @import("syscall_abi.zig");
const syscall_dispatch = @import("syscall_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");

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

pub fn dispatch(
    port: *component_port.KernelPort,
    caller_task_id: u64,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) DispatchResult {
    if (caller_task_id == 0) return .{
        .status = .denied,
        .denial_reason = .scope_violation,
    };
    const memory = syscall_dispatch.UserMemoryContext.init(port, caller_task_id);
    const header = syscall_dispatch.readRequest(abi.RequestHeader, memory, request_addr) orelse return .{
        .status = .invalid_request_pointer,
    };
    if (header.version != abi.ABI_VERSION) return .{
        .status = .unsupported_abi_version,
    };
    if (header.subject_task_id == 0 or header.subject_task_id != caller_task_id) return .{
        .status = .denied,
        .denial_reason = .scope_violation,
    };

    const descriptor = syscallDescriptorFromOpcode(header.operation) orelse return .{
        .status = .unsupported_operation,
        .denial_reason = .unsupported_operation,
    };

    return descriptor.handler(port, memory, now_ticks, request_addr, response_addr, response_len);
}

fn syscallDescriptorFromOpcode(opcode: u16) ?*const SyscallDescriptor {
    for (&syscall_table) |*descriptor| {
        if (abi.opcode(descriptor.operation) == opcode) {
            return descriptor;
        }
    }
    return null;
}

fn syscallDescriptorFor(operation: abi.NativeOperation) ?*const SyscallDescriptor {
    return syscallDescriptorFromOpcode(abi.opcode(operation));
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
    try std.testing.expectEqual(@sizeOf(abi.DevicePortReadResponse), syscallDescriptorFor(.device_port_read).?.response_size);
    try std.testing.expectEqual(@as(usize, 0), syscallDescriptorFor(.device_port_write).?.response_size);
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
                .memory_bytes = 4096,
                .endpoint_slots = 8,
                .shared_memory_bytes = 4096,
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

test "syscall surface dispatches typed task creation requests" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const syscall_test_image = task_runtime.syntheticUserspaceImage("syscall-test", "app.example.syscall");
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 77, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 9 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
                .resource_class = .batch_compute,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 21,
                .component_abi_version = 1,
                .signed = true,
                .bundle_id = "app.example.syscall",
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
    try std.testing.expect(response.task_id != 0);
    try std.testing.expectEqual(@as(u16, @intFromEnum(task_runtime.ComponentClass.app_component)), response.component_class);
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(response.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    try std.testing.expectEqual(@as(u8, @intFromEnum(accelerator_scheduler.ResourceClass.batch_compute)), abi.taskFlagsResourceClass(response.flags));
}

test "syscall surface returns an explicit empty receive response when no message is queued" {
    var test_kernel = TestKernel{};
    try test_kernel.init();

    const empty_queue_image = task_runtime.syntheticUserspaceImage("empty-queue", "app.example.empty-queue");
    const app_task = try test_kernel.port.taskCreate(.{
        .header = component_port.makeHeader(.task_create, 88, test_kernel.session_task_id),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 10 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
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
    const request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, 90, app_task.task_id),
        .endpoint_capability_id = created.capability_id,
        .receiver_task_id = app_task.task_id,
    };
    const app_record = test_kernel.runtime.find(app_task.task_id).?;
    test_kernel.runtime.findAddressSpace(app_record.address_space_id).?.region_count = 0;

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
}

test "syscall surface denies task creation without userspace launch provenance" {
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
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
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
    try std.testing.expectEqual(@as(u32, 0), result.bytes_written);
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

    const spoofed_subject_image = task_runtime.syntheticUserspaceImage(
        "spoofed-subject",
        "app.example.spoofed-subject",
    );
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 92, test_kernel.session_task_id + 1),
        .authority_capability_id = test_kernel.authority_capability_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 99 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
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

test "syscall surface copies and bounds embedded user buffers" {
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
                .memory_bytes = 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 1024,
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
}

test "syscall surface dispatches typed device broker requests" {
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
    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 2048,
    }));

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

    const write_request = component_port.DevicePortWriteRequest{
        .header = component_port.makeHeader(.device_port_write, 102, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
        .value = 0x5C,
    };
    try std.testing.expectEqual(abi.SyscallStatus.success, dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&write_request),
        0,
        0,
    ).status);

    const read_request = component_port.DevicePortReadRequest{
        .header = component_port.makeHeader(.device_port_read, 103, test_kernel.session_task_id),
        .device_capability_id = device_capability.id,
        .port = 0x1F0 + 7,
        .width = .u8,
    };
    var read_response = abi.DevicePortReadResponse{ .value = 0 };
    const read_result = dispatch(
        &test_kernel.port,
        test_kernel.session_task_id,
        12,
        @intFromPtr(&read_request),
        @intFromPtr(&read_response),
        @sizeOf(abi.DevicePortReadResponse),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, read_result.status);
    try std.testing.expectEqual(@as(u32, 0x5C), read_response.value);
}
