const builtin = @import("builtin");
pub const std = @import("std");
const abi = @import("native_abi");
const mailbox = @import("userspace_bootstrap_mailbox");
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

export var zigos_userspace_bootstrap: mailbox.Mailbox align(@alignOf(mailbox.Mailbox)) linksection(mailbox.SECTION_NAME) = .{};

const freestanding_trap = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn syscall3_asm(request_addr: usize, response_addr: usize, response_len: usize) callconv(.c) usize;

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

pub fn zigos_userspace_contract_main() callconv(.c) noreturn {
    const descriptor = &contract_bindings.zigos_userspace_descriptor;
    userspace_descriptor.validate(descriptor) catch signalFault(.unknown, 1);

    const detail = mailbox.classifyDetail(descriptor.component_class, descriptor.contract_flags);
    publishState(.descriptor_ready, detail, 1);

    if (zigos_userspace_bootstrap.authority_capability_id != 0 and zigos_userspace_bootstrap.task_id != 0) {
        publishState(.mailbox_ready, detail, 2);
        runStartupQueries(detail);
    }

    if (descriptor.role_tag == mailbox.MMU_ISOLATION_PROOF_ROLE_TAG) {
        runMmuIsolationProbe(detail);
    }

    runSteadyState(detail, descriptor.heartbeat_increment);
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
    runSteadyState(detail, descriptor.heartbeat_increment);
}

pub fn startAsm(comptime _: u32) []const u8 {
    const assembly =
        \\mov $0x23, %ax
        \\mov %ax, %ds
        \\mov %ax, %es
        \\mov %ax, %fs
        \\mov %ax, %gs
        \\call zigos_userspace_contract_main
        \\ud2
    ;
    return assembly;
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

pub const ServiceModel = struct {
    kind: ServiceKind,
    operation_count: u16,
    state_hash: u64,
};

pub fn serviceModel(comptime service_kind: ServiceKind) ServiceModel {
    return switch (service_kind) {
        .generic => .{
            .kind = .generic,
            .operation_count = 0,
            .state_hash = hashServiceState("generic:heartbeat-only"),
        },
        .storage => .{
            .kind = .storage,
            .operation_count = 4,
            .state_hash = hashServiceState("storage:workspace-open:object-put:snapshot:file-bridge"),
        },
        .sync => .{
            .kind = .sync,
            .operation_count = 4,
            .state_hash = hashServiceState("sync:device-graph:vector-clock:delta-queue:conflict-record"),
        },
        .network => .{
            .kind = .network,
            .operation_count = 3,
            .state_hash = hashServiceState("network:route-table:egress-policy:device-queue"),
        },
        .package => .{
            .kind = .package,
            .operation_count = 4,
            .state_hash = hashServiceState("package:manifest-verify:bundle-stage:rollback-journal:update-channel"),
        },
        .compositor => .{
            .kind = .compositor,
            .operation_count = 4,
            .state_hash = hashServiceState("compositor:surface-create:input-route:frame-commit:session-focus"),
        },
    };
}

fn publishServiceReady(comptime service_kind: ServiceKind, detail: mailbox.Detail) void {
    const model = serviceModel(service_kind);
    zigos_userspace_bootstrap.service_kind = @intFromEnum(model.kind);
    zigos_userspace_bootstrap.service_ready = 1;
    zigos_userspace_bootstrap.service_operation_count = model.operation_count;
    zigos_userspace_bootstrap.service_state_hash = model.state_hash;
    publishState(.service_ready, detail, model.operation_count);
}

fn hashServiceState(comptime text: []const u8) u64 {
    return std.hash.Wyhash.hash(0x5A47_5345_5256_4943, text);
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

fn invalidSyscallPointerStatus() abi.SyscallStatus {
    var response = abi.TimeQueryResponse{ .now_ticks = 0 };
    return freestanding_trap.call(
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

fn runSteadyState(detail: mailbox.Detail, heartbeat_increment: u32) noreturn {
    const increment: u16 = @truncate(if (heartbeat_increment == 0) 1 else heartbeat_increment);
    var pulse: u16 = 4;
    while (true) {
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
    return asm volatile ("int $129"
        : [result] "={eax}" (-> u32),
        : [value] "{eax}" (value),
    );
}

fn trapCall(request: anytype, response: anytype) abi.SyscallStatus {
    return freestanding_trap.call(
        @intFromPtr(request),
        @intFromPtr(response),
        @sizeOf(@TypeOf(response.*)),
    );
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

test "userspace service models expose domain-specific behavior before heartbeat" {
    const storage = serviceModel(.storage);
    const network = serviceModel(.network);
    const package = serviceModel(.package);
    const compositor = serviceModel(.compositor);
    const sync = serviceModel(.sync);

    try std.testing.expectEqual(ServiceKind.storage, storage.kind);
    try std.testing.expect(storage.operation_count >= 4);
    try std.testing.expect(network.operation_count >= 3);
    try std.testing.expect(package.operation_count >= 4);
    try std.testing.expect(compositor.operation_count >= 4);
    try std.testing.expect(sync.operation_count >= 4);
    try std.testing.expect(storage.state_hash != network.state_hash);
    try std.testing.expect(package.state_hash != compositor.state_hash);
}
