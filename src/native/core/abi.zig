const std = @import("std");

pub const ABI_VERSION: u16 = 1;
pub const ENDPOINT_INLINE_BYTES: usize = 96;

pub const NativeOperation = enum(u16) {
    task_create = 0x100,
    task_terminate,
    endpoint_create,
    endpoint_connect,
    endpoint_send,
    endpoint_recv,
    capability_mint,
    capability_derive,
    capability_pass,
    capability_revoke,
    capability_query,
    shared_memory_create,
    shared_memory_map,
    shared_memory_unmap,
    shared_memory_revoke,
    time_query,
    resource_query,
    accounting_query,
    device_describe,
    device_mmio_window,
    device_port_read,
    device_port_write,
};

pub const PolicyOperation = enum(u16) {
    authorize_request = 0x200,
    apply_manifest,
};

pub const ReviewOperation = enum(u16) {
    review_bundle = 0x240,
};

pub const SyscallStatus = enum(u32) {
    success = 0,
    unavailable,
    invalid_request_pointer,
    invalid_response_buffer,
    buffer_too_small,
    unsupported_operation,
    unsupported_abi_version,
    denied,
    not_found,
    conflict,
    internal_error,
};

pub const DenialReason = enum(u16) {
    none = 0,
    invalid_target,
    capability_missing,
    capability_revoked,
    capability_expired,
    scope_violation,
    policy_denied,
    budget_exhausted,
    interface_not_found,
    unsupported_operation,
};

pub const TASK_FLAG_LOCAL_ONLY: u16 = 1 << 0;
pub const TASK_FLAG_ZERO_AMBIENT_AUTHORITY: u16 = 1 << 1;
pub const TASK_FLAG_BACKGROUND_ALLOWED: u16 = 1 << 2;
pub const TASK_FLAG_USERSPACE_PROCESS: u16 = 1 << 3;
pub const TASK_FLAG_EXECUTABLE_IMAGE_MAPPED: u16 = 1 << 4;
pub const TASK_RESOURCE_CLASS_SHIFT = 8;
pub const TASK_RESOURCE_CLASS_MASK: u16 = 0b111 << TASK_RESOURCE_CLASS_SHIFT;
pub const SERVICE_CONNECTION_FLAG_USERSPACE_OWNER: u16 = 1 << 0;
pub const SERVICE_CONNECTION_FLAG_SIGNED_IMAGE: u16 = 1 << 1;

pub const ScopeFlags = packed struct(u32) {
    local_only: bool = false,
    broker_only: bool = false,
    task_scoped: bool = false,
    workspace_scoped: bool = false,
    ephemeral: bool = false,
    _reserved: u27 = 0,
};

pub const RequestHeader = extern struct {
    version: u16 = ABI_VERSION,
    operation: u16,
    flags: u32 = 0,
    correlation_id: u64,
    subject_task_id: u64,
};

pub const CapabilityDescriptor = extern struct {
    capability_id: u64,
    target_id: u64,
    rights: u32,
    revocation_generation: u32,
    expires_at_ticks: u64,
    scope_task_id: u64,
    scope_workspace_id: u64,
    scope_flags: u32,
};

pub const TaskDescriptor = extern struct {
    task_id: u64,
    owner_serial: u64,
    owner_kind: u16,
    component_class: u16,
    state: u16,
    flags: u16,
    ui_surface_id: u64,
};

pub const EndpointDescriptor = extern struct {
    endpoint_id: u64,
    owner_task_id: u64,
    peer_endpoint_id: u64,
    queued_messages: u16,
    flags: u16,
    label_hash: u64,
};

pub const EndpointMessageDescriptor = extern struct {
    endpoint_id: u64,
    sender_task_id: u64,
    correlation_id: u64,
    attached_capability_id: u64,
    payload_len: u16,
    flags: u16,
};

pub const SharedMemoryDescriptor = extern struct {
    object_id: u64,
    owner_task_id: u64,
    size_bytes: u64,
    revocation_generation: u32,
    mapped_task_count: u16,
    flags: u16,
};

pub const ResourceDescriptor = extern struct {
    task_id: u64,
    state: u16,
    capability_count: u16,
    endpoint_count: u16,
    flags: u16,
    cpu_time_ticks: u64,
    memory_bytes: u64,
    shared_memory_bytes: u64,
};

pub const AccountingDescriptor = extern struct {
    task_id: u64,
    audit_event_count: u16,
    capability_count: u16,
    component_count: u16,
    endpoint_count: u16,
    shared_memory_mappings: u16,
    _reserved: u16 = 0,
    ui_surface_id: u64,
};

pub const ServiceConnectionDescriptor = extern struct {
    service_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
    interface_id: u16,
    version_major: u16,
    version_minor: u16,
    flags: u16,
};

pub const DEVICE_DESCRIPTOR_FLAG_ATA_MASTER: u16 = 1 << 0;
pub const MMIO_WINDOW_FLAG_WRITABLE: u16 = 1 << 0;
pub const MMIO_WINDOW_FLAG_EXECUTABLE: u16 = 1 << 1;

pub const DevicePortWidth = enum(u8) {
    u8 = 1,
    u16 = 2,
    u32 = 4,
};

pub const DeviceDescriptor = extern struct {
    device_id: u64,
    base_port: u16,
    io_port_count: u16,
    ctrl_port: u16,
    irq_line: u8,
    mmio_window_count: u8,
    flags: u16,
    sector_count: u64,
};

pub const DeviceMmioWindowDescriptor = extern struct {
    base: u64,
    length: u64,
    flags: u16,
    _reserved: [6]u8,
};

pub const DevicePortReadResponse = extern struct {
    value: u32,
};

pub const BoolResponse = extern struct {
    value: u8,
    _reserved: [7]u8,
};

pub const TimeQueryResponse = extern struct {
    now_ticks: u64,
};

pub const EndpointCreateResponse = extern struct {
    endpoint: EndpointDescriptor,
    capability: CapabilityDescriptor,
    capability_id: u64,
};

pub const EndpointRecvResponse = extern struct {
    present: u8,
    has_attached_capability: u8,
    _reserved: [6]u8,
    message: EndpointMessageDescriptor,
    payload: [ENDPOINT_INLINE_BYTES]u8,
    attached_capability: CapabilityDescriptor,
};

pub const SharedMemoryCreateResponse = extern struct {
    object: SharedMemoryDescriptor,
    capability: CapabilityDescriptor,
    capability_id: u64,
};

pub fn opcode(operation: NativeOperation) u16 {
    return @intFromEnum(operation);
}

pub fn policyOpcode(operation: PolicyOperation) u16 {
    return @intFromEnum(operation);
}

pub fn reviewOpcode(operation: ReviewOperation) u16 {
    return @intFromEnum(operation);
}

pub fn taskFlagsHas(flags: u16, mask: u16) bool {
    return (flags & mask) != 0;
}

pub fn taskFlagsResourceClass(flags: u16) u8 {
    return @intCast((flags & TASK_RESOURCE_CLASS_MASK) >> TASK_RESOURCE_CLASS_SHIFT);
}

pub fn serviceFlagsHas(flags: u16, mask: u16) bool {
    return (flags & mask) != 0;
}

test "native abi operation ids stay in a dedicated namespace" {
    try std.testing.expect(opcode(.task_create) >= 0x100);
    try std.testing.expect(policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 1), ABI_VERSION);
    try std.testing.expectEqual(@as(usize, 96), ENDPOINT_INLINE_BYTES);
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(CapabilityDescriptor));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(TaskDescriptor));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ResourceDescriptor));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(DeviceDescriptor));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(DeviceMmioWindowDescriptor));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(DevicePortReadResponse));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(BoolResponse));
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(EndpointCreateResponse));
    try std.testing.expectEqual(@as(usize, 200), @sizeOf(EndpointRecvResponse));
    try std.testing.expectEqual(@as(usize, 96), @sizeOf(SharedMemoryCreateResponse));
    try std.testing.expect(taskFlagsHas(TASK_FLAG_LOCAL_ONLY, TASK_FLAG_LOCAL_ONLY));
    try std.testing.expectEqual(@as(u8, 3), taskFlagsResourceClass(@as(u16, 3) << TASK_RESOURCE_CLASS_SHIFT));
    try std.testing.expect(serviceFlagsHas(SERVICE_CONNECTION_FLAG_USERSPACE_OWNER, SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(DevicePortWidth.u32));
}
