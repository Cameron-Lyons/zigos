const std = @import("std");

pub const ABI_VERSION: u16 = 8;
pub const ENDPOINT_INLINE_BYTES: usize = 96;
pub const INPUT_PACKET_BYTES: usize = 8;
pub const SURFACE_PRESENT_IS_HANDLE_PLUS_FENCE = true;
pub const WAIT_PLUS_SEALED_RINGS = true;

pub const InputByte = struct {
    pub const text: u8 = 1;
    pub const backspace: u8 = 2;
    pub const commit_text: u8 = 3;
    pub const focus_next: u8 = 4;
    pub const focus_previous: u8 = 5;
    pub const activate: u8 = 6;
    pub const task_switch_next: u8 = 7;
    pub const task_switch_previous: u8 = 8;
    pub const show_recovery: u8 = 9;
    pub const dismiss_recovery: u8 = 10;
};

pub fn inputPacket(op: u8, data: u8) [INPUT_PACKET_BYTES]u8 {
    var bytes = [_]u8{0} ** INPUT_PACKET_BYTES;
    bytes[0] = op;
    bytes[1] = data;
    return bytes;
}

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
    input_recv,
    surface_present,
    wait,
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
    operation: u16,
    flags: u16 = 0,
    subject_task_id: u64 = 0,
};

pub const CapabilityDescriptor = extern struct {
    capability_id: u64,
    target_id: u64,
    rights: u64,
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

pub const InputEventDescriptor = extern struct {
    sequence: u64,
    tick: u64,
    window_id: u64,
    task_id: u64,
    surface_id: u64,
    port_id: u8,
    slot_id: u8,
    length: u8,
    _reserved: [5]u8 = [_]u8{0} ** 5,
    bytes: [INPUT_PACKET_BYTES]u8 = [_]u8{0} ** INPUT_PACKET_BYTES,
};

pub const InputRecvResponse = extern struct {
    present: u8,
    _reserved: [7]u8 = [_]u8{0} ** 7,
    event: InputEventDescriptor,
};

pub const SurfacePresentation = extern struct {
    surface_id: u64,
    revision: u64,
    buffer_object_id: u64,
    buffer_offset: u32,
    buffer_bytes: u32,

    pub fn presentsByHandle(self: *const SurfacePresentation) bool {
        return self.buffer_object_id != 0 and self.buffer_bytes != 0;
    }
};

pub const ServiceConnectionDescriptor = extern struct {
    service_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

pub const MMIO_WINDOW_FLAG_WRITABLE: u16 = 1 << 0;
pub const MMIO_WINDOW_FLAG_EXECUTABLE: u16 = 1 << 1;
pub const DEVICE_DESCRIPTOR_RESERVED_BYTES: usize = 7;
pub const DEVICE_MMIO_WINDOW_RESERVED_BYTES: usize = 6;
pub const BOOL_RESPONSE_RESERVED_BYTES: usize = 7;

pub const DeviceDescriptor = extern struct {
    device_id: u64,
    mmio_window_count: u8,
    _reserved: [DEVICE_DESCRIPTOR_RESERVED_BYTES]u8,
};

pub const DeviceMmioWindowDescriptor = extern struct {
    base: u64,
    length: u64,
    flags: u16,
    _reserved: [DEVICE_MMIO_WINDOW_RESERVED_BYTES]u8,
};

pub const BoolResponse = extern struct {
    value: u8,
    _reserved: [BOOL_RESPONSE_RESERVED_BYTES]u8,
};

pub fn boolResponse(value: bool) BoolResponse {
    return .{
        .value = @intFromBool(value),
        ._reserved = [_]u8{0} ** BOOL_RESPONSE_RESERVED_BYTES,
    };
}

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
};

pub const EndpointRecvResult = struct {
    present: u8,
    has_attached_capability: u8,
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

pub fn isCanonicalSurfacePresentation(presentation: *const SurfacePresentation) bool {
    return presentation.surface_id != 0 and presentation.revision != 0 and presentation.presentsByHandle();
}

test "native abi operation ids stay in a dedicated namespace" {
    try std.testing.expect(opcode(.task_create) >= 0x100);
    try std.testing.expect(policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 8), ABI_VERSION);
    try std.testing.expect(SURFACE_PRESENT_IS_HANDLE_PLUS_FENCE);
    try std.testing.expect(WAIT_PLUS_SEALED_RINGS);
    try std.testing.expectEqual(@as(u16, opcode(.surface_present) + 1), opcode(.wait));
    try std.testing.expectEqual(@as(usize, 96), ENDPOINT_INLINE_BYTES);
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(CapabilityDescriptor));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(TaskDescriptor));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ResourceDescriptor));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(InputEventDescriptor));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(InputRecvResponse));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(SurfacePresentation));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(DeviceDescriptor));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(DeviceMmioWindowDescriptor));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(BoolResponse));
    try std.testing.expectEqual(@as(usize, 112), @sizeOf(EndpointCreateResponse));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(EndpointRecvResponse));
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(SharedMemoryCreateResponse));
    try std.testing.expect(taskFlagsHas(TASK_FLAG_LOCAL_ONLY, TASK_FLAG_LOCAL_ONLY));
    try std.testing.expectEqual(@as(u8, 3), taskFlagsResourceClass(@as(u16, 3) << TASK_RESOURCE_CLASS_SHIFT));
    try std.testing.expect(serviceFlagsHas(SERVICE_CONNECTION_FLAG_USERSPACE_OWNER, SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    const packet = inputPacket(InputByte.text, 'a');
    try std.testing.expectEqual(InputByte.text, packet[0]);
    try std.testing.expectEqual(@as(u8, 'a'), packet[1]);

    var presentation = std.mem.zeroes(SurfacePresentation);
    presentation.surface_id = 9;
    presentation.revision = 1;
    presentation.buffer_object_id = 9;
    presentation.buffer_bytes = 4096;
    try std.testing.expect(isCanonicalSurfacePresentation(&presentation));
    presentation.buffer_object_id = 0;
    try std.testing.expect(!isCanonicalSurfacePresentation(&presentation));
}
