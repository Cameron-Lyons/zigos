const std = @import("std");

pub const ABI_VERSION: u16 = 5;
pub const ENDPOINT_INLINE_BYTES: usize = 96;
pub const SURFACE_PRESENTATION_TEXT_BYTES: usize = 512;

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

pub const InputEventKind = enum(u8) {
    text,
    backspace,
    commit_text,
    focus_next,
    focus_previous,
    activate,
    task_switch_next,
    task_switch_previous,
    show_recovery,
    dismiss_recovery,
};

pub const InputEventDescriptor = extern struct {
    sequence: u64,
    tick: u64,
    window_id: u64,
    task_id: u64,
    surface_id: u64,
    kind: u8,
    text: u8,
    port_id: u8,
    slot_id: u8,
    _reserved: [4]u8 = [_]u8{0} ** 4,
};

pub const InputRecvResponse = extern struct {
    present: u8,
    _reserved: [7]u8 = [_]u8{0} ** 7,
    event: InputEventDescriptor,
};

pub const SurfaceModelKind = enum(u8) {
    none,
    notes,
    viewer,
    capture,
    permission_review,
    compositor,
    generic,
};

pub const SurfaceStateFlags = packed struct(u8) {
    dirty: bool = false,
    recovery_visible: bool = false,
    active: bool = false,
    input_overflow: bool = false,
    _reserved: u4 = 0,
};

pub const SurfacePresentation = extern struct {
    surface_id: u64,
    revision: u64,
    interaction_hash: u64,
    commit_count: u32,
    activation_count: u32,
    focus_index: u16,
    text_length: u16,
    cursor: u16,
    model_kind: u8,
    state_flags: u8,
    text: [SURFACE_PRESENTATION_TEXT_BYTES]u8,

    pub fn textSlice(self: *const SurfacePresentation) []const u8 {
        return self.text[0..@min(self.text_length, self.text.len)];
    }
};

pub const ServiceConnectionDescriptor = extern struct {
    service_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
    interface_id: u16,
    flags: u16,
    _reserved: u32 = 0,
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

pub fn inputEventKind(raw: u8) ?InputEventKind {
    return std.enums.fromInt(InputEventKind, raw);
}

pub fn surfaceModelKind(raw: u8) ?SurfaceModelKind {
    return std.enums.fromInt(SurfaceModelKind, raw);
}

pub fn isCanonicalSurfacePresentation(presentation: *const SurfacePresentation) bool {
    if (presentation.surface_id == 0 or presentation.revision == 0 or presentation.interaction_hash == 0) return false;
    if (presentation.text_length > presentation.text.len or presentation.cursor > presentation.text_length) return false;
    const model = surfaceModelKind(presentation.model_kind) orelse return false;
    if (model == .none) return false;
    const flags: SurfaceStateFlags = @bitCast(presentation.state_flags);
    if (flags._reserved != 0) return false;
    for (presentation.text[0..presentation.text_length]) |byte| {
        if (byte != '\n' and (byte < 0x20 or byte > 0x7e)) return false;
    }
    for (presentation.text[presentation.text_length..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

test "native abi operation ids stay in a dedicated namespace" {
    try std.testing.expect(opcode(.task_create) >= 0x100);
    try std.testing.expect(policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 5), ABI_VERSION);
    try std.testing.expectEqual(@as(usize, 96), ENDPOINT_INLINE_BYTES);
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(CapabilityDescriptor));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(TaskDescriptor));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ResourceDescriptor));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(InputEventDescriptor));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(InputRecvResponse));
    try std.testing.expectEqual(@as(usize, 552), @sizeOf(SurfacePresentation));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(DeviceDescriptor));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(DeviceMmioWindowDescriptor));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(BoolResponse));
    try std.testing.expectEqual(@as(usize, 112), @sizeOf(EndpointCreateResponse));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(EndpointRecvResponse));
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(SharedMemoryCreateResponse));
    try std.testing.expect(taskFlagsHas(TASK_FLAG_LOCAL_ONLY, TASK_FLAG_LOCAL_ONLY));
    try std.testing.expectEqual(@as(u8, 3), taskFlagsResourceClass(@as(u16, 3) << TASK_RESOURCE_CLASS_SHIFT));
    try std.testing.expect(serviceFlagsHas(SERVICE_CONNECTION_FLAG_USERSPACE_OWNER, SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expectEqual(InputEventKind.commit_text, inputEventKind(@intFromEnum(InputEventKind.commit_text)).?);
    try std.testing.expect(inputEventKind(0xFF) == null);
    try std.testing.expectEqual(SurfaceModelKind.notes, surfaceModelKind(@intFromEnum(SurfaceModelKind.notes)).?);
    try std.testing.expect(surfaceModelKind(0xFF) == null);

    var presentation = std.mem.zeroes(SurfacePresentation);
    presentation.surface_id = 9;
    presentation.revision = 1;
    presentation.interaction_hash = 2;
    presentation.model_kind = @intFromEnum(SurfaceModelKind.notes);
    presentation.text[0] = 'x';
    presentation.text_length = 1;
    presentation.cursor = 1;
    try std.testing.expect(isCanonicalSurfacePresentation(&presentation));
    presentation.text[presentation.text.len - 1] = 1;
    try std.testing.expect(!isCanonicalSurfacePresentation(&presentation));
}
