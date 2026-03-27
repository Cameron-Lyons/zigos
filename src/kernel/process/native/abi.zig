const std = @import("std");

pub const ABI_VERSION: u16 = 1;

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
    service_register,
    service_connect,
};

pub const PolicyOperation = enum(u16) {
    authorize_request = 0x200,
    apply_manifest,
};

pub const ReviewOperation = enum(u16) {
    review_bundle = 0x240,
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
    interface_hash: u64,
    version_major: u16,
    version_minor: u16,
    flags: u16,
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

test "native abi operation ids stay in a dedicated namespace" {
    try std.testing.expect(opcode(.task_create) >= 0x100);
    try std.testing.expect(policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 1), ABI_VERSION);
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(CapabilityDescriptor));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(TaskDescriptor));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ResourceDescriptor));
}
