const header = @import("request_header_wire.zig");

pub const SCOPE_TASK_PRESENT: u16 = 1 << 0;
pub const SCOPE_WORKSPACE_PRESENT: u16 = 1 << 1;
pub const SCOPE_LOCAL_ONLY: u16 = 1 << 2;
pub const SCOPE_BROKER_ONLY: u16 = 1 << 3;
pub const SCOPE_FLAGS: u16 = SCOPE_TASK_PRESENT | SCOPE_WORKSPACE_PRESENT | SCOPE_LOCAL_ONLY | SCOPE_BROKER_ONLY;
pub const LEASE_RENEWABLE: u16 = 1 << 0;
pub const AUDIT_USER_VISIBLE: u16 = 1 << 1;
pub const GRANT_FLAGS: u16 = LEASE_RENEWABLE | AUDIT_USER_VISIBLE;
pub const PASS_REVOKE_SOURCE: u32 = 1 << 0;

// Every tag and boolean is an integer until the kernel validates the complete
// request. Explicit presence bits preserve present-zero scope identifiers.
pub const CapabilityMintWireRequest = extern struct {
    header: header.RequestHeader,
    policy_capability_id: u64,
    holder_serial: u64,
    issuer_serial: u64,
    target_id: u64,
    rights_bits: u64,
    scope_task_id: u64 = 0,
    scope_workspace_id: u64 = 0,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    audit_source_task_id: u64 = 0,
    audit_broker_service_id: u64 = 0,
    audit_trace_id: u64 = 0,
    audit_parent_trace_id: u64 = 0,
    audit_policy_generation: u32 = 0,
    flags: u16 = 0,
    scope_flags: u16 = 0,
    holder_kind: u8,
    issuer_kind: u8,
    target_kind: u8,
    rights_kind: u8,
    delegation_depth: u8 = 0,
    max_delegation_depth: u8 = 4,
    reserved: u16 = 0,
};

pub const CapabilityDeriveWireRequest = extern struct {
    header: header.RequestHeader,
    parent_capability_id: u64,
    holder_serial: u64,
    rights_bits: u64,
    scope_task_id: u64 = 0,
    scope_workspace_id: u64 = 0,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    audit_source_task_id: u64 = 0,
    audit_broker_service_id: u64 = 0,
    audit_trace_id: u64 = 0,
    audit_parent_trace_id: u64 = 0,
    audit_policy_generation: u32 = 0,
    flags: u16 = 0,
    scope_flags: u16 = 0,
    holder_kind: u8,
    rights_kind: u8,
    delegation_depth: u8 = 0,
    max_delegation_depth: u8 = 4,
    reserved: u32 = 0,
};

pub const CapabilityPassWireRequest = extern struct {
    header: header.RequestHeader,
    capability_id: u64,
    receiver_task_id: u64,
    flags: u32 = 0,
    reserved: u32 = 0,
};

comptime {
    if (@sizeOf(CapabilityMintWireRequest) != 136 or @alignOf(CapabilityMintWireRequest) != 8 or
        @sizeOf(CapabilityDeriveWireRequest) != 120 or @alignOf(CapabilityDeriveWireRequest) != 8 or
        @sizeOf(CapabilityPassWireRequest) != 40 or @alignOf(CapabilityPassWireRequest) != 8)
        @compileError("capability wire geometry changed");
    for (.{ CapabilityMintWireRequest, CapabilityDeriveWireRequest, CapabilityPassWireRequest }) |T| {
        var end: usize = 0;
        for (@typeInfo(T).@"struct".field_names) |field| {
            if (@offsetOf(T, field) != end) @compileError("capability wire contains implicit padding");
            end += @sizeOf(@FieldType(T, field));
        }
        if (end != @sizeOf(T)) @compileError("capability wire contains implicit tail padding");
    }
}
