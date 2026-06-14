const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const rights = @import("rights.zig");

pub const CapabilityScope = struct {
    task_id: ?u64 = null,
    workspace_id: ?u64 = null,
    local_only: bool = false,
    broker_only: bool = false,

    pub fn isSubsetOf(self: CapabilityScope, parent: CapabilityScope) bool {
        if (parent.task_id) |task_id| {
            if (self.task_id == null or self.task_id.? != task_id) return false;
        }
        if (parent.workspace_id) |workspace_id| {
            if (self.workspace_id == null or self.workspace_id.? != workspace_id) return false;
        }
        if (parent.local_only and !self.local_only) return false;
        if (parent.broker_only and !self.broker_only) return false;
        return true;
    }
};

pub const CapabilityLease = struct {
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    renewable: bool = false,

    pub fn isActive(self: CapabilityLease, now_ticks: u64) bool {
        return now_ticks >= self.issued_at_ticks and now_ticks <= self.expires_at_ticks;
    }

    pub fn isSubsetOf(self: CapabilityLease, parent: CapabilityLease) bool {
        return self.issued_at_ticks >= parent.issued_at_ticks and self.expires_at_ticks <= parent.expires_at_ticks;
    }
};

pub const AuditMetadata = struct {
    policy_generation: u32 = 0,
    source_task_id: u64 = 0,
    broker_service_id: u64 = 0,
    trace_id: u64 = 0,
    parent_trace_id: u64 = 0,
    user_visible_entitlement: bool = false,
};

pub const Capability = struct {
    id: u64,
    holder: principal.PrincipalId,
    issuer: principal.PrincipalId,
    target: rights.CapabilityTarget,
    rights: rights.CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    revocation_generation: u32,
    audit: AuditMetadata,

    pub fn traceId(self: Capability) u64 {
        if (self.audit.trace_id != 0) return self.audit.trace_id;
        return computeCapabilityTraceId(self);
    }
};

fn computeCapabilityTraceId(record: Capability) u64 {
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(record.holder.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.holder.serial);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(record.issuer.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.issuer.serial);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(record.target.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.target.id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.rights.toBits());
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.scope.task_id orelse 0);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.scope.workspace_id orelse 0);
    hash = native_util.fnv1a64AppendByte(hash, @intFromBool(record.scope.local_only));
    hash = native_util.fnv1a64AppendByte(hash, @intFromBool(record.scope.broker_only));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.lease.issued_at_ticks);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.lease.expires_at_ticks);
    hash = native_util.fnv1a64AppendU32LittleEndian(hash, record.audit.policy_generation);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.audit.source_task_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.audit.broker_service_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.audit.parent_trace_id);
    return hash;
}
