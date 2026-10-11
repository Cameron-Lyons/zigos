const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const rights = @import("rights.zig");

pub const DEFAULT_MAX_DELEGATION_DEPTH: u8 = 4;

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
    delegation_depth: u8 = 0,
    max_delegation_depth: u8 = DEFAULT_MAX_DELEGATION_DEPTH,
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

    pub fn traceId(self: *const Capability) u64 {
        if (self.audit.trace_id != 0) return self.audit.trace_id;
        return computeCapabilityTraceId(self);
    }
};

fn computeCapabilityTraceId(record: *const Capability) u64 {
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = appendTraceU64(hash, record.id);
    hash = native_util.fnv1a64AppendByte(hash, @backingInt(record.holder.kind));
    hash = appendTraceU64(hash, record.holder.serial);
    hash = native_util.fnv1a64AppendByte(hash, @backingInt(record.issuer.kind));
    hash = appendTraceU64(hash, record.issuer.serial);
    hash = native_util.fnv1a64AppendByte(hash, @backingInt(record.target.kind));
    hash = appendTraceU64(hash, record.target.id);
    hash = appendTraceU64(hash, record.rights.toBits());
    hash = appendTraceU64(hash, record.scope.task_id orelse 0);
    hash = appendTraceU64(hash, record.scope.workspace_id orelse 0);
    hash = native_util.fnv1a64AppendByte(hash, @intFromBool(record.scope.local_only));
    hash = native_util.fnv1a64AppendByte(hash, @intFromBool(record.scope.broker_only));
    hash = appendTraceU64(hash, record.lease.issued_at_ticks);
    hash = appendTraceU64(hash, record.lease.expires_at_ticks);
    hash = native_util.fnv1a64AppendU32LittleEndian(hash, record.audit.policy_generation);
    hash = appendTraceU64(hash, record.audit.source_task_id);
    hash = appendTraceU64(hash, record.audit.broker_service_id);
    hash = appendTraceU64(hash, record.audit.parent_trace_id);
    hash = native_util.fnv1a64AppendByte(hash, record.audit.delegation_depth);
    hash = native_util.fnv1a64AppendByte(hash, record.audit.max_delegation_depth);
    return hash;
}

fn tracePrimePower(comptime count: usize) u64 {
    comptime {
        var result: u64 = 1;
        for (0..count) |_| result *%= native_util.FNV1A_64_PRIME;
        return result;
    }
}

const trace_prime_power_8 = tracePrimePower(8);
const trace_prime_power_4 = tracePrimePower(4);

// The canonical stream always contains eight little-endian bytes. Each zero
// suffix byte XORs nothing, so its serial FNV multiplications can be combined.
// Keep this optimization local to capability tracing and its common small IDs.
inline fn appendTraceU64(hash: u64, value: u64) u64 {
    if (value == 0) return hash *% trace_prime_power_8;
    if (value <= 0xff) return (hash ^ value) *% trace_prime_power_8;
    if (value <= 0xffff_ffff) return native_util.fnv1a64AppendU32LittleEndian(hash, @intCast(value)) *% trace_prime_power_4;
    return native_util.fnv1a64AppendU64LittleEndian(hash, value);
}

// This byte-stream oracle deliberately retains the pre-optimization canonical
// field order. Tests hash its complete 107 bytes using ordinary byte FNV.
fn traceBytesForTest(record: *const Capability) [107]u8 {
    const Encoder = struct {
        bytes: [107]u8 = undefined,
        position: usize = 0,

        fn byte(self: *@This(), value: u8) void {
            self.bytes[self.position] = value;
            self.position += 1;
        }

        fn integer(self: *@This(), comptime T: type, value: T) void {
            var remaining = value;
            for (0..@sizeOf(T)) |_| {
                self.byte(@truncate(remaining));
                remaining >>= 8;
            }
        }
    };
    var encoded = Encoder{};
    encoded.integer(u64, record.id);
    encoded.byte(@backingInt(record.holder.kind));
    encoded.integer(u64, record.holder.serial);
    encoded.byte(@backingInt(record.issuer.kind));
    encoded.integer(u64, record.issuer.serial);
    encoded.byte(@backingInt(record.target.kind));
    encoded.integer(u64, record.target.id);
    encoded.integer(u64, record.rights.toBits());
    encoded.integer(u64, record.scope.task_id orelse 0);
    encoded.integer(u64, record.scope.workspace_id orelse 0);
    encoded.byte(@intFromBool(record.scope.local_only));
    encoded.byte(@intFromBool(record.scope.broker_only));
    encoded.integer(u64, record.lease.issued_at_ticks);
    encoded.integer(u64, record.lease.expires_at_ticks);
    encoded.integer(u32, record.audit.policy_generation);
    encoded.integer(u64, record.audit.source_task_id);
    encoded.integer(u64, record.audit.broker_service_id);
    encoded.integer(u64, record.audit.parent_trace_id);
    encoded.byte(record.audit.delegation_depth);
    encoded.byte(record.audit.max_delegation_depth);
    @import("std").debug.assert(encoded.position == encoded.bytes.len);
    return encoded.bytes;
}

fn traceRecordForTest() Capability {
    return .{
        .id = 0x0000_0001_0000_0003,
        .holder = .{ .kind = .service, .serial = 2 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .object, .id = 0x8000_0000_0000_0000 },
        .rights = .{ .object = .{ .object_read = true, .capability_pass = true, .capability_revoke = true } },
        .scope = .{ .task_id = 0x0000_0001_0000_0001, .local_only = true },
        .lease = .{ .issued_at_ticks = 7, .expires_at_ticks = @import("std").math.maxInt(u64) },
        .revocation_generation = 1,
        .audit = .{},
    };
}

test "capability trace suffix collapse preserves every integer byte" {
    const std = @import("std");
    const values = [_]u64{
        0,                   1,                     0xfe,                  0xff,
        0x100,               0xffff,                0x1_0000,              0xff_ffff,
        0x100_0000,          0xffff_fffe,           0xffff_ffff,           0x1_0000_0000,
        0xff_ffff_ffff,      0x100_0000_0000,       0xffff_ffff_ffff,      0x1_0000_0000_0000,
        0xff_ffff_ffff_ffff, 0x0100_0000_0000_0000, 0x8000_0000_0000_0000, std.math.maxInt(u64),
    };
    const seeds = [_]u64{ 0, 1, native_util.FNV1A_64_OFFSET_BASIS, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, std.math.maxInt(u64) };
    for (values) |value| {
        for (seeds) |seed| try std.testing.expectEqual(native_util.fnv1a64AppendU64LittleEndian(seed, value), appendTraceU64(seed, value));
    }
    var state: u64 = 0x867c_052d_039a_145b;
    for (0..4096) |_| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const value = state;
        state = state *% 6364136223846793005 +% 1442695040888963407;
        try std.testing.expectEqual(native_util.fnv1a64AppendU64LittleEndian(state, value), appendTraceU64(state, value));
    }
}

test "capability trace retains canonical fields scopes and explicit overrides" {
    const std = @import("std");
    var record = traceRecordForTest();
    try std.testing.expectEqual(@as(u64, 0xdfb8_77df_c237_a24f), record.traceId());
    try std.testing.expectEqual(native_util.fnv1a64(&traceBytesForTest(&record)), record.traceId());
    inline for (comptime std.meta.tags(rights.CapabilityTargetKind)) |kind| {
        record.target.kind = kind;
        record.rights = rights.CapabilityRights.emptyForTarget(kind);
        const Payload = @FieldType(rights.CapabilityRights, @tagName(kind));
        inline for (@typeInfo(Payload).@"struct".field_names) |name| {
            if (comptime !std.mem.eql(u8, name, "_reserved")) {
                @field(@field(record.rights, @tagName(kind)), name) = true;
                try std.testing.expectEqual(native_util.fnv1a64(&traceBytesForTest(&record)), record.traceId());
            }
        }
    }
    record = traceRecordForTest();
    record.scope.task_id = null;
    record.scope.workspace_id = null;
    const absent = record.traceId();
    record.scope.task_id = 0;
    record.scope.workspace_id = 0;
    try std.testing.expectEqual(absent, record.traceId());
    try std.testing.expectEqual(native_util.fnv1a64(&traceBytesForTest(&record)), record.traceId());

    var state: u64 = 0x958b_7046_8cdf_294e;
    for (0..1024) |index| {
        var words: [13]u64 = undefined;
        for (&words) |*word| {
            state = state *% 6364136223846793005 +% 1442695040888963407;
            word.* = state;
        }
        record = traceRecordForTest();
        record.id = words[0];
        record.holder = .{ .kind = std.meta.tags(principal.PrincipalKind)[index % std.meta.tags(principal.PrincipalKind).len], .serial = words[1] };
        record.issuer = .{ .kind = std.meta.tags(principal.PrincipalKind)[(index + 1) % std.meta.tags(principal.PrincipalKind).len], .serial = words[2] };
        record.target.id = words[3];
        record.scope = .{ .task_id = if (index % 3 == 0) null else words[4], .workspace_id = if (index % 5 == 0) null else words[5], .local_only = index & 1 != 0, .broker_only = index & 2 != 0 };
        record.lease = .{ .issued_at_ticks = words[6], .expires_at_ticks = words[7], .renewable = index & 4 != 0 };
        record.revocation_generation = @truncate(words[8]);
        record.audit = .{ .policy_generation = @truncate(words[9]), .source_task_id = words[10], .broker_service_id = words[11], .parent_trace_id = words[12], .delegation_depth = @truncate(index), .max_delegation_depth = @truncate(index >> 2), .user_visible_entitlement = index & 8 != 0 };
        try std.testing.expectEqual(native_util.fnv1a64(&traceBytesForTest(&record)), record.traceId());
        record.audit.trace_id = words[0] | 1;
        try std.testing.expectEqual(record.audit.trace_id, record.traceId());
    }
}
