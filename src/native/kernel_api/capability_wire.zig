const std = @import("std");
const wire = @import("../core/capability_wire.zig");
const header = @import("../core/request_header_wire.zig");
const principal = @import("../core/principal.zig");
const capability = @import("capability.zig");

fn rightsFromWireInto(kind_byte: u8, bits: u64, out: *capability.CapabilityRights) bool {
    const kind = std.enums.fromInt(capability.CapabilityTargetKind, kind_byte) orelse return false;
    switch (kind) {
        inline else => |tag| {
            const Payload = @FieldType(capability.CapabilityRights, @tagName(tag));
            var payload: Payload = .{};
            var allowed: u64 = 0;
            inline for (@typeInfo(Payload).@"struct".field_names) |name| {
                if (comptime !std.mem.eql(u8, name, "_reserved")) {
                    const mask = @field(capability.CapabilityRight, name).mask();
                    allowed |= mask;
                    @field(payload, name) = bits & mask != 0;
                }
            }
            if (bits & ~allowed != 0) return false;
            out.* = @unionInit(capability.CapabilityRights, @tagName(tag), payload);
        },
    }
    return true;
}

fn validGrant(w: anytype) bool {
    return w.reserved == 0 and w.flags & ~wire.GRANT_FLAGS == 0 and w.scope_flags & ~wire.SCOPE_FLAGS == 0 and
        (w.scope_flags & wire.SCOPE_TASK_PRESENT != 0 or w.scope_task_id == 0) and
        (w.scope_flags & wire.SCOPE_WORKSPACE_PRESENT != 0 or w.scope_workspace_id == 0);
}

fn scopeFromWire(w: anytype) capability.CapabilityScope {
    return .{
        .task_id = if (w.scope_flags & wire.SCOPE_TASK_PRESENT != 0) w.scope_task_id else null,
        .workspace_id = if (w.scope_flags & wire.SCOPE_WORKSPACE_PRESENT != 0) w.scope_workspace_id else null,
        .local_only = w.scope_flags & wire.SCOPE_LOCAL_ONLY != 0,
        .broker_only = w.scope_flags & wire.SCOPE_BROKER_ONLY != 0,
    };
}

fn leaseFromWire(w: anytype) capability.CapabilityLease {
    return .{ .issued_at_ticks = w.issued_at_ticks, .expires_at_ticks = w.expires_at_ticks, .renewable = w.flags & wire.LEASE_RENEWABLE != 0 };
}

fn auditFromWire(w: anytype) capability.AuditMetadata {
    return .{
        .policy_generation = w.audit_policy_generation,
        .source_task_id = w.audit_source_task_id,
        .broker_service_id = w.audit_broker_service_id,
        .trace_id = w.audit_trace_id,
        .parent_trace_id = w.audit_parent_trace_id,
        .user_visible_entitlement = w.flags & wire.AUDIT_USER_VISIBLE != 0,
        .delegation_depth = w.delegation_depth,
        .max_delegation_depth = w.max_delegation_depth,
    };
}

pub fn mintFromWireInto(w: wire.CapabilityMintWireRequest, out: *capability.MintRequest) bool {
    if (!validGrant(w)) return false;
    const holder = std.enums.fromInt(principal.PrincipalKind, w.holder_kind) orelse return false;
    const issuer = std.enums.fromInt(principal.PrincipalKind, w.issuer_kind) orelse return false;
    const target = std.enums.fromInt(capability.CapabilityTargetKind, w.target_kind) orelse return false;
    var rights: capability.CapabilityRights = undefined;
    if (!rightsFromWireInto(w.rights_kind, w.rights_bits, &rights)) return false;
    out.* = .{
        .holder = .{ .kind = holder, .serial = w.holder_serial },
        .issuer = .{ .kind = issuer, .serial = w.issuer_serial },
        .target = .{ .kind = target, .id = w.target_id },
        .rights = rights,
        .scope = scopeFromWire(w),
        .lease = leaseFromWire(w),
        .audit = auditFromWire(w),
    };
    return true;
}

pub fn deriveFromWireInto(w: wire.CapabilityDeriveWireRequest, out: *capability.DeriveRequest) bool {
    if (!validGrant(w)) return false;
    const holder = std.enums.fromInt(principal.PrincipalKind, w.holder_kind) orelse return false;
    var rights: capability.CapabilityRights = undefined;
    if (!rightsFromWireInto(w.rights_kind, w.rights_bits, &rights)) return false;
    out.* = .{
        .parent_capability_id = w.parent_capability_id,
        .holder = .{ .kind = holder, .serial = w.holder_serial },
        .rights = rights,
        .scope = scopeFromWire(w),
        .lease = leaseFromWire(w),
        .audit = auditFromWire(w),
    };
    return true;
}

pub fn passEncodingIsValid(w: wire.CapabilityPassWireRequest) bool {
    return w.reserved == 0 and w.flags & ~wire.PASS_REVOKE_SOURCE == 0;
}

fn scopeFlags(scope: capability.CapabilityScope) u16 {
    return (if (scope.task_id != null) wire.SCOPE_TASK_PRESENT else @as(u16, 0)) |
        (if (scope.workspace_id != null) wire.SCOPE_WORKSPACE_PRESENT else @as(u16, 0)) |
        (if (scope.local_only) wire.SCOPE_LOCAL_ONLY else @as(u16, 0)) |
        (if (scope.broker_only) wire.SCOPE_BROKER_ONLY else @as(u16, 0));
}

fn grantFlags(lease: capability.CapabilityLease, audit: capability.AuditMetadata) u16 {
    return (if (lease.renewable) wire.LEASE_RENEWABLE else @as(u16, 0)) |
        (if (audit.user_visible_entitlement) wire.AUDIT_USER_VISIBLE else @as(u16, 0));
}

pub fn mintToWireInto(h: header.RequestHeader, policy_capability_id: u64, request: capability.MintRequest, out: *wire.CapabilityMintWireRequest) void {
    out.* = .{
        .header = h,
        .policy_capability_id = policy_capability_id,
        .holder_serial = request.holder.serial,
        .issuer_serial = request.issuer.serial,
        .target_id = request.target.id,
        .rights_bits = request.rights.toBits(),
        .scope_task_id = request.scope.task_id orelse 0,
        .scope_workspace_id = request.scope.workspace_id orelse 0,
        .issued_at_ticks = request.lease.issued_at_ticks,
        .expires_at_ticks = request.lease.expires_at_ticks,
        .audit_source_task_id = request.audit.source_task_id,
        .audit_broker_service_id = request.audit.broker_service_id,
        .audit_trace_id = request.audit.trace_id,
        .audit_parent_trace_id = request.audit.parent_trace_id,
        .audit_policy_generation = request.audit.policy_generation,
        .flags = grantFlags(request.lease, request.audit),
        .scope_flags = scopeFlags(request.scope),
        .holder_kind = @backingInt(request.holder.kind),
        .issuer_kind = @backingInt(request.issuer.kind),
        .target_kind = @backingInt(request.target.kind),
        .rights_kind = @backingInt(std.meta.activeTag(request.rights)),
        .delegation_depth = request.audit.delegation_depth,
        .max_delegation_depth = request.audit.max_delegation_depth,
    };
}

pub fn deriveToWireInto(h: header.RequestHeader, request: capability.DeriveRequest, out: *wire.CapabilityDeriveWireRequest) void {
    out.* = .{
        .header = h,
        .parent_capability_id = request.parent_capability_id,
        .holder_serial = request.holder.serial,
        .rights_bits = request.rights.toBits(),
        .scope_task_id = request.scope.task_id orelse 0,
        .scope_workspace_id = request.scope.workspace_id orelse 0,
        .issued_at_ticks = request.lease.issued_at_ticks,
        .expires_at_ticks = request.lease.expires_at_ticks,
        .audit_source_task_id = request.audit.source_task_id,
        .audit_broker_service_id = request.audit.broker_service_id,
        .audit_trace_id = request.audit.trace_id,
        .audit_parent_trace_id = request.audit.parent_trace_id,
        .audit_policy_generation = request.audit.policy_generation,
        .flags = grantFlags(request.lease, request.audit),
        .scope_flags = scopeFlags(request.scope),
        .holder_kind = @backingInt(request.holder.kind),
        .rights_kind = @backingInt(std.meta.activeTag(request.rights)),
        .delegation_depth = request.audit.delegation_depth,
        .max_delegation_depth = request.audit.max_delegation_depth,
    };
}

pub fn passToWireInto(h: header.RequestHeader, capability_id: u64, receiver_task_id: u64, revoke_source: bool, out: *wire.CapabilityPassWireRequest) void {
    out.* = .{ .header = h, .capability_id = capability_id, .receiver_task_id = receiver_task_id, .flags = if (revoke_source) wire.PASS_REVOKE_SOURCE else 0 };
}

test "capability scalar wire roundtrips all rights kinds and explicit optional scopes" {
    @setEvalBranchQuota(20_000);
    const h = header.RequestHeader{ .operation = 0x107, .subject_task_id = 17 };
    inline for (std.meta.tags(capability.CapabilityTargetKind)) |kind| {
        var rights = capability.CapabilityRights.emptyForTarget(kind);
        switch (rights) {
            inline else => |*payload| inline for (@typeInfo(@TypeOf(payload.*)).@"struct".field_names) |name| {
                if (comptime !std.mem.eql(u8, name, "_reserved")) @field(payload, name) = true;
            },
        }
        const request = capability.MintRequest{
            .holder = .{ .kind = .app, .serial = 7 },
            .issuer = .{ .kind = .policy_authority, .serial = 8 },
            .target = .{ .kind = kind, .id = 9 },
            .rights = rights,
            .scope = .{ .task_id = 0, .workspace_id = 13, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 3, .expires_at_ticks = 19, .renewable = true },
            .audit = .{ .policy_generation = 4, .source_task_id = 5, .broker_service_id = 6, .trace_id = 10, .parent_trace_id = 11, .user_visible_entitlement = true, .delegation_depth = 2, .max_delegation_depth = 7 },
        };
        var encoded: wire.CapabilityMintWireRequest = undefined;
        mintToWireInto(h, 12, request, &encoded);
        var decoded: capability.MintRequest = undefined;
        try std.testing.expect(mintFromWireInto(encoded, &decoded));
        try std.testing.expect(std.meta.eql(request, decoded));
        const derive = capability.DeriveRequest{ .parent_capability_id = 12, .holder = request.holder, .rights = rights, .scope = request.scope, .lease = request.lease, .audit = request.audit };
        var derived_wire: wire.CapabilityDeriveWireRequest = undefined;
        deriveToWireInto(h, derive, &derived_wire);
        var derived: capability.DeriveRequest = undefined;
        try std.testing.expect(deriveFromWireInto(derived_wire, &derived));
        try std.testing.expect(std.meta.eql(derive, derived));
        try std.testing.expectEqual(@as(?u64, 0), derived.scope.task_id);
    }
}

test "capability scalar decoder rejects integer tags masks flags and absent values atomically" {
    const request = capability.MintRequest{ .holder = .{ .kind = .app, .serial = 1 }, .issuer = .{ .kind = .policy_authority, .serial = 2 }, .target = .{ .kind = .object, .id = 3 }, .rights = .{ .object = .{ .object_read = true } }, .scope = .{}, .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 } };
    var valid: wire.CapabilityMintWireRequest = undefined;
    mintToWireInto(.{ .operation = 0x107 }, 4, request, &valid);
    var out = request;
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        var bad = valid;
        bad.holder_kind = byte;
        var before = out;
        try std.testing.expectEqual(std.enums.fromInt(principal.PrincipalKind, byte) != null, mintFromWireInto(bad, &out));
        if (std.enums.fromInt(principal.PrincipalKind, byte) == null) try std.testing.expect(std.meta.eql(before, out));
        bad = valid;
        bad.issuer_kind = byte;
        before = out;
        try std.testing.expectEqual(std.enums.fromInt(principal.PrincipalKind, byte) != null, mintFromWireInto(bad, &out));
        if (std.enums.fromInt(principal.PrincipalKind, byte) == null) try std.testing.expect(std.meta.eql(before, out));
        bad = valid;
        bad.target_kind = byte;
        before = out;
        try std.testing.expectEqual(std.enums.fromInt(capability.CapabilityTargetKind, byte) != null, mintFromWireInto(bad, &out));
        if (std.enums.fromInt(capability.CapabilityTargetKind, byte) == null) try std.testing.expect(std.meta.eql(before, out));
        bad = valid;
        bad.rights_kind = byte;
        bad.rights_bits = 0;
        before = out;
        try std.testing.expectEqual(std.enums.fromInt(capability.CapabilityTargetKind, byte) != null, mintFromWireInto(bad, &out));
        if (std.enums.fromInt(capability.CapabilityTargetKind, byte) == null) try std.testing.expect(std.meta.eql(before, out));
    }
    const fields = .{ "flags", "scope_flags", "reserved" };
    inline for (fields) |field| {
        var bad = valid;
        @field(bad, field) = 0x8000;
        out = request;
        try std.testing.expect(!mintFromWireInto(bad, &out));
        try std.testing.expect(std.meta.eql(request, out));
    }
    inline for (.{ "scope_task_id", "scope_workspace_id" }) |field| {
        var bad = valid;
        @field(bad, field) = 1;
        out = request;
        try std.testing.expect(!mintFromWireInto(bad, &out));
        try std.testing.expect(std.meta.eql(request, out));
    }
    inline for (std.meta.tags(capability.CapabilityTargetKind)) |kind| {
        var zero: capability.CapabilityRights = undefined;
        try std.testing.expect(rightsFromWireInto(@backingInt(kind), 0, &zero));
        for (0..64) |bit| {
            const bits = @as(u64, 1) << @intCast(bit);
            var rights = zero;
            if (rightsFromWireInto(@backingInt(kind), bits, &rights)) {
                try std.testing.expectEqual(bits, rights.toBits());
            } else try std.testing.expect(std.meta.eql(zero, rights));
        }
    }
    var pass: wire.CapabilityPassWireRequest = undefined;
    passToWireInto(.{ .operation = 0x109 }, 5, 6, true, &pass);
    try std.testing.expect(passEncodingIsValid(pass));
    pass.flags = 2;
    try std.testing.expect(!passEncodingIsValid(pass));
    pass.flags = wire.PASS_REVOKE_SOURCE;
    pass.reserved = 1;
    try std.testing.expect(!passEncodingIsValid(pass));
}

test "capability scalar derive denial preserves typed output and encoder overwrites every byte" {
    const request = capability.DeriveRequest{
        .parent_capability_id = 1,
        .holder = .{ .kind = .user, .serial = 2 },
        .rights = .{ .endpoint = .{ .endpoint_recv = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 3, .expires_at_ticks = 9 },
    };
    var encoded: wire.CapabilityDeriveWireRequest = undefined;
    @memset(std.mem.asBytes(&encoded), 0xa5);
    deriveToWireInto(.{ .operation = 0x108, .subject_task_id = 2 }, request, &encoded);
    var clean: wire.CapabilityDeriveWireRequest = undefined;
    @memset(std.mem.asBytes(&clean), 0x5a);
    deriveToWireInto(.{ .operation = 0x108, .subject_task_id = 2 }, request, &clean);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&clean), std.mem.asBytes(&encoded));
    inline for (.{ "holder_kind", "rights_kind", "reserved", "flags", "scope_flags", "scope_task_id", "scope_workspace_id" }) |field| {
        var bad = encoded;
        @field(bad, field) = if (comptime std.mem.eql(u8, field, "flags") or std.mem.eql(u8, field, "scope_flags")) 0x8000 else if (comptime std.mem.eql(u8, field, "holder_kind") or std.mem.eql(u8, field, "rights_kind")) 255 else 1;
        var out = request;
        try std.testing.expect(!deriveFromWireInto(bad, &out));
        try std.testing.expect(std.meta.eql(request, out));
    }
    for (0..64) |bit| {
        var bad = encoded;
        bad.rights_bits = @as(u64, 1) << @intCast(bit);
        var out = request;
        if (deriveFromWireInto(bad, &out)) {
            try std.testing.expectEqual(bad.rights_bits, out.rights.toBits());
        } else try std.testing.expect(std.meta.eql(request, out));
    }
}
