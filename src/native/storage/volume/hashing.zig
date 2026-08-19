const native_util = @import("../../core/util.zig");
const principal = @import("../../core/principal.zig");
const volume_errors = @import("errors.zig");
const workspace = @import("../workspace.zig");

pub fn workspaceStateHash(record: *const workspace.WorkspaceRecord) volume_errors.Error!u64 {
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = hashBytes(hash, "workspace-state");
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.id.raw());
    hash = hashPrincipal(hash, record.owner);
    hash = hashBytes(hash, record.labelSlice());
    hash = native_util.fnv1a64AppendU32LittleEndian(hash, record.generation);
    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.path_index.entry_count));
    hash = hashBytes(hash, &record.path_index.root_address);

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.mutation_log.entry_mutation_count));
    for (record.mutation_log.entriesConst()[0..record.mutation_log.entry_mutation_count]) |mutation| {
        hash = native_util.fnv1a64AppendU32LittleEndian(hash, mutation.generation);
        hash = hashEntry(hash, mutation.entry);
    }

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.share_table.share_grant_count));
    for (record.share_table.share_grants[0..record.share_table.share_grant_count]) |grant| {
        hash = hashShareGrant(hash, grant);
    }

    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intCast(record.recoverable_deletes.deleted_count));
    for (record.recoverable_deletes.deleted_entries[0..record.recoverable_deletes.deleted_count]) |entry| {
        hash = hashEntry(hash, entry);
    }
    return hash;
}

pub fn checksumBytes(bytes: []const u8) u64 {
    return native_util.fnv1a64(bytes);
}

fn hashBytes(hash: u64, bytes: []const u8) u64 {
    var next = native_util.fnv1a64AppendU32LittleEndian(hash, @intCast(bytes.len));
    next = native_util.fnv1a64WithSeed(next, bytes);
    return next;
}

fn hashPrincipal(hash: u64, id: principal.PrincipalId) u64 {
    var next = native_util.fnv1a64AppendByte(hash, @intFromEnum(id.kind));
    next = native_util.fnv1a64AppendU64LittleEndian(next, id.serial);
    return next;
}

fn hashEntry(hash: u64, entry: workspace.Entry) u64 {
    var next = hashBytes(hash, entry.pathSlice());
    next = native_util.fnv1a64AppendU64LittleEndian(next, entry.object_id.raw());
    next = native_util.fnv1a64AppendU64LittleEndian(next, entry.version_id.raw());
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(entry.object_type));
    return next;
}

fn hashShareGrant(hash: u64, grant: workspace.ShareGrant) u64 {
    var next = hashPrincipal(hash, grant.principal_id);
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_read));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_write));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_admin));
    next = native_util.fnv1a64AppendByte(next, @intFromBool(grant.can_export));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.network_scope));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.reshare_policy));
    next = native_util.fnv1a64AppendByte(next, @intFromEnum(grant.audit_visibility));
    next = native_util.fnv1a64AppendU64LittleEndian(next, grant.expires_at_ticks);
    next = native_util.fnv1a64AppendU64LittleEndian(next, grant.scope_object_id.raw());
    next = hashBytes(next, grant.scopePathSlice());
    return next;
}
