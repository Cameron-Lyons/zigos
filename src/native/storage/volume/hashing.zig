const std = @import("std");
const principal = @import("../../core/principal.zig");
const workspace = @import("../workspace.zig");
pub const checksumBytes = @import("checksum.zig").checksumBytes;

/// Change detector for a persisted workspace summary: seed-zero XXH64 over
/// every persisted field, framed so adjacent fields cannot alias.
pub fn workspaceStateHash(record: *const workspace.WorkspaceRecord) u64 {
    var hasher = StateHasher{};
    hasher.bytes("workspace-state");
    hasher.int(u64, record.id.raw());
    hasher.principalId(record.owner);
    hasher.bytes(record.labelSlice());
    hasher.int(u32, record.generation);
    hasher.int(u16, @intCast(record.counts.entry_count));
    hasher.bytes(&record.path_index.root_address);

    hasher.int(u16, @intCast(record.counts.entry_mutation_count));
    for (record.mutation_log.entriesConst()[0..record.counts.entry_mutation_count]) |mutation| {
        hasher.int(u32, mutation.generation);
        hasher.entry(mutation.entry);
    }

    hasher.int(u16, @intCast(record.counts.share_grant_count));
    if (record.counts.share_grant_count != 0) {
        const share_table = record.share_table.dataConst();
        for (share_table.share_grants[0..record.counts.share_grant_count]) |grant| {
            hasher.shareGrant(grant);
        }
    }

    hasher.int(u16, @intCast(record.counts.deleted_count));
    for (record.recoverable_deletes.entriesConst(record.counts.deleted_count)) |deleted| {
        hasher.entry(deleted);
    }
    return hasher.state.final();
}

const StateHasher = struct {
    state: std.hash.XxHash64 = .init(0),

    fn int(self: *StateHasher, comptime T: type, value: T) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        self.state.update(&encoded);
    }

    fn bytes(self: *StateHasher, value: []const u8) void {
        self.int(u32, @intCast(value.len));
        self.state.update(value);
    }

    fn principalId(self: *StateHasher, id: principal.PrincipalId) void {
        self.int(u8, @backingInt(id.kind));
        self.int(u64, id.serial);
    }

    fn entry(self: *StateHasher, value: workspace.Entry) void {
        self.bytes(value.pathSlice());
        self.int(u64, value.object_id.raw());
        self.int(u64, value.version_id.raw());
        self.int(u8, @backingInt(value.object_type));
    }

    fn shareGrant(self: *StateHasher, grant: workspace.ShareGrant) void {
        self.principalId(grant.principal_id);
        self.int(u8, @intFromBool(grant.can_read));
        self.int(u8, @intFromBool(grant.can_write));
        self.int(u8, @intFromBool(grant.can_admin));
        self.int(u8, @intFromBool(grant.can_export));
        self.int(u8, @backingInt(grant.network_scope));
        self.int(u8, @backingInt(grant.reshare_policy));
        self.int(u8, @backingInt(grant.audit_visibility));
        self.int(u64, grant.expires_at_ticks);
        self.int(u64, grant.scope_object_id.raw());
        self.bytes(grant.scopePathSlice());
    }
};
