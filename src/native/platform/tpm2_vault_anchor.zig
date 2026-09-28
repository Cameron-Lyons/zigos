const std = @import("std");
const tpm = @import("tpm2_sealing.zig");
const catalog = @import("../storage/vault_catalog.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const RECORD_BYTES = 136;

// Ordinary authenticated TPM NV, not a TPM monotonic counter. The caller owns
// the index authorization independently of the disk and serializes all writes.
// Clearing/replacing the TPM or losing authorization requires explicit recovery.
pub const Record = struct {
    checkpoint: catalog.Checkpoint,
    device_root_pin: ?signing.PublicKey = null,

    pub fn trust(self: Record) catalog.Trust {
        return .{ .object_id = self.checkpoint.object_id, .owner = self.checkpoint.owner, .public_key = self.checkpoint.public_key, .minimum_generation = self.checkpoint.generation, .device_root_pin = self.device_root_pin, .payload_digest = self.checkpoint.payload_digest };
    }

    pub fn encode(self: Record) ![RECORD_BYTES]u8 {
        if (self.checkpoint.object_id == 0 or self.checkpoint.owner.serial == 0 or self.checkpoint.generation == 0 or
            std.mem.allEqual(u8, &self.checkpoint.public_key, 0)) return error.InvalidVaultAnchor;
        var bytes: [RECORD_BYTES]u8 = @splat(0);
        @memcpy(bytes[0..8], "ZGVAnch1");
        std.mem.writeInt(u64, bytes[8..16], self.checkpoint.object_id, .little);
        std.mem.writeInt(u64, bytes[16..24], self.checkpoint.owner.serial, .little);
        std.mem.writeInt(u64, bytes[24..32], self.checkpoint.generation, .little);
        bytes[32] = @intFromEnum(self.checkpoint.owner.kind);
        bytes[33] = @intFromBool(self.device_root_pin != null);
        @memcpy(bytes[40..72], &self.checkpoint.public_key);
        if (self.device_root_pin) |pin| {
            if (std.mem.allEqual(u8, &pin, 0)) return error.InvalidVaultAnchor;
            @memcpy(bytes[72..104], &pin);
        }
        @memcpy(bytes[104..136], &self.checkpoint.payload_digest);
        return bytes;
    }

    pub fn decode(bytes: []const u8) !Record {
        if (bytes.len != RECORD_BYTES or !std.mem.eql(u8, bytes[0..8], "ZGVAnch1") or
            bytes[33] > 1 or !std.mem.allEqual(u8, bytes[34..40], 0) or
            (bytes[33] == 0 and !std.mem.allEqual(u8, bytes[72..104], 0))) return error.InvalidVaultAnchor;
        const record = Record{ .checkpoint = .{
            .object_id = std.mem.readInt(u64, bytes[8..16], .little),
            .owner = .{ .kind = std.enums.fromInt(principal.PrincipalKind, bytes[32]) orelse return error.InvalidVaultAnchor, .serial = std.mem.readInt(u64, bytes[16..24], .little) },
            .generation = std.mem.readInt(u64, bytes[24..32], .little),
            .public_key = bytes[40..72].*,
            .payload_digest = bytes[104..136].*,
        }, .device_root_pin = if (bytes[33] == 1) bytes[72..104].* else null };
        _ = try record.encode();
        return record;
    }

    fn successor(self: Record, checkpoint: catalog.Checkpoint) !Record {
        if (checkpoint.object_id != self.checkpoint.object_id or !checkpoint.owner.eql(self.checkpoint.owner) or
            !std.mem.eql(u8, &checkpoint.public_key, &self.checkpoint.public_key)) return error.VaultAnchorBindingChanged;
        if (checkpoint.generation == self.checkpoint.generation) {
            if (!std.mem.eql(u8, &checkpoint.payload_digest, &self.checkpoint.payload_digest)) return error.VaultCatalogAnchorMismatch;
        } else if (checkpoint.generation != (std.math.add(u64, self.checkpoint.generation, 1) catch return error.VaultCatalogGenerationExhausted)) return error.VaultCatalogRollback;
        const next = Record{ .checkpoint = checkpoint, .device_root_pin = self.device_root_pin };
        _ = try next.encode();
        return next;
    }
};

pub fn Backend(comptime Io: type) type {
    return struct {
        const Self = @This();
        client: *tpm.Client,
        io: *Io,
        authorization: *const tpm.Key,
        index: u32,
        current: Record,

        fn space(self: *const Self) tpm.NvSpace {
            return .{ .index = self.index, .size = RECORD_BYTES };
        }

        pub fn read(client: *tpm.Client, io: *Io, authorization: *const tpm.Key, index: u32) !Record {
            var bytes: [RECORD_BYTES]u8 = undefined;
            defer std.crypto.secureZero(u8, &bytes);
            try client.nvRead(io, .{ .index = index, .size = RECORD_BYTES }, authorization, &bytes);
            return Record.decode(&bytes);
        }

        // Explicit first enrollment, only after a durable catalog checkpoint.
        // Failure may leave a defined/unwritten index; never overwrite it here.
        pub fn provision(self: *Self) !void {
            var bytes = try self.current.encode();
            defer std.crypto.secureZero(u8, &bytes);
            try self.client.nvDefine(self.io, self.space(), self.authorization);
            try self.client.nvWrite(self.io, self.space(), self.authorization, &bytes);
        }

        // Keep this backend and the returned interface at stable addresses
        // while attached to catalog.Session. No shared or concurrent writers.
        pub fn interface(self: *Self) catalog.Anchor {
            return .{ .context = self, .advance_fn = advance };
        }

        fn advance(context: *anyopaque, checkpoint: catalog.Checkpoint) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            const next = try self.current.successor(checkpoint);
            const actual = try read(self.client, self.io, self.authorization, self.index);
            const expected_bytes = try self.current.encode();
            const actual_bytes = try actual.encode();
            const next_bytes = try next.encode();
            // Reconcile an authenticated write whose response was lost, using
            // a fresh initialized client after any transport/protocol failure.
            if (!std.mem.eql(u8, &actual_bytes, &next_bytes)) {
                if (!std.mem.eql(u8, &actual_bytes, &expected_bytes)) return error.VaultAnchorChanged;
                try self.client.nvWrite(self.io, self.space(), self.authorization, &next_bytes);
            }
            self.current = next;
        }
    };
}

test "TPM vault anchor codec rejects malformed records and binds freshness to exact payload" {
    const initial = Record{ .checkpoint = .{ .object_id = 12, .owner = .{ .kind = .user, .serial = 3 }, .public_key = @splat(4), .generation = 7, .payload_digest = @splat(5) }, .device_root_pin = @splat(6) };
    const bytes = try initial.encode();
    try std.testing.expectEqualDeep(initial, try Record.decode(&bytes));
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidVaultAnchor, Record.decode(bytes[0..len]));
    for ([_]usize{ 0, 32, 33, 34, 39 }) |offset| {
        var changed = bytes;
        changed[offset] = 0xff;
        try std.testing.expectError(error.InvalidVaultAnchor, Record.decode(&changed));
    }
    var changed = initial.checkpoint;
    changed.generation = 6;
    try std.testing.expectError(error.VaultCatalogRollback, initial.successor(changed));
    changed.generation = 9;
    try std.testing.expectError(error.VaultCatalogRollback, initial.successor(changed));
    changed = initial.checkpoint;
    changed.payload_digest[0] ^= 1;
    try std.testing.expectError(error.VaultCatalogAnchorMismatch, initial.successor(changed));
    changed.generation += 1;
    const next = try initial.successor(changed);
    try std.testing.expectEqualDeep(initial.device_root_pin, next.device_root_pin);
    changed.public_key[0] ^= 1;
    try std.testing.expectError(error.VaultAnchorBindingChanged, initial.successor(changed));
}
