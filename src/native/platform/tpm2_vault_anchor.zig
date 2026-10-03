const std = @import("std");
const tpm = @import("tpm2_sealing.zig");
const catalog = @import("../storage/vault_catalog.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const hash = @import("../core/crypto_hash.zig");
const storage_service = @import("../storage/storage_service.zig");

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
        bytes[32] = @backingInt(self.checkpoint.owner.kind);
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

    pub fn enrollmentSpace(self: Record, index: u32) !tpm.NvSpace {
        const bytes = try self.encode();
        var index_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &index_bytes, index, .big);
        var digest = std.crypto.hash.sha2.Sha256.init(.{});
        digest.update("zigos:tpm-vault-enrollment:v1\x00");
        digest.update(&index_bytes);
        digest.update(&bytes);
        return .{ .index = index, .size = RECORD_BYTES, .binding = .{ .pinned = digest.finalResult() } };
    }

    fn successor(self: Record, checkpoint: catalog.Checkpoint, previous_digest: hash.Digest) !Record {
        if (checkpoint.object_id != self.checkpoint.object_id or !checkpoint.owner.eql(self.checkpoint.owner) or
            !std.mem.eql(u8, &checkpoint.public_key, &self.checkpoint.public_key)) return error.VaultAnchorBindingChanged;
        if (checkpoint.generation == self.checkpoint.generation) {
            if (!std.mem.eql(u8, &checkpoint.payload_digest, &self.checkpoint.payload_digest)) return error.VaultCatalogAnchorMismatch;
        } else {
            if (checkpoint.generation != (std.math.add(u64, self.checkpoint.generation, 1) catch return error.VaultCatalogGenerationExhausted)) return error.VaultCatalogRollback;
            if (!std.mem.eql(u8, &previous_digest, &self.checkpoint.payload_digest)) return error.VaultCatalogAnchorMismatch;
        }
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
            return .{ .index = self.index, .size = RECORD_BYTES, .binding = .discover };
        }

        pub fn read(client: *tpm.Client, io: *Io, authorization: *const tpm.Key, index: u32) !Record {
            var bytes: [RECORD_BYTES]u8 = undefined;
            defer std.crypto.secureZero(u8, &bytes);
            try client.nvRead(io, .{ .index = index, .size = RECORD_BYTES, .binding = .discover }, authorization, &bytes);
            return Record.decode(&bytes);
        }

        // Explicit first enrollment. Commit the exact catalog before defining
        // the immutable NV enrollment commitment. Existing indexes are refused.
        pub fn provision(self: *Self, storage: *const storage_service.Service, scratch: *[catalog.MAX_BYTES]u8, owner_auth: ?*const tpm.Key) !void {
            var bytes = try self.current.encode();
            defer std.crypto.secureZero(u8, &bytes);
            const candidate = try enrollmentCandidate(storage, self.current.checkpoint.object_id, self.current.checkpoint.owner, scratch);
            if (!std.mem.eql(u8, &bytes, &(try candidate.encode()))) return error.VaultAnchorBindingChanged;
            _ = try storage.checkpointDurable();
            const enrollment_space = try self.current.enrollmentSpace(self.index);
            try self.client.nvDefine(self.io, enrollment_space, self.authorization, owner_auth);
            try self.client.nvInitialize(self.io, enrollment_space, self.authorization, &bytes);
        }

        // Resume only a definition already committed by explicit enrollment.
        // NV_ReadPublic is unauthenticated: its claims become authority only
        // when the HMAC read/write succeeds with that exact committed Name.
        // A missing index is never redefined, and a later anchor is never reset.
        pub fn resumeProvision(client: *tpm.Client, io: *Io, authorization: *const tpm.Key, index: u32, storage: *const storage_service.Service, object_id: u64, owner: principal.PrincipalId, scratch: *[catalog.MAX_BYTES]u8) !Record {
            const candidate = try enrollmentCandidate(storage, object_id, owner, scratch);
            const enrollment_space = try candidate.enrollmentSpace(index);
            var expected = try candidate.encode();
            defer std.crypto.secureZero(u8, &expected);
            _ = try storage.checkpointDurable();
            var actual: [RECORD_BYTES]u8 = undefined;
            defer std.crypto.secureZero(u8, &actual);
            client.nvRead(io, enrollment_space, authorization, &actual) catch |err| {
                if (err != error.NvUninitialized) return err;
                // Recheck WRITTEN inside the same Name-bound HMAC operation;
                // never trust an earlier public-area reply to permit a write.
                try client.nvInitialize(io, enrollment_space, authorization, &expected);
                return candidate;
            };
            if (!std.mem.eql(u8, &actual, &expected)) return error.VaultAnchorChanged;
            return candidate;
        }

        // Keep this backend and the returned interface at stable addresses
        // while attached to catalog.Session. No shared or concurrent writers.
        pub fn interface(self: *Self) catalog.Anchor {
            return .{ .context = self, .advance_fn = advance };
        }

        // Start with a freshly read authenticated record. A reboot may leave
        // exactly one durable signed successor ahead of NV. Authenticate its
        // predecessor link, confirm disk durability, and finish the same update
        // before the caller restores any secrets or publishes identity state.
        pub fn recover(self: *Self, storage: *const storage_service.Service, scratch: *[catalog.MAX_BYTES]u8) !void {
            _ = catalog.inspect(storage, self.current.trust(), scratch) catch |err| {
                if (err != error.VaultCatalogAnchorMismatch) return err;
                const checkpoint = try catalog.inspectSuccessor(storage, self.current.trust(), scratch);
                _ = try storage.checkpointDurable();
                try advance(self, checkpoint, self.current.checkpoint.payload_digest);
                return;
            };
        }

        fn advance(context: *anyopaque, checkpoint: catalog.Checkpoint, previous_digest: hash.Digest) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            const next = try self.current.successor(checkpoint, previous_digest);
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

fn enrollmentCandidate(storage: *const storage_service.Service, object_id: u64, owner: principal.PrincipalId, scratch: *[catalog.MAX_BYTES]u8) !Record {
    const candidate = try catalog.inspectEnrollment(storage, object_id, owner, scratch);
    return .{ .checkpoint = candidate.checkpoint, .device_root_pin = candidate.device_root_pin };
}

test "TPM vault anchor codec rejects malformed records and binds freshness to exact payload" {
    const initial = Record{ .checkpoint = .{ .object_id = 12, .owner = .{ .kind = .user, .serial = 3 }, .public_key = @splat(4), .generation = 7, .payload_digest = @splat(5) }, .device_root_pin = @splat(6) };
    const bytes = try initial.encode();
    const commitment = (try initial.enrollmentSpace(0x0180_1234)).binding.pinned;
    try std.testing.expect(!std.mem.eql(u8, &commitment, &(try initial.enrollmentSpace(0x0180_1235)).binding.pinned));
    for ([_]usize{ 8, 16, 24, 40, 72, 104, 135 }) |offset| {
        var altered = bytes;
        altered[offset] ^= 1;
        const other = try Record.decode(&altered);
        try std.testing.expect(!std.mem.eql(u8, &commitment, &(try other.enrollmentSpace(0x0180_1234)).binding.pinned));
    }
    try std.testing.expectEqualDeep(initial, try Record.decode(&bytes));
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidVaultAnchor, Record.decode(bytes[0..len]));
    for ([_]usize{ 0, 32, 33, 34, 39 }) |offset| {
        var changed = bytes;
        changed[offset] = 0xff;
        try std.testing.expectError(error.InvalidVaultAnchor, Record.decode(&changed));
    }
    var changed = initial.checkpoint;
    changed.generation = 6;
    try std.testing.expectError(error.VaultCatalogRollback, initial.successor(changed, initial.checkpoint.payload_digest));
    changed.generation = 9;
    try std.testing.expectError(error.VaultCatalogRollback, initial.successor(changed, initial.checkpoint.payload_digest));
    changed = initial.checkpoint;
    changed.payload_digest[0] ^= 1;
    try std.testing.expectError(error.VaultCatalogAnchorMismatch, initial.successor(changed, initial.checkpoint.payload_digest));
    changed.generation += 1;
    try std.testing.expectError(error.VaultCatalogAnchorMismatch, initial.successor(changed, @splat(0xee)));
    const next = try initial.successor(changed, initial.checkpoint.payload_digest);
    try std.testing.expectEqualDeep(initial.device_root_pin, next.device_root_pin);
    changed.public_key[0] ^= 1;
    try std.testing.expectError(error.VaultAnchorBindingChanged, initial.successor(changed, initial.checkpoint.payload_digest));
}

test "TPM first enrollment validates its entire candidate and disk barrier before hardware" {
    const durable = @import("../storage/document_save_test.zig");
    const SigningFixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
    const identity = @import("os_identity.zig");
    const Io = struct {
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedHardwareAccess;
        }
        pub fn execute(_: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            return error.UnexpectedHardwareAccess;
        }
    };
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    var fixture = SigningFixture{};
    const signer = try fixture.init(owner, device.service.owner, device.service.task_id, durable.signer);
    var identities = identity.Store.init();
    const state = catalog.State{ .vault = &fixture.service, .identities = &identities };
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var session = catalog.Session{};
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, session.save(&device.service, state, signer, 1000, 0, 2, &scratch));
    const candidate = try enrollmentCandidate(&device.service, 1000, owner, &scratch);
    var client = tpm.Client{};
    var io = Io{};
    const auth: tpm.Key = @splat(1);
    const Anchor = Backend(Io);
    var backend = Anchor{ .client = &client, .io = &io, .authorization = &auth, .index = 0x0180_1234, .current = candidate };
    backend.current.device_root_pin = @splat(7);
    try std.testing.expectError(error.VaultAnchorBindingChanged, backend.provision(&device.service, &scratch, null));
    backend.current = candidate;
    backend.current.checkpoint.owner.serial += 1;
    try std.testing.expectError(error.InvalidVaultCatalog, backend.provision(&device.service, &scratch, null));
    backend.current = candidate;
    backend.current.checkpoint.payload_digest[0] ^= 1;
    try std.testing.expectError(error.VaultAnchorBindingChanged, backend.provision(&device.service, &scratch, null));
    backend.current = candidate;
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, backend.provision(&device.service, &scratch, null));
    try std.testing.expectError(error.DurabilityBarrierFailed, Anchor.resumeProvision(&client, &io, &auth, backend.index, &device.service, 1000, owner, &scratch));
    device.fail_flushes = false;
    try std.testing.expectError(error.NotInitialized, backend.provision(&device.service, &scratch, null));
    try std.testing.expectError(error.NotInitialized, Anchor.resumeProvision(&client, &io, &auth, backend.index, &device.service, 1000, owner, &scratch));
    try std.testing.expectEqualDeep(candidate, backend.current);
    device.crash();
    try std.testing.expectEqualDeep(candidate, try enrollmentCandidate(&device.service, 1000, owner, &scratch));
}

test "TPM vault recovery requires durable disk state and retains its pin when hardware fails" {
    const durable = @import("../storage/document_save_test.zig");
    const SigningFixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
    const identity = @import("os_identity.zig");
    const Io = struct {
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedHardwareAccess;
        }
        pub fn execute(_: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            return error.UnexpectedHardwareAccess;
        }
    };
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    var fixture = SigningFixture{};
    const signer = try fixture.init(owner, device.service.owner, device.service.task_id, durable.signer);
    var identities = identity.Store.init();
    const state = catalog.State{ .vault = &fixture.service, .identities = &identities };
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var session = catalog.Session{};
    const first = try session.save(&device.service, state, signer, 1000, 0, 2, &scratch);
    const checkpoint = try catalog.inspect(&device.service, .{ .object_id = 1000, .owner = owner, .public_key = try signing.publicKey(durable.signer) }, &scratch);
    var client = tpm.Client{};
    var io = Io{};
    const auth: tpm.Key = @splat(1);
    var backend = Backend(Io){ .client = &client, .io = &io, .authorization = &auth, .index = 0x0180_1234, .current = .{ .checkpoint = checkpoint } };
    // An exact pinned head needs no NV update, even after reboot.
    device.crash();
    try backend.recover(&device.service, &scratch);
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, session.save(&device.service, state, signer, 1000, first.version_id, 3, &scratch));
    try std.testing.expectError(error.DurabilityBarrierFailed, backend.recover(&device.service, &scratch));
    try std.testing.expectEqualDeep(checkpoint, backend.current.checkpoint);
    device.fail_flushes = false;
    // The disk can now commit, but unavailable TPM state must withhold the pin.
    try std.testing.expectError(error.NotInitialized, backend.recover(&device.service, &scratch));
    try std.testing.expectEqualDeep(checkpoint, backend.current.checkpoint);
    device.crash();
    try std.testing.expectEqual(@as(u64, 2), (try catalog.inspectSuccessor(&device.service, backend.current.trust(), &scratch)).generation);
}
