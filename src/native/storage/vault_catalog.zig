const std = @import("std");
const cursor = @import("binary_cursor");
const hash = @import("../core/crypto_hash.zig");
const ids = @import("../core/ids.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const secrets = @import("../platform/secure_secret_store.zig");
const sealing = @import("../platform/secret_sealing.zig");
const vault = @import("../services/secret_vault_service.zig");
const objects = @import("object_store.zig");
const storage_service = @import("storage_service.zig");
const object_signer = @import("sealed_object_signer.zig");
const identity = @import("../platform/os_identity.zig");
const graph = @import("../sync/device_graph.zig");
const graph_snapshot = @import("../sync/device_graph_snapshot.zig");

pub const CONTENT_TYPE = "application/x-zigos-vault-catalog";
const label = "Sealed vault catalog";
const magic = "ZGVault3";
const format_version: u16 = 3;
const header_bytes = 27;
pub const MAX_BYTES = header_bytes + secrets.MAX_SECRETS * (13 + secrets.MAX_LABEL_BYTES + sealing.MAX_BLOB_BYTES) + 2 + identity.MAX_SNAPSHOT_BYTES + graph_snapshot.MAX_BYTES;
const CodecError = error{ InvalidVaultCatalog, VaultCatalogTooLarge };
const Writer = cursor.Writer(CodecError, error.VaultCatalogTooLarge);
const Reader = cursor.Reader(CodecError, error.InvalidVaultCatalog);

// One authenticated checkpoint binds credential counters, revocations and key
// generations and device enrollment to the same sealed-key table.
pub const State = struct {
    vault: *vault.Service,
    identities: *identity.Store,
    devices: ?*graph.Graph = null,
};

// Supplied by trusted enrollment state, never learned from the catalog being
// opened. The generation floor must live outside a rollbackable volume if disk
// rollback protection is required. This module does not issue unlock authority.
pub const Trust = struct {
    object_id: u64,
    owner: principal.PrincipalId,
    public_key: signing.PublicKey,
    minimum_generation: u64 = 1,
    device_root_pin: ?signing.PublicKey = null,
};

pub const Receipt = struct {
    version_id: u64,
    catalog_generation: u64,
    checkpoint_generation: u64,
};

const Pending = struct {
    object_id: u64,
    base_version_id: u64,
    version_id: u64,
    catalog_generation: u64,
    payload_digest: hash.Digest,
    key_digest: hash.Digest,
};

// A failed barrier retains one immutable snapshot for an explicit retry. The
// caller serializes vault/storage access and provides bounded scratch storage.
pub const Session = struct {
    pending: ?Pending = null,

    pub fn save(self: *Session, storage: *storage_service.Service, state: State, signer: object_signer.Signer, object_id: u64, expected_version_id: u64, now_ticks: u64, scratch: *[MAX_BYTES]u8) !Receipt {
        const service = state.vault;
        try signer.validateService(storage.owner, storage.task_id, now_ticks);
        if (signer.key.authority.?.service != service) return error.InvalidSigningAuthority;
        try storage.requireDurableBoundary();
        const head = storage.latestVersion(object_id);
        var previous_key: ?signing.PublicKey = null;
        const next_generation = if (self.pending) |pending| pending.catalog_generation else blk: {
            if ((if (head) |version| version.id.raw() else @as(u64, 0)) != expected_version_id) return error.VaultCatalogChanged;
            if (head) |version| {
                if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), CONTENT_TYPE)) return error.VaultCatalogChanged;
                const old = try storage.versionPayloadInto(version, scratch);
                if (!version.metadata.verifyFor(.secret, old)) return error.UntrustedVaultCatalog;
                previous_key = version.metadata.signature.publicKeySlice()[0..signing.PUBLIC_KEY_BYTES].*;
                var reader = Reader{ .buffer = old };
                const old_header = try header(&reader, object_id);
                break :blk std.math.add(u64, old_header.generation, 1) catch return error.VaultCatalogGenerationExhausted;
            }
            break :blk @as(u64, 1);
        };
        const payload = try encode(&service.store, state.identities, state.devices, object_id, next_generation, signer.key.authority.?.owner, scratch);
        var digest: hash.Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
        if (self.pending) |pending| {
            if (object_id != pending.object_id or expected_version_id != pending.base_version_id or
                !std.mem.eql(u8, &digest, &pending.payload_digest) or
                !std.mem.eql(u8, &signer.key.sealed_digest, &pending.key_digest)) return error.PendingVaultCheckpoint;
            if (head == null or head.?.id.raw() != pending.version_id) return error.VaultCatalogChanged;
        } else {
            const metadata = try signer.signObjectMetadata(label, CONTENT_TYPE, .secret, payload, now_ticks);
            if (previous_key) |key| if (!std.mem.eql(u8, &key, metadata.signature.publicKeySlice())) return error.UntrustedVaultCatalog;
            storage.beginCheckpointBatch();
            defer storage.endCheckpointBatch();
            const stored = try storage.putVersion(.{
                .preferred_object_id = ids.object(object_id),
                .object_type = .secret,
                .payload = payload,
                .metadata = metadata,
                .parent_version_id = if (head) |version| version.id else null,
            });
            self.pending = .{
                .object_id = object_id,
                .base_version_id = expected_version_id,
                .version_id = stored.version_id.raw(),
                .catalog_generation = next_generation,
                .payload_digest = digest,
                .key_digest = signer.key.sealed_digest,
            };
        }
        const generation = try storage.checkpointDurable();
        const receipt = Receipt{ .version_id = self.pending.?.version_id, .catalog_generation = next_generation, .checkpoint_generation = generation };
        self.pending = null;
        return receipt;
    }
};

pub fn restore(storage: *const storage_service.Service, state: State, trust: Trust, scratch: *[MAX_BYTES]u8) !u64 {
    const destination = state.vault;
    // Never replace a live store or rewind its generational lease arenas.
    if (state.identities.credential_count != 0 or destination.store.secret_count != 0 or destination.handles.countInUse() != 0 or
        destination.store.handles.countInUse() != 0) return error.VaultNotEmpty;
    if (state.devices) |devices| if (!graph_snapshot.empty(devices)) return error.GraphNotEmpty;
    const version = storage.latestVersion(trust.object_id) orelse return error.VaultCatalogMissing;
    if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), CONTENT_TYPE) or
        !std.mem.eql(u8, version.metadata.labelSlice(), label) or
        !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &trust.public_key)) return error.UntrustedVaultCatalog;
    const payload = try storage.versionPayloadInto(version, scratch);
    if (!version.metadata.verifyFor(.secret, payload)) return error.UntrustedVaultCatalog;
    var reader = Reader{ .buffer = payload };
    const catalog_header = try header(&reader, trust.object_id);
    if (catalog_header.generation < trust.minimum_generation) return error.VaultCatalogRollback;
    try decode(&destination.store, state.identities, state.devices, trust.device_root_pin, trust.object_id, trust.owner, payload);
    return catalog_header.generation;
}

fn encode(store: *const secrets.Store, identities: *const identity.Store, devices: ?*const graph.Graph, object_id: u64, generation: u64, owner: principal.PrincipalId, scratch: []u8) ![]const u8 {
    if (object_id == 0 or generation == 0 or owner.serial == 0 or store.secret_count == 0 or store.secret_count > secrets.MAX_SECRETS) return error.InvalidVaultCatalog;
    var writer = Writer{ .buffer = scratch };
    try writer.writeBytes(magic);
    try writer.writeU16(format_version);
    try writer.writeU64(object_id);
    try writer.writeU64(generation);
    try writer.writeByte(store.secret_count);
    for (store.secrets[0..store.secret_count], 0..) |*secret, index| {
        if (secret.id != index + 1 or !secret.owner.eql(owner) or secret.label_len > secrets.MAX_LABEL_BYTES or
            !secret.hardware_backed or !secret.hardware_provider_used or secret.resident_material or
            !secret.sealed_digest_present) return error.InvalidVaultCatalog;
        const blob = secret.sealedBlob() orelse return error.InvalidVaultCatalog;
        try writer.writeByte(@intFromEnum(secret.owner.kind));
        try writer.writeU64(secret.owner.serial);
        try writer.writeByte(secret.label_len);
        try writer.writeBytes(secret.labelSlice());
        try writer.writeByte(@intFromBool(secret.exportable));
        try writer.writeU16(@intCast(blob.len));
        try writer.writeBytes(blob);
    }
    const size_offset = writer.offset;
    try writer.writeU16(0);
    const credentials = try identities.encodeSnapshot(owner, store, scratch[writer.offset..]);
    writer.offset += credentials.len;
    std.mem.writeInt(u16, scratch[size_offset..][0..2], @intCast(credentials.len), .little);
    const enrollment = try graph_snapshot.encode(devices, owner, scratch[writer.offset..]);
    writer.offset += enrollment.len;
    return scratch[0..writer.offset];
}

fn header(reader: *Reader, object_id: u64) !struct { count: u8, generation: u64 } {
    if (object_id == 0 or !std.mem.eql(u8, try reader.readSlice(magic.len), magic) or
        try reader.readU16() != format_version or try reader.readU64() != object_id) return error.InvalidVaultCatalog;
    const generation = try reader.readU64();
    const count = try reader.readByte();
    if (generation == 0 or count == 0 or count > secrets.MAX_SECRETS) return error.InvalidVaultCatalog;
    return .{ .count = count, .generation = generation };
}

const Record = struct {
    owner: principal.PrincipalId,
    name: []const u8,
    exportable: bool,
    blob: []const u8,
};

fn readRecord(reader: *Reader, owner: principal.PrincipalId) !Record {
    const kind = std.enums.fromInt(principal.PrincipalKind, try reader.readByte()) orelse return error.InvalidVaultCatalog;
    const record_owner = principal.PrincipalId{ .kind = kind, .serial = try reader.readU64() };
    if (owner.serial == 0 or !record_owner.eql(owner)) return error.InvalidVaultCatalog;
    const name_len = try reader.readByte();
    if (name_len > secrets.MAX_LABEL_BYTES) return error.InvalidVaultCatalog;
    const name = try reader.readSlice(name_len);
    const exportable = try reader.readByte();
    if (exportable > 1) return error.InvalidVaultCatalog;
    const blob_len = try reader.readU16();
    if (blob_len == 0 or blob_len > sealing.MAX_BLOB_BYTES) return error.InvalidVaultCatalog;
    return .{ .owner = record_owner, .name = name, .exportable = exportable == 1, .blob = try reader.readSlice(blob_len) };
}

fn decode(store: *secrets.Store, identities: *identity.Store, devices: ?*graph.Graph, root_pin: ?signing.PublicKey, object_id: u64, owner: principal.PrincipalId, payload: []const u8) !void {
    // Validate the complete canonical framing before touching the hardware.
    var reader = Reader{ .buffer = payload };
    const count = (try header(&reader, object_id)).count;
    for (0..count) |_| _ = try readRecord(&reader, owner);
    const credentials = try reader.readSlice(try reader.readU16());
    identity.validateSnapshot(owner, credentials) catch return error.InvalidVaultCatalog;
    var candidate = graph.Graph.init();
    graph_snapshot.decode(&candidate, owner, root_pin, payload[reader.offset..]) catch |err| {
        if (err == error.InvalidGraphSnapshot) return error.InvalidVaultCatalog;
        return err;
    };
    if (devices == null and !graph_snapshot.empty(&candidate)) return error.GraphDestinationRequired;
    reader.offset = header_bytes;
    // A later unseal may fail even after earlier records authenticated. Roll
    // back every unpublished slot; neither raw keys nor leases survive restore.
    errdefer {
        for (store.secrets[0..store.secret_count]) |*secret| secret.* = empty_secret;
        store.secret_count = 0;
    }
    for (0..count) |_| {
        const record = try readRecord(&reader, owner);
        _ = try store.restoreSealed(record.owner, record.name, record.blob, record.exportable);
    }
    try identities.restoreSnapshot(owner, store, credentials);
    if (devices) |destination| destination.* = candidate;
}

const empty_secret = secrets.Store.init().secrets[0];

comptime {
    if (MAX_BYTES > objects.MAX_PAYLOAD_BYTES or @sizeOf(Session) > 104)
        @compileError("vault catalog exceeds bounded checkpoint storage");
}

const durable = @import("document_save_test.zig");
const SigningFixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
const test_owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
const test_object_id: u64 = 1000;

fn prepare(fixture: *SigningFixture, storage: *storage_service.Service) !object_signer.Signer {
    return fixture.init(test_owner, storage.owner, storage.task_id, durable.signer);
}

fn testTrust() !Trust {
    return .{ .object_id = test_object_id, .owner = test_owner, .public_key = try signing.publicKey(durable.signer) };
}

test "vault catalog persists sealed IDs and restores no leases after a crash" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    const portable = [_]u8{0x27} ** secrets.MAX_VALUE_BYTES;
    _ = try fixture.service.store.importSecret(test_owner, "portable", &portable, true, true);
    var scratch: [MAX_BYTES]u8 = undefined;
    var session = Session{};
    const receipt = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 2, &scratch);
    try std.testing.expectEqual(@as(u64, 1), receipt.catalog_generation);
    try std.testing.expect(receipt.checkpoint_generation != 0);
    device.crash();
    var recovered = vault.Service.init();
    recovered.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
    try std.testing.expectEqual(@as(u64, 1), try restore(&device.service, .{ .vault = &recovered, .identities = &identities }, try testTrust(), &scratch));
    try std.testing.expectEqual(@as(u8, 2), recovered.store.secret_count);
    try std.testing.expectEqual(@as(usize, 0), recovered.handles.countInUse());
    try std.testing.expectEqual(@as(usize, 0), recovered.store.handles.countInUse());
    for (fixture.service.store.secrets[0..2], recovered.store.secrets[0..2]) |*before, *after| {
        try std.testing.expectEqual(before.id, after.id);
        try std.testing.expectEqualSlices(u8, &before.sealed_digest, &after.sealed_digest);
        try std.testing.expectEqualStrings(before.labelSlice(), after.labelSlice());
        try std.testing.expect(!after.resident_material);
    }
    const handle = try recovered.lendHandle(&fixture.policies, fixture.authority.subjects, .{ .owner = test_owner, .holder = device.service.owner, .task_id = device.service.task_id, .secret_id = 1, .expires_at_ticks = 100, .now_ticks = 3 }, null);
    const signature = try recovered.signMessage(&fixture.policies, fixture.authority.subjects, .{ .holder = handle.holder, .task_id = handle.task_id, .handle_id = handle.id, .now_ticks = 4 }, "recovered", null);
    try std.testing.expect(signing.verify(signature, "recovered"));
    try std.testing.expectEqualSlices(u8, &(try testTrust()).public_key, signature.publicKeySlice());
    try std.testing.expectError(error.VaultNotEmpty, restore(&device.service, .{ .vault = &recovered, .identities = &identities }, try testTrust(), &scratch));
}

test "vault catalog retries a failed barrier without another version and rechecks its lease" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    var scratch: [MAX_BYTES]u8 = undefined;
    var session = Session{};
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 2, &scratch));
    const count = device.service.versionCount();
    const version_id = session.pending.?.version_id;
    fixture.service.findHandle(signer.key.handle_id).?.revoked = true;
    device.fail_flushes = false;
    try std.testing.expectError(error.HandleRevoked, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 3, &scratch));
    fixture.service.findHandle(signer.key.handle_id).?.revoked = false;
    fixture.service.store.secrets[0].label[0] ^= 1;
    try std.testing.expectError(error.PendingVaultCheckpoint, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 3, &scratch));
    fixture.service.store.secrets[0].label[0] ^= 1;
    const receipt = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 3, &scratch);
    try std.testing.expectEqual(version_id, receipt.version_id);
    try std.testing.expectEqual(count, device.service.versionCount());
    try std.testing.expect(session.pending == null);
    try std.testing.expectError(error.VaultCatalogChanged, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 4, &scratch));
    const second = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, version_id, 4, &scratch);
    try std.testing.expectEqual(@as(u64, 2), second.catalog_generation);
}

test "vault catalog authenticates its trust pin owner and signed generation" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    var scratch: [MAX_BYTES]u8 = undefined;
    var session = Session{};
    const first = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 2, &scratch);
    const original = device.service.version(first.version_id).?.*;
    var saved: [MAX_BYTES]u8 = undefined;
    const old_payload = try device.service.versionPayloadInto(&original, &saved);
    const second = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, first.version_id, 3, &scratch);
    var foreign_fixture = SigningFixture{};
    const foreign_signer = try foreign_fixture.init(test_owner, device.service.owner, device.service.task_id, .{ .label = "foreign", .seed = @splat(0xee) });
    try std.testing.expectError(error.UntrustedVaultCatalog, session.save(&device.service, .{ .vault = &foreign_fixture.service, .identities = &identities }, foreign_signer, test_object_id, second.version_id, 4, &scratch));
    try std.testing.expectEqual(second.version_id, device.service.latestVersion(test_object_id).?.id.raw());
    var recovered = vault.Service.init();
    recovered.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
    var trust = try testTrust();
    trust.public_key[0] ^= 1;
    try std.testing.expectError(error.UntrustedVaultCatalog, restore(&device.service, .{ .vault = &recovered, .identities = &identities }, trust, &scratch));
    trust = try testTrust();
    trust.owner.serial += 1;
    try std.testing.expectError(error.InvalidVaultCatalog, restore(&device.service, .{ .vault = &recovered, .identities = &identities }, trust, &scratch));
    // Replaying authentic old bytes as a newer object-store version must not
    // evade the externally supplied floor on the signed catalog generation.
    _ = try device.service.putVersion(.{ .preferred_object_id = ids.object(test_object_id), .object_type = .secret, .payload = old_payload, .metadata = original.metadata, .parent_version_id = ids.version(second.version_id) });
    trust = try testTrust();
    trust.minimum_generation = 2;
    try std.testing.expectError(error.VaultCatalogRollback, restore(&device.service, .{ .vault = &recovered, .identities = &identities }, trust, &scratch));
    try std.testing.expectEqual(@as(u8, 0), recovered.store.secret_count);
}

test "vault catalog rejects incomplete framing and rolls back a later failed unseal" {
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    _ = try fixture.init(test_owner, .{ .kind = .service, .serial = 2 }, 3, durable.signer);
    _ = try fixture.service.importSecret(&fixture.policies, fixture.authority.subjects, .{ .owner = test_owner, .task_id = 3, .label = "second", .raw = "another secret", .now_ticks = 1 }, null);
    var scratch: [MAX_BYTES]u8 = undefined;
    const payload = try encode(&fixture.service.store, &identities, null, test_object_id, 1, test_owner, &scratch);
    var destination = secrets.Store.init();
    destination.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
    for (0..payload.len) |len| {
        try std.testing.expectError(error.InvalidVaultCatalog, decode(&destination, &identities, null, null, test_object_id, test_owner, payload[0..len]));
        try std.testing.expectEqual(@as(u8, 0), destination.secret_count);
    }
    const mutations = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 8, .value = 0 }, // Unknown format.
        .{ .offset = 26, .value = 0 }, // Empty catalog.
        .{ .offset = 26, .value = secrets.MAX_SECRETS + 1 },
        .{ .offset = header_bytes, .value = 255 }, // Unknown principal kind.
        .{ .offset = header_bytes + 1, .value = 2 }, // Foreign owner.
        .{ .offset = header_bytes + 9, .value = secrets.MAX_LABEL_BYTES + 1 },
        .{ .offset = header_bytes + 10 + durable.signer.label.len, .value = 2 }, // Noncanonical bool.
    };
    for (mutations) |mutation| {
        const original = scratch[mutation.offset];
        scratch[mutation.offset] = mutation.value;
        try std.testing.expectError(error.InvalidVaultCatalog, decode(&destination, &identities, null, null, test_object_id, test_owner, payload));
        try std.testing.expectEqual(@as(u8, 0), destination.secret_count);
        scratch[mutation.offset] = original;
    }
    scratch[payload.len] = 0;
    try std.testing.expectError(error.InvalidVaultCatalog, decode(&destination, &identities, null, null, test_object_id, test_owner, scratch[0 .. payload.len + 1]));
    try std.testing.expectError(error.InvalidVaultCatalog, decode(&destination, &identities, null, null, test_object_id + 1, test_owner, payload));
    scratch[payload.len - 5] ^= 1;
    try std.testing.expectError(error.InvalidSealedSecret, decode(&destination, &identities, null, null, test_object_id, test_owner, payload));
    try std.testing.expectEqual(@as(u8, 0), destination.secret_count);
    try std.testing.expectEqualDeep(empty_secret, destination.secrets[0]);
    scratch[payload.len - 5] ^= 1;
    try decode(&destination, &identities, null, null, test_object_id, test_owner, payload);
    try std.testing.expectEqual(@as(u8, 2), destination.secret_count);
}

test "vault catalog refuses non-durable saves before publishing a version" {
    const device = try durable.Fixture.init(false);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    var scratch: [MAX_BYTES]u8 = undefined;
    var session = Session{};
    const count = device.service.versionCount();
    try std.testing.expectError(error.NoBackingDevice, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 1, &scratch));
    try std.testing.expectEqual(count, device.service.versionCount());
    try std.testing.expect(session.pending == null);
}

test "vault catalog restores the previous complete catalog after an interrupted update" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    var scratch: [MAX_BYTES]u8 = undefined;
    var session = Session{};
    const first = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 1, &scratch);
    _ = try fixture.service.store.importSecret(test_owner, "uncommitted", "new key", true, false);
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, first.version_id, 2, &scratch));
    device.crash();
    var recovered = vault.Service.init();
    recovered.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
    try std.testing.expectEqual(@as(u64, 1), try restore(&device.service, .{ .vault = &recovered, .identities = &identities }, try testTrust(), &scratch));
    try std.testing.expectEqual(@as(u8, 1), recovered.store.secret_count);
    try std.testing.expect(recovered.store.describeSecret(2) == null);
}

test "vault catalog round trips the full vault with maximum envelopes across storage pages" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var identities = identity.Store.init();
    var fixture = SigningFixture{};
    const signer = try prepare(&fixture, &device.service);
    const provider = @import("../../tests/fixtures/secret_provider.zig").maximumEnvelopeProvider();
    fixture.service.attachHardwareProvider(provider);
    const value = [_]u8{0x23} ** secrets.MAX_VALUE_BYTES;
    for (1..secrets.MAX_SECRETS) |i| {
        var name = [_]u8{'k'} ** secrets.MAX_LABEL_BYTES;
        name[0] = @intCast('A' + i);
        _ = try fixture.service.store.importSecret(test_owner, &name, &value, true, false);
    }
    var scratch: [MAX_BYTES]u8 = undefined;
    try std.testing.expect((try encode(&fixture.service.store, &identities, null, test_object_id, 1, test_owner, &scratch)).len > objects.MAX_INLINE_PAYLOAD_BYTES);
    var session = Session{};
    _ = try session.save(&device.service, .{ .vault = &fixture.service, .identities = &identities }, signer, test_object_id, 0, 1, &scratch);
    device.crash();
    var recovered = vault.Service.init();
    recovered.attachHardwareProvider(provider);
    _ = try restore(&device.service, .{ .vault = &recovered, .identities = &identities }, try testTrust(), &scratch);
    try std.testing.expectEqual(secrets.MAX_SECRETS, recovered.store.secret_count);
    for (&fixture.service.store.secrets, &recovered.store.secrets) |*before, *after| {
        try std.testing.expectEqual(before.id, after.id);
        try std.testing.expectEqualSlices(u8, before.sealedBlob().?, after.sealedBlob().?);
    }
}
