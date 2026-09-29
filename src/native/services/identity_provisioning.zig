//! Trusted, serialized first-user provisioning. The caller must independently
//! retain the returned enrollment pin and random recovery key before commit.
//! Neither disk metadata nor a caller-supplied "enrolled" flag is authority.
//! This service never clears a TPM, evicts a parent, or resets the lockout counter.
const std = @import("std");
const principal = @import("../core/principal.zig");
const ids = @import("../core/ids.zig");
const tpm = @import("../platform/tpm2_sealing.zig");
const pin = @import("../platform/tpm2_pin.zig");
const wire = @import("../platform/tpm2_wire.zig");
const provider = @import("../platform/tpm2_secret_provider.zig");
const nv = @import("../platform/tpm2_vault_anchor.zig");
const policy = @import("../policy/policy_object.zig");
const catalog = @import("../storage/vault_catalog.zig");
const storage_service = @import("../storage/storage_service.zig");
const sealed = @import("sealed_signing_key.zig");
const enrollment = @import("identity_enrollment.zig");
const recovery = @import("identity_recovery.zig");
const graph_snapshot = @import("../sync/device_graph_snapshot.zig");

pub const CONTENT_TYPE = "application/x-zigos-identity-provisioning";
pub const MAX_BYTES = 8 + 8 + 2 + enrollment.MAX_BYTES + nv.RECORD_BYTES + recovery.PACKAGE_BYTES;

pub const Request = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    record_object_id: u64,
    catalog_object_id: u64,
    parent_handle: u32,
    anchor_index: u32,

    fn validate(self: Request) !void {
        if (self.owner.kind != .user or self.owner.serial == 0 or self.device.kind != .device or self.device.serial == 0 or
            self.record_object_id == 0 or self.catalog_object_id == 0 or self.record_object_id == self.catalog_object_id or
            self.parent_handle < 0x8100_0000 or self.parent_handle >= 0x8180_0000 or
            self.anchor_index < 0x0180_0000 or self.anchor_index > 0x0180_ffff) return error.InvalidProvisioningRequest;
    }
};

// A separate trusted channel must retain this pin. Reading it from the same
// object being opened would turn a signature into self-authenticated enrollment.
pub const Pin = struct { object_id: u64, digest: tpm.Key };

pub const Bundle = struct {
    object_id: u64,
    identity: enrollment.Record,
    initial_anchor: nv.Record,
    package: recovery.Package,

    fn validate(self: *const Bundle) !void {
        try self.identity.validate();
        _ = try self.initial_anchor.encode();
        const e = self.identity.enrollment;
        if (self.object_id == 0 or self.object_id == e.catalog_object_id or
            self.initial_anchor.checkpoint.object_id != e.catalog_object_id or
            !self.initial_anchor.checkpoint.owner.eql(e.owner) or self.initial_anchor.checkpoint.generation != 1 or
            self.initial_anchor.device_root_pin == null or std.mem.allEqual(u8, &self.initial_anchor.checkpoint.payload_digest, 0)) return error.InvalidProvisioningBundle;
        if (!std.mem.eql(u8, self.package.bytes[0..8], "ZGIDRC01") or
            !std.crypto.timing_safe.eql(tpm.Key, self.package.bytes[8..40].*, try self.identity.digest())) return error.RecoveryEnrollmentChanged;
    }

    pub fn encode(self: *const Bundle, out: *[MAX_BYTES]u8) ![]const u8 {
        @memset(out, 0);
        errdefer @memset(out, 0);
        try self.validate();
        var w = wire.Writer{ .bytes = out };
        try w.put("ZGIDPR01");
        try w.int(u64, self.object_id);
        var identity: [enrollment.MAX_BYTES]u8 = undefined;
        try w.sized(try self.identity.encode(&identity));
        try w.put(&(try self.initial_anchor.encode()));
        try w.put(&self.package.bytes);
        return out[0..w.pos];
    }

    pub fn trustedPin(self: *const Bundle) !Pin {
        var bytes: [MAX_BYTES]u8 = undefined;
        return .{ .object_id = self.object_id, .digest = digest(try self.encode(&bytes)) };
    }

    pub fn decode(bytes: []const u8, trusted: Pin) !Bundle {
        if (trusted.object_id == 0 or std.mem.allEqual(u8, &trusted.digest, 0) or bytes.len > MAX_BYTES or
            !std.crypto.timing_safe.eql(tpm.Key, digest(bytes), trusted.digest)) return error.UntrustedProvisioningBundle;
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGIDPR01")) return error.InvalidProvisioningBundle;
        const object_id = try r.int(u64);
        // The whole bundle has already matched an independent pin. Its capsule
        // digest may now be used to decode the embedded public enrollment.
        const identity_bytes = try r.sized();
        var identity_hash = std.crypto.hash.sha2.Sha256.init(.{});
        identity_hash.update("zigos:identity-enrollment:v1\x00");
        identity_hash.update(identity_bytes);
        const identity = try enrollment.Record.decode(identity_bytes, &identity_hash.finalResult());
        const initial_anchor = try nv.Record.decode(try r.take(nv.RECORD_BYTES));
        const package = recovery.Package{ .bytes = (try r.take(recovery.PACKAGE_BYTES))[0..recovery.PACKAGE_BYTES].* };
        try r.end();
        const result = Bundle{ .object_id = object_id, .identity = identity, .initial_anchor = initial_anchor, .package = package };
        try result.validate();
        if (object_id != trusted.object_id) return error.UntrustedProvisioningBundle;
        return result;
    }
};

// Generate only hardware-sealed keys and stage the complete candidate. No
// persistent parent, hierarchy authorization, DA policy or NV index changes.
// A failed preparation can leave inert encrypted objects, never an enrolled
// identity. The caller owns fresh object IDs and must not overwrite a candidate.
pub fn prepare(io: anytype, storage: *storage_service.Service, state: catalog.State, policies: *const policy.Directory, request: Request, value: []const u8, recovery_key: *const tpm.Key, now: u64, scratch: *[catalog.MAX_BYTES]u8) !Pin {
    try request.validate();
    try pin.validatePin(value);
    if (std.mem.allEqual(u8, recovery_key, 0)) return error.InvalidRecoveryKey;
    try storage.requireDurableBoundary();
    if (storage.latestVersion(request.record_object_id) != null or storage.latestVersion(request.catalog_object_id) != null) return error.ProvisioningAlreadyPrepared;
    const devices = state.devices orelse return error.GraphDestinationRequired;
    if (!state.vault.store.empty() or state.vault.activeHandleCount() != 0 or state.vault.store.handles.countInUse() != 0 or
        state.identities.credential_count != 0 or !graph_snapshot.empty(devices)) return error.VaultNotEmpty;
    // These private leases are consumed synchronously at this trusted tick and
    // revoked before returning; they never become a live user's session leases.
    const deadline = std.math.add(u64, now, 1) catch return error.InvalidLease;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    try client.createEnrollmentParent(io);
    const hierarchy = try client.hierarchyState(io);
    if (hierarchy.owner_auth_set or hierarchy.lockout_auth_set or hierarchy.in_lockout) return error.TpmAlreadyProvisioned;
    var secrets = recovery.Secrets{};
    defer secrets.wipe();
    try recovery.Secrets.generate(io, &secrets);
    const capsule = try pin.Capsule.enroll(&client, io, request.owner, request.device, value, &secrets.vault);
    var adapter = provider.Backend(@TypeOf(io.*)){ .client = &client, .io = io, .authorization = &secrets.vault };
    state.vault.attachHardwareProvider(adapter.provider());
    defer {
        state.vault.unload();
        state.identities.reset();
        devices.reset();
    }
    const subjects = policy.SubjectSet{ .user_id = request.owner.serial };
    var authority = sealed.Authority{ .service = state.vault, .policies = policies, .subjects = subjects, .owner = request.owner, .holder = storage.owner, .task_id = storage.task_id };
    var keys: [3]sealed.Key = undefined;
    var secret_ids: [3]u64 = undefined;
    for (&keys, &secret_ids, [_][]const u8{ "Identity catalog", "Identity root", "Device identity" }) |*key, *secret_id, label| {
        const secret = try state.vault.generateSigningKey(policies, subjects, .{ .owner = request.owner, .task_id = storage.task_id, .label = label, .now_ticks = now }, null);
        secret_id.* = secret.id;
        const handle = try state.vault.lendHandle(policies, subjects, .{ .owner = request.owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = secret.id, .now_ticks = now, .expires_at_ticks = deadline }, null);
        key.* = try sealed.Key.bind(&authority, handle.id, now);
    }
    _ = try devices.ensureSealedUserRoot(request.owner, "Local user", keys[1], now);
    _ = try devices.enrollSealedDevice(request.owner, request.device, "This device", keys[1], keys[2], now);
    // A single explicit barrier in commit covers both signed objects. Suppress
    // incidental checkpoints while their shared enrollment is being assembled.
    var checkpoint = catalog.Session{};
    const staged = try checkpoint.stage(storage, state, .{ .key = keys[0] }, request.catalog_object_id, 0, now, scratch);
    storage.beginCheckpointBatch();
    defer storage.endCheckpointBatch();
    var bundle = Bundle{ .object_id = request.record_object_id, .identity = .{ .capsule = capsule, .enrollment = .{
        .owner = request.owner,
        .device = request.device,
        .capsule_digest = try capsule.digest(),
        .parent = .{ .handle = request.parent_handle, .name = client.parent_name },
        .catalog_object_id = request.catalog_object_id,
        .anchor_index = request.anchor_index,
        .catalog_secret_id = secret_ids[0],
        .device_secret_id = secret_ids[2],
    } }, .initial_anchor = .{ .checkpoint = staged.checkpoint, .device_root_pin = try keys[1].publicKey(now) }, .package = .{} };
    try recovery.Package.seal(&bundle.identity, &secrets, recovery_key, io, &bundle.package);
    var bytes: [MAX_BYTES]u8 = undefined;
    const payload = try bundle.encode(&bytes);
    _ = try storage.putVersion(.{ .preferred_object_id = ids.object(request.record_object_id), .object_type = .secret, .payload = payload, .metadata = try (@import("../storage/sealed_object_signer.zig").Signer{ .key = keys[0] }).signObjectMetadata("Identity provisioning", CONTENT_TYPE, .secret, payload, now) });
    return bundle.trustedPin();
}

pub fn load(storage: *const storage_service.Service, trusted: Pin) !Bundle {
    const version = storage.latestVersion(trusted.object_id) orelse return error.ProvisioningMissing;
    if (version.object_type != .secret or !std.mem.eql(u8, version.metadata.contentTypeSlice(), CONTENT_TYPE)) return error.UntrustedProvisioningBundle;
    var bytes: [MAX_BYTES]u8 = undefined;
    const payload = try storage.versionPayloadInto(version, &bytes);
    const bundle = try Bundle.decode(payload, trusted);
    if (!version.metadata.verifyFor(.secret, payload) or !std.mem.eql(u8, version.metadata.signature.publicKeySlice(), &bundle.initial_anchor.checkpoint.public_key)) return error.UntrustedProvisioningBundle;
    return bundle;
}

// Explicit setup/recovery authorization, never an ordinary unlock path. Retain
// trusted and recovery_key outside the candidate's disk before invoking this.
// Retry only by invoking this operation again with those same retained values;
// live authenticated TPM state reconciles accepted commands with lost replies.
pub fn commit(io: anytype, storage: *storage_service.Service, trusted: Pin, recovery_key: *const tpm.Key, scratch: *[catalog.MAX_BYTES]u8) !enrollment.Record {
    const bundle = try load(storage, trusted);
    var secrets = recovery.Secrets{};
    defer secrets.wipe();
    try recovery.Package.open(&bundle.package.bytes, &(try bundle.identity.digest()), recovery_key, &secrets);
    _ = try catalog.inspect(storage, bundle.initial_anchor.trust(), scratch);
    _ = try storage.checkpointDurable();
    // Disk waits may yield. Recheck both complete objects after the barrier,
    // before the first permanent mutation or administrator authorization.
    _ = try load(storage, trusted);
    _ = try catalog.inspect(storage, bundle.initial_anchor.trust(), scratch);
    const e = bundle.identity.enrollment;
    var client = tpm.Client{};
    defer client.close(io) catch {};
    client.openPersistent(io, e.parent) catch |err| {
        if (err != error.PersistentParentMissing) return err;
        try client.createEnrollmentParent(io);
        if (!std.mem.eql(u8, &client.parent_name, &e.parent.name)) return error.PersistentParentChanged;
        const state = try client.hierarchyState(io);
        if (state.owner_auth_set or state.lockout_auth_set or state.in_lockout) return error.TpmAlreadyProvisioned;
        try client.persistParent(io, e.parent, null);
    };
    const state = try client.hierarchyState(io);
    if (state.in_lockout) return error.PinLockedOut;
    // No trial with an old/empty value after a failed command. A replay after
    // a lost reply authenticates with the retained NEW value when the flag is set.
    try client.changeOwnerAuthorization(io, if (state.owner_auth_set) &secrets.owner else null, &secrets.owner);
    try client.changeLockoutAuthorization(io, if (state.lockout_auth_set) &secrets.lockout else null, &secrets.lockout);
    try client.configureDictionaryAttack(io, &secrets.lockout, pin.DEFAULT_POLICY);
    _ = try catalog.inspect(storage, bundle.initial_anchor.trust(), scratch);
    const space = try bundle.initial_anchor.enrollmentSpace(e.anchor_index);
    const expected = try bundle.initial_anchor.encode();
    var actual: [nv.RECORD_BYTES]u8 = undefined;
    client.nvRead(io, space, &secrets.vault, &actual) catch |err| {
        if (err == error.NvIndexMissing) {
            try client.nvDefine(io, space, &secrets.vault, &secrets.owner);
        } else if (err != error.NvUninitialized) return err;
        try client.nvInitialize(io, space, &secrets.vault, &expected);
        // An authenticated read also verifies the completed first write.
        try client.nvRead(io, space, &secrets.vault, &actual);
    };
    if (!std.mem.eql(u8, &actual, &expected)) return error.VaultAnchorChanged;
    return bundle.identity;
}

fn digest(bytes: []const u8) tpm.Key {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zigos:identity-provisioning:v1\x00");
    h.update(bytes);
    return h.finalResult();
}

test "identity provisioning requires an independent pin over every bundle byte" {
    const identity = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    var bundle = Bundle{ .object_id = 1001, .identity = identity, .initial_anchor = .{
        .checkpoint = .{ .object_id = identity.enrollment.catalog_object_id, .owner = identity.enrollment.owner, .public_key = @splat(6), .generation = 1, .payload_digest = @splat(7) },
        .device_root_pin = @splat(8),
    }, .package = .{} };
    const Entropy = struct {
        pub fn random(_: *@This(), out: []u8) !void {
            @memset(out, 9);
        }
    };
    var entropy = Entropy{};
    const secrets = recovery.Secrets{ .owner = @splat(1), .lockout = @splat(2), .vault = @splat(3) };
    const key: tpm.Key = @splat(4);
    try recovery.Package.seal(&identity, &secrets, &key, &entropy, &bundle.package);
    var bytes: [MAX_BYTES]u8 = undefined;
    const encoded = try bundle.encode(&bytes);
    const trusted = try bundle.trustedPin();
    try std.testing.expectEqualDeep(bundle, try Bundle.decode(encoded, trusted));
    for (0..encoded.len) |i| {
        bytes[i] ^= 1;
        try std.testing.expectError(error.UntrustedProvisioningBundle, Bundle.decode(encoded, trusted));
        bytes[i] ^= 1;
    }
    for (0..encoded.len) |length| {
        if (Bundle.decode(encoded[0..length], trusted)) |_| return error.AcceptedTruncatedBundle else |_| {}
    }
    try std.testing.expectError(error.UntrustedProvisioningBundle, Bundle.decode(encoded, .{ .object_id = trusted.object_id + 1, .digest = trusted.digest }));
    try std.testing.expectError(error.InvalidResponse, Bundle.decode(bytes[0 .. encoded.len + 1], .{ .object_id = trusted.object_id, .digest = digest(bytes[0 .. encoded.len + 1]) }));
    // Even an authenticated outer record must have canonical internal bindings.
    bundle.initial_anchor.checkpoint.generation = 2;
    try std.testing.expectError(error.InvalidProvisioningBundle, bundle.encode(&bytes));
    try std.testing.expect(std.mem.allEqual(u8, &bytes, 0));
    bundle.initial_anchor.checkpoint.generation = 1;
    bundle.package.bytes[8] ^= 1;
    try std.testing.expectError(error.RecoveryEnrollmentChanged, bundle.trustedPin());
}

test "identity provisioning rejects untrusted inputs and failed durability before TPM access" {
    const durable = @import("../storage/document_save_test.zig");
    const objects = @import("../storage/object_store.zig");
    const vault = @import("secret_vault_service.zig");
    const identity_mod = @import("../platform/os_identity.zig");
    const graph_mod = @import("../sync/device_graph.zig");
    const RejectIo = struct {
        calls: usize = 0,
        pub fn random(self: *@This(), _: []u8) !void {
            self.calls += 1;
            return error.UnexpectedHardwareAccess;
        }
        pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            self.calls += 1;
            return error.UnexpectedHardwareAccess;
        }
    };
    var io = RejectIo{};
    const disk = try durable.Fixture.init(true);
    defer disk.deinit();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var service = vault.Service.init();
    var identities = identity_mod.Store.init();
    var graph = graph_mod.Graph.init();
    const state = catalog.State{ .vault = &service, .identities = &identities, .devices = &graph };
    var policies = policy.Directory.init();
    const request = Request{ .owner = .{ .kind = .user, .serial = 1 }, .device = .{ .kind = .device, .serial = 2 }, .record_object_id = 1001, .catalog_object_id = 1000, .parent_handle = 0x8100_1234, .anchor_index = 0x0180_1234 };
    const key: tpm.Key = @splat(4);
    var bad = request;
    bad.record_object_id = bad.catalog_object_id;
    try std.testing.expectError(error.InvalidProvisioningRequest, prepare(&io, &disk.service, state, &policies, bad, "123456", &key, 1, &scratch));
    try std.testing.expectError(error.InvalidPin, prepare(&io, &disk.service, state, &policies, request, "123x56", &key, 1, &scratch));
    const zero: tpm.Key = @splat(0);
    try std.testing.expectError(error.InvalidRecoveryKey, prepare(&io, &disk.service, state, &policies, request, "123456", &zero, 1, &scratch));
    var signer_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const signer = try signer_fixture.init(request.owner, disk.service.owner, disk.service.task_id, durable.signer);
    var checkpoint = catalog.Session{};
    const staged = try checkpoint.stage(&disk.service, .{ .vault = &signer_fixture.service, .identities = &identities }, signer, request.catalog_object_id, 0, 1, &scratch);
    var identity = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    identity.enrollment.owner = request.owner;
    identity.capsule.owner = request.owner;
    identity.enrollment.capsule_digest = try identity.capsule.digest();
    var bundle = Bundle{ .object_id = request.record_object_id, .identity = identity, .initial_anchor = .{ .checkpoint = staged.checkpoint, .device_root_pin = @splat(8) }, .package = .{} };
    const Entropy = struct {
        pub fn random(_: *@This(), out: []u8) !void {
            @memset(out, 9);
        }
    };
    var entropy = Entropy{};
    const secrets = recovery.Secrets{ .owner = @splat(1), .lockout = @splat(2), .vault = @splat(3) };
    try recovery.Package.seal(&identity, &secrets, &key, &entropy, &bundle.package);
    var bytes: [MAX_BYTES]u8 = undefined;
    const payload = try bundle.encode(&bytes);
    const trusted = try bundle.trustedPin();
    disk.service.beginCheckpointBatch();
    _ = try disk.service.putVersion(.{ .preferred_object_id = ids.object(request.record_object_id), .object_type = .secret, .payload = payload, .metadata = try objects.signMetadata(durable.signer, "Identity provisioning", CONTENT_TYPE, .secret, payload, 1) });
    disk.service.endCheckpointBatch();
    var wrong = trusted;
    wrong.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedProvisioningBundle, commit(&io, &disk.service, wrong, &key, &scratch));
    const wrong_key: tpm.Key = @splat(5);
    try std.testing.expectError(error.RecoveryAuthenticationFailed, commit(&io, &disk.service, trusted, &wrong_key, &scratch));
    try std.testing.expectError(error.ProvisioningAlreadyPrepared, prepare(&io, &disk.service, state, &policies, request, "123456", &key, 1, &scratch));
    disk.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, commit(&io, &disk.service, trusted, &key, &scratch));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
    disk.fail_flushes = false;
    // A complete durable checkpoint survives a restart without requiring RAM
    // enrollment state or changing the independently held pin.
    _ = try disk.service.checkpointDurable();
    disk.crash();
    try std.testing.expectEqualDeep(bundle, try load(&disk.service, trusted));
    disk.service.store.latestVersion(request.catalog_object_id).?.metadata.signature.value[0] ^= 1;
    try std.testing.expectError(error.UntrustedVaultCatalog, commit(&io, &disk.service, trusted, &key, &scratch));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
}
