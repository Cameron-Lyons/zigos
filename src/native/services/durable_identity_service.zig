const identity = @import("../platform/os_identity.zig");
const graph = @import("../sync/device_graph.zig");
const principal = @import("../core/principal.zig");
const catalog = @import("../storage/vault_catalog.zig");
const storage_service = @import("../storage/storage_service.zig");
const object_signer = @import("../storage/sealed_object_signer.zig");
const sealed = @import("sealed_signing_key.zig");
const enrollment = @import("../sync/device_enrollment.zig");

// Trusted native service boundary. All borrowed state stays at stable addresses
// and operations are serialized. A failed checkpoint withholds the result and
// blocks further mutations until an explicit flush succeeds. Unlock evidence
// and identity request dispatch remain the caller's responsibility.
pub const Service = struct {
    state: catalog.State,
    storage: *storage_service.Service,
    signer: object_signer.Signer,
    object_id: u64,
    version_id: u64 = 0,
    checkpoint: catalog.Session = .{},
    dirty: bool = false,

    pub fn flush(self: *Service, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !catalog.Receipt {
        self.dirty = true;
        const receipt = try self.checkpoint.save(self.storage, self.state, self.signer, self.object_id, self.version_id, now_ticks, scratch);
        self.version_id = receipt.version_id;
        self.dirty = false;
        return receipt;
    }

    pub fn registerCredential(self: *Service, devices: *const graph.Graph, authority: identity.VaultAuthority, request: identity.RegisterCredentialRequest, scratch: *[catalog.MAX_BYTES]u8) !*const identity.CredentialRecord {
        try self.requireAuthority(authority);
        try self.requireReady(request.owner, authority.now_ticks);
        const credential = try self.state.identities.registerCredential(devices, authority, request);
        _ = try self.flush(authority.now_ticks, scratch);
        return credential;
    }

    pub fn assertCredential(self: *Service, devices: *const graph.Graph, authority: identity.VaultAuthority, request: identity.AssertionRequest, scratch: *[catalog.MAX_BYTES]u8) !identity.Assertion {
        try self.requireAuthority(authority);
        const credential = self.state.identities.findCredentialConst(request.credential_id) orelse return error.CredentialNotFound;
        try self.requireReady(credential.owner, authority.now_ticks);
        const assertion = try self.state.identities.assertCredential(devices, authority, request);
        // The signature never leaves this call unless its counter is durable.
        _ = try self.flush(authority.now_ticks, scratch);
        return assertion;
    }

    pub fn recoverCredential(self: *Service, devices: *const graph.Graph, authority: identity.VaultAuthority, request: identity.RecoveryRequest, scratch: *[catalog.MAX_BYTES]u8) !*const identity.CredentialRecord {
        try self.requireAuthority(authority);
        const old = self.state.identities.findCredentialConst(request.credential_id) orelse return error.CredentialNotFound;
        try self.requireReady(old.owner, authority.now_ticks);
        const credential = try self.state.identities.recoverCredential(devices, authority, request);
        _ = try self.flush(authority.now_ticks, scratch);
        return credential;
    }

    pub fn revokeCredential(self: *Service, credential_id: u64, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        const credential = self.state.identities.findCredentialConst(credential_id) orelse return error.CredentialNotFound;
        try self.requireReady(credential.owner, now_ticks);
        try self.state.identities.revokeCredential(credential_id, now_ticks);
        _ = try self.flush(now_ticks, scratch);
    }

    pub fn deviceGraph(self: *const Service, now_ticks: u64) !*const graph.Graph {
        const owner = self.signer.key.authority orelse return error.InvalidIdentityAuthority;
        try self.requireReady(owner.owner, now_ticks);
        return self.state.devices orelse error.GraphDestinationRequired;
    }

    pub fn ensureUserRoot(self: *Service, owner: principal.PrincipalId, label: []const u8, key: sealed.Key, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(owner, key, now_ticks);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        _ = try devices.ensureSealedUserRoot(owner, label, key, now_ticks);
        _ = try self.flush(now_ticks, scratch);
    }

    pub fn enrollDevice(self: *Service, owner: principal.PrincipalId, device: principal.PrincipalId, label: []const u8, root_key: sealed.Key, device_key: sealed.Key, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(owner, root_key, now_ticks);
        try self.requireEnrollmentKey(owner, device_key, now_ticks);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        _ = try devices.enrollSealedDevice(owner, device, label, root_key, device_key, now_ticks);
        _ = try self.flush(now_ticks, scratch);
    }

    pub fn rotateDeviceKey(self: *Service, owner: principal.PrincipalId, device: principal.PrincipalId, root_key: sealed.Key, device_key: sealed.Key, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(owner, root_key, now_ticks);
        try self.requireEnrollmentKey(owner, device_key, now_ticks);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        _ = try devices.rotateSealedDeviceKey(owner, device, root_key, device_key, now_ticks);
        _ = try self.flush(now_ticks, scratch);
    }

    pub fn approveEnrollment(self: *Service, proposal: *const graph.EnrollmentProposal, root_key: sealed.Key, now: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(proposal.owner, root_key, now);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        const existed = devices.findDeviceConst(proposal.device) != null;
        _ = try devices.approveEnrollment(proposal, root_key, now);
        if (!existed or self.version_id == 0) _ = try self.flush(now, scratch);
    }

    pub fn prepareDeviceRotation(self: *Service, owner: principal.PrincipalId, device: principal.PrincipalId, pin: signing.PublicKey, current_key: sealed.Key, next_key: sealed.Key, now: u64, scratch: *[catalog.MAX_BYTES]u8) !graph.RotationProposal {
        try self.requireEnrollmentKey(owner, current_key, now);
        try self.requireEnrollmentKey(owner, next_key, now);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        const proposal = try graph.RotationProposal.create(devices, device, pin, current_key, next_key, now);
        // Keep both keys durable while the authority approves the public change.
        // No request escapes if the replacement key checkpoint fails.
        _ = try self.flush(now, scratch);
        return proposal;
    }

    pub fn approveDeviceRotation(self: *Service, proposal: *const graph.RotationProposal, root_key: sealed.Key, now: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(proposal.owner, root_key, now);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        const changed = try devices.approveRotation(proposal, root_key, now);
        if (changed or self.version_id == 0) _ = try self.flush(now, scratch);
    }

    pub fn publishEnrollment(self: *const Service, owner: principal.PrincipalId, root_key: sealed.Key, now: u64, buffer: []u8) ![]const u8 {
        try self.requireEnrollmentKey(owner, root_key, now);
        if (self.version_id == 0) return error.IdentityCheckpointRequired;
        return enrollment.publish(self.state.devices orelse return error.GraphDestinationRequired, owner, root_key, now, buffer);
    }

    pub fn acceptEnrollment(self: *Service, owner: principal.PrincipalId, local_device: principal.PrincipalId, local_key: sealed.Key, pin: signing.PublicKey, bytes: []const u8, now: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(owner, local_key, now);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        var candidate = graph.Graph.init();
        try enrollment.readPublication(&candidate, owner, pin, bytes);
        const local = try candidate.authenticatedRecord(local_device, pin);
        if (!std.mem.eql(u8, local.device_signature.publicKeySlice(), &(try local_key.publicKey(now)))) return error.InvalidIdentityAuthority;
        const changed = try enrollment.requireExtension(devices, &candidate, owner, pin);
        if (!changed and self.version_id != 0) return;
        devices.* = candidate;
        _ = try self.flush(now, scratch);
    }

    pub fn revokeDevice(self: *Service, owner: principal.PrincipalId, device: principal.PrincipalId, root_key: sealed.Key, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
        try self.requireEnrollmentKey(owner, root_key, now_ticks);
        const devices = self.state.devices orelse return error.GraphDestinationRequired;
        try devices.revokeSealedDevice(owner, device, root_key, now_ticks);
        _ = try self.flush(now_ticks, scratch);
    }

    fn requireEnrollmentKey(self: *const Service, owner: principal.PrincipalId, key: sealed.Key, now_ticks: u64) !void {
        try self.requireReady(owner, now_ticks);
        try key.validate(now_ticks);
        // New signing keys must be in the same vault that this checkpoint
        // commits. A graph must never outlive an unpersisted sibling vault.
        if (key.authority.?.service != self.state.vault or !key.authority.?.owner.eql(owner)) return error.InvalidIdentityAuthority;
    }

    fn requireReady(self: *const Service, owner: principal.PrincipalId, now_ticks: u64) !void {
        if (self.dirty or self.checkpoint.pending != null) return error.IdentityCheckpointPending;
        try self.signer.validateService(self.storage.owner, self.storage.task_id, now_ticks);
        if (self.signer.key.authority.?.service != self.state.vault or !self.signer.key.authority.?.owner.eql(owner)) return error.InvalidIdentityAuthority;
        try self.storage.requireDurableBoundary();
    }

    fn requireAuthority(self: *const Service, authority: identity.VaultAuthority) !void {
        if (authority.vault != self.state.vault or authority.holder.kind != .service or authority.task_id == 0) return error.InvalidIdentityAuthority;
    }
};

comptime {
    if (@sizeOf(Service) > 208) @compileError("durable identity service exceeds bounded coordination state");
}

const std = @import("std");
const signing = @import("../core/signing.zig");
const vault = @import("secret_vault_service.zig");
const durable = @import("../storage/document_save_test.zig");

const Fixture = if (@import("builtin").is_test) struct {
    keys: @import("../../tests/fixtures/document_signer.zig").Fixture = .{},
    identities: identity.Store = .init(),
    devices: graph.Graph = .init(),
    service: Service = undefined,
    credential_handle: u64 = 0,
    unlock_session: identity.unlock_context.Session = @import("../../tests/fixtures/identity_vault.zig").unlock_session,

    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 600 };
    const device_key = signing.SignerIdentity{ .label = "device", .seed = @splat(0x22) };
    const credential_key = signing.SignerIdentity{ .label = "credential", .seed = @splat(0x33) };

    fn init(self: *Fixture, storage: *storage_service.Service) !void {
        const signer = try self.keys.init(owner, storage.owner, storage.task_id, durable.signer);
        self.keys.policies = .init();
        _ = try self.keys.policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "identity fixture", .secret_vault_allowed = true, .require_hardware_backed_secrets = true, .deny_secret_raw_export = true, .max_secret_handle_lease_ticks = std.math.maxInt(u64), .credential_assertions_allowed = true }, durable.signer);
        _ = try self.devices.ensureUserRoot(owner, "owner", durable.signer);
        _ = try self.devices.enrollDevice(owner, device, "device", durable.signer, device_key, 1);
        self.credential_handle = try self.addKey(credential_key);
        self.service = .{ .state = .{ .vault = &self.keys.service, .identities = &self.identities }, .storage = storage, .signer = signer, .object_id = 1000 };
    }

    fn addKey(self: *Fixture, key: signing.SignerIdentity) !u64 {
        const secret = try self.keys.service.importSecret(&self.keys.policies, self.keys.authority.subjects, .{ .owner = owner, .task_id = 600, .label = key.label, .raw = &key.seed, .now_ticks = 1 }, null);
        return self.lendCredentialKey(secret.id);
    }

    fn lendCredentialKey(self: *Fixture, secret_id: u64) !u64 {
        return (try self.keys.service.lendHandle(&self.keys.policies, self.keys.authority.subjects, .{ .owner = owner, .holder = holder, .task_id = 600, .secret_id = secret_id, .expires_at_ticks = 1000, .now_ticks = 1 }, null)).id;
    }

    fn authority(self: *Fixture, tick: u64) identity.VaultAuthority {
        return .{ .vault = &self.keys.service, .policies = &self.keys.policies, .subjects = self.keys.authority.subjects, .holder = holder, .task_id = 600, .now_ticks = tick, .unlock_session = &self.unlock_session };
    }

    fn register(self: *Fixture, scratch: *[catalog.MAX_BYTES]u8) !void {
        _ = try self.service.registerCredential(&self.devices, self.authority(2), .{ .owner = owner, .device = device, .relying_party_id = "accounts.example", .label = "account", .key_handle_id = self.credential_handle }, scratch);
    }

    fn request(self: *Fixture) !identity.AssertionRequest {
        return .{ .credential_id = 1, .device = device, .relying_party_id = "accounts.example", .origin = "https://accounts.example", .challenge = "nonce", .key_handle_id = self.credential_handle, .local_unlock = try identity.createLocalUnlockProofForVerification(try self.unlock_session.binding(), owner, device, "accounts.example", "nonce", .device_pin, 1, 1000, device_key) };
    }

    fn restore(self: *Fixture, storage: *storage_service.Service, scratch: *[catalog.MAX_BYTES]u8) !void {
        // Model process loss: discard live handles, identity state and proof scope.
        self.unlock_session.current.boot_instance[0] +%= 1;
        self.unlock_session.current.session_nonce[0] +%= 1;
        self.keys.service = .init();
        self.keys.service.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
        self.identities = .init();
        const state = catalog.State{ .vault = &self.keys.service, .identities = &self.identities };
        _ = try catalog.restore(storage, state, .{ .object_id = 1000, .owner = owner, .public_key = try signing.publicKey(durable.signer) }, scratch);
        const root = try self.keys.service.lendHandle(&self.keys.policies, self.keys.authority.subjects, .{ .owner = owner, .holder = storage.owner, .task_id = storage.task_id, .secret_id = 1, .expires_at_ticks = 1000, .now_ticks = 1 }, null);
        const signer = try object_signer.Signer.bind(&self.keys.authority, root.id, 1);
        self.credential_handle = try self.lendCredentialKey(self.identities.findCredentialConst(1).?.secret_id);
        self.service = .{ .state = state, .storage = storage, .signer = signer, .object_id = 1000, .version_id = storage.latestVersion(@as(u64, 1000)).?.id.raw() };
    }
} else void;

test "durable identity preserves assertion counters and revocations across crashes" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var fixture = Fixture{};
    try fixture.init(&device.service);
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    try fixture.register(&scratch);
    const first = try fixture.service.assertCredential(&fixture.devices, fixture.authority(3), try fixture.request(), &scratch);
    try std.testing.expectEqual(@as(u64, 1), first.assertion_counter);
    device.crash();
    try fixture.restore(&device.service, &scratch);
    const second = try fixture.service.assertCredential(&fixture.devices, fixture.authority(3), try fixture.request(), &scratch);
    try std.testing.expectEqual(@as(u64, 2), second.assertion_counter);
    try std.testing.expect(identity.verifyAssertion(&second, &(try signing.publicKey(Fixture.credential_key))));
    try fixture.service.revokeCredential(1, 4, &scratch);
    device.crash();
    try fixture.restore(&device.service, &scratch);
    try std.testing.expectError(error.CredentialRevoked, fixture.service.assertCredential(&fixture.devices, fixture.authority(5), try fixture.request(), &scratch));
    try std.testing.expectEqual(@as(u64, 2), fixture.identities.findCredentialConst(1).?.assertion_count);
}

test "durable identity withholds failed assertions and blocks mutation until retry or restart" {
    for (0..2) |variant| {
        const device = try durable.Fixture.init(true);
        defer device.deinit();
        var fixture = Fixture{};
        try fixture.init(&device.service);
        var scratch: [catalog.MAX_BYTES]u8 = undefined;
        try fixture.register(&scratch);
        device.fail_flushes = true;
        try std.testing.expectError(error.DurabilityBarrierFailed, fixture.service.assertCredential(&fixture.devices, fixture.authority(3), try fixture.request(), &scratch));
        const versions = device.service.versionCount();
        try std.testing.expectError(error.IdentityCheckpointPending, fixture.service.assertCredential(&fixture.devices, fixture.authority(4), try fixture.request(), &scratch));
        try std.testing.expectError(error.IdentityCheckpointPending, fixture.service.revokeCredential(1, 4, &scratch));
        device.fail_flushes = false;
        if (variant == 0) {
            _ = try fixture.service.flush(4, &scratch);
            try std.testing.expectEqual(versions, device.service.versionCount());
        }
        device.crash();
        try fixture.restore(&device.service, &scratch);
        const assertion = try fixture.service.assertCredential(&fixture.devices, fixture.authority(5), try fixture.request(), &scratch);
        try std.testing.expectEqual(if (variant == 0) @as(u64, 2) else @as(u64, 1), assertion.assertion_counter);
    }
}

test "durable identity retains its counter when catalog signing fails before version publication" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var fixture = Fixture{};
    try fixture.init(&device.service);
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    try fixture.register(&scratch);
    const before = device.service.versionCount();
    const root = &fixture.keys.service.store.secrets[0].material.sealed;
    root.bytes[root.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSealedSecret, fixture.service.assertCredential(&fixture.devices, fixture.authority(3), try fixture.request(), &scratch));
    try std.testing.expectEqual(before, device.service.versionCount());
    try std.testing.expectEqual(@as(u64, 1), fixture.identities.findCredentialConst(1).?.assertion_count);
    try std.testing.expect(fixture.service.checkpoint.pending == null and fixture.service.dirty);
    try std.testing.expectError(error.IdentityCheckpointPending, fixture.service.assertCredential(&fixture.devices, fixture.authority(4), try fixture.request(), &scratch));
    root.bytes[root.len - 1] ^= 1;
    _ = try fixture.service.flush(4, &scratch);
    const assertion = try fixture.service.assertCredential(&fixture.devices, fixture.authority(5), try fixture.request(), &scratch);
    try std.testing.expectEqual(@as(u64, 2), assertion.assertion_counter);
}

test "durable identity failed revocations cannot be bypassed while a checkpoint is pending" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var fixture = Fixture{};
    try fixture.init(&device.service);
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    try fixture.register(&scratch);
    device.fail_flushes = true;
    try std.testing.expectError(error.DurabilityBarrierFailed, fixture.service.revokeCredential(1, 3, &scratch));
    try std.testing.expectError(error.IdentityCheckpointPending, fixture.service.assertCredential(&fixture.devices, fixture.authority(4), try fixture.request(), &scratch));
    device.fail_flushes = false;
    _ = try fixture.service.flush(4, &scratch);
    device.crash();
    try fixture.restore(&device.service, &scratch);
    try std.testing.expectError(error.CredentialRevoked, fixture.service.assertCredential(&fixture.devices, fixture.authority(5), try fixture.request(), &scratch));
}

test "durable identity checkpoints replacement keys together with recovery generations" {
    for (0..2) |variant| {
        const device = try durable.Fixture.init(true);
        defer device.deinit();
        var fixture = Fixture{};
        try fixture.init(&device.service);
        var scratch: [catalog.MAX_BYTES]u8 = undefined;
        try fixture.register(&scratch);
        _ = try fixture.service.assertCredential(&fixture.devices, fixture.authority(2), try fixture.request(), &scratch);
        const replacement = try fixture.addKey(.{ .label = "replacement", .seed = @splat(0x44) });
        const challenge = try fixture.identities.recoveryChallenge(fixture.authority(3), 1, Fixture.device, replacement);
        const request = identity.RecoveryRequest{ .credential_id = 1, .recovery_device = Fixture.device, .relying_party_id = "accounts.example", .replacement_key_handle_id = replacement, .local_unlock = try identity.createLocalUnlockProofForVerification(try fixture.unlock_session.binding(), Fixture.owner, Fixture.device, "accounts.example", &challenge, .recovery_key, 2, 1000, Fixture.device_key) };
        device.fail_flushes = variant == 1;
        if (variant == 1) {
            try std.testing.expectError(error.DurabilityBarrierFailed, fixture.service.recoverCredential(&fixture.devices, fixture.authority(3), request, &scratch));
        } else {
            _ = try fixture.service.recoverCredential(&fixture.devices, fixture.authority(3), request, &scratch);
        }
        device.crash();
        device.fail_flushes = false;
        try fixture.restore(&device.service, &scratch);
        const credential = fixture.identities.findCredentialConst(1).?;
        try std.testing.expectEqual(if (variant == 0) @as(u32, 2) else @as(u32, 1), credential.credential_generation);
        try std.testing.expectEqual(if (variant == 0) @as(u64, 3) else @as(u64, 2), credential.secret_id);
        try std.testing.expectEqual(if (variant == 0) @as(u8, 3) else @as(u8, 2), fixture.keys.service.store.secret_count);
        const assertion = try fixture.service.assertCredential(&fixture.devices, fixture.authority(4), try fixture.request(), &scratch);
        try std.testing.expectEqual(@as(u64, 2), assertion.assertion_counter);
        try std.testing.expect(identity.verifyAssertion(&assertion, &credential.credential_public_key));
    }
}

test "durable identity rejects invalid credential bindings without publishing any restored keys" {
    const device = try durable.Fixture.init(true);
    defer device.deinit();
    var fixture = Fixture{};
    try fixture.init(&device.service);
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    try fixture.register(&scratch);
    const previous = device.service.latestVersion(@as(u64, 1000)).?;
    const bytes = try device.service.versionPayloadInto(previous, &scratch);
    const digest = fixture.identities.findCredentialConst(1).?.sealed_secret_digest;
    const offset = std.mem.lastIndexOf(u8, bytes, &digest).?;
    scratch[offset] ^= 1;
    // A valid outer signature cannot make a credential's wrong sealed-key
    // binding valid. Recovery must roll back the already authenticated keys.
    const metadata = try fixture.service.signer.signObjectMetadata("Sealed vault catalog", catalog.CONTENT_TYPE, .secret, bytes, 3);
    _ = try device.service.putVersion(.{ .preferred_object_id = @import("../core/ids.zig").object(1000), .object_type = .secret, .payload = bytes, .metadata = metadata, .parent_version_id = previous.id });
    var recovered_vault = vault.Service.init();
    recovered_vault.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());
    var recovered_identity = identity.Store.init();
    try std.testing.expectError(error.InvalidIdentitySnapshot, catalog.restore(&device.service, .{ .vault = &recovered_vault, .identities = &recovered_identity }, .{ .object_id = 1000, .owner = Fixture.owner, .public_key = try signing.publicKey(durable.signer) }, &scratch));
    try std.testing.expectEqual(@as(u8, 0), recovered_identity.credential_count);
    try std.testing.expectEqual(@as(u8, 0), recovered_vault.store.secret_count);
    try std.testing.expectEqual(@as(usize, 0), recovered_vault.handles.countInUse());
}
