//! Serialized, trusted PIN-to-identity session owner. Keep this object and its
//! exclusively borrowed stores at stable addresses until close succeeds.
//! Enrollment pins, policy, monotonic time and PIN input are trusted inputs;
//! this is not an application IPC boundary or first-user provisioning UI.
const std = @import("std");
const principal = @import("../core/principal.zig");
const policy = @import("../policy/policy_object.zig");
const identity = @import("../platform/os_identity.zig");
const tpm = @import("../platform/tpm2_sealing.zig");
const pin_mod = @import("../platform/tpm2_pin.zig");
const provider = @import("../platform/tpm2_secret_provider.zig");
const nv = @import("../platform/tpm2_vault_anchor.zig");
const catalog = @import("../storage/vault_catalog.zig");
const storage_service = @import("../storage/storage_service.zig");
const graph_snapshot = @import("../sync/device_graph_snapshot.zig");
const sealed = @import("sealed_signing_key.zig");
const durable = @import("durable_identity_service.zig");

// Provisioning supplies this independently of the capsule/catalog being opened.
// Secret IDs select keys; their public keys are checked against the NV pins.
pub const Enrollment = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    capsule_digest: tpm.Key,
    catalog_object_id: u64,
    anchor_index: u32,
    catalog_secret_id: u64,
    device_secret_id: u64,
};

pub const AssertionRequest = struct {
    credential_id: u64,
    relying_party_id: []const u8,
    origin: []const u8,
    challenge: []const u8,
    local_unlock: identity.LocalUnlockProof,
};

pub fn Session(comptime Io: type) type {
    return struct {
        const Self = @This();
        io: *Io,
        enrollment: Enrollment,
        state: catalog.State,
        storage: *storage_service.Service,
        policies: *const policy.Directory,
        subjects: policy.SubjectSet,
        client: tpm.Client = .{},
        authorization: tpm.Key = @splat(0),
        replay: identity.unlock_context.Session = .{},
        backend: provider.Backend(Io) = undefined,
        anchor_backend: nv.Backend(Io) = undefined,
        anchor_interface: catalog.Anchor = undefined,
        signing_authority: sealed.Authority = undefined,
        coordinator: ?durable.Service = null,
        device_key: sealed.Key = .{},
        verified_at_ticks: u64 = 0,
        last_ticks: u64 = 0,
        expires_at_ticks: u64 = 0,

        comptime {
            if (@sizeOf(Self) > 4096) @compileError("identity session exceeds bounded coordination state");
        }

        // No I/O, allocation, audit or fallible policy check. Invalidate replay
        // authority first. Arenas retain generation history, even on failed
        // unlocks. Pending checkpoints are recovered from disk/NV next time.
        pub fn lock(self: *Self) void {
            self.replay.lock();
            self.state.vault.unload();
            std.crypto.secureZero(u8, &self.authorization);
            std.crypto.secureZero(u8, &self.client.command);
            std.crypto.secureZero(u8, &self.client.response);
            self.state.identities.* = .init();
            if (self.state.devices) |devices| devices.* = .init();
            self.device_key = .{};
            self.coordinator = null;
            self.verified_at_ticks = 0;
            self.last_ticks = 0;
            self.expires_at_ticks = 0;
        }

        // TPM resource cleanup is separate from local revocation. Failure must
        // keep the session locked; retain the client so cleanup can be retried.
        pub fn close(self: *Self) !void {
            self.lock();
            try self.client.close(self.io);
            self.client = .{};
        }

        pub fn unlock(self: *Self, capsule: *const pin_mod.Capsule, pin: []const u8, boot_instance: [16]u8, now_ticks: u64, lifetime_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
            if (self.replay.active) return error.IdentitySessionAlreadyActive;
            errdefer self.lock();
            const enrolled = self.enrollment;
            const devices = self.state.devices orelse return error.GraphDestinationRequired;
            if (enrolled.owner.kind != .user or enrolled.owner.serial == 0 or enrolled.device.kind != .device or enrolled.device.serial == 0 or
                enrolled.catalog_object_id == 0 or enrolled.catalog_secret_id == 0 or enrolled.device_secret_id == 0 or enrolled.catalog_secret_id == enrolled.device_secret_id or
                self.storage.owner.kind != .service or self.storage.owner.serial == 0 or self.storage.task_id == 0 or
                !capsule.owner.eql(enrolled.owner) or !capsule.device.eql(enrolled.device) or std.mem.allEqual(u8, &boot_instance, 0)) return error.InvalidIdentitySession;
            if (lifetime_ticks == 0) return error.InvalidLease;
            const deadline = std.math.add(u64, now_ticks, lifetime_ticks) catch return error.InvalidLease;
            if (!self.state.vault.store.empty() or self.state.vault.handles.countInUse() != 0 or self.state.vault.store.handles.countInUse() != 0 or
                self.state.identities.credential_count != 0 or !graph_snapshot.empty(devices)) return error.VaultNotEmpty;
            try self.close();
            try self.client.initialize(self.io);
            try capsule.unlock(&self.client, self.io, &enrolled.capsule_digest, pin, &self.authorization);
            const Anchor = nv.Backend(Io);
            const record = Anchor.read(&self.client, self.io, &self.authorization, enrolled.anchor_index) catch |err| blk: {
                if (err != error.NvUninitialized) return err;
                // Only resume an independently committed NV definition. A
                // missing index never becomes an enrollment request here.
                break :blk try Anchor.resumeProvision(&self.client, self.io, &self.authorization, enrolled.anchor_index, self.storage, enrolled.catalog_object_id, enrolled.owner, scratch);
            };
            if (record.checkpoint.object_id != enrolled.catalog_object_id or !record.checkpoint.owner.eql(enrolled.owner)) return error.VaultAnchorBindingChanged;
            const root_pin = record.device_root_pin orelse return error.InvalidIdentitySession;
            self.anchor_backend = .{ .client = &self.client, .io = self.io, .authorization = &self.authorization, .index = enrolled.anchor_index, .current = record };
            try self.anchor_backend.recover(self.storage, scratch);
            self.backend = .{ .client = &self.client, .io = self.io, .authorization = &self.authorization };
            self.state.vault.attachHardwareProvider(self.backend.provider());
            _ = try catalog.restore(self.storage, self.state, self.anchor_backend.current.trust(), scratch);
            _ = try devices.authenticatedRoot(enrolled.owner, root_pin);
            const device = try devices.authenticatedDevice(enrolled.device, root_pin);
            if (!device.owner.eql(enrolled.owner)) return error.InvalidIdentitySession;
            self.signing_authority = .{ .service = self.state.vault, .policies = self.policies, .subjects = self.subjects, .owner = enrolled.owner, .holder = self.storage.owner, .task_id = self.storage.task_id };
            self.expires_at_ticks = deadline;
            const catalog_key = try self.lendKey(enrolled.catalog_secret_id, now_ticks);
            if (!std.mem.eql(u8, &(try catalog_key.publicKey(now_ticks)), &record.checkpoint.public_key)) return error.SigningKeyChanged;
            self.device_key = try self.lendKey(enrolled.device_secret_id, now_ticks);
            if (!std.mem.eql(u8, &(try self.device_key.publicKey(now_ticks)), device.device_signature.publicKeySlice())) return error.SigningKeyChanged;
            self.anchor_interface = self.anchor_backend.interface();
            self.coordinator = .{
                .state = self.state,
                .storage = self.storage,
                .signer = .{ .key = catalog_key },
                .object_id = enrolled.catalog_object_id,
                .version_id = self.storage.latestVersion(enrolled.catalog_object_id).?.id.raw(),
                .checkpoint = .{ .anchor = &self.anchor_interface },
            };
            self.verified_at_ticks = now_ticks;
            self.last_ticks = now_ticks;
            // This is the only activation point, after every authenticated
            // restore and key check. Entropy failure erases all loaded state.
            try self.replay.begin(boot_instance, self.io);
        }

        pub fn issueUnlockProof(self: *Self, relying_party_id: []const u8, challenge: []const u8, now_ticks: u64, expires_at_ticks: u64) !identity.LocalUnlockProof {
            try self.requireActive(now_ticks);
            if (expires_at_ticks > self.expires_at_ticks) return error.LocalUnlockExpired;
            return identity.issueLocalUnlockProof(self.state.devices.?, self.authority(now_ticks), .{
                .owner = self.enrollment.owner,
                .device = self.enrollment.device,
                .relying_party_id = relying_party_id,
                .challenge = challenge,
                .method = .device_pin,
                .verified_at_ticks = self.verified_at_ticks,
                .expires_at_ticks = expires_at_ticks,
                .key_handle_id = self.device_key.handle_id,
            });
        }

        pub fn assertCredential(self: *Self, request: AssertionRequest, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !identity.Assertion {
            try self.requireActive(now_ticks);
            const credential = self.state.identities.findCredentialConst(request.credential_id) orelse return error.CredentialNotFound;
            if (!credential.owner.eql(self.enrollment.owner)) return error.InvalidIdentitySession;
            // This private lease never crosses an app boundary. Reuse it for
            // repeated assertions instead of consuming the bounded handle table.
            const key = try self.lendKey(credential.secret_id, now_ticks);
            return self.coordinator.?.assertCredential(self.state.devices.?, self.authority(now_ticks), .{
                .credential_id = request.credential_id,
                .device = self.enrollment.device,
                .relying_party_id = request.relying_party_id,
                .origin = request.origin,
                .challenge = request.challenge,
                .local_unlock = request.local_unlock,
                .key_handle_id = key.handle_id,
            }, scratch);
        }

        pub fn requireActive(self: *Self, now_ticks: u64) !void {
            _ = try self.replay.binding();
            if (now_ticks < self.last_ticks or now_ticks >= self.expires_at_ticks) {
                self.lock();
                return error.IdentitySessionExpired;
            }
            self.last_ticks = now_ticks;
        }

        fn authority(self: *Self, now_ticks: u64) identity.VaultAuthority {
            return .{ .vault = self.state.vault, .policies = self.policies, .subjects = self.subjects, .holder = self.storage.owner, .task_id = self.storage.task_id, .now_ticks = now_ticks, .unlock_session = &self.replay };
        }

        fn lendKey(self: *Self, secret_id: u64, now_ticks: u64) !sealed.Key {
            for (self.state.vault.handles.slots) |slot| {
                const handle = slot.handle;
                if (slot.in_use and handle.secret_id == secret_id and handle.holder.eql(self.storage.owner) and handle.task_id == self.storage.task_id and
                    !handle.revoked and !handle.expired(now_ticks) and handle.expires_at_ticks == self.expires_at_ticks and !handle.raw_export_allowed)
                    return sealed.Key.bind(&self.signing_authority, handle.id, now_ticks);
            }
            const handle = try self.state.vault.lendHandle(self.policies, self.subjects, .{ .owner = self.enrollment.owner, .holder = self.storage.owner, .task_id = self.storage.task_id, .secret_id = secret_id, .now_ticks = now_ticks, .expires_at_ticks = self.expires_at_ticks }, null);
            return sealed.Key.bind(&self.signing_authority, handle.id, now_ticks);
        }
    };
}

test "identity session lock erases authority before fallible TPM cleanup" {
    const Io = struct {
        calls: usize = 0,
        pub fn random(_: *@This(), _: []u8) !void {
            return error.NoEntropy;
        }
        pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            self.calls += 1;
            return error.HardwareUnavailable;
        }
    };
    const Fixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
    const device = try @import("../storage/document_save_test.zig").Fixture.init(true);
    defer device.deinit();
    var keys = Fixture{};
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const signer = try keys.init(owner, device.service.owner, device.service.task_id, .{ .label = "lock", .seed = @splat(0x29) });
    const old_handle = keys.service.findHandleConst(signer.key.handle_id).?.*;
    var identities = identity.Store.init();
    var graph = @import("../sync/device_graph.zig").Graph.init();
    var io = Io{};
    var session = Session(Io){ .io = &io, .enrollment = .{ .owner = owner, .device = .{ .kind = .device, .serial = 2 }, .capsule_digest = @splat(4), .catalog_object_id = 1000, .anchor_index = 0x0180_4321, .catalog_secret_id = 1, .device_secret_id = 2 }, .state = .{ .vault = &keys.service, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &keys.policies, .subjects = .{ .user_id = owner.serial } };
    session.replay = @import("../../tests/fixtures/identity_vault.zig").unlock_session;
    const captured = try session.replay.binding();
    session.authorization = @splat(0x55);
    session.client.command = @splat(0x55);
    session.client.response = @splat(0x55);
    session.client.parent = 0x8000_0001;
    try std.testing.expectError(error.HardwareUnavailable, session.close());
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expectError(error.UnlockContextUnavailable, session.replay.require(captured));
    try std.testing.expect(std.mem.allEqual(u8, &session.authorization, 0));
    try std.testing.expect(std.mem.allEqual(u8, &session.client.command, 0));
    try std.testing.expect(std.mem.allEqual(u8, &session.client.response, 0));
    try std.testing.expect(keys.service.store.empty());
    try std.testing.expect(keys.service.store.hardware_provider.operations == null);
    try std.testing.expect(keys.service.store.describeHandle(old_handle.store_handle_id) == null);
    try std.testing.expectError(error.VaultHandleNotFound, signer.key.validate(3));
    try std.testing.expect(session.coordinator == null);
    session.lock();
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    // Repeated local lock preserves the last nonce and cannot do I/O.
    try std.testing.expectEqualDeep(captured, session.replay.current);
    session.replay.active = true;
    session.last_ticks = 5;
    session.expires_at_ticks = 10;
    try session.requireActive(7);
    try std.testing.expectError(error.IdentitySessionExpired, session.requireActive(6));
    try std.testing.expect(!session.replay.active);
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    session.replay.active = true;
    session.expires_at_ticks = 10;
    try std.testing.expectError(error.IdentitySessionExpired, session.requireActive(10));
    try std.testing.expect(!session.replay.active);
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    session.client.parent = 0;
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var capsule = pin_mod.Capsule{ .owner = owner, .device = session.enrollment.device, .salt = @splat(4), .sealed = .{ .len = 1 } };
    try std.testing.expectError(error.InvalidLease, session.unlock(&capsule, "123456", @splat(1), 1, std.math.maxInt(u64), &scratch));
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expectError(error.HardwareUnavailable, session.unlock(&capsule, "123456", @splat(1), 1, 10, &scratch));
    try std.testing.expect(!session.replay.active and session.coordinator == null);
    try std.testing.expect(keys.service.store.empty());
    try std.testing.expect(std.mem.allEqual(u8, &session.authorization, 0));
}
