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
const enrollment_mod = @import("identity_enrollment.zig");
const recovery = @import("identity_recovery.zig");
const operation_guard = @import("../platform/operation_guard.zig");
const cooperative = @import("../task/cooperative_worker.zig");

// Provisioning supplies this independently of the capsule/catalog being opened.
// Secret IDs select keys; their public keys are checked against the NV pins.
pub const Enrollment = enrollment_mod.Enrollment;

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
        unlock_method: ?identity.UnlockMethod = null,
        verified_at_ticks: u64 = 0,
        last_ticks: u64 = 0,
        expires_at_ticks: u64 = 0,
        publication_guard: ?*const operation_guard.Guard = null,
        operation_worker: ?*cooperative.Worker = null,
        revocation: ?struct { context: *anyopaque, call: *const fn (*anyopaque) void } = null,
        lock_pending: bool = false,

        comptime {
            if (@sizeOf(Self) > 4096) @compileError("identity session exceeds bounded coordination state");
        }

        pub fn bindPublicationGuard(self: *Self, guard: ?*const operation_guard.Guard) void {
            self.publication_guard = guard;
            self.signing_authority.publication_guard = guard;
        }

        // Own session state before installing guards or entering any protocol.
        // The token is the stable worker, including while it waits for TPM use.
        pub fn beginOperation(self: *Self, worker: *cooperative.Worker) error{WorkerBusy}!void {
            if (self.operation_worker != null) return error.WorkerBusy;
            self.operation_worker = worker;
            self.lock_pending = false;
        }

        pub fn endOperation(self: *Self, worker: *cooperative.Worker) void {
            if (self.operation_worker != worker) @panic("identity operation releases its exact worker");
            self.bindPublicationGuard(null);
            if (self.lock_pending) self.lockNow();
            self.operation_worker = null;
            self.lock_pending = false;
        }

        pub fn lockOwned(self: *Self, worker: *cooperative.Worker) void {
            if (self.operation_worker != worker) @panic("identity cleanup owns its session operation");
            self.replay.lock();
            if (self.revocation) |revoke| revoke.call(revoke.context);
            self.lockNow();
        }

        pub fn closeOwned(self: *Self, worker: *cooperative.Worker) !void {
            self.lockOwned(worker);
            try self.client.close(self.io);
            self.client = .{};
        }

        // No I/O, allocation, audit or fallible policy check. Invalidate replay
        // authority first. Arenas retain generation history, even on failed
        // unlocks. Pending checkpoints are recovered from disk/NV next time.
        pub fn lock(self: *Self) void {
            self.replay.lock();
            if (self.revocation) |revoke| revoke.call(revoke.context);
            if (self.operation_worker) |worker| {
                self.lock_pending = true;
                worker.cancel();
                return;
            }
            self.lockNow();
        }

        fn lockNow(self: *Self) void {
            self.replay.lock();
            self.state.vault.unload();
            std.crypto.secureZero(u8, &self.authorization);
            std.crypto.secureZero(u8, &self.client.command);
            std.crypto.secureZero(u8, &self.client.response);
            self.state.identities.reset();
            if (self.state.devices) |devices| devices.reset();
            self.device_key = .{};
            self.unlock_method = null;
            self.coordinator = null;
            self.verified_at_ticks = 0;
            self.last_ticks = 0;
            self.expires_at_ticks = 0;
        }

        // TPM resource cleanup is separate from local revocation. Failure must
        // keep the session locked; retain the client so cleanup can be retried.
        pub fn close(self: *Self) !void {
            self.lock();
            if (self.operation_worker != null) return error.WorkerBusy;
            try self.client.close(self.io);
            self.client = .{};
        }

        pub fn unlock(self: *Self, capsule: *const pin_mod.Capsule, pin: []const u8, boot_instance: [16]u8, now_ticks: u64, lifetime_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
            if (self.replay.active) return error.IdentitySessionAlreadyActive;
            errdefer self.lock();
            const deadline = try self.prepareUnlock(capsule, boot_instance, now_ticks, lifetime_ticks);
            try self.client.openPersistent(self.io, self.enrollment.parent);
            try capsule.unlock(&self.client, self.io, &self.enrollment.capsule_digest, pin, &self.authorization);
            try self.restore(boot_instance, now_ticks, deadline, .device_pin, scratch);
        }

        // Explicit recovery authority: authenticate the entire package against
        // this independently enrolled identity BEFORE sending administrator
        // authorization. Only this path resets DA lockout. It retains neither
        // the recovery key nor owner/lockout secrets in the active session.
        pub fn unlockRecovery(self: *Self, capsule: *const pin_mod.Capsule, package: []const u8, recovery_key: *const tpm.Key, boot_instance: [16]u8, now_ticks: u64, lifetime_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !void {
            if (self.replay.active) return error.IdentitySessionAlreadyActive;
            errdefer self.lock();
            const deadline = try self.prepareUnlock(capsule, boot_instance, now_ticks, lifetime_ticks);
            const record = enrollment_mod.Record{ .enrollment = self.enrollment, .capsule = capsule.* };
            var secrets = recovery.Secrets{};
            defer secrets.wipe();
            try recovery.Package.open(package, &(try record.digest()), recovery_key, &secrets);
            try self.client.openPersistent(self.io, self.enrollment.parent);
            try self.client.resetDictionaryAttack(self.io, &secrets.lockout);
            self.authorization = secrets.vault;
            try self.restore(boot_instance, now_ticks, deadline, .recovery_key, scratch);
        }

        fn prepareUnlock(self: *Self, capsule: *const pin_mod.Capsule, boot_instance: [16]u8, now_ticks: u64, lifetime_ticks: u64) !u64 {
            const enrolled = self.enrollment;
            const devices = self.state.devices orelse return error.GraphDestinationRequired;
            try enrolled.validate();
            if (self.storage.owner.kind != .service or self.storage.owner.serial == 0 or self.storage.task_id == 0 or
                self.subjects.user_id != enrolled.owner.serial or
                !capsule.owner.eql(enrolled.owner) or !capsule.device.eql(enrolled.device) or std.mem.allEqual(u8, &boot_instance, 0)) return error.InvalidIdentitySession;
            if (lifetime_ticks == 0) return error.InvalidLease;
            const deadline = std.math.add(u64, now_ticks, lifetime_ticks) catch return error.InvalidLease;
            if (!self.policies.sessionLifetimeDecision(self.subjects, lifetime_ticks).allowed) return error.IdentityPolicyDenied;
            if (!self.state.vault.store.empty() or self.state.vault.handles.countInUse() != 0 or self.state.vault.store.handles.countInUse() != 0 or
                self.state.identities.credential_count != 0 or !graph_snapshot.empty(devices)) return error.VaultNotEmpty;
            if (self.operation_worker) |worker| {
                if (cooperative.current() != worker) return error.WorkerBusy;
                try self.closeOwned(worker);
            } else try self.close();
            return deadline;
        }

        fn restore(self: *Self, boot_instance: [16]u8, now_ticks: u64, deadline: u64, method: identity.UnlockMethod, scratch: *[catalog.MAX_BYTES]u8) !void {
            const enrolled = self.enrollment;
            const devices = self.state.devices.?;
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
            self.signing_authority = .{ .service = self.state.vault, .policies = self.policies, .subjects = self.subjects, .owner = enrolled.owner, .holder = self.storage.owner, .task_id = self.storage.task_id, .publication_guard = self.publication_guard };
            self.expires_at_ticks = deadline;
            const catalog_key = try self.lendKey(enrolled.catalog_secret_id, now_ticks);
            if (!std.mem.eql(u8, &(try catalog_key.publicKey(now_ticks)), &record.checkpoint.public_key)) return error.SigningKeyChanged;
            self.device_key = try self.lendKey(enrolled.device_secret_id, now_ticks);
            if (!std.mem.eql(u8, &(try self.device_key.publicKey(now_ticks)), device.device_signature.publicKeySlice())) return error.SigningKeyChanged;
            // Key binding above enforces actual sealed, nonexportable hardware
            // custody. Platform attestation and primary-device status are not
            // inferred from TPM sealing or supplied by an application.
            if (!self.policies.sessionTrustDecision(self.subjects, .{
                .hardware_backed_credential = true,
                .device_platform_backed = device.usesPlatformBackedKey(),
                .unlock_age_ticks = 0,
            }).allowed) return error.IdentityPolicyDenied;
            // TPM waits may yield to the desktop. Recheck the exact pinned
            // catalog before publishing its current storage version.
            _ = try catalog.inspect(self.storage, self.anchor_backend.current.trust(), scratch);
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
            self.unlock_method = method;
            // Activate only after authenticated restore. Entropy acquisition
            // may also yield; neither gate erases an active command's backing.
            try self.activate(boot_instance, now_ticks, deadline, device.usesPlatformBackedKey(), catalog_key);
        }

        fn activationTicks(self: *Self, observed_ticks: u64, verified_ticks: u64, deadline: u64, device_platform_backed: bool, catalog_key: sealed.Key) !u64 {
            const actual_ticks = try operation_guard.currentTicks(self.publication_guard, observed_ticks);
            if (actual_ticks >= deadline) return error.IdentitySessionExpired;
            if (!self.policies.sessionLifetimeDecision(self.subjects, deadline - verified_ticks).allowed or
                !self.policies.sessionTrustDecision(self.subjects, .{
                    .hardware_backed_credential = true,
                    .device_platform_backed = device_platform_backed,
                    .unlock_age_ticks = actual_ticks - verified_ticks,
                }).allowed) return error.IdentityPolicyDenied;
            try self.device_key.validate(actual_ticks);
            try catalog_key.validate(actual_ticks);
            return actual_ticks;
        }

        fn activate(self: *Self, boot_instance: [16]u8, verified_ticks: u64, deadline: u64, device_platform_backed: bool, catalog_key: sealed.Key) !void {
            errdefer self.replay.lock();
            const before = try self.activationTicks(verified_ticks, verified_ticks, deadline, device_platform_backed, catalog_key);
            try self.replay.begin(boot_instance, self.io);
            self.last_ticks = try self.activationTicks(before, verified_ticks, deadline, device_platform_backed, catalog_key);
        }

        pub fn issueUnlockProof(self: *Self, relying_party_id: []const u8, challenge: []const u8, now_ticks: u64, expires_at_ticks: u64) !identity.LocalUnlockProof {
            const actual_ticks = try operation_guard.currentTicks(self.publication_guard, now_ticks);
            try self.requireActive(actual_ticks);
            if (expires_at_ticks > self.expires_at_ticks) return error.LocalUnlockExpired;
            return identity.issueLocalUnlockProof(self.state.devices.?, self.authority(actual_ticks), .{
                .owner = self.enrollment.owner,
                .device = self.enrollment.device,
                .relying_party_id = relying_party_id,
                .challenge = challenge,
                .method = self.unlock_method orelse return error.InvalidIdentitySession,
                .verified_at_ticks = self.verified_at_ticks,
                .expires_at_ticks = expires_at_ticks,
                .key_handle_id = self.device_key.handle_id,
            });
        }

        pub fn assertCredential(self: *Self, request: AssertionRequest, now_ticks: u64, scratch: *[catalog.MAX_BYTES]u8) !identity.Assertion {
            const actual_ticks = try operation_guard.currentTicks(self.publication_guard, now_ticks);
            try self.requireActive(actual_ticks);
            const credential = self.state.identities.findCredentialConst(request.credential_id) orelse return error.CredentialNotFound;
            if (!credential.owner.eql(self.enrollment.owner)) return error.InvalidIdentitySession;
            // This private lease never crosses an app boundary. Reuse it for
            // repeated assertions instead of consuming the bounded handle table.
            const key = try self.lendKey(credential.secret_id, actual_ticks);
            return self.coordinator.?.assertCredential(self.state.devices.?, self.authority(actual_ticks), .{
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
            return .{ .vault = self.state.vault, .policies = self.policies, .subjects = self.subjects, .holder = self.storage.owner, .task_id = self.storage.task_id, .now_ticks = now_ticks, .unlock_session = &self.replay, .publication_guard = self.publication_guard };
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
    var session = Session(Io){ .io = &io, .enrollment = .{ .owner = owner, .device = .{ .kind = .device, .serial = 2 }, .capsule_digest = @splat(4), .parent = .{ .handle = 0x8100_4321, .name = .{ 0, 0x0b } ++ @as([32]u8, @splat(4)) }, .catalog_object_id = 1000, .anchor_index = 0x0180_4321, .catalog_secret_id = 1, .device_secret_id = 2 }, .state = .{ .vault = &keys.service, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &keys.policies, .subjects = .{ .user_id = owner.serial } };
    const Check = struct {
        fn current(_: *anyopaque) operation_guard.Error!u64 {
            return 3;
        }
    };
    const guard = operation_guard.Guard{ .context = &session, .check_fn = Check.current };
    session.bindPublicationGuard(&guard);
    try std.testing.expect(session.signing_authority.publication_guard == &guard);
    session.replay = @import("../../tests/fixtures/identity_vault.zig").unlock_session;
    const captured = try session.replay.binding();
    session.authorization = @splat(0x55);
    session.unlock_method = .recovery_key;
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
    try std.testing.expect(session.unlock_method == null);
    session.bindPublicationGuard(null);
    try std.testing.expect(session.publication_guard == null and session.signing_authority.publication_guard == null);
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
    const calls = io.calls;
    _ = try keys.policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = owner, .label = "bounded session", .max_session_unlock_age_ticks = 5 }, .{ .label = "policy fixture", .seed = @splat(11) });
    try std.testing.expectError(error.IdentityPolicyDenied, session.unlock(&capsule, "123456", @splat(1), 1, 6, &scratch));
    try std.testing.expectEqual(calls, io.calls);
    session.subjects.user_id = null;
    try std.testing.expectError(error.InvalidIdentitySession, session.unlock(&capsule, "123456", @splat(1), 1, 1, &scratch));
    try std.testing.expectEqual(calls, io.calls);
}

test "identity session recovery authenticates enrollment before hardware and never provisions a replacement" {
    const Io = struct {
        reads: usize = 0,
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedEntropy;
        }
        pub fn execute(self: *@This(), command: []const u8, response: []u8, _: u32) ![]u8 {
            if (command.len != 14 or std.mem.readInt(u32, command[6..10], .big) != 0x173) return error.UnexpectedAdministratorCommand;
            self.reads += 1;
            var writer = @import("../platform/tpm2_wire.zig").Writer{ .bytes = response };
            try writer.begin(0x8001, 0x18b);
            return writer.finish();
        }
    };
    const Entropy = struct {
        pub fn random(_: *@This(), out: []u8) !void {
            @memset(out, 7);
        }
    };
    const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    var secrets = recovery.Secrets{ .owner = @splat(1), .lockout = @splat(2), .vault = @splat(3) };
    defer secrets.wipe();
    const key: tpm.Key = @splat(8);
    var entropy = Entropy{};
    var package = recovery.Package{};
    try recovery.Package.seal(&record, &secrets, &key, &entropy, &package);
    const device = try @import("../storage/document_save_test.zig").Fixture.init(true);
    defer device.deinit();
    var vault = @import("secret_vault_service.zig").Service.init();
    var identities = identity.Store.init();
    var graph = @import("../sync/device_graph.zig").Graph.init();
    var policies = policy.Directory.init();
    var io = Io{};
    var session = Session(Io){ .io = &io, .enrollment = record.enrollment, .state = .{ .vault = &vault, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &policies, .subjects = .{ .user_id = record.enrollment.owner.serial } };
    defer session.close() catch {};
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    const wrong_key: tpm.Key = @splat(9);
    try std.testing.expectError(error.RecoveryAuthenticationFailed, session.unlockRecovery(&record.capsule, &package.bytes, &wrong_key, @splat(1), 1, 100, &scratch));
    session.enrollment.parent.name[2] ^= 1;
    try std.testing.expectError(error.RecoveryEnrollmentChanged, session.unlockRecovery(&record.capsule, &package.bytes, &key, @splat(1), 1, 100, &scratch));
    session.enrollment = record.enrollment;
    var changed_capsule = record.capsule;
    changed_capsule.salt[0] ^= 1;
    try std.testing.expectError(error.UntrustedPinCapsule, session.unlockRecovery(&changed_capsule, &package.bytes, &key, @splat(1), 1, 100, &scratch));
    try std.testing.expectEqual(@as(usize, 0), io.reads);
    try std.testing.expectError(error.PersistentParentMissing, session.unlockRecovery(&record.capsule, &package.bytes, &key, @splat(1), 1, 100, &scratch));
    try std.testing.expectEqual(@as(usize, 1), io.reads);
    try std.testing.expect(std.mem.allEqual(u8, &session.authorization, 0));
    try std.testing.expect(session.unlock_method == null and !session.replay.active and session.coordinator == null and vault.store.empty());
}

test "identity session activation rechecks live authority after entropy yields without unloading borrows" {
    const guarded = @import("../task/guarded_worker_stack.zig");
    const Control = struct {
        ticks: u64 = 1,
        cancelled: bool = false,
        fn check(context: *anyopaque) operation_guard.Error!u64 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.cancelled) return error.Cancelled;
            return self.ticks;
        }
    };
    const Io = struct {
        pub fn random(_: *@This(), out: []u8) !void {
            cooperative.current().?.yield();
            @memset(out, 0x72);
        }
        pub fn execute(_: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            return error.UnexpectedHardwareCommand;
        }
    };
    const Run = struct {
        session: *Session(Io),
        key: sealed.Key,
        failure: ?anyerror = null,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.session.activate(@splat(1), 1, 10, false, self.key) catch |err| {
                self.failure = err;
            };
        }
    };
    const Variant = enum { success, cancel, expiry, rollback, policy };
    for (std.enums.values(Variant)) |variant| {
        const device = try @import("../storage/document_save_test.zig").Fixture.init(false);
        defer device.deinit();
        var keys = @import("../../tests/fixtures/document_signer.zig").Fixture{};
        const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
        const signer = try keys.init(record.enrollment.owner, device.service.owner, device.service.task_id, .{ .label = "activation fixture", .seed = @splat(0x21) });
        var identities = identity.Store.init();
        var graph = @import("../sync/device_graph.zig").Graph.init();
        var io = Io{};
        var control = Control{};
        const guard = operation_guard.Guard{ .context = &control, .check_fn = Control.check };
        keys.authority.publication_guard = &guard;
        var session = Session(Io){ .io = &io, .enrollment = record.enrollment, .state = .{ .vault = &keys.service, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &keys.policies, .subjects = keys.authority.subjects, .device_key = signer.key, .publication_guard = &guard };
        defer session.close() catch unreachable;
        var run = Run{ .session = &session, .key = signer.key };
        // Policy verification needs the native operation worker's bounded,
        // guarded stack before entropy acquisition can suspend activation.
        var stack = try guarded.Stack.allocate();
        defer stack.deinit();
        try std.testing.expect(stack.guardsPresent());
        var worker = cooperative.Worker{ .stack = stack.bytes };
        try worker.start(&run, Run.run);
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        switch (variant) {
            .success => control.ticks = 2,
            .cancel => control.cancelled = true,
            .expiry => control.ticks = 10,
            .rollback => control.ticks = 0,
            .policy => {
                _ = try keys.policies.create(.{ .scope = .user, .subject_id = record.enrollment.owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "require platform session", .secret_vault_allowed = true, .require_platform_backed_device_session = true }, .{ .label = "policy fixture", .seed = @splat(11) });
            },
        }
        try worker.step();
        try std.testing.expectEqual(cooperative.Worker.State.complete, worker.state);
        try std.testing.expectEqual(variant == .success, session.replay.active);
        try std.testing.expectEqual(variant != .success, run.failure != null);
        try std.testing.expect(!keys.service.store.empty());
        try std.testing.expect(keys.service.findHandleConst(signer.key.handle_id) != null);
        try std.testing.expect(std.mem.allEqual(u8, stack.bytes, 0));
    }
}
