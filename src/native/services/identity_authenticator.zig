//! Stable, exclusive native input owner. Retain the adapter, session, capsule, recovery package,
//! policy, vault, identity/graph stores and scratch through worker completion.
//! Shared storage is inspected synchronously; no storage record borrow spans a
//! yield. Lock only revokes replay authority while protocol buffers are in use.
const std = @import("std");
const entry = @import("../platform/trusted_auth_entry.zig");
const identity_session = @import("identity_session.zig");
const pin = @import("../platform/tpm2_pin.zig");
const recovery = @import("identity_recovery.zig");
const recovery_record = @import("identity_recovery_record.zig");
const recovery_key = @import("../platform/recovery_key.zig");
const catalog = @import("../storage/vault_catalog.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const guarded = @import("../task/guarded_worker_stack.zig");
const tpm_lease = @import("../task/tpm_worker_lease.zig");
const identity = @import("../platform/os_identity.zig");
const request_mod = @import("identity_request.zig");

pub fn Adapter(comptime Io: type) type {
    return struct {
        const Self = @This();
        session: *identity_session.Session(Io),
        capsule: *const pin.Capsule,
        recovery_package: ?*const recovery.Package = null,
        recovery_pin: ?@import("identity_provisioning.zig").Pin = null,
        boot_instance: [16]u8,
        lifetime_ticks: u64,
        scratch: *[catalog.MAX_BYTES]u8,
        stack: ?guarded.Stack = null,
        worker: cooperative.Worker = .{ .stack = &.{} },
        value: [entry.MAX_PIN_BYTES]u8 = @splat(0),
        value_len: usize = 0,
        method: entry.Method = .pin,
        started_at: u64 = 0,
        now_ticks: u64 = 0,
        failure: ?anyerror = null,
        operation: enum { authenticate, assertion } = .authenticate,
        assertion_grant: request_mod.Grant = undefined,
        relying_party_id: [identity.MAX_RP_ID_BYTES]u8 = @splat(0),
        origin: [identity.MAX_ORIGIN_BYTES]u8 = @splat(0),
        challenge: [identity.MAX_CHALLENGE_BYTES]u8 = @splat(0),
        challenge_len: u8 = 0,
        assertion_result: ?identity.Assertion = null,

        pub fn authenticator(self: *Self) entry.Authenticator {
            return .{ .context = self, .recovery_available = self.recovery_package != null, .recovery_characters = if (self.recovery_pin != null) recovery_record.CODE_BYTES else recovery_key.CODE_BYTES, .lock_fn = lock, .start_fn = start, .poll_fn = poll, .busy_fn = busy, .deadline_fn = deadline };
        }

        pub fn requests(self: *Self) request_mod.Backend {
            return .{ .context = self, .authorized = authorized, .start = startAssertion, .poll = pollAssertion, .cancel = cancelAssertion };
        }

        fn authorized(context: *anyopaque, grant: request_mod.Grant, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.session.replay.active or now < self.session.last_ticks or now >= self.session.expires_at_ticks or
                now >= grant.expires_at_ticks or grant.expires_at_ticks > self.session.expires_at_ticks or
                grant.relying_party_id.len > self.relying_party_id.len or grant.origin.len > self.origin.len or
                !identity.originMatchesRelyingParty(grant.origin, grant.relying_party_id)) return false;
            self.session.replay.require(grant.session) catch return false;
            const credential = self.session.state.identities.findCredentialConst(grant.credential_id) orelse return false;
            return credential.status == .active and credential.owner.eql(self.session.enrollment.owner) and
                std.mem.eql(u8, credential.relyingPartySlice(), grant.relying_party_id);
        }

        fn startAssertion(context: *anyopaque, request: request_mod.Request, now: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (busy(self) or self.assertion_result != null) return error.WorkerBusy;
            if (!authorized(self, request.grant, now) or request.challenge.len == 0 or request.challenge.len > self.challenge.len)
                return error.IdentityRequestDenied;
            if (self.stack == null) self.stack = try guarded.Stack.allocate();
            self.worker.stack = self.stack.?.bytes;
            self.assertion_grant = request.grant;
            @memcpy(self.relying_party_id[0..request.grant.relying_party_id.len], request.grant.relying_party_id);
            @memcpy(self.origin[0..request.grant.origin.len], request.grant.origin);
            self.assertion_grant.relying_party_id = self.relying_party_id[0..request.grant.relying_party_id.len];
            self.assertion_grant.origin = self.origin[0..request.grant.origin.len];
            @memcpy(self.challenge[0..request.challenge.len], request.challenge);
            self.challenge_len = @intCast(request.challenge.len);
            self.operation = .assertion;
            self.started_at = now;
            self.now_ticks = now;
            self.failure = null;
            errdefer self.eraseAssertion();
            try self.worker.start(self, run);
        }

        fn pollAssertion(context: *anyopaque, now: u64) !?identity.Assertion {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.operation != .assertion) return error.NoIdentityRequest;
            if (busy(self) and !(try poll(self, now))) return null;
            if (self.failure) |err| return err;
            if (!authorized(self, self.assertion_grant, now)) {
                self.eraseAssertion();
                return error.IdentityRequestDenied;
            }
            const result = self.assertion_result orelse return error.Cancelled;
            self.eraseAssertion();
            return result;
        }

        fn eraseAssertion(self: *Self) void {
            @memset(&self.relying_party_id, 0);
            @memset(&self.origin, 0);
            @memset(&self.challenge, 0);
            self.challenge_len = 0;
            self.assertion_result = null;
        }

        fn cancelAssertion(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.operation != .assertion) return;
            if (busy(self)) {
                self.worker.cancel();
                self.session.replay.lock();
                return;
            }
            self.eraseAssertion();
        }

        // Detach trusted input and finish cancellation before releasing backing
        // stores. Session.close separately releases its retained TPM parent.
        pub fn deinit(self: *Self) !void {
            lock(self);
            if (busy(self)) return error.WorkerBusy;
            if (self.stack) |*stack| stack.deinit();
            self.stack = null;
            self.worker = .{ .stack = &.{} };
            std.crypto.secureZero(u8, &self.value);
        }

        fn busy(context: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.worker.state == .suspended or self.worker.state == .running;
        }

        fn lock(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (busy(self)) {
                self.worker.cancel();
                self.session.replay.lock();
            } else {
                self.session.lock();
                self.eraseAssertion();
            }
        }

        fn start(context: *anyopaque, method: entry.Method, value: []const u8, now_ticks: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (busy(self)) return error.WorkerBusy;
            self.eraseAssertion();
            self.operation = .authenticate;
            self.session.lock();
            std.crypto.secureZero(u8, &self.value);
            self.value_len = 0;
            self.method = .pin;
            errdefer {
                std.crypto.secureZero(u8, &self.value);
                self.value_len = 0;
                self.method = .pin;
            }
            switch (method) {
                .pin => {
                    if (value.len < entry.MIN_PIN_BYTES or value.len > self.value.len) return error.InvalidPin;
                    for (value) |byte| if (byte < '0' or byte > '9') return error.InvalidPin;
                    @memcpy(self.value[0..value.len], value);
                    self.value_len = value.len;
                },
                .recovery => {
                    if (self.recovery_package == null) return error.RecoveryUnavailable;
                    if (self.recovery_pin) |trusted| {
                        var retained = recovery_record.Record{};
                        defer retained.erase();
                        recovery_record.Record.decode(value, &retained) catch return error.InvalidRecoveryCode;
                        if (trusted.object_id != retained.trusted.object_id or !std.crypto.timing_safe.eql([32]u8, trusted.digest, retained.trusted.digest)) return error.RecoveryEnrollmentChanged;
                        self.value = retained.key;
                    } else recovery_key.decode(value, &self.value) catch return error.InvalidRecoveryCode;
                    self.value_len = self.value.len;
                },
            }
            if (self.stack == null) self.stack = try guarded.Stack.allocate();
            self.worker.stack = self.stack.?.bytes;
            self.method = method;
            self.started_at = now_ticks;
            self.now_ticks = now_ticks;
            self.failure = null;
            try self.worker.start(self, run);
        }

        fn poll(context: *anyopaque, now_ticks: u64) !bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!busy(self)) return error.NoAuthenticationAttempt;
            if (now_ticks < self.now_ticks) self.worker.cancel();
            if (self.operation == .assertion and (now_ticks >= self.assertion_grant.expires_at_ticks or
                !self.session.replay.active or now_ticks >= self.session.expires_at_ticks)) self.worker.cancel();
            self.now_ticks = now_ticks;
            try self.worker.step();
            if (busy(self)) return false;
            if (self.failure) |err| return err;
            return true;
        }

        fn run(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            defer std.crypto.secureZero(u8, &self.value);
            defer self.value_len = 0;
            defer self.method = .pin;
            while (!(tpm_lease.tryAcquire() catch |err| {
                self.failure = err;
                return;
            })) self.worker.yield();
            defer tpm_lease.release();
            self.perform() catch |err| {
                // Every borrowed command has returned. Close can yield for
                // FlushContext; do not publish failure until cleanup completes.
                self.session.close() catch |cleanup_error| {
                    self.failure = cleanup_error;
                    return;
                };
                self.failure = err;
                self.assertion_result = null;
            };
        }

        fn perform(self: *Self) !void {
            if (self.worker.cancel_requested) return error.Cancelled;
            if (self.operation == .assertion) {
                if (!authorized(self, self.assertion_grant, self.now_ticks)) return error.IdentityRequestDenied;
                const proof = try self.session.issueUnlockProof(self.assertion_grant.relying_party_id, self.challenge[0..self.challenge_len], self.started_at, self.assertion_grant.expires_at_ticks);
                if (self.worker.cancel_requested) return error.Cancelled;
                self.assertion_result = try self.session.assertCredential(.{
                    .credential_id = self.assertion_grant.credential_id,
                    .relying_party_id = self.assertion_grant.relying_party_id,
                    .origin = self.assertion_grant.origin,
                    .challenge = self.challenge[0..self.challenge_len],
                    .local_unlock = proof,
                }, self.started_at, self.scratch);
                self.assertion_result.?.signature.signer = "";
            } else switch (self.method) {
                .pin => try self.session.unlock(self.capsule, self.value[0..self.value_len], self.boot_instance, self.started_at, self.lifetime_ticks, self.scratch),
                .recovery => try self.session.unlockRecovery(self.capsule, &self.recovery_package.?.bytes, &self.value, self.boot_instance, self.started_at, self.lifetime_ticks, self.scratch),
            }
            // No yield between these checks and publishing completion. Validate
            // actual elapsed time and current policy after all device waits.
            if (self.worker.cancel_requested) return error.Cancelled;
            try self.session.requireActive(self.now_ticks);
            try self.session.device_key.validate(self.now_ticks);
            try self.session.coordinator.?.signer.key.validate(self.now_ticks);
        }

        fn deadline(context: *anyopaque) u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            return if (self.session.replay.active and (!busy(self) or self.operation == .assertion)) self.session.expires_at_ticks else 0;
        }
    };
}

test "identity authentication adapter validates recovery before hardware and retains command borrows through cancellation" {
    const Io = struct {
        calls: usize = 0,
        pub fn random(_: *@This(), out: []u8) !void {
            @memset(out, 0x35);
        }
        pub fn execute(self: *@This(), command: []const u8, _: []u8, _: u32) ![]u8 {
            const first = command[0];
            self.calls += 1;
            cooperative.current().?.yield();
            // Local revocation must not erase an in-flight command's backing.
            if (first != command[0] or command[0] == 0) return error.OverwrittenCommand;
            if (cooperative.current().?.cancel_requested) return error.Cancelled;
            return error.HardwareUnavailable;
        }
    };
    const device = try @import("../storage/document_save_test.zig").Fixture.init(false);
    defer device.deinit();
    var service = @import("secret_vault_service.zig").Service.init();
    defer service.unload();
    var policies = @import("../policy/policy_object.zig").Directory.init();
    var identities = @import("../platform/os_identity.zig").Store.init();
    var graph = @import("../sync/device_graph.zig").Graph.init();
    var io = Io{};
    const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    var session = identity_session.Session(Io){ .io = &io, .enrollment = record.enrollment, .state = .{ .vault = &service, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &policies, .subjects = .{ .user_id = record.enrollment.owner.serial } };
    var secrets = recovery.Secrets{ .owner = @splat(1), .lockout = @splat(2), .vault = @splat(3) };
    defer secrets.wipe();
    const key: recovery_key.Key = @splat(4);
    var package = recovery.Package{};
    try recovery.Package.seal(&record, &secrets, &key, &io, &package);
    var code: [recovery_key.CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    try recovery_key.encode(&key, &code);
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var adapter = Adapter(Io){ .session = &session, .capsule = &record.capsule, .boot_instance = @splat(1), .lifetime_ticks = 100, .scratch = &scratch };
    defer adapter.deinit() catch unreachable;
    var auth = adapter.authenticator();
    try std.testing.expect(!auth.recovery_available);
    try std.testing.expectError(error.RecoveryUnavailable, auth.start_fn(auth.context, .recovery, &code, 1));
    adapter.recovery_package = &package;
    auth = adapter.authenticator();
    try std.testing.expect(auth.recovery_available);
    code[0] = if (code[0] == '0') '1' else '0';
    try std.testing.expectError(error.InvalidRecoveryCode, auth.start_fn(auth.context, .recovery, &code, 1));
    try std.testing.expectError(error.InvalidPin, auth.start_fn(auth.context, .pin, "73019a28", 1));
    try std.testing.expect(io.calls == 0 and adapter.stack == null and adapter.value_len == 0);
    try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
    const wrong_key: recovery_key.Key = @splat(5);
    try recovery_key.encode(&wrong_key, &code);
    try auth.start_fn(auth.context, .recovery, &code, 1);
    try std.testing.expectError(error.RecoveryAuthenticationFailed, auth.poll_fn(auth.context, 1));
    try std.testing.expect(io.calls == 0 and !session.replay.active);
    try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
    try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
    try recovery_key.encode(&key, &code);
    for ([_]entry.Method{ .pin, .recovery }) |method| {
        const value: []const u8 = if (method == .pin) "73019428" else &code;
        const before = io.calls;
        try auth.start_fn(auth.context, method, value, 1);
        try std.testing.expect(!try auth.poll_fn(auth.context, 1));
        try std.testing.expectEqual(before + 1, io.calls);
        try std.testing.expectError(error.WorkerBusy, adapter.deinit());
        try std.testing.expectError(error.WorkerBusy, auth.start_fn(auth.context, method, value, 2));
        try std.testing.expectError(error.Cancelled, auth.poll_fn(auth.context, 2));
        try std.testing.expect(!auth.busy_fn(auth.context) and !session.replay.active);
        try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
        try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
        try std.testing.expect(std.mem.allEqual(u8, &session.client.command, 0));
        try auth.start_fn(auth.context, method, value, 3);
        try std.testing.expect(!try auth.poll_fn(auth.context, 3));
        try std.testing.expectError(error.HardwareUnavailable, auth.poll_fn(auth.context, 4));
        try std.testing.expect(!auth.busy_fn(auth.context) and !session.replay.active);
        try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
        try std.testing.expectEqual(before + 2, io.calls);
        try auth.start_fn(auth.context, method, value, 5);
        try std.testing.expect(!try auth.poll_fn(auth.context, 5));
        try std.testing.expectError(error.Cancelled, auth.poll_fn(auth.context, 4));
        try std.testing.expect(!auth.busy_fn(auth.context) and !session.replay.active);
        try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
        try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
    }
    adapter.recovery_pin = .{ .object_id = 1001, .digest = @splat(8) };
    auth = adapter.authenticator();
    try std.testing.expectEqual(recovery_record.CODE_BYTES, auth.recovery_characters);
    var retained = recovery_record.Record{ .trusted = adapter.recovery_pin.?, .key = key };
    defer retained.erase();
    var record_code: [recovery_record.CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &record_code);
    retained.trusted.digest[0] ^= 1;
    try retained.encode(&record_code);
    const before = io.calls;
    try std.testing.expectError(error.RecoveryEnrollmentChanged, auth.start_fn(auth.context, .recovery, &record_code, 10));
    try std.testing.expectEqual(before, io.calls);
    try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
    retained.trusted = adapter.recovery_pin.?;
    retained.key = wrong_key;
    try retained.encode(&record_code);
    try auth.start_fn(auth.context, .recovery, &record_code, 10);
    try std.testing.expectError(error.RecoveryAuthenticationFailed, auth.poll_fn(auth.context, 10));
    try std.testing.expectEqual(before, io.calls);
    try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0) and std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
}
