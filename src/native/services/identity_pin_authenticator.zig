//! Stable, exclusive native input owner. Retain the adapter, session, capsule,
//! policy, vault, identity/graph stores and scratch through worker completion.
//! Shared storage is inspected synchronously; no storage record borrow spans a
//! yield. Lock only revokes replay authority while protocol buffers are in use.
const std = @import("std");
const entry = @import("../platform/trusted_pin_entry.zig");
const identity_session = @import("identity_session.zig");
const pin = @import("../platform/tpm2_pin.zig");
const catalog = @import("../storage/vault_catalog.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const guarded = @import("../task/guarded_worker_stack.zig");

pub fn Adapter(comptime Io: type) type {
    return struct {
        const Self = @This();
        session: *identity_session.Session(Io),
        capsule: *const pin.Capsule,
        boot_instance: [16]u8,
        lifetime_ticks: u64,
        scratch: *[catalog.MAX_BYTES]u8,
        stack: ?guarded.Stack = null,
        worker: cooperative.Worker = .{ .stack = &.{} },
        value: [entry.MAX_PIN_BYTES]u8 = @splat(0),
        value_len: usize = 0,
        started_at: u64 = 0,
        now_ticks: u64 = 0,
        failure: ?anyerror = null,

        pub fn authenticator(self: *Self) entry.Authenticator {
            return .{ .context = self, .lock_fn = lock, .start_fn = start, .poll_fn = poll, .busy_fn = busy, .deadline_fn = deadline };
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
            } else self.session.lock();
        }

        fn start(context: *anyopaque, value: []const u8, now_ticks: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (busy(self)) return error.WorkerBusy;
            self.session.lock();
            if (value.len < entry.MIN_PIN_BYTES or value.len > self.value.len) return error.InvalidPin;
            if (self.stack == null) self.stack = try guarded.Stack.allocate();
            self.worker.stack = self.stack.?.bytes;
            std.crypto.secureZero(u8, &self.value);
            @memcpy(self.value[0..value.len], value);
            self.value_len = value.len;
            self.started_at = now_ticks;
            self.now_ticks = now_ticks;
            self.failure = null;
            errdefer std.crypto.secureZero(u8, &self.value);
            try self.worker.start(self, run);
        }

        fn poll(context: *anyopaque, now_ticks: u64) !bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!busy(self)) return error.NoAuthenticationAttempt;
            if (now_ticks < self.now_ticks) self.worker.cancel();
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
            self.authenticate() catch |err| {
                // Every borrowed command has returned. Close can yield for
                // FlushContext; do not publish failure until cleanup completes.
                self.session.close() catch |cleanup_error| {
                    self.failure = cleanup_error;
                    return;
                };
                self.failure = err;
            };
        }

        fn authenticate(self: *Self) !void {
            if (self.worker.cancel_requested) return error.Cancelled;
            try self.session.unlock(self.capsule, self.value[0..self.value_len], self.boot_instance, self.started_at, self.lifetime_ticks, self.scratch);
            // No yield between these checks and publishing completion. Validate
            // actual elapsed time and current policy after all device waits.
            if (self.worker.cancel_requested) return error.Cancelled;
            try self.session.requireActive(self.now_ticks);
            try self.session.device_key.validate(self.now_ticks);
            try self.session.coordinator.?.signer.key.validate(self.now_ticks);
        }

        fn deadline(context: *anyopaque) u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            return if (!busy(self) and self.session.replay.active) self.session.expires_at_ticks else 0;
        }
    };
}

test "identity PIN adapter retains command borrows until cancelled worker unwinds" {
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
    const owner = @import("../core/principal.zig").PrincipalId{ .kind = .user, .serial = 1 };
    var session = identity_session.Session(Io){ .io = &io, .enrollment = .{ .owner = owner, .device = .{ .kind = .device, .serial = 2 }, .capsule_digest = @splat(4), .catalog_object_id = 1000, .anchor_index = 0x0180_4321, .catalog_secret_id = 1, .device_secret_id = 2 }, .state = .{ .vault = &service, .identities = &identities, .devices = &graph }, .storage = &device.service, .policies = &policies, .subjects = .{ .user_id = owner.serial } };
    var capsule = pin.Capsule{ .owner = owner, .device = session.enrollment.device, .salt = @splat(4), .sealed = .{ .len = 1 } };
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var adapter = Adapter(Io){ .session = &session, .capsule = &capsule, .boot_instance = @splat(1), .lifetime_ticks = 100, .scratch = &scratch };
    defer adapter.deinit() catch unreachable;
    const auth = adapter.authenticator();
    try auth.start_fn(auth.context, "73019428", 1);
    try std.testing.expect(!try auth.poll_fn(auth.context, 1));
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expectError(error.WorkerBusy, adapter.deinit());
    try std.testing.expectError(error.WorkerBusy, auth.start_fn(auth.context, "73019428", 2));
    try std.testing.expectError(error.Cancelled, auth.poll_fn(auth.context, 2));
    try std.testing.expect(!auth.busy_fn(auth.context) and !session.replay.active);
    try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
    try std.testing.expect(std.mem.allEqual(u8, &adapter.value, 0));
    try std.testing.expect(std.mem.allEqual(u8, &session.client.command, 0));
    try auth.start_fn(auth.context, "73019428", 3);
    try std.testing.expect(!try auth.poll_fn(auth.context, 3));
    try std.testing.expectError(error.HardwareUnavailable, auth.poll_fn(auth.context, 4));
    try std.testing.expect(!auth.busy_fn(auth.context) and !session.replay.active);
    try std.testing.expect(std.mem.allEqual(u8, adapter.stack.?.bytes, 0));
    try std.testing.expectEqual(@as(usize, 2), io.calls);
}
