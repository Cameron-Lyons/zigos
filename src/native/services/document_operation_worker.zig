//! One stable, lazy document operation under the authenticated native owner.
//! This supplies execution and lifetime coordination, never document grants.
const builtin = @import("builtin");
const std = @import("std");
const session_mod = @import("identity_session.zig");
const sessions_mod = @import("../session/document_sessions.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const guarded = @import("../task/guarded_worker_stack.zig");
const tpm_lease = @import("../task/tpm_worker_lease.zig");
const operation_guard = @import("../platform/operation_guard.zig");
const unlock = @import("../platform/unlock_context.zig");
const object_signer = @import("../storage/sealed_object_signer.zig");

// One native creation job shares the owner's existing worker, operation guard,
// TPM lease and cancellation boundary with editor save/load operations.
pub const JobInterface = struct {
    context: *anyopaque,
    ready: *const fn (*anyopaque, u64) bool,
    run: *const fn (*anyopaque, object_signer.Signer, *const operation_guard.Guard) void,
    cancel: *const fn (*anyopaque, u64) void,
};

pub fn Coordinator(comptime Io: type) type {
    return struct {
        const Self = @This();
        session: *session_mod.Session(Io),
        documents: *sessions_mod.Sessions,
        timeout_ticks: u64,
        stack: ?guarded.Stack = null,
        worker: cooperative.Worker = .{ .stack = &.{} },
        guard: operation_guard.Guard = undefined,
        binding: unlock.Binding = .{},
        signer: object_signer.Signer = .{},
        started_at: u64 = 0,
        now_ticks: u64 = 0,
        deadline: u64 = 0,
        wake: ?u64 = null,
        bound: bool = false,
        job: ?JobInterface = null,
        running_job: bool = false,

        pub fn setJob(self: *Self, job: ?JobInterface) void {
            if (self.busy()) @panic("native document job backing stays stable during an operation");
            self.job = job;
        }
        pub fn cancelJob(self: *Self, now: u64) void {
            if (self.busy() and self.running_job) {
                self.worker.cancel();
                self.wake = now;
            }
        }

        // Bind only after the stable Session has been initialized. Revocation
        // also retires idle channels before a later unlock replaces its keys.
        pub fn bind(self: *Self) void {
            if (self.session.revocation) |existing| if (existing.context != @as(*anyopaque, self))
                @panic("native document revocation has one stable owner");
            self.session.revocation = .{ .context = self, .call = cancelOwned };
            self.bound = true;
        }

        pub fn busy(self: *const Self) bool {
            return self.worker.state == .running or self.worker.state == .suspended;
        }

        fn signerForSession(self: *const Self) ?object_signer.Signer {
            if (!self.session.replay.active or self.session.coordinator == null) return null;
            const signer = self.session.coordinator.?.signer;
            if (signer.key.authority != &self.session.signing_authority) return null;
            return signer;
        }

        pub fn ready(self: *const Self, now: u64) bool {
            if (!self.bound) return false;
            if (self.busy()) return if (self.wake) |due| now >= due else false;
            if (self.session.operation_worker != null) return false;
            const signer = self.signerForSession() orelse
                return self.documents.hasAuthority(&self.session.signing_authority);
            if (now < self.now_ticks or now >= self.session.expires_at_ticks)
                return self.documents.hasAuthority(&self.session.signing_authority);
            if (self.wake) |due| if (now < due) return false;
            return self.documents.hasPendingForSigner(signer) or (if (self.job) |job| job.ready(job.context, now) else false);
        }

        pub fn nextWake(self: *const Self) ?u64 {
            if (!self.bound) return null;
            if (self.busy()) return self.wake;
            if (!self.documents.hasAuthority(&self.session.signing_authority) and !(if (self.job) |job| job.ready(job.context, self.now_ticks) else false)) return null;
            return if (self.wake) |due| @min(due, self.session.expires_at_ticks) else self.session.expires_at_ticks;
        }

        pub fn cancel(self: *Self, now: u64) void {
            self.worker.cancel();
            if (self.job) |job| job.cancel(job.context, now);
            self.documents.cancelForAuthority(&self.session.signing_authority, now);
            if (!self.busy()) self.wake = null;
        }

        fn cancelOwned(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.cancel(self.now_ticks);
        }

        fn step(self: *Self, now: u64) void {
            self.wake = std.math.add(u64, now, 1) catch null;
            if (self.wake == null) {
                // No future tick is representable. Revoke and finish bounded
                // provider cleanup instead of parking without a wake source.
                self.session.lock();
                while (self.busy()) self.worker.step() catch @panic("owned document cleanup resumes on its native context");
            } else self.worker.step() catch @panic("owned document worker resumes on its native context");
            if (!self.busy()) self.wake = null;
        }

        pub fn service(self: *Self, now: u64) bool {
            if (!self.bound) return false;
            return self.serviceStep(now, false);
        }

        fn serviceStep(self: *Self, now: u64, draining: bool) bool {
            if (self.busy()) {
                if (now < self.now_ticks or now >= self.deadline or !self.session.replay.active or self.session.lock_pending) {
                    self.session.lock();
                    self.cancel(now);
                }
                self.now_ticks = now;
                if (!draining and !self.ready(now)) return false;
                self.step(now);
                return true;
            }
            if (self.session.operation_worker != null) return false;
            if (!self.session.replay.active and !self.documents.hasAuthority(&self.session.signing_authority)) {
                self.wake = null;
                return false;
            }
            if (!self.session.replay.active or now < self.now_ticks or now >= self.session.expires_at_ticks or self.signerForSession() == null) {
                const had_channels = self.documents.hasAuthority(&self.session.signing_authority);
                self.session.lock();
                self.cancel(now);
                self.now_ticks = now;
                self.wake = null;
                return had_channels;
            }
            if (!self.ready(now)) return false;
            const deadline = std.math.add(u64, now, self.timeout_ticks) catch {
                self.session.lock();
                self.cancel(now);
                return true;
            };
            if (self.timeout_ticks == 0) {
                self.session.lock();
                self.cancel(now);
                return true;
            }
            self.session.beginOperation(&self.worker) catch return false;
            self.running_job = if (self.job) |job| job.ready(job.context, now) else false;
            self.binding = self.session.replay.binding() catch unreachable;
            self.signer = self.signerForSession() orelse unreachable;
            self.started_at = now;
            self.now_ticks = now;
            self.deadline = @min(deadline, self.session.expires_at_ticks);
            if (self.stack == null) self.stack = guarded.Stack.allocate() catch {
                self.session.endOperation(&self.worker);
                self.wake = std.math.add(u64, now, 1) catch null;
                return false;
            };
            self.worker.stack = self.stack.?.bytes;
            self.guard = .{ .context = self, .check_fn = check };
            self.session.bindPublicationGuard(&self.guard);
            self.worker.start(self, run) catch {
                self.session.endOperation(&self.worker);
                self.wake = std.math.add(u64, now, 1) catch null;
                return false;
            };
            self.step(now);
            return true;
        }

        fn check(context: *anyopaque) operation_guard.Error!u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.worker.cancel_requested or self.session.lock_pending) return error.Cancelled;
            if (self.session.operation_worker != &self.worker) return error.OperationAuthorityChanged;
            const current_signer = self.signerForSession() orelse return error.OperationAuthorityChanged;
            if (!std.meta.eql(current_signer, self.signer)) return error.OperationAuthorityChanged;
            const now = if (comptime builtin.os.tag == .freestanding) blk: {
                const timer = @import("../../kernel/timer/timer.zig");
                timer.synchronize();
                break :blk timer.getTicks();
            } else self.now_ticks;
            if (now < self.started_at or now < self.session.last_ticks or now < self.session.verified_at_ticks)
                return error.OperationClockRollback;
            if (now >= self.deadline or now >= self.session.expires_at_ticks) return error.OperationExpired;
            self.session.replay.require(self.binding) catch return error.OperationAuthorityChanged;
            if (!self.session.policies.sessionLifetimeDecision(self.session.subjects, self.session.expires_at_ticks - self.session.verified_at_ticks).allowed)
                return error.OperationPolicyDenied;
            const platform_backed = if (self.session.state.devices) |graph|
                if (graph.findDeviceConst(self.session.enrollment.device)) |device| device.usesPlatformBackedKey() else false
            else
                false;
            if (!self.session.policies.sessionTrustDecision(self.session.subjects, .{ .hardware_backed_credential = true, .device_platform_backed = platform_backed, .unlock_age_ticks = now - self.session.verified_at_ticks }).allowed)
                return error.OperationPolicyDenied;
            return now;
        }

        fn run(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            defer self.session.endOperation(&self.worker);
            while (!(tpm_lease.tryAcquire() catch return)) {
                _ = check(self) catch {
                    self.cancel(self.now_ticks);
                    return;
                };
                self.worker.yield();
            }
            defer tpm_lease.release();
            if (check(self)) |_| {
                if (self.running_job) {
                    if (self.job) |job| if (job.ready(job.context, self.now_ticks)) job.run(job.context, self.signer, &self.guard);
                } else _ = self.documents.serviceForSigner(self.signer, self.now_ticks);
            } else |_| self.cancel(self.now_ticks);
            // Providers finish transient-handle cleanup before returning from
            // the channel. Only now may pending revocation unload this session.
            if (self.session.lock_pending) self.session.closeOwned(&self.worker) catch {};
        }

        pub fn quiesce(self: *Self, now: u64) void {
            self.cancel(now);
            while (self.busy()) _ = self.serviceStep(now, true);
        }

        pub fn deinit(self: *Self) error{WorkerBusy}!void {
            if (self.busy()) return error.WorkerBusy;
            if (self.bound) if (self.session.revocation) |revoke| if (revoke.context == @as(*anyopaque, self)) {
                self.session.revocation = null;
            };
            self.bound = false;
            if (self.stack) |*stack| stack.deinit();
            self.stack = null;
            self.worker = .{ .stack = &.{} };
        }

        comptime {
            if (@sizeOf(Self) > 320) @compileError("document operation coordinator exceeds bounded native state");
        }
    };
}

const TestCoordinator = if (builtin.is_test) struct {
    const disk_mod = @import("../storage/document_save_test.zig");
    const keys_mod = @import("../../tests/fixtures/document_signer.zig");
    const Io = struct {
        pub fn execute(_: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            return error.UnexpectedHardwareCommand;
        }
    };
    disk: *disk_mod.Fixture,
    keys: keys_mod.Fixture = .{},
    identities: @import("../platform/os_identity.zig").Store = .init(),
    io: Io = .{},
    documents: sessions_mod.Sessions = .{},
    session: session_mod.Session(Io) = undefined,
    coordinator: Coordinator(Io) = undefined,

    fn init() !*@This() {
        const disk = try disk_mod.Fixture.init(true);
        errdefer disk.deinit();
        const self = try std.testing.allocator.create(@This());
        errdefer std.testing.allocator.destroy(self);
        self.* = .{ .disk = disk };
        const signer = try self.keys.init(.{ .kind = .user, .serial = 1 }, disk.service.owner, disk.service.task_id, disk_mod.signer);
        var record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
        record.enrollment.owner = self.keys.authority.owner;
        self.session = .{
            .io = &self.io,
            .enrollment = record.enrollment,
            .state = .{ .vault = &self.keys.service, .identities = &self.identities },
            .storage = &disk.service,
            .policies = &self.keys.policies,
            .subjects = self.keys.authority.subjects,
            .replay = @import("../../tests/fixtures/identity_vault.zig").unlock_session,
            .signing_authority = self.keys.authority,
            .verified_at_ticks = 1,
            .last_ticks = 1,
            .expires_at_ticks = 100,
        };
        var owned_signer = signer;
        owned_signer.key.authority = &self.session.signing_authority;
        self.session.coordinator = .{ .state = self.session.state, .storage = &disk.service, .signer = owned_signer, .object_id = record.enrollment.catalog_object_id };
        self.coordinator = .{ .session = &self.session, .documents = &self.documents, .timeout_ticks = 20 };
        self.coordinator.bind();
        return self;
    }

    fn deinit(self: *@This()) void {
        self.coordinator.quiesce(self.coordinator.now_ticks);
        self.coordinator.deinit() catch @panic("fixture coordinator was not drained");
        self.session.close() catch @panic("fixture session close was refused");
        self.documents.deinit(99) catch @panic("fixture channels were not drained");
        self.disk.deinit();
        std.testing.allocator.destroy(self);
    }
} else struct {};

const TestJob = if (builtin.is_test) struct {
    requested: bool = true,
    pause: bool = false,
    runs: usize = 0,
    cancels: usize = 0,
    resumed: bool = false,
    denied: bool = false,
    running_address: usize = 0,

    fn interface(self: *@This()) JobInterface {
        return .{ .context = self, .ready = ready, .run = run, .cancel = cancel };
    }
    fn ready(context: *anyopaque, _: u64) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        return self.requested;
    }
    fn run(context: *anyopaque, signer: object_signer.Signer, guard: *const operation_guard.Guard) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.runs += 1;
        self.running_address = @intFromPtr(self);
        const worker = cooperative.current() orelse @panic("production job runs on its owned Worker");
        _ = guard.check_fn(guard.context) catch @panic("job entry has current authority");
        signer.validateService(signer.key.authority.?.holder, signer.key.authority.?.task_id, guard.check_fn(guard.context) catch @panic("job entry authority")) catch @panic("job uses a real sealed signer");
        if (self.pause) worker.yield();
        if (self.running_address != @intFromPtr(self)) @panic("suspended callback backing changed");
        self.resumed = true;
        _ = guard.check_fn(guard.context) catch {
            self.denied = true;
            return;
        };
        self.requested = false;
    }
    fn cancel(context: *anyopaque, _: u64) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.cancels += 1;
        self.requested = false;
    }
} else struct {};

const TestTpmHolder = if (builtin.is_test) struct {
    held: bool = false,
    fn run(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!(tpm_lease.tryAcquire() catch @panic("fixture TPM lease"))) @panic("fixture starts with idle TPM lease");
        self.held = true;
        defer {
            self.held = false;
            tpm_lease.release();
        }
        cooperative.current().?.yield();
    }
} else struct {};

test "owned document job cancellation drains queued TPM wait without running successor intent" {
    const fixture = try @import("../storage/document_save_ipc_test.zig").OwnedDocument.init();
    defer fixture.deinit();
    try fixture.fixture.queueCommit("pending editor draft");
    var selected = TestJob{};
    fixture.coordinator.setJob(selected.interface());
    var holder = TestTpmHolder{};
    var stack: [32 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&holder, TestTpmHolder.run);
    try worker.step();
    defer if (worker.state == .suspended) worker.step() catch @panic("holder cleanup");
    try std.testing.expect(holder.held and fixture.coordinator.service(10));
    try std.testing.expect(fixture.coordinator.busy() and fixture.coordinator.running_job);
    try std.testing.expectEqual(@as(usize, 0), selected.runs);
    // Narrow creation cancellation preserves older document sessions. The
    // launch request clears its own intent before asking the worker to drain.
    selected.requested = false;
    fixture.coordinator.cancelJob(10);
    try std.testing.expect(fixture.coordinator.service(10));
    try std.testing.expect(!fixture.coordinator.busy() and fixture.session.operation_worker == null);
    try std.testing.expect(selected.cancels == 0 and !selected.requested and selected.runs == 0);
    try std.testing.expect(holder.held and fixture.session.replay.active);
    try std.testing.expectEqual(@as(u16, 1), (try fixture.fixture.endpoints.descriptor(@import("../core/ids.zig").endpoint(fixture.fixture.server_endpoint_id))).queued_messages);
    try std.testing.expect(!fixture.fixture.server.running);
    try worker.step();
    var successor = TestJob{};
    fixture.coordinator.setJob(successor.interface());
    try std.testing.expect(fixture.coordinator.service(12));
    try std.testing.expect(!fixture.coordinator.busy() and successor.runs == 1 and selected.runs == 0);
    try std.testing.expectEqual(@as(u16, 1), (try fixture.fixture.endpoints.descriptor(@import("../core/ids.zig").endpoint(fixture.fixture.server_endpoint_id))).queued_messages);
    try std.testing.expectEqual(@as(usize, 1), fixture.fixture.device.service.versionCount());
}

test "owned document job rejects expired changed session signer and policy while queued" {
    const Failure = enum { expiry, session, signer, policy };
    for (std.enums.values(Failure)) |failure| {
        const fixture = try TestCoordinator.init();
        defer fixture.deinit();
        var selected = TestJob{};
        fixture.coordinator.setJob(selected.interface());
        var holder = TestTpmHolder{};
        var stack: [32 * 1024]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        try worker.start(&holder, TestTpmHolder.run);
        try worker.step();
        defer if (worker.state == .suspended) worker.step() catch @panic("holder cleanup");
        try std.testing.expect(fixture.coordinator.service(10));
        try std.testing.expect(fixture.coordinator.busy() and selected.runs == 0);
        var now: u64 = 11;
        switch (failure) {
            .expiry => now = 100,
            .session => fixture.session.replay.current.session_nonce[0] ^= 1,
            .signer => fixture.session.coordinator.?.signer.key.sealed_digest[0] ^= 1,
            .policy => {
                _ = try fixture.keys.policies.create(.{ .scope = .user, .subject_id = 1, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "late session restriction", .max_session_unlock_age_ticks = 3 }, TestCoordinator.disk_mod.signer);
            },
        }
        try std.testing.expect(fixture.coordinator.service(now));
        try std.testing.expect(!fixture.coordinator.busy());
        try std.testing.expect(selected.runs == 0 and selected.cancels != 0 and !selected.requested);
        try std.testing.expect(fixture.session.operation_worker == null and fixture.session.publication_guard == null);
        try std.testing.expect(holder.held);
        try std.testing.expect(!fixture.coordinator.service(now + 1));
    }
}

test "owned document job quiesce retains suspended callback backing until cleanup" {
    const fixture = try TestCoordinator.init();
    defer fixture.deinit();
    var selected = TestJob{ .pause = true };
    fixture.coordinator.setJob(selected.interface());
    try std.testing.expect(fixture.coordinator.service(10));
    try std.testing.expect(fixture.coordinator.busy() and selected.runs == 1 and !selected.resumed);
    try std.testing.expectError(error.WorkerBusy, fixture.coordinator.deinit());
    fixture.coordinator.quiesce(11);
    try std.testing.expect(!fixture.coordinator.busy() and selected.resumed and selected.denied);
    try std.testing.expect(selected.cancels != 0 and selected.running_address == @intFromPtr(&selected));
    try std.testing.expect(fixture.session.operation_worker == null and fixture.session.publication_guard == null);
    try std.testing.expect(std.mem.allEqual(u8, fixture.coordinator.stack.?.bytes, 0));
    var successor = TestJob{};
    fixture.coordinator.setJob(successor.interface());
    try std.testing.expect(fixture.coordinator.service(12));
    try std.testing.expect(successor.runs == 1 and !fixture.coordinator.busy());
}
