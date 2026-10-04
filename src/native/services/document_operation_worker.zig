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
            return self.documents.hasPendingForSigner(signer);
        }

        pub fn nextWake(self: *const Self) ?u64 {
            if (!self.bound) return null;
            if (self.busy()) return self.wake;
            if (!self.documents.hasAuthority(&self.session.signing_authority)) return null;
            return if (self.wake) |due| @min(due, self.session.expires_at_ticks) else self.session.expires_at_ticks;
        }

        pub fn cancel(self: *Self, now: u64) void {
            self.worker.cancel();
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
            while (!(tpm_lease.tryAcquire() catch return)) self.worker.yield();
            defer tpm_lease.release();
            if (check(self)) |_| {
                _ = self.documents.serviceForSigner(self.signer, self.now_ticks);
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
