//! One trusted local quote owner. Network input selects neither credentials nor
//! a TPM parent. Retain this owner, credentials, service and transport until
//! cancellation has drained; command buffers belong exclusively to the worker.
const std = @import("std");
const service_mod = @import("../platform/attestation_service.zig");
const attest = service_mod.tpm;
const tpm = @import("../platform/tpm2_sealing.zig");
const connections = @import("../sync/peer_connections.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const guarded = @import("../task/guarded_worker_stack.zig");
const tpm_lease = @import("../task/tpm_worker_lease.zig");

pub const Credentials = struct {
    enrollment: attest.Enrollment,
    parent: tpm.PersistentParent,
    blob: tpm.Blob,
    authorization: tpm.Key,
    expires_at_ticks: u64,
    active: bool = true,

    fn validate(self: *const Credentials, now: u64) !void {
        if (!self.active or now >= self.expires_at_ticks) return error.AttestationLeaseExpired;
        try self.enrollment.validate();
        try self.parent.validate();
        if (self.blob.len == 0 or self.blob.len > self.blob.bytes.len or
            !std.mem.allEqual(u8, self.blob.bytes[self.blob.len..], 0)) return error.InvalidBlob;
        if (std.mem.allEqual(u8, &self.authorization, 0)) return error.InvalidAuthorization;
    }

    pub fn revoke(self: *Credentials) void {
        self.active = false;
        std.crypto.secureZero(u8, &self.authorization);
    }
};

// All callbacks are bounded native-owner calls without hardware waits. Handles
// are copied; no connection or storage pointer survives a cooperative yield.
pub const Owner = struct {
    context: *anyopaque,
    next_fn: *const fn (*anyopaque, u64, usize) ?connections.Handle,
    challenge_fn: *const fn (*anyopaque, connections.Handle, u64) ?attest.Challenge,
    complete_fn: *const fn (*anyopaque, connections.Handle, *const attest.Response, u64) anyerror!void,
    release_fn: *const fn (*anyopaque, connections.Handle) void,
};

pub const Interface = struct {
    context: *anyopaque,
    operations: *const Operations,
    pub const Operations = struct {
        service: *const fn (*anyopaque, Owner, u64) bool,
        ready: *const fn (*anyopaque, Owner, u64) bool,
        next_wake: *const fn (*anyopaque) ?u64,
        quiesce: *const fn (*anyopaque) void,
    };
};

pub fn Worker(comptime Io: type) type {
    return struct {
        const Self = @This();
        io: *Io,
        credentials: *const Credentials,
        service: *service_mod.Service,
        stack: ?guarded.Stack = null,
        worker: cooperative.Worker = .{ .stack = &.{} },
        client: tpm.Client = .{},
        snapshot: Credentials = undefined,
        challenge: attest.Challenge = undefined,
        evidence: attest.Response = .{},
        handle: ?connections.Handle = null,
        last_tick: u64 = 0,
        next_poll: u64 = 0,
        cursor: usize = 0,
        failure: ?anyerror = null,
        cancellation: ?anyerror = null,
        last_failure: ?anyerror = null,

        comptime {
            if (@sizeOf(Self) > 4096) @compileError("peer quote worker exceeds bounded coordination state");
        }

        pub fn interface(self: *Self) Interface {
            return .{ .context = self, .operations = &operations };
        }
        const operations = Interface.Operations{ .service = serviceOnce, .ready = ready, .next_wake = nextWake, .quiesce = quiesce };

        pub fn busy(self: *const Self) bool {
            return self.worker.state == .suspended or self.worker.state == .running;
        }

        pub fn cancel(self: *Self) void {
            if (self.handle != null) self.cancellation = error.Cancelled;
            self.worker.cancel();
        }

        pub fn deinit(self: *Self) !void {
            self.cancel();
            if (self.busy()) return error.WorkerBusy;
            self.erase();
            if (self.stack) |*stack| stack.deinit();
            self.stack = null;
            self.worker = .{ .stack = &.{} };
        }

        pub fn start(self: *Self, owner: Owner, handle: connections.Handle, now: u64) !void {
            if (self.handle != null or self.busy()) return error.WorkerBusy;
            try self.credentials.validate(now);
            const challenge = owner.challenge_fn(owner.context, handle, now) orelse return error.StalePeerConnection;
            try self.service.validateTpmAttestationRequest(&self.credentials.enrollment, &challenge);
            if (self.stack == null) self.stack = try guarded.Stack.allocate();
            self.snapshot = self.credentials.*;
            self.challenge = challenge;
            self.evidence = .{};
            self.client = .{};
            self.handle = handle;
            self.last_tick = now;
            self.next_poll = now;
            self.failure = null;
            self.cancellation = null;
            self.last_failure = null;
            self.worker.stack = self.stack.?.bytes;
            errdefer self.erase();
            try self.worker.start(self, run);
        }

        pub fn poll(self: *Self, owner: Owner, now: u64) !bool {
            const handle = self.handle orelse return error.NoAttestationAttempt;
            if (now >= self.last_tick and now < self.next_poll) return false;
            if (self.cancellation == null) self.validate(owner, handle, now) catch |err| {
                self.cancellation = err;
                self.worker.cancel();
            };
            // After cancellation, use the observed cleanup tick so rollback
            // neither strands borrowed buffers nor permits repeated same-tick steps.
            self.last_tick = now;
            // Cancellation also respects transport ownership: step finishes an
            // active command and lets the client flush newly discovered handles.
            try self.worker.step();
            if (self.busy()) {
                self.next_poll = now +| 1;
                return false;
            }
            defer self.erase();
            if (self.cancellation) |err| return err;
            if (self.failure) |err| return err;
            try self.validate(owner, handle, now);
            const Publication = struct {
                owner: Owner,
                handle: connections.Handle,
                response: *const attest.Response,
                now: u64,
                pub fn publish(p: @This()) !void {
                    try p.owner.complete_fn(p.owner.context, p.handle, p.response, p.now);
                }
            };
            // No yield between current policy/nonce validation, handle delivery
            // and recording the visible request. Failed delivery consumes nothing.
            try self.service.finishTpmAttestationRequest(&self.snapshot.enrollment, &self.challenge, Publication{ .owner = owner, .handle = handle, .response = &self.evidence, .now = now });
            return true;
        }

        fn validate(self: *Self, owner: Owner, handle: connections.Handle, now: u64) !void {
            if (now < self.last_tick) return error.AttestationClockRollback;
            self.last_tick = now;
            try self.credentials.validate(now);
            if (!std.meta.eql(self.credentials.*, self.snapshot)) return error.AttestationCredentialsChanged;
            const current = owner.challenge_fn(owner.context, handle, now) orelse return error.StalePeerConnection;
            if (!std.meta.eql(current, self.challenge)) return error.AttestationChallengeChanged;
            try self.service.validateTpmAttestationRequest(&self.snapshot.enrollment, &self.challenge);
        }

        fn run(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.runExclusive() catch |err| {
                self.failure = err;
            };
        }

        fn runExclusive(self: *Self) !void {
            while (!try tpm_lease.tryAcquire()) self.worker.yield();
            defer tpm_lease.release();
            self.quote() catch |err| {
                self.failure = err;
            };
            try self.client.close(self.io);
        }

        fn quote(self: *Self) !void {
            if (self.worker.cancel_requested) return error.Cancelled;
            try self.client.openPersistent(self.io, self.snapshot.parent);
            const qualifying = self.challenge.qualifyingData();
            try self.client.quoteAttestation(self.io, self.snapshot.blob.slice(), &self.snapshot.authorization, &self.snapshot.enrollment.identity, &qualifying, &self.challenge.approved_pcr11, &self.evidence);
            if (self.worker.cancel_requested) return error.Cancelled;
        }

        fn erase(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(&self.snapshot));
            std.crypto.secureZero(u8, std.mem.asBytes(&self.challenge));
            std.crypto.secureZero(u8, std.mem.asBytes(&self.client));
            std.crypto.secureZero(u8, std.mem.asBytes(&self.evidence));
            self.handle = null;
            self.next_poll = 0;
        }

        fn serviceOnce(context: *anyopaque, owner: Owner, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.handle == null) {
                const handle = owner.next_fn(owner.context, self.credentials.enrollment.device.serial, self.cursor) orelse return false;
                self.cursor = (@as(usize, @intCast(@backingInt(handle) & 3)) + 1) % connections.MAX_CONNECTIONS;
                self.start(owner, handle, now) catch |err| {
                    self.last_failure = err;
                    owner.release_fn(owner.context, handle);
                };
                return true;
            }
            if (now >= self.last_tick and now < self.next_poll) return false;
            const handle = self.handle.?;
            _ = self.poll(owner, now) catch |err| {
                self.last_failure = err;
                owner.release_fn(owner.context, handle);
                // Context errors cannot abandon suspended command buffers.
                if (self.busy()) self.cancel();
                return true;
            };
            return true;
        }

        fn ready(context: *anyopaque, owner: Owner, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return if (self.handle != null) now < self.last_tick or now >= self.next_poll else owner.next_fn(owner.context, self.credentials.enrollment.device.serial, self.cursor) != null;
        }

        fn nextWake(context: *anyopaque) ?u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            return if (self.handle != null) self.next_poll else null;
        }

        // Exclusive teardown. Ordinary revocation cancels and keeps polling;
        // global reset drains before releasing the borrowed owner and transport.
        fn quiesce(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.cancel();
            while (self.busy()) self.worker.step() catch @panic("attestation worker teardown outside its owner context");
            self.erase();
        }
    };
}
