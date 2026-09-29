//! Asynchronous owner of one trusted first-user operation. All borrowed stores,
//! policy and transport stay alive and serialized until cancellation completes.
const std = @import("std");
const provisioning = @import("identity_provisioning.zig");
const record = @import("identity_recovery_record.zig");
const entry = @import("../platform/trusted_setup_entry.zig");
const recovery_key = @import("../platform/recovery_key.zig");
const pin = @import("../platform/tpm2_pin.zig");
const catalog = @import("../storage/vault_catalog.zig");
const storage_mod = @import("../storage/storage_service.zig");
const policy = @import("../policy/policy_object.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const guarded = @import("../task/guarded_worker_stack.zig");
const lease = @import("../task/tpm_worker_lease.zig");

pub fn Worker(comptime Io: type) type {
    return struct {
        const Self = @This();
        io: *Io,
        storage: *storage_mod.Service,
        state: catalog.State,
        policies: *const policy.Directory,
        request: provisioning.Request,
        scratch: *[catalog.MAX_BYTES]u8,
        max_duration_ticks: u64,
        stack: ?guarded.Stack = null,
        worker: cooperative.Worker = .{ .stack = &.{} },
        operation: ?enum { load, prepare, commit } = null,
        value: [32]u8 = @splat(0),
        value_len: usize = 0,
        recovery_record: record.Record = .{},
        result: entry.Result = .{},
        failure: ?anyerror = null,
        cancellation: ?anyerror = null,
        started_at: u64 = 0,
        last_tick: u64 = 0,
        deadline: u64 = 0,

        pub fn backend(self: *Self) entry.Backend {
            return .{ .context = self, .start_load = startLoad, .start_prepare = startPrepare, .start_commit = startCommit, .poll = poll, .cancel = cancel, .busy = busy };
        }

        pub fn deinit(self: *Self) !void {
            cancel(self);
            if (busy(self)) return error.WorkerBusy;
            self.erase();
            if (self.stack) |*stack| stack.deinit();
            self.stack = null;
            self.worker = .{ .stack = &.{} };
        }

        fn busy(context: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.worker.state == .running or self.worker.state == .suspended;
        }

        fn cancel(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.operation != null) self.cancellation = error.Cancelled;
            self.worker.cancel();
            if (!busy(self)) self.erase();
        }

        fn prepare(self: *Self, now: u64) !void {
            if (self.operation != null or busy(self)) return error.WorkerBusy;
            if (self.max_duration_ticks == 0) return error.InvalidLease;
            const deadline = std.math.add(u64, now, self.max_duration_ticks) catch return error.InvalidLease;
            if (self.stack == null) self.stack = try guarded.Stack.allocate();
            self.worker.stack = self.stack.?.bytes;
            self.failure = null;
            self.cancellation = null;
            self.started_at = now;
            self.last_tick = now;
            self.deadline = deadline;
        }

        fn startLoad(context: *anyopaque, now: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.prepare(now);
            errdefer self.erase();
            self.operation = .load;
            try self.worker.start(self, run);
        }

        fn startPrepare(context: *anyopaque, value: []const u8, now: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try pin.validatePin(value);
            try self.prepare(now);
            errdefer self.erase();
            // Cancelled preparation may leave encrypted candidate objects. A
            // new attempt uses fresh IDs rather than replacing a retained card.
            if (self.request.record_object_id == 0 or self.request.catalog_object_id == 0 or
                self.storage.latestVersion(self.request.record_object_id) != null or self.storage.latestVersion(self.request.catalog_object_id) != null)
            {
                const next = self.storage.store.next_object_id;
                if (next == 0 or next == std.math.maxInt(u64)) return error.ObjectIdExhausted;
                self.request.catalog_object_id = next;
                self.request.record_object_id = next + 1;
            }
            @memcpy(self.value[0..value.len], value);
            self.value_len = value.len;
            self.operation = .prepare;
            try self.worker.start(self, run);
        }

        fn startCommit(context: *anyopaque, recovery_record: *const record.Record, now: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try recovery_record.validate();
            try self.prepare(now);
            errdefer self.erase();
            self.recovery_record = recovery_record.*;
            self.operation = .commit;
            try self.worker.start(self, run);
        }

        fn poll(context: *anyopaque, now: u64) !entry.Result {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.operation == null) return error.NoSetupAttempt;
            if (now < self.last_tick or now >= self.deadline) {
                self.cancellation = error.SetupExpired;
                self.worker.cancel();
            }
            self.last_tick = now;
            try self.worker.step();
            if (busy(self)) return .{};
            defer self.erase();
            if (self.cancellation) |err| return err;
            if (self.failure) |err| return err;
            return self.result;
        }

        fn run(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            defer std.crypto.secureZero(u8, &self.value);
            defer self.value_len = 0;
            defer self.recovery_record.erase();
            while (!(lease.tryAcquire() catch |err| {
                self.failure = err;
                return;
            })) self.worker.yield();
            defer lease.release();
            self.execute() catch |err| {
                self.result.erase();
                self.failure = err;
            };
        }

        fn execute(self: *Self) !void {
            if (self.worker.cancel_requested) return error.Cancelled;
            switch (self.operation.?) {
                .prepare => {
                    if (self.request.device.serial == 0) {
                        var serial: [8]u8 = undefined;
                        try self.io.random(&serial);
                        self.request.device.serial = std.mem.readInt(u64, &serial, .big);
                        if (self.request.device.serial == 0) return error.EntropyUnavailable;
                    }
                    try recovery_key.generate(self.io, &self.recovery_record.key);
                    self.recovery_record.trusted = try provisioning.prepare(self.io, self.storage, self.state, self.policies, self.request, self.value[0..self.value_len], &self.recovery_record.key, self.started_at, self.scratch);
                    if (self.worker.cancel_requested) return error.Cancelled;
                    // Once a user can save the recovery record, its encrypted
                    // candidate must already survive power loss. Permanent TPM
                    // changes still wait for separate recovery confirmation.
                    _ = try self.storage.checkpointDurable();
                    _ = try provisioning.load(self.storage, self.recovery_record.trusted);
                    self.result = .{ .kind = .prepared, .recovery_record = self.recovery_record };
                },
                .commit => {
                    const bundle = try provisioning.load(self.storage, self.recovery_record.trusted);
                    const enrolled = bundle.identity.enrollment;
                    if (!enrolled.owner.eql(self.request.owner) or enrolled.parent.handle != self.request.parent_handle or
                        enrolled.anchor_index != self.request.anchor_index or bundle.boot_index != self.request.boot_index) return error.RecoveryEnrollmentChanged;
                    self.result = .{ .kind = .committed, .identity = try provisioning.commit(self.io, self.storage, self.recovery_record.trusted, &self.recovery_record.key, self.scratch), .trusted = self.recovery_record.trusted };
                },
                .load => {
                    if (provisioning.loadBoot(self.io, self.storage, self.request.boot_index)) |loaded| {
                        self.result = .{ .kind = .loaded, .identity = loaded.bundle.identity, .trusted = loaded.trusted };
                    } else |err| {
                        if (err != error.NvIndexMissing and err != error.BootPinIncomplete) return err;
                        self.result = .{ .kind = if (err == error.NvIndexMissing) .fresh else .incomplete };
                    }
                },
            }
            if (self.worker.cancel_requested) return error.Cancelled;
        }

        fn erase(self: *Self) void {
            std.crypto.secureZero(u8, &self.value);
            self.value_len = 0;
            self.recovery_record.erase();
            self.result.erase();
            self.operation = null;
            self.deadline = 0;
        }

        comptime {
            if (@sizeOf(Self) > 4096) @compileError("setup worker exceeds bounded coordination state");
        }
    };
}

test "identity setup worker preserves command borrows and erases cancelled or expired work" {
    const Io = struct {
        calls: usize = 0,
        pub fn random(_: *@This(), out: []u8) !void {
            @memset(out, 9);
        }
        pub fn execute(self: *@This(), command: []const u8, _: []u8, _: u32) ![]u8 {
            const first = command[0];
            self.calls += 1;
            cooperative.current().?.yield();
            if (first != command[0] or first == 0) return error.OverwrittenCommand;
            if (cooperative.current().?.cancel_requested) return error.Cancelled;
            return error.HardwareUnavailable;
        }
    };
    var io = Io{};
    const disk = try @import("../storage/document_save_test.zig").Fixture.init(true);
    defer disk.deinit();
    var vault = @import("secret_vault_service.zig").Service.init();
    var identities = @import("../platform/os_identity.zig").Store.init();
    var graph = @import("../sync/device_graph.zig").Graph.init();
    var policies = policy.Directory.init();
    var scratch: [catalog.MAX_BYTES]u8 = undefined;
    var worker = Worker(Io){ .io = &io, .storage = &disk.service, .state = .{ .vault = &vault, .identities = &identities, .devices = &graph }, .policies = &policies, .request = .{ .owner = .{ .kind = .user, .serial = 1 }, .device = .{ .kind = .device, .serial = 2 }, .catalog_object_id = 1000, .record_object_id = 1001, .parent_handle = 0x8100_1234, .anchor_index = 0x0180_1234, .boot_index = 0x0180_1235, .max_session_ticks = 100 }, .scratch = &scratch, .max_duration_ticks = 20 };
    defer worker.deinit() catch unreachable;
    const backend = worker.backend();
    try std.testing.expectError(error.InvalidPin, backend.start_prepare(backend.context, "12345x", 1));
    try std.testing.expect(worker.stack == null and io.calls == 0);
    for (0..3) |variant| {
        try backend.start_prepare(backend.context, "12345678", 1);
        const result = try backend.poll(backend.context, 1);
        try std.testing.expect(result.kind == .pending and backend.busy(backend.context));
        try std.testing.expectError(error.WorkerBusy, backend.start_prepare(backend.context, "12345678", 2));
        if (variant == 0) {
            try std.testing.expectError(error.WorkerBusy, worker.deinit());
            try std.testing.expectError(error.Cancelled, backend.poll(backend.context, 2));
        } else if (variant == 1) {
            try std.testing.expectError(error.SetupExpired, backend.poll(backend.context, 21));
        } else try std.testing.expectError(error.HardwareUnavailable, backend.poll(backend.context, 2));
        try std.testing.expect(!backend.busy(backend.context));
        try std.testing.expect(std.mem.allEqual(u8, &worker.value, 0));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&worker.recovery_record), 0));
        try std.testing.expect(std.mem.allEqual(u8, worker.stack.?.bytes, 0));
        try std.testing.expect(vault.store.empty());
    }
}
