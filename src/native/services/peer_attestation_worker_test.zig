const std = @import("std");
const worker_mod = @import("peer_attestation_worker.zig");
const cooperative = @import("../task/cooperative_worker.zig");
const service_mod = @import("../platform/attestation_service.zig");
const attest = service_mod.tpm;
const quote = @import("../platform/tpm2_quote.zig");
const connections = @import("../sync/peer_connections.zig");
const Io = struct {
    calls: usize = 0,
    borrowed_checked: bool = false,
    yields: usize = 1,
    pub fn random(_: *@This(), out: []u8) !void {
        @memset(out, 0x49);
    }
    pub fn execute(self: *@This(), command: []const u8, response: []u8, _: u32) ![]u8 {
        var before: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(command, &before, .{});
        @memset(response, 0xa7);
        self.calls += 1;
        for (0..self.yields) |_| cooperative.current().?.yield();
        var after: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(command, &after, .{});
        try std.testing.expectEqualSlices(u8, &before, &after);
        try std.testing.expect(std.mem.allEqual(u8, response, 0xa7));
        self.borrowed_checked = true;
        return error.HardwareUnavailable;
    }
};
const Fixture = struct {
    challenge: attest.Challenge,
    handle: connections.Handle = @fromBackingInt(@intCast(5)),
    alive: bool = true,
    publications: usize = 0,
    releases: usize = 0,
    fn init() !struct { owner: Fixture, credentials: worker_mod.Credentials } {
        const evidence = try quote.testing.QuoteFixture.initFor(@splat(1), @splat(2));
        const enrolled = try attest.Enrollment.init(.{ .kind = .device, .serial = 22 }, evidence.identity, 2, "worker-root");
        var io = Io{};
        var pending = try attest.Pending.init(&io, enrolled, @splat(2), .{ .remote_party = "worker.peer", .policy_label = "worker-policy" }, 200, 1000);
        try pending.bindChannel(@splat(3), 200);
        var credentials = worker_mod.Credentials{ .enrollment = enrolled, .parent = .{ .handle = 0x8100_7020, .name = quote.objectName("parent") }, .blob = .{ .len = 1 }, .authorization = @splat(0x57), .expires_at_ticks = 100 };
        credentials.blob.bytes[0] = 1;
        return .{ .owner = .{ .challenge = pending.challenge }, .credentials = credentials };
    }
    fn owner(self: *Fixture) worker_mod.Owner {
        return .{ .context = self, .next_fn = next, .challenge_fn = get, .complete_fn = complete, .release_fn = release };
    }
    fn next(context: *anyopaque, device: u64, _: usize) ?connections.Handle {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return if (self.alive and device == 22) self.handle else null;
    }
    fn get(context: *anyopaque, handle: connections.Handle, _: u64) ?attest.Challenge {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return if (self.alive and handle == self.handle) self.challenge else null;
    }
    fn complete(context: *anyopaque, handle: connections.Handle, _: *const attest.Response, _: u64) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (!self.alive or handle != self.handle) return error.StalePeerConnection;
        self.publications += 1;
    }
    fn release(context: *anyopaque, handle: connections.Handle) void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (self.handle != handle) return;
        self.alive = false;
        self.releases += 1;
    }
};

test "peer attestation worker rejects invalid local authority before allocation or hardware" {
    for (0..5) |fault| {
        var f = try Fixture.init();
        var service = service_mod.Service.init(f.credentials.enrollment.device);
        var io = Io{};
        var worker = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
        defer worker.deinit() catch unreachable;
        switch (fault) {
            0 => f.credentials.revoke(),
            1 => f.credentials.expires_at_ticks = 20,
            2 => f.owner.alive = false,
            3 => f.owner.challenge.request.attestation_verifier_metadata_digest[0] ^= 1,
            4 => try service.revokeRootGeneration(2),
            else => unreachable,
        }
        if (worker.start(f.owner.owner(), f.owner.handle, 20)) |_| return error.InvalidQuoteJobAdmitted else |_| {}
        try std.testing.expect(worker.stack == null and worker.handle == null and io.calls == 0);
        try std.testing.expectEqual(@as(u64, 0), service.visible_request_count);
    }
}

test "peer attestation worker drains borrowed buffers through cancellation revocation expiry and stale handles" {
    for (0..8) |fault| {
        var f = try Fixture.init();
        var service = service_mod.Service.init(f.credentials.enrollment.device);
        var io = Io{};
        var worker = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
        defer worker.deinit() catch unreachable;
        try worker.start(f.owner.owner(), f.owner.handle, 20);
        try std.testing.expect(!try worker.poll(f.owner.owner(), 20));
        try std.testing.expect(worker.busy() and io.calls == 1 and !io.borrowed_checked);
        try std.testing.expectError(error.WorkerBusy, worker.start(f.owner.owner(), f.owner.handle, 21));
        var now: u64 = 21;
        const expected: anyerror = switch (fault) {
            0 => blk: {
                worker.cancel();
                break :blk error.Cancelled;
            },
            1 => blk: {
                f.credentials.revoke();
                break :blk error.AttestationLeaseExpired;
            },
            2 => blk: {
                now = 100;
                break :blk error.AttestationLeaseExpired;
            },
            3 => blk: {
                f.owner.handle = @fromBackingInt(@intCast(9));
                break :blk error.StalePeerConnection;
            },
            4 => blk: {
                f.credentials.blob.bytes[0] ^= 1;
                break :blk error.AttestationCredentialsChanged;
            },
            5 => blk: {
                try service.revokeRootGeneration(2);
                break :blk error.RootGenerationRevoked;
            },
            6 => blk: {
                now = 19;
                break :blk error.AttestationClockRollback;
            },
            else => error.HardwareUnavailable,
        };
        try std.testing.expectError(expected, worker.poll(f.owner.owner(), now));
        try std.testing.expect(io.borrowed_checked and !worker.busy() and worker.handle == null);
        try std.testing.expect(std.mem.allEqual(u8, worker.stack.?.bytes, 0));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&worker.snapshot), 0));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&worker.client), 0));
        try std.testing.expectEqual(@as(usize, 0), f.owner.publications);
        try std.testing.expectEqual(@as(u64, 0), service.visible_request_count);
        try std.testing.expectEqual(@as(u8, 0), service.remote_nonce_history_count);
    }
}

test "peer attestation worker scheduler avoids polling twice per tick and retires failed jobs" {
    var f = try Fixture.init();
    var service = service_mod.Service.init(f.credentials.enrollment.device);
    var io = Io{};
    var worker = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
    defer worker.deinit() catch unreachable;
    const interface = worker.interface();
    const owner = f.owner.owner();
    try std.testing.expect(interface.operations.ready(interface.context, owner, 20));
    try std.testing.expect(interface.operations.service(interface.context, owner, 20));
    try std.testing.expectEqual(@as(usize, 0), io.calls);
    try std.testing.expect(interface.operations.service(interface.context, owner, 20));
    try std.testing.expectEqual(@as(?u64, 21), interface.operations.next_wake(interface.context));
    for (0..8) |_| {
        try std.testing.expect(!interface.operations.ready(interface.context, owner, 20));
        try std.testing.expect(!interface.operations.service(interface.context, owner, 20));
        try std.testing.expect(!try worker.poll(owner, 20));
    }
    try std.testing.expectEqual(@as(usize, 1), io.calls);
    try std.testing.expect(interface.operations.service(interface.context, owner, 21));
    try std.testing.expectEqual(error.HardwareUnavailable, worker.last_failure.?);
    try std.testing.expect(f.owner.releases == 1 and !worker.busy());
    try std.testing.expect(interface.operations.next_wake(interface.context) == null);
    try std.testing.expect(!interface.operations.ready(interface.context, owner, 22));
}

test "peer attestation worker detach drains before freeing stacks and preserves unpublished history" {
    var f = try Fixture.init();
    var service = service_mod.Service.init(f.credentials.enrollment.device);
    var io = Io{};
    var worker = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
    defer worker.deinit() catch unreachable;
    try worker.start(f.owner.owner(), f.owner.handle, 20);
    try std.testing.expect(!try worker.poll(f.owner.owner(), 20));
    try std.testing.expectError(error.WorkerBusy, worker.deinit());
    try std.testing.expect(!io.borrowed_checked);
    const manager_mod = @import("../session/session_manager.zig");
    manager_mod.testing.resetState();
    defer manager_mod.testing.resetState();
    const manager = manager_mod.system();
    manager.bindPeerAttestationWorker(worker.interface());
    try std.testing.expectEqual(@as(?u64, 21), manager.nextServiceWake());
    manager.reset();
    try std.testing.expect(io.borrowed_checked and !worker.busy() and worker.handle == null);
    try std.testing.expect(manager.peer_quote_worker == null);
    try std.testing.expectEqual(@as(u64, 0), service.visible_request_count);
    try std.testing.expect(std.mem.allEqual(u8, worker.stack.?.bytes, 0));
}

test "peer attestation publication checks current policy and commits history only after delivery" {
    var f = try Fixture.init();
    var service = service_mod.Service.init(f.credentials.enrollment.device);
    const Publication = struct {
        fail: bool,
        pub fn publish(self: @This()) !void {
            if (self.fail) return error.StalePeerConnection;
        }
    };
    try std.testing.expectError(error.StalePeerConnection, service.finishTpmAttestationRequest(&f.credentials.enrollment, &f.owner.challenge, Publication{ .fail = true }));
    try std.testing.expectEqual(@as(u64, 0), service.visible_request_count);
    try std.testing.expectEqual(@as(u8, 0), service.remote_nonce_history_count);
    try service.finishTpmAttestationRequest(&f.credentials.enrollment, &f.owner.challenge, Publication{ .fail = false });
    try std.testing.expectError(error.RemoteNonceReplay, service.finishTpmAttestationRequest(&f.credentials.enrollment, &f.owner.challenge, Publication{ .fail = false }));
    try std.testing.expectEqual(@as(u64, 1), service.visible_request_count);
}

test "peer attestation workers serialize complete TPM jobs and queued cancellation never touches another borrow" {
    var f = try Fixture.init();
    var second = try Fixture.init();
    var service = service_mod.Service.init(f.credentials.enrollment.device);
    var io = Io{};
    var other_io = Io{};
    var a = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
    defer a.deinit() catch unreachable;
    var b = worker_mod.Worker(Io){ .io = &other_io, .credentials = &second.credentials, .service = &service };
    defer b.deinit() catch unreachable;
    try a.start(f.owner.owner(), f.owner.handle, 20);
    try std.testing.expect(!try a.poll(f.owner.owner(), 20));
    const lease = @import("../task/tpm_worker_lease.zig");
    try std.testing.expect(!lease.allowsCurrent());
    try b.start(second.owner.owner(), second.owner.handle, 20);
    try std.testing.expect(!try b.poll(second.owner.owner(), 20));
    try std.testing.expectEqual(@as(usize, 0), other_io.calls);
    b.cancel();
    try std.testing.expectError(error.Cancelled, b.poll(second.owner.owner(), 21));
    try std.testing.expect(!lease.allowsCurrent() and a.busy() and !io.borrowed_checked);
    try std.testing.expectError(error.HardwareUnavailable, a.poll(f.owner.owner(), 21));
    try std.testing.expect(lease.allowsCurrent() and io.borrowed_checked);
    try b.start(second.owner.owner(), second.owner.handle, 22);
    try std.testing.expect(!try b.poll(second.owner.owner(), 22));
    try std.testing.expectEqual(@as(usize, 1), other_io.calls);
    try std.testing.expectError(error.HardwareUnavailable, b.poll(second.owner.owner(), 23));
    try std.testing.expect(lease.allowsCurrent());
}

test "peer attestation worker binding runs outside packet dispatch and detaches on boot failure" {
    const Mock = struct {
        steps: usize = 0,
        drains: usize = 0,
        fn service(context: *anyopaque, _: worker_mod.Owner, _: u64) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.steps += 1;
            return true;
        }
        fn ready(_: *anyopaque, _: worker_mod.Owner, _: u64) bool {
            return true;
        }
        fn nextWake(_: *anyopaque) ?u64 {
            return 24;
        }
        fn quiesce(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.drains += 1;
        }
        const operations = worker_mod.Interface.Operations{ .service = service, .ready = ready, .next_wake = nextWake, .quiesce = quiesce };
    };
    var mock = Mock{};
    const manager_mod = @import("../session/session_manager.zig");
    manager_mod.testing.resetState();
    defer manager_mod.testing.resetState();
    const manager = manager_mod.system();
    manager.bindPeerAttestationWorker(.{ .context = &mock, .operations = &Mock.operations });
    _ = manager.servicePeerWork(20);
    try std.testing.expectEqual(@as(usize, 0), mock.steps);
    try std.testing.expect(manager.userspaceSchedulerHasReadyTasks());
    try std.testing.expect(manager.runUserspaceScheduler(20));
    try std.testing.expectEqual(@as(usize, 1), mock.steps);
    try std.testing.expectEqual(@as(?u64, 24), manager.nextServiceWake());
    manager.failBoot();
    try std.testing.expectEqual(@as(usize, 1), mock.drains);
    try std.testing.expect(manager.peer_quote_worker == null);
}

test "peer attestation cancelled cleanup observes later clock rollback without stranding buffers" {
    var f = try Fixture.init();
    var service = service_mod.Service.init(f.credentials.enrollment.device);
    var io = Io{ .yields = 3 };
    var worker = worker_mod.Worker(Io){ .io = &io, .credentials = &f.credentials, .service = &service };
    defer worker.deinit() catch unreachable;
    try worker.start(f.owner.owner(), f.owner.handle, 20);
    try std.testing.expect(!try worker.poll(f.owner.owner(), 20));
    worker.cancel();
    try std.testing.expect(!try worker.poll(f.owner.owner(), 100));
    try std.testing.expect(worker.busy() and !io.borrowed_checked);
    try std.testing.expect(!try worker.poll(f.owner.owner(), 99));
    for (0..8) |_| try std.testing.expect(!try worker.poll(f.owner.owner(), 99));
    try std.testing.expect(worker.busy() and !io.borrowed_checked);
    try std.testing.expectError(error.Cancelled, worker.poll(f.owner.owner(), 100));
    try std.testing.expect(io.borrowed_checked and !worker.busy() and worker.handle == null);
    try std.testing.expect(std.mem.allEqual(u8, worker.stack.?.bytes, 0));
}
