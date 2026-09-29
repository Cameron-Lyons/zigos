const std = @import("std");
const abi = @import("../core/abi.zig");
const component = @import("../kernel_api/component_port.zig");
const syscall = @import("../kernel_api/syscall_surface.zig");
const runtime_mod = @import("../task/task_runtime.zig");
const channel_mod = @import("identity_channel.zig");
const request_mod = @import("identity_request.zig");
const identity = @import("../platform/os_identity.zig");
const client_mod = @import("../../userspace/identity_client.zig");
const protocol = channel_mod.protocol;

const Fixture = struct {
    runtime: runtime_mod.Runtime = .init(),
    caps: @import("../kernel_api/capability.zig").CapabilityTable = .init(),
    endpoints: @import("../kernel_api/endpoint.zig").Table = .init(),
    shared: @import("../kernel_api/shared_memory.zig").Table = .init(),
    kernel: @import("../kernel_api/native_kernel.zig").Kernel = undefined,
    port: component.KernelPort = undefined,
    channel: channel_mod.Channel = .{},
    app: u64 = 0,
    service_task: u64 = 0,
    binding: protocol.Binding = undefined,
    client: client_mod.Client = .{},
    now: u64 = 10,
    allowed: bool = true,
    hold: bool = false,
    worker_busy: bool = false,
    starts: usize = 0,
    polls: usize = 0,
    cancels: usize = 0,
    cancelled: bool = false,
    cancellation_waits: usize = 0,
    challenge: [64]u8 = @splat(0),
    length: u8 = 0,

    fn init() !*Fixture {
        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);
        f.* = .{};
        f.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &f.runtime, &f.caps, &f.endpoints, &f.shared);
        errdefer f.kernel.deinit();
        f.port = component.KernelPort.init(&f.kernel);
        for (0..2) |index| {
            const task = try f.runtime.createTask(.{
                .owner = .{ .kind = if (index == 0) .app else .service, .serial = index + 10 },
                .component_class = if (index == 0) .app_component else .service_component,
                .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 4096, .endpoint_slots = 8, .shared_memory_bytes = 0 },
                .local_only = true,
            });
            if (index == 0) f.app = task.id else f.service_task = task.id;
            const cap = try f.caps.mintBootRoot(.{
                .holder = task.owner,
                .issuer = .{ .kind = .policy_authority, .serial = 1 },
                .target = .{ .kind = .service, .id = 1 },
                .rights = .{ .service = .{ .endpoint_create = true } },
                .scope = .{ .task_id = task.id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
            });
            try f.runtime.grantCapability(task.id, cap.id);
            f.runtime.allowHostPointerSyscallsForTask(task.id);
        }
        f.binding = try f.channel.open(&f.port, .{ .context = f, .authorized = authorized, .start = start, .poll = poll, .cancel = cancel }, f.app, f.service_task, .{ .credential_id = 9, .relying_party_id = "session.example", .origin = "https://session.example", .session = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) }, .expires_at_ticks = 100 }, f.now);
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.channel.close(f.now);
        f.kernel.deinit();
        std.testing.allocator.destroy(f);
    }
    fn authorized(context: *anyopaque, grant: request_mod.Grant, now: u64) bool {
        const f: *Fixture = @ptrCast(@alignCast(context));
        return f.allowed and now < grant.expires_at_ticks and grant.credential_id == 9 and grant.session.session_nonce[0] == 2;
    }
    fn start(context: *anyopaque, request: request_mod.Request, _: u64) !void {
        const f: *Fixture = @ptrCast(@alignCast(context));
        if (f.worker_busy) return error.WorkerBusy;
        f.starts += 1;
        f.length = @intCast(request.challenge.len);
        @memcpy(f.challenge[0..f.length], request.challenge);
    }
    fn poll(context: *anyopaque, _: u64) !?identity.Assertion {
        const f: *Fixture = @ptrCast(@alignCast(context));
        f.polls += 1;
        if (f.cancelled) {
            if (f.cancellation_waits != 0) {
                f.cancellation_waits -= 1;
                return null;
            }
            return error.Cancelled;
        }
        if (f.hold) return null;
        var assertion = identity.Assertion{
            .credential_id = 9,
            .owner = .{ .kind = .user, .serial = 1 },
            .device = .{ .kind = .device, .serial = 2 },
            .credential_generation = 1,
            .assertion_counter = 1,
            .relying_party_id_len = 15,
            .relying_party_id = @splat(0),
            .origin_len = 23,
            .origin = @splat(0),
            .challenge_len = f.length,
            .challenge = f.challenge,
            .signature = .{ .public_key = @splat(7), .value = @splat(8), .public_key_len = 32, .value_len = 64 },
            .local_unlock_verified = true,
            .phishing_resistant = true,
            .hardware_backed_credential = true,
            .device_platform_backed = false,
            .primary_device_assertion = true,
            .device_trust_generation = 1,
            .unlock_age_ticks = 5,
        };
        @memcpy(assertion.relying_party_id[0..15], "session.example");
        @memcpy(assertion.origin[0..23], "https://session.example");
        return assertion;
    }
    fn cancel(context: *anyopaque) void {
        const f: *Fixture = @ptrCast(@alignCast(context));
        if (!f.cancelled) f.cancels += 1;
        f.cancelled = true;
    }

    pub fn send(f: *Fixture, cap: u64, correlation: u64, bytes: []const u8) client_mod.SendResult {
        const request = component.EndpointSendRequest{ .header = component.makeHeader(.endpoint_send, f.app), .endpoint_capability_id = cap, .correlation_id = correlation, .payload = bytes };
        const result = syscall.dispatch(&f.port, f.app, f.now, request.header.operation, @intFromPtr(&request), 0, 0);
        return switch (result.status) {
            .success => .sent,
            .would_block => .busy,
            else => .failed,
        };
    }
    pub fn receive(f: *Fixture, cap: u64) client_mod.ReceiveResult {
        var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        var attached: abi.CapabilityDescriptor = undefined;
        var response: abi.EndpointRecvResponse = undefined;
        const request = component.EndpointRecvRequest{ .header = component.makeHeader(.endpoint_recv, f.app), .endpoint_capability_id = cap, .receiver_task_id = f.app, .payload_out = &bytes, .attached_capability_out = &attached };
        const result = syscall.dispatch(&f.port, f.app, f.now, request.header.operation, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(@TypeOf(response)));
        if (result.status != .success or response.has_attached_capability != 0) return .failed;
        if (response.present == 0) return .empty;
        return .{ .reply = .{ .sender_endpoint_id = response.message.sender_endpoint_id, .correlation_id = response.message.correlation_id, .length = response.message.payload_len, .bytes = bytes } };
    }
    fn frame(f: *Fixture, body: protocol.Body) !void {
        var out: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        try std.testing.expectEqual(client_mod.SendResult.sent, f.send(f.binding.endpoint_capability_id, 77, try protocol.encode(&out, .{ .request_id = 77, .body = body })));
    }
};

test "identity channel delivers one complete assertion through authenticated endpoint syscalls" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.client.begin(f.binding, 77, "challenge");
    for (0..30) |_| {
        f.now += 1;
        _ = f.client.step(f);
        _ = f.channel.service(f.now);
        if (!f.client.pending()) break;
        try std.testing.expect(f.client.result() == null);
    }
    const result = f.client.result() orelse return error.MissingAssertion;
    try std.testing.expectEqualStrings("challenge", result.challenge);
    try std.testing.expectEqualStrings("https://session.example", result.origin);
    try std.testing.expectEqual(@as(u64, 9), result.credential_id);
    try std.testing.expectEqual(@as(usize, 1), f.starts);
    try std.testing.expectEqual(@as(usize, 0), f.cancels);
    try std.testing.expect(f.channel.kernel == null);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&f.channel), 0));
}

test "identity channel cancels and erases pending work on lock expiry suspension and revocation" {
    for (0..7) |case| {
        const f = try Fixture.init();
        defer f.deinit();
        f.hold = true;
        try f.frame(.{ .assert = "challenge" });
        try std.testing.expect(f.channel.service(f.now));
        try std.testing.expect(f.channel.service(f.now));
        try std.testing.expect(f.channel.running);
        switch (case) {
            0 => f.allowed = false,
            1 => f.now = 100,
            2 => {
                _ = try f.runtime.suspendTask(f.app, f.now);
            },
            3 => try f.caps.revokeGrant(f.binding.endpoint_capability_id),
            4 => f.now = 9,
            5 => _ = try f.runtime.rehostTask(f.app, f.now),
            6 => _ = try f.runtime.rehostTask(f.service_task, f.now),
            else => return error.InvalidTestCase,
        }
        try std.testing.expect(f.channel.service(f.now));
        try std.testing.expectEqual(@as(usize, 1), f.cancels);
        try std.testing.expect(f.channel.kernel == null);
        try std.testing.expect(std.mem.allEqual(u8, &f.channel.result, 0));
    }
}

test "identity channel drains revocation incrementally without publishing a late result" {
    const f = try Fixture.init();
    defer f.deinit();
    f.hold = true;
    try f.frame(.{ .assert = "challenge" });
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    f.cancellation_waits = 3;
    f.allowed = false;
    for (0..3) |_| {
        f.now += 1;
        const polls = f.polls;
        try std.testing.expect(f.channel.service(f.now));
        try std.testing.expect(f.channel.kernel != null and f.channel.running and f.channel.retiring);
        try std.testing.expect(f.polls == polls + 1 and f.channel.result_len == 0);
    }
    f.now += 1;
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expect(f.channel.kernel == null and f.cancels == 1);
}

test "identity channel binds syscalls to the real caller and rejects malformed frames" {
    const f = try Fixture.init();
    defer f.deinit();
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const payload = try protocol.encode(&bytes, .{ .request_id = 77, .body = .{ .assert = "challenge" } });
    const forged = component.EndpointSendRequest{ .header = component.makeHeader(.endpoint_send, f.service_task), .endpoint_capability_id = f.channel.server_capability, .correlation_id = 77, .payload = payload };
    const denied = syscall.dispatch(&f.port, f.app, f.now, forged.header.operation, @intFromPtr(&forged), 0, 0);
    try std.testing.expect(denied.status != .success);
    try std.testing.expect(!f.channel.service(f.now));
    bytes[4] = 9;
    try std.testing.expectEqual(client_mod.SendResult.sent, f.send(f.binding.endpoint_capability_id, 77, payload));
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expectEqual(@as(usize, 0), f.starts);
    try std.testing.expect(f.channel.kernel == null);
}

test "identity channel withholds a blocked reply after native grant revocation" {
    const f = try Fixture.init();
    defer f.deinit();
    try f.frame(.{ .assert = "challenge" });
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    for (0..@import("../kernel_api/endpoint.zig").MAX_ENDPOINT_QUEUE) |_| try f.port.endpointSend(.{
        .header = component.makeHeader(.endpoint_send, f.service_task),
        .endpoint_capability_id = f.channel.server_capability,
        .reply_endpoint_id = f.channel.client_endpoint,
        .correlation_id = 55,
        .payload = "occupied",
    }, f.now);
    try std.testing.expect(!f.channel.service(f.now));
    try std.testing.expect(f.channel.outgoing_len != 0 and !f.channel.hasPendingWork());
    f.allowed = false;
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expect(f.channel.kernel == null and f.channel.outgoing_len == 0);
}

test "identity channel queues a busy worker and consumes its grant once" {
    const f = try Fixture.init();
    defer f.deinit();
    f.worker_busy = true;
    try f.frame(.{ .assert = "challenge" });
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expect(!f.channel.service(f.now));
    try std.testing.expect(!f.channel.hasPendingWork() and !f.channel.running and f.starts == 0);
    try std.testing.expectEqual(f.now + 1, f.channel.nextWake().?);
    f.worker_busy = false;
    f.now += 1;
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expect(f.channel.running and f.starts == 1 and f.channel.pending_len == 0);
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    try f.frame(.{ .assert = "replay" });
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expect(f.channel.kernel == null and f.starts == 1);
}

test "identity channel arms a wake instead of spinning on a suspended worker" {
    const f = try Fixture.init();
    defer f.deinit();
    f.hold = true;
    try f.frame(.{ .assert = "challenge" });
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    _ = f.channel.service(f.now);
    const polls = f.polls;
    for (0..5) |_| try std.testing.expect(!f.channel.service(f.now));
    try std.testing.expect(!f.channel.hasPendingWork() and f.polls == polls);
    try std.testing.expectEqual(f.now + 1, f.channel.nextWake().?);
    f.now += 1;
    try std.testing.expect(f.channel.service(f.now));
    try std.testing.expectEqual(polls + 1, f.polls);
}
