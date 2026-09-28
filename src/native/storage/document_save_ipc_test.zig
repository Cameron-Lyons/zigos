const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");
const storage_service = @import("storage_service.zig");
const workspace = @import("workspace.zig");
const durable = @import("document_save_test.zig");
const ipc = @import("document_save_ipc.zig");
const document_channel = @import("document_channel.zig");
const protocol = ipc.protocol;
const Client = @import("../../userspace/document_client.zig").Client;

test "clipboard document authorization rechecks signed workspace policy and existing read write grants" {
    const document_sessions = @import("../session/document_sessions.zig");
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channel.close(0);
    var sessions = document_sessions.Sessions{};
    defer sessions.deinit(0);
    _ = try sessions.open(&fixture.port, &fixture.device.service, fixture.open_request, 0);
    // The default signing fixture authorizes its key, not clipboard access.
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, false, 10));
    sessions.closeTask(fixture.app_task_id, 0);
    fixture.open_request.signer = try fixture.signing_fixture.initWithClipboard(
        .{ .kind = .user, .serial = 1 },
        fixture.device.service.owner,
        fixture.device.service.task_id,
        durable.signer,
        true,
    );
    _ = try sessions.open(&fixture.port, &fixture.device.service, fixture.open_request, 0);
    try std.testing.expect(sessions.allowsClipboard(fixture.app_task_id, false, 10));
    try std.testing.expect(sessions.allowsClipboard(fixture.app_task_id, true, 10));
    try std.testing.expect(sessions.allowsClipboard(fixture.app_task_id, false, 100));
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, false, 101));
    _ = try fixture.signing_fixture.policies.create(.{
        .scope = .workspace,
        .subject_id = fixture.device.workspace_id,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "private workspace",
        .clipboard_allowed = false,
    }, durable.signer);
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, false, 10));
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, true, 10));
    // Removing the restrictive overlay still cannot revive revoked authority.
    fixture.signing_fixture.policies = .init();
    try fixture.capabilities.revokeGrant(fixture.write_capability);
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, false, 10));
    try std.testing.expect(!sessions.allowsClipboard(fixture.app_task_id, true, 10));
}

const Fixture = struct {
    device: *durable.Fixture,
    signing_fixture: @import("../../tests/fixtures/document_signer.zig").Fixture = .{},
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    channel: document_channel.Channel = .{},
    server: *ipc.Server = undefined,
    open_request: document_channel.OpenRequest = undefined,
    client: Client = undefined,
    app_task_id: u64 = 0,
    app_endpoint_id: u64 = 0,
    app_endpoint_capability: u64 = 0,
    server_endpoint_id: u64 = 0,
    write_capability: u64 = 0,

    fn init() !*Fixture {
        const device = try durable.Fixture.init(true);
        errdefer device.deinit();
        const self = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(self);
        self.* = .{ .device = device };
        self.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &self.runtime, &self.capabilities, &self.endpoints, &self.shared);
        self.port = component_port.KernelPort.init(&self.kernel);
        const app = try self.runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = 77 },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 4096, .endpoint_slots = 4, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        const service = try self.runtime.createTask(.{
            .owner = device.service.owner,
            .component_class = .service_component,
            .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 4096, .endpoint_slots = 4, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        device.service.task_id = service.id;
        self.app_task_id = app.id;
        self.runtime.allowHostPointerSyscallsForTask(app.id);
        const write = try self.capabilities.mintBootRoot(.{
            .holder = app.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .workspace, .id = device.workspace_id },
            .rights = .{ .workspace = .{ .object_read = true, .object_write = true } },
            .scope = .{ .task_id = app.id, .workspace_id = device.workspace_id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        self.write_capability = write.id;
        try self.runtime.grantCapability(app.id, write.id);
        try device.service.shareWorkspace(device.workspace_id, try (workspace.ShareGrant{
            .principal_id = app.owner,
            .can_read = true,
            .can_write = true,
            .expires_at_ticks = 100,
            .network_scope = .local_only,
        }).withObjectScope(ids.object(900), durable.path));
        self.open_request = .{
            .authority = .{ .task_id = app.id, .principal = app.owner, .capability_id = write.id, .now_ticks = 0 },
            .client_bootstrap_capability_id = try self.bootstrapCapability(app),
            .server_bootstrap_capability_id = try self.bootstrapCapability(service),
            .workspace_id = device.workspace_id,
            .path = durable.path,
            .signer = try self.signing_fixture.init(.{ .kind = .user, .serial = 1 }, service.owner, service.id, durable.signer),
        };
        const binding = try self.channel.open(&self.port, &device.service, self.open_request, 0);
        self.server = &self.channel.server.?;
        self.app_endpoint_id = self.channel.client_endpoint_id;
        self.server_endpoint_id = binding.service_endpoint_id;
        self.app_endpoint_capability = binding.endpoint_capability_id;
        self.client = .{ .service_endpoint_id = binding.service_endpoint_id, .object_id = binding.object_id, .version_id = binding.version_id };
        return self;
    }

    fn bootstrapCapability(self: *Fixture, task: *task_runtime.TaskRecord) !u64 {
        const grant = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .service, .id = self.device.service.service_id },
            .rights = .{ .service = .{ .endpoint_create = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        try self.runtime.grantCapability(task.id, grant.id);
        return grant.id;
    }

    fn deinit(self: *Fixture) void {
        self.channel.close(99);
        self.kernel.deinit();
        self.device.deinit();
        std.testing.allocator.destroy(self);
    }

    fn send(self: *Fixture, bytes: []const u8, request_id: u64) !void {
        const request = component_port.EndpointSendRequest{
            .header = component_port.makeHeader(.endpoint_send, self.app_task_id),
            .correlation_id = request_id,
            .endpoint_capability_id = self.app_endpoint_capability,
            .payload = bytes,
        };
        const result = syscall_surface.dispatch(&self.port, self.app_task_id, 10, request.header.operation, @intFromPtr(&request), 0, 0);
        try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    }

    fn sendFrame(self: *Fixture, body: protocol.Body) !void {
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        try self.send(try protocol.encode(&bytes, .{ .request_id = self.client.request_id, .body = body }), self.client.request_id);
        try std.testing.expect(try self.server.runOnce(10));
    }

    fn submit(self: *Fixture) !void {
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        while (try self.client.nextFrame(&bytes)) |frame| {
            try self.send(frame, self.client.request_id);
            self.client.sent();
            try std.testing.expect(try self.server.runOnce(10));
        }
    }

    fn receive(self: *Fixture, deliver: bool) !abi.EndpointRecvResult {
        var out = std.mem.zeroes(abi.EndpointRecvResult);
        var response: abi.EndpointRecvResponse = undefined;
        const request = component_port.EndpointRecvRequest{
            .header = component_port.makeHeader(.endpoint_recv, self.app_task_id),
            .endpoint_capability_id = self.app_endpoint_capability,
            .receiver_task_id = self.app_task_id,
            .payload_out = &out.payload,
            .attached_capability_out = &out.attached_capability,
        };
        try std.testing.expectEqual(abi.SyscallStatus.success, syscall_surface.dispatch(&self.port, self.app_task_id, 10, request.header.operation, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointRecvResponse)).status);
        out.present = response.present;
        out.message = response.message;
        if (deliver) {
            try std.testing.expectEqual(@as(u8, 1), out.present);
            try std.testing.expect(self.client.accept(out.message.sender_endpoint_id, out.message.correlation_id, out.payload[0..out.message.payload_len]));
        }
        return out;
    }
};

test "document IPC saves a full bounded draft durably through client syscalls" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var text: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined;
    for (&text, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);
    try fixture.client.start(&text);
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.saved, fixture.client.last_status.?);
    try std.testing.expectEqualStrings(&text, fixture.client.acknowledgedText().?);
    fixture.device.crash();
    try std.testing.expectEqualStrings(&text, try fixture.device.text());
    try std.testing.expectEqual(fixture.client.version_id, (try fixture.device.service.resolve(fixture.device.workspace_id, durable.path)).version_id.raw());
}

test "document IPC loads bounded immutable versions and empty documents before saving" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var full: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined;
    for (&full, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);
    for ([_][]const u8{ &full, "" }) |text| {
        try fixture.client.start(text);
        try fixture.submit();
        _ = try fixture.receive(true);
        try fixture.client.open();
        var frames: usize = 0;
        while (fixture.client.phase != .loaded and frames < (protocol.MAX_DOCUMENT_BYTES + protocol.READ_CHUNK_BYTES - 1) / protocol.READ_CHUNK_BYTES) : (frames += 1) {
            try fixture.submit();
            _ = try fixture.receive(true);
        }
        try std.testing.expectEqual(.loaded, fixture.client.phase);
        try std.testing.expectEqualStrings(text, fixture.client.finishOpen().?);
        try std.testing.expect(fixture.client.finishOpen() == null);
    }
}

test "document IPC rejects a version change or revoked read midway through loading" {
    const full = [_]u8{'a'} ** protocol.MAX_DOCUMENT_BYTES;
    for ([_]bool{ false, true }) |revoke| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.client.start(&full);
        try fixture.submit();
        _ = try fixture.receive(true);
        try fixture.client.open();
        try fixture.submit();
        _ = try fixture.receive(true);
        try std.testing.expect(fixture.client.finishOpen() == null);
        if (revoke) {
            try fixture.capabilities.revokeGrant(fixture.write_capability);
        } else {
            var other_editor = @import("document_save.zig").Session{};
            _ = try other_editor.saveForVerification(&fixture.device.service, .{
                .workspace_id = fixture.device.workspace_id,
                .path = durable.path,
                .expected_version_id = fixture.client.version_id,
                .payload = "changed while loading",
                .signer = durable.signer,
                .tick = 10,
            });
        }
        try fixture.submit();
        _ = try fixture.receive(true);
        try std.testing.expectEqual(if (revoke) protocol.Status.permission_denied else protocol.Status.document_changed, fixture.client.last_status.?);
        try std.testing.expect(fixture.client.finishOpen() == null);
    }
}

test "document IPC loads read-only shares but refuses hidden reads and oversized documents" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.device.service.shareWorkspace(fixture.device.workspace_id, try (workspace.ShareGrant{
        .principal_id = fixture.server.binding.authority.principal,
        .can_read = true,
        .can_write = false,
        .expires_at_ticks = 100,
        .network_scope = .local_only,
    }).withObjectScope(ids.object(900), durable.path));
    try fixture.client.open();
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqualStrings("original", fixture.client.finishOpen().?);
    try fixture.client.start("forbidden write");
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    try fixture.send((try fixture.client.nextFrame(&bytes)).?, fixture.client.request_id);
    fixture.client.sent();
    _ = try fixture.server.runOnce(10);
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.permission_denied, fixture.client.last_status.?);

    fixture.client = .{ .service_endpoint_id = fixture.server_endpoint_id, .object_id = 900, .version_id = fixture.device.original_version_id };
    try fixture.device.service.shareWorkspace(fixture.device.workspace_id, try (workspace.ShareGrant{
        .principal_id = fixture.server.binding.authority.principal,
        .can_read = false,
        .can_write = true,
        .expires_at_ticks = 100,
        .network_scope = .local_only,
    }).withObjectScope(ids.object(900), durable.path));
    try fixture.client.open();
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.permission_denied, fixture.client.last_status.?);

    try fixture.device.service.shareWorkspace(fixture.device.workspace_id, try (workspace.ShareGrant{
        .principal_id = fixture.server.binding.authority.principal,
        .can_read = true,
        .can_write = true,
        .expires_at_ticks = 100,
        .network_scope = .local_only,
    }).withObjectScope(ids.object(900), durable.path));
    var other_editor = @import("document_save.zig").Session{};
    const oversized = [_]u8{'x'} ** (protocol.MAX_DOCUMENT_BYTES + 1);
    const saved = try other_editor.saveForVerification(&fixture.device.service, .{
        .workspace_id = fixture.device.workspace_id,
        .path = durable.path,
        .expected_version_id = fixture.device.original_version_id,
        .payload = &oversized,
        .signer = durable.signer,
        .tick = 10,
    });
    fixture.client = .{ .service_endpoint_id = fixture.server_endpoint_id, .object_id = 900, .version_id = saved.version_id };
    try fixture.client.open();
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.too_large, fixture.client.last_status.?);
    try std.testing.expect(fixture.client.finishOpen() == null);
}

test "document IPC retries failed barriers and lost receipts without another version" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.device.fail_flushes = true;
    try fixture.client.start("pending draft");
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.durability_failed, fixture.client.last_status.?);
    try std.testing.expect(fixture.client.acknowledgedText() == null);
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());
    fixture.device.fail_flushes = false;
    try std.testing.expect(fixture.client.retry());
    try fixture.submit();
    _ = try fixture.receive(false); // Simulate losing the durable acknowledgement.
    try std.testing.expect(fixture.client.retry());
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.saved, fixture.client.last_status.?);
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());
    fixture.device.crash();
    try std.testing.expectEqualStrings("pending draft", try fixture.device.text());
}

test "document IPC rechecks revocation before committing assembled data" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.client.start("revoked draft");
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    while (fixture.client.phase != .commit) {
        const frame = (try fixture.client.nextFrame(&bytes)).?;
        try fixture.send(frame, fixture.client.request_id);
        fixture.client.sent();
        _ = try fixture.server.runOnce(10);
    }
    try fixture.capabilities.revokeGrant(fixture.write_capability);
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.permission_denied, fixture.client.last_status.?);
    try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
    try std.testing.expectEqualStrings("original", try fixture.device.text());
}

test "document IPC rejects expired revoked denied and unavailable signing leases before publication" {
    for (0..4) |variant| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.client.start("unsaved signing failure");
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        while (fixture.client.phase != .commit) {
            const frame = (try fixture.client.nextFrame(&bytes)).?;
            try fixture.send(frame, fixture.client.request_id);
            fixture.client.sent();
            _ = try fixture.server.runOnce(10);
        }
        const signing_fixture = &fixture.signing_fixture;
        const handle = signing_fixture.service.findHandle(fixture.open_request.signer.key.handle_id).?;
        switch (variant) {
            0 => handle.expires_at_ticks = 10,
            1 => handle.revoked = true,
            2 => {
                _ = try signing_fixture.policies.create(.{
                    .scope = .user,
                    .subject_id = 1,
                    .issuer = .{ .kind = .policy_authority, .serial = 1 },
                    .label = "deny signing",
                    .secret_vault_allowed = false,
                }, durable.signer);
            },
            3 => signing_fixture.service.attachHardwareProvider(.{}),
            else => unreachable,
        }
        try fixture.submit();
        _ = try fixture.receive(true);
        try std.testing.expectEqual(if (variant == 3) protocol.Status.storage_failed else protocol.Status.permission_denied, fixture.client.last_status.?);
        try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
        try std.testing.expectEqualStrings("original", try fixture.device.text());
        try std.testing.expect(fixture.client.acknowledgedText() == null);
    }
}

test "document IPC retains a committed receipt while the client queue is full" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    for (0..endpoint.MAX_ENDPOINT_QUEUE) |index| {
        _ = try fixture.endpoints.reply(ids.endpoint(fixture.server_endpoint_id), ids.endpoint(fixture.app_endpoint_id), ids.task(fixture.device.service.task_id), index, "queued", null, false);
    }
    try fixture.client.start("backpressured draft");
    try fixture.submit();
    try std.testing.expect(fixture.server.pending_reply != null);
    try std.testing.expect(!try fixture.server.runOnce(10));
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());
    for (0..endpoint.MAX_ENDPOINT_QUEUE) |_| _ = try fixture.receive(false);
    try std.testing.expect(try fixture.server.runOnce(10));
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.saved, fixture.client.last_status.?);
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());
}

test "document IPC rejects changed retries incomplete chunks and stale versions" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.client.start("original draft");
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    try fixture.send((try fixture.client.nextFrame(&bytes)).?, fixture.client.request_id);
    fixture.client.sent();
    _ = try fixture.server.runOnce(10);
    try fixture.sendFrame(.{ .chunk = .{ .offset = 4, .bytes = "gap" } });
    const incomplete = try fixture.receive(false);
    try std.testing.expectEqual(protocol.Status.incomplete, (try protocol.decode(incomplete.payload[0..incomplete.message.payload_len])).body.receipt.status);
    try fixture.submit();
    _ = try fixture.receive(true);
    const saved_version = fixture.client.version_id;
    try fixture.sendFrame(.{ .begin = .{
        .expected_version_id = fixture.device.original_version_id,
        .length = 5,
        .digest = protocol.digest("other"),
    } });
    const conflict = try fixture.receive(false);
    try std.testing.expectEqual(protocol.Status.request_conflict, (try protocol.decode(conflict.payload[0..conflict.message.payload_len])).body.receipt.status);
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());

    fixture.client.version_id = fixture.device.original_version_id;
    try fixture.client.start("stale draft");
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.document_changed, fixture.client.last_status.?);
    try std.testing.expectEqual(saved_version, (try fixture.device.service.resolve(fixture.device.workspace_id, durable.path)).version_id.raw());
    try std.testing.expectEqual(@as(usize, 2), fixture.device.service.versionCount());
}

test "document IPC rejects another client endpoint and surrendered write authority" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const other = try fixture.endpoints.create(ids.task(fixture.app_task_id), "other channel", .{ .local_only = true });
    try fixture.endpoints.connect(other.id, ids.endpoint(fixture.server_endpoint_id));
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const begin = try protocol.encode(&bytes, .{ .request_id = 1, .body = .{ .begin = .{
        .expected_version_id = fixture.device.original_version_id,
        .length = 0,
        .digest = protocol.digest(""),
    } } });
    _ = try fixture.endpoints.send(other.id, ids.task(fixture.app_task_id), 1, begin, null, false);
    _ = try fixture.server.runOnce(10);
    var reply_bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const received = (try fixture.endpoints.recvInto(other.id, &reply_bytes)).?;
    try std.testing.expectEqual(protocol.Status.permission_denied, (try protocol.decode(reply_bytes[0..received.len])).body.receipt.status);
    try std.testing.expect(fixture.server.attempt == null);

    try std.testing.expect(try fixture.runtime.revokeCapability(fixture.app_task_id, fixture.write_capability));
    try fixture.client.start("surrendered authority");
    const frame = (try fixture.client.nextFrame(&bytes)).?;
    try fixture.send(frame, fixture.client.request_id);
    _ = try fixture.server.runOnce(10);
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.permission_denied, fixture.client.last_status.?);
    try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
}

test "document IPC discards unexpected grants even on malformed input" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const app = fixture.runtime.find(fixture.app_task_id).?;
    const gift = try fixture.capabilities.mintBootRoot(.{
        .holder = app.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = fixture.device.service.service_id },
        .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
        .scope = .{ .task_id = app.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    try fixture.runtime.grantCapability(app.id, gift.id);
    const count = fixture.capabilities.activeCount();
    const receiver_count = fixture.runtime.find(fixture.device.service.task_id).?.capability_count;
    for (0..4) |_| {
        try fixture.port.endpointSend(.{
            .header = component_port.makeHeader(.endpoint_send, app.id),
            .correlation_id = 1,
            .endpoint_capability_id = fixture.app_endpoint_capability,
            .payload = "bad frame",
            .attached_capability_id = gift.id,
        }, 10);
        try std.testing.expect(try fixture.server.runOnce(10));
        try std.testing.expectEqual(count, fixture.capabilities.activeCount());
        try std.testing.expectEqual(receiver_count, fixture.runtime.find(fixture.device.service.task_id).?.capability_count);
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
}

test "document IPC confines writes to the bound object path and workspace" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const service = &fixture.device.service;
    const workspace_id = fixture.device.workspace_id;
    const alias = "documents/alias.md";
    try service.beginTransaction(workspace_id);
    try service.stagePut(workspace_id, alias, ids.object(900), ids.version(fixture.device.original_version_id), .document);
    _ = try service.commit(workspace_id, 3);
    const other_workspace = try service.createWorkspace(.{ .owner = .{ .kind = .user, .serial = 1 }, .label = "other" });
    try fixture.client.start("scoped draft");
    const original_binding = fixture.server.binding;
    const targets = [_]struct { workspace_id: u64, path: []const u8, object_id: u64 }{
        .{ .workspace_id = workspace_id, .path = alias, .object_id = 900 },
        .{ .workspace_id = workspace_id, .path = durable.path, .object_id = 901 },
        .{ .workspace_id = other_workspace.id.raw(), .path = durable.path, .object_id = 900 },
    };
    for (targets) |target| {
        fixture.server.binding.workspace_id = target.workspace_id;
        fixture.server.binding.path = target.path;
        fixture.server.binding.object_id = target.object_id;
        try fixture.sendFrame(.{ .begin = .{
            .expected_version_id = fixture.device.original_version_id,
            .length = 0,
            .digest = protocol.digest(""),
        } });
        const received = try fixture.receive(false);
        try std.testing.expectEqual(protocol.Status.permission_denied, (try protocol.decode(received.payload[0..received.message.payload_len])).body.receipt.status);
        try std.testing.expect(fixture.server.attempt == null);
    }
    fixture.server.binding = original_binding;
    try fixture.submit();
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.saved, fixture.client.last_status.?);
    try std.testing.expectEqual(fixture.device.original_version_id, (try service.resolve(workspace_id, alias)).version_id.raw());
}

test "document IPC rejects read-only and expired shares with a live write capability" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.client.start("unauthorized draft");
    for ([_]workspace.ShareGrant{
        .{ .principal_id = fixture.server.binding.authority.principal, .can_read = true, .can_write = false, .expires_at_ticks = 100, .network_scope = .local_only },
        .{ .principal_id = fixture.server.binding.authority.principal, .can_read = true, .can_write = true, .expires_at_ticks = 9, .network_scope = .local_only },
    }) |share| {
        try fixture.device.service.shareWorkspace(fixture.device.workspace_id, try share.withObjectScope(ids.object(900), durable.path));
        try fixture.sendFrame(.{ .begin = .{
            .expected_version_id = fixture.device.original_version_id,
            .length = 0,
            .digest = protocol.digest(""),
        } });
        const received = try fixture.receive(false);
        try std.testing.expectEqual(protocol.Status.permission_denied, (try protocol.decode(received.payload[0..received.message.payload_len])).body.receipt.status);
        try std.testing.expect(fixture.server.attempt == null);
    }
    try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
    try std.testing.expectEqualStrings("original", try fixture.device.text());
}

test "document IPC rejects conflicting duplicates and digest mismatches before storage" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.client.start("hello");
    try fixture.sendFrame(.{ .begin = .{
        .expected_version_id = fixture.device.original_version_id,
        .length = 5,
        .digest = protocol.digest("hello"),
    } });
    try fixture.sendFrame(.{ .chunk = .{ .offset = 0, .bytes = "wrong" } });
    try fixture.sendFrame(.{ .chunk = .{ .offset = 0, .bytes = "wrong" } });
    try std.testing.expectEqual(@as(u8, 0), (try fixture.receive(false)).present);
    try fixture.sendFrame(.{ .chunk = .{ .offset = 0, .bytes = "hello" } });
    const conflict = try fixture.receive(false);
    try std.testing.expectEqual(protocol.Status.request_conflict, (try protocol.decode(conflict.payload[0..conflict.message.payload_len])).body.receipt.status);
    try fixture.sendFrame(.{ .commit = {} });
    _ = try fixture.receive(true);
    try std.testing.expectEqual(protocol.Status.request_conflict, fixture.client.last_status.?);
    try std.testing.expectEqual(@as(usize, 1), fixture.device.service.versionCount());
    try std.testing.expectEqualStrings("original", try fixture.device.text());
}

test "document channel owns borrowed opening metadata and reuses retired resources" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channel.close(1);
    const baseline = fixture.capabilities.activeCount();
    var path = durable.path.*;
    var request = fixture.open_request;
    request.path = &path;
    const binding = try fixture.channel.open(&fixture.port, &fixture.device.service, request, 2);
    @memset(&path, 'x');
    request.signer.key.handle_id += 1;
    request.signer.key.sealed_digest[0] ^= 1;
    try std.testing.expectEqualStrings(durable.path, fixture.channel.server.?.binding.path);
    try std.testing.expectEqual(fixture.open_request.signer.key.handle_id, fixture.channel.server.?.binding.signer.key.handle_id);
    try std.testing.expectEqual(fixture.device.original_version_id, binding.version_id);
    try std.testing.expectError(error.DocumentAlreadyOpen, fixture.channel.open(&fixture.port, &fixture.device.service, request, 2));
    fixture.channel.close(3);
    for (0..128) |_| {
        _ = try fixture.channel.open(&fixture.port, &fixture.device.service, fixture.open_request, 4);
        fixture.channel.close(5);
        try std.testing.expectEqual(baseline, fixture.capabilities.activeCount());
        try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
        try std.testing.expectEqual(@as(u16, 0), fixture.endpoints.activeForTask(ids.task(fixture.app_task_id)));
    }
}

test "document channel opening failure rolls back the first endpoint and all ownership grants" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channel.close(1);
    const baseline = fixture.capabilities.activeCount();
    var request = fixture.open_request;
    request.server_bootstrap_capability_id = request.client_bootstrap_capability_id;
    for (0..128) |_| {
        try std.testing.expectError(error.CapabilityNotFound, fixture.channel.open(&fixture.port, &fixture.device.service, request, 2));
        try std.testing.expect(fixture.channel.server == null);
        try std.testing.expectEqual(baseline, fixture.capabilities.activeCount());
        try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
    }
    request = fixture.open_request;
    request.authority.principal.serial += 1;
    try std.testing.expectError(error.PermissionDenied, fixture.channel.open(&fixture.port, &fixture.device.service, request, 2));
    request = fixture.open_request;
    request.authority.capability_id = request.client_bootstrap_capability_id;
    try std.testing.expectError(error.PermissionDenied, fixture.channel.open(&fixture.port, &fixture.device.service, request, 2));
    _ = try fixture.channel.open(&fixture.port, &fixture.device.service, fixture.open_request, 3);
}

test "document channel cancels a queued commit when the client closes or either task exits" {
    for (0..3) |ending| {
        const fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.client.start("must never commit");
        var buffer: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        while (try fixture.client.nextFrame(&buffer)) |frame| {
            const commit = (try protocol.decode(frame)).body == .commit;
            try fixture.send(frame, fixture.client.request_id);
            fixture.client.sent();
            if (commit) break;
            try std.testing.expect(fixture.channel.runOnce(10));
        }
        try std.testing.expect(fixture.channel.hasPendingWork());
        switch (ending) {
            0 => try fixture.port.endpointClose(.{
                .header = component_port.makeHeader(.endpoint_close, fixture.app_task_id),
                .endpoint_capability_id = fixture.app_endpoint_capability,
            }, 11),
            1 => _ = try fixture.runtime.terminateTask(fixture.app_task_id, 11),
            else => _ = try fixture.runtime.terminateTask(fixture.device.service.task_id, 11),
        }
        try std.testing.expect(fixture.channel.runOnce(12));
        try std.testing.expect(!fixture.channel.hasPendingWork());
        try std.testing.expect(fixture.channel.server == null);
        try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
        try std.testing.expectEqual(fixture.device.original_version_id, (try fixture.device.service.resolve(fixture.device.workspace_id, durable.path)).version_id.raw());
    }
}

test "document channel teardown still releases endpoints after ownership grants are revoked" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.capabilities.revokeGrant(fixture.app_endpoint_capability);
    _ = try fixture.runtime.revokeCapability(fixture.app_task_id, fixture.app_endpoint_capability);
    try fixture.capabilities.revokeGrant(fixture.server.binding.server_endpoint_capability_id);
    _ = try fixture.runtime.revokeCapability(fixture.device.service.task_id, fixture.server.binding.server_endpoint_capability_id);
    fixture.channel.close(10);
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
    try std.testing.expect(!fixture.runtime.find(fixture.app_task_id).?.hasCapability(fixture.app_endpoint_capability));
}

test "document sessions bound dispatch and remain idle under reply backpressure" {
    const Sessions = @import("../session/document_sessions.zig").Sessions;
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channel.close(1);
    var sessions = Sessions{};
    defer sessions.deinit(99);
    const binding = try sessions.open(&fixture.port, &fixture.device.service, fixture.open_request, 2);
    try std.testing.expectError(error.DocumentAlreadyOpen, sessions.open(&fixture.port, &fixture.device.service, fixture.open_request, 2));
    try std.testing.expect(!sessions.hasPendingWork());
    try std.testing.expect(!sessions.service(3));
    fixture.app_endpoint_capability = binding.endpoint_capability_id;
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    for (0..3) |index| {
        const frame = try protocol.encode(&bytes, .{ .request_id = index + 1, .body = .{ .read = .{ .version_id = binding.version_id, .offset = 0 } } });
        try fixture.send(frame, index + 1);
    }
    try std.testing.expect(sessions.hasPendingWork());
    try std.testing.expect(sessions.service(4));
    try std.testing.expectEqual(@as(u16, 2), (try fixture.endpoints.descriptor(ids.endpoint(binding.service_endpoint_id))).queued_messages);
    try std.testing.expect(sessions.service(4));
    try std.testing.expectEqual(@as(u16, 1), (try fixture.endpoints.descriptor(ids.endpoint(binding.service_endpoint_id))).queued_messages);
    const client_id = fixture.capabilities.query(binding.endpoint_capability_id).?.target.id;
    for (2..endpoint.MAX_ENDPOINT_QUEUE) |index| {
        _ = try fixture.endpoints.reply(ids.endpoint(binding.service_endpoint_id), ids.endpoint(client_id), ids.task(fixture.device.service.task_id), index, "full", null, false);
    }
    try std.testing.expect(sessions.service(5));
    try std.testing.expect(!sessions.hasPendingWork());
    try std.testing.expect(!sessions.service(6));
    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    _ = try fixture.endpoints.recvInto(ids.endpoint(client_id), &payload);
    try std.testing.expect(sessions.hasPendingWork());
    try std.testing.expect(sessions.service(7));
    sessions.closeTask(fixture.app_task_id, 8);
    try std.testing.expectEqual(@as(usize, 0), fixture.endpoints.activeCount());
}

test "document channel suspension preserves queued work until both tasks resume" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const frame = try protocol.encode(&bytes, .{ .request_id = 1, .body = .{ .read = .{ .version_id = fixture.device.original_version_id, .offset = 0 } } });
    try fixture.send(frame, 1);
    try std.testing.expect(fixture.channel.hasPendingWork());
    for ([_]u64{ fixture.app_task_id, fixture.device.service.task_id }) |task_id| {
        try std.testing.expect(try fixture.runtime.suspendTask(task_id, 10));
        try std.testing.expect(!fixture.channel.hasPendingWork());
        try std.testing.expect(!fixture.channel.runOnce(11));
        try std.testing.expect(fixture.channel.server != null);
        try std.testing.expectEqual(@as(u16, 1), (try fixture.endpoints.descriptor(ids.endpoint(fixture.server_endpoint_id))).queued_messages);
        try std.testing.expect(try fixture.runtime.resumeTask(task_id, 12));
    }
    try std.testing.expect(fixture.channel.hasPendingWork());
    try std.testing.expect(fixture.channel.runOnce(13));
    try std.testing.expect(!fixture.channel.hasPendingWork());
    const received = try fixture.receive(false);
    try std.testing.expectEqual(@as(u8, 1), received.present);
    try std.testing.expectEqual(std.meta.Tag(protocol.Body).read_data, std.meta.activeTag((try protocol.decode(received.payload[0..received.message.payload_len])).body));
}

test "document sessions enforce capacity and share each dispatch fairly" {
    const sessions_mod = @import("../session/document_sessions.zig");
    const fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channel.close(1);
    var sessions = sessions_mod.Sessions{};
    defer sessions.deinit(99);
    const Binding = @import("../task/userspace_bootstrap_mailbox.zig").DocumentBinding;
    var bindings: [sessions_mod.MAX_CHANNELS]Binding = undefined;
    var requests: [sessions_mod.MAX_CHANNELS + 1]document_channel.OpenRequest = undefined;
    for (&requests, 0..) |*request, index| {
        const app = try fixture.runtime.createTask(.{
            .owner = fixture.open_request.authority.principal,
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 4096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        const write = try fixture.capabilities.mintBootRoot(.{
            .holder = app.owner,
            .issuer = fixture.kernel.policy_authority,
            .target = .{ .kind = .workspace, .id = fixture.device.workspace_id },
            .rights = .{ .workspace = .{ .object_read = true, .object_write = true } },
            .scope = .{ .task_id = app.id, .workspace_id = fixture.device.workspace_id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        try fixture.runtime.grantCapability(app.id, write.id);
        request.* = fixture.open_request;
        request.authority.task_id = app.id;
        request.authority.capability_id = write.id;
        request.client_bootstrap_capability_id = try fixture.bootstrapCapability(app);
        if (index < bindings.len) bindings[index] = try sessions.open(&fixture.port, &fixture.device.service, request.*, 2);
    }
    const count = fixture.capabilities.activeCount();
    try std.testing.expectError(error.DocumentTableFull, sessions.open(&fixture.port, &fixture.device.service, requests[bindings.len], 2));
    try std.testing.expectEqual(count, fixture.capabilities.activeCount());
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    for (bindings, requests[0..bindings.len]) |binding, request| {
        try fixture.port.endpointSend(.{
            .header = component_port.makeHeader(.endpoint_send, request.authority.task_id),
            .correlation_id = 1,
            .endpoint_capability_id = binding.endpoint_capability_id,
            .payload = try protocol.encode(&bytes, .{ .request_id = 1, .body = .{ .read = .{ .version_id = binding.version_id, .offset = 0 } } }),
        }, 3);
    }
    for (0..2) |dispatch| {
        try std.testing.expect(sessions.service(4));
        for (bindings, 0..) |binding, index| {
            const queued: u16 = if (index < (dispatch + 1) * sessions_mod.DISPATCH_BUDGET) 0 else 1;
            try std.testing.expectEqual(queued, (try fixture.endpoints.descriptor(ids.endpoint(binding.service_endpoint_id))).queued_messages);
        }
    }
    try std.testing.expect(!sessions.hasPendingWork());
    sessions.closeTask(requests[0].authority.task_id, 5);
    _ = try sessions.open(&fixture.port, &fixture.device.service, requests[bindings.len], 6);
}
