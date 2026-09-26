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
const protocol = ipc.protocol;
const Client = @import("../../userspace/document_client.zig").Client;

const Fixture = struct {
    device: *durable.Fixture,
    runtime: task_runtime.Runtime = .init(),
    capabilities: capability.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: shared_memory.Table = .init(),
    kernel: native_kernel.Kernel = undefined,
    port: component_port.KernelPort = undefined,
    storage: storage_service.StoragePort = undefined,
    server: ipc.Server = undefined,
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
        const client_endpoint = try self.endpoints.create(ids.task(app.id), "document-client", .{ .local_only = true });
        const server_endpoint = try self.endpoints.create(ids.task(service.id), "document-server", .{ .local_only = true, .service_port = true });
        try self.endpoints.connect(client_endpoint.id, server_endpoint.id);
        self.app_endpoint_id = client_endpoint.id.raw();
        self.server_endpoint_id = server_endpoint.id.raw();
        self.app_endpoint_capability = try self.endpointCapability(app, client_endpoint.id.raw());
        const server_capability = try self.endpointCapability(service, server_endpoint.id.raw());
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
        self.storage = storage_service.StoragePort.init(&device.service, &self.capabilities);
        self.server = .{
            .kernel = &self.port,
            .storage = &self.storage,
            .binding = .{
                .client_endpoint_id = self.app_endpoint_id,
                .server_endpoint_capability_id = server_capability,
                .authority = .{ .task_id = app.id, .principal = app.owner, .capability_id = write.id, .now_ticks = 0 },
                .workspace_id = device.workspace_id,
                .path = durable.path,
                .object_id = 900,
                .signer = durable.signer,
            },
        };
        self.client = .{ .service_endpoint_id = self.server_endpoint_id, .object_id = 900, .version_id = device.original_version_id };
        return self;
    }

    fn endpointCapability(self: *Fixture, task: *task_runtime.TaskRecord, endpoint_id: u64) !u64 {
        const grant = try self.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .endpoint, .id = endpoint_id },
            .rights = .{ .endpoint = .{ .endpoint_send = true, .endpoint_recv = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        });
        try self.runtime.grantCapability(task.id, grant.id);
        return grant.id;
    }

    fn deinit(self: *Fixture) void {
        self.kernel.deinit();
        self.device.deinit();
        std.testing.allocator.destroy(self);
    }

    fn send(self: *Fixture, bytes: []const u8, request_id: u64) !void {
        const request = component_port.EndpointSendRequest{
            .header = component_port.makeHeader(.endpoint_send, request_id, self.app_task_id),
            .endpoint_capability_id = self.app_endpoint_capability,
            .payload = bytes,
        };
        const result = syscall_surface.dispatch(&self.port, self.app_task_id, 10, @intFromPtr(&request), 0, 0);
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
            .header = component_port.makeHeader(.endpoint_recv, 99, self.app_task_id),
            .endpoint_capability_id = self.app_endpoint_capability,
            .receiver_task_id = self.app_task_id,
            .payload_out = &out.payload,
            .attached_capability_out = &out.attached_capability,
        };
        try std.testing.expectEqual(abi.SyscallStatus.success, syscall_surface.dispatch(
            &self.port,
            self.app_task_id,
            10,
            @intFromPtr(&request),
            @intFromPtr(&response),
            @sizeOf(abi.EndpointRecvResponse),
        ).status);
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
        while (fixture.client.phase != .loaded and frames < 8) : (frames += 1) {
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
            _ = try other_editor.save(&fixture.device.service, .{
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
    const saved = try other_editor.save(&fixture.device.service, .{
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
            .header = component_port.makeHeader(.endpoint_send, 1, app.id),
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
