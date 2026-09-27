const builtin = @import("builtin");
const std = @import("std");
const protocol = @import("../../userspace/launcher_protocol.zig");
const component_port = @import("../kernel_api/component_port.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const ids = @import("../core/ids.zig");
const abi = @import("../core/abi.zig");
const executor = @import("../task/userspace_executor.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const documents = @import("document_sessions.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding) @import("../../kernel/memory/memory.zig") else struct {};
const heap_backed = builtin.target.os.tag == .freestanding;

const Pending = struct {
    request: documents.OpenRequest,
    path: [workspace.MAX_ENTRY_PATH_BYTES]u8,
    signer_label: [workspace.MAX_EXPORT_SIGNATURE_SIGNER_BYTES]u8,
    object_id: u64,
    version_id: u64,
    window_id: u64,
    previous_window_id: u64,
};
const Outgoing = struct { token: u64, length: u8, bytes: [protocol.MAX_FRAME_BYTES]u8 };
const State = struct {
    kernel: *component_port.KernelPort,
    client_task_id: u64,
    server_task_id: u64,
    client_endpoint_id: u64,
    server_endpoint_id: u64,
    server_capability_id: u64,
    binding: mailbox.LauncherBinding,
    pending: ?Pending = null,
    outgoing: ?Outgoing = null,
    result: ?protocol.Result = null,
};

// One approved document offer per session, allocated only when used. Endpoint
// messages contain no storage authority, path, signer, or executable choice.
pub const Launcher = struct {
    backing: if (heap_backed) ?*State else ?State = null,
    owner_task_id: u64 = 0,
    token: u64 = 0,

    fn state(self: *Launcher) ?*State {
        if (comptime heap_backed) return self.backing;
        return if (self.backing) |*value| value else null;
    }

    fn stateConst(self: *const Launcher) ?*const State {
        if (comptime heap_backed) return self.backing;
        return if (self.backing) |*value| value else null;
    }

    pub fn offer(self: *Launcher, manager: anytype, request: documents.OpenRequest, label: []const u8, now_ticks: u64) !u64 {
        if (self.state()) |s| if (s.pending != null or s.outgoing != null) return error.LauncherBusy;
        if (self.token == std.math.maxInt(u64)) return error.LaunchTokenExhausted;
        if (request.path.len > workspace.MAX_ENTRY_PATH_BYTES or request.signer.label.len == 0 or
            request.signer.label.len > workspace.MAX_EXPORT_SIGNATURE_SIGNER_BYTES) return error.InvalidDocumentRequest;
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        _ = try protocol.encode(&bytes, .{ .token = self.token + 1, .body = .{ .offer = .{ .window_id = 1, .label = label } } });
        var port = storage_service.StoragePort.init(manager.storageServicePtr(), manager.capabilityTablePtr());
        var authority = request.authority;
        authority.now_ticks = now_ticks;
        const view = try port.openEntry(authority, request.workspace_id, request.path, .read);
        if (view.object_type != .document) return error.NotDocument;
        try port.requireDocumentWrite(authority, request.workspace_id, request.path, view.object_id.raw());
        const s = try self.ensureChannel(manager, now_ticks);
        const compositor_task = manager.runtimePtr().find(s.client_task_id) orelse return error.TaskNotFound;
        if (compositor_task.state != .active) return error.TaskNotPrepared;
        const compositor = manager.compositorSessionPtr();
        const previous_window_id = compositor.active_window_id;
        const window = try compositor.openTaskView(compositor_task, "Open document");
        self.token += 1;
        s.pending = .{
            .request = request,
            .path = undefined,
            .signer_label = undefined,
            .object_id = view.object_id.raw(),
            .version_id = view.version_id.raw(),
            .window_id = window.id,
            .previous_window_id = previous_window_id,
        };
        const pending = &s.pending.?;
        @memcpy(pending.path[0..request.path.len], request.path);
        @memcpy(pending.signer_label[0..request.signer.label.len], request.signer.label);
        pending.request.path = pending.path[0..request.path.len];
        pending.request.signer.label = pending.signer_label[0..request.signer.label.len];
        s.result = null;
        queue(s, .{ .token = self.token, .body = .{ .offer = .{ .window_id = window.id, .label = label } } });
        return self.token;
    }

    fn ensureChannel(self: *Launcher, manager: anytype, now_ticks: u64) !*State {
        if (self.state()) |s| return s;
        const kernel = manager.kernelPort() orelse return error.KernelUnavailable;
        const runtime = manager.runtimePtr();
        const client_task = runtime.find(manager.inputRouterPtr().compositor_task_id) orelse return error.TaskNotFound;
        const server_task = runtime.find(self.owner_task_id) orelse return error.TaskNotFound;
        const capabilities = manager.capabilityTablePtr();
        const client_authority = executor.resolveMailboxAuthorities(client_task, capabilities, now_ticks).bootstrap_capability_id;
        const server_authority = executor.resolveMailboxAuthorities(server_task, capabilities, now_ticks).bootstrap_capability_id;
        const client = try kernel.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, client_task.id),
            .authority_capability_id = client_authority,
            .owner_task_id = client_task.id,
            .label = "launcher-client",
            .flags = .{ .local_only = true },
        }, now_ticks);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(client.endpoint.endpoint_id), now_ticks) catch unreachable;
        const server = try kernel.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, server_task.id),
            .authority_capability_id = server_authority,
            .owner_task_id = server_task.id,
            .label = "launcher-session",
            .flags = .{ .local_only = true, .service_port = true },
        }, now_ticks);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(server.endpoint.endpoint_id), now_ticks) catch unreachable;
        _ = try kernel.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, client_task.id),
            .endpoint_capability_id = client.capability_id,
            .peer_endpoint_capability_id = server.capability_id,
            .peer_endpoint_id = server.endpoint.endpoint_id,
        }, now_ticks);
        const binding = mailbox.LauncherBinding{ .endpoint_capability_id = client.capability_id, .service_endpoint_id = server.endpoint.endpoint_id };
        if (comptime heap_backed) {
            const allocation = kernel_memory.kmalloc(@sizeOf(State)) orelse return error.NoSpaceLeft;
            self.backing = @ptrCast(@alignCast(allocation));
        }
        errdefer if (comptime heap_backed) {
            kernel_memory.kfree(@ptrCast(self.backing.?));
            self.backing = null;
        };
        if (comptime heap_backed) {
            if (!manager.runtime_context.userspace_executor.bindLauncherChannel(manager.userspaceCatalogPtr(), runtime, capabilities, client_task.id, binding, now_ticks)) return error.LauncherBindingUnavailable;
        }
        const initial = State{
            .kernel = kernel,
            .client_task_id = client_task.id,
            .server_task_id = server_task.id,
            .client_endpoint_id = client.endpoint.endpoint_id,
            .server_endpoint_id = server.endpoint.endpoint_id,
            .server_capability_id = server.capability_id,
            .binding = binding,
        };
        if (comptime heap_backed) self.backing.?.* = initial else self.backing = initial;
        return self.state().?;
    }

    pub fn service(self: *Launcher, manager: anytype, now_ticks: u64) bool {
        const s = self.state() orelse return false;
        switch (peerState(s)) {
            .closed => {
                self.deinit(manager, now_ticks);
                return true;
            },
            .suspended => return false,
            .active => {},
        }
        if (s.outgoing != null) return flush(s, now_ticks) catch {
            self.deinit(manager, now_ticks);
            return true;
        };
        if (pendingTaskRetired(s)) {
            const pending = &s.pending.?;
            closeOfferWindow(manager, pending, true);
            @memset(std.mem.asBytes(pending), 0);
            s.pending = null;
            const result = protocol.Result{ .status = .unavailable };
            s.result = result;
            queue(s, .{ .token = self.token, .body = .{ .result = result } });
            return true;
        }
        var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        var attached: abi.CapabilityDescriptor = undefined;
        const received = (s.kernel.endpointRecv(.{
            .header = component_port.makeHeader(.endpoint_recv, s.server_task_id),
            .endpoint_capability_id = s.server_capability_id,
            .receiver_task_id = s.server_task_id,
            .payload_out = &bytes,
            .attached_capability_out = &attached,
        }, now_ticks) catch {
            self.deinit(manager, now_ticks);
            return true;
        }) orelse return false;
        if (received.attached_capability) |grant| {
            _ = s.kernel.kernel.runtime.revokeCapability(s.server_task_id, grant.capability_id) catch unreachable;
            s.kernel.kernel.capability_table.revokeGrant(grant.capability_id) catch unreachable;
            return true;
        }
        if (received.message.sender_task_id != s.client_task_id or received.message.sender_endpoint_id != s.client_endpoint_id) return true;
        const frame = protocol.decode(bytes[0..received.message.payload_len]) catch return true;
        if (frame.token != received.message.correlation_id or frame.token != self.token or
            (frame.body != .open and frame.body != .cancel)) return true;
        if (s.pending != null) {
            const pending = &s.pending.?;
            var result = protocol.Result{ .status = .unavailable };
            if (frame.body == .open and unchanged(manager, pending, now_ticks)) {
                if (manager.activateDocumentTask(pending.request, now_ticks)) |opened| {
                    result = .{ .status = .opened, .task_id = opened.task_id, .window_id = opened.window_id };
                } else |_| {}
            } else if (frame.body == .cancel) result.status = .cancelled;
            if (result.status != .opened) manager.cancelPreparedDocumentTask(pending.request.authority.task_id, now_ticks) catch {};
            closeOfferWindow(manager, pending, result.status != .opened);
            // No request can execute twice, including a contrary replay after
            // cancellation. Retain only the terminal receipt, erase secrets.
            @memset(std.mem.asBytes(pending), 0);
            s.pending = null;
            s.result = result;
        }
        if (s.result) |result| queue(s, .{ .token = self.token, .body = .{ .result = result } });
        return true;
    }

    pub fn hasPendingWork(self: *const Launcher) bool {
        const s = self.stateConst() orelse return false;
        switch (peerState(s)) {
            .closed => return true,
            .suspended => return false,
            .active => {},
        }
        if (s.outgoing == null and pendingTaskRetired(s)) return true;
        const table = s.kernel.kernel.endpoint_table;
        const descriptor = table.descriptor(ids.endpoint(if (s.outgoing != null) s.client_endpoint_id else s.server_endpoint_id)) catch return true;
        return if (s.outgoing != null) descriptor.queued_messages < endpoint.MAX_ENDPOINT_QUEUE else descriptor.queued_messages != 0;
    }

    pub fn deinit(self: *Launcher, manager: anytype, now_ticks: u64) void {
        const s = self.state() orelse return;
        if (s.pending) |*pending| {
            manager.cancelPreparedDocumentTask(pending.request.authority.task_id, now_ticks) catch {};
            closeOfferWindow(manager, pending, true);
        }
        for ([_]u64{ s.server_endpoint_id, s.client_endpoint_id }) |id| s.kernel.kernel.retireEndpoint(ids.endpoint(id), now_ticks) catch |err| switch (err) {
            error.EndpointNotFound => {},
            else => unreachable,
        };
        @memset(std.mem.asBytes(s), 0);
        if (comptime heap_backed) kernel_memory.kfree(@ptrCast(s));
        self.backing = null;
        // Keep the token cursor across channel loss within this session.
    }
};

fn unchanged(manager: anytype, pending: *const Pending, now_ticks: u64) bool {
    var port = storage_service.StoragePort.init(manager.storageServicePtr(), manager.capabilityTablePtr());
    var authority = pending.request.authority;
    authority.now_ticks = now_ticks;
    const view = port.openEntry(authority, pending.request.workspace_id, pending.request.path, .read) catch return false;
    return view.object_type == .document and view.object_id.raw() == pending.object_id and view.version_id.raw() == pending.version_id;
}

fn closeOfferWindow(manager: anytype, pending: *const Pending, restore: bool) void {
    const compositor = manager.compositorSessionPtr();
    const was_focused = compositor.active_window_id == pending.window_id;
    _ = compositor.closeWindow(pending.window_id);
    if (restore and was_focused and pending.previous_window_id != 0) _ = compositor.switchView(pending.previous_window_id) catch {};
}

fn queue(s: *State, frame: protocol.Frame) void {
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const encoded = protocol.encode(&bytes, frame) catch unreachable;
    s.outgoing = .{ .token = frame.token, .length = @intCast(encoded.len), .bytes = bytes };
}

fn flush(s: *State, now_ticks: u64) !bool {
    const outgoing = s.outgoing orelse return false;
    s.kernel.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, s.server_task_id),
        .endpoint_capability_id = s.server_capability_id,
        .reply_endpoint_id = s.client_endpoint_id,
        .correlation_id = outgoing.token,
        .payload = outgoing.bytes[0..outgoing.length],
    }, now_ticks) catch |err| switch (err) {
        error.RingFull => return false,
        else => return err,
    };
    s.outgoing = null;
    return true;
}

fn peerState(s: *const State) enum { active, suspended, closed } {
    const runtime = s.kernel.kernel.runtime;
    const client = runtime.findConst(s.client_task_id) orelse return .closed;
    const server = runtime.findConst(s.server_task_id) orelse return .closed;
    if (client.state == .terminated or server.state == .terminated) return .closed;
    _ = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(s.client_endpoint_id)) catch return .closed;
    _ = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(s.server_endpoint_id)) catch return .closed;
    return if (client.state == .suspended or server.state == .suspended) .suspended else .active;
}

fn pendingTaskRetired(s: *const State) bool {
    const pending = if (s.pending) |*value| value else return false;
    const task = s.kernel.kernel.runtime.findConst(pending.request.authority.task_id) orelse return true;
    return task.state == .terminated;
}

comptime {
    if (heap_backed and @sizeOf(Launcher) > 24) @compileError("launcher handle exceeds resident size bound");
    if (@sizeOf(State) > 1024) @compileError("launcher exceeds bounded storage");
}

fn prepareTestDocument(manager: anytype) !documents.OpenRequest {
    const signing = @import("../core/signing.zig");
    const object_store = @import("../storage/object_store.zig");
    const task = try @import("../task/userspace_launch.zig").prepareRegisteredDirect(manager.userspaceCatalogPtr(), manager.runtimePtr(), "app.notes", .{
        .owner = .{ .kind = .app, .serial = 0xD0C6 },
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = 0xD0C6,
    });
    const storage = manager.storageServicePtr();
    const signer = signing.SignerIdentity{ .label = "launcher-test", .seed = signing.seedFromByte(0xD6) };
    const original = try storage.putVersion(.{
        .object_type = .document,
        .payload = "Original",
        .metadata = try object_store.signMetadata(signer, "Notes", "text/plain", .document, "Original", 0),
    });
    const ws = try storage.createWorkspace(.{ .owner = task.owner, .label = "launcher-test" });
    const path = "documents/notes.md";
    try storage.beginTransaction(ws.id);
    try storage.stagePut(ws.id, path, original.object_id, original.version_id, .document);
    _ = try storage.commit(ws.id, 0);
    const capabilities = manager.capabilityTablePtr();
    const grant = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = manager.kernelPort().?.kernel.policy_authority,
        .target = .{ .kind = .workspace, .id = ws.id.raw() },
        .rights = .{ .workspace = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = task.id, .workspace_id = ws.id.raw(), .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    try manager.runtimePtr().grantCapability(task.id, grant.id);
    return .{
        .authority = .{ .task_id = task.id, .principal = task.owner, .capability_id = grant.id, .now_ticks = 0 },
        .client_bootstrap_capability_id = 0,
        .server_bootstrap_capability_id = 0,
        .workspace_id = ws.id.raw(),
        .path = path,
        .signer = signer,
    };
}

fn sendTestDecision(s: *State, token: u64, body: protocol.Body) !void {
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const encoded = try protocol.encode(&bytes, .{ .token = token, .body = body });
    try s.kernel.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, s.client_task_id),
        .endpoint_capability_id = s.binding.endpoint_capability_id,
        .correlation_id = token,
        .payload = encoded,
    }, 1);
}

fn receiveTestFrame(s: *State) !?protocol.Result {
    var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    var attached: abi.CapabilityDescriptor = undefined;
    const received = (try s.kernel.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, s.client_task_id),
        .endpoint_capability_id = s.binding.endpoint_capability_id,
        .receiver_task_id = s.client_task_id,
        .payload_out = &bytes,
        .attached_capability_out = &attached,
    }, 1)).?;
    try std.testing.expect(received.attached_capability == null);
    const frame = try protocol.decode(bytes[0..received.message.payload_len]);
    return if (frame.body == .result) frame.body.result else null;
}

test "document launcher consumes cancellation once and refuses revoked or replaced documents" {
    const session_manager = @import("session_manager.zig");
    for ([_]enum { cancel, revoke, replace }{ .cancel, .revoke, .replace }) |case| {
        session_manager.testing.resetState();
        defer session_manager.testing.resetState();
        session_manager.boot();
        const manager = session_manager.system();
        const request = try prepareTestDocument(manager);
        const task = manager.runtimePtr().find(request.authority.task_id).?;
        const address_space_id = task.address_space_id;
        const windows_before = manager.compositorSessionPtr().window_count;
        const focus_before = manager.compositorSessionPtr().active_window_id;
        const launcher = &manager.launcher;
        var path_buffer = "documents/notes.md".*;
        var borrowed = request;
        borrowed.path = &path_buffer;
        const token = try manager.offerDocumentLaunch(borrowed, "Notes", 1);
        @memset(&path_buffer, 'x');
        const s = launcher.state().?;
        try std.testing.expectEqualStrings(request.path, s.pending.?.request.path);
        try std.testing.expectError(error.LauncherBusy, manager.offerDocumentLaunch(request, "Another", 1));
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(try receiveTestFrame(s) == null);
        try std.testing.expect(!launcher.hasPendingWork());
        try sendTestDecision(s, token + 1, .open);
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(s.pending != null);
        if (case == .revoke) try manager.capabilityTablePtr().revokeGrant(request.authority.capability_id);
        if (case == .replace) {
            const storage = manager.storageServicePtr();
            const object_store = @import("../storage/object_store.zig");
            const replacement = try storage.putVersion(.{
                .object_type = .document,
                .payload = "Replacement",
                .metadata = try object_store.signMetadata(request.signer, "Notes", "text/plain", .document, "Replacement", 1),
            });
            try storage.beginTransaction(request.workspace_id);
            try storage.stagePut(request.workspace_id, request.path, replacement.object_id, replacement.version_id, .document);
            _ = try storage.commit(request.workspace_id, 1);
        }
        try sendTestDecision(s, token, if (case == .cancel) .cancel else .open);
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(s.pending == null);
        try std.testing.expectEqual(if (case == .cancel) protocol.Status.cancelled else .unavailable, s.result.?.status);
        try std.testing.expectEqual(@import("../task/task_runtime.zig").TaskState.terminated, task.state);
        try std.testing.expect(manager.runtimePtr().findAddressSpaceConst(address_space_id) == null);
        try std.testing.expect(manager.userspaceSchedulerPtr().taskDispatchStats(task.id) == null);
        try std.testing.expectEqual(windows_before, manager.compositorSessionPtr().window_count);
        try std.testing.expectEqual(focus_before, manager.compositorSessionPtr().active_window_id);
        try std.testing.expect(launcher.service(manager, 1));
        const result = (try receiveTestFrame(s)).?;
        const grants_after = manager.capabilityTablePtr().activeCount();
        try sendTestDecision(s, token, .open);
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expectEqualDeep(result, (try receiveTestFrame(s)).?);
        try std.testing.expectEqual(grants_after, manager.capabilityTablePtr().activeCount());
        const cursor = launcher.token;
        launcher.deinit(manager, 1);
        try std.testing.expectEqual(cursor, launcher.token);
    }
}

test "document launcher bounds queue pressure and retires pending offers on channel loss" {
    const session_manager = @import("session_manager.zig");
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();
    session_manager.boot();
    const manager = session_manager.system();
    const request = try prepareTestDocument(manager);
    const endpoints_before = manager.kernelPort().?.kernel.endpoint_table.activeCount();
    const windows_before = manager.compositorSessionPtr().window_count;
    _ = try manager.offerDocumentLaunch(request, "Notes", 1);
    const launcher = &manager.launcher;
    const s = launcher.state().?;
    const offer = s.outgoing.?;
    for (0..endpoint.MAX_ENDPOINT_QUEUE) |_| {
        s.outgoing = offer;
        try std.testing.expect(try flush(s, 1));
    }
    s.outgoing = offer;
    try std.testing.expect(!launcher.hasPendingWork());
    try std.testing.expect(!launcher.service(manager, 1));
    try std.testing.expectEqualDeep(offer, s.outgoing.?);
    _ = try receiveTestFrame(s);
    try std.testing.expect(launcher.hasPendingWork());
    try std.testing.expect(launcher.service(manager, 1));
    _ = try manager.runtimePtr().suspendTask(request.authority.task_id, 1);
    try s.kernel.kernel.retireEndpoint(ids.endpoint(s.client_endpoint_id), 1);
    try std.testing.expect(launcher.hasPendingWork());
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expect(launcher.state() == null);
    try std.testing.expectEqual(@import("../task/task_runtime.zig").TaskState.terminated, manager.runtimePtr().find(request.authority.task_id).?.state);
    try std.testing.expectEqual(endpoints_before, manager.kernelPort().?.kernel.endpoint_table.activeCount());
    try std.testing.expectEqual(windows_before, manager.compositorSessionPtr().window_count);
}

test "document launcher rejects foreign endpoints and releases unexpected authority" {
    const session_manager = @import("session_manager.zig");
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();
    session_manager.boot();
    const manager = session_manager.system();
    const request = try prepareTestDocument(manager);
    const token = try manager.offerDocumentLaunch(request, "Notes", 1);
    const launcher = &manager.launcher;
    const s = launcher.state().?;
    try std.testing.expect(launcher.service(manager, 1));
    _ = try receiveTestFrame(s);
    const table = s.kernel.kernel.endpoint_table;
    const other = try table.create(ids.task(s.client_task_id), "wrong-launcher", .{ .local_only = true });
    try table.connect(other.id, ids.endpoint(s.server_endpoint_id));
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const decision = try protocol.encode(&bytes, .{ .token = token, .body = .cancel });
    _ = try table.send(other.id, ids.task(s.client_task_id), token, decision, null, false);
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expect(s.pending != null);
    const client = manager.runtimePtr().find(s.client_task_id).?;
    const gift = try manager.capabilityTablePtr().mintBootRoot(.{
        .holder = client.owner,
        .issuer = s.kernel.kernel.policy_authority,
        .target = .{ .kind = .service, .id = manager.storageServicePtr().service_id },
        .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
        .scope = .{ .task_id = client.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    try manager.runtimePtr().grantCapability(client.id, gift.id);
    const count = manager.capabilityTablePtr().activeCount();
    const receiver_count = manager.runtimePtr().find(s.server_task_id).?.capability_count;
    for ([_][]const u8{ decision, "malformed" }) |payload| {
        try s.kernel.endpointSend(.{
            .header = component_port.makeHeader(.endpoint_send, client.id),
            .endpoint_capability_id = s.binding.endpoint_capability_id,
            .correlation_id = token,
            .payload = payload,
            .attached_capability_id = gift.id,
        }, 1);
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(s.pending != null);
        try std.testing.expectEqual(count, manager.capabilityTablePtr().activeCount());
        try std.testing.expectEqual(receiver_count, manager.runtimePtr().find(s.server_task_id).?.capability_count);
    }
    try manager.cancelPreparedDocumentTask(request.authority.task_id, 1);
    try std.testing.expect(launcher.hasPendingWork());
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expect(s.pending == null);
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expectEqual(protocol.Status.unavailable, (try receiveTestFrame(s)).?.status);
}
