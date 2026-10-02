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

pub const Request = struct {
    authority: storage_service.AuthorityContext,
    client_bootstrap_capability_id: u64,
    server_bootstrap_capability_id: u64,
    workspace_id: u64,
    signer: @import("../storage/sealed_object_signer.zig").Signer,

    pub fn fromDocument(request: documents.OpenRequest) Request {
        return .{ .authority = request.authority, .client_bootstrap_capability_id = request.client_bootstrap_capability_id, .server_bootstrap_capability_id = request.server_bootstrap_capability_id, .workspace_id = request.workspace_id, .signer = request.signer };
    }

    fn document(self: Request, path: []const u8) documents.OpenRequest {
        return .{ .authority = self.authority, .client_bootstrap_capability_id = self.client_bootstrap_capability_id, .server_bootstrap_capability_id = self.server_bootstrap_capability_id, .workspace_id = self.workspace_id, .signer = self.signer, .path = path };
    }
};

const Pending = struct {
    request: Request,
    entries: [protocol.PAGE_ENTRIES]workspace.Entry = undefined,
    count: u8 = 0,
    first: u16 = 0,
    next: bool = false,
    text: [protocol.MAX_PAGE_TEXT_BYTES]u8 = @splat(0),
    text_length: u16 = 0,
    queued_text: u16 = 0,
    sending_page: bool = false,
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

// One workspace picker per session, allocated only when used. Only authorized
// display names leave the session; object identities, grants and signers stay here.
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

    pub fn offer(self: *Launcher, manager: anytype, request: Request, now_ticks: u64) !u64 {
        if (self.state()) |s| if (s.pending != null or s.outgoing != null) return error.LauncherBusy;
        if (self.token == std.math.maxInt(u64)) return error.LaunchTokenExhausted;
        const storage = manager.storageServicePtr();
        try request.signer.validateService(storage.owner, storage.task_id, now_ticks);
        var pending = Pending{ .request = request, .window_id = 0, .previous_window_id = manager.compositorSessionPtr().active_window_id };
        try selectPage(manager, &pending, 0, now_ticks);
        const s = try self.ensureChannel(manager, now_ticks);
        const compositor_task = manager.runtimePtr().find(s.client_task_id) orelse return error.TaskNotFound;
        if (compositor_task.state != .active) return error.TaskNotPrepared;
        const window = try manager.compositorSessionPtr().openTaskView(compositor_task, "Open document");
        pending.window_id = window.id;
        self.token += 1;
        s.pending = pending;
        s.result = null;
        self.queuePage(s);
        return self.token;
    }

    fn queuePage(self: *Launcher, s: *State) void {
        const pending = &s.pending.?;
        pending.queued_text = 0;
        pending.sending_page = true;
        queue(s, .{ .token = self.token, .body = .{ .page = .{ .window_id = pending.window_id, .text_length = pending.text_length, .count = pending.count, .previous = pending.first != 0, .next = pending.next } } });
    }

    fn finish(self: *Launcher, manager: anytype, s: *State, result: protocol.Result, now_ticks: u64) void {
        const pending = &s.pending.?;
        if (result.status != .opened) manager.cancelPreparedDocumentTask(pending.request.authority.task_id, now_ticks) catch {};
        closeOfferWindow(manager, pending, result.status != .opened);
        @memset(std.mem.asBytes(pending), 0);
        s.pending = null;
        s.result = result;
        queue(s, .{ .token = self.token, .body = .{ .result = result } });
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
        // Recheck before every chunk, including retries after queue pressure.
        // A revoked grant cannot disclose the remainder of a buffered page.
        if (s.pending != null and (pendingTaskRetired(s) or (s.outgoing != null and !current(manager, &s.pending.?, now_ticks)))) {
            self.finish(manager, s, .{ .status = .unavailable }, now_ticks);
            return true;
        }
        if (s.outgoing != null) {
            const sent = flush(s, now_ticks) catch {
                self.deinit(manager, now_ticks);
                return true;
            };
            if (sent) if (s.pending) |*pending| {
                if (pending.sending_page) {
                    if (pending.queued_text < pending.text_length) {
                        const offset = pending.queued_text;
                        const length = @min(protocol.CHUNK_BYTES, pending.text_length - offset);
                        queue(s, .{ .token = self.token, .body = .{ .text = .{ .offset = offset, .bytes = pending.text[offset..][0..length] } } });
                        pending.queued_text += length;
                    } else pending.sending_page = false;
                }
            };
            return sent;
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
            (frame.body != .open and frame.body != .cancel and frame.body != .move)) return true;
        if (s.pending) |*pending| {
            if (frame.body == .cancel) {
                self.finish(manager, s, .{ .status = .cancelled }, now_ticks);
                return true;
            }
            if (manager.compositorSessionPtr().active_window_id != pending.window_id or !current(manager, pending, now_ticks)) {
                self.finish(manager, s, .{ .status = .unavailable }, now_ticks);
                return true;
            }
            if (frame.body == .move) {
                const forward = frame.body.move;
                if ((forward and !pending.next) or (!forward and pending.first == 0)) return true;
                if (self.token == std.math.maxInt(u64)) {
                    self.finish(manager, s, .{ .status = .unavailable }, now_ticks);
                    return true;
                }
                const first = if (forward) pending.first + protocol.PAGE_ENTRIES else pending.first - protocol.PAGE_ENTRIES;
                selectPage(manager, pending, first, now_ticks) catch {
                    self.finish(manager, s, .{ .status = .unavailable }, now_ticks);
                    return true;
                };
                self.token += 1;
                self.queuePage(s);
                return true;
            }
            if (frame.body.open >= pending.count) return true;
            var result = protocol.Result{ .status = .unavailable };
            if (manager.activateDocumentTask(pending.request.document(pending.entries[frame.body.open].pathSlice()), now_ticks)) |opened| {
                result = .{ .status = .opened, .task_id = opened.task_id, .window_id = opened.window_id };
            } else |_| {}
            self.finish(manager, s, result, now_ticks);
            return true;
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

fn selectPage(manager: anytype, pending: *Pending, first: u16, now_ticks: u64) !void {
    var port = storage_service.StoragePort.init(manager.storageServicePtr(), manager.capabilityTablePtr());
    var authority = pending.request.authority;
    authority.now_ticks = now_ticks;
    try port.requireWorkspaceCapability(authority, pending.request.workspace_id, .read);
    try port.requireWorkspaceCapability(authority, pending.request.workspace_id, .write);
    pending.first = first;
    pending.count = 0;
    pending.next = false;
    pending.text_length = 0;
    @memset(&pending.text, 0);
    @memset(std.mem.asBytes(&pending.entries), 0);
    var visible: usize = 0;
    // The workspace itself is bounded at 96 entries. Examine each at most once;
    // filter before copying any name or counting it toward the visible page.
    for (try manager.storageServicePtr().entries(pending.request.workspace_id)) |entry| {
        if (entry.object_type != .document or !protocol.validLabel(entry.pathSlice())) continue;
        _ = port.openEntry(authority, pending.request.workspace_id, entry.pathSlice(), .read) catch continue;
        port.requireDocumentWrite(authority, pending.request.workspace_id, entry.pathSlice(), entry.object_id.raw()) catch continue;
        visible += 1;
        if (visible <= first) continue;
        if (pending.count == protocol.PAGE_ENTRIES) {
            pending.next = true;
            break;
        }
        pending.entries[pending.count] = entry;
        if (pending.count != 0) {
            pending.text[pending.text_length] = '\n';
            pending.text_length += 1;
        }
        const label = entry.pathSlice();
        @memcpy(pending.text[pending.text_length..][0..label.len], label);
        pending.text_length += @intCast(label.len);
        pending.count += 1;
    }
}

fn current(manager: anytype, pending: *const Pending, now_ticks: u64) bool {
    const task = manager.runtimePtr().find(pending.request.authority.task_id) orelse return false;
    if (task.state != .active or !task.owner.eql(pending.request.authority.principal) or !task.hasCapability(pending.request.authority.capability_id)) return false;
    const storage = manager.storageServicePtr();
    pending.request.signer.validateService(storage.owner, storage.task_id, now_ticks) catch return false;
    var port = storage_service.StoragePort.init(storage, manager.capabilityTablePtr());
    var authority = pending.request.authority;
    authority.now_ticks = now_ticks;
    port.requireWorkspaceCapability(authority, pending.request.workspace_id, .read) catch return false;
    port.requireWorkspaceCapability(authority, pending.request.workspace_id, .write) catch return false;
    for (pending.entries[0..pending.count]) |entry| {
        const view = port.openEntry(authority, pending.request.workspace_id, entry.pathSlice(), .read) catch return false;
        if (view.object_type != .document or view.object_id.raw() != entry.object_id.raw() or view.version_id.raw() != entry.version_id.raw()) return false;
        port.requireDocumentWrite(authority, pending.request.workspace_id, entry.pathSlice(), entry.object_id.raw()) catch return false;
    }
    return true;
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
    if (protocol.MAX_LABEL_BYTES != workspace.MAX_ENTRY_PATH_BYTES) @compileError("picker must represent full workspace paths");
    if (heap_backed and @sizeOf(Launcher) > 24) @compileError("launcher handle exceeds resident size bound");
    if (@sizeOf(State) > 2048) @compileError("launcher exceeds bounded storage");
}

fn prepareTestDocument(manager: anytype, signing_fixture: *@import("../../tests/fixtures/document_signer.zig").Fixture) !documents.OpenRequest {
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
        .signer = try signing_fixture.init(task.owner, storage.owner, storage.task_id, signer),
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
        var signing_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
        const request = try prepareTestDocument(manager, &signing_fixture);
        const task = manager.runtimePtr().find(request.authority.task_id).?;
        const address_space_id = task.address_space_id;
        const windows_before = manager.compositorSessionPtr().window_count;
        const focus_before = manager.compositorSessionPtr().active_window_id;
        const launcher = &manager.launcher;
        const token = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
        const s = launcher.state().?;
        try std.testing.expectEqualStrings(request.path, s.pending.?.entries[0].pathSlice());
        try std.testing.expectError(error.LauncherBusy, manager.offerDocumentPicker(Request.fromDocument(request), 1));
        try drainTestPage(launcher, manager);
        try std.testing.expect(!launcher.hasPendingWork());
        try sendTestDecision(s, token + 1, .{ .open = 0 });
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(s.pending != null);
        if (case == .revoke) try manager.capabilityTablePtr().revokeGrant(request.authority.capability_id);
        if (case == .replace) {
            const storage = manager.storageServicePtr();
            const replacement = try storage.putVersion(.{
                .object_type = .document,
                .payload = "Replacement",
                .metadata = try request.signer.signMetadata("Notes", "Replacement", 1),
            });
            try storage.beginTransaction(request.workspace_id);
            try storage.stagePut(request.workspace_id, request.path, replacement.object_id, replacement.version_id, .document);
            _ = try storage.commit(request.workspace_id, 1);
        }
        try sendTestDecision(s, token, if (case == .cancel) .cancel else .{ .open = 0 });
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
        try sendTestDecision(s, token, .{ .open = 0 });
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
    var signing_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const request = try prepareTestDocument(manager, &signing_fixture);
    const endpoints_before = manager.kernelPort().?.kernel.endpoint_table.activeCount();
    const windows_before = manager.compositorSessionPtr().window_count;
    _ = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
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
    var signing_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const request = try prepareTestDocument(manager, &signing_fixture);
    const token = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
    const launcher = &manager.launcher;
    const s = launcher.state().?;
    try drainTestPage(launcher, manager);
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

fn drainTestPage(launcher: *Launcher, manager: anytype) !void {
    const s = launcher.state().?;
    var frames: usize = 0;
    while (s.outgoing != null) {
        try std.testing.expect(launcher.service(manager, 1));
        try std.testing.expect(try receiveTestFrame(s) == null);
        frames += 1;
        try std.testing.expect(frames <= 1 + (protocol.MAX_PAGE_TEXT_BYTES + protocol.CHUNK_BYTES - 1) / protocol.CHUNK_BYTES);
    }
}

test "document launcher pages authorized names and binds decisions to the displayed page" {
    const session_manager = @import("session_manager.zig");
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();
    session_manager.boot();
    const manager = session_manager.system();
    var fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const request = try prepareTestDocument(manager, &fixture);
    const storage = manager.storageServicePtr();
    try storage.beginTransaction(request.workspace_id);
    for ([_][]const u8{ "a.md", "b.md", "c.md", "d.md", "e.md", "f.md" }) |path| {
        const stored = try storage.putVersion(.{ .object_type = .document, .payload = path, .metadata = try request.signer.signMetadata("Notes", path, 1) });
        try storage.stagePut(request.workspace_id, path, stored.object_id, stored.version_id, .document);
    }
    _ = try storage.commit(request.workspace_id, 1);
    const launcher = &manager.launcher;
    const token = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
    const s = launcher.state().?;
    try std.testing.expectEqualStrings("a.md\nb.md\nc.md\nd.md", s.pending.?.text[0..s.pending.?.text_length]);
    try std.testing.expect(s.pending.?.next);
    try drainTestPage(launcher, manager);
    try sendTestDecision(s, token, .{ .move = true });
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expectEqual(token + 1, launcher.token);
    try std.testing.expectEqualStrings("documents/notes.md\ne.md\nf.md", s.pending.?.text[0..s.pending.?.text_length]);
    try std.testing.expect(!s.pending.?.next);
    try drainTestPage(launcher, manager);
    // A queued double page-down or old Open cannot choose a different document.
    try sendTestDecision(s, token, .{ .move = true });
    try sendTestDecision(s, token, .{ .open = 0 });
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expectEqual(token + 1, launcher.token);
    try std.testing.expect(s.pending != null);
    try sendTestDecision(s, launcher.token, .{ .open = 3 });
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expect(s.pending != null);
    try sendTestDecision(s, launcher.token, .{ .move = false });
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expectEqualStrings("a.md", s.pending.?.entries[0].pathSlice());
    try drainTestPage(launcher, manager);
    // Scope the workspace share to one object. Unlisted names stay hidden.
    const ws = storage.workspaces.find(ids.workspace(request.workspace_id)).?;
    ws.owner = .{ .kind = .user, .serial = 0xD0CF };
    const entry = try storage.resolve(request.workspace_id, request.path);
    try storage.shareWorkspace(request.workspace_id, try (workspace.ShareGrant{
        .principal_id = request.authority.principal,
        .can_read = true,
        .can_write = true,
        .expires_at_ticks = 1000,
        .network_scope = .local_only,
    }).withObjectScope(entry.object_id, request.path));
    var pending = Pending{ .request = Request.fromDocument(request), .window_id = 1, .previous_window_id = 0 };
    try selectPage(manager, &pending, 0, 1);
    try std.testing.expectEqualStrings(request.path, pending.text[0..pending.text_length]);
    try std.testing.expectEqual(@as(u8, 1), pending.count);
    try std.testing.expect(!pending.next);
    // The displayed page has lost access: navigation closes instead of using it.
    try sendTestDecision(s, launcher.token, .{ .move = true });
    try std.testing.expect(launcher.service(manager, 1));
    try std.testing.expectEqual(protocol.Status.unavailable, s.result.?.status);
}

test "document launcher withdraws buffered names on revocation suspension and expiry" {
    const session_manager = @import("session_manager.zig");
    for ([_]enum { revoke, suspended, expire, membership, signing }{ .revoke, .suspended, .expire, .membership, .signing }) |case| {
        session_manager.testing.resetState();
        defer session_manager.testing.resetState();
        session_manager.boot();
        const manager = session_manager.system();
        var fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
        const request = try prepareTestDocument(manager, &fixture);
        _ = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
        const launcher = &manager.launcher;
        const s = launcher.state().?;
        // Publish only the header. No label byte has reached the client yet.
        try std.testing.expect(launcher.service(manager, 1));
        _ = try receiveTestFrame(s);
        switch (case) {
            .revoke => try manager.capabilityTablePtr().revokeGrant(request.authority.capability_id),
            .suspended => {
                _ = try manager.runtimePtr().suspendTask(request.authority.task_id, 1);
            },
            .membership => {
                _ = try manager.runtimePtr().revokeCapability(request.authority.task_id, request.authority.capability_id);
            },
            .signing => fixture.service.findHandle(request.signer.key.handle_id).?.revoked = true,
            .expire => {},
        }
        const now: u64 = if (case == .expire) 1001 else 1;
        try std.testing.expect(launcher.service(manager, now));
        try std.testing.expect(s.pending == null);
        try std.testing.expect(launcher.service(manager, now));
        try std.testing.expectEqual(protocol.Status.unavailable, (try receiveTestFrame(s)).?.status);
        try std.testing.expect(!launcher.hasPendingWork());
    }
}

test "document launcher validates empty workspaces and does not steal changed focus" {
    const session_manager = @import("session_manager.zig");
    for ([_]bool{ false, true }) |empty| {
        session_manager.testing.resetState();
        defer session_manager.testing.resetState();
        session_manager.boot();
        const manager = session_manager.system();
        var fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
        const request = try prepareTestDocument(manager, &fixture);
        if (empty) {
            const storage = manager.storageServicePtr();
            try storage.beginTransaction(request.workspace_id);
            try storage.stageDelete(request.workspace_id, request.path);
            _ = try storage.commit(request.workspace_id, 1);
        }
        const launcher = &manager.launcher;
        const token = try manager.offerDocumentPicker(Request.fromDocument(request), 1);
        const s = launcher.state().?;
        try drainTestPage(launcher, manager);
        if (empty) {
            try std.testing.expectEqual(@as(u8, 0), s.pending.?.count);
            try manager.capabilityTablePtr().revokeGrant(request.authority.capability_id);
            try sendTestDecision(s, token, .{ .open = 0 });
            try std.testing.expect(launcher.service(manager, 1));
            try std.testing.expectEqual(protocol.Status.unavailable, s.result.?.status);
        } else {
            const other = try manager.compositorSessionPtr().openTaskView(manager.runtimePtr().find(s.client_task_id).?, "Another view");
            const other_id = other.id;
            try sendTestDecision(s, token, .{ .open = 0 });
            try std.testing.expect(launcher.service(manager, 1));
            try std.testing.expectEqual(protocol.Status.unavailable, s.result.?.status);
            try std.testing.expectEqual(other_id, manager.compositorSessionPtr().active_window_id);
            try std.testing.expect(manager.userspaceSchedulerPtr().taskDispatchStats(request.authority.task_id) == null);
        }
    }
}
