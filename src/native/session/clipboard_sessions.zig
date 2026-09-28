const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const port = @import("../kernel_api/component_port.zig");
const executor = @import("../task/userspace_executor.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const pasteboard = @import("../services/secure_pasteboard.zig");
const protocol = @import("../../userspace/clipboard_protocol.zig");
const timer = @import("../../kernel/timer/timer.zig");
const memory = if (builtin.target.os.tag == .freestanding) @import("../../kernel/memory/memory.zig") else struct {};
const heap_backed = builtin.target.os.tag == .freestanding;
pub const MAX_CHANNELS = 4;
pub const DISPATCH_BUDGET = 2;
pub const GESTURE_TICKS = 5 * timer.TICKS_PER_SECOND;
pub const CONTENT_TICKS = 5 * 60 * timer.TICKS_PER_SECOND;

const Gesture = struct {
    sequence: u64,
    deadline: u64,
    window: u64,
    surface: u64,
    epoch: u64,
    focus_epoch: u32,
    kind: u8,
};
const Outgoing = struct {
    gesture: u64,
    bytes: [protocol.MAX_FRAME_BYTES]u8,
    length: u8,
    finish: bool,
};
const Channel = struct {
    task_id: u64 = 0,
    client_endpoint: u64 = 0,
    server_endpoint: u64 = 0,
    server_capability: u64 = 0,
    binding: mailbox.ClipboardBinding = .{},
    available: ?Gesture = null,
    authorization: ?Gesture = null,
    operation: enum { idle, copy, paste } = .idle,
    source_task: u64 = 0,
    length: u16 = 0,
    offset: u16 = 0,
    bytes: [protocol.MAX_TEXT_BYTES]u8 = @splat(0),
    outgoing: ?Outgoing = null,

    fn clearOutgoing(self: *Channel) void {
        if (self.outgoing) |*outgoing| @memset(&outgoing.bytes, 0);
        self.outgoing = null;
    }

    fn clearTransfer(self: *Channel) void {
        @memset(&self.bytes, 0);
        self.authorization = null;
        self.operation = .idle;
        self.source_task = 0;
        self.length = 0;
        self.offset = 0;
    }
};
const Item = struct {
    source_task: u64 = 0,
    expires: u64 = 0,
    length: u16 = 0,
    bytes: [protocol.MAX_TEXT_BYTES]u8 = @splat(0),
};
const State = struct {
    kernel: *port.KernelPort,
    channels: [MAX_CHANNELS]Channel = @splat(.{}),
    grants: pasteboard.Service = .{},
    item: Item = .{},
    cursor: u8 = 0,
};

// The session records gestures only after authorized input_recv delivery.
// Endpoint clients cannot mint this evidence by supplying a sequence number.
pub const Sessions = struct {
    backing: if (heap_backed) ?*State else ?State = null,
    owner_task_id: u64 = 0,

    fn state(self: *Sessions) ?*State {
        if (comptime heap_backed) return self.backing;
        return if (self.backing) |*s| s else null;
    }
    fn stateConst(self: *const Sessions) ?*const State {
        if (comptime heap_backed) return self.backing;
        return if (self.backing) |*s| s else null;
    }
    fn ensure(self: *Sessions, kernel: *port.KernelPort) !*State {
        if (self.state()) |s| return s;
        if (comptime heap_backed) {
            const allocation = memory.kmalloc(@sizeOf(State)) orelse return error.NoSpaceLeft;
            self.backing = @ptrCast(@alignCast(allocation));
            self.backing.?.* = .{ .kernel = kernel };
        } else self.backing = .{ .kernel = kernel };
        return self.state().?;
    }

    pub fn open(self: *Sessions, manager: anytype, task_id: u64, now: u64) !mailbox.ClipboardBinding {
        const kernel = manager.kernelPort() orelse return error.KernelUnavailable;
        const task = manager.runtimePtr().find(task_id) orelse return error.TaskNotFound;
        const owner = manager.runtimePtr().find(self.owner_task_id) orelse return error.TaskNotFound;
        if (task.state != .active or owner.state != .active) return error.PermissionDenied;
        const s = try self.ensure(kernel);
        var free: ?*Channel = null;
        for (&s.channels) |*channel| {
            if (channel.task_id == task_id) return error.ClipboardAlreadyOpen;
            if (channel.task_id == 0 and free == null) free = channel;
        }
        const channel = free orelse return error.ClipboardTableFull;
        const client = try kernel.endpointCreate(.{
            .header = port.makeHeader(.endpoint_create, task_id),
            .authority_capability_id = executor.resolveMailboxAuthorities(task, manager.capabilityTablePtr(), now).bootstrap_capability_id,
            .owner_task_id = task_id,
            .label = "clipboard-client",
            .flags = .{ .local_only = true },
        }, now);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(client.endpoint.endpoint_id), now) catch unreachable;
        const server = try kernel.endpointCreate(.{
            .header = port.makeHeader(.endpoint_create, owner.id),
            .authority_capability_id = executor.resolveMailboxAuthorities(owner, manager.capabilityTablePtr(), now).bootstrap_capability_id,
            .owner_task_id = owner.id,
            .label = "clipboard-service",
            .flags = .{ .local_only = true, .service_port = true },
        }, now);
        errdefer kernel.kernel.retireEndpoint(ids.endpoint(server.endpoint.endpoint_id), now) catch unreachable;
        _ = try kernel.endpointConnect(.{
            .header = port.makeHeader(.endpoint_connect, task_id),
            .endpoint_capability_id = client.capability_id,
            .peer_endpoint_capability_id = server.capability_id,
            .peer_endpoint_id = server.endpoint.endpoint_id,
        }, now);
        channel.* = .{
            .task_id = task_id,
            .client_endpoint = client.endpoint.endpoint_id,
            .server_endpoint = server.endpoint.endpoint_id,
            .server_capability = server.capability_id,
            .binding = .{ .endpoint_capability_id = client.capability_id, .service_endpoint_id = server.endpoint.endpoint_id },
        };
        return channel.binding;
    }

    pub fn observe(self: *Sessions, manager: anytype, event: abi.InputEventDescriptor) void {
        const s = self.state() orelse return;
        for (&s.channels) |*channel| {
            if (channel.task_id != event.task_id) continue;
            channel.available = null;
            channel.clearOutgoing();
            channel.clearTransfer();
            if (event.sequence == 0 or event.length != 2 or event.bytes[1] != 0 or
                (event.bytes[0] != abi.InputByte.copy and event.bytes[0] != abi.InputByte.cut and event.bytes[0] != abi.InputByte.paste)) return;
            const gesture = Gesture{
                .sequence = event.sequence,
                .deadline = event.tick +| GESTURE_TICKS,
                .window = event.window_id,
                .surface = event.surface_id,
                .epoch = manager.inputRouterPtr().routing_epoch,
                .focus_epoch = manager.compositorSessionPtr().focus_epoch,
                .kind = event.bytes[0],
            };
            if (focused(manager, channel.task_id, gesture, event.tick)) channel.available = gesture;
            return;
        }
    }

    pub fn service(self: *Sessions, manager: anytype, now: u64) bool {
        const s = self.state() orelse return false;
        var progress: usize = 0;
        if (s.item.source_task != 0 and (now >= s.item.expires or !manager.documents.allowsClipboard(s.item.source_task, false, now))) {
            s.item = .{};
            progress += 1;
        }
        for (0..MAX_CHANNELS) |_| {
            const channel = &s.channels[s.cursor];
            s.cursor = @intCast((s.cursor + 1) % MAX_CHANNELS);
            if (channel.task_id == 0) continue;
            switch (peerState(s, channel, self.owner_task_id)) {
                .closed => {
                    self.closeTask(channel.task_id, now);
                    progress += 1;
                },
                .suspended => {
                    // Suspension revokes input intent and staged transfer data.
                    if (channel.available != null or channel.authorization != null) {
                        channel.available = null;
                        if (channel.authorization) |g| queue(channel, g.sequence, .{ .status = .denied }, true);
                        channel.clearTransfer();
                        progress += 1;
                    }
                },
                .active => {
                    if (channel.available) |g| if (now >= g.deadline) {
                        channel.available = null;
                    };
                    if (channel.authorization) |g| if (!authorized(manager, channel, g, now)) {
                        queue(channel, g.sequence, .{ .status = if (now >= g.deadline) .expired else .denied }, true);
                        channel.clearTransfer();
                    };
                    if (self.runOnce(manager, s, channel, now) catch failed: {
                        self.closeTask(channel.task_id, now);
                        break :failed true;
                    }) progress += 1;
                },
            }
            if (progress >= DISPATCH_BUDGET) break;
        }
        return progress != 0;
    }

    fn runOnce(self: *Sessions, manager: anytype, s: *State, channel: *Channel, now: u64) !bool {
        if (channel.outgoing) |*outgoing| {
            trySend: {
                s.kernel.endpointSend(.{
                    .header = port.makeHeader(.endpoint_send, self.owner_task_id),
                    .endpoint_capability_id = channel.server_capability,
                    .reply_endpoint_id = channel.client_endpoint,
                    .correlation_id = outgoing.gesture,
                    .payload = outgoing.bytes[0..outgoing.length],
                }, now) catch |err| switch (err) {
                    error.RingFull => break :trySend,
                    else => return err,
                };
                const finish = outgoing.finish;
                channel.clearOutgoing();
                if (finish) channel.clearTransfer();
                return true;
            }
            return false;
        }
        var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        var attached: abi.CapabilityDescriptor = undefined;
        const received = (try s.kernel.endpointRecv(.{
            .header = port.makeHeader(.endpoint_recv, self.owner_task_id),
            .endpoint_capability_id = channel.server_capability,
            .receiver_task_id = self.owner_task_id,
            .payload_out = &bytes,
            .attached_capability_out = &attached,
        }, now)) orelse return false;
        if (received.attached_capability) |cap| {
            s.kernel.kernel.capability_table.revokeGrant(cap.capability_id) catch {};
            return error.UnexpectedAuthority;
        }
        if (received.message.sender_task_id != channel.task_id or received.message.sender_endpoint_id != channel.client_endpoint)
            return error.UnexpectedPeer;
        const frame = protocol.decode(bytes[0..received.message.payload_len]) catch return error.InvalidFrame;
        if (frame.gesture != received.message.correlation_id or frame.body == .reply) return error.InvalidFrame;
        handle(manager, s, channel, frame, now);
        return true;
    }

    pub fn closeTask(self: *Sessions, task_id: u64, now: u64) void {
        const s = self.state() orelse return;
        if (s.item.source_task == task_id) s.item = .{};
        for (&s.channels) |*channel| {
            if (channel.task_id != task_id or task_id == 0) continue;
            for ([_]u64{ channel.client_endpoint, channel.server_endpoint }) |id| {
                s.kernel.kernel.retireEndpoint(ids.endpoint(id), now) catch |err| switch (err) {
                    error.EndpointNotFound => {},
                    else => unreachable,
                };
            }
            channel.* = .{};
        }
    }

    pub fn hasPendingWork(self: *const Sessions) bool {
        const s = self.stateConst() orelse return false;
        for (&s.channels) |*channel| {
            if (channel.task_id == 0) continue;
            switch (peerState(s, channel, self.owner_task_id)) {
                .closed => return true,
                .suspended => {
                    if (channel.available != null or channel.authorization != null) return true;
                },
                .active => {
                    const id = if (channel.outgoing != null) channel.client_endpoint else channel.server_endpoint;
                    const descriptor = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(id)) catch return true;
                    if (if (channel.outgoing != null) descriptor.queued_messages < endpoint.MAX_ENDPOINT_QUEUE else descriptor.queued_messages != 0) return true;
                },
            }
        }
        return false;
    }

    pub fn nextWake(self: *const Sessions) ?u64 {
        const s = self.stateConst() orelse return null;
        var wake: ?u64 = if (s.item.source_task != 0) s.item.expires else null;
        for (&s.channels) |*channel| {
            for ([_]?Gesture{ channel.available, channel.authorization }) |g| if (g) |gesture| {
                wake = if (wake) |value| @min(value, gesture.deadline) else gesture.deadline;
            };
        }
        return wake;
    }

    pub fn transferPendingForTask(self: *const Sessions, task_id: u64) bool {
        const s = self.stateConst() orelse return false;
        for (&s.channels) |*channel| {
            if (channel.task_id != task_id) continue;
            if (channel.available != null or channel.authorization != null or channel.outgoing != null) return true;
            for ([_]u64{ channel.client_endpoint, channel.server_endpoint }) |id| {
                const descriptor = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(id)) catch return false;
                if (descriptor.queued_messages != 0) return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *Sessions, now: u64) void {
        const s = self.state() orelse return;
        for (&s.channels) |*channel| if (channel.task_id != 0) {
            self.closeTask(channel.task_id, now);
        };
        if (comptime heap_backed) {
            @memset(std.mem.asBytes(s), 0);
            memory.kfree(@ptrCast(s));
        }
        self.backing = null;
    }
};

fn focused(manager: anytype, task_id: u64, gesture: Gesture, now: u64) bool {
    if (now >= gesture.deadline or gesture.deadline - now > GESTURE_TICKS or
        gesture.epoch == std.math.maxInt(u64) or gesture.epoch != manager.inputRouterPtr().routing_epoch or
        gesture.focus_epoch == std.math.maxInt(u32) or gesture.focus_epoch != manager.compositorSessionPtr().focus_epoch) return false;
    const window = manager.compositorSessionPtr().activeWindow() orelse return false;
    return window.id == gesture.window and window.subject_task_id == task_id and
        (!window.modal or window.reviewer_task_id == 0) and (window.ui_surface_id orelse 0) == gesture.surface;
}

fn authorized(manager: anytype, channel: *const Channel, gesture: Gesture, now: u64) bool {
    if (!focused(manager, channel.task_id, gesture, now) or
        !manager.documents.allowsClipboard(channel.task_id, gesture.kind != abi.InputByte.copy, now)) return false;
    return channel.operation != .paste or manager.documents.allowsClipboard(channel.source_task, false, now);
}

fn handle(manager: anytype, s: *State, channel: *Channel, frame: protocol.Frame, now: u64) void {
    if (frame.body == .copy_begin or frame.body == .paste) {
        const gesture = channel.available;
        channel.available = null;
        if (channel.operation != .idle or gesture == null or gesture.?.sequence != frame.gesture or
            ((frame.body == .paste) != (gesture.?.kind == abi.InputByte.paste)) or
            !authorized(manager, channel, gesture.?, now))
        {
            queue(channel, frame.gesture, .{ .status = .denied }, true);
            return;
        }
        channel.authorization = gesture;
        if (frame.body == .copy_begin) {
            channel.operation = .copy;
            channel.length = frame.body.copy_begin;
            queue(channel, frame.gesture, .{ .status = .ok, .total = channel.length }, false);
            return;
        }
        if (s.item.source_task == 0 or now >= s.item.expires) {
            queue(channel, frame.gesture, .{ .status = .empty }, true);
            return;
        }
        channel.operation = .paste;
        channel.source_task = s.item.source_task;
        if (!authorized(manager, channel, gesture.?, now)) {
            queue(channel, frame.gesture, .{ .status = .denied }, true);
            return;
        }
        const source = manager.runtimePtr().findConst(channel.source_task) orelse unreachable;
        const destination = manager.runtimePtr().findConst(channel.task_id) orelse unreachable;
        const grant = s.grants.offer(.{
            .subject = source.owner,
            .destination = destination.owner,
            .source_task_id = source.id,
            .destination_task_id = destination.id,
            .user_gesture_id = frame.gesture,
            .foreground_session_id = gesture.?.window,
            .expires_at_ticks = gesture.?.deadline,
            .now_ticks = now,
            .purpose = "foreground text paste",
            .payload = s.item.bytes[0..s.item.length],
        }, &manager.recovery_context.diagnostic_ledger) catch {
            queue(channel, frame.gesture, .{ .status = .unavailable }, true);
            return;
        };
        const text = s.grants.read(.{
            .subject = destination.owner,
            .destination_task_id = destination.id,
            .token_id = grant.token_id,
            .user_gesture_id = frame.gesture,
            .foreground_session_id = gesture.?.window,
            .now_ticks = now,
            .expected_purpose = "foreground text paste",
        }, &channel.bytes, &manager.recovery_context.diagnostic_ledger) catch {
            queue(channel, frame.gesture, .{ .status = .unavailable }, true);
            return;
        };
        channel.length = @intCast(text.len);
        pasteReply(channel, frame.gesture);
        return;
    }
    const gesture = channel.authorization orelse {
        queue(channel, frame.gesture, .{ .status = .denied }, true);
        return;
    };
    if (gesture.sequence != frame.gesture or !authorized(manager, channel, gesture, now)) {
        queue(channel, frame.gesture, .{ .status = .denied }, true);
        return;
    }
    switch (frame.body) {
        .copy_chunk => |chunk| {
            if (channel.operation != .copy or chunk.offset != channel.offset or chunk.bytes.len > channel.length - channel.offset) {
                queue(channel, frame.gesture, .{ .status = .invalid }, true);
                return;
            }
            @memcpy(channel.bytes[channel.offset..][0..chunk.bytes.len], chunk.bytes);
            channel.offset += @intCast(chunk.bytes.len);
            queue(channel, frame.gesture, .{ .status = .ok, .total = channel.length, .offset = channel.offset }, false);
        },
        .copy_commit => {
            if (channel.operation != .copy or channel.offset != channel.length or !abi.text_layout.unicode.validText(channel.bytes[0..channel.length])) {
                queue(channel, frame.gesture, .{ .status = .invalid }, true);
                return;
            }
            s.item = .{ .source_task = channel.task_id, .expires = now +| CONTENT_TICKS, .length = channel.length };
            @memcpy(s.item.bytes[0..channel.length], channel.bytes[0..channel.length]);
            queue(channel, frame.gesture, .{ .status = .ok, .total = channel.length, .offset = channel.length }, true);
        },
        .paste_read => |offset| {
            if (channel.operation != .paste or offset != channel.offset or offset >= channel.length) {
                queue(channel, frame.gesture, .{ .status = .invalid }, true);
                return;
            }
            pasteReply(channel, frame.gesture);
        },
        else => queue(channel, frame.gesture, .{ .status = .invalid }, true),
    }
}

fn pasteReply(channel: *Channel, gesture: u64) void {
    const end = @min(channel.offset + protocol.CHUNK_BYTES, channel.length);
    queue(channel, gesture, .{ .status = .ok, .total = channel.length, .offset = channel.offset, .bytes = channel.bytes[channel.offset..end] }, end == channel.length);
    channel.offset = @intCast(end);
}

fn queue(channel: *Channel, gesture: u64, reply: protocol.Reply, finish: bool) void {
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const encoded = protocol.encode(&bytes, .{ .gesture = gesture, .body = .{ .reply = reply } }) catch unreachable;
    channel.outgoing = .{ .gesture = gesture, .bytes = bytes, .length = @intCast(encoded.len), .finish = finish };
}

fn peerState(s: *const State, channel: *const Channel, owner: u64) enum { active, suspended, closed } {
    const client = s.kernel.kernel.runtime.findConst(channel.task_id) orelse return .closed;
    const server = s.kernel.kernel.runtime.findConst(owner) orelse return .closed;
    if (client.state == .terminated or server.state == .terminated) return .closed;
    _ = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(channel.client_endpoint)) catch return .closed;
    _ = s.kernel.kernel.endpoint_table.descriptor(ids.endpoint(channel.server_endpoint)) catch return .closed;
    return if (client.state == .suspended or server.state == .suspended) .suspended else .active;
}

comptime {
    if (heap_backed and @sizeOf(Sessions) > 16) @compileError("clipboard session handle exceeds resident size bound");
    if (@sizeOf(Channel) > 1024 or @sizeOf(State) > 16 * 1024) @compileError("clipboard state exceeds its lazy allocation bound");
}

const TestFixture = struct {
    const runtime_mod = @import("../task/task_runtime.zig");
    const caps = @import("../kernel_api/capability.zig");
    const kernel_mod = @import("../kernel_api/native_kernel.zig");
    const router_mod = @import("../platform/input_router.zig");
    const compositor_mod = @import("../platform/compositor_session.zig");
    runtime: runtime_mod.Runtime = .init(),
    capabilities: caps.CapabilityTable = .init(),
    endpoints: endpoint.Table = .init(),
    shared: @import("../kernel_api/shared_memory.zig").Table = .init(),
    kernel: kernel_mod.Kernel = undefined,
    port: port.KernelPort = undefined,
    router: router_mod.Router = .{},
    compositor: compositor_mod.Session = .init(),
    clipboard: Sessions = .{},
    recovery_context: struct { diagnostic_ledger: @import("../platform/event_ledger.zig").Ledger = .init() } = .{},
    documents: struct {
        denied_task: u64 = 0,
        pub fn allowsClipboard(self: *@This(), task_id: u64, _: bool, _: u64) bool {
            return task_id != 0 and self.denied_task != task_id;
        }
    } = .{},
    tasks: [2]u64 = undefined,
    windows: [2]u64 = undefined,
    bindings: [2]mailbox.ClipboardBinding = undefined,
    receive_capabilities: [2]u64 = undefined,
    sequence: u64 = 0,
    received: [protocol.MAX_FRAME_BYTES]u8 = undefined,

    pub fn kernelPort(self: *@This()) ?*port.KernelPort {
        return &self.port;
    }
    pub fn runtimePtr(self: *@This()) *runtime_mod.Runtime {
        return &self.runtime;
    }
    pub fn capabilityTablePtr(self: *@This()) *caps.CapabilityTable {
        return &self.capabilities;
    }
    pub fn inputRouterPtr(self: *@This()) *router_mod.Router {
        return &self.router;
    }
    pub fn compositorSessionPtr(self: *@This()) *compositor_mod.Session {
        return &self.compositor;
    }

    fn init() !*@This() {
        const f = try std.testing.allocator.create(@This());
        f.* = .{};
        errdefer std.testing.allocator.destroy(f);
        f.kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &f.runtime, &f.capabilities, &f.endpoints, &f.shared);
        f.port = port.KernelPort.init(&f.kernel);
        const budget = runtime_mod.ResourceBudget{ .cpu_time_ticks = 1000, .memory_bytes = 4096, .endpoint_slots = 8, .shared_memory_bytes = 0 };
        const service_task = try f.runtime.createTask(.{ .owner = .{ .kind = .service, .serial = 1 }, .component_class = .service_component, .budget = budget, .local_only = true });
        try f.bootstrap(service_task);
        f.clipboard.owner_task_id = service_task.id;
        for (0..2) |index| {
            const task = try f.runtime.createTask(.{ .owner = .{ .kind = .app, .serial = index + 1 }, .component_class = .app_component, .budget = budget, .ui_surface_id = index + 1, .local_only = true });
            try f.bootstrap(task);
            f.tasks[index] = task.id;
            f.windows[index] = (try f.compositor.openDocumentView(task, 1, "notes.md")).id;
            f.bindings[index] = try f.clipboard.open(f, task.id, 0);
            const receive = try f.capabilities.mintBootRoot(.{
                .holder = task.owner,
                .issuer = f.kernel.policy_authority,
                .target = .{ .kind = .task, .id = task.id },
                .rights = .{ .task = .{ .input_recv = true } },
                .scope = .{ .task_id = task.id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
            });
            try f.runtime.grantCapability(task.id, receive.id);
            f.receive_capabilities[index] = receive.id;
        }
        f.router.bindCompositor(&f.compositor, service_task.id);
        f.router.bindHardwareSource(.{ .poll_report = testPollReport, .input_proof = testNoProof });
        f.kernel.bindFocusedInputReceiver(.{ .context = f, .poll = pollForKernel });
        return f;
    }
    fn deinit(f: *@This()) void {
        f.clipboard.deinit(0);
        f.router.deinit();
        f.compositor.deinit();
        f.kernel.deinit();
        std.testing.allocator.destroy(f);
    }
    fn bootstrap(f: *@This(), task: *runtime_mod.TaskRecord) !void {
        const grant = try f.capabilities.mintBootRoot(.{
            .holder = task.owner,
            .issuer = f.kernel.policy_authority,
            .target = .{ .kind = .service, .id = 1 },
            .rights = .{ .service = .{ .endpoint_create = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
        });
        try f.runtime.grantCapability(task.id, grant.id);
    }
    fn pollForKernel(context: *anyopaque, task_id: u64) ?abi.InputEventDescriptor {
        const f: *@This() = @ptrCast(@alignCast(context));
        const event = f.router.pollAbiForTask(task_id) orelse return null;
        f.clipboard.observe(f, event);
        return event;
    }
    fn gesture(f: *@This(), index: usize, usage: u8) !u64 {
        _ = try f.compositor.switchView(f.windows[index]);
        for ([_]u8{ 0, usage }) |key| {
            f.sequence += 1;
            test_report = .{ .sequence = f.sequence, .port_id = 1, .slot_id = 1, .endpoint_id = 3 };
            test_report.?.bytes[0] = 1;
            test_report.?.bytes[2] = key;
            _ = f.router.service(10, 1);
        }
        const event = (try f.port.inputRecv(.{
            .header = port.makeHeader(.input_recv, f.tasks[index]),
            .input_capability_id = f.receive_capabilities[index],
            .receiver_task_id = f.tasks[index],
        }, 10)).?;
        return event.sequence;
    }
    fn send(f: *@This(), index: usize, gesture_id: u64, body: protocol.Body) !void {
        var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        try f.port.endpointSend(.{
            .header = port.makeHeader(.endpoint_send, f.tasks[index]),
            .endpoint_capability_id = f.bindings[index].endpoint_capability_id,
            .correlation_id = gesture_id,
            .payload = try protocol.encode(&bytes, .{ .gesture = gesture_id, .body = body }),
        }, 10);
    }
    fn exchange(f: *@This(), index: usize, gesture_id: u64, body: protocol.Body, now: u64) !protocol.Reply {
        try f.send(index, gesture_id, body);
        for (0..3) |_| _ = f.clipboard.service(f, now);
        return f.receiveReply(index, gesture_id, now);
    }
    fn receiveReply(f: *@This(), index: usize, gesture_id: u64, now: u64) !protocol.Reply {
        var attached: abi.CapabilityDescriptor = undefined;
        const reply = (try f.port.endpointRecv(.{
            .header = port.makeHeader(.endpoint_recv, f.tasks[index]),
            .endpoint_capability_id = f.bindings[index].endpoint_capability_id,
            .receiver_task_id = f.tasks[index],
            .payload_out = &f.received,
            .attached_capability_out = &attached,
        }, now)).?;
        try std.testing.expect(reply.attached_capability == null);
        try std.testing.expectEqual(f.bindings[index].service_endpoint_id, reply.message.sender_endpoint_id);
        try std.testing.expectEqual(gesture_id, reply.message.correlation_id);
        return (try protocol.decode(f.received[0..reply.message.payload_len])).body.reply;
    }
    fn copy(f: *@This(), index: usize, text: []const u8) !u64 {
        const g = try f.gesture(index, 0x06);
        try std.testing.expectEqual(protocol.Status.ok, (try f.exchange(index, g, .{ .copy_begin = @intCast(text.len) }, 10)).status);
        var offset: usize = 0;
        while (offset < text.len) {
            const end = @min(offset + protocol.CHUNK_BYTES, text.len);
            const result = try f.exchange(index, g, .{ .copy_chunk = .{ .offset = @intCast(offset), .bytes = text[offset..end] } }, 10);
            try std.testing.expectEqual(protocol.Status.ok, result.status);
            try std.testing.expectEqual(end, result.offset);
            offset = end;
        }
        try std.testing.expectEqual(protocol.Status.ok, (try f.exchange(index, g, .{ .copy_commit = {} }, 10)).status);
        return g;
    }
};
var test_report: ?@import("../../kernel/drivers/xhci.zig").HardwareBootKeyboardReport = null;
fn testPollReport() ?@import("../../kernel/drivers/xhci.zig").HardwareBootKeyboardReport {
    const report = test_report;
    test_report = null;
    return report;
}
fn testNoProof() ?@import("../../kernel/drivers/xhci.zig").InputProof {
    return null;
}

test "clipboard session requires delivered gestures and transfers a pinned payload through native endpoints" {
    const f = try TestFixture.init();
    defer f.deinit();
    try std.testing.expectEqual(protocol.Status.denied, (try f.exchange(0, 500, .{ .paste = {} }, 10)).status);
    const text: [protocol.MAX_TEXT_BYTES]u8 = @splat('x');
    const copied = try f.copy(0, &text);
    try std.testing.expectEqual(protocol.Status.denied, (try f.exchange(0, copied, .{ .copy_begin = 1 }, 10)).status);
    const g = try f.gesture(1, 0x19);
    var reply = try f.exchange(1, g, .{ .paste = {} }, 10);
    var offset: usize = 0;
    while (true) {
        try std.testing.expectEqual(protocol.Status.ok, reply.status);
        try std.testing.expectEqual(text.len, reply.total);
        try std.testing.expectEqual(offset, reply.offset);
        try std.testing.expectEqualStrings(text[offset..][0..reply.bytes.len], reply.bytes);
        offset += reply.bytes.len;
        if (offset == text.len) break;
        // A later copy cannot splice its bytes into a paste already in flight.
        if (offset == protocol.CHUNK_BYTES) @memset(&f.clipboard.state().?.item.bytes, 'y');
        reply = try f.exchange(1, g, .{ .paste_read = @intCast(offset) }, 10);
    }
    try std.testing.expectEqual(protocol.Status.denied, (try f.exchange(1, g, .{ .paste = {} }, 10)).status);
    for (&f.clipboard.state().?.grants.grants) |*grant| {
        if (grant.token_id == 0) continue;
        try std.testing.expect(grant.consumed);
        try std.testing.expectEqual(@as(u16, 0), grant.payload_len);
    }
    // The same task is also a valid destination, using a new gesture each time.
    for (0..pasteboard.MAX_GRANTS + 1) |_| {
        _ = try f.copy(1, "local");
        const local = try f.gesture(1, 0x19);
        const pasted = try f.exchange(1, local, .{ .paste = {} }, 10);
        try std.testing.expectEqualStrings("local", pasted.bytes);
        try std.testing.expect(!f.clipboard.transferPendingForTask(f.tasks[1]));
    }
}

test "clipboard session rejects focus replay source restart expiry and revoked document access" {
    for ([_]enum { focus, source, expired, wrong_task, wrong_kind, revoked, exhausted_focus, exhausted_routing }{ .focus, .source, .expired, .wrong_task, .wrong_kind, .revoked, .exhausted_focus, .exhausted_routing }) |case| {
        const f = try TestFixture.init();
        defer f.deinit();
        const g = try f.gesture(0, if (case == .wrong_kind) 0x19 else 0x06);
        switch (case) {
            .focus => {
                _ = try f.compositor.switchView(f.windows[1]);
                _ = try f.compositor.switchView(f.windows[0]);
            },
            .source => f.router.bindHardwareSource(.{ .poll_report = testPollReport, .input_proof = testNoProof }),
            .revoked => f.documents.denied_task = f.tasks[0],
            .exhausted_focus => f.compositor.focus_epoch = std.math.maxInt(u32),
            .exhausted_routing => f.router.routing_epoch = std.math.maxInt(u64),
            else => {},
        }
        const result = try f.exchange(if (case == .wrong_task) 1 else 0, g, .{ .copy_begin = 4 }, if (case == .expired) 10 + GESTURE_TICKS else 10);
        try std.testing.expectEqual(protocol.Status.denied, result.status);
        try std.testing.expectEqual(@as(u64, 0), f.clipboard.state().?.item.source_task);
    }
}

test "clipboard session retains blocked replies and rechecks authority before completing a paste" {
    for ([_]enum { retained, focus, source, destination, expired, suspended }{ .retained, .focus, .source, .destination, .expired, .suspended }) |case| {
        const f = try TestFixture.init();
        defer f.deinit();
        const text: [2 * protocol.CHUNK_BYTES]u8 = @splat('p');
        _ = try f.copy(0, &text);
        const g = try f.gesture(1, 0x19);
        const first = try f.exchange(1, g, .{ .paste = {} }, 10);
        try std.testing.expectEqual(protocol.CHUNK_BYTES, first.bytes.len);
        const channel = &f.clipboard.state().?.channels[1];
        var filler: [protocol.MAX_FRAME_BYTES]u8 = undefined;
        const payload = try protocol.encode(&filler, .{ .gesture = 900, .body = .{ .reply = .{ .status = .empty } } });
        for (0..endpoint.MAX_ENDPOINT_QUEUE) |_| try f.port.endpointSend(.{
            .header = port.makeHeader(.endpoint_send, f.clipboard.owner_task_id),
            .endpoint_capability_id = channel.server_capability,
            .reply_endpoint_id = channel.client_endpoint,
            .correlation_id = 900,
            .payload = payload,
        }, 10);
        try f.send(1, g, .{ .paste_read = protocol.CHUNK_BYTES });
        try std.testing.expect(f.clipboard.service(f, 10));
        try std.testing.expect(!f.clipboard.service(f, 10));
        try std.testing.expect(!f.clipboard.hasPendingWork());
        try std.testing.expect(channel.outgoing != null);
        const now: u64 = if (case == .expired) 10 + GESTURE_TICKS else 10;
        switch (case) {
            .focus => {
                _ = try f.compositor.switchView(f.windows[0]);
                _ = try f.compositor.switchView(f.windows[1]);
            },
            .source => f.documents.denied_task = f.tasks[0],
            .destination => f.documents.denied_task = f.tasks[1],
            .suspended => try std.testing.expect(try f.runtime.suspendTask(f.tasks[1], now)),
            else => {},
        }
        _ = f.clipboard.service(f, now);
        if (case != .retained) {
            try std.testing.expect(channel.authorization == null);
            try std.testing.expectEqualSlices(u8, &@as([protocol.MAX_TEXT_BYTES]u8, @splat(0)), &channel.bytes);
        }
        if (case == .suspended) {
            try std.testing.expect(!f.clipboard.hasPendingWork());
            try std.testing.expect(try f.runtime.resumeTask(f.tasks[1], now));
        }
        for (0..endpoint.MAX_ENDPOINT_QUEUE) |_| try std.testing.expectEqual(protocol.Status.empty, (try f.receiveReply(1, 900, now)).status);
        try std.testing.expect(f.clipboard.hasPendingWork());
        _ = f.clipboard.service(f, now);
        const final = try f.receiveReply(1, g, now);
        const expected: protocol.Status = if (case == .retained) .ok else if (case == .expired) .expired else .denied;
        try std.testing.expectEqual(expected, final.status);
        if (case == .retained) try std.testing.expectEqualStrings(text[protocol.CHUNK_BYTES..], final.bytes);
        try std.testing.expect(!f.clipboard.transferPendingForTask(f.tasks[1]));
        try std.testing.expectEqualSlices(u8, &@as([protocol.MAX_TEXT_BYTES]u8, @splat(0)), &channel.bytes);
    }
}

test "clipboard session preserves old content on incomplete uploads and erases it on expiry and retirement" {
    const f = try TestFixture.init();
    defer f.deinit();
    _ = try f.copy(0, "retained");
    const g = try f.gesture(0, 0x06);
    _ = try f.exchange(0, g, .{ .copy_begin = 10 }, 10);
    try std.testing.expectEqual(protocol.Status.invalid, (try f.exchange(0, g, .{ .copy_commit = {} }, 10)).status);
    try std.testing.expectEqualStrings("retained", f.clipboard.state().?.item.bytes[0..8]);
    try std.testing.expectEqual(@as(?u64, 10 + CONTENT_TICKS), f.clipboard.nextWake());
    _ = f.clipboard.service(f, 10 + CONTENT_TICKS);
    try std.testing.expect(f.clipboard.nextWake() == null);
    try std.testing.expectEqualSlices(u8, &@as([protocol.MAX_TEXT_BYTES]u8, @splat(0)), &f.clipboard.state().?.item.bytes);
    _ = try f.copy(0, "private");
    const client_id = f.clipboard.state().?.channels[0].client_endpoint;
    f.clipboard.closeTask(f.tasks[0], 10);
    try std.testing.expectEqual(@as(u64, 0), f.clipboard.state().?.item.source_task);
    try std.testing.expectError(error.EndpointNotFound, f.endpoints.descriptor(ids.endpoint(client_id)));
}

test "clipboard session validates complete UTF-8 across chunk boundaries before publishing" {
    const f = try TestFixture.init();
    defer f.deinit();
    const text = "a" ** 67 ++ "界e\u{301}👩‍💻";
    _ = try f.copy(0, text);
    try std.testing.expectEqualStrings(text, f.clipboard.state().?.item.bytes[0..text.len]);
    for ([_][]const u8{ "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82", "\xc2\x85" }) |bad| {
        const g = try f.gesture(0, 0x06);
        _ = try f.exchange(0, g, .{ .copy_begin = @intCast(bad.len) }, 10);
        _ = try f.exchange(0, g, .{ .copy_chunk = .{ .offset = 0, .bytes = bad } }, 10);
        try std.testing.expectEqual(protocol.Status.invalid, (try f.exchange(0, g, .{ .copy_commit = {} }, 10)).status);
        try std.testing.expectEqualStrings(text, f.clipboard.state().?.item.bytes[0..text.len]);
    }
}
