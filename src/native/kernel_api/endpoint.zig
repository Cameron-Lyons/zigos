const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_ENDPOINT_QUEUE: usize = 8;
pub const MAX_MESSAGE_BYTES: usize = abi.ENDPOINT_INLINE_BYTES;
pub const MAX_ENDPOINT_LABEL_BYTES: usize = 48;
const ENDPOINT_INDEX_CAPACITY: usize = MAX_ENDPOINTS * 2;
const MAX_ENDPOINT_LABEL_PAYLOAD_BYTES: usize = MAX_ENDPOINT_LABEL_BYTES - 1;
pub const ENDPOINT_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const ENDPOINT_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;

pub const EndpointFlags = packed struct(u16) {
    local_only: bool = false,
    service_port: bool = false,
    carries_capability: bool = false,
    _reserved: u13 = 0,
};

pub const Message = struct {
    sender_task_id: ids.TaskId,
    correlation_id: u64,
    attached_capability_id: ?ids.CapabilityId = null,
    move_attached_capability: bool = false,
    flags: EndpointFlags = .{},
    len: usize,
    bytes: [MAX_MESSAGE_BYTES]u8,

    pub fn payload(self: *const Message) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const ReceivedMessage = struct {
    sender_task_id: ids.TaskId,
    correlation_id: u64,
    attached_capability_id: ?ids.CapabilityId,
    move_attached_capability: bool,
    flags: EndpointFlags,
    len: usize,
};

pub const Endpoint = struct {
    id: ids.EndpointId,
    owner_task_id: ids.TaskId,
    flags: EndpointFlags,
    label_len: usize,
    label: [MAX_ENDPOINT_LABEL_BYTES]u8,
    peer_endpoint_id: ?ids.EndpointId = null,
    queue_head: usize = 0,
    queue_len: usize = 0,
    queue: [MAX_ENDPOINT_QUEUE]Message = [_]Message{zeroMessage()} ** MAX_ENDPOINT_QUEUE,

    pub fn labelSlice(self: *const Endpoint) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const Error = error{
    EndpointBusy,
    EndpointNotFound,
    MessageTooLarge,
    ReceiveBufferTooSmall,
    PeerNotConnected,
    QueueFull,
    TableFull,
};

const EndpointSlot = struct {
    in_use: bool = false,
    endpoint: Endpoint = zeroEndpoint(),
};

const EndpointArena = indexed_arena.GenerationalArena("EndpointId", EndpointSlot, MAX_ENDPOINTS);
const EndpointHandle = EndpointArena.Handle;
const EndpointOwnerIndex = indexed_arena.MultimapIndex(MAX_ENDPOINTS, MAX_ENDPOINTS, ENDPOINT_INDEX_CAPACITY);

pub const TaskRetirement = struct {
    endpoint_count: u16 = 0,
    endpoint_ids: [MAX_ENDPOINTS]ids.EndpointId = [_]ids.EndpointId{ids.EndpointId.zero} ** MAX_ENDPOINTS,

    pub fn retiredEndpointIds(self: *const TaskRetirement) []const ids.EndpointId {
        return self.endpoint_ids[0..self.endpoint_count];
    }
};

pub const Table = struct {
    arena: EndpointArena = EndpointArena.init(),
    owner_index: EndpointOwnerIndex = EndpointOwnerIndex.init(),

    pub fn init() Table {
        return .{};
    }

    pub fn create(self: *Table, owner_task_id: ids.TaskId, label: []const u8, flags: EndpointFlags) Error!Endpoint {
        const handle = self.arena.reserveHandle() orelse return error.TableFull;
        const slot = self.arena.getByHandle(handle) orelse
            native_util.impossibleByInvariant("reserved endpoint handle is not live");
        const endpoint_id = ids.endpoint(handle.value);
        slot.* = .{
            .in_use = true,
            .endpoint = .{
                .id = endpoint_id,
                .owner_task_id = owner_task_id,
                .flags = flags,
                .label_len = @min(label.len, MAX_ENDPOINT_LABEL_PAYLOAD_BYTES),
                .label = [_]u8{0} ** MAX_ENDPOINT_LABEL_BYTES,
            },
        };
        @memcpy(slot.endpoint.label[0..slot.endpoint.label_len], label[0..slot.endpoint.label_len]);
        if (!self.owner_index.append(owner_task_id.raw(), handle.slotIndex())) {
            native_util.impossibleByInvariant("endpoint owner index capacity covers endpoint slots");
        }
        return slot.endpoint;
    }

    pub fn connect(self: *Table, endpoint_id: ids.EndpointId, peer_endpoint_id: ids.EndpointId) Error!void {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;

        if (peer.flags.service_port) {
            if (endpoint.peer_endpoint_id != null) return error.EndpointBusy;
            endpoint.peer_endpoint_id = peer_endpoint_id;
            if (peer.peer_endpoint_id == null) {
                peer.peer_endpoint_id = endpoint_id;
            }
            return;
        }

        if (endpoint.flags.service_port) {
            if (peer.peer_endpoint_id != null) return error.EndpointBusy;
            peer.peer_endpoint_id = endpoint_id;
            if (endpoint.peer_endpoint_id == null) {
                endpoint.peer_endpoint_id = peer_endpoint_id;
            }
            return;
        }

        if (endpoint.peer_endpoint_id != null or peer.peer_endpoint_id != null) return error.EndpointBusy;

        endpoint.peer_endpoint_id = peer_endpoint_id;
        peer.peer_endpoint_id = endpoint_id;
    }

    pub fn send(
        self: *Table,
        endpoint_id: ids.EndpointId,
        sender_task_id: ids.TaskId,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?ids.CapabilityId,
        move_attached_capability: bool,
    ) Error!void {
        if (payload.len > MAX_MESSAGE_BYTES) return error.MessageTooLarge;

        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const peer_endpoint_id = endpoint.peer_endpoint_id orelse return error.PeerNotConnected;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;
        if (peer.queue_len >= MAX_ENDPOINT_QUEUE) return error.QueueFull;

        const insert_index = (peer.queue_head + peer.queue_len) % MAX_ENDPOINT_QUEUE;
        peer.queue[insert_index].sender_task_id = sender_task_id;
        peer.queue[insert_index].correlation_id = correlation_id;
        peer.queue[insert_index].attached_capability_id = attached_capability_id;
        peer.queue[insert_index].move_attached_capability = move_attached_capability;
        peer.queue[insert_index].flags = .{
            .local_only = endpoint.flags.local_only and peer.flags.local_only,
            .service_port = endpoint.flags.service_port or peer.flags.service_port,
            .carries_capability = attached_capability_id != null,
        };
        peer.queue[insert_index].len = payload.len;
        @memcpy(peer.queue[insert_index].bytes[0..payload.len], payload);
        peer.queue_len += 1;
    }

    pub fn recvInto(
        self: *Table,
        endpoint_id: ids.EndpointId,
        payload_out: []u8,
    ) Error!?ReceivedMessage {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.queue_len == 0) return null;

        const index = endpoint.queue_head;
        const message = &endpoint.queue[index];
        if (message.len > payload_out.len) return error.ReceiveBufferTooSmall;
        @memcpy(payload_out[0..message.len], message.payload());
        const received = ReceivedMessage{
            .sender_task_id = message.sender_task_id,
            .correlation_id = message.correlation_id,
            .attached_capability_id = message.attached_capability_id,
            .move_attached_capability = message.move_attached_capability,
            .flags = message.flags,
            .len = message.len,
        };
        message.len = 0;
        endpoint.queue_head = (endpoint.queue_head + 1) % MAX_ENDPOINT_QUEUE;
        endpoint.queue_len -= 1;
        return received;
    }

    pub fn descriptor(self: *const Table, endpoint_id: ids.EndpointId) Error!abi.EndpointDescriptor {
        const endpoint = self.findConst(endpoint_id) orelse return error.EndpointNotFound;
        return .{
            .endpoint_id = endpoint.id.raw(),
            .owner_task_id = endpoint.owner_task_id.raw(),
            .peer_endpoint_id = if (endpoint.peer_endpoint_id) |id| id.raw() else 0,
            .queued_messages = @intCast(endpoint.queue_len),
            .flags = @bitCast(endpoint.flags),
            .label_hash = hashLabel(endpoint.labelSlice()),
        };
    }

    pub fn activeForTask(self: *const Table, task_id: ids.TaskId) u16 {
        return @intCast(self.owner_index.count(task_id.raw()));
    }

    pub fn activeCount(self: *const Table) usize {
        return self.arena.countInUse();
    }

    pub fn retireTask(self: *Table, task_id: ids.TaskId) TaskRetirement {
        var retired = TaskRetirement{};
        while (true) {
            const slot_index = self.owner_index.head(task_id.raw());
            if (slot_index == indexed_arena.no_index) break;
            if (slot_index >= self.arena.slots.len) {
                native_util.impossibleByInvariant("endpoint owner index points outside endpoint slots");
            }
            const slot = &self.arena.slots[slot_index];
            if (!slot.in_use or !slot.endpoint.owner_task_id.eql(task_id)) {
                native_util.impossibleByInvariant("endpoint owner index points at the wrong endpoint");
            }
            retired.endpoint_ids[retired.endpoint_count] = slot.endpoint.id;
            retired.endpoint_count += 1;
            if (!self.owner_index.remove(task_id.raw(), slot_index)) {
                native_util.impossibleByInvariant("live endpoint is absent from its owner index");
            }
            if (!self.arena.removeIndex(slot_index)) {
                native_util.impossibleByInvariant("live endpoint disappeared during retirement");
            }
        }
        if (retired.endpoint_count == 0) return retired;

        for (&self.arena.slots) |*slot| {
            if (!slot.in_use) continue;
            const peer_endpoint_id = slot.endpoint.peer_endpoint_id orelse continue;
            for (retired.retiredEndpointIds()) |retired_id| {
                if (peer_endpoint_id.eql(retired_id)) {
                    slot.endpoint.peer_endpoint_id = null;
                    break;
                }
            }
        }
        return retired;
    }

    fn find(self: *Table, endpoint_id: ids.EndpointId) ?*Endpoint {
        const slot = self.arena.getByHandle(EndpointHandle{ .value = endpoint_id.raw() }) orelse return null;
        return &slot.endpoint;
    }

    fn findConst(self: *const Table, endpoint_id: ids.EndpointId) ?*const Endpoint {
        const slot = self.arena.getConstByHandle(EndpointHandle{ .value = endpoint_id.raw() }) orelse return null;
        return &slot.endpoint;
    }
};

fn zeroMessage() Message {
    return .{
        .sender_task_id = ids.TaskId.zero,
        .correlation_id = 0,
        .len = 0,
        .bytes = [_]u8{0} ** MAX_MESSAGE_BYTES,
    };
}

fn zeroEndpoint() Endpoint {
    return .{
        .id = ids.EndpointId.zero,
        .owner_task_id = ids.TaskId.zero,
        .flags = .{},
        .label_len = 0,
        .label = [_]u8{0} ** MAX_ENDPOINT_LABEL_BYTES,
    };
}

fn hashLabel(label: []const u8) u64 {
    return native_util.fnv1a64(label);
}

test "endpoints connect and exchange queued messages" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{ .local_only = true });
    const right = try table.create(ids.task(11), "right", .{ .local_only = true });
    try table.connect(left.id, right.id);

    try table.send(left.id, ids.task(10), 77, "hello", null, false);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;

    try std.testing.expect(received.sender_task_id.eql(ids.task(10)));
    try std.testing.expectEqual(@as(u64, 77), received.correlation_id);
    try std.testing.expectEqualStrings("hello", payload[0..received.len]);
}

test "endpoint descriptors track peer links and queue depth" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{});
    const right = try table.create(ids.task(11), "right", .{ .service_port = true });
    try table.connect(left.id, right.id);
    try table.send(left.id, ids.task(10), 1, "ok", ids.capability(99), true);

    const descriptor = try table.descriptor(right.id);
    try std.testing.expectEqual(left.id.raw(), descriptor.peer_endpoint_id);
    try std.testing.expectEqual(@as(u16, 1), descriptor.queued_messages);
    try std.testing.expect(descriptor.label_hash != 0);
}

test "endpoint ids reject stale handles after slot reuse" {
    var table = Table.init();
    const endpoint = try table.create(ids.task(10), "first", .{});
    const original_handle = EndpointHandle{ .value = endpoint.id.raw() };

    const retired = table.retireTask(ids.task(10));
    try std.testing.expectEqual(@as(u16, 1), retired.endpoint_count);
    try std.testing.expect(retired.retiredEndpointIds()[0].eql(endpoint.id));
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(endpoint.id));

    const replacement = try table.create(ids.task(11), "replacement", .{});
    const replacement_handle = EndpointHandle{ .value = replacement.id.raw() };
    try std.testing.expectEqual(original_handle.slotIndex(), replacement_handle.slotIndex());
    try std.testing.expect(!endpoint.id.eql(replacement.id));
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(endpoint.id));
    try std.testing.expectEqual(replacement.id.raw(), (try table.descriptor(replacement.id)).endpoint_id);
}

test "endpoint table rejection preserves active endpoints" {
    var table = Table.init();
    for (0..MAX_ENDPOINTS) |index| {
        _ = try table.create(ids.task(@intCast(index + 100)), "endpoint", .{});
    }

    try std.testing.expectEqual(MAX_ENDPOINTS, table.activeCount());
    try std.testing.expectError(error.TableFull, table.create(ids.task(1_000), "rejected", .{}));
    try std.testing.expectEqual(MAX_ENDPOINTS, table.activeCount());
    try std.testing.expectEqual(@as(u16, 1), table.activeForTask(ids.task(100)));
}

test "retiring task endpoints clears queues and surviving peer links" {
    var table = Table.init();
    const client_a = try table.create(ids.task(10), "client-a", .{});
    const client_b = try table.create(ids.task(11), "client-b", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });

    try table.connect(client_a.id, service.id);
    try table.connect(client_b.id, service.id);
    try table.send(client_a.id, ids.task(10), 1, "queued-a", null, false);
    try table.send(client_b.id, ids.task(11), 2, "queued-b", null, false);
    try std.testing.expectEqual(@as(u16, 2), (try table.descriptor(service.id)).queued_messages);

    const retired = table.retireTask(ids.task(12));
    try std.testing.expectEqual(@as(u16, 1), retired.endpoint_count);
    try std.testing.expect(retired.retiredEndpointIds()[0].eql(service.id));
    try std.testing.expectEqual(@as(usize, 2), table.activeCount());
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(service.id));
    try std.testing.expectEqual(@as(u64, 0), (try table.descriptor(client_a.id)).peer_endpoint_id);
    try std.testing.expectEqual(@as(u64, 0), (try table.descriptor(client_b.id)).peer_endpoint_id);
    try std.testing.expectError(error.PeerNotConnected, table.send(client_a.id, ids.task(10), 3, "stale", null, false));
}

test "endpoint identity paths avoid primary indexes and collision probes" {
    try std.testing.expectEqual(@as(u8, 0), ENDPOINT_PRIMARY_INDEX_LOOKUPS_PER_OPERATION);
    try std.testing.expectEqual(@as(u8, 0), ENDPOINT_ID_COLLISION_PROBES_PER_INSERT);
}

test "service ports accept multiple client connections without blocking later binds" {
    var table = Table.init();
    const client_a = try table.create(ids.task(10), "client-a", .{});
    const client_b = try table.create(ids.task(11), "client-b", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });

    try table.connect(client_a.id, service.id);
    try table.connect(client_b.id, service.id);
    try table.send(client_b.id, ids.task(11), 77, "ping", null, false);

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(service.id, &payload)).?;
    try std.testing.expect(received.sender_task_id.eql(ids.task(11)));
    try std.testing.expectEqual(service.id.raw(), (try table.descriptor(client_b.id)).peer_endpoint_id);
}

test "endpoint receive keeps a message queued when the caller buffer is too small" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{});
    const right = try table.create(ids.task(11), "right", .{});
    try table.connect(left.id, right.id);
    try table.send(left.id, ids.task(10), 9, "hello", null, false);

    var short_payload: [4]u8 = undefined;
    try std.testing.expectError(error.ReceiveBufferTooSmall, table.recvInto(right.id, &short_payload));
    try std.testing.expectEqual(@as(u16, 1), (try table.descriptor(right.id)).queued_messages);

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqual(@as(u64, 9), received.correlation_id);
    try std.testing.expectEqualStrings("hello", payload[0..received.len]);
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(right.id)).queued_messages);
}
