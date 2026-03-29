const std = @import("std");
const abi = @import("abi.zig");
const native_util = @import("util.zig");

pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_ENDPOINT_QUEUE: usize = 8;
pub const MAX_MESSAGE_BYTES: usize = abi.ENDPOINT_INLINE_BYTES;

pub const EndpointFlags = packed struct(u16) {
    local_only: bool = false,
    service_port: bool = false,
    carries_capability: bool = false,
    _reserved: u13 = 0,
};

pub const Message = struct {
    sender_task_id: u64,
    correlation_id: u64,
    attached_capability_id: ?u64 = null,
    move_attached_capability: bool = false,
    flags: EndpointFlags = .{},
    len: usize,
    bytes: [MAX_MESSAGE_BYTES]u8,

    pub fn payload(self: *const Message) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Endpoint = struct {
    id: u64,
    owner_task_id: u64,
    flags: EndpointFlags,
    label_len: usize,
    label: [48]u8,
    peer_endpoint_id: ?u64 = null,
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
    PeerNotConnected,
    QueueFull,
    TableFull,
};

const EndpointSlot = struct {
    in_use: bool = false,
    endpoint: Endpoint = zeroEndpoint(),
};

pub const Table = struct {
    next_endpoint_id: u64 = 1,
    slots: [MAX_ENDPOINTS]EndpointSlot = [_]EndpointSlot{EndpointSlot{}} ** MAX_ENDPOINTS,

    pub fn init() Table {
        return .{};
    }

    pub fn create(self: *Table, owner_task_id: u64, label: []const u8, flags: EndpointFlags) Error!Endpoint {
        for (&self.slots) |*slot| {
            if (slot.in_use) continue;

            slot.in_use = true;
            slot.endpoint = .{
                .id = self.allocateEndpointId(),
                .owner_task_id = owner_task_id,
                .flags = flags,
                .label_len = @min(label.len, 47),
                .label = [_]u8{0} ** 48,
            };
            @memcpy(slot.endpoint.label[0..slot.endpoint.label_len], label[0..slot.endpoint.label_len]);
            return slot.endpoint;
        }
        return error.TableFull;
    }

    pub fn connect(self: *Table, endpoint_id: u64, peer_endpoint_id: u64) Error!void {
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
        endpoint_id: u64,
        sender_task_id: u64,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?u64,
        move_attached_capability: bool,
    ) Error!void {
        if (payload.len > MAX_MESSAGE_BYTES) return error.MessageTooLarge;

        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const peer_endpoint_id = endpoint.peer_endpoint_id orelse return error.PeerNotConnected;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;
        if (peer.queue_len >= MAX_ENDPOINT_QUEUE) return error.QueueFull;

        const insert_index = (peer.queue_head + peer.queue_len) % MAX_ENDPOINT_QUEUE;
        peer.queue[insert_index] = zeroMessage();
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

    pub fn recv(self: *Table, endpoint_id: u64) Error!?Message {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.queue_len == 0) return null;

        const index = endpoint.queue_head;
        const message = endpoint.queue[index];
        endpoint.queue[index] = zeroMessage();
        endpoint.queue_head = (endpoint.queue_head + 1) % MAX_ENDPOINT_QUEUE;
        endpoint.queue_len -= 1;
        return message;
    }

    pub fn descriptor(self: *const Table, endpoint_id: u64) Error!abi.EndpointDescriptor {
        const endpoint = self.findConst(endpoint_id) orelse return error.EndpointNotFound;
        return .{
            .endpoint_id = endpoint.id,
            .owner_task_id = endpoint.owner_task_id,
            .peer_endpoint_id = endpoint.peer_endpoint_id orelse 0,
            .queued_messages = @intCast(endpoint.queue_len),
            .flags = @bitCast(endpoint.flags),
            .label_hash = hashLabel(endpoint.labelSlice()),
        };
    }

    pub fn activeForTask(self: *const Table, task_id: u64) u16 {
        var count: u16 = 0;
        for (self.slots) |slot| {
            if (slot.in_use and slot.endpoint.owner_task_id == task_id) {
                count += 1;
            }
        }
        return count;
    }

    fn allocateEndpointId(self: *Table) u64 {
        defer self.next_endpoint_id += 1;
        return self.next_endpoint_id;
    }

    fn find(self: *Table, endpoint_id: u64) ?*Endpoint {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.endpoint.id == endpoint_id) return &slot.endpoint;
        }
        return null;
    }

    fn findConst(self: *const Table, endpoint_id: u64) ?*const Endpoint {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.endpoint.id == endpoint_id) return &slot.endpoint;
        }
        return null;
    }
};

fn zeroMessage() Message {
    return .{
        .sender_task_id = 0,
        .correlation_id = 0,
        .len = 0,
        .bytes = [_]u8{0} ** MAX_MESSAGE_BYTES,
    };
}

fn zeroEndpoint() Endpoint {
    return .{
        .id = 0,
        .owner_task_id = 0,
        .flags = .{},
        .label_len = 0,
        .label = [_]u8{0} ** 48,
    };
}

fn hashLabel(label: []const u8) u64 {
    return native_util.fnv1a64(label);
}

test "endpoints connect and exchange queued messages" {
    var table = Table.init();
    const left = try table.create(10, "left", .{ .local_only = true });
    const right = try table.create(11, "right", .{ .local_only = true });
    try table.connect(left.id, right.id);

    try table.send(left.id, 10, 77, "hello", null, false);
    const received = (try table.recv(right.id)).?;

    try std.testing.expectEqual(@as(u64, 10), received.sender_task_id);
    try std.testing.expectEqual(@as(u64, 77), received.correlation_id);
    try std.testing.expectEqualStrings("hello", received.payload());
}

test "endpoint descriptors track peer links and queue depth" {
    var table = Table.init();
    const left = try table.create(10, "left", .{});
    const right = try table.create(11, "right", .{ .service_port = true });
    try table.connect(left.id, right.id);
    try table.send(left.id, 10, 1, "ok", 99, true);

    const descriptor = try table.descriptor(right.id);
    try std.testing.expectEqual(left.id, descriptor.peer_endpoint_id);
    try std.testing.expectEqual(@as(u16, 1), descriptor.queued_messages);
    try std.testing.expect(descriptor.label_hash != 0);
}

test "service ports accept multiple client connections without blocking later binds" {
    var table = Table.init();
    const client_a = try table.create(10, "client-a", .{});
    const client_b = try table.create(11, "client-b", .{});
    const service = try table.create(12, "service", .{ .service_port = true });

    try table.connect(client_a.id, service.id);
    try table.connect(client_b.id, service.id);
    try table.send(client_b.id, 11, 77, "ping", null, false);

    const received = (try table.recv(service.id)).?;
    try std.testing.expectEqual(@as(u64, 11), received.sender_task_id);
    try std.testing.expectEqual(@as(u64, service.id), (try table.descriptor(client_b.id)).peer_endpoint_id);
}
