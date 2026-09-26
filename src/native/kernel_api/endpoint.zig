const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const root = @import("root");

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_ENDPOINT_QUEUE: usize = 8;
pub const MAX_MESSAGE_BYTES: usize = abi.ENDPOINT_INLINE_BYTES;
pub const MAX_ENDPOINT_LABEL_BYTES: usize = 48;
const ENDPOINT_INDEX_CAPACITY: usize = MAX_ENDPOINTS * 2;
const MAX_ENDPOINT_LABEL_PAYLOAD_BYTES: usize = MAX_ENDPOINT_LABEL_BYTES - 1;
pub const ENDPOINT_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const ENDPOINT_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;
pub const FREESTANDING_TABLE_SIZE_CEILING_BYTES: usize = 8_976;

comptime {
    const byte_capacities = [_]usize{
        MAX_ENDPOINT_QUEUE,
        MAX_MESSAGE_BYTES,
        MAX_ENDPOINT_LABEL_BYTES,
    };
    for (byte_capacities) |capacity| {
        if (capacity > std.math.maxInt(u8)) {
            @compileError("endpoint capacity exceeds its compact field");
        }
    }
}

pub const EndpointFlags = packed struct(u16) {
    local_only: bool = false,
    service_port: bool = false,
    carries_capability: bool = false,
    _reserved: u13 = 0,
};

pub const Message = struct {
    sender_endpoint_id: ids.EndpointId,
    sender_task_id: ids.TaskId,
    correlation_id: u64,
    attached_capability_id: ids.CapabilityId = ids.CapabilityId.zero,
    move_attached_capability: bool = false,
    flags: EndpointFlags = .{},
    len: u8,
    bytes: [MAX_MESSAGE_BYTES]u8,

    pub fn payload(self: *const Message) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn attachedCapabilityId(self: *const Message) ?ids.CapabilityId {
        if (self.attached_capability_id.isZero()) return null;
        return self.attached_capability_id;
    }
};

pub const ReceivedMessage = struct {
    sender_endpoint_id: ids.EndpointId,
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
    label_len: u8,
    label: [MAX_ENDPOINT_LABEL_BYTES]u8,
    peer_endpoint_id: ids.EndpointId = ids.EndpointId.zero,
    queue_head: u8 = 0,
    queue_len: u8 = 0,
    queue: EndpointQueueBacking = if (heap_backed_endpoint_queues) null else [_]Message{zeroMessage()} ** MAX_ENDPOINT_QUEUE,

    comptime {
        if (heap_backed_endpoint_queues and @sizeOf(@This()) > 128) {
            @compileError("heap-backed endpoints exceed their compact resident layout");
        }
    }

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
    NoSpaceLeft,
    ScopeViolation,
};

const EndpointQueue = [MAX_ENDPOINT_QUEUE]Message;
const heap_backed_endpoint_queues = builtin.target.os.tag == .freestanding;
const EndpointQueueBacking = if (heap_backed_endpoint_queues) ?*EndpointQueue else EndpointQueue;

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

    comptime {
        if (builtin.target.os.tag == .freestanding and @sizeOf(@This()) > FREESTANDING_TABLE_SIZE_CEILING_BYTES) {
            @compileError("freestanding endpoint table exceeds its compact layout ceiling");
        }
    }

    pub fn init() Table {
        return .{};
    }

    pub fn initializeAllocated(self: *Table) void {
        @memset(std.mem.asBytes(self), 0);
        const no_endpoint_index = indexed_arena.reusableNoIndex(MAX_ENDPOINTS);
        @memset(self.arena.free_next[0..], no_endpoint_index);
        self.arena.free_head = no_endpoint_index;

        const OwnerIndex = @FieldType(Table, "owner_index");
        const CompactIndex = @FieldType(OwnerIndex, "free_bucket_head");
        const no_owner_bucket: CompactIndex = @intCast(@max(self.owner_index.links.len, self.owner_index.buckets.len));
        for (&self.owner_index.links) |*link| link.bucket = no_owner_bucket;
        self.owner_index.free_bucket_head = no_owner_bucket;
    }

    pub fn reset(self: *Table) void {
        self.deinit();
        self.* = Table.init();
    }

    pub fn deinit(self: *Table) void {
        if (comptime heap_backed_endpoint_queues) {
            for (&self.arena.slots) |*slot| {
                if (slot.in_use) releaseEndpointQueue(&slot.endpoint);
            }
        }
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
                .label_len = @intCast(@min(label.len, MAX_ENDPOINT_LABEL_PAYLOAD_BYTES)),
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

        if (endpoint.flags.service_port and peer.flags.service_port) return error.ScopeViolation;

        if (peer.flags.service_port) {
            if (!endpoint.peer_endpoint_id.isZero()) return error.EndpointBusy;
            endpoint.peer_endpoint_id = peer_endpoint_id;
            return;
        }

        if (endpoint.flags.service_port) {
            if (!peer.peer_endpoint_id.isZero()) return error.EndpointBusy;
            peer.peer_endpoint_id = endpoint_id;
            return;
        }

        if (!endpoint.peer_endpoint_id.isZero() or !peer.peer_endpoint_id.isZero()) return error.EndpointBusy;

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
    ) Error!ids.TaskId {
        if (payload.len > MAX_MESSAGE_BYTES) return error.MessageTooLarge;

        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const peer_endpoint_id = endpoint.peer_endpoint_id;
        if (peer_endpoint_id.isZero()) return error.PeerNotConnected;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;
        return enqueue(endpoint, peer, sender_task_id, correlation_id, payload, attached_capability_id, move_attached_capability);
    }

    // Services have no implicit peer. The kernel supplies the sender endpoint
    // with each received request, and replies must name that connected client.
    // Generational endpoint ids prevent delayed replies reaching reused slots.
    pub fn reply(
        self: *Table,
        endpoint_id: ids.EndpointId,
        reply_endpoint_id: ids.EndpointId,
        sender_task_id: ids.TaskId,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?ids.CapabilityId,
        move_attached_capability: bool,
    ) Error!ids.TaskId {
        if (payload.len > MAX_MESSAGE_BYTES) return error.MessageTooLarge;
        const service = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const client = self.find(reply_endpoint_id) orelse return error.EndpointNotFound;
        if (!service.flags.service_port or client.flags.service_port or
            !client.peer_endpoint_id.eql(service.id)) return error.ScopeViolation;
        return enqueue(service, client, sender_task_id, correlation_id, payload, attached_capability_id, move_attached_capability);
    }

    fn enqueue(
        source: *const Endpoint,
        peer: *Endpoint,
        sender_task_id: ids.TaskId,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?ids.CapabilityId,
        move_attached_capability: bool,
    ) Error!ids.TaskId {
        if (peer.queue_len >= MAX_ENDPOINT_QUEUE) return error.QueueFull;

        const queue = try ensureEndpointQueue(peer);
        const insert_index = (peer.queue_head + peer.queue_len) % MAX_ENDPOINT_QUEUE;
        queue[insert_index].sender_endpoint_id = source.id;
        queue[insert_index].sender_task_id = sender_task_id;
        queue[insert_index].correlation_id = correlation_id;
        queue[insert_index].attached_capability_id = attached_capability_id orelse ids.CapabilityId.zero;
        queue[insert_index].move_attached_capability = move_attached_capability;
        queue[insert_index].flags = .{
            .local_only = source.flags.local_only and peer.flags.local_only,
            .service_port = source.flags.service_port or peer.flags.service_port,
            .carries_capability = attached_capability_id != null,
        };
        queue[insert_index].len = @intCast(payload.len);
        @memcpy(queue[insert_index].bytes[0..payload.len], payload);
        peer.queue_len += 1;
        return peer.owner_task_id;
    }

    pub fn recvInto(
        self: *Table,
        endpoint_id: ids.EndpointId,
        payload_out: []u8,
    ) Error!?ReceivedMessage {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.queue_len == 0) return null;

        const queue = endpointQueue(endpoint) orelse
            native_util.impossibleByInvariant("non-empty endpoint queue retains its backing");
        const index = endpoint.queue_head;
        const message = &queue[index];
        if (message.len > payload_out.len) return error.ReceiveBufferTooSmall;
        @memcpy(payload_out[0..message.len], message.payload());
        const received = ReceivedMessage{
            .sender_endpoint_id = message.sender_endpoint_id,
            .sender_task_id = message.sender_task_id,
            .correlation_id = message.correlation_id,
            .attached_capability_id = message.attachedCapabilityId(),
            .move_attached_capability = message.move_attached_capability,
            .flags = message.flags,
            .len = message.len,
        };
        message.len = 0;
        endpoint.queue_head = @intCast((endpoint.queue_head + 1) % MAX_ENDPOINT_QUEUE);
        endpoint.queue_len -= 1;
        return received;
    }

    pub fn descriptor(self: *const Table, endpoint_id: ids.EndpointId) Error!abi.EndpointDescriptor {
        const endpoint = self.findConst(endpoint_id) orelse return error.EndpointNotFound;
        return .{
            .endpoint_id = endpoint.id.raw(),
            .owner_task_id = endpoint.owner_task_id.raw(),
            .peer_endpoint_id = endpoint.peer_endpoint_id.raw(),
            .queued_messages = @intCast(endpoint.queue_len),
            .flags = @bitCast(endpoint.flags),
            .label_hash = hashLabel(endpoint.labelSlice()),
        };
    }

    pub fn activeForTask(self: *const Table, task_id: ids.TaskId) u16 {
        return @intCast(self.owner_index.count(task_id.raw()));
    }

    // Only visit this owner's endpoints when deciding whether it can sleep.
    pub fn hasPendingForTask(self: *const Table, task_id: ids.TaskId) bool {
        var slot_index = self.owner_index.head(task_id.raw());
        while (slot_index != indexed_arena.no_index) : (slot_index = self.owner_index.next(slot_index)) {
            if (self.arena.slots[slot_index].endpoint.queue_len != 0) return true;
        }
        return false;
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
            releaseEndpointQueue(&slot.endpoint);
            if (!self.arena.removeIndex(slot_index)) {
                native_util.impossibleByInvariant("live endpoint disappeared during retirement");
            }
        }
        if (retired.endpoint_count == 0) return retired;

        for (&self.arena.slots) |*slot| {
            if (!slot.in_use) continue;
            const peer_endpoint_id = slot.endpoint.peer_endpoint_id;
            if (peer_endpoint_id.isZero()) continue;
            for (retired.retiredEndpointIds()) |retired_id| {
                if (peer_endpoint_id.eql(retired_id)) {
                    slot.endpoint.peer_endpoint_id = ids.EndpointId.zero;
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

fn endpointQueue(endpoint: *Endpoint) ?*EndpointQueue {
    if (comptime heap_backed_endpoint_queues) return endpoint.queue;
    return &endpoint.queue;
}

fn ensureEndpointQueue(endpoint: *Endpoint) error{NoSpaceLeft}!*EndpointQueue {
    if (endpointQueue(endpoint)) |queue| return queue;
    if (comptime heap_backed_endpoint_queues) {
        const allocation = kernel_memory.kmalloc(@sizeOf(EndpointQueue)) orelse return error.NoSpaceLeft;
        const queue: *EndpointQueue = @ptrCast(@alignCast(allocation));
        initializeEndpointQueue(queue);
        endpoint.queue = queue;
        return queue;
    }
    return &endpoint.queue;
}

fn releaseEndpointQueue(endpoint: *Endpoint) void {
    if (comptime heap_backed_endpoint_queues) {
        if (endpoint.queue) |queue| {
            @memset(std.mem.asBytes(queue), 0);
            kernel_memory.kfree(@ptrCast(queue));
            endpoint.queue = null;
        }
    }
    endpoint.queue_head = 0;
    endpoint.queue_len = 0;
}

fn initializeEndpointQueue(queue: *EndpointQueue) void {
    @memset(std.mem.asBytes(queue), 0);
}

fn zeroMessage() Message {
    return .{
        .sender_endpoint_id = ids.EndpointId.zero,
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

test "endpoint queues use capacity-sized resident metadata" {
    try std.testing.expectEqual(@as(usize, 136), @sizeOf(Message));
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(@FieldType(Message, "len")));
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(@FieldType(Endpoint, "queue_len")));
    try std.testing.expectEqual(@as(usize, 1_168), @sizeOf(Endpoint));
    try std.testing.expectEqual(@as(usize, 1_176), @sizeOf(EndpointSlot));
    try std.testing.expectEqual(@as(usize, 78_096), @sizeOf(Table));
}

test "allocated endpoint table initializes reusable metadata" {
    const table = try std.testing.allocator.create(Table);
    defer std.testing.allocator.destroy(table);
    table.initializeAllocated();

    const created = try table.create(ids.task(1), "allocated", .{});
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
    try std.testing.expectEqual(created.id.raw(), (try table.descriptor(created.id)).endpoint_id);
}

test "endpoints connect and exchange queued messages" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{ .local_only = true });
    const right = try table.create(ids.task(11), "right", .{ .local_only = true });
    try table.connect(left.id, right.id);

    _ = try table.send(left.id, ids.task(10), 77, "hello", null, false);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;

    try std.testing.expect(received.sender_task_id.eql(ids.task(10)));
    try std.testing.expectEqual(@as(u64, 77), received.correlation_id);
    try std.testing.expectEqual(@as(?ids.CapabilityId, null), received.attached_capability_id);
    try std.testing.expectEqualStrings("hello", payload[0..received.len]);
}

test "queued endpoint messages own their payload" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{});
    const right = try table.create(ids.task(11), "right", .{});
    try table.connect(left.id, right.id);

    var source = [_]u8{ 'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l' };
    _ = try table.send(left.id, ids.task(10), 78, &source, null, false);
    @memset(&source, 'x');

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqualStrings("original", payload[0..received.len]);
}

test "endpoint table reset clears live queues and reuses capacity" {
    var table = Table.init();
    const left = try table.create(ids.task(20), "left", .{});
    const right = try table.create(ids.task(21), "right", .{});
    try table.connect(left.id, right.id);
    _ = try table.send(left.id, ids.task(20), 88, "queued", null, false);
    try std.testing.expectEqual(@as(u16, 1), (try table.descriptor(right.id)).queued_messages);

    table.reset();
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    const replacement = try table.create(ids.task(22), "replacement", .{});
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(replacement.id)).queued_messages);
}

test "endpoint descriptors track peer links and queue depth" {
    var table = Table.init();
    const left = try table.create(ids.task(10), "left", .{});
    const right = try table.create(ids.task(11), "right", .{ .service_port = true });
    try table.connect(left.id, right.id);
    _ = try table.send(left.id, ids.task(10), 1, "ok", ids.capability(99), true);

    const descriptor = try table.descriptor(right.id);
    try std.testing.expectEqual(@as(u64, 0), descriptor.peer_endpoint_id);
    try std.testing.expectEqual(@as(u16, 1), descriptor.queued_messages);
    try std.testing.expect(descriptor.label_hash != 0);

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expect(received.attached_capability_id.?.eql(ids.capability(99)));
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
    _ = try table.send(client_a.id, ids.task(10), 1, "queued-a", null, false);
    _ = try table.send(client_b.id, ids.task(11), 2, "queued-b", null, false);
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
    _ = try table.send(client_b.id, ids.task(11), 77, "ping", null, false);

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
    _ = try table.send(left.id, ids.task(10), 9, "hello", null, false);

    var short_payload: [4]u8 = undefined;
    try std.testing.expectError(error.ReceiveBufferTooSmall, table.recvInto(right.id, &short_payload));
    try std.testing.expectEqual(@as(u16, 1), (try table.descriptor(right.id)).queued_messages);

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqual(@as(u64, 9), received.correlation_id);
    try std.testing.expectEqualStrings("hello", payload[0..received.len]);
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(right.id)).queued_messages);
}

test "service replies route by request endpoint across clients and out of order" {
    var table = Table.init();
    const first = try table.create(ids.task(10), "first", .{});
    const second = try table.create(ids.task(11), "second", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });
    try table.connect(first.id, service.id);
    try table.connect(service.id, second.id);
    _ = try table.send(first.id, first.owner_task_id, 7, "first request", null, false);
    _ = try table.send(second.id, second.owner_task_id, 7, "second request", null, false);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const a = (try table.recvInto(service.id, &payload)).?;
    const b = (try table.recvInto(service.id, &payload)).?;
    try std.testing.expectEqual(first.id, a.sender_endpoint_id);
    try std.testing.expectEqual(second.id, b.sender_endpoint_id);
    try std.testing.expectError(error.PeerNotConnected, table.send(service.id, service.owner_task_id, 7, "ambiguous", null, false));
    _ = try table.reply(service.id, b.sender_endpoint_id, service.owner_task_id, b.correlation_id, "second reply", null, false);
    try std.testing.expect((try table.recvInto(first.id, &payload)) == null);
    _ = try table.reply(service.id, a.sender_endpoint_id, service.owner_task_id, a.correlation_id, "first reply", null, false);
    const received_b = (try table.recvInto(second.id, &payload)).?;
    try std.testing.expectEqualStrings("second reply", payload[0..received_b.len]);
    try std.testing.expectEqual(service.id, received_b.sender_endpoint_id);
    const received_a = (try table.recvInto(first.id, &payload)).?;
    try std.testing.expectEqualStrings("first reply", payload[0..received_a.len]);
}

test "reply routing rejects unrelated endpoints without publishing a message" {
    var table = Table.init();
    const client = try table.create(ids.task(10), "client", .{});
    const stranger = try table.create(ids.task(11), "stranger", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });
    const other = try table.create(ids.task(13), "other service", .{ .service_port = true });
    try table.connect(client.id, service.id);
    try table.connect(stranger.id, other.id);
    try std.testing.expectError(error.ScopeViolation, table.connect(service.id, other.id));
    try std.testing.expectError(error.ScopeViolation, table.reply(service.id, stranger.id, service.owner_task_id, 1, "secret", null, false));
    try std.testing.expectError(error.ScopeViolation, table.reply(client.id, stranger.id, client.owner_task_id, 1, "secret", null, false));
    try std.testing.expectError(error.ScopeViolation, table.reply(service.id, other.id, service.owner_task_id, 1, "secret", null, false));
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(stranger.id)).queued_messages);
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(other.id)).queued_messages);
}

test "delayed service replies reject retired client handles after slot reuse" {
    var table = Table.init();
    const client = try table.create(ids.task(10), "client", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });
    try table.connect(client.id, service.id);
    _ = try table.send(client.id, client.owner_task_id, 1, "request", null, false);
    _ = table.retireTask(client.owner_task_id);
    const replacement = try table.create(client.owner_task_id, "replacement", .{});
    try table.connect(replacement.id, service.id);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const request = (try table.recvInto(service.id, &payload)).?;
    try std.testing.expectEqual(client.id, request.sender_endpoint_id);
    try std.testing.expectError(error.EndpointNotFound, table.reply(service.id, request.sender_endpoint_id, service.owner_task_id, 1, "late", null, false));
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(replacement.id)).queued_messages);
}

test "a full reply queue never redirects a service response to another client" {
    var table = Table.init();
    const first = try table.create(ids.task(10), "first", .{});
    const second = try table.create(ids.task(11), "second", .{});
    const service = try table.create(ids.task(12), "service", .{ .service_port = true });
    try table.connect(first.id, service.id);
    try table.connect(second.id, service.id);
    for (0..MAX_ENDPOINT_QUEUE) |sequence| {
        _ = try table.reply(service.id, second.id, service.owner_task_id, sequence, "reply", null, false);
    }
    try std.testing.expectError(error.QueueFull, table.reply(service.id, second.id, service.owner_task_id, 99, "overflow", null, false));
    try std.testing.expectEqual(@as(u16, MAX_ENDPOINT_QUEUE), (try table.descriptor(second.id)).queued_messages);
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(first.id)).queued_messages);
}

test "endpoint readiness follows queued ownership through drains and retirement" {
    var table = Table.init();
    const client = try table.create(ids.task(10), "client", .{});
    const service = try table.create(ids.task(20), "service", .{ .service_port = true });
    _ = try table.create(service.owner_task_id, "empty service endpoint", .{});
    try table.connect(client.id, service.id);
    try std.testing.expect(!table.hasPendingForTask(service.owner_task_id));
    try std.testing.expectEqual(service.owner_task_id, try table.send(client.id, client.owner_task_id, 1, "request", null, false));
    try std.testing.expect(table.hasPendingForTask(service.owner_task_id));
    try std.testing.expect(!table.hasPendingForTask(client.owner_task_id));
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    _ = try table.recvInto(service.id, &payload);
    try std.testing.expect(!table.hasPendingForTask(service.owner_task_id));
    try std.testing.expectEqual(client.owner_task_id, try table.reply(service.id, client.id, service.owner_task_id, 1, "reply", null, false));
    try std.testing.expect(table.hasPendingForTask(client.owner_task_id));
    _ = table.retireTask(client.owner_task_id);
    _ = try table.create(client.owner_task_id, "replacement", .{});
    try std.testing.expect(!table.hasPendingForTask(client.owner_task_id));
}
