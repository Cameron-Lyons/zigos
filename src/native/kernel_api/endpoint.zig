const std = @import("std");
const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const table_backing = @import("../core/table_backing.zig");
const ipc_ring = @import("ipc_ring.zig");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn allowSupervisorUserMemory() void {}
        pub fn forbidSupervisorUserMemory() void {}
    };

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_ENDPOINT_QUEUE: usize = 8;
pub const MAX_MESSAGE_BYTES: usize = abi.ENDPOINT_INLINE_BYTES;
pub const MAX_ENDPOINT_LABEL_BYTES: usize = 48;
const ENDPOINT_INDEX_CAPACITY: usize = MAX_ENDPOINTS * 2;
const MAX_ENDPOINT_LABEL_PAYLOAD_BYTES: usize = MAX_ENDPOINT_LABEL_BYTES - 1;
pub const ENDPOINT_PRIMARY_INDEX_LOOKUPS_PER_OPERATION: u8 = 0;
pub const ENDPOINT_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;
pub const FREESTANDING_TABLE_SIZE_CEILING_BYTES: usize = 12_000;

comptime {
    const byte_capacities = [_]usize{
        MAX_ENDPOINTS,
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

pub const HEAP_BACKS_QUEUES_ON_ALL_TARGETS = table_backing.HEAP_BACKS_ON_ALL_TARGETS;
pub const PREFERS_SEALED_RING_DATAPLANE = ipc_ring.DATA_PLANE_USES_SEALED_RINGS;
pub const AUTO_ATTACHES_DATA_RINGS = true;
pub const RINGS_ONLY_DATAPLANE = true;
pub const DEFAULT_DATA_RING_CAPACITY: u32 = 1024;
const DataRingStorage = struct {
    // The kernel heap guarantees its granule alignment, not cache-line
    // alignment. Retain the aligned ring's prefix length to free its allocation.
    bytes: [ipc_ring.minimumBytes(MAX_ENDPOINT_QUEUE) + ipc_ring.STORAGE_ALIGNMENT - 1]u8 = undefined,

    fn ring(self: *DataRingStorage) []u8 {
        const address = @intFromPtr(&self.bytes);
        const offset = std.mem.alignForward(usize, address, ipc_ring.STORAGE_ALIGNMENT) - address;
        return self.bytes[offset..][0..ipc_ring.minimumBytes(MAX_ENDPOINT_QUEUE)];
    }
};
const BORROWED_RING: u8 = std.math.maxInt(u8);
const ENDPOINT_RESIDENT_SIZE_CEILING_BYTES: usize = 160;

pub const Endpoint = struct {
    id: ids.EndpointId,
    owner_task_id: ids.TaskId,
    flags: EndpointFlags,
    label_len: u8,
    label: [MAX_ENDPOINT_LABEL_BYTES]u8,
    peer_endpoint_id: ids.EndpointId = ids.EndpointId.zero,
    peer_closed: bool = false,
    queue_len: u8 = 0,
    data_ring: []u8 = &.{},
    ring_allocation_offset: u8 = BORROWED_RING,

    comptime {
        if (@hasField(@This(), "queue")) @compileError("endpoint payloads live in the sealed ring");
        if (@sizeOf(@This()) > ENDPOINT_RESIDENT_SIZE_CEILING_BYTES) {
            @compileError("endpoints exceed their compact resident layout");
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
    PeerClosed,
    TableFull,
    NoSpaceLeft,
    ScopeViolation,
    RingFull,
    RingCorrupt,
};

const EndpointSlot = struct {
    in_use: bool = false,
    endpoint: Endpoint = zeroEndpoint(),
};

const EndpointArena = indexed_arena.GenerationalArena("EndpointId", EndpointSlot, MAX_ENDPOINTS);
const EndpointHandle = EndpointArena.Handle;
const EndpointOwnerIndex = indexed_arena.MultimapIndex(MAX_ENDPOINTS, MAX_ENDPOINTS, ENDPOINT_INDEX_CAPACITY);

pub const Retirement = struct {
    endpoint_count: u16 = 0,
    endpoint_ids: [MAX_ENDPOINTS]ids.EndpointId = [_]ids.EndpointId{ids.EndpointId.zero} ** MAX_ENDPOINTS,
    disconnected_count: u16 = 0,
    disconnected_task_ids: [MAX_ENDPOINTS]ids.TaskId = undefined,

    pub fn retiredEndpointIds(self: *const Retirement) []const ids.EndpointId {
        return self.endpoint_ids[0..self.endpoint_count];
    }

    // One notification per affected endpoint; the scheduler coalesces tasks.
    pub fn disconnectedTaskIds(self: *const Retirement) []const ids.TaskId {
        return self.disconnected_task_ids[0..self.disconnected_count];
    }
};

pub const MovedCapabilityCleanup = struct {
    context: *anyopaque,
    release: *const fn (context: *anyopaque, capability_id: ids.CapabilityId) void,
};

pub const Table = struct {
    arena: EndpointArena = EndpointArena.init(),
    owner_index: EndpointOwnerIndex = EndpointOwnerIndex.init(),
    pending_endpoint_counts: [MAX_ENDPOINTS]u8 = @splat(0),

    comptime {
        if (@sizeOf(@This()) > FREESTANDING_TABLE_SIZE_CEILING_BYTES) {
            @compileError("endpoint table exceeds its compact layout ceiling");
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
        self.arena.reset();
        self.owner_index.reset();
    }

    pub fn deinit(self: *Table) void {
        for (&self.arena.slots) |*slot| {
            if (slot.in_use) releaseEndpointRing(&slot.endpoint);
        }
        @memset(&self.pending_endpoint_counts, 0);
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

    // Only for a newly created endpoint whose handle has not been published.
    // The kernel uses this to unwind creation if the ownership grant fails.
    pub fn rollbackCreate(self: *Table, endpoint_id: ids.EndpointId) void {
        const handle = EndpointHandle{ .value = endpoint_id.raw() };
        const slot = self.arena.getByHandle(handle) orelse
            native_util.impossibleByInvariant("unpublished endpoint remains live until rollback");
        if (!slot.endpoint.peer_endpoint_id.isZero() or slot.endpoint.queue_len != 0) {
            native_util.impossibleByInvariant("unpublished endpoint has no peer or queued messages");
        }
        if (!self.owner_index.remove(slot.endpoint.owner_task_id.raw(), handle.slotIndex())) {
            native_util.impossibleByInvariant("unpublished endpoint is present in its owner index");
        }
        releaseEndpointRing(&slot.endpoint);
        if (!self.arena.removeHandle(handle)) {
            native_util.impossibleByInvariant("endpoint rollback removes its live handle");
        }
    }

    pub fn connect(self: *Table, endpoint_id: ids.EndpointId, peer_endpoint_id: ids.EndpointId) Error!void {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.peer_closed or peer.peer_closed) return error.PeerClosed;

        if (endpoint.flags.service_port and peer.flags.service_port) return error.ScopeViolation;

        if (peer.flags.service_port) {
            if (!endpoint.peer_endpoint_id.isZero()) return error.EndpointBusy;
            try attachConnectedRings(endpoint, peer);
            endpoint.peer_endpoint_id = peer_endpoint_id;
            return;
        }

        if (endpoint.flags.service_port) {
            if (!peer.peer_endpoint_id.isZero()) return error.EndpointBusy;
            try attachConnectedRings(endpoint, peer);
            peer.peer_endpoint_id = endpoint_id;
            return;
        }

        if (!endpoint.peer_endpoint_id.isZero() or !peer.peer_endpoint_id.isZero()) return error.EndpointBusy;

        try attachConnectedRings(endpoint, peer);
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
        if (payload.len > MAX_MESSAGE_BYTES or payload.len > ipc_ring.PAYLOAD_BYTES) return error.MessageTooLarge;

        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.peer_closed) return error.PeerClosed;
        const peer_endpoint_id = endpoint.peer_endpoint_id;
        if (peer_endpoint_id.isZero()) return error.PeerNotConnected;
        const peer = self.find(peer_endpoint_id) orelse return error.EndpointNotFound;
        return self.enqueue(endpoint, peer, sender_task_id, correlation_id, payload, attached_capability_id, move_attached_capability);
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
        return self.enqueue(service, client, sender_task_id, correlation_id, payload, attached_capability_id, move_attached_capability);
    }

    fn enqueue(
        self: *Table,
        source: *const Endpoint,
        peer: *Endpoint,
        sender_task_id: ids.TaskId,
        correlation_id: u64,
        payload: []const u8,
        attached_capability_id: ?ids.CapabilityId,
        move_attached_capability: bool,
    ) Error!ids.TaskId {
        if (peer.data_ring.len == 0) return error.RingCorrupt;
        if (peer.queue_len >= MAX_ENDPOINT_QUEUE) return error.RingFull;

        var record = ipc_ring.Record{
            .sender_endpoint_id = source.id.raw(),
            .sender_task_id = sender_task_id.raw(),
            .correlation_id = correlation_id,
            .attached_capability_id = if (attached_capability_id) |capability_id| capability_id.raw() else 0,
            .flags = @bitCast(EndpointFlags{
                .local_only = source.flags.local_only and peer.flags.local_only,
                .service_port = source.flags.service_port or peer.flags.service_port,
                .carries_capability = attached_capability_id != null,
            }),
            .payload_len = @intCast(payload.len),
            .move_attached = if (move_attached_capability) 1 else 0,
        };
        x86.allowSupervisorUserMemory();
        defer x86.forbidSupervisorUserMemory();
        if (payload.len != 0) @memcpy(record.bytes[0..payload.len], payload);
        ipc_ring.pushRecord(peer.data_ring, record) catch |err| switch (err) {
            error.RingFull => return error.RingFull,
            error.RingTooSmall, error.RingCorrupt, error.RingEmpty, error.PayloadTooLarge => return error.RingCorrupt,
        };
        if (peer.queue_len == 0) self.pendingCountForEndpoint(peer).* += 1;
        peer.queue_len += 1;
        return peer.owner_task_id;
    }

    // The caller retains storage lifetime; only this serialized table may
    // access the ring until replacement or endpoint retirement.
    pub fn attachDataRing(self: *Table, endpoint_id: ids.EndpointId, buffer: []u8) Error!void {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.queue_len != 0) return error.EndpointBusy;
        if (buffer.len < ipc_ring.minimumBytes(1) or
            buffer.len > ipc_ring.minimumBytes(MAX_ENDPOINT_QUEUE) or
            @intFromPtr(buffer.ptr) % ipc_ring.STORAGE_ALIGNMENT != 0) return error.RingCorrupt;
        for (&self.arena.slots) |*slot| {
            if (!slot.in_use or slot.endpoint.data_ring.len == 0) continue;
            const existing = &slot.endpoint;
            const owned = existing.ring_allocation_offset != BORROWED_RING;
            const base = @intFromPtr(existing.data_ring.ptr) - if (owned) existing.ring_allocation_offset else @as(usize, 0);
            const length = if (owned) @sizeOf(DataRingStorage) else existing.data_ring.len;
            const candidate = @intFromPtr(buffer.ptr);
            if (if (candidate >= base) candidate - base < length else base - candidate < buffer.len) return error.EndpointBusy;
        }
        _ = ipc_ring.init(buffer, @intCast(buffer.len - ipc_ring.HEADER_BYTES)) catch return error.RingCorrupt;
        releaseOwnedRing(endpoint);
        endpoint.data_ring = buffer;
    }

    pub fn recvInto(
        self: *Table,
        endpoint_id: ids.EndpointId,
        payload_out: []u8,
    ) Error!?ReceivedMessage {
        const endpoint = self.find(endpoint_id) orelse return error.EndpointNotFound;
        if (endpoint.queue_len == 0) {
            if (endpoint.peer_closed) return error.PeerClosed;
            return null;
        }
        if (endpoint.data_ring.len == 0) return error.RingCorrupt;

        x86.allowSupervisorUserMemory();
        defer x86.forbidSupervisorUserMemory();
        const record = ipc_ring.receive(endpoint.data_ring, payload_out) catch |err| switch (err) {
            error.PayloadTooLarge => return error.ReceiveBufferTooSmall,
            else => return error.RingCorrupt,
        };
        const attached = ids.capability(record.attached_capability_id);
        const received = ReceivedMessage{
            .sender_endpoint_id = ids.endpoint(record.sender_endpoint_id),
            .sender_task_id = ids.task(record.sender_task_id),
            .correlation_id = record.correlation_id,
            .attached_capability_id = if (attached.isZero()) null else attached,
            .move_attached_capability = record.move_attached != 0,
            .flags = @bitCast(record.flags),
            .len = record.payload_len,
        };
        endpoint.queue_len -= 1;
        if (endpoint.queue_len == 0) self.clearPendingEndpoint(endpoint);
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

    // Readiness depends on nonempty endpoint queues, independently of how many
    // empty endpoints the owner holds. Bucket reuse starts with a zero count.
    pub fn hasPendingForTask(self: *const Table, task_id: ids.TaskId) bool {
        const bucket_index = self.owner_index.bucketIndexForKey(task_id.raw()) orelse return false;
        return self.pending_endpoint_counts[bucket_index] != 0;
    }

    pub fn activeCount(self: *const Table) usize {
        return self.arena.countInUse();
    }

    pub fn close(self: *Table, endpoint_id: ids.EndpointId, cleanup: ?MovedCapabilityCleanup) Error!Retirement {
        const handle = EndpointHandle{ .value = endpoint_id.raw() };
        _ = self.arena.getByHandle(handle) orelse return error.EndpointNotFound;
        var retired = Retirement{};
        self.retireIndex(handle.slotIndex(), cleanup, &retired);
        self.disconnectRetiredPeers(&retired);
        return retired;
    }

    pub fn retireTask(self: *Table, task_id: ids.TaskId, cleanup: ?MovedCapabilityCleanup) Retirement {
        var retired = Retirement{};
        while (true) {
            const slot_index = self.owner_index.head(task_id.raw());
            if (slot_index == indexed_arena.no_index) break;
            if (slot_index >= self.arena.slots.len or
                !self.arena.slots[slot_index].endpoint.owner_task_id.eql(task_id))
            {
                native_util.impossibleByInvariant("endpoint owner index points at the wrong endpoint");
            }
            self.retireIndex(slot_index, cleanup, &retired);
        }
        if (retired.endpoint_count != 0) self.disconnectRetiredPeers(&retired);
        return retired;
    }

    fn retireIndex(self: *Table, slot_index: usize, cleanup: ?MovedCapabilityCleanup, retired: *Retirement) void {
        const slot = &self.arena.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("retiring endpoint slot remains live");
        retired.endpoint_ids[retired.endpoint_count] = slot.endpoint.id;
        retired.endpoint_count += 1;
        if (slot.endpoint.queue_len != 0) self.clearPendingEndpoint(&slot.endpoint);
        if (!self.owner_index.remove(slot.endpoint.owner_task_id.raw(), slot_index)) {
            native_util.impossibleByInvariant("live endpoint is absent from its owner index");
        }
        if (cleanup) |sink| {
            if (slot.endpoint.data_ring.len != 0) {
                while (true) {
                    const record = ipc_ring.popRecord(slot.endpoint.data_ring) catch break;
                    if (record.move_attached != 0 and record.attached_capability_id != 0) {
                        sink.release(sink.context, ids.capability(record.attached_capability_id));
                    }
                }
            }
        }
        releaseEndpointRing(&slot.endpoint);
        if (!self.arena.removeIndex(slot_index)) {
            native_util.impossibleByInvariant("live endpoint disappeared during retirement");
        }
    }

    fn disconnectRetiredPeers(self: *Table, retired: *Retirement) void {
        // A single bounded scan, with generational lookups rather than comparing
        // every live peer against every endpoint retired from a large task.
        for (&self.arena.slots) |*slot| {
            if (!slot.in_use or slot.endpoint.peer_endpoint_id.isZero()) continue;
            if (self.findConst(slot.endpoint.peer_endpoint_id) != null) continue;
            slot.endpoint.peer_endpoint_id = ids.EndpointId.zero;
            slot.endpoint.peer_closed = true;
            retired.disconnected_task_ids[retired.disconnected_count] = slot.endpoint.owner_task_id;
            retired.disconnected_count += 1;
        }
    }

    fn find(self: *Table, endpoint_id: ids.EndpointId) ?*Endpoint {
        const slot = self.arena.getByHandle(EndpointHandle{ .value = endpoint_id.raw() }) orelse return null;
        return &slot.endpoint;
    }

    fn findConst(self: *const Table, endpoint_id: ids.EndpointId) ?*const Endpoint {
        const slot = self.arena.getConstByHandle(EndpointHandle{ .value = endpoint_id.raw() }) orelse return null;
        return &slot.endpoint;
    }

    fn pendingCountForEndpoint(self: *Table, endpoint: *const Endpoint) *u8 {
        const slot_index = (EndpointHandle{ .value = endpoint.id.raw() }).slotIndex();
        const bucket_index = self.owner_index.bucketIndexForSlot(slot_index) orelse
            native_util.impossibleByInvariant("live endpoint belongs to an owner bucket");
        return &self.pending_endpoint_counts[bucket_index];
    }

    fn clearPendingEndpoint(self: *Table, endpoint: *const Endpoint) void {
        const count = self.pendingCountForEndpoint(endpoint);
        if (count.* == 0) native_util.impossibleByInvariant("nonempty endpoint is counted in owner readiness");
        count.* -= 1;
    }
};

fn attachConnectedRings(endpoint: *Endpoint, peer: *Endpoint) Error!void {
    const allocated_endpoint = endpoint.data_ring.len == 0;
    try ensureDataRing(endpoint);
    errdefer if (allocated_endpoint) releaseOwnedRing(endpoint);
    try ensureDataRing(peer);
}

fn releaseEndpointRing(endpoint: *Endpoint) void {
    releaseOwnedRing(endpoint);
    endpoint.queue_len = 0;
}

fn ensureDataRing(endpoint: *Endpoint) error{NoSpaceLeft}!void {
    if (endpoint.data_ring.len != 0) return;
    const storage = table_backing.alloc(DataRingStorage) orelse return error.NoSpaceLeft;
    const buffer = storage.ring();
    _ = ipc_ring.init(buffer, DEFAULT_DATA_RING_CAPACITY) catch {
        table_backing.free(DataRingStorage, storage);
        return error.NoSpaceLeft;
    };
    endpoint.data_ring = buffer;
    endpoint.ring_allocation_offset = @intCast(@intFromPtr(buffer.ptr) - @intFromPtr(storage));
}

fn releaseOwnedRing(endpoint: *Endpoint) void {
    if (endpoint.ring_allocation_offset != BORROWED_RING) {
        const storage: *DataRingStorage = @ptrCast(endpoint.data_ring.ptr - endpoint.ring_allocation_offset);
        table_backing.free(DataRingStorage, storage);
    }
    endpoint.data_ring = &.{};
    endpoint.ring_allocation_offset = BORROWED_RING;
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
    try std.testing.expectEqual(@as(usize, 128), ipc_ring.SLOT_BYTES);
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(@FieldType(Endpoint, "queue_len")));
    try std.testing.expect(HEAP_BACKS_QUEUES_ON_ALL_TARGETS);
    try std.testing.expect(AUTO_ATTACHES_DATA_RINGS);
    try std.testing.expect(@sizeOf(Endpoint) <= ENDPOINT_RESIDENT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(EndpointSlot) <= ENDPOINT_RESIDENT_SIZE_CEILING_BYTES + 8);
    try std.testing.expect(@sizeOf(Table) <= FREESTANDING_TABLE_SIZE_CEILING_BYTES);
}

test "endpoints move payloads on a sealed ring" {
    var table = Table.init();
    defer table.deinit();
    const left = try table.create(ids.task(20), "ring-left", .{});
    const right = try table.create(ids.task(21), "ring-right", .{});
    try table.connect(left.id, right.id);
    _ = try table.send(left.id, ids.task(20), 9, "ring-payload", null, false);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqualStrings("ring-payload", payload[0..received.len]);
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
    defer table.deinit();
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

test "closing an endpoint drains peer replies and makes the connection terminal" {
    const Recorder = struct {
        released: u64 = 0,
        count: usize = 0,
        fn release(context: *anyopaque, capability_id: ids.CapabilityId) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.released = capability_id.raw();
            self.count += 1;
        }
    };
    var table = Table.init();
    var recorder = Recorder{};
    const left = try table.create(ids.task(10), "left", .{});
    const right = try table.create(ids.task(20), "right", .{});
    const sibling = try table.create(left.owner_task_id, "sibling", .{});
    try table.connect(left.id, right.id);
    _ = try table.send(left.id, left.owner_task_id, 1, "last reply", ids.capability(77), true);
    _ = try table.send(right.id, right.owner_task_id, 2, "discarded move", ids.capability(88), true);
    _ = try table.send(right.id, right.owner_task_id, 3, "sender copy", ids.capability(99), false);
    const closed = try table.close(left.id, .{ .context = &recorder, .release = Recorder.release });
    try std.testing.expectEqual(@as(usize, 1), recorder.count);
    try std.testing.expectEqual(@as(u64, 88), recorder.released);
    try std.testing.expectEqual(@as(u16, 1), closed.endpoint_count);
    try std.testing.expectEqual(@as(u16, 1), closed.disconnected_count);
    try std.testing.expect(closed.disconnectedTaskIds()[0].eql(right.owner_task_id));
    try std.testing.expectEqual(@as(u16, 1), table.activeForTask(left.owner_task_id));
    _ = try table.descriptor(sibling.id);
    try std.testing.expectError(error.PeerClosed, table.send(right.id, right.owner_task_id, 4, "closed", null, false));
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const last = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqualStrings("last reply", payload[0..last.len]);
    try std.testing.expect(last.attached_capability_id.?.eql(ids.capability(77)));
    try std.testing.expectError(error.PeerClosed, table.recvInto(right.id, &payload));
    try std.testing.expectError(error.PeerClosed, table.recvInto(right.id, &payload));
    try std.testing.expect(!table.hasPendingForTask(right.owner_task_id));
    const replacement = try table.create(left.owner_task_id, "replacement", .{});
    try std.testing.expect(!replacement.id.eql(left.id));
    try std.testing.expectError(error.EndpointNotFound, table.close(left.id, null));
    try std.testing.expectError(error.PeerClosed, table.connect(right.id, replacement.id));
    try std.testing.expectEqual(@as(u64, 0), (try table.descriptor(replacement.id)).peer_endpoint_id);
}

test "closing a client preserves service peers and closing the service notifies survivors" {
    var table = Table.init();
    const service = try table.create(ids.task(1), "service", .{ .service_port = true });
    const first = try table.create(ids.task(2), "first", .{});
    const second = try table.create(ids.task(3), "second", .{});
    try table.connect(first.id, service.id);
    try table.connect(second.id, service.id);
    _ = try table.send(first.id, first.owner_task_id, 1, "queued", null, false);
    const closed_client = try table.close(first.id, null);
    try std.testing.expectEqual(@as(u16, 0), closed_client.disconnected_count);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    _ = (try table.recvInto(service.id, &payload)).?;
    try std.testing.expectError(error.EndpointNotFound, table.reply(service.id, first.id, service.owner_task_id, 1, "late", null, false));
    try std.testing.expect((try table.recvInto(service.id, &payload)) == null);
    _ = try table.send(second.id, second.owner_task_id, 2, "live", null, false);
    _ = (try table.recvInto(service.id, &payload)).?;
    _ = try table.reply(service.id, second.id, service.owner_task_id, 2, "reply", null, false);
    const third = try table.create(ids.task(4), "third", .{});
    try table.connect(third.id, service.id);
    const closed_service = try table.close(service.id, null);
    try std.testing.expectEqual(@as(u16, 2), closed_service.disconnected_count);
    const last = (try table.recvInto(second.id, &payload)).?;
    try std.testing.expectEqualStrings("reply", payload[0..last.len]);
    try std.testing.expectError(error.PeerClosed, table.recvInto(second.id, &payload));
    try std.testing.expectError(error.PeerClosed, table.recvInto(third.id, &payload));
}

test "endpoint ids reject stale handles after slot reuse" {
    var table = Table.init();
    const endpoint = try table.create(ids.task(10), "first", .{});
    const original_handle = EndpointHandle{ .value = endpoint.id.raw() };

    const retired = table.retireTask(ids.task(10), null);
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

test "endpoint exhaustion survives table reset without reviving stale authority" {
    var table = Table.init();
    defer table.deinit();
    table.arena.slot_generations[0] = indexed_arena.MAX_HANDLE_GENERATION;
    const last = try table.create(ids.task(10), "last", .{});
    const ordinary = try table.create(ids.task(11), "ordinary", .{});
    table.reset();
    const next = try table.create(ids.task(12), "next", .{});
    try std.testing.expectEqual(@as(usize, 1), (EndpointHandle{ .value = next.id.raw() }).slotIndex());
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(last.id));
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(ordinary.id));
    try std.testing.expectEqual(@as(u16, 0), table.activeForTask(ids.task(10)));
    try std.testing.expectEqual(@as(u16, 1), table.activeForTask(ids.task(12)));
    table.reset();
    @memset(&table.arena.slot_generations, indexed_arena.EXHAUSTED_HANDLE_GENERATION);
    try std.testing.expectError(error.TableFull, table.create(ids.task(13), "exhausted", .{}));
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
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

test "endpoint retirement releases only unread moves across queue wraparound" {
    const Recorder = struct {
        ids: [MAX_ENDPOINT_QUEUE]u64 = [_]u64{0} ** MAX_ENDPOINT_QUEUE,
        count: usize = 0,
        fn release(context: *anyopaque, capability_id: ids.CapabilityId) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.ids[self.count] = capability_id.raw();
            self.count += 1;
        }
    };
    var recorder = Recorder{};
    var table = Table.init();
    const client = try table.create(ids.task(1), "client", .{});
    const server = try table.create(ids.task(2), "server", .{ .service_port = true });
    try table.connect(client.id, server.id);
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    for (0..4) |index| {
        _ = try table.send(client.id, client.owner_task_id, 1, "already received", ids.capability(100 + index), true);
        _ = try table.recvInto(server.id, &payload);
    }
    for (0..MAX_ENDPOINT_QUEUE) |index| {
        _ = try table.send(client.id, client.owner_task_id, 2, "unread", ids.capability(200 + index), index % 2 == 0);
    }
    _ = table.retireTask(server.owner_task_id, .{ .context = &recorder, .release = Recorder.release });
    try std.testing.expectEqual(@as(usize, 4), recorder.count);
    try std.testing.expectEqualSlices(u64, &.{ 200, 202, 204, 206 }, recorder.ids[0..recorder.count]);
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

    const retired = table.retireTask(ids.task(12), null);
    try std.testing.expectEqual(@as(u16, 1), retired.endpoint_count);
    try std.testing.expect(retired.retiredEndpointIds()[0].eql(service.id));
    try std.testing.expectEqual(@as(usize, 2), table.activeCount());
    try std.testing.expectError(error.EndpointNotFound, table.descriptor(service.id));
    try std.testing.expectEqual(@as(u64, 0), (try table.descriptor(client_a.id)).peer_endpoint_id);
    try std.testing.expectEqual(@as(u64, 0), (try table.descriptor(client_b.id)).peer_endpoint_id);
    try std.testing.expectError(error.PeerClosed, table.send(client_a.id, ids.task(10), 3, "stale", null, false));
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
    _ = table.retireTask(client.owner_task_id, null);
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
    try std.testing.expectError(error.RingFull, table.reply(service.id, second.id, service.owner_task_id, 99, "overflow", null, false));
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
    _ = table.retireTask(client.owner_task_id, null);
    _ = try table.create(client.owner_task_id, "replacement", .{});
    try std.testing.expect(!table.hasPendingForTask(client.owner_task_id));
}

test "owner readiness survives partial drains failed receives and queued endpoint closure" {
    var table = Table.init();
    defer table.deinit();
    const owner = ids.task(20);
    const first_sender = try table.create(ids.task(10), "first sender", .{});
    const second_sender = try table.create(first_sender.owner_task_id, "second sender", .{});
    const first = try table.create(owner, "first receiver", .{});
    const second = try table.create(owner, "second receiver", .{});
    _ = try table.create(owner, "empty receiver", .{});
    try table.connect(first_sender.id, first.id);
    try table.connect(second_sender.id, second.id);
    {
        const buffer = table.find(second.id).?.data_ring;
        const original_magic_byte = buffer[0];
        buffer[0] ^= 0xff;
        defer buffer[0] = original_magic_byte;
        try std.testing.expectError(error.RingCorrupt, table.send(second_sender.id, second_sender.owner_task_id, 0, "failed", null, false));
        try std.testing.expect(!table.hasPendingForTask(owner));
    }
    _ = try table.send(first_sender.id, first_sender.owner_task_id, 1, "first", null, false);
    _ = try table.send(first_sender.id, first_sender.owner_task_id, 2, "second", null, false);
    _ = try table.send(second_sender.id, second_sender.owner_task_id, 3, "remaining", ids.capability(99), true);
    try std.testing.expect(table.hasPendingForTask(owner));

    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    _ = (try table.recvInto(first.id, &payload)).?;
    try std.testing.expect(table.hasPendingForTask(owner));
    _ = try table.close(first.id, null);
    try std.testing.expect(table.hasPendingForTask(owner));
    var short: [1]u8 = undefined;
    try std.testing.expectError(error.ReceiveBufferTooSmall, table.recvInto(second.id, &short));
    try std.testing.expect(table.hasPendingForTask(owner));
    const ring_buffer = table.find(second.id).?.data_ring;
    const original_magic_byte = ring_buffer[0];
    ring_buffer[0] ^= 0xff;
    try std.testing.expectError(error.RingCorrupt, table.recvInto(second.id, &payload));
    try std.testing.expect(table.hasPendingForTask(owner));
    ring_buffer[0] = original_magic_byte;
    for (1..MAX_ENDPOINT_QUEUE) |sequence| {
        _ = try table.send(second_sender.id, second_sender.owner_task_id, sequence + 3, "queued", null, false);
    }
    try std.testing.expectError(error.RingFull, table.send(second_sender.id, second_sender.owner_task_id, 99, "overflow", null, false));
    try std.testing.expect(table.hasPendingForTask(owner));
    const preserved = (try table.recvInto(second.id, &payload)).?;
    try std.testing.expectEqualStrings("remaining", payload[0..preserved.len]);
    try std.testing.expectEqual(ids.capability(99), preserved.attached_capability_id.?);
    try std.testing.expect(preserved.move_attached_capability);
    for (1..MAX_ENDPOINT_QUEUE) |_| {
        try std.testing.expect(table.hasPendingForTask(owner));
        _ = (try table.recvInto(second.id, &payload)).?;
    }
    try std.testing.expect(!table.hasPendingForTask(owner));
}

test "owner readiness clears on retirement deinit reset and owner bucket reuse" {
    var table = Table.init();
    defer table.deinit();
    const sender = try table.create(ids.task(10), "sender", .{});
    const receiver = try table.create(ids.task(20), "receiver", .{});
    try table.connect(sender.id, receiver.id);
    _ = try table.send(sender.id, sender.owner_task_id, 1, "retired", null, false);
    try std.testing.expect(table.hasPendingForTask(receiver.owner_task_id));
    _ = table.retireTask(receiver.owner_task_id, null);
    const replacement = try table.create(ids.task(30), "new owner", .{});
    try std.testing.expect(!table.hasPendingForTask(receiver.owner_task_id));
    try std.testing.expect(!table.hasPendingForTask(replacement.owner_task_id));
    const new_sender = try table.create(sender.owner_task_id, "new sender", .{});
    try table.connect(new_sender.id, replacement.id);
    _ = try table.send(new_sender.id, new_sender.owner_task_id, 2, "deinitialized", null, false);
    try std.testing.expect(table.hasPendingForTask(replacement.owner_task_id));
    table.deinit();
    try std.testing.expect(!table.hasPendingForTask(replacement.owner_task_id));
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(replacement.id)).queued_messages);
    table.reset();
    const restored = try table.create(replacement.owner_task_id, "reset owner", .{});
    try std.testing.expect(!table.hasPendingForTask(restored.owner_task_id));
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
}

test "ring replacement rejects malformed storage and preserves queued messages" {
    var table = Table.init();
    defer table.deinit();
    const left = try table.create(ids.task(101), "left", .{});
    const right = try table.create(ids.task(102), "right", .{});
    var invalid: [ipc_ring.HEADER_BYTES]u8 align(64) = undefined;
    try std.testing.expectError(error.RingCorrupt, table.attachDataRing(left.id, &invalid));
    try table.connect(left.id, right.id);
    _ = try table.send(left.id, left.owner_task_id, 1, "pending", null, false);
    var replacement: [ipc_ring.HEADER_BYTES + DEFAULT_DATA_RING_CAPACITY]u8 align(64) = undefined;
    try std.testing.expectError(error.EndpointBusy, table.attachDataRing(right.id, &replacement));
    var payload: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(right.id, &payload)).?;
    try std.testing.expectEqualStrings("pending", payload[0..received.len]);
}

test "endpoint ring storage aligns from every possible allocation offset" {
    var arena: [@sizeOf(DataRingStorage) + ipc_ring.STORAGE_ALIGNMENT]u8 align(ipc_ring.STORAGE_ALIGNMENT) = undefined;
    for (0..ipc_ring.STORAGE_ALIGNMENT) |offset| {
        const storage: *DataRingStorage = @ptrCast(&arena[offset]);
        const ring = storage.ring();
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(ring.ptr) % ipc_ring.STORAGE_ALIGNMENT);
        try std.testing.expect(@intFromPtr(ring.ptr) >= @intFromPtr(storage));
        try std.testing.expect(@intFromPtr(ring.ptr) + ring.len <= @intFromPtr(storage) + @sizeOf(DataRingStorage));
        _ = try ipc_ring.init(ring, DEFAULT_DATA_RING_CAPACITY);
        try ipc_ring.push(ring, "aligned");
        var out: [MAX_MESSAGE_BYTES]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 7), try ipc_ring.pop(ring, &out));
        try std.testing.expectEqualStrings("aligned", out[0..7]);
    }
}

test "endpoint ring replacement rejects non power of two storage without losing ownership" {
    var table = Table.init();
    defer table.deinit();
    const client = try table.create(ids.task(101), "client", .{});
    const server = try table.create(ids.task(102), "server", .{});
    try table.connect(client.id, server.id);
    const allocation = table.find(server.id).?.data_ring.ptr;
    const prefix = table.find(server.id).?.ring_allocation_offset;
    var malformed: [ipc_ring.minimumBytes(3)]u8 align(ipc_ring.STORAGE_ALIGNMENT) = @splat(0xa5);
    try std.testing.expectError(error.RingCorrupt, table.attachDataRing(server.id, &malformed));
    try std.testing.expectEqual(allocation, table.find(server.id).?.data_ring.ptr);
    try std.testing.expectEqual(prefix, table.find(server.id).?.ring_allocation_offset);
    for (malformed) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    _ = try table.send(client.id, client.owner_task_id, 1, "still connected", null, false);
    var out: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(server.id, &out)).?;
    try std.testing.expectEqualStrings("still connected", out[0..received.len]);

    var replacement: [ipc_ring.minimumBytes(1)]u8 align(ipc_ring.STORAGE_ALIGNMENT) = undefined;
    try table.attachDataRing(server.id, &replacement);
    try std.testing.expectEqual(BORROWED_RING, table.find(server.id).?.ring_allocation_offset);
    _ = try table.send(client.id, client.owner_task_id, 2, "one slot", null, false);
    try std.testing.expectError(error.RingFull, table.send(client.id, client.owner_task_id, 3, "full", null, false));
    try std.testing.expectEqual(@as(u16, 1), (try table.descriptor(server.id)).queued_messages);
    _ = try table.recvInto(server.id, &out);
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(server.id)).queued_messages);
}

test "endpoint ring attachment rejects aliases before resetting or freeing storage" {
    var table = Table.init();
    defer table.deinit();
    const client = try table.create(ids.task(101), "client", .{});
    const server = try table.create(ids.task(102), "server", .{});
    try table.connect(client.id, server.id);
    const existing = table.find(server.id).?.data_ring;
    try std.testing.expectError(error.EndpointBusy, table.attachDataRing(server.id, existing));
    try std.testing.expectError(error.EndpointBusy, table.attachDataRing(client.id, existing));
    try std.testing.expectError(error.EndpointBusy, table.attachDataRing(client.id, existing[64..][0..ipc_ring.minimumBytes(2)]));
    _ = try table.send(client.id, client.owner_task_id, 1, "still owned", ids.capability(77), true);
    var out: [MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try table.recvInto(server.id, &out)).?;
    try std.testing.expectEqualStrings("still owned", out[0..received.len]);
    try std.testing.expectEqual(ids.capability(77), received.attached_capability_id.?);
}
