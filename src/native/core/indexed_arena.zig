const builtin = @import("builtin");
const std = @import("std");
const id_index = @import("id_index.zig");
const ids = @import("ids.zig");
const native_util = @import("util.zig");

pub const no_index = std.math.maxInt(usize);

pub fn nonZeroKey(key: u64) u64 {
    return if (key == 0) 1 else key;
}

pub fn UniqueIndex(comptime capacity: usize) type {
    if (capacity == 0) @compileError("unique index requires at least one slot");

    return struct {
        const Self = @This();

        slots: [capacity]id_index.Slot = id_index.emptyTable(capacity),

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.slots = id_index.emptyTable(capacity);
        }

        pub fn lookup(self: *const Self, key: u64) ?usize {
            return id_index.lookup(capacity, &self.slots, key);
        }

        pub fn contains(self: *const Self, key: u64) bool {
            return self.lookup(key) != null;
        }

        pub fn insert(self: *Self, key: u64, slot_index: usize) void {
            id_index.insert(capacity, &self.slots, key, slot_index, "indexed arena unique indexes never store zero keys");
        }

        pub fn remove(self: *Self, key: u64) void {
            id_index.remove(capacity, &self.slots, key);
        }
    };
}

pub fn MultimapIndex(
    comptime link_capacity: usize,
    comptime bucket_capacity: usize,
    comptime index_capacity: usize,
) type {
    if (link_capacity == 0) @compileError("multimap index requires at least one linked slot");
    if (bucket_capacity == 0) @compileError("multimap index requires at least one bucket");
    if (index_capacity < bucket_capacity) @compileError("multimap bucket index capacity must cover buckets");

    return struct {
        const Self = @This();
        const BucketIndex = UniqueIndex(index_capacity);

        const Bucket = struct {
            in_use: bool = false,
            key: u64 = 0,
            head: usize = no_index,
            tail: usize = no_index,
            count: usize = 0,
        };

        bucket_index: BucketIndex = BucketIndex.init(),
        buckets: [bucket_capacity]Bucket = [_]Bucket{Bucket{}} ** bucket_capacity,
        next_by_slot: [link_capacity]usize = [_]usize{no_index} ** link_capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn count(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return 0;
            return entry.count;
        }

        pub fn head(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return no_index;
            return entry.head;
        }

        pub fn tail(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return no_index;
            return entry.tail;
        }

        pub fn next(self: *const Self, slot_index: usize) usize {
            if (slot_index >= link_capacity) return no_index;
            return self.next_by_slot[slot_index];
        }

        pub fn append(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            const entry = self.findOrCreateBucket(key) orelse return false;
            self.next_by_slot[slot_index] = no_index;
            if (entry.tail == no_index) {
                entry.head = slot_index;
            } else {
                self.next_by_slot[entry.tail] = slot_index;
            }
            entry.tail = slot_index;
            entry.count += 1;
            return true;
        }

        pub fn remove(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            const entry = self.bucket(key) orelse return false;

            var previous: usize = no_index;
            var current = entry.head;
            while (current != no_index) : (current = self.next_by_slot[current]) {
                if (current == slot_index) {
                    const next_index = self.next_by_slot[current];
                    if (previous == no_index) {
                        entry.head = next_index;
                    } else {
                        self.next_by_slot[previous] = next_index;
                    }
                    if (entry.tail == current) entry.tail = previous;
                    self.next_by_slot[current] = no_index;
                    entry.count -= 1;
                    if (entry.count == 0) {
                        const bucket_key = entry.key;
                        entry.* = .{};
                        self.bucket_index.remove(bucket_key);
                    }
                    return true;
                }
                previous = current;
            }
            return false;
        }

        fn bucket(self: *Self, key: u64) ?*Bucket {
            const bucket_index = self.bucket_index.lookup(key) orelse return null;
            if (bucket_index >= bucket_capacity) native_util.impossibleByInvariant("multimap bucket index points outside buckets");
            const slot = &self.buckets[bucket_index];
            if (!slot.in_use or slot.key != key) native_util.impossibleByInvariant("multimap bucket index points at the wrong bucket");
            return slot;
        }

        fn bucketConst(self: *const Self, key: u64) ?*const Bucket {
            const bucket_index = self.bucket_index.lookup(key) orelse return null;
            if (bucket_index >= bucket_capacity) native_util.impossibleByInvariant("multimap bucket index points outside buckets");
            const slot = &self.buckets[bucket_index];
            if (!slot.in_use or slot.key != key) native_util.impossibleByInvariant("multimap bucket index points at the wrong bucket");
            return slot;
        }

        fn findOrCreateBucket(self: *Self, key: u64) ?*Bucket {
            if (self.bucket(key)) |slot| return slot;
            for (&self.buckets, 0..) |*slot, bucket_index| {
                if (slot.in_use) continue;
                slot.* = .{
                    .in_use = true,
                    .key = key,
                };
                self.bucket_index.insert(key, bucket_index);
                return slot;
            }
            return null;
        }
    };
}

pub fn IndexedArena(
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    return IndexedArenaWithKey(u64, Slot, capacity, index_capacity, keyOf);
}

pub fn IndexedArenaWithKey(
    comptime Key: type,
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    if (capacity == 0) @compileError("indexed arena requires at least one slot");
    if (index_capacity < capacity) @compileError("indexed arena primary index capacity must cover slots");

    return struct {
        const Self = @This();

        slots: [capacity]Slot = [_]Slot{Slot{}} ** capacity,
        primary_index: UniqueIndex(index_capacity) = UniqueIndex(index_capacity).init(),
        slot_keys: [capacity]Key = [_]Key{ids.zero(Key)} ** capacity,
        free_next: [capacity]?usize = [_]?usize{null} ** capacity,
        free_head: ?usize = null,
        next_unclaimed_index: usize = 0,
        used_count: usize = 0,
        dirty_count: usize = 0,
        dirty_ids: [capacity]Key = [_]Key{ids.zero(Key)} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn reserve(self: *Self, key: Key) ?*Slot {
            const slot_index = self.reserveIndex(key) orelse return null;
            return &self.slots[slot_index];
        }

        pub fn reserveIndex(self: *Self, key: Key) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;

            const slot_index = self.popFreeIndex() orelse return null;
            self.claimSlot(key, raw_key, slot_index);
            return slot_index;
        }

        pub fn reserveAtIndex(self: *Self, key: Key, slot_index: usize) ?*Slot {
            const claimed_index = self.reserveIndexAt(key, slot_index) orelse return null;
            return &self.slots[claimed_index];
        }

        pub fn reserveIndexAt(self: *Self, key: Key, slot_index: usize) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0 or slot_index >= capacity) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;
            if (self.slots[slot_index].in_use) return null;
            if (!self.claimFreeIndex(slot_index)) return null;

            self.claimSlot(key, raw_key, slot_index);
            return slot_index;
        }

        fn claimSlot(self: *Self, key: Key, raw_key: u64, slot_index: usize) void {
            self.slots[slot_index] = Slot{};
            self.slots[slot_index].in_use = true;
            self.slot_keys[slot_index] = key;
            self.primary_index.insert(raw_key, slot_index);
            self.used_count += 1;
            self.markDirty(key);
        }

        pub fn availableIndexExcluding(
            self: *const Self,
            context: anytype,
            comptime excludes: anytype,
        ) ?usize {
            var next_index = self.free_head;
            var attempts: usize = 0;
            while (next_index) |slot_index| : (attempts += 1) {
                if (slot_index >= capacity or attempts >= capacity) return null;
                next_index = self.free_next[slot_index];
                if (excludes(context, slot_index)) continue;
                return slot_index;
            }

            var slot_index = self.next_unclaimed_index;
            while (slot_index < capacity) : (slot_index += 1) {
                if (excludes(context, slot_index)) continue;
                return slot_index;
            }
            return null;
        }

        pub fn get(self: *Self, key: Key) ?*Slot {
            const slot_index = self.findIndex(key) orelse return null;
            return &self.slots[slot_index];
        }

        pub fn getConst(self: *const Self, key: Key) ?*const Slot {
            const slot_index = self.findIndex(key) orelse return null;
            return &self.slots[slot_index];
        }

        pub fn slotIndexOf(self: *const Self, key: Key) ?usize {
            return self.findIndex(key);
        }

        pub fn remove(self: *Self, key: Key) bool {
            const slot_index = self.findIndex(key) orelse return false;
            return self.removeIndex(slot_index);
        }

        pub fn removeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity) return false;
            const slot = &self.slots[slot_index];
            if (!slot.in_use) return false;

            const key = self.slot_keys[slot_index];
            const raw_key = ids.raw(key);
            if (raw_key != 0) {
                self.primary_index.remove(raw_key);
                self.markDirty(key);
            }
            slot.* = Slot{};
            self.slot_keys[slot_index] = ids.zero(Key);
            self.used_count -= 1;
            self.pushFreeIndex(slot_index);
            return true;
        }

        pub fn rebuildPrimaryIndex(self: *Self) void {
            self.primary_index.reset();
            self.slot_keys = [_]Key{ids.zero(Key)} ** capacity;
            self.free_next = [_]?usize{null} ** capacity;
            self.free_head = null;
            self.next_unclaimed_index = capacity;
            self.used_count = 0;

            for (&self.slots, 0..) |*slot, slot_index| {
                if (slot.in_use) {
                    const key = keyOf(slot);
                    const raw_key = ids.raw(key);
                    if (raw_key != 0) {
                        self.slot_keys[slot_index] = key;
                        self.primary_index.insert(raw_key, slot_index);
                    }
                    self.used_count += 1;
                }
            }

            var slot_index = capacity;
            while (slot_index > 0) {
                slot_index -= 1;
                if (!self.slots[slot_index].in_use) self.pushFreeIndex(slot_index);
            }
        }

        pub fn countInUse(self: *const Self) usize {
            return self.used_count;
        }

        fn countMatching(self: *const Self, context: anytype, comptime matches: anytype) usize {
            var count: usize = 0;
            for (&self.slots) |*slot| {
                if (!slot.in_use) continue;
                if (matches(context, slot)) count += 1;
            }
            return count;
        }

        fn findMatching(self: *Self, context: anytype, comptime matches: anytype) ?*Slot {
            for (&self.slots) |*slot| {
                if (!slot.in_use) continue;
                if (matches(context, slot)) return slot;
            }
            return null;
        }

        fn findConstMatching(self: *const Self, context: anytype, comptime matches: anytype) ?*const Slot {
            for (&self.slots) |*slot| {
                if (!slot.in_use) continue;
                if (matches(context, slot)) return slot;
            }
            return null;
        }

        pub fn findByUniqueIndex(
            self: *Self,
            secondary_index: anytype,
            key: u64,
            context: anytype,
            comptime matches: anytype,
        ) ?*Slot {
            if (secondary_index.lookup(key)) |slot_index| {
                if (slot_index >= capacity) native_util.impossibleByInvariant("indexed arena secondary index points outside slots");
                const slot = &self.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("indexed arena secondary index points at a free slot");
                if (!matches(context, slot)) native_util.impossibleByInvariant("indexed arena secondary index points at the wrong slot");
                return slot;
            }
            if (debugScanFallbackEnabled() and self.findMatching(context, matches) != null) {
                native_util.impossibleByInvariant("indexed arena secondary index missed a live slot");
            }
            return null;
        }

        pub fn findConstByUniqueIndex(
            self: *const Self,
            secondary_index: anytype,
            key: u64,
            context: anytype,
            comptime matches: anytype,
        ) ?*const Slot {
            if (secondary_index.lookup(key)) |slot_index| {
                if (slot_index >= capacity) native_util.impossibleByInvariant("indexed arena secondary index points outside slots");
                const slot = &self.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("indexed arena secondary index points at a free slot");
                if (!matches(context, slot)) native_util.impossibleByInvariant("indexed arena secondary index points at the wrong slot");
                return slot;
            }
            if (debugScanFallbackEnabled() and self.findConstMatching(context, matches) != null) {
                native_util.impossibleByInvariant("indexed arena secondary index missed a live slot");
            }
            return null;
        }

        pub fn rebuildUniqueIndex(
            self: *const Self,
            secondary_index: anytype,
            comptime secondaryKeyOf: anytype,
        ) void {
            secondary_index.reset();
            for (self.slots, 0..) |slot, slot_index| {
                if (!slot.in_use) continue;
                const key = secondaryKeyOf(&slot);
                if (key != 0) secondary_index.insert(key, slot_index);
            }
        }

        pub fn markDirty(self: *Self, key: Key) void {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return;
            for (self.dirty_ids[0..self.dirty_count]) |existing| {
                if (ids.raw(existing) == raw_key) return;
            }
            if (self.dirty_count >= capacity) native_util.impossibleByInvariant("indexed arena dirty id capacity covers slot capacity");
            self.dirty_ids[self.dirty_count] = key;
            self.dirty_count += 1;
        }

        pub fn dirtyIds(self: *const Self) []const Key {
            return self.dirty_ids[0..self.dirty_count];
        }

        pub fn clearDirty(self: *Self) void {
            @memset(self.dirty_ids[0..], ids.zero(Key));
            self.dirty_count = 0;
        }

        fn findIndex(self: *const Self, key: Key) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key)) |slot_index| {
                if (slot_index >= capacity) native_util.impossibleByInvariant("indexed arena primary index points outside slots");
                const slot = &self.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("indexed arena primary index points at a free slot");
                if (ids.raw(self.slot_keys[slot_index]) != raw_key) native_util.impossibleByInvariant("indexed arena primary index points at the wrong key");
                const payload_key = keyOf(slot);
                const raw_payload_key = ids.raw(payload_key);
                if (raw_payload_key != 0 and raw_payload_key != raw_key) native_util.impossibleByInvariant("indexed arena slot payload key diverged from its primary index");
                return slot_index;
            }
            if (debugScanFallbackEnabled() and self.scanForKey(key) != null) {
                native_util.impossibleByInvariant("indexed arena primary index missed a live slot");
            }
            return null;
        }

        fn scanForKey(self: *const Self, key: Key) ?usize {
            const raw_key = ids.raw(key);
            for (self.slots, 0..) |slot, slot_index| {
                if (slot.in_use and ids.raw(keyOf(&slot)) == raw_key) return slot_index;
            }
            return null;
        }

        fn popFreeIndex(self: *Self) ?usize {
            if (self.free_head) |slot_index| {
                if (slot_index >= capacity) return null;
                self.free_head = self.free_next[slot_index];
                self.free_next[slot_index] = null;
                return slot_index;
            }

            if (self.next_unclaimed_index >= capacity) return null;
            const slot_index = self.next_unclaimed_index;
            self.next_unclaimed_index += 1;
            return slot_index;
        }

        fn pushFreeIndex(self: *Self, slot_index: usize) void {
            self.free_next[slot_index] = self.free_head;
            self.free_head = slot_index;
        }

        fn claimFreeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or self.slots[slot_index].in_use) return false;

            if (slot_index >= self.next_unclaimed_index) {
                while (self.next_unclaimed_index < slot_index) : (self.next_unclaimed_index += 1) {
                    self.pushFreeIndex(self.next_unclaimed_index);
                }
                self.next_unclaimed_index = slot_index + 1;
                return true;
            }

            return self.unlinkFreeIndex(slot_index);
        }

        fn unlinkFreeIndex(self: *Self, slot_index: usize) bool {
            var previous: ?usize = null;
            var current = self.free_head;
            while (current) |current_index| {
                if (current_index >= capacity) return false;
                const next = self.free_next[current_index];
                if (current_index == slot_index) {
                    if (previous) |previous_index| {
                        self.free_next[previous_index] = next;
                    } else {
                        self.free_head = next;
                    }
                    self.free_next[current_index] = null;
                    return true;
                }
                previous = current_index;
                current = next;
            }
            return false;
        }
    };
}

pub fn GenerationalHandle(comptime display_name: []const u8) type {
    return extern struct {
        const Self = @This();
        pub const zero = Self{ .value = 0 };

        value: u64 = 0,

        pub fn fromParts(slot_index: usize, generation_value: u32) Self {
            if (generation_value == 0) return .{};
            return .{ .value = (@as(u64, generation_value) << 32) | @as(u64, @intCast(slot_index)) };
        }

        pub fn slotIndex(self: Self) usize {
            return @intCast(self.value & 0xffff_ffff);
        }

        pub fn generation(self: Self) u32 {
            return @intCast(self.value >> 32);
        }

        pub fn isZero(self: Self) bool {
            return self.value == 0;
        }

        pub fn eql(self: Self, other: Self) bool {
            return self.value == other.value;
        }

        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print("{s}({d}:{d})", .{ display_name, self.slotIndex(), self.generation() });
        }
    };
}

pub fn PagedIndexedArena(
    comptime Slot: type,
    comptime page_size: usize,
    comptime page_count: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    return PagedIndexedArenaWithKey(u64, Slot, page_size, page_count, index_capacity, keyOf);
}

pub fn PagedIndexedArenaWithKey(
    comptime Key: type,
    comptime Slot: type,
    comptime page_size: usize,
    comptime page_count: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    if (page_size == 0) @compileError("paged indexed arena requires at least one slot per page");
    if (page_count == 0) @compileError("paged indexed arena requires at least one page");
    const capacity = page_size * page_count;
    if (index_capacity < capacity) @compileError("paged indexed arena primary index capacity must cover all slab slots");

    return struct {
        const Self = @This();
        pub const Handle = GenerationalHandle("PagedArenaHandle");
        pub const slot_capacity = capacity;
        pub const slots_per_page = page_size;
        pub const slab_page_count = page_count;

        const Page = struct {
            slots: [page_size]Slot = [_]Slot{Slot{}} ** page_size,
        };

        pages: [page_count]Page = [_]Page{Page{}} ** page_count,
        primary_index: UniqueIndex(index_capacity) = UniqueIndex(index_capacity).init(),
        slot_keys: [capacity]Key = [_]Key{ids.zero(Key)} ** capacity,
        slot_generations: [capacity]u32 = [_]u32{0} ** capacity,
        free_next: [capacity]?usize = [_]?usize{null} ** capacity,
        free_head: ?usize = null,
        next_unclaimed_index: usize = 0,
        used_count: usize = 0,
        dirty_count: usize = 0,
        dirty_ids: [capacity]Key = [_]Key{ids.zero(Key)} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            var slot_index: usize = 0;
            while (slot_index < capacity) : (slot_index += 1) {
                self.slotAt(slot_index).* = Slot{};
                self.slot_keys[slot_index] = ids.zero(Key);
                self.slot_generations[slot_index] = 0;
                self.free_next[slot_index] = null;
                self.dirty_ids[slot_index] = ids.zero(Key);
            }
            self.primary_index.reset();
            self.free_head = null;
            self.next_unclaimed_index = 0;
            self.used_count = 0;
            self.dirty_count = 0;
        }

        pub fn reserve(self: *Self, key: Key) ?*Slot {
            const slot_index = self.reserveIndex(key) orelse return null;
            return self.slotAt(slot_index);
        }

        pub fn reserveIndex(self: *Self, key: Key) ?usize {
            return self.reserveIndexInternal(key, null);
        }

        pub fn reserveAtIndex(self: *Self, key: Key, slot_index: usize) ?*Slot {
            const claimed_index = self.reserveIndexAt(key, slot_index) orelse return null;
            return self.slotAt(claimed_index);
        }

        pub fn reserveIndexAt(self: *Self, key: Key, slot_index: usize) ?usize {
            return self.reserveIndexInternal(key, slot_index);
        }

        pub fn reserveHandle(self: *Self, key: Key) ?Handle {
            const slot_index = self.reserveIndex(key) orelse return null;
            return self.handleForIndex(slot_index);
        }

        pub fn get(self: *Self, key: Key) ?*Slot {
            const slot_index = self.findIndex(key) orelse return null;
            return self.slotAt(slot_index);
        }

        pub fn getConst(self: *const Self, key: Key) ?*const Slot {
            const slot_index = self.findIndex(key) orelse return null;
            return self.slotAtConst(slot_index);
        }

        pub fn getByHandle(self: *Self, handle: Handle) ?*Slot {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return null;
            return self.slotAt(slot_index);
        }

        pub fn getConstByHandle(self: *const Self, handle: Handle) ?*const Slot {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return null;
            return self.slotAtConst(slot_index);
        }

        pub fn slotIndexOf(self: *const Self, key: Key) ?usize {
            return self.findIndex(key);
        }

        pub fn handleForIndex(self: *const Self, slot_index: usize) ?Handle {
            if (slot_index >= capacity) return null;
            const slot = self.slotAtConst(slot_index);
            if (!slot.in_use) return null;
            return Handle.fromParts(slot_index, self.slot_generations[slot_index]);
        }

        pub fn slotAt(self: *Self, slot_index: usize) *Slot {
            if (slot_index >= capacity) native_util.impossibleByInvariant("paged indexed arena slot index points outside slabs");
            return &self.pages[slot_index / page_size].slots[slot_index % page_size];
        }

        pub fn slotAtConst(self: *const Self, slot_index: usize) *const Slot {
            if (slot_index >= capacity) native_util.impossibleByInvariant("paged indexed arena slot index points outside slabs");
            return &self.pages[slot_index / page_size].slots[slot_index % page_size];
        }

        pub fn remove(self: *Self, key: Key) bool {
            const slot_index = self.findIndex(key) orelse return false;
            return self.removeIndex(slot_index);
        }

        pub fn removeHandle(self: *Self, handle: Handle) bool {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return false;
            return self.removeIndex(slot_index);
        }

        pub fn removeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity) return false;
            const slot = self.slotAt(slot_index);
            if (!slot.in_use) return false;

            const key = self.slot_keys[slot_index];
            const raw_key = ids.raw(key);
            if (raw_key != 0) {
                self.primary_index.remove(raw_key);
                self.markDirty(key);
            }
            slot.* = Slot{};
            self.slot_keys[slot_index] = ids.zero(Key);
            self.slot_generations[slot_index] +%= 1;
            if (self.slot_generations[slot_index] == 0) self.slot_generations[slot_index] = 1;
            self.used_count -= 1;
            self.pushFreeIndex(slot_index);
            return true;
        }

        pub fn rebuildPrimaryIndex(self: *Self) void {
            self.primary_index.reset();
            self.slot_keys = [_]Key{ids.zero(Key)} ** capacity;
            self.free_next = [_]?usize{null} ** capacity;
            self.free_head = null;
            self.next_unclaimed_index = capacity;
            self.used_count = 0;

            var slot_index: usize = 0;
            while (slot_index < capacity) : (slot_index += 1) {
                const slot = self.slotAt(slot_index);
                if (slot.in_use) {
                    const key = keyOf(slot);
                    const raw_key = ids.raw(key);
                    if (raw_key != 0) {
                        self.slot_keys[slot_index] = key;
                        self.primary_index.insert(raw_key, slot_index);
                    }
                    if (self.slot_generations[slot_index] == 0) self.slot_generations[slot_index] = 1;
                    self.used_count += 1;
                }
            }

            slot_index = capacity;
            while (slot_index > 0) {
                slot_index -= 1;
                if (!self.slotAtConst(slot_index).in_use) self.pushFreeIndex(slot_index);
            }
        }

        pub fn countInUse(self: *const Self) usize {
            return self.used_count;
        }

        pub fn markDirty(self: *Self, key: Key) void {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return;
            for (self.dirty_ids[0..self.dirty_count]) |existing| {
                if (ids.raw(existing) == raw_key) return;
            }
            if (self.dirty_count >= capacity) native_util.impossibleByInvariant("paged indexed arena dirty id capacity covers slot capacity");
            self.dirty_ids[self.dirty_count] = key;
            self.dirty_count += 1;
        }

        pub fn dirtyIds(self: *const Self) []const Key {
            return self.dirty_ids[0..self.dirty_count];
        }

        pub fn clearDirty(self: *Self) void {
            @memset(self.dirty_ids[0..], ids.zero(Key));
            self.dirty_count = 0;
        }

        fn reserveIndexInternal(self: *Self, key: Key, requested_slot_index: ?usize) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;

            const slot_index = if (requested_slot_index) |explicit_index| blk: {
                if (explicit_index >= capacity or self.slotAtConst(explicit_index).in_use) return null;
                if (!self.claimFreeIndex(explicit_index)) return null;
                break :blk explicit_index;
            } else self.popFreeIndex() orelse return null;

            const slot = self.slotAt(slot_index);
            slot.* = Slot{};
            slot.in_use = true;
            if (self.slot_generations[slot_index] == 0) self.slot_generations[slot_index] = 1;
            self.slot_keys[slot_index] = key;
            self.primary_index.insert(raw_key, slot_index);
            self.used_count += 1;
            self.markDirty(key);
            return slot_index;
        }

        fn findIndex(self: *const Self, key: Key) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key)) |slot_index| {
                if (slot_index >= capacity) native_util.impossibleByInvariant("paged indexed arena primary index points outside slabs");
                const slot = self.slotAtConst(slot_index);
                if (!slot.in_use) native_util.impossibleByInvariant("paged indexed arena primary index points at a free slot");
                if (ids.raw(self.slot_keys[slot_index]) != raw_key) native_util.impossibleByInvariant("paged indexed arena primary index points at the wrong key");
                const payload_key = keyOf(slot);
                const raw_payload_key = ids.raw(payload_key);
                if (raw_payload_key != 0 and raw_payload_key != raw_key) native_util.impossibleByInvariant("paged indexed arena slot payload key diverged from its primary index");
                return slot_index;
            }
            if (debugScanFallbackEnabled() and self.scanForKey(key) != null) {
                native_util.impossibleByInvariant("paged indexed arena primary index missed a live slot");
            }
            return null;
        }

        fn scanForKey(self: *const Self, key: Key) ?usize {
            const raw_key = ids.raw(key);
            var slot_index: usize = 0;
            while (slot_index < capacity) : (slot_index += 1) {
                const slot = self.slotAtConst(slot_index);
                if (slot.in_use and ids.raw(keyOf(slot)) == raw_key) return slot_index;
            }
            return null;
        }

        fn handleMatches(self: *const Self, slot_index: usize, handle: Handle) bool {
            if (handle.isZero() or slot_index >= capacity) return false;
            const slot = self.slotAtConst(slot_index);
            return slot.in_use and self.slot_generations[slot_index] == handle.generation();
        }

        fn popFreeIndex(self: *Self) ?usize {
            if (self.free_head) |slot_index| {
                if (slot_index >= capacity) return null;
                self.free_head = self.free_next[slot_index];
                self.free_next[slot_index] = null;
                return slot_index;
            }

            if (self.next_unclaimed_index >= capacity) return null;
            const slot_index = self.next_unclaimed_index;
            self.next_unclaimed_index += 1;
            return slot_index;
        }

        fn pushFreeIndex(self: *Self, slot_index: usize) void {
            self.free_next[slot_index] = self.free_head;
            self.free_head = slot_index;
        }

        fn claimFreeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or self.slotAtConst(slot_index).in_use) return false;

            if (slot_index >= self.next_unclaimed_index) {
                while (self.next_unclaimed_index < slot_index) : (self.next_unclaimed_index += 1) {
                    self.pushFreeIndex(self.next_unclaimed_index);
                }
                self.next_unclaimed_index = slot_index + 1;
                return true;
            }

            return self.unlinkFreeIndex(slot_index);
        }

        fn unlinkFreeIndex(self: *Self, slot_index: usize) bool {
            var previous: ?usize = null;
            var current = self.free_head;
            while (current) |current_index| {
                if (current_index >= capacity) return false;
                const next = self.free_next[current_index];
                if (current_index == slot_index) {
                    if (previous) |previous_index| {
                        self.free_next[previous_index] = next;
                    } else {
                        self.free_head = next;
                    }
                    self.free_next[current_index] = null;
                    return true;
                }
                previous = current_index;
                current = next;
            }
            return false;
        }
    };
}

fn debugScanFallbackEnabled() bool {
    return builtin.mode == .Debug;
}

const TestRecord = struct {
    id: u64 = 0,
    owner: u64 = 0,
    label: []const u8 = "",
};

const TestSlot = struct {
    in_use: bool = false,
    record: TestRecord = .{},
};

fn testSlotId(slot: *const TestSlot) u64 {
    return slot.record.id;
}

fn testSlotOwner(slot: *const TestSlot) u64 {
    return slot.record.owner;
}

fn testSlotMatchesOwner(owner: u64, slot: *const TestSlot) bool {
    return slot.record.owner == owner;
}

fn testIndexExcluded(excluded_index: usize, slot_index: usize) bool {
    return excluded_index == slot_index;
}

test "indexed arena reserves reuses indexes and tracks dirty ids" {
    const Arena = IndexedArena(TestSlot, 4, 8, testSlotId);
    var arena = Arena.init();

    const first = arena.reserve(41).?;
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.reserve(41));
    first.record = .{ .id = 41, .owner = 7, .label = "first" };
    const second_index = arena.reserveIndex(42).?;
    arena.slots[second_index].record = .{ .id = 42, .owner = 8, .label = "second" };

    try std.testing.expectEqual(@as(usize, 2), arena.countInUse());
    try std.testing.expectEqualStrings("first", arena.get(41).?.record.label);
    try std.testing.expectEqual(@as(u64, 42), arena.getConst(42).?.record.id);
    try std.testing.expectEqual(@as(usize, 2), arena.dirtyIds().len);

    try std.testing.expect(arena.remove(41));
    const pending_index = arena.reserveIndex(44).?;
    try std.testing.expect(arena.removeIndex(pending_index));
    const pending_reused = arena.reserve(44).?;
    pending_reused.record = .{ .id = 44, .owner = 10, .label = "pending-reused" };
    try std.testing.expect(arena.remove(44));
    const reused = arena.reserve(43).?;
    reused.record = .{ .id = 43, .owner = 9, .label = "reused" };

    try std.testing.expectEqualStrings("reused", arena.get(43).?.record.label);
    try std.testing.expectEqual(@as(usize, 2), arena.countInUse());
    arena.clearDirty();
    try std.testing.expectEqual(@as(usize, 0), arena.dirtyIds().len);
}

test "indexed arena reserves explicit free indexes" {
    const Arena = IndexedArena(TestSlot, 4, 8, testSlotId);
    var arena = Arena.init();

    const reserved = arena.reserveAtIndex(41, 2).?;
    reserved.record = .{ .id = 41, .owner = 7, .label = "explicit" };
    try std.testing.expectEqual(@as(usize, 0), arena.availableIndexExcluding(@as(usize, 1), testIndexExcluded).?);
    try std.testing.expectEqualStrings("explicit", arena.get(41).?.record.label);

    _ = arena.reserveAtIndex(42, 0).?;
    try std.testing.expectEqual(@as(usize, 1), arena.availableIndexExcluding(@as(usize, 3), testIndexExcluded).?);
}

test "indexed arena supports secondary indexes" {
    const Arena = IndexedArena(TestSlot, 4, 8, testSlotId);
    const OwnerIndex = UniqueIndex(8);
    var arena = Arena.init();
    var owner_index = OwnerIndex.init();

    const alpha_index = arena.reserveIndex(1).?;
    arena.slots[alpha_index].record = .{ .id = 1, .owner = 91, .label = "alpha" };
    const beta_index = arena.reserveIndex(2).?;
    arena.slots[beta_index].record = .{ .id = 2, .owner = 92, .label = "beta" };
    arena.rebuildUniqueIndex(&owner_index, testSlotOwner);

    try std.testing.expectEqualStrings(
        "beta",
        arena.findByUniqueIndex(&owner_index, 92, @as(u64, 92), testSlotMatchesOwner).?.record.label,
    );
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.findByUniqueIndex(&owner_index, 93, @as(u64, 93), testSlotMatchesOwner));
}

test "indexed arena supports maintained multimap indexes" {
    const OwnerMultimap = MultimapIndex(4, 4, 8);
    var owner_index = OwnerMultimap.init();

    try std.testing.expect(owner_index.append(7, 0));
    try std.testing.expect(owner_index.append(7, 2));
    try std.testing.expect(owner_index.append(8, 1));

    try std.testing.expectEqual(@as(usize, 2), owner_index.count(7));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(8));
    try std.testing.expectEqual(@as(usize, 0), owner_index.head(7));
    try std.testing.expectEqual(@as(usize, 2), owner_index.next(0));
    try std.testing.expectEqual(no_index, owner_index.next(2));

    try std.testing.expect(owner_index.remove(7, 0));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(7));
    try std.testing.expectEqual(@as(usize, 2), owner_index.head(7));
    try std.testing.expect(owner_index.remove(7, 2));
    try std.testing.expectEqual(@as(usize, 0), owner_index.count(7));
}

test "paged indexed arena uses slab pages and invalidates stale handles" {
    const Arena = PagedIndexedArena(TestSlot, 2, 2, 8, testSlotId);
    var arena = Arena.init();

    const first_index = arena.reserveIndex(11).?;
    arena.slotAt(first_index).record = .{ .id = 11, .owner = 1, .label = "first" };
    const first_handle = arena.handleForIndex(first_index).?;

    const second_handle = arena.reserveHandle(12).?;
    arena.getByHandle(second_handle).?.record = .{ .id = 12, .owner = 2, .label = "second" };

    try std.testing.expectEqual(@as(usize, 2), arena.countInUse());
    try std.testing.expectEqualStrings("first", arena.get(11).?.record.label);
    try std.testing.expectEqualStrings("second", arena.getConstByHandle(second_handle).?.record.label);

    try std.testing.expect(arena.removeHandle(first_handle));
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.getByHandle(first_handle));

    const reused_index = arena.reserveIndex(13).?;
    arena.slotAt(reused_index).record = .{ .id = 13, .owner = 3, .label = "reused" };
    try std.testing.expectEqual(first_index, reused_index);
    try std.testing.expect(!arena.handleForIndex(reused_index).?.eql(first_handle));
    try std.testing.expectEqualStrings("reused", arena.get(13).?.record.label);
}
