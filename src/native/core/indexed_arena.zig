const builtin = @import("builtin");
const std = @import("std");
const id_index = @import("id_index.zig");
const ids = @import("ids.zig");
const native_util = @import("util.zig");

pub const no_index = std.math.maxInt(usize);

pub fn ReusableIndex(comptime capacity: usize) type {
    if (capacity == 0) @compileError("reusable indexes require at least one slot");
    if (capacity <= std.math.maxInt(u8)) return u8;
    if (capacity <= std.math.maxInt(u16)) return u16;
    if (@bitSizeOf(usize) > 32 and capacity <= 4_294_967_295) return u32;
    return usize;
}

pub fn reusableNoIndex(comptime capacity: usize) ReusableIndex(capacity) {
    return @intCast(capacity);
}

inline fn publicReusableIndex(comptime capacity: usize, index: ReusableIndex(capacity)) ?usize {
    return if (index == reusableNoIndex(capacity)) null else @intCast(index);
}

pub fn nonZeroKey(key: u64) u64 {
    return if (key == 0) 1 else key;
}

inline fn popReusableIndex(
    comptime capacity: usize,
    claimed_count: usize,
    free_head: *ReusableIndex(capacity),
    free_next: *[capacity]ReusableIndex(capacity),
    next_unclaimed_index: *usize,
) ?usize {
    if (publicReusableIndex(capacity, free_head.*)) |slot_index| {
        if (slot_index >= claimed_count) return null;
        free_head.* = free_next.*[slot_index];
        free_next.*[slot_index] = reusableNoIndex(capacity);
        return slot_index;
    }

    if (claimed_count >= capacity) return null;
    next_unclaimed_index.* += 1;
    return claimed_count;
}

inline fn pushReusableIndex(
    comptime capacity: usize,
    free_head: *ReusableIndex(capacity),
    free_next: *[capacity]ReusableIndex(capacity),
    slot_index: usize,
) void {
    if (slot_index >= capacity) native_util.impossibleByInvariant("reusable index fits its arena capacity");
    free_next.*[slot_index] = free_head.*;
    free_head.* = @intCast(slot_index);
}

inline fn unlinkReusableIndex(
    comptime capacity: usize,
    claimed_count: usize,
    free_head: *ReusableIndex(capacity),
    free_next: *[capacity]ReusableIndex(capacity),
    slot_index: usize,
) bool {
    if (slot_index >= claimed_count) return false;
    var previous: ?usize = null;
    var current = publicReusableIndex(capacity, free_head.*);
    while (current) |current_index| {
        if (current_index >= claimed_count) return false;
        const next = free_next.*[current_index];
        if (current_index == slot_index) {
            if (previous) |previous_index| {
                free_next.*[previous_index] = next;
            } else {
                free_head.* = next;
            }
            free_next.*[current_index] = reusableNoIndex(capacity);
            return true;
        }
        previous = current_index;
        current = publicReusableIndex(capacity, next);
    }
    return false;
}

inline fn claimReusableIndex(
    comptime capacity: usize,
    claimed_count: usize,
    free_head: *ReusableIndex(capacity),
    free_next: *[capacity]ReusableIndex(capacity),
    next_unclaimed_index: *usize,
    slot_index: usize,
) bool {
    if (slot_index >= claimed_count) {
        while (next_unclaimed_index.* < slot_index) : (next_unclaimed_index.* += 1) {
            pushReusableIndex(capacity, free_head, free_next, next_unclaimed_index.*);
        }
        next_unclaimed_index.* = slot_index + 1;
        return true;
    }

    return unlinkReusableIndex(capacity, claimed_count, free_head, free_next, slot_index);
}

pub fn UniqueIndex(comptime capacity: usize) type {
    if (capacity == 0) @compileError("unique index requires at least one slot");

    return struct {
        const Self = @This();

        table: id_index.Table(capacity) = id_index.emptyTable(capacity),

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.table = id_index.emptyTable(capacity);
        }

        pub fn lookup(self: *const Self, key: u64) ?usize {
            return id_index.lookup(capacity, &self.table, key);
        }

        pub fn contains(self: *const Self, key: u64) bool {
            return self.lookup(key) != null;
        }

        pub fn insert(self: *Self, key: u64, slot_index: usize) void {
            id_index.insert(capacity, &self.table, key, slot_index, "indexed arena unique indexes never store zero keys");
        }

        pub fn insertAbsent(self: *Self, key: u64, slot_index: usize) void {
            id_index.insertAbsent(capacity, &self.table, key, slot_index, "indexed arena unique indexes never store zero keys");
        }

        pub fn remove(self: *Self, key: u64) void {
            id_index.remove(capacity, &self.table, key);
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
        const compact_capacity = @max(link_capacity, bucket_capacity);
        const CompactIndex = ReusableIndex(compact_capacity);
        const compact_no_index = reusableNoIndex(compact_capacity);

        const Bucket = struct {
            key: u64 = 0,
            head: CompactIndex = compact_no_index,
            tail: CompactIndex = compact_no_index,
            count: CompactIndex = 0,
            in_use: bool = false,
        };

        const Link = struct {
            next: CompactIndex = compact_no_index,
            previous: CompactIndex = compact_no_index,
            bucket: CompactIndex = compact_no_index,
        };

        bucket_index: BucketIndex = BucketIndex.init(),
        buckets: [bucket_capacity]Bucket = [_]Bucket{Bucket{}} ** bucket_capacity,
        links: [link_capacity]Link = [_]Link{Link{}} ** link_capacity,
        free_bucket_head: CompactIndex = compact_no_index,
        next_unclaimed_bucket: CompactIndex = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn count(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return 0;
            return @intCast(entry.count);
        }

        pub fn head(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return no_index;
            return publicIndex(entry.head);
        }

        pub fn tail(self: *const Self, key: u64) usize {
            const entry = self.bucketConst(key) orelse return no_index;
            return publicIndex(entry.tail);
        }

        pub fn next(self: *const Self, slot_index: usize) usize {
            if (slot_index >= link_capacity) return no_index;
            return publicIndex(self.links[slot_index].next);
        }

        pub fn previous(self: *const Self, slot_index: usize) usize {
            if (slot_index >= link_capacity) return no_index;
            return publicIndex(self.links[slot_index].previous);
        }

        pub fn append(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            const link = &self.links[slot_index];
            if (link.bucket != compact_no_index) return false;

            const bucket_slot_index = self.findOrCreateBucketIndex(key) orelse return false;
            const entry = &self.buckets[@intCast(bucket_slot_index)];
            const compact_slot_index: CompactIndex = @intCast(slot_index);
            link.* = .{
                .previous = entry.tail,
                .bucket = bucket_slot_index,
            };
            if (entry.tail == compact_no_index) {
                if (entry.head != compact_no_index or entry.count != 0) {
                    native_util.impossibleByInvariant("empty multimap bucket has no links");
                }
                entry.head = compact_slot_index;
            } else {
                const tail_index: usize = @intCast(entry.tail);
                if (tail_index >= link_capacity) native_util.impossibleByInvariant("multimap tail points outside links");
                const tail_link = &self.links[tail_index];
                if (tail_link.bucket != bucket_slot_index or tail_link.next != compact_no_index) {
                    native_util.impossibleByInvariant("multimap tail link belongs to the bucket tail");
                }
                tail_link.next = compact_slot_index;
            }
            entry.tail = compact_slot_index;
            entry.count += 1;
            return true;
        }

        pub fn remove(self: *Self, key: u64, slot_index: usize) bool {
            if (key == 0 or slot_index >= link_capacity) return false;
            const bucket_slot_index = self.bucket_index.lookup(key) orelse return false;
            if (bucket_slot_index >= bucket_capacity) native_util.impossibleByInvariant("multimap bucket index points outside buckets");
            const entry = &self.buckets[bucket_slot_index];
            if (!entry.in_use or entry.key != key) native_util.impossibleByInvariant("multimap bucket index points at the wrong bucket");
            const compact_bucket_slot_index: CompactIndex = @intCast(bucket_slot_index);
            const compact_slot_index: CompactIndex = @intCast(slot_index);
            const link = &self.links[slot_index];
            if (link.bucket != compact_bucket_slot_index) return false;
            if (entry.count == 0) native_util.impossibleByInvariant("live multimap bucket contains at least one link");

            if (link.previous == compact_no_index) {
                if (entry.head != compact_slot_index) native_util.impossibleByInvariant("multimap head link belongs to the bucket head");
                entry.head = link.next;
            } else {
                const previous_index: usize = @intCast(link.previous);
                if (previous_index >= link_capacity) native_util.impossibleByInvariant("multimap previous link points outside links");
                const previous_link = &self.links[previous_index];
                if (previous_link.bucket != compact_bucket_slot_index or previous_link.next != compact_slot_index) {
                    native_util.impossibleByInvariant("multimap previous link points at its successor");
                }
                previous_link.next = link.next;
            }

            if (link.next == compact_no_index) {
                if (entry.tail != compact_slot_index) native_util.impossibleByInvariant("multimap tail link belongs to the bucket tail");
                entry.tail = link.previous;
            } else {
                const next_index: usize = @intCast(link.next);
                if (next_index >= link_capacity) native_util.impossibleByInvariant("multimap next link points outside links");
                const next_link = &self.links[next_index];
                if (next_link.bucket != compact_bucket_slot_index or next_link.previous != compact_slot_index) {
                    native_util.impossibleByInvariant("multimap next link points at its predecessor");
                }
                next_link.previous = link.previous;
            }

            link.* = .{};
            entry.count -= 1;
            if (entry.count == 0) {
                if (entry.head != compact_no_index or entry.tail != compact_no_index) {
                    native_util.impossibleByInvariant("empty multimap bucket has no links");
                }
                const bucket_key = entry.key;
                entry.* = .{};
                self.bucket_index.remove(bucket_key);
                self.pushFreeBucket(compact_bucket_slot_index);
            }
            return true;
        }

        fn bucketConst(self: *const Self, key: u64) ?*const Bucket {
            const bucket_index = self.bucket_index.lookup(key) orelse return null;
            if (bucket_index >= bucket_capacity) native_util.impossibleByInvariant("multimap bucket index points outside buckets");
            const slot = &self.buckets[bucket_index];
            if (!slot.in_use or slot.key != key) native_util.impossibleByInvariant("multimap bucket index points at the wrong bucket");
            return slot;
        }

        fn findOrCreateBucketIndex(self: *Self, key: u64) ?CompactIndex {
            if (self.bucket_index.lookup(key)) |bucket_slot_index| {
                if (bucket_slot_index >= bucket_capacity) native_util.impossibleByInvariant("multimap bucket index points outside buckets");
                const slot = &self.buckets[bucket_slot_index];
                if (!slot.in_use or slot.key != key) native_util.impossibleByInvariant("multimap bucket index points at the wrong bucket");
                return @intCast(bucket_slot_index);
            }
            const bucket_slot_index = self.popFreeBucket() orelse return null;
            const slot = &self.buckets[@intCast(bucket_slot_index)];
            slot.* = .{
                .key = key,
                .in_use = true,
            };
            self.bucket_index.insertAbsent(key, @intCast(bucket_slot_index));
            return bucket_slot_index;
        }

        fn popFreeBucket(self: *Self) ?CompactIndex {
            if (self.free_bucket_head != compact_no_index) {
                const bucket_slot_index = self.free_bucket_head;
                const bucket_index: usize = @intCast(bucket_slot_index);
                if (bucket_index >= bucket_capacity) native_util.impossibleByInvariant("multimap free bucket index points outside buckets");
                const free_bucket = &self.buckets[bucket_index];
                if (free_bucket.in_use) native_util.impossibleByInvariant("multimap free bucket list points at a live bucket");
                self.free_bucket_head = free_bucket.head;
                free_bucket.head = compact_no_index;
                return bucket_slot_index;
            }

            if (@as(usize, @intCast(self.next_unclaimed_bucket)) >= bucket_capacity) return null;
            const bucket_slot_index = self.next_unclaimed_bucket;
            self.next_unclaimed_bucket += 1;
            return bucket_slot_index;
        }

        fn pushFreeBucket(self: *Self, bucket_slot_index: CompactIndex) void {
            const bucket_index: usize = @intCast(bucket_slot_index);
            if (bucket_index >= bucket_capacity) native_util.impossibleByInvariant("multimap recycled bucket index points outside buckets");
            const free_bucket = &self.buckets[bucket_index];
            if (free_bucket.in_use) native_util.impossibleByInvariant("multimap cannot recycle a live bucket");
            free_bucket.head = self.free_bucket_head;
            self.free_bucket_head = bucket_slot_index;
        }

        inline fn publicIndex(index: CompactIndex) usize {
            return if (index == compact_no_index) no_index else @intCast(index);
        }
    };
}

pub const Options = struct {
    track_dirty: bool = false,
};

pub fn IndexedArena(
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    return IndexedArenaWithKeyOptions(u64, Slot, capacity, index_capacity, keyOf, .{});
}

pub fn IndexedArenaWithKey(
    comptime Key: type,
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    return IndexedArenaWithKeyOptions(Key, Slot, capacity, index_capacity, keyOf, .{});
}

pub fn DirtyTrackedIndexedArenaWithKey(
    comptime Key: type,
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
) type {
    return IndexedArenaWithKeyOptions(Key, Slot, capacity, index_capacity, keyOf, .{ .track_dirty = true });
}

pub fn IndexedArenaWithKeyOptions(
    comptime Key: type,
    comptime Slot: type,
    comptime capacity: usize,
    comptime index_capacity: usize,
    comptime keyOf: anytype,
    comptime options: Options,
) type {
    if (capacity == 0) @compileError("indexed arena requires at least one slot");
    if (index_capacity < capacity) @compileError("indexed arena primary index capacity must cover slots");
    const dirty_capacity = if (options.track_dirty) capacity else 0;
    const DirtyIdIndex = if (options.track_dirty) UniqueIndex(index_capacity) else struct {};

    return struct {
        const Self = @This();
        const FreeIndex = ReusableIndex(capacity);
        const free_no_index = reusableNoIndex(capacity);

        slots: [capacity]Slot = [_]Slot{Slot{}} ** capacity,
        primary_index: UniqueIndex(index_capacity) = UniqueIndex(index_capacity).init(),
        slot_keys: [capacity]Key = [_]Key{ids.zero(Key)} ** capacity,
        free_next: [capacity]FreeIndex = [_]FreeIndex{free_no_index} ** capacity,
        free_head: FreeIndex = free_no_index,
        next_unclaimed_index: usize = 0,
        used_count: usize = 0,
        dirty_count: usize = 0,
        dirty_ids: [dirty_capacity]Key = [_]Key{ids.zero(Key)} ** dirty_capacity,
        dirty_id_index: DirtyIdIndex = .{},

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = Self.init();
        }

        pub fn resetRetainingPayloads(self: *Self) void {
            const claimed_count = self.claimedCount();
            const dirty_count = self.dirty_count;
            if (dirty_count > dirty_capacity) {
                native_util.impossibleByInvariant("indexed arena dirty count fits its storage");
            }
            for (self.slots[0..claimed_count]) |*slot| {
                slot.in_use = false;
            }
            self.primary_index.reset();
            @memset(self.slot_keys[0..claimed_count], ids.zero(Key));
            @memset(self.free_next[0..claimed_count], free_no_index);
            self.free_head = free_no_index;
            self.next_unclaimed_index = 0;
            self.used_count = 0;
            self.dirty_count = 0;
            @memset(self.dirty_ids[0..dirty_count], ids.zero(Key));
            if (comptime options.track_dirty) self.dirty_id_index.reset();
        }

        pub fn reserve(self: *Self, key: Key) ?*Slot {
            const slot_index = self.reserveIndex(key) orelse return null;
            return &self.slots[slot_index];
        }

        pub fn reserveClean(self: *Self, key: Key) ?*Slot {
            const slot_index = self.reserveIndexClean(key) orelse return null;
            return &self.slots[slot_index];
        }

        pub fn reserveIndex(self: *Self, key: Key) ?usize {
            return self.reserveIndexWithDirty(key, true);
        }

        pub fn insertIndex(self: *Self, key: Key, value: Slot) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;

            const slot_index = self.popFreeIndex() orelse return null;
            self.slots[slot_index] = value;
            self.claimSlotMetadata(key, raw_key, slot_index, true);
            return slot_index;
        }

        pub fn reserveIndexClean(self: *Self, key: Key) ?usize {
            if (!options.track_dirty) @compileError("clean reservation is only available on dirty-tracked arenas");
            return self.reserveIndexWithDirty(key, false);
        }

        fn reserveIndexWithDirty(self: *Self, key: Key, mark_dirty: bool) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;

            const slot_index = self.popFreeIndex() orelse return null;
            self.claimSlot(key, raw_key, slot_index, mark_dirty);
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

            self.claimSlot(key, raw_key, slot_index, true);
            return slot_index;
        }

        pub fn insertIndexAt(self: *Self, key: Key, slot_index: usize, value: Slot) ?usize {
            const raw_key = ids.raw(key);
            if (raw_key == 0 or slot_index >= capacity) return null;
            if (self.primary_index.lookup(raw_key) != null) return null;
            if (self.slots[slot_index].in_use) return null;
            if (!self.claimFreeIndex(slot_index)) return null;

            self.slots[slot_index] = value;
            self.claimSlotMetadata(key, raw_key, slot_index, true);
            return slot_index;
        }

        fn claimSlot(self: *Self, key: Key, raw_key: u64, slot_index: usize, mark_dirty: bool) void {
            self.slots[slot_index] = Slot{};
            self.claimSlotMetadata(key, raw_key, slot_index, mark_dirty);
        }

        fn claimSlotMetadata(self: *Self, key: Key, raw_key: u64, slot_index: usize, mark_dirty: bool) void {
            self.slots[slot_index].in_use = true;
            self.slot_keys[slot_index] = key;
            self.primary_index.insertAbsent(raw_key, slot_index);
            self.used_count += 1;
            if (mark_dirty) self.noteDirty(key);
        }

        pub fn availableIndexExcluding(
            self: *const Self,
            context: anytype,
            comptime excludes: anytype,
        ) ?usize {
            const claimed_count = self.claimedCount();
            var next_index = publicReusableIndex(capacity, self.free_head);
            var attempts: usize = 0;
            while (next_index) |slot_index| : (attempts += 1) {
                if (slot_index >= claimed_count or attempts >= claimed_count) return null;
                next_index = publicReusableIndex(capacity, self.free_next[slot_index]);
                if (excludes(context, slot_index)) continue;
                return slot_index;
            }

            var slot_index = claimed_count;
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
                self.noteDirty(key);
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
            self.free_next = [_]FreeIndex{free_no_index} ** capacity;
            self.free_head = free_no_index;
            self.next_unclaimed_index = capacity;
            self.used_count = 0;

            for (&self.slots, 0..) |*slot, slot_index| {
                if (slot.in_use) {
                    const key = keyOf(slot);
                    const raw_key = ids.raw(key);
                    if (raw_key != 0) {
                        self.slot_keys[slot_index] = key;
                        self.primary_index.insertAbsent(raw_key, slot_index);
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

        fn findMatching(self: *Self, context: anytype, comptime matches: anytype) ?*Slot {
            for (self.slots[0..self.claimedCount()]) |*slot| {
                if (!slot.in_use) continue;
                if (matches(context, slot)) return slot;
            }
            return null;
        }

        fn findConstMatching(self: *const Self, context: anytype, comptime matches: anytype) ?*const Slot {
            for (self.slots[0..self.claimedCount()]) |*slot| {
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
            if (!options.track_dirty) @compileError("this arena does not track dirty ids; instantiate it with DirtyTrackedIndexedArenaWithKey");
            const raw_key = ids.raw(key);
            if (raw_key == 0) return;
            if (self.dirty_id_index.contains(raw_key)) return;
            if (self.dirty_count >= dirty_capacity) native_util.impossibleByInvariant("indexed arena dirty id capacity covers slot capacity");
            self.dirty_ids[self.dirty_count] = key;
            self.dirty_id_index.insertAbsent(raw_key, self.dirty_count);
            self.dirty_count += 1;
        }

        pub fn dirtyIds(self: *const Self) []const Key {
            if (!options.track_dirty) @compileError("this arena does not track dirty ids; instantiate it with DirtyTrackedIndexedArenaWithKey");
            return self.dirty_ids[0..self.dirty_count];
        }

        pub fn clearDirty(self: *Self) void {
            if (!options.track_dirty) @compileError("this arena does not track dirty ids; instantiate it with DirtyTrackedIndexedArenaWithKey");
            @memset(self.dirty_ids[0..self.dirty_count], ids.zero(Key));
            self.dirty_count = 0;
            self.dirty_id_index.reset();
        }

        fn noteDirty(self: *Self, key: Key) void {
            if (comptime !options.track_dirty) return;
            self.markDirty(key);
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
            for (self.slots[0..self.claimedCount()], 0..) |slot, slot_index| {
                if (slot.in_use and ids.raw(keyOf(&slot)) == raw_key) return slot_index;
            }
            return null;
        }

        pub inline fn claimedCount(self: *const Self) usize {
            if (self.next_unclaimed_index > capacity) {
                native_util.impossibleByInvariant("indexed arena claimed prefix fits its slots");
            }
            return self.next_unclaimed_index;
        }

        inline fn popFreeIndex(self: *Self) ?usize {
            return popReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index);
        }

        inline fn pushFreeIndex(self: *Self, slot_index: usize) void {
            pushReusableIndex(capacity, &self.free_head, &self.free_next, slot_index);
        }

        inline fn claimFreeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or self.slots[slot_index].in_use) return false;
            return claimReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index, slot_index);
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

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{s}({d}:{d})", .{ display_name, self.slotIndex(), self.generation() });
        }
    };
}

pub fn GenerationalArena(
    comptime display_name: []const u8,
    comptime Slot: type,
    comptime capacity: usize,
) type {
    if (capacity == 0) @compileError("generational arena requires at least one slot");
    if (capacity > @as(usize, std.math.maxInt(u32)) + 1) {
        @compileError("generational arena slot indexes must fit in a handle");
    }

    return struct {
        const Self = @This();
        const FreeIndex = ReusableIndex(capacity);
        const free_no_index = reusableNoIndex(capacity);
        pub const Handle = GenerationalHandle(display_name);
        pub const slot_capacity = capacity;

        slots: [capacity]Slot = [_]Slot{Slot{}} ** capacity,
        slot_generations: [capacity]u32 = [_]u32{0} ** capacity,
        free_next: [capacity]FreeIndex = [_]FreeIndex{free_no_index} ** capacity,
        free_head: FreeIndex = free_no_index,
        next_unclaimed_index: usize = 0,
        used_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            const claimed_count = self.claimedCount();
            var slot_index: usize = 0;
            while (slot_index < claimed_count) : (slot_index += 1) {
                self.slots[slot_index] = Slot{};
                self.slot_generations[slot_index] = nextSlotGeneration(self.slot_generations[slot_index]);
                self.free_next[slot_index] = free_no_index;
            }
            self.free_head = free_no_index;
            self.next_unclaimed_index = 0;
            self.used_count = 0;
        }

        pub fn reserve(self: *Self) ?*Slot {
            const slot_index = self.reserveIndex() orelse return null;
            return &self.slots[slot_index];
        }

        pub fn reserveHandle(self: *Self) ?Handle {
            const slot_index = self.reserveIndex() orelse return null;
            return self.handleForIndex(slot_index);
        }

        pub fn reserveIndex(self: *Self) ?usize {
            const slot_index = self.popFreeIndex() orelse return null;
            self.claimSlot(slot_index);
            return slot_index;
        }

        pub fn reserveHandleAt(self: *Self, slot_index: usize) ?Handle {
            const reserved_index = self.reserveIndexAt(slot_index) orelse return null;
            return self.handleForIndex(reserved_index);
        }

        pub fn reserveIndexAt(self: *Self, slot_index: usize) ?usize {
            if (slot_index >= capacity or self.slots[slot_index].in_use) return null;
            if (!self.claimFreeIndex(slot_index)) return null;
            self.claimSlot(slot_index);
            return slot_index;
        }

        pub fn availableIndexExcluding(
            self: *const Self,
            context: anytype,
            comptime excludes: anytype,
        ) ?usize {
            const claimed_count = self.claimedCount();
            var next_index = publicReusableIndex(capacity, self.free_head);
            var attempts: usize = 0;
            while (next_index) |slot_index| : (attempts += 1) {
                if (slot_index >= claimed_count or attempts >= claimed_count) return null;
                next_index = publicReusableIndex(capacity, self.free_next[slot_index]);
                if (excludes(context, slot_index)) continue;
                return slot_index;
            }

            var slot_index = claimed_count;
            while (slot_index < capacity) : (slot_index += 1) {
                if (excludes(context, slot_index)) continue;
                return slot_index;
            }
            return null;
        }

        pub fn getByHandle(self: *Self, handle: Handle) ?*Slot {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return null;
            return &self.slots[slot_index];
        }

        pub fn getConstByHandle(self: *const Self, handle: Handle) ?*const Slot {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return null;
            return &self.slots[slot_index];
        }

        pub fn handleForIndex(self: *const Self, slot_index: usize) ?Handle {
            if (slot_index >= capacity or !self.slots[slot_index].in_use) return null;
            return Handle.fromParts(slot_index, self.slot_generations[slot_index]);
        }

        pub fn removeHandle(self: *Self, handle: Handle) bool {
            const slot_index = handle.slotIndex();
            if (!self.handleMatches(slot_index, handle)) return false;
            return self.removeIndex(slot_index);
        }

        pub fn removeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or !self.slots[slot_index].in_use) return false;
            self.slots[slot_index] = Slot{};
            self.slot_generations[slot_index] = nextSlotGeneration(self.slot_generations[slot_index]);
            self.used_count -= 1;
            self.pushFreeIndex(slot_index);
            return true;
        }

        pub fn countInUse(self: *const Self) usize {
            return self.used_count;
        }

        pub inline fn claimedCount(self: *const Self) usize {
            if (self.next_unclaimed_index > capacity) {
                native_util.impossibleByInvariant("generational arena claimed prefix fits its slots");
            }
            return self.next_unclaimed_index;
        }

        fn claimSlot(self: *Self, slot_index: usize) void {
            self.slots[slot_index] = Slot{};
            self.slots[slot_index].in_use = true;
            if (self.slot_generations[slot_index] == 0) self.slot_generations[slot_index] = 1;
            self.used_count += 1;
        }

        fn handleMatches(self: *const Self, slot_index: usize, handle: Handle) bool {
            if (handle.isZero() or slot_index >= capacity) return false;
            return self.slots[slot_index].in_use and self.slot_generations[slot_index] == handle.generation();
        }

        inline fn popFreeIndex(self: *Self) ?usize {
            return popReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index);
        }

        inline fn pushFreeIndex(self: *Self, slot_index: usize) void {
            pushReusableIndex(capacity, &self.free_head, &self.free_next, slot_index);
        }

        inline fn claimFreeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or self.slots[slot_index].in_use) return false;
            return claimReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index, slot_index);
        }
    };
}

inline fn nextSlotGeneration(current: u32) u32 {
    const next = current +% 1;
    return if (next == 0) 1 else next;
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
        const FreeIndex = ReusableIndex(capacity);
        const free_no_index = reusableNoIndex(capacity);
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
        free_next: [capacity]FreeIndex = [_]FreeIndex{free_no_index} ** capacity,
        free_head: FreeIndex = free_no_index,
        next_unclaimed_index: usize = 0,
        used_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            const claimed_count = self.claimedCount();
            var slot_index: usize = 0;
            while (slot_index < capacity) : (slot_index += 1) {
                self.slotAt(slot_index).* = Slot{};
                self.slot_keys[slot_index] = ids.zero(Key);
                if (slot_index < claimed_count) {
                    self.slot_generations[slot_index] = nextSlotGeneration(self.slot_generations[slot_index]);
                }
                self.free_next[slot_index] = free_no_index;
            }
            self.primary_index.reset();
            self.free_head = free_no_index;
            self.next_unclaimed_index = 0;
            self.used_count = 0;
        }

        pub fn resetRetainingPayloads(self: *Self) void {
            const claimed_count = self.claimedCount();
            var slot_index: usize = 0;
            while (slot_index < claimed_count) : (slot_index += 1) {
                self.slotAt(slot_index).in_use = false;
                self.slot_keys[slot_index] = ids.zero(Key);
                self.slot_generations[slot_index] = nextSlotGeneration(self.slot_generations[slot_index]);
                self.free_next[slot_index] = free_no_index;
            }
            self.primary_index.reset();
            self.free_head = free_no_index;
            self.next_unclaimed_index = 0;
            self.used_count = 0;
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
            }
            slot.* = Slot{};
            self.slot_keys[slot_index] = ids.zero(Key);
            self.slot_generations[slot_index] = nextSlotGeneration(self.slot_generations[slot_index]);
            self.used_count -= 1;
            self.pushFreeIndex(slot_index);
            return true;
        }

        pub fn rebuildPrimaryIndex(self: *Self) void {
            self.primary_index.reset();
            self.slot_keys = [_]Key{ids.zero(Key)} ** capacity;
            self.free_next = [_]FreeIndex{free_no_index} ** capacity;
            self.free_head = free_no_index;
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
                        self.primary_index.insertAbsent(raw_key, slot_index);
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
            self.primary_index.insertAbsent(raw_key, slot_index);
            self.used_count += 1;
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
            const claimed_count = self.claimedCount();
            var slot_index: usize = 0;
            while (slot_index < claimed_count) : (slot_index += 1) {
                const slot = self.slotAtConst(slot_index);
                if (slot.in_use and ids.raw(keyOf(slot)) == raw_key) return slot_index;
            }
            return null;
        }

        pub inline fn claimedCount(self: *const Self) usize {
            if (self.next_unclaimed_index > capacity) {
                native_util.impossibleByInvariant("paged indexed arena claimed prefix fits its slots");
            }
            return self.next_unclaimed_index;
        }

        fn handleMatches(self: *const Self, slot_index: usize, handle: Handle) bool {
            if (handle.isZero() or slot_index >= capacity) return false;
            const slot = self.slotAtConst(slot_index);
            return slot.in_use and self.slot_generations[slot_index] == handle.generation();
        }

        inline fn popFreeIndex(self: *Self) ?usize {
            return popReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index);
        }

        inline fn pushFreeIndex(self: *Self, slot_index: usize) void {
            pushReusableIndex(capacity, &self.free_head, &self.free_next, slot_index);
        }

        inline fn claimFreeIndex(self: *Self, slot_index: usize) bool {
            if (slot_index >= capacity or self.slotAtConst(slot_index).in_use) return false;
            return claimReusableIndex(capacity, self.claimedCount(), &self.free_head, &self.free_next, &self.next_unclaimed_index, slot_index);
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

test "arena free lists select the narrowest lossless reusable index" {
    try std.testing.expect(ReusableIndex(255) == u8);
    try std.testing.expect(ReusableIndex(256) == u16);
    try std.testing.expect(ReusableIndex(65_535) == u16);
    try std.testing.expect(ReusableIndex(65_536) == u32);
    try std.testing.expectEqual(@as(u8, 255), reusableNoIndex(255));
    try std.testing.expectEqual(@as(u16, 256), reusableNoIndex(256));

    const ByteArena = IndexedArena(TestSlot, 4, 8, testSlotId);
    const WordArena = IndexedArena(TestSlot, 256, 512, testSlotId);
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(@FieldType(ByteArena, "free_next")));
    try std.testing.expectEqual(@as(usize, 512), @sizeOf(@FieldType(WordArena, "free_next")));
}

test "arena free lists retain the highest reusable index at width boundaries" {
    {
        const Arena = IndexedArena(TestSlot, 255, 510, testSlotId);
        var arena = Arena.init();
        const highest_index: usize = 254;
        _ = arena.reserveIndexAt(1, highest_index).?;
        try std.testing.expect(arena.removeIndex(highest_index));
        try std.testing.expectEqual(highest_index, arena.reserveIndex(2).?);
    }
    {
        const Arena = IndexedArena(TestSlot, 256, 512, testSlotId);
        var arena = Arena.init();
        const highest_index: usize = 255;
        _ = arena.reserveIndexAt(1, highest_index).?;
        try std.testing.expect(arena.removeIndex(highest_index));
        try std.testing.expectEqual(highest_index, arena.reserveIndex(2).?);
    }
}

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
    const Arena = DirtyTrackedIndexedArenaWithKey(u64, TestSlot, 4, 8, testSlotId);
    var arena = Arena.init();

    const first = arena.reserve(41).?;
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.reserve(41));
    first.record = .{ .id = 41, .owner = 7, .label = "first" };
    const second_index = arena.insertIndex(42, .{
        .record = .{ .id = 42, .owner = 8, .label = "second" },
    }).?;
    try std.testing.expect(arena.slots[second_index].in_use);

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
    try std.testing.expectEqualSlices(u64, &.{ 41, 42, 44, 43 }, arena.dirtyIds());
    try std.testing.expectEqual(@as(?usize, 2), arena.dirty_id_index.lookup(44));
    arena.clearDirty();
    try std.testing.expectEqual(@as(usize, 0), arena.dirtyIds().len);
    try std.testing.expectEqual(@as(?usize, null), arena.dirty_id_index.lookup(44));

    arena.markDirty(44);
    arena.markDirty(44);
    try std.testing.expectEqualSlices(u64, &.{44}, arena.dirtyIds());
    try std.testing.expectEqual(@as(?usize, 0), arena.dirty_id_index.lookup(44));
    arena.clearDirty();

    const restored = arena.reserveClean(45).?;
    restored.record = .{ .id = 45, .owner = 11, .label = "restored" };
    const restored_index = arena.reserveIndexClean(46).?;
    arena.slots[restored_index].record = .{ .id = 46, .owner = 12, .label = "restored-index" };
    try std.testing.expectEqual(@as(usize, 0), arena.dirtyIds().len);
    try std.testing.expectEqualStrings("restored", arena.get(45).?.record.label);
    try std.testing.expectEqualStrings("restored-index", arena.get(46).?.record.label);
}

test "indexed arena reuses tombstoned primary index slots" {
    const Arena = IndexedArena(TestSlot, 2, 2, testSlotId);
    var arena = Arena.init();

    var id: u64 = 1;
    while (id <= 8) : (id += 1) {
        const slot = arena.reserve(id).?;
        slot.record = .{ .id = id, .owner = 7, .label = "cycle" };
        try std.testing.expectEqual(id, arena.get(id).?.record.id);
        try std.testing.expect(arena.remove(id));
    }

    const final_slot = arena.reserve(99).?;
    final_slot.record = .{ .id = 99, .owner = 8, .label = "final" };
    try std.testing.expectEqualStrings("final", arena.get(99).?.record.label);
}

test "indexed arena claims the first tombstone for proven absent keys" {
    const Arena = IndexedArena(TestSlot, 3, 4, testSlotId);
    var arena = Arena.init();

    _ = arena.insertIndex(1, .{ .record = .{ .id = 1, .label = "first" } }).?;
    _ = arena.insertIndex(5, .{ .record = .{ .id = 5, .label = "second" } }).?;
    try std.testing.expect(arena.remove(1));
    _ = arena.insertIndex(9, .{ .record = .{ .id = 9, .label = "replacement" } }).?;

    const shared_bucket = id_index.hash(1, 4);
    try std.testing.expectEqual(@as(u64, 9), arena.primary_index.table.ids[shared_bucket]);
    try std.testing.expectEqualStrings("replacement", arena.get(9).?.record.label);
    try std.testing.expectEqualStrings("second", arena.get(5).?.record.label);
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

test "indexed arena inserts complete values at explicit free indexes" {
    const Arena = IndexedArena(TestSlot, 4, 8, testSlotId);
    var arena = Arena.init();

    const inserted_index = arena.insertIndexAt(41, 2, .{
        .record = .{ .id = 41, .owner = 7, .label = "explicit-insert" },
    }).?;
    try std.testing.expectEqual(@as(usize, 2), inserted_index);
    try std.testing.expect(arena.slots[inserted_index].in_use);
    try std.testing.expectEqualStrings("explicit-insert", arena.get(41).?.record.label);
    try std.testing.expectEqual(@as(?usize, null), arena.insertIndexAt(41, 1, .{
        .record = .{ .id = 41, .owner = 8, .label = "duplicate" },
    }));

    try std.testing.expect(arena.remove(41));
    const reused_index = arena.insertIndexAt(42, 2, .{
        .record = .{ .id = 42, .owner = 9, .label = "reused" },
    }).?;
    try std.testing.expectEqual(inserted_index, reused_index);
    try std.testing.expectEqualStrings("reused", arena.get(42).?.record.label);
}

test "indexed arena can reset membership while retaining unreachable payloads" {
    const Arena = DirtyTrackedIndexedArenaWithKey(u64, TestSlot, 4, 8, testSlotId);
    var arena = Arena.init();

    const slot_index = arena.reserveIndexAt(41, 2).?;
    arena.slots[slot_index].record = .{ .id = 41, .owner = 7, .label = "retained" };
    const recycled_index = arena.reserveIndex(42).?;
    try std.testing.expect(arena.removeIndex(recycled_index));
    try std.testing.expectEqual(@as(usize, 2), arena.dirtyIds().len);
    arena.dirty_ids[2] = 99;

    arena.resetRetainingPayloads();
    try std.testing.expectEqual(@as(usize, 0), arena.countInUse());
    try std.testing.expectEqual(@as(usize, 0), arena.claimedCount());
    try std.testing.expectEqual(reusableNoIndex(4), arena.free_head);
    try std.testing.expectEqual(@as(usize, 0), arena.dirtyIds().len);
    try std.testing.expectEqual(@as(u64, 0), arena.dirty_ids[0]);
    try std.testing.expectEqual(@as(u64, 0), arena.dirty_ids[1]);
    try std.testing.expectEqual(@as(u64, 99), arena.dirty_ids[2]);
    try std.testing.expectEqual(@as(?usize, null), arena.dirty_id_index.lookup(41));
    try std.testing.expectEqual(@as(?usize, null), arena.dirty_id_index.lookup(42));
    try std.testing.expect(arena.get(41) == null);
    try std.testing.expect(!arena.slots[slot_index].in_use);
    try std.testing.expectEqualStrings("retained", arena.slots[slot_index].record.label);

    try std.testing.expectEqual(@as(usize, 0), arena.reserveIndex(43).?);
    const replacement = arena.reserveAtIndex(44, slot_index).?;
    try std.testing.expectEqual(@as(u64, 0), replacement.record.id);
    try std.testing.expectEqualStrings("", replacement.record.label);
    replacement.record = .{ .id = 44, .owner = 8, .label = "replacement" };
    try std.testing.expectEqualStrings("replacement", arena.get(44).?.record.label);
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

test "multimap indexes size links to their fixed capacities" {
    const ByteIndex = MultimapIndex(128, 128, 256);
    const WordIndex = MultimapIndex(256, 256, 512);

    try std.testing.expectEqual(@as(usize, 384), @sizeOf(@FieldType(ByteIndex, "links")));
    try std.testing.expectEqual(@as(usize, 5_000), @sizeOf(ByteIndex));
    try std.testing.expectEqual(@as(usize, 1_536), @sizeOf(@FieldType(WordIndex, "links")));
    try std.testing.expectEqual(@as(usize, 11_272), @sizeOf(WordIndex));
}

test "indexed arena supports constant-time arbitrary multimap removal" {
    const OwnerMultimap = MultimapIndex(5, 4, 8);
    var owner_index = OwnerMultimap.init();

    try std.testing.expect(!owner_index.append(0, 0));
    try std.testing.expect(!owner_index.append(7, 5));
    try std.testing.expect(!owner_index.remove(0, 0));
    try std.testing.expect(!owner_index.remove(7, 5));
    try std.testing.expect(owner_index.append(7, 0));
    try std.testing.expect(owner_index.append(7, 2));
    try std.testing.expect(owner_index.append(7, 3));
    try std.testing.expect(owner_index.append(8, 1));

    try std.testing.expectEqual(@as(usize, 3), owner_index.count(7));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(8));
    try std.testing.expectEqual(@as(usize, 0), owner_index.head(7));
    try std.testing.expectEqual(no_index, owner_index.previous(0));
    try std.testing.expectEqual(@as(usize, 2), owner_index.next(0));
    try std.testing.expectEqual(@as(usize, 0), owner_index.previous(2));
    try std.testing.expectEqual(@as(usize, 3), owner_index.next(2));
    try std.testing.expectEqual(@as(usize, 2), owner_index.previous(3));
    try std.testing.expectEqual(no_index, owner_index.next(3));
    try std.testing.expect(!owner_index.append(9, 2));
    try std.testing.expect(!owner_index.remove(8, 2));

    try std.testing.expect(owner_index.remove(7, 2));
    try std.testing.expectEqual(@as(usize, 2), owner_index.count(7));
    try std.testing.expectEqual(@as(usize, 3), owner_index.next(0));
    try std.testing.expectEqual(@as(usize, 0), owner_index.previous(3));
    try std.testing.expectEqual(@as(usize, 3), owner_index.tail(7));
    try std.testing.expectEqual(no_index, owner_index.next(2));
    try std.testing.expectEqual(no_index, owner_index.previous(2));
    try std.testing.expect(owner_index.append(7, 2));
    try std.testing.expectEqual(@as(usize, 2), owner_index.tail(7));
    try std.testing.expectEqual(@as(usize, 3), owner_index.previous(2));
    try std.testing.expect(owner_index.remove(7, 2));
    try std.testing.expectEqual(@as(usize, 3), owner_index.tail(7));
    try std.testing.expectEqual(no_index, owner_index.next(2));
    try std.testing.expect(owner_index.remove(7, 0));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(7));
    try std.testing.expectEqual(@as(usize, 3), owner_index.head(7));
    try std.testing.expect(owner_index.remove(7, 3));
    try std.testing.expectEqual(@as(usize, 0), owner_index.count(7));

    try std.testing.expect(owner_index.append(9, 0));
    try std.testing.expect(owner_index.append(10, 2));
    try std.testing.expect(owner_index.append(11, 3));
    try std.testing.expect(!owner_index.append(12, 4));
    try std.testing.expectEqual(@as(usize, 0), owner_index.count(12));
    try std.testing.expect(owner_index.append(9, 4));
    try std.testing.expect(owner_index.remove(9, 4));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(8));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(9));

    try std.testing.expect(owner_index.remove(10, 2));
    try std.testing.expect(owner_index.append(12, 4));
    try std.testing.expectEqual(@as(usize, 1), owner_index.count(12));
}

test "multimap index matches an insertion-order model under churn" {
    const slot_count = 8;
    const bucket_capacity = 4;
    const model_key_count = 6;
    const ModelIndex = MultimapIndex(slot_count, bucket_capacity, 8);
    const empty_order = [_][slot_count]usize{[_]usize{0} ** slot_count} ** model_key_count;

    var index = ModelIndex.init();
    var model_slot_keys = [_]u64{0} ** slot_count;
    var model_order = empty_order;
    var model_counts = [_]usize{0} ** model_key_count;
    var random_state: u64 = 0x6d75_6c74_696d_6170;

    var operation_index: usize = 0;
    while (operation_index < 4096) : (operation_index += 1) {
        random_state = random_state *% 6_364_136_223_846_793_005 +% 1_442_695_040_888_963_407;
        const slot_index: usize = @intCast((random_state >> 8) % slot_count);
        const key = 1 + ((random_state >> 32) % model_key_count);
        const key_index: usize = @intCast(key - 1);

        if (operation_index != 0 and operation_index % 257 == 0) {
            index.reset();
            model_slot_keys = [_]u64{0} ** slot_count;
            model_order = empty_order;
            model_counts = [_]usize{0} ** model_key_count;
        } else if (random_state & 1 == 0) {
            var active_bucket_count: usize = 0;
            for (model_counts) |count| {
                if (count != 0) active_bucket_count += 1;
            }
            const expected = model_slot_keys[slot_index] == 0 and
                (model_counts[key_index] != 0 or active_bucket_count < bucket_capacity);
            try std.testing.expectEqual(expected, index.append(key, slot_index));
            if (expected) {
                model_order[key_index][model_counts[key_index]] = slot_index;
                model_counts[key_index] += 1;
                model_slot_keys[slot_index] = key;
            }
        } else {
            const expected = model_slot_keys[slot_index] == key;
            try std.testing.expectEqual(expected, index.remove(key, slot_index));
            if (expected) {
                var removed_at: usize = 0;
                while (model_order[key_index][removed_at] != slot_index) : (removed_at += 1) {}
                while (removed_at + 1 < model_counts[key_index]) : (removed_at += 1) {
                    model_order[key_index][removed_at] = model_order[key_index][removed_at + 1];
                }
                model_counts[key_index] -= 1;
                model_slot_keys[slot_index] = 0;
            }
        }

        for (0..model_key_count) |model_key_index| {
            const model_key: u64 = @intCast(model_key_index + 1);
            const expected_count = model_counts[model_key_index];
            const expected_head = if (expected_count == 0) no_index else model_order[model_key_index][0];
            const expected_tail = if (expected_count == 0) no_index else model_order[model_key_index][expected_count - 1];
            try std.testing.expectEqual(expected_count, index.count(model_key));
            try std.testing.expectEqual(expected_head, index.head(model_key));
            try std.testing.expectEqual(expected_tail, index.tail(model_key));

            var traversed: usize = 0;
            var cursor = index.head(model_key);
            while (cursor != no_index) : (cursor = index.next(cursor)) {
                try std.testing.expect(traversed < expected_count);
                try std.testing.expect(cursor < slot_count);
                try std.testing.expectEqual(model_order[model_key_index][traversed], cursor);
                try std.testing.expectEqual(model_key, model_slot_keys[cursor]);
                traversed += 1;
            }
            try std.testing.expectEqual(expected_count, traversed);

            traversed = 0;
            cursor = index.tail(model_key);
            while (cursor != no_index) : (cursor = index.previous(cursor)) {
                try std.testing.expect(traversed < expected_count);
                try std.testing.expect(cursor < slot_count);
                try std.testing.expectEqual(model_order[model_key_index][expected_count - traversed - 1], cursor);
                try std.testing.expectEqual(model_key, model_slot_keys[cursor]);
                traversed += 1;
            }
            try std.testing.expectEqual(expected_count, traversed);
        }

        for (model_slot_keys, 0..) |model_key, slot_index_to_check| {
            if (model_key == 0) {
                try std.testing.expectEqual(no_index, index.next(slot_index_to_check));
                try std.testing.expectEqual(no_index, index.previous(slot_index_to_check));
            }
        }
    }
}

test "generational arena reuses slots and rejects stale handles" {
    const Arena = GenerationalArena("TestGenerationalHandle", TestSlot, 3);
    var arena = Arena.init();

    const first_handle = arena.reserveHandle().?;
    arena.getByHandle(first_handle).?.record = .{ .id = 11, .owner = 1, .label = "first" };
    const second_handle = arena.reserveHandleAt(2).?;
    arena.getByHandle(second_handle).?.record = .{ .id = 12, .owner = 2, .label = "second" };
    const third_handle = arena.reserveHandle().?;
    try std.testing.expectEqual(@as(usize, 1), third_handle.slotIndex());
    try std.testing.expect(arena.reserveHandle() == null);
    try std.testing.expectEqual(@as(usize, 3), arena.countInUse());

    try std.testing.expect(arena.removeHandle(first_handle));
    try std.testing.expect(arena.getByHandle(first_handle) == null);
    const replacement_handle = arena.reserveHandle().?;
    try std.testing.expectEqual(first_handle.slotIndex(), replacement_handle.slotIndex());
    try std.testing.expect(!first_handle.eql(replacement_handle));
    try std.testing.expectEqualStrings("", arena.getByHandle(replacement_handle).?.record.label);

    arena.reset();
    try std.testing.expectEqual(@as(usize, 0), arena.countInUse());
    try std.testing.expect(arena.getByHandle(second_handle) == null);
    try std.testing.expect(arena.getByHandle(replacement_handle) == null);
}

test "generational arena generations wrap without zero" {
    const Arena = GenerationalArena("TestGenerationalHandle", TestSlot, 1);
    var arena = Arena.init();
    arena.slot_generations[0] = std.math.maxInt(u32);

    const last_generation_handle = arena.reserveHandle().?;
    try std.testing.expectEqual(std.math.maxInt(u32), last_generation_handle.generation());
    try std.testing.expect(arena.removeHandle(last_generation_handle));
    const wrapped_handle = arena.reserveHandle().?;
    try std.testing.expectEqual(@as(u32, 1), wrapped_handle.generation());
    try std.testing.expect(arena.getByHandle(last_generation_handle) == null);
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

test "paged indexed arena generations advance without using zero" {
    try std.testing.expectEqual(@as(u32, 1), nextSlotGeneration(0));
    try std.testing.expectEqual(@as(u32, 2), nextSlotGeneration(1));
    try std.testing.expectEqual(@as(u32, 1), nextSlotGeneration(std.math.maxInt(u32)));
}

test "paged indexed arena full reset clears payloads and invalidates handles" {
    const Arena = PagedIndexedArena(TestSlot, 2, 2, 8, testSlotId);
    var arena = Arena.init();

    const stale_handle = arena.reserveHandle(41).?;
    arena.getByHandle(stale_handle).?.record = .{ .id = 41, .owner = 7, .label = "discarded" };

    arena.reset();
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.getByHandle(stale_handle));

    const replacement_handle = arena.reserveHandle(42).?;
    try std.testing.expectEqual(stale_handle.slotIndex(), replacement_handle.slotIndex());
    try std.testing.expect(!replacement_handle.eql(stale_handle));
    try std.testing.expectEqualStrings("", arena.getByHandle(replacement_handle).?.record.label);
}

test "paged indexed arena can reset membership while retaining unreachable payloads" {
    const Arena = PagedIndexedArena(TestSlot, 2, 4, 16, testSlotId);
    var arena = Arena.init();

    const high_slot_index: usize = 5;
    _ = arena.reserveIndexAt(51, high_slot_index).?;
    arena.slotAt(high_slot_index).record = .{ .id = 51, .owner = 9, .label = "retained" };
    const stale_high_handle = arena.handleForIndex(high_slot_index).?;

    arena.resetRetainingPayloads();
    try std.testing.expectEqual(@as(usize, 0), arena.countInUse());
    try std.testing.expectEqual(@as(usize, 0), arena.claimedCount());
    try std.testing.expectEqual(reusableNoIndex(8), arena.free_head);
    try std.testing.expect(arena.get(51) == null);
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.getByHandle(stale_high_handle));
    try std.testing.expect(!arena.slotAt(high_slot_index).in_use);
    try std.testing.expectEqualStrings("retained", arena.slotAt(high_slot_index).record.label);
    const parked_high_generation = arena.slot_generations[high_slot_index];

    arena.resetRetainingPayloads();
    _ = arena.reserveIndexAt(52, 2).?;
    arena.resetRetainingPayloads();
    try std.testing.expectEqual(parked_high_generation, arena.slot_generations[high_slot_index]);
    try std.testing.expectEqual(@as(usize, 0), arena.claimedCount());
    try std.testing.expectEqual(reusableNoIndex(8), arena.free_head);
    try std.testing.expectEqual(@as(usize, 0), arena.reserveIndex(53).?);

    const replacement = arena.reserveAtIndex(54, high_slot_index).?;
    try std.testing.expectEqual(@as(u64, 0), replacement.record.id);
    try std.testing.expectEqualStrings("", replacement.record.label);
    replacement.record = .{ .id = 54, .owner = 10, .label = "replacement" };
    const replacement_handle = arena.handleForIndex(high_slot_index).?;
    try std.testing.expect(!replacement_handle.eql(stale_high_handle));
    try std.testing.expectEqual(@as(?*TestSlot, null), arena.getByHandle(stale_high_handle));
    try std.testing.expectEqualStrings("replacement", arena.get(54).?.record.label);
}
