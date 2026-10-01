const std = @import("std");
const object_store = @import("../object_store.zig");
const volume_errors = @import("errors.zig");

// Version IDs at or below the selected root's watermark are already committed.
// Their immutable payload chunks need no second log record. Reconstruct this
// bounded set for each append, so failed writes, recovery, and compaction never
// leave a speculative durability receipt behind.
pub const Tracker = struct {
    chunks: std.StaticBitSet(object_store.MAX_CHUNKS) = .initEmpty(),
    blobs: std.StaticBitSet(object_store.MAX_BLOBS) = .initEmpty(),

    pub fn init(store: *const object_store.Store, version_watermark: u64) volume_errors.Error!Tracker {
        var tracker = Tracker{};
        for (store.versions.slots[0..store.versions.claimedCount()]) |*slot| {
            if (!slot.arenaInUse() or slot.version.id.raw() > version_watermark) continue;
            const blob = store.versionBlob(&slot.version) orelse return error.CorruptImage;
            if (!try tracker.includeBlob(slot.version.blob_slot_index)) continue;
            for (0..blob.chunkCount()) |chunk_index| {
                const chunk_slot_index = store.blobChunkSlotIndex(blob, chunk_index) orelse return error.CorruptImage;
                _ = try tracker.includeChunk(chunk_slot_index);
            }
        }
        // Existing blobs still need their current refcounts persisted when a
        // new version references them; emit each affected manifest once.
        tracker.blobs = .initEmpty();
        return tracker;
    }

    pub fn includeChunk(self: *Tracker, slot_index: usize) volume_errors.Error!bool {
        if (slot_index >= object_store.MAX_CHUNKS) return error.CorruptImage;
        if (self.chunks.isSet(slot_index)) return false;
        self.chunks.set(slot_index);
        return true;
    }

    pub fn includeBlob(self: *Tracker, slot_index: usize) volume_errors.Error!bool {
        if (slot_index >= object_store.MAX_BLOBS) return error.CorruptImage;
        if (self.blobs.isSet(slot_index)) return false;
        self.blobs.set(slot_index);
        return true;
    }
};
