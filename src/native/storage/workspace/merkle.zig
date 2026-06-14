const crypto_hash = @import("../../core/crypto_hash.zig");

pub const RootAddress = crypto_hash.Digest;

pub fn zeroRootAddress() RootAddress {
    return crypto_hash.zero_digest;
}

pub fn rootAddress(entries: anytype) RootAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "workspace-root", "merkle");
    crypto_hash.updateInt(&hasher, "entry-count", entries.len);
    for (entries) |entry| {
        const leaf_hash = entryLeafAddress(entry);
        crypto_hash.updateBytes(&hasher, "leaf", &leaf_hash);
    }
    return crypto_hash.finalize(&hasher);
}

pub fn rebuildPathMerkle(index: anytype, comptime max_entries: usize) void {
    var entry_index: usize = 0;
    while (entry_index < index.entry_count) : (entry_index += 1) {
        index.leaf_hashes[entry_index] = entryLeafAddress(index.entries[entry_index]);
    }
    while (entry_index < max_entries) : (entry_index += 1) {
        index.leaf_hashes[entry_index] = zeroRootAddress();
    }
    index.root_address = rootFromLeaves(index.leaf_hashes[0..index.entry_count]);
}

fn rootFromLeaves(leaf_hashes: []const RootAddress) RootAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "workspace-root", "merkle");
    crypto_hash.updateInt(&hasher, "entry-count", leaf_hashes.len);
    for (leaf_hashes) |leaf_hash| {
        crypto_hash.updateBytes(&hasher, "leaf", &leaf_hash);
    }
    return crypto_hash.finalize(&hasher);
}

fn entryLeafAddress(entry: anytype) RootAddress {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "workspace-path-index", "leaf");
    crypto_hash.updateBytes(&hasher, "path", entry.pathSlice());
    crypto_hash.updateInt(&hasher, "object-id", entry.object_id.raw());
    crypto_hash.updateInt(&hasher, "version-id", entry.version_id.raw());
    crypto_hash.updateInt(&hasher, "object-type", @intFromEnum(entry.object_type));
    return crypto_hash.finalize(&hasher);
}
