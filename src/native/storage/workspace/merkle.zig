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

pub fn rebuildPathMerkle(root_address: *RootAddress, leaf_hashes: anytype, entries: anytype) void {
    for (entries, 0..) |entry, entry_index| updatePathLeaf(leaf_hashes, entry_index, entry);

    for (leaf_hashes[entries.len..]) |*leaf_hash| {
        leaf_hash.* = zeroRootAddress();
    }
    refreshPathRoot(root_address, leaf_hashes[0..entries.len]);
}

pub fn updatePathLeaf(leaf_hashes: anytype, entry_index: usize, entry: anytype) void {
    leaf_hashes[entry_index] = entryLeafAddress(entry);
}

pub fn refreshPathRoot(root_address: *RootAddress, leaf_hashes: []const RootAddress) void {
    root_address.* = rootFromLeaves(leaf_hashes);
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
