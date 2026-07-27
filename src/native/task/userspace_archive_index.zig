const std = @import("std");
const archive = @import("userspace_archive");
const id_index = @import("../core/id_index.zig");
const native_util = @import("../core/util.zig");

pub const GeneratedArtifact = @TypeOf(archive.artifacts[0]);
pub const ArchiveRole = archive.ArchiveRole;
pub const archive_role: ArchiveRole = archive.archive_role;
pub const includes_verification_images = archive.includes_verification_images;
pub const artifacts = archive.artifacts;

comptime {
    if (includes_verification_images != (archive_role == .verification)) {
        @compileError("generated userspace archive role metadata is inconsistent");
    }
}

const BUNDLE_INDEX_CAPACITY: usize = archive.artifacts.len * 2;
const bundle_index = buildBundleIndex();

pub fn artifactFor(bundle_id: []const u8) ?GeneratedArtifact {
    const artifact_index = id_index.lookup(BUNDLE_INDEX_CAPACITY, &bundle_index, bundleIndexKey(bundle_id)) orelse {
        debugAssertArchiveIndexMissAbsent(bundle_id);
        return null;
    };
    if (artifact_index >= archive.artifacts.len) {
        native_util.impossibleByInvariant("userspace archive index points outside artifacts");
    }
    const artifact = archive.artifacts[artifact_index];
    if (!std.mem.eql(u8, artifact.bundle_id, bundle_id)) {
        native_util.impossibleByInvariant("userspace archive index points at the wrong artifact");
    }
    return artifact;
}

fn bundleIndexKey(bundle_id: []const u8) u64 {
    const hash = native_util.fnv1a64(bundle_id);
    return if (hash == 0) 1 else hash;
}

fn buildBundleIndex() [BUNDLE_INDEX_CAPACITY]id_index.Slot {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(BUNDLE_INDEX_CAPACITY);
    for (archive.artifacts, 0..) |artifact, artifact_index| {
        id_index.insert(BUNDLE_INDEX_CAPACITY, &index, bundleIndexKey(artifact.bundle_id), artifact_index, "userspace archive bundle index covers generated artifacts");
    }
    return index;
}

fn debugAssertArchiveIndexMissAbsent(bundle_id: []const u8) void {
    if (@import("builtin").mode != .Debug) return;
    for (archive.artifacts) |artifact| {
        if (std.mem.eql(u8, artifact.bundle_id, bundle_id)) {
            native_util.impossibleByInvariant("userspace archive bundle index missed a generated artifact");
        }
    }
}

test "userspace archive index resolves every generated artifact bundle" {
    try std.testing.expect(archive.artifacts.len > 0);
    for (archive.artifacts) |artifact| {
        const indexed = artifactFor(artifact.bundle_id) orelse return error.MissingGeneratedArtifact;
        try std.testing.expectEqualStrings(artifact.bundle_id, indexed.bundle_id);
        try std.testing.expectEqualStrings(artifact.display_name, indexed.display_name);
        try std.testing.expectEqual(artifact.data.byte_len, indexed.data.byte_len);
        try std.testing.expectEqualSlices(u32, artifact.data.chunk_indices, indexed.data.chunk_indices);
    }
    try std.testing.expect(artifactFor("zigos.system.missing-artifact") == null);
}

test "userspace archive shares identical image chunks" {
    try std.testing.expect(archive.artifacts.len > 1);
    const shared_pool = archive.artifacts[0].data.chunk_pool;
    var logical_bytes: usize = 0;
    for (archive.artifacts) |artifact| {
        try std.testing.expectEqual(shared_pool.ptr, artifact.data.chunk_pool.ptr);
        try std.testing.expectEqual(shared_pool.len, artifact.data.chunk_pool.len);
        logical_bytes += artifact.data.byte_len;
    }
    try std.testing.expect(shared_pool.len < logical_bytes);
}
