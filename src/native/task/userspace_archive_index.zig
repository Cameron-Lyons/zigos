const std = @import("std");
const archive = @import("userspace_archive");
const embedded_file = @import("embedded_file.zig");
const native_util = @import("../core/util.zig");
const role_registry = if (archive.includes_verification_images)
    @import("userspace_verification_registry.zig")
else
    @import("userspace_registry.zig");

pub const GeneratedArtifact = @TypeOf(archive.artifacts[0]);
pub const ArchiveRole = archive.ArchiveRole;
pub const archive_role: ArchiveRole = archive.archive_role;
pub const includes_verification_images = archive.includes_verification_images;
pub const artifacts = archive.artifacts;

comptime {
    if (includes_verification_images != (archive_role == .verification)) {
        @compileError("generated userspace archive role metadata is inconsistent");
    }
    if (archive.artifacts.len != role_registry.role_boot_image_specs.len) {
        @compileError("generated userspace archive does not match its role-specific registry");
    }
    for ([_][]const u8{
        "bundle_id",
        "display_name",
        "publisher",
        "label",
        "entry",
        "component_class",
        "role_tag",
        "heartbeat_increment",
        "contract_flags",
        "signed",
    }) |field_name| {
        if (@hasField(GeneratedArtifact, field_name)) {
            @compileError("generated userspace artifacts must not duplicate registry identity field: " ++ field_name);
        }
    }
}

pub fn artifactFor(bundle_id: []const u8) ?GeneratedArtifact {
    // Archive artifacts are emitted in registry order, so the registry's
    // existing bundle index is the single source of identity lookup truth.
    const artifact_index = role_registry.indexForRole(bundle_id) orelse return null;
    if (artifact_index >= archive.artifacts.len) {
        native_util.impossibleByInvariant("userspace registry index points outside archive artifacts");
    }
    return archive.artifacts[artifact_index];
}

test "userspace archive index resolves every generated artifact bundle" {
    try std.testing.expect(archive.artifacts.len > 0);
    for (role_registry.role_boot_image_specs, 0..) |spec, artifact_index| {
        const artifact = archive.artifacts[artifact_index];
        const indexed = artifactFor(spec.bundle_id) orelse return error.MissingGeneratedArtifact;
        try std.testing.expectEqual(artifact.entry_point, indexed.entry_point);
        try std.testing.expectEqual(artifact.data.byte_len, indexed.data.byte_len);
        try std.testing.expectEqualSlices(embedded_file.ChunkIndex, artifact.data.chunk_indices, indexed.data.chunk_indices);
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
