const std = @import("std");
const archive_index = @import("userspace_archive_index.zig");
const embedded_file = @import("embedded_file.zig");
const elf_image_inspector = @import("elf_image_inspector.zig");
const launch_helpers = @import("task_runtime_launch.zig");
const task_runtime = @import("task_runtime_model.zig");

pub const app_fixture_bundle_id = "app.viewer";
pub const service_fixture_bundle_id = "zigos.system.service-registry";
pub const service_client_fixture_bundle_id = "zigos.system.service-client";
pub const storage_driver_fixture_bundle_id = "zigos.system.storage-driver";
pub const storage_service_fixture_bundle_id = "zigos.system.storage-object";
pub const sync_service_fixture_bundle_id = "zigos.system.sync-service";
pub const workspace_storage_fixture_bundle_id = "zigos.system.workspace-storage";

pub const Error = task_runtime.Error || elf_image_inspector.Error || error{
    GeneratedImageDigestMismatch,
    GeneratedImageLengthMismatch,
    GeneratedImageMetadataMismatch,
    GeneratedImageMissing,
    GeneratedImageMissingBytes,
};

pub fn imageByBundleId(bundle_id: []const u8) Error!task_runtime.ExecutableImageSpec {
    const artifact = archive_index.artifactFor(bundle_id) orelse return error.GeneratedImageMissing;
    return validateArtifact(artifact);
}

pub fn appImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(app_fixture_bundle_id);
}

pub fn serviceImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(service_fixture_bundle_id);
}

pub fn serviceClientImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(service_client_fixture_bundle_id);
}

pub fn storageDriverImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(storage_driver_fixture_bundle_id);
}

pub fn storageServiceImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(storage_service_fixture_bundle_id);
}

pub fn syncServiceImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(sync_service_fixture_bundle_id);
}

pub fn workspaceStorageImage() Error!task_runtime.ExecutableImageSpec {
    return imageByBundleId(workspace_storage_fixture_bundle_id);
}

pub fn validateArtifact(artifact: anytype) Error!task_runtime.ExecutableImageSpec {
    const file = embedded_file.File.fromChunkedArtifact(artifact);
    if (!file.isPresent()) return error.GeneratedImageMissingBytes;
    if (artifact.file_size_bytes != file.byte_len) return error.GeneratedImageLengthMismatch;

    const digest = file.sha256() orelse return error.GeneratedImageMissingBytes;
    if (!std.mem.eql(u8, &digest, &artifact.file_sha256)) return error.GeneratedImageDigestMismatch;

    const inspection = try elf_image_inspector.inspectFile(file);
    if (!metadataMatchesInspection(artifact, inspection)) return error.GeneratedImageMetadataMismatch;

    return launch_helpers.validateUserspaceImage(
        Error,
        task_runtime.MAX_EXECUTABLE_SEGMENTS,
        inspection.executable_image,
    );
}

pub fn expectReaderRejectsInvalidGeneratedRecords() !void {
    try std.testing.expect(archive_index.artifacts.len > 0);
    const production_image = try validateArtifact(archive_index.artifacts[0]);
    try std.testing.expect(production_image.bootstrap_mailbox_address != 0);

    var missing_bytes = archive_index.artifacts[0];
    missing_bytes.data.byte_len = 0;
    missing_bytes.data.chunk_pool = &.{};
    missing_bytes.data.chunk_indices = &.{};
    missing_bytes.file_size_bytes = 0;
    missing_bytes.file_sha256 = [_]u8{0} ** 32;
    try std.testing.expectError(error.GeneratedImageMissingBytes, validateArtifact(missing_bytes));

    var digest_mismatch = archive_index.artifacts[0];
    digest_mismatch.file_sha256[0] ^= 0x5A;
    try std.testing.expectError(error.GeneratedImageDigestMismatch, validateArtifact(digest_mismatch));

    var truncated = archive_index.artifacts[0];
    truncated.data.byte_len = @min(truncated.data.byte_len, 8);
    truncated.data.chunk_indices = truncated.data.chunk_indices[0..1];
    truncated.file_size_bytes = truncated.data.byte_len;
    truncated.file_sha256 = embedded_file.File.fromChunkedArtifact(truncated).sha256().?;
    try std.testing.expectError(error.InvalidElfHeader, validateArtifact(truncated));

    var stale_metadata = archive_index.artifacts[0];
    stale_metadata.entry_point +%= launch_helpers.SYNTHETIC_SEGMENT_ALIGNMENT;
    try std.testing.expectError(error.GeneratedImageMetadataMismatch, validateArtifact(stale_metadata));
}

fn metadataMatchesInspection(artifact: anytype, inspection: elf_image_inspector.Inspection) bool {
    if (artifact.entry_point != inspection.entry_point) return false;
    if (artifact.bootstrap_mailbox_address != inspection.bootstrap_mailbox_address) return false;
    if (artifact.file_size_bytes != inspection.byte_len) return false;
    if (!std.mem.eql(u8, &artifact.file_sha256, &inspection.file_sha256)) return false;

    const expected = executableImageFromArtifact(artifact);
    return expected.eql(&inspection.executable_image);
}

fn executableImageFromArtifact(artifact: anytype) task_runtime.ExecutableImageSpec {
    var image = task_runtime.ExecutableImageSpec{
        .entry_point = artifact.entry_point,
        .bootstrap_mailbox_address = artifact.bootstrap_mailbox_address,
        .stack_top = artifact.stack_top,
        .stack_size_bytes = artifact.stack_size_bytes,
        .file_size_bytes = artifact.file_size_bytes,
        .file_sha256 = artifact.file_sha256,
        .segment_count = @intCast(artifact.segment_count),
    };

    var index: usize = 0;
    while (index < artifact.segment_count and index < image.segments.len) : (index += 1) {
        const segment = artifact.segments[index];
        image.segments[index] = .{
            .virtual_address = segment.virtual_address,
            .file_offset = segment.file_offset,
            .file_size = segment.file_size,
            .memory_size = segment.memory_size,
            .alignment = segment.alignment,
            .access = .{
                .read = segment.access.read,
                .write = segment.access.write,
                .execute = segment.access.execute,
            },
        };
    }

    return image;
}

test "generated image fixture reader returns archive-backed executable images" {
    const image = try storageServiceImage();
    try std.testing.expect(image.isPresent());
    try std.testing.expect(image.file_size_bytes != 0);
    try std.testing.expect(image.bootstrap_mailbox_address != 0);
    try std.testing.expect(!std.mem.allEqual(u8, &image.file_sha256, 0));
}

test "generated image fixture reader rejects invalid archive records" {
    try expectReaderRejectsInvalidGeneratedRecords();
}
