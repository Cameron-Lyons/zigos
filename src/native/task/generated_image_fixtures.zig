const std = @import("std");
const archive = @import("userspace_archive");
const crypto_hash = @import("../core/crypto_hash.zig");
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
    GeneratedImageUnsigned,
};

pub fn imageByBundleId(bundle_id: []const u8) Error!task_runtime.ExecutableImageSpec {
    for (archive.artifacts) |artifact| {
        if (std.mem.eql(u8, artifact.bundle_id, bundle_id)) {
            return validateArtifact(artifact);
        }
    }
    return error.GeneratedImageMissing;
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
    if (artifact.data.len == 0) return error.GeneratedImageMissingBytes;
    if (!artifact.signed) return error.GeneratedImageUnsigned;
    if (artifact.file_size_bytes != artifact.data.len) return error.GeneratedImageLengthMismatch;

    const digest = rawSha256(artifact.data);
    if (!std.mem.eql(u8, &digest, &artifact.file_sha256)) return error.GeneratedImageDigestMismatch;

    const inspection = try elf_image_inspector.inspect(artifact.data);
    if (!metadataMatchesInspection(artifact, inspection)) return error.GeneratedImageMetadataMismatch;

    return launch_helpers.validateUserspaceImage(
        Error,
        task_runtime.MAX_EXECUTABLE_SEGMENTS,
        inspection.executable_image,
    );
}

pub fn expectReaderRejectsInvalidGeneratedRecords() !void {
    try std.testing.expect(archive.artifacts.len > 0);
    _ = try validateArtifact(archive.artifacts[0]);

    var missing_bytes = archive.artifacts[0];
    missing_bytes.data = "";
    missing_bytes.file_size_bytes = 0;
    missing_bytes.file_sha256 = rawSha256(missing_bytes.data);
    try std.testing.expectError(error.GeneratedImageMissingBytes, validateArtifact(missing_bytes));

    var unsigned = archive.artifacts[0];
    unsigned.signed = false;
    try std.testing.expectError(error.GeneratedImageUnsigned, validateArtifact(unsigned));

    var digest_mismatch = archive.artifacts[0];
    digest_mismatch.file_sha256[0] ^= 0x5A;
    try std.testing.expectError(error.GeneratedImageDigestMismatch, validateArtifact(digest_mismatch));

    var truncated = archive.artifacts[0];
    truncated.data = truncated.data[0..@min(truncated.data.len, 8)];
    truncated.file_size_bytes = truncated.data.len;
    truncated.file_sha256 = rawSha256(truncated.data);
    try std.testing.expectError(error.InvalidElfHeader, validateArtifact(truncated));

    var stale_metadata = archive.artifacts[0];
    stale_metadata.entry_point +%= launch_helpers.SYNTHETIC_SEGMENT_ALIGNMENT;
    try std.testing.expectError(error.GeneratedImageMetadataMismatch, validateArtifact(stale_metadata));
}

fn metadataMatchesInspection(artifact: anytype, inspection: elf_image_inspector.Inspection) bool {
    if (artifact.entry_point != inspection.entry_point) return false;
    if (artifact.bootstrap_mailbox_address != inspection.bootstrap_mailbox_address) return false;
    if (artifact.file_size_bytes != inspection.byte_len) return false;
    if (!std.mem.eql(u8, &artifact.file_sha256, &inspection.file_sha256)) return false;

    const expected = executableImageFromArtifact(artifact);
    return executableImagesEqual(expected, inspection.executable_image);
}

fn executableImageFromArtifact(artifact: anytype) task_runtime.ExecutableImageSpec {
    var image = task_runtime.ExecutableImageSpec{
        .entry_point = artifact.entry_point,
        .stack_top = artifact.stack_top,
        .stack_size_bytes = artifact.stack_size_bytes,
        .file_size_bytes = artifact.file_size_bytes,
        .file_sha256 = artifact.file_sha256,
        .segment_count = artifact.segment_count,
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

fn executableImagesEqual(
    lhs: task_runtime.ExecutableImageSpec,
    rhs: task_runtime.ExecutableImageSpec,
) bool {
    if (lhs.entry_point != rhs.entry_point) return false;
    if (lhs.stack_top != rhs.stack_top) return false;
    if (lhs.stack_size_bytes != rhs.stack_size_bytes) return false;
    if (lhs.file_size_bytes != rhs.file_size_bytes) return false;
    if (!std.mem.eql(u8, &lhs.file_sha256, &rhs.file_sha256)) return false;
    if (lhs.segment_count != rhs.segment_count) return false;

    var index: usize = 0;
    while (index < lhs.segment_count) : (index += 1) {
        const left = lhs.segments[index];
        const right = rhs.segments[index];
        if (left.virtual_address != right.virtual_address) return false;
        if (left.file_offset != right.file_offset) return false;
        if (left.file_size != right.file_size) return false;
        if (left.memory_size != right.memory_size) return false;
        if (left.alignment != right.alignment) return false;
        if (left.access.read != right.access.read) return false;
        if (left.access.write != right.access.write) return false;
        if (left.access.execute != right.access.execute) return false;
    }

    return true;
}

fn rawSha256(bytes: []const u8) crypto_hash.Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var digest: crypto_hash.Digest = undefined;
    hasher.final(&digest);
    return digest;
}

test "generated image fixture reader returns archive-backed executable images" {
    const image = try storageServiceImage();
    try std.testing.expect(image.isPresent());
    try std.testing.expect(image.file_size_bytes > task_runtime.DEFAULT_SYNTHETIC_IMAGE_BYTES);
    try std.testing.expect(!std.mem.allEqual(u8, &image.file_sha256, 0));
}

test "generated image fixture reader rejects invalid archive records" {
    try expectReaderRejectsInvalidGeneratedRecords();
}
