const std = @import("std");
const native_archive_deps = @import("native_archive_deps");
const crypto_hash = native_archive_deps.crypto_hash;
const elf_image_inspector = native_archive_deps;
const hex = native_archive_deps.hex;
const signing = native_archive_deps;
const units = native_archive_deps.units;

const EmbeddedInfo = elf_image_inspector.Inspection;
const ChunkIndex = native_archive_deps.EmbeddedFileChunkIndex;
const max_userspace_image_bytes: usize = units.mebibytes(16);
const max_bootloader_source_bytes: usize = units.mebibytes(1);
const max_build_artifact_entries: usize = 32;
const build_artifact_manifest_payload_buffer_bytes: usize = units.kibibytes(4);
const archive_chunk_bytes: usize = native_archive_deps.embedded_file_chunk_bytes;
const archive_chunk_pool_name = "userspace_chunks.bin";

const ArchiveRole = enum {
    production,
    verification,
};

const Artifact = struct {
    source_path: []const u8,
    bundle_id: []const u8,
    embedded_info: EmbeddedInfo,
};

const StoredChunk = struct {
    pool_index: ChunkIndex,
    byte_len: usize,
};

const ChunkedArchive = struct {
    pool: []u8,
    artifact_chunk_indices: [][]ChunkIndex,

    fn deinit(self: *ChunkedArchive, allocator: std.mem.Allocator) void {
        allocator.free(self.pool);
        for (self.artifact_chunk_indices) |indices| allocator.free(indices);
        allocator.free(self.artifact_chunk_indices);
        self.* = undefined;
    }
};

const BuildArtifactKind = enum(u8) {
    bootloader_source,
    bootloader_measurement,
    userspace_image,
};

const BuildArtifactEntry = struct {
    kind: BuildArtifactKind,
    label: []const u8,
    digest: crypto_hash.Digest,
};

const BuildArtifactSignature = struct {
    format: []const u8 = signing.SIGNATURE_FORMAT_ED25519,
    signer: []const u8 = "",
    public_key: [signing.ED25519_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** signing.ED25519_PUBLIC_KEY_BYTES,
    value: [signing.ED25519_SIGNATURE_BYTES]u8 = [_]u8{0} ** signing.ED25519_SIGNATURE_BYTES,
};

const BuildArtifactManifest = struct {
    generation: u64,
    entry_count: usize = 0,
    entries: [max_build_artifact_entries]BuildArtifactEntry = [_]BuildArtifactEntry{.{
        .kind = .bootloader_source,
        .label = "",
        .digest = crypto_hash.zero_digest,
    }} ** max_build_artifact_entries,
    signature: BuildArtifactSignature = .{},

    fn init(generation: u64) BuildArtifactManifest {
        return .{ .generation = generation };
    }

    fn addDigest(self: *BuildArtifactManifest, kind: BuildArtifactKind, label: []const u8, digest: crypto_hash.Digest) !void {
        if (self.entry_count >= self.entries.len) return error.RecordTableFull;
        self.entries[self.entry_count] = .{
            .kind = kind,
            .label = label,
            .digest = digest,
        };
        self.entry_count += 1;
    }
};

const build_manifest_generation: u64 = 1;
const build_manifest_signer = signing.SignerIdentity{
    .label = "zigos-build-artifact-manifest",
    .seed = signing.seedFromByte(0xC7),
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const cwd = std.Io.Dir.cwd();
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 6) return error.MissingOutputPath;
    const output_dir = args[1];
    const boot_profile = args[2];
    const archive_role: ArchiveRole = if (std.mem.eql(u8, args[3], "production"))
        .production
    else if (std.mem.eql(u8, args[3], "verification"))
        .verification
    else
        return error.InvalidArchiveRole;
    const bootloader_label = args[4];
    const bootloader_path = args[5];

    var artifacts = std.ArrayList(Artifact).empty;
    defer artifacts.deinit(allocator);

    const artifact_args = args[6..];
    if (artifact_args.len == 0) return error.MissingArtifactInput;
    if (artifact_args.len % 2 != 0) return error.InvalidArtifactArguments;
    var artifact_arg_index: usize = 0;
    while (artifact_arg_index < artifact_args.len) : (artifact_arg_index += 2) {
        const bundle_id = artifact_args[artifact_arg_index];
        const path = artifact_args[artifact_arg_index + 1];
        if (bundle_id.len == 0) return error.InvalidArtifactBundleId;
        try artifacts.append(allocator, try parseArtifact(arena, allocator, cwd, io, bundle_id, path));
    }

    try writeArchive(cwd, io, allocator, output_dir, archive_role, artifacts.items);
    try writeBuildArtifactManifest(cwd, io, allocator, output_dir, boot_profile, archive_role, bootloader_label, bootloader_path, artifacts.items);
}

fn parseArtifact(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    cwd: std.Io.Dir,
    io: std.Io,
    bundle_id: []const u8,
    path: []const u8,
) !Artifact {
    const bytes = try cwd.readFileAlloc(io, path, allocator, .limited(max_userspace_image_bytes));
    defer allocator.free(bytes);

    return .{
        .source_path = try arena.dupe(u8, path),
        .bundle_id = try arena.dupe(u8, bundle_id),
        .embedded_info = try elf_image_inspector.inspect(bytes),
    };
}

fn buildChunkedArchive(
    cwd: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    artifacts: []const Artifact,
) !ChunkedArchive {
    var pool = std.ArrayList(u8).empty;
    defer pool.deinit(allocator);
    var artifact_chunk_indices = std.ArrayList([]ChunkIndex).empty;
    defer artifact_chunk_indices.deinit(allocator);
    errdefer {
        for (artifact_chunk_indices.items) |indices| allocator.free(indices);
    }

    var chunks_by_digest = std.StringHashMap(StoredChunk).init(allocator);
    defer {
        var key_iterator = chunks_by_digest.keyIterator();
        while (key_iterator.next()) |key| allocator.free(key.*);
        chunks_by_digest.deinit();
    }

    const zero_padding = [_]u8{0} ** archive_chunk_bytes;
    for (artifacts) |artifact| {
        const bytes = try cwd.readFileAlloc(io, artifact.source_path, allocator, .limited(max_userspace_image_bytes));
        defer allocator.free(bytes);
        var indices = std.ArrayList(ChunkIndex).empty;
        defer indices.deinit(allocator);

        var offset: usize = 0;
        while (offset < bytes.len) : (offset += archive_chunk_bytes) {
            const end = @min(bytes.len, offset + archive_chunk_bytes);
            const chunk = bytes[offset..end];
            const digest = rawSha256(chunk);
            const stored = chunks_by_digest.get(&digest) orelse stored: {
                const pool_index = std.math.cast(ChunkIndex, pool.items.len / archive_chunk_bytes) orelse
                    return error.ArchiveChunkTableFull;
                try pool.appendSlice(allocator, chunk);
                try pool.appendSlice(allocator, zero_padding[0 .. archive_chunk_bytes - chunk.len]);
                const key = try allocator.dupe(u8, &digest);
                chunks_by_digest.put(key, .{
                    .pool_index = pool_index,
                    .byte_len = chunk.len,
                }) catch |err| {
                    allocator.free(key);
                    return err;
                };
                break :stored StoredChunk{
                    .pool_index = pool_index,
                    .byte_len = chunk.len,
                };
            };

            const pool_offset = @as(usize, stored.pool_index) * archive_chunk_bytes;
            if (stored.byte_len != chunk.len or
                !std.mem.eql(u8, pool.items[pool_offset..][0..chunk.len], chunk))
            {
                return error.ArchiveChunkDigestCollision;
            }
            try indices.append(allocator, stored.pool_index);
        }

        const owned_indices = try indices.toOwnedSlice(allocator);
        artifact_chunk_indices.append(allocator, owned_indices) catch |err| {
            allocator.free(owned_indices);
            return err;
        };
    }

    const owned_pool = try pool.toOwnedSlice(allocator);
    errdefer allocator.free(owned_pool);
    return .{
        .pool = owned_pool,
        .artifact_chunk_indices = try artifact_chunk_indices.toOwnedSlice(allocator),
    };
}

fn writeArchive(
    cwd: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    output_dir: []const u8,
    archive_role: ArchiveRole,
    artifacts: []const Artifact,
) !void {
    try cwd.createDirPath(io, output_dir);
    var chunked_archive = try buildChunkedArchive(cwd, io, allocator, artifacts);
    defer chunked_archive.deinit(allocator);
    if (chunked_archive.artifact_chunk_indices.len != artifacts.len) {
        return error.InvalidArchiveChunkIndex;
    }

    const chunk_pool_path = try std.fs.path.join(allocator, &.{ output_dir, archive_chunk_pool_name });
    defer allocator.free(chunk_pool_path);
    try cwd.writeFile(io, .{
        .sub_path = chunk_pool_path,
        .data = chunked_archive.pool,
    });

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const writer = &aw.writer;

    try writer.writeAll("pub const ArchiveRole = enum { production, verification };\n");
    try writer.print("pub const archive_role: ArchiveRole = .{s};\n", .{@tagName(archive_role)});
    try writer.writeAll("pub const includes_verification_images = archive_role == .verification;\n");
    try writer.print("pub const ChunkIndex = {s};\n\n", .{@typeName(ChunkIndex)});

    try writer.writeAll(
        \\const builtin = @import("builtin");
        \\const userspace_archive_section = switch (builtin.target.ofmt) {
        \\    .macho => "__DATA,zigos_userspace",
        \\    else => ".rodata.zigos_userspace_archive",
        \\};
        \\
        \\pub const SegmentAccess = packed struct(u8) {
        \\    read: bool = true,
        \\    write: bool = false,
        \\    execute: bool = false,
        \\    _reserved: u5 = 0,
        \\};
        \\
        \\pub const ExecutableSegmentSpec = struct {
        \\    virtual_address: u64 = 0,
        \\    file_offset: u32 = 0,
        \\    file_size: u32 = 0,
        \\    memory_size: u32 = 0,
        \\    alignment: u32 = 0x1000,
        \\    access: SegmentAccess = .{},
        \\};
        \\
        \\pub const EmbeddedFile = struct {
        \\    byte_len: usize,
        \\    chunk_pool: []const u8,
        \\    chunk_indices: []const ChunkIndex,
        \\};
        \\
        \\pub const Artifact = struct {
        \\    entry_point: u64,
        \\    stack_top: u64,
        \\    stack_size_bytes: usize,
        \\    file_size_bytes: usize,
        \\    file_sha256: [32]u8,
        \\    segment_count: usize,
        \\    segments: [8]ExecutableSegmentSpec,
        \\    bootstrap_mailbox_address: u64,
        \\    data: EmbeddedFile,
        \\};
        \\
    );

    try writer.print(
        "const archive_chunk_pool align(1) linksection(userspace_archive_section) = @embedFile(\"{f}\").*;\n",
        .{std.zig.fmtString(archive_chunk_pool_name)},
    );
    for (chunked_archive.artifact_chunk_indices, 0..) |indices, index| {
        try writer.print("const artifact_chunk_indices_{d} = [_]ChunkIndex{{", .{index});
        for (indices, 0..) |chunk_index, chunk_ordinal| {
            if (chunk_ordinal != 0) try writer.writeAll(", ");
            try writer.print("{d}", .{chunk_index});
        }
        try writer.writeAll("};\n");
    }

    try writer.writeAll(
        \\
        \\pub const artifacts = [_]Artifact{
        \\
    );

    for (artifacts, 0..) |artifact, index| {
        try writer.writeAll("    .{\n");
        try writer.print("        .entry_point = 0x{x},\n", .{artifact.embedded_info.entry_point});
        try writer.print("        .stack_top = 0x{x},\n", .{artifact.embedded_info.executable_image.stack_top});
        try writer.print("        .stack_size_bytes = {d},\n", .{artifact.embedded_info.executable_image.stack_size_bytes});
        try writer.print("        .file_size_bytes = {d},\n", .{artifact.embedded_info.executable_image.file_size_bytes});
        try writer.writeAll("        .file_sha256 = .{");
        for (artifact.embedded_info.file_sha256, 0..) |byte, digest_index| {
            if (digest_index != 0) try writer.writeAll(", ");
            try writer.print("0x{x:0>2}", .{byte});
        }
        try writer.writeAll("},\n");
        try writer.print("        .segment_count = {d},\n", .{artifact.embedded_info.executable_image.segment_count});
        try writer.writeAll("        .segments = .{\n");
        for (artifact.embedded_info.executable_image.segments) |segment| {
            try writer.print(
                "            .{{ .virtual_address = 0x{x}, .file_offset = {d}, .file_size = {d}, .memory_size = {d}, .alignment = {d}, .access = .{{ .read = {}, .write = {}, .execute = {} }} }},\n",
                .{
                    segment.virtual_address,
                    segment.file_offset,
                    segment.file_size,
                    segment.memory_size,
                    segment.alignment,
                    segment.access.read,
                    segment.access.write,
                    segment.access.execute,
                },
            );
        }
        try writer.writeAll("        },\n");
        try writer.print("        .bootstrap_mailbox_address = 0x{x},\n", .{artifact.embedded_info.bootstrap_mailbox_address});
        try writer.writeAll("        .data = .{\n");
        try writer.print("            .byte_len = {d},\n", .{artifact.embedded_info.byte_len});
        try writer.writeAll("            .chunk_pool = &archive_chunk_pool,\n");
        try writer.print("            .chunk_indices = &artifact_chunk_indices_{d},\n", .{index});
        try writer.writeAll("        },\n");
        try writer.writeAll("    },\n");
    }

    try writer.writeAll("};\n");
    const output_path = try std.fs.path.join(allocator, &.{ output_dir, "userspace_archive.zig" });
    defer allocator.free(output_path);
    try cwd.writeFile(io, .{
        .sub_path = output_path,
        .data = aw.written(),
    });
}

fn writeBuildArtifactManifest(
    cwd: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    output_dir: []const u8,
    boot_profile: []const u8,
    archive_role: ArchiveRole,
    bootloader_label: []const u8,
    bootloader_path: []const u8,
    artifacts: []const Artifact,
) !void {
    var build_manifest = BuildArtifactManifest.init(build_manifest_generation);
    const bootloader_bytes = try cwd.readFileAlloc(io, bootloader_path, allocator, .limited(max_bootloader_source_bytes));
    defer allocator.free(bootloader_bytes);

    try build_manifest.addDigest(.bootloader_source, bootloader_label, rawSha256(bootloader_bytes));
    try build_manifest.addDigest(.bootloader_measurement, bootloaderMeasurementLabel(boot_profile), bootloaderMeasurementDigest(boot_profile, bootloader_label));
    for (artifacts) |artifact| {
        try build_manifest.addDigest(.userspace_image, artifact.bundle_id, artifact.embedded_info.file_sha256);
    }

    try signBuildArtifactManifest(&build_manifest);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const writer = &aw.writer;

    try writer.writeAll(
        \\pub const Entry = struct {
        \\    kind: u8,
        \\    label: []const u8,
        \\    digest: [32]u8,
        \\};
        \\
    );
    try writer.print("pub const generation: u64 = {d};\n", .{build_manifest.generation});
    try writer.print("pub const signature_format = \"{f}\";\n", .{std.zig.fmtString(build_manifest.signature.format)});
    try writer.print("pub const signature_signer = \"{f}\";\n", .{std.zig.fmtString(build_manifest.signature.signer)});
    try writer.writeAll("pub const signature_public_key = [_]u8{");
    try writeByteArray(writer, &build_manifest.signature.public_key);
    try writer.writeAll("};\n");
    try writer.writeAll("pub const signature_value = [_]u8{");
    try writeByteArray(writer, &build_manifest.signature.value);
    try writer.writeAll("};\n\n");
    try writer.writeAll("pub const entries = [_]Entry{\n");
    for (build_manifest.entries[0..build_manifest.entry_count]) |entry| {
        try writer.print(
            "    .{{ .kind = {d}, .label = \"{f}\", .digest = .{{",
            .{
                @intFromEnum(entry.kind),
                std.zig.fmtString(entry.label),
            },
        );
        try writeByteArray(writer, &entry.digest);
        try writer.writeAll("} },\n");
    }
    try writer.writeAll("};\n");

    const manifest_filename = switch (archive_role) {
        .production => "production_artifact_manifest.zig",
        .verification => "verification_artifact_manifest.zig",
    };
    const manifest_path = try std.fs.path.join(allocator, &.{ output_dir, manifest_filename });
    defer allocator.free(manifest_path);
    try cwd.writeFile(io, .{
        .sub_path = manifest_path,
        .data = aw.written(),
    });
}

fn bootloaderMeasurementLabel(boot_profile: []const u8) []const u8 {
    if (std.mem.eql(u8, boot_profile, "benchmark")) return "multiboot:benchmark";
    return "multiboot:zigos_native";
}

fn bootloaderMeasurementDigest(boot_profile: []const u8, bootloader_label: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bootloader", "multiboot");
    crypto_hash.updateBytes(&hasher, "boot-profile", boot_profile);
    crypto_hash.updateBytes(&hasher, "entry-assembly", bootloader_label);
    return crypto_hash.finalize(&hasher);
}

fn rawSha256(bytes: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    hasher.update(bytes);
    return crypto_hash.finalize(&hasher);
}

fn signBuildArtifactManifest(manifest: *BuildArtifactManifest) !void {
    var payload_buffer: [build_artifact_manifest_payload_buffer_bytes]u8 = undefined;
    const payload = try encodeBuildArtifactManifest(
        manifest.generation,
        manifest.entries[0..manifest.entry_count],
        &payload_buffer,
    );
    const signature = try signing.signWithDefaultRegistry(.ed25519, build_manifest_signer, payload);
    manifest.signature = .{
        .format = signature.formatSlice(),
        .signer = signature.signer,
        .public_key = signature.ed25519PublicKeySlice()[0..signing.ED25519_PUBLIC_KEY_BYTES].*,
        .value = signature.ed25519SignatureSlice()[0..signing.ED25519_SIGNATURE_BYTES].*,
    };
}

fn encodeBuildArtifactManifest(generation: u64, entries: []const BuildArtifactEntry, buffer: []u8) ![]const u8 {
    var offset: usize = 0;
    offset = try appendFormat(buffer, offset, "ZBAM1|g={d}|n={d}", .{ generation, entries.len });
    for (entries) |entry| {
        offset = try appendFormat(buffer, offset, "|{s}:{s}:", .{
            @tagName(entry.kind),
            entry.label,
        });
        offset = try appendHexDigest(buffer, offset, &entry.digest);
    }
    return buffer[0..offset];
}

fn appendFormat(buffer: []u8, offset: usize, comptime fmt: []const u8, args: anytype) !usize {
    const text = std.fmt.bufPrint(buffer[offset..], fmt, args) catch return error.ManifestTooLarge;
    return offset + text.len;
}

fn appendHexDigest(buffer: []u8, offset: usize, digest: *const crypto_hash.Digest) !usize {
    const output_len = crypto_hash.hex_digest_bytes;
    if (offset + output_len > buffer.len) return error.ManifestTooLarge;
    _ = hex.encodeLower(digest, buffer[offset..][0..output_len]) catch return error.ManifestTooLarge;
    return offset + output_len;
}

fn writeByteArray(writer: anytype, bytes: []const u8) !void {
    for (bytes, 0..) |byte, index| {
        if (index != 0) try writer.writeAll(", ");
        try writer.print("0x{x:0>2}", .{byte});
    }
}
