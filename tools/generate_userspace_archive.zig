const std = @import("std");
const elf = std.elf;
const native_archive_deps = @import("native_archive_deps");
const crypto_hash = native_archive_deps.crypto_hash;
const elf_image_inspector = native_archive_deps;
const hex = native_archive_deps.hex;
const signing = native_archive_deps;
const units = native_archive_deps.units;
const userspace_descriptor = @import("userspace_descriptor");

const EmbeddedInfo = elf_image_inspector.Inspection;
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
    display_name: []const u8,
    publisher: []const u8,
    label: []const u8,
    entry: []const u8,
    component_class: u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
    signed: bool,
    embedded_info: EmbeddedInfo,
};

const StoredChunk = struct {
    pool_index: u32,
    byte_len: usize,
};

const ChunkedArchive = struct {
    pool: []u8,
    artifact_chunk_indices: [][]u32,

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

    for (args[6..]) |path| {
        try artifacts.append(allocator, try parseArtifact(arena, allocator, cwd, io, path));
    }

    if (artifacts.items.len == 0) return error.MissingArtifactInput;
    try writeArchive(cwd, io, allocator, output_dir, archive_role, artifacts.items);
    try writeBuildArtifactManifest(cwd, io, allocator, output_dir, boot_profile, archive_role, bootloader_label, bootloader_path, artifacts.items);
}

fn parseArtifact(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    cwd: std.Io.Dir,
    io: std.Io,
    path: []const u8,
) !Artifact {
    const bytes = try cwd.readFileAlloc(io, path, allocator, .limited(max_userspace_image_bytes));
    defer allocator.free(bytes);

    if (bytes.len < elf.EI_NIDENT) return error.UnexpectedEof;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElfMagic;
    const descriptor_offset = switch (bytes[elf.EI_CLASS]) {
        elf.ELFCLASS32 => descriptor: {
            const header = try readStruct(elf.Elf32_Ehdr, bytes, 0);
            try validateHeader(elf.Elf32_Shdr, header, bytes.len, elf.ELFCLASS32, .@"386");
            break :descriptor try findDescriptorOffset(elf.Elf32_Shdr, elf.Elf32_Sym, bytes, header);
        },
        elf.ELFCLASS64 => descriptor: {
            const header = try readStruct(elf.Elf64_Ehdr, bytes, 0);
            try validateHeader(elf.Elf64_Shdr, header, bytes.len, elf.ELFCLASS64, .X86_64);
            break :descriptor try findDescriptorOffset(elf.Elf64_Shdr, elf.Elf64_Sym, bytes, header);
        },
        else => return error.UnsupportedElfClass,
    };
    var descriptor = try readStruct(userspace_descriptor.Descriptor, bytes, descriptor_offset);
    try userspace_descriptor.validate(&descriptor);

    return .{
        .source_path = try arena.dupe(u8, path),
        .bundle_id = try arena.dupe(u8, descriptor.bundleIdSlice()),
        .display_name = try arena.dupe(u8, descriptor.displayNameSlice()),
        .publisher = try arena.dupe(u8, descriptor.publisherSlice()),
        .label = try arena.dupe(u8, descriptor.labelSlice()),
        .entry = try arena.dupe(u8, descriptor.entrySlice()),
        .component_class = descriptor.component_class,
        .role_tag = descriptor.role_tag,
        .heartbeat_increment = descriptor.heartbeat_increment,
        .contract_flags = descriptor.contract_flags,
        .signed = descriptor.signed != 0,
        .embedded_info = try elf_image_inspector.inspect(bytes),
    };
}

fn validateHeader(
    comptime SectionHeader: type,
    header: anytype,
    byte_len: usize,
    expected_class: u8,
    expected_machine: elf.EM,
) !void {
    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[elf.EI_CLASS] != expected_class) return error.UnsupportedElfClass;
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != expected_machine) return error.UnsupportedElfMachine;
    if (header.e_shentsize != @sizeOf(SectionHeader)) return error.InvalidSectionHeaderSize;

    const sh_offset = std.math.cast(usize, header.e_shoff) orelse return error.InvalidSectionHeaderTable;
    const sh_bytes = std.math.mul(usize, @as(usize, header.e_shentsize), @as(usize, header.e_shnum)) catch
        return error.InvalidSectionHeaderTable;
    const sh_end = std.math.add(usize, sh_offset, sh_bytes) catch return error.InvalidSectionHeaderTable;
    if (sh_offset == 0 or sh_end > byte_len) return error.InvalidSectionHeaderTable;
}

fn findDescriptorOffset(comptime SectionHeader: type, comptime Symbol: type, bytes: []const u8, header: anytype) !usize {
    return findDescriptorSectionOffset(SectionHeader, bytes, header) catch |err| switch (err) {
        error.DescriptorSectionNotFound => findDescriptorSymbolOffset(SectionHeader, Symbol, bytes, header),
        else => return err,
    };
}

fn findDescriptorSectionOffset(comptime SectionHeader: type, bytes: []const u8, header: anytype) !usize {
    const section_count: usize = header.e_shnum;
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) return error.InvalidSectionNameTable;

    const section_names = try sliceSection(bytes, try sectionHeader(SectionHeader, bytes, header, header.e_shstrndx));

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionHeader(SectionHeader, bytes, header, index);
        const name = readString(section_names, section.sh_name) orelse continue;
        if (!std.mem.eql(u8, name, userspace_descriptor.ELF_SECTION_NAME)) continue;

        if (section.sh_size < @sizeOf(userspace_descriptor.Descriptor)) {
            return error.DescriptorSectionTooSmall;
        }
        const file_offset = std.math.cast(usize, section.sh_offset) orelse return error.DescriptorOutOfBounds;
        const descriptor_end = std.math.add(usize, file_offset, @sizeOf(userspace_descriptor.Descriptor)) catch
            return error.DescriptorOutOfBounds;
        if (descriptor_end > bytes.len) {
            return error.DescriptorOutOfBounds;
        }
        return file_offset;
    }

    return error.DescriptorSectionNotFound;
}

fn findDescriptorSymbolOffset(
    comptime SectionHeader: type,
    comptime Symbol: type,
    bytes: []const u8,
    header: anytype,
) !usize {
    const section_count: usize = header.e_shnum;
    var symtab: ?SectionHeader = null;

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionHeader(SectionHeader, bytes, header, index);
        if (section.sh_type == elf.SHT_SYMTAB) {
            symtab = section;
            break;
        }
    }
    const symbol_table = symtab orelse return error.SymbolTableNotFound;
    if (symbol_table.sh_entsize != @sizeOf(Symbol)) return error.InvalidSymbolTable;
    if (symbol_table.sh_link >= section_count) return error.InvalidStringTableReference;

    const strings_section = try sectionHeader(SectionHeader, bytes, header, symbol_table.sh_link);
    const strings = try sliceSection(bytes, strings_section);
    const symbol_bytes = try sliceSection(bytes, symbol_table);
    const symbol_count = symbol_bytes.len / @sizeOf(Symbol);

    index = 0;
    while (index < symbol_count) : (index += 1) {
        const offset = index * @sizeOf(Symbol);
        const symbol = try readStruct(Symbol, symbol_bytes, offset);
        const name = readString(strings, symbol.st_name) orelse continue;
        if (!std.mem.eql(u8, name, "zigos_userspace_descriptor")) continue;
        if (symbol.st_shndx == 0 or symbol.st_shndx >= section_count) return error.InvalidDescriptorSection;

        const section = try sectionHeader(SectionHeader, bytes, header, symbol.st_shndx);
        if (symbol.st_value < section.sh_addr) return error.InvalidDescriptorAddress;
        const relative = symbol.st_value - section.sh_addr;
        const section_offset = std.math.cast(usize, section.sh_offset) orelse return error.DescriptorOutOfBounds;
        const relative_offset = std.math.cast(usize, relative) orelse return error.DescriptorOutOfBounds;
        const file_offset = std.math.add(usize, section_offset, relative_offset) catch return error.DescriptorOutOfBounds;
        const descriptor_end = std.math.add(usize, file_offset, @sizeOf(userspace_descriptor.Descriptor)) catch
            return error.DescriptorOutOfBounds;
        if (descriptor_end > bytes.len) {
            return error.DescriptorOutOfBounds;
        }
        return file_offset;
    }

    return error.DescriptorSymbolNotFound;
}

fn buildChunkedArchive(
    cwd: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    artifacts: []const Artifact,
) !ChunkedArchive {
    var pool = std.ArrayList(u8).empty;
    defer pool.deinit(allocator);
    var artifact_chunk_indices = std.ArrayList([]u32).empty;
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
        var indices = std.ArrayList(u32).empty;
        defer indices.deinit(allocator);

        var offset: usize = 0;
        while (offset < bytes.len) : (offset += archive_chunk_bytes) {
            const end = @min(bytes.len, offset + archive_chunk_bytes);
            const chunk = bytes[offset..end];
            const digest = rawSha256(chunk);
            const stored = chunks_by_digest.get(&digest) orelse stored: {
                const pool_index = std.math.cast(u32, pool.items.len / archive_chunk_bytes) orelse
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
    try writer.writeAll("pub const includes_verification_images = archive_role == .verification;\n\n");

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
        \\    chunk_indices: []const u32,
        \\};
        \\
        \\pub const Artifact = struct {
        \\    bundle_id: []const u8,
        \\    display_name: []const u8,
        \\    publisher: []const u8,
        \\    label: []const u8,
        \\    entry: []const u8,
        \\    component_class: u8,
        \\    role_tag: u32,
        \\    heartbeat_increment: u32,
        \\    contract_flags: u32,
        \\    signed: bool,
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
        try writer.print("const artifact_chunk_indices_{d} = [_]u32{{", .{index});
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
        try writer.print("        .bundle_id = \"{f}\",\n", .{std.zig.fmtString(artifact.bundle_id)});
        try writer.print("        .display_name = \"{f}\",\n", .{std.zig.fmtString(artifact.display_name)});
        try writer.print("        .publisher = \"{f}\",\n", .{std.zig.fmtString(artifact.publisher)});
        try writer.print("        .label = \"{f}\",\n", .{std.zig.fmtString(artifact.label)});
        try writer.print("        .entry = \"{f}\",\n", .{std.zig.fmtString(artifact.entry)});
        try writer.print("        .component_class = {d},\n", .{artifact.component_class});
        try writer.print("        .role_tag = 0x{x},\n", .{artifact.role_tag});
        try writer.print("        .heartbeat_increment = {d},\n", .{artifact.heartbeat_increment});
        try writer.print("        .contract_flags = 0x{x},\n", .{artifact.contract_flags});
        try writer.print("        .signed = {},\n", .{artifact.signed});
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

fn sectionHeader(comptime SectionHeader: type, bytes: []const u8, header: anytype, index: usize) !SectionHeader {
    const table_offset = std.math.cast(usize, header.e_shoff) orelse return error.InvalidSectionHeaderTable;
    const section_delta = std.math.mul(usize, index, @as(usize, header.e_shentsize)) catch
        return error.InvalidSectionHeaderTable;
    const offset = std.math.add(usize, table_offset, section_delta) catch return error.InvalidSectionHeaderTable;
    return readStruct(SectionHeader, bytes, offset);
}

fn sliceSection(bytes: []const u8, section: anytype) ![]const u8 {
    const start = std.math.cast(usize, section.sh_offset) orelse return error.SectionOutOfBounds;
    const size = std.math.cast(usize, section.sh_size) orelse return error.SectionOutOfBounds;
    const end = std.math.add(usize, start, size) catch return error.SectionOutOfBounds;
    if (end > bytes.len) return error.SectionOutOfBounds;
    return bytes[start..end];
}

fn readString(strings: []const u8, offset: u32) ?[]const u8 {
    if (offset >= strings.len) return null;
    var end: usize = offset;
    while (end < strings.len and strings[end] != 0) : (end += 1) {}
    return strings[offset..end];
}

fn readStruct(comptime T: type, bytes: []const u8, offset: usize) !T {
    if (offset + @sizeOf(T) > bytes.len) return error.UnexpectedEof;
    var value: T = undefined;
    @memcpy(std.mem.asBytes(&value), bytes[offset..][0..@sizeOf(T)]);
    return value;
}
