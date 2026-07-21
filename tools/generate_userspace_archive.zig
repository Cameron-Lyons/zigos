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

const ArchiveRole = enum {
    production,
    verification,
};

const Artifact = struct {
    source_path: []const u8,
    embedded_name: []const u8,
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
    if (args.len < 5) return error.MissingOutputPath;
    const output_dir = args[1];
    const boot_profile = args[2];
    const archive_role: ArchiveRole = if (std.mem.eql(u8, args[3], "production"))
        .production
    else if (std.mem.eql(u8, args[3], "verification"))
        .verification
    else
        return error.InvalidArchiveRole;
    const bootloader_path = args[4];

    var artifacts = std.ArrayList(Artifact).empty;
    defer artifacts.deinit(allocator);

    for (args[5..]) |path| {
        try artifacts.append(allocator, try parseArtifact(arena, allocator, cwd, io, path));
    }

    if (artifacts.items.len == 0) return error.MissingArtifactInput;
    try writeArchive(cwd, io, allocator, output_dir, archive_role, artifacts.items);
    try writeBuildArtifactManifest(cwd, io, allocator, output_dir, boot_profile, archive_role, bootloader_path, artifacts.items);
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

    const header = try readStruct(elf.Elf32_Ehdr, bytes, 0);
    try validateHeader(header, bytes.len);

    const descriptor_offset = try findDescriptorOffset(bytes, header);
    var descriptor = try readStruct(userspace_descriptor.Descriptor, bytes, descriptor_offset);
    try userspace_descriptor.validate(&descriptor);

    return .{
        .source_path = try arena.dupe(u8, path),
        .embedded_name = try arena.dupe(u8, std.fs.path.basename(path)),
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

fn validateHeader(header: elf.Elf32_Ehdr, byte_len: usize) !void {
    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS32) return error.UnsupportedElfClass;
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != .@"386") return error.UnsupportedElfMachine;
    if (header.e_shentsize != @sizeOf(elf.Elf32_Shdr)) return error.InvalidSectionHeaderSize;

    const sh_end = @as(usize, header.e_shoff) + @as(usize, header.e_shentsize) * @as(usize, header.e_shnum);
    if (header.e_shoff == 0 or sh_end > byte_len) return error.InvalidSectionHeaderTable;
}

fn findDescriptorOffset(bytes: []const u8, header: elf.Elf32_Ehdr) !usize {
    return findDescriptorSectionOffset(bytes, header) catch |err| switch (err) {
        error.DescriptorSectionNotFound => findDescriptorSymbolOffset(bytes, header),
        else => return err,
    };
}

fn findDescriptorSectionOffset(bytes: []const u8, header: elf.Elf32_Ehdr) !usize {
    const section_count: usize = header.e_shnum;
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) return error.InvalidSectionNameTable;

    const section_names = try sliceSection(bytes, try sectionHeader(bytes, header, header.e_shstrndx));

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionHeader(bytes, header, index);
        const name = readString(section_names, section.sh_name) orelse continue;
        if (!std.mem.eql(u8, name, userspace_descriptor.ELF_SECTION_NAME)) continue;

        if (section.sh_size < @sizeOf(userspace_descriptor.Descriptor)) {
            return error.DescriptorSectionTooSmall;
        }
        const file_offset = @as(usize, section.sh_offset);
        if (file_offset + @sizeOf(userspace_descriptor.Descriptor) > bytes.len) {
            return error.DescriptorOutOfBounds;
        }
        return file_offset;
    }

    return error.DescriptorSectionNotFound;
}

fn findDescriptorSymbolOffset(bytes: []const u8, header: elf.Elf32_Ehdr) !usize {
    const section_count: usize = header.e_shnum;
    var symtab: ?elf.Elf32_Shdr = null;

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionHeader(bytes, header, index);
        if (section.sh_type == elf.SHT_SYMTAB) {
            symtab = section;
            break;
        }
    }
    const symbol_table = symtab orelse return error.SymbolTableNotFound;
    if (symbol_table.sh_entsize != @sizeOf(elf.Elf32_Sym)) return error.InvalidSymbolTable;
    if (symbol_table.sh_link >= section_count) return error.InvalidStringTableReference;

    const strings_section = try sectionHeader(bytes, header, symbol_table.sh_link);
    const strings = try sliceSection(bytes, strings_section);
    const symbol_bytes = try sliceSection(bytes, symbol_table);
    const symbol_count = symbol_bytes.len / @sizeOf(elf.Elf32_Sym);

    index = 0;
    while (index < symbol_count) : (index += 1) {
        const offset = index * @sizeOf(elf.Elf32_Sym);
        const symbol = try readStruct(elf.Elf32_Sym, symbol_bytes, offset);
        const name = readString(strings, symbol.st_name) orelse continue;
        if (!std.mem.eql(u8, name, "zigos_userspace_descriptor")) continue;
        if (symbol.st_shndx == 0 or symbol.st_shndx >= section_count) return error.InvalidDescriptorSection;

        const section = try sectionHeader(bytes, header, symbol.st_shndx);
        if (symbol.st_value < section.sh_addr) return error.InvalidDescriptorAddress;
        const relative = symbol.st_value - section.sh_addr;
        const file_offset = @as(usize, section.sh_offset) + @as(usize, relative);
        if (file_offset + @sizeOf(userspace_descriptor.Descriptor) > bytes.len) {
            return error.DescriptorOutOfBounds;
        }
        return file_offset;
    }

    return error.DescriptorSymbolNotFound;
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
        \\    else => ".zigos_userspace_archive",
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
        \\    data: []const u8,
        \\};
        \\
    );

    for (artifacts, 0..) |artifact, index| {
        const copied_bytes = try cwd.readFileAlloc(io, artifact.source_path, allocator, .limited(max_userspace_image_bytes));
        defer allocator.free(copied_bytes);
        const copied_path = try std.fs.path.join(allocator, &.{ output_dir, artifact.embedded_name });
        defer allocator.free(copied_path);
        try cwd.writeFile(io, .{
            .sub_path = copied_path,
            .data = copied_bytes,
        });

        try writer.print(
            "const artifact_data_{d} align(1) linksection(userspace_archive_section) = @embedFile(\"{f}\").*;\n",
            .{ index, std.zig.fmtString(artifact.embedded_name) },
        );
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
        try writer.print("        .data = &artifact_data_{d},\n", .{index});
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
    bootloader_path: []const u8,
    artifacts: []const Artifact,
) !void {
    var build_manifest = BuildArtifactManifest.init(build_manifest_generation);
    const bootloader_bytes = try cwd.readFileAlloc(io, bootloader_path, allocator, .limited(max_bootloader_source_bytes));
    defer allocator.free(bootloader_bytes);

    try build_manifest.addDigest(.bootloader_source, "src/boot/boot64.S", rawSha256(bootloader_bytes));
    try build_manifest.addDigest(.bootloader_measurement, bootloaderMeasurementLabel(boot_profile), bootloaderMeasurementDigest(boot_profile));
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

fn bootloaderMeasurementDigest(boot_profile: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bootloader", "multiboot");
    crypto_hash.updateBytes(&hasher, "boot-profile", boot_profile);
    crypto_hash.updateBytes(&hasher, "entry-assembly", "src/boot/boot64.S");
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
        .format = signature.format,
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

fn sectionHeader(bytes: []const u8, header: elf.Elf32_Ehdr, index: usize) !elf.Elf32_Shdr {
    const offset = @as(usize, header.e_shoff) + index * @as(usize, header.e_shentsize);
    return readStruct(elf.Elf32_Shdr, bytes, offset);
}

fn sliceSection(bytes: []const u8, section: elf.Elf32_Shdr) ![]const u8 {
    const start = @as(usize, section.sh_offset);
    const end = start + @as(usize, section.sh_size);
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
