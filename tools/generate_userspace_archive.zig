const std = @import("std");
const elf = std.elf;
const userspace_descriptor = @import("userspace_descriptor");

const DEFAULT_USER_STACK_TOP: u64 = 0xBFFF_F000;
const DEFAULT_USER_STACK_SIZE_BYTES: usize = 64 * 1024;
const MAX_IMAGE_HASH_BYTES: usize = 32;
const MAX_EXECUTABLE_SEGMENTS: usize = 8;
const BOOTSTRAP_MAILBOX_SECTION_NAME = ".zigos_userspace_bootstrap";

const SegmentAccess = packed struct(u8) {
    read: bool = true,
    write: bool = false,
    execute: bool = false,
    _reserved: u5 = 0,
};

const ExecutableSegmentSpec = struct {
    virtual_address: u64 = 0,
    file_offset: u32 = 0,
    file_size: u32 = 0,
    memory_size: u32 = 0,
    alignment: u32 = 0x1000,
    access: SegmentAccess = .{},
};

const ExecutableImageSpec = struct {
    entry_point: u64 = 0,
    stack_top: u64 = DEFAULT_USER_STACK_TOP,
    stack_size_bytes: usize = DEFAULT_USER_STACK_SIZE_BYTES,
    file_size_bytes: usize = 0,
    file_sha256: [MAX_IMAGE_HASH_BYTES]u8 = [_]u8{0} ** MAX_IMAGE_HASH_BYTES,
    segment_count: usize = 0,
    segments: [MAX_EXECUTABLE_SEGMENTS]ExecutableSegmentSpec = [_]ExecutableSegmentSpec{ExecutableSegmentSpec{}} ** MAX_EXECUTABLE_SEGMENTS,
};

const EmbeddedInfo = struct {
    entry_point: u64,
    byte_len: usize,
    bootstrap_mailbox_address: u64,
    file_sha256: [MAX_IMAGE_HASH_BYTES]u8,
    executable_image: ExecutableImageSpec,
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cwd = std.fs.cwd();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return error.MissingOutputPath;
    const output_dir = args[1];

    var artifacts = std.ArrayList(Artifact).empty;
    defer artifacts.deinit(allocator);

    for (args[2..]) |path| {
        try artifacts.append(allocator, try parseArtifact(arena, allocator, cwd, path));
    }

    if (artifacts.items.len == 0) return error.MissingArtifactInput;
    try writeArchive(cwd, allocator, output_dir, artifacts.items);
}

fn parseArtifact(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    cwd: std.fs.Dir,
    path: []const u8,
) !Artifact {
    const bytes = try cwd.readFileAlloc(allocator, path, 16 * 1024 * 1024);
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
        .embedded_info = try inspectEmbeddedElf(bytes),
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
    cwd: std.fs.Dir,
    allocator: std.mem.Allocator,
    output_dir: []const u8,
    artifacts: []const Artifact,
) !void {
    try cwd.makePath(output_dir);
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const writer = &aw.writer;

    try writer.writeAll(
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
        \\pub const artifacts = [_]Artifact{
        \\
    );

    for (artifacts) |artifact| {
        const copied_bytes = try cwd.readFileAlloc(allocator, artifact.source_path, 16 * 1024 * 1024);
        defer allocator.free(copied_bytes);
        const copied_path = try std.fs.path.join(allocator, &.{ output_dir, artifact.embedded_name });
        defer allocator.free(copied_path);
        try cwd.writeFile(.{
            .sub_path = copied_path,
            .data = copied_bytes,
        });

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
        for (artifact.embedded_info.file_sha256, 0..) |byte, index| {
            if (index != 0) try writer.writeAll(", ");
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
        try writer.print("        .data = @embedFile(\"{f}\"),\n", .{std.zig.fmtString(artifact.embedded_name)});
        try writer.writeAll("    },\n");
    }

    try writer.writeAll("};\n");
    const output_path = try std.fs.path.join(allocator, &.{ output_dir, "userspace_archive.zig" });
    defer allocator.free(output_path);
    try cwd.writeFile(.{
        .sub_path = output_path,
        .data = aw.written(),
    });
}

fn inspectEmbeddedElf(elf_bytes: []const u8) !EmbeddedInfo {
    if (elf_bytes.len < @sizeOf(elf.Elf32_Ehdr)) return error.InvalidElfHeader;

    const header = try readStruct(elf.Elf32_Ehdr, elf_bytes, 0);
    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS32) return error.UnsupportedElfClass;
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != .@"386") return error.UnsupportedElfMachine;
    if (header.e_phentsize != @sizeOf(elf.Elf32_Phdr)) return error.InvalidProgramHeaderTable;

    const program_headers_end = @as(usize, header.e_phoff) +
        @as(usize, header.e_phentsize) * @as(usize, header.e_phnum);
    if (header.e_phoff == 0 or program_headers_end > elf_bytes.len) {
        return error.InvalidProgramHeaderTable;
    }

    var executable_image = ExecutableImageSpec{};
    executable_image.entry_point = header.e_entry;
    executable_image.stack_top = DEFAULT_USER_STACK_TOP;
    executable_image.stack_size_bytes = DEFAULT_USER_STACK_SIZE_BYTES;
    executable_image.file_size_bytes = elf_bytes.len;

    var loadable_segment_count: usize = 0;
    var offset: usize = header.e_phoff;
    var index: usize = 0;
    while (index < header.e_phnum) : (index += 1) {
        const program_header = try readStruct(elf.Elf32_Phdr, elf_bytes, offset);
        if (program_header.p_type == elf.PT_LOAD) {
            if (loadable_segment_count >= MAX_EXECUTABLE_SEGMENTS) {
                return error.TooManyLoadableSegments;
            }
            if (program_header.p_vaddr == 0 or program_header.p_memsz == 0) {
                return error.InvalidLoadableSegment;
            }
            if (program_header.p_filesz > program_header.p_memsz) return error.InvalidLoadableSegment;

            const segment_end = @as(usize, program_header.p_offset) + @as(usize, program_header.p_filesz);
            if (segment_end > elf_bytes.len) return error.InvalidLoadableSegment;

            executable_image.segments[loadable_segment_count] = .{
                .virtual_address = program_header.p_vaddr,
                .file_offset = program_header.p_offset,
                .file_size = @intCast(program_header.p_filesz),
                .memory_size = @intCast(program_header.p_memsz),
                .alignment = if (program_header.p_align == 0) 1 else program_header.p_align,
                .access = .{
                    .read = (program_header.p_flags & elf.PF_R) != 0,
                    .write = (program_header.p_flags & elf.PF_W) != 0,
                    .execute = (program_header.p_flags & elf.PF_X) != 0,
                },
            };
            loadable_segment_count += 1;
        }
        offset += @sizeOf(elf.Elf32_Phdr);
    }
    if (loadable_segment_count == 0) return error.MissingLoadableSegment;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(elf_bytes);
    hasher.final(&executable_image.file_sha256);
    executable_image.segment_count = loadable_segment_count;

    return .{
        .entry_point = header.e_entry,
        .byte_len = elf_bytes.len,
        .bootstrap_mailbox_address = findOptionalSectionAddress(
            elf_bytes,
            header,
            BOOTSTRAP_MAILBOX_SECTION_NAME,
        ) orelse 0,
        .file_sha256 = executable_image.file_sha256,
        .executable_image = executable_image,
    };
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

fn findOptionalSectionAddress(
    elf_bytes: []const u8,
    header: elf.Elf32_Ehdr,
    section_name: []const u8,
) ?u64 {
    const section_count: usize = header.e_shnum;
    if (header.e_shoff == 0 or header.e_shentsize != @sizeOf(elf.Elf32_Shdr)) return null;
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) return null;

    const section_headers_end = @as(usize, header.e_shoff) + @as(usize, header.e_shentsize) * section_count;
    if (section_headers_end > elf_bytes.len) return null;

    const names_header_offset = @as(usize, header.e_shoff) + @as(usize, header.e_shstrndx) * @sizeOf(elf.Elf32_Shdr);
    const names_header = readStruct(elf.Elf32_Shdr, elf_bytes, names_header_offset) catch return null;

    const names_start = @as(usize, names_header.sh_offset);
    const names_end = names_start + @as(usize, names_header.sh_size);
    if (names_end > elf_bytes.len) return null;
    const section_names = elf_bytes[names_start..names_end];

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section_offset = @as(usize, header.e_shoff) + index * @sizeOf(elf.Elf32_Shdr);
        const section = readStruct(elf.Elf32_Shdr, elf_bytes, section_offset) catch return null;
        const name = readOptionalSectionName(section_names, section.sh_name) orelse continue;
        if (std.mem.eql(u8, name, section_name)) return section.sh_addr;
    }
    return null;
}

fn readOptionalSectionName(section_names: []const u8, offset: u32) ?[]const u8 {
    if (offset >= section_names.len) return null;
    var end: usize = offset;
    while (end < section_names.len and section_names[end] != 0) : (end += 1) {}
    return section_names[offset..end];
}
