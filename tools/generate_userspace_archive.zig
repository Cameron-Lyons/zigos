const std = @import("std");
const elf = std.elf;
const userspace_descriptor = @import("userspace_descriptor");

const Artifact = struct {
    source_path: []const u8,
    embedded_name: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    publisher: []const u8,
    label: []const u8,
    entry: []const u8,
    component_class: u8,
    signed: bool,
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
        .signed = descriptor.signed != 0,
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
        \\pub const Artifact = struct {
        \\    bundle_id: []const u8,
        \\    display_name: []const u8,
        \\    publisher: []const u8,
        \\    label: []const u8,
        \\    entry: []const u8,
        \\    component_class: u8,
        \\    signed: bool,
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
        try writer.print("        .signed = {},\n", .{artifact.signed});
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
