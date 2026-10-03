const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const embedded_file = @import("embedded_file.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_layout = @import("../core/userspace_layout.zig");

pub const Inspection = struct {
    entry_point: u64,
    loadable_segment_count: u16,
    byte_len: task_runtime.UserImageByteLength,
    bootstrap_mailbox_address: u64,
    file_sha256: crypto_hash.Digest,
    executable_image: task_runtime.ExecutableImageSpec,
};

pub const Error = error{
    InvalidElfHeader,
    InvalidEmbeddedFile,
    InvalidElfMagic,
    InvalidLoadableSegment,
    InvalidProgramHeaderTable,
    InvalidSectionHeaderTable,
    MissingLoadableSegment,
    MissingBootstrapMailbox,
    InvalidBootstrapMailboxSection,
    TooManyLoadableSegments,
    UnsupportedElfClass,
    UnsupportedElfEndian,
    UnsupportedElfMachine,
};

pub fn inspect(elf_bytes: []const u8) Error!Inspection {
    return inspectFile(embedded_file.File.fromBytes(elf_bytes));
}

pub fn inspectFile(file: embedded_file.File) Error!Inspection {
    const reader = file.reader() orelse return error.InvalidEmbeddedFile;
    if (file.byte_len < std.elf.EI.NIDENT) return error.InvalidElfHeader;
    var ident: std.elf.Ident = undefined;
    if (!reader.readInto(0, std.mem.asBytes(&ident))) return error.InvalidElfHeader;
    if (!std.mem.eql(u8, &ident.magic, std.elf.MAGIC)) return error.InvalidElfMagic;
    if (ident.class != .@"64") return error.UnsupportedElfClass;
    if (ident.data != .@"2LSB") return error.UnsupportedElfEndian;

    return inspectTyped(
        std.elf.Elf64.Ehdr,
        std.elf.Elf64.Phdr,
        std.elf.Elf64.Shdr,
        reader,
        file,
        .@"64",
        .X86_64,
    );
}

fn inspectTyped(
    comptime Header: type,
    comptime ProgramHeader: type,
    comptime SectionHeader: type,
    reader: embedded_file.Reader,
    file: embedded_file.File,
    expected_class: std.elf.CLASS,
    expected_machine: std.elf.EM,
) Error!Inspection {
    if (file.byte_len < @sizeOf(Header)) return error.InvalidElfHeader;

    var header: Header = undefined;
    if (!reader.readInto(0, std.mem.asBytes(&header))) return error.InvalidElfHeader;
    if (!std.mem.eql(u8, &header.ident.magic, std.elf.MAGIC)) return error.InvalidElfMagic;
    if (header.ident.class != expected_class) return error.UnsupportedElfClass;
    if (header.ident.data != .@"2LSB") return error.UnsupportedElfEndian;
    if (header.machine != expected_machine) return error.UnsupportedElfMachine;
    if (header.phentsize != @sizeOf(ProgramHeader)) return error.InvalidProgramHeaderTable;

    const program_headers_bytes = std.math.mul(
        usize,
        @as(usize, header.phentsize),
        @as(usize, header.phnum),
    ) catch return error.InvalidProgramHeaderTable;
    const program_headers_offset = std.math.cast(usize, header.phoff) orelse
        return error.InvalidProgramHeaderTable;
    const program_headers_end = std.math.add(usize, program_headers_offset, program_headers_bytes) catch
        return error.InvalidProgramHeaderTable;
    if (program_headers_offset == 0 or program_headers_end > file.byte_len) {
        return error.InvalidProgramHeaderTable;
    }

    const bootstrap_mailbox_address = try findRequiredMailboxSectionAddress(
        SectionHeader,
        reader,
        header,
        userspace_bootstrap_mailbox.SECTION_NAME,
    );

    var executable_image = task_runtime.ExecutableImageSpec{};
    executable_image.entry_point = @intCast(header.entry);
    executable_image.bootstrap_mailbox_address = bootstrap_mailbox_address;
    executable_image.stack_top = task_runtime.DEFAULT_USER_STACK_TOP;
    executable_image.stack_size_bytes = task_runtime.DEFAULT_USER_STACK_SIZE_BYTES;
    executable_image.file_size_bytes = file.byte_len;

    var loadable_segment_count: usize = 0;
    var offset = program_headers_offset;
    var index: usize = 0;
    while (index < header.phnum) : (index += 1) {
        var program_header: ProgramHeader = undefined;
        const program_end = std.math.add(usize, offset, @sizeOf(ProgramHeader)) catch
            return error.InvalidProgramHeaderTable;
        if (program_end > file.byte_len) return error.InvalidProgramHeaderTable;
        if (!reader.readInto(offset, std.mem.asBytes(&program_header))) return error.InvalidProgramHeaderTable;
        if (program_header.type == .LOAD) {
            if (loadable_segment_count >= task_runtime.MAX_EXECUTABLE_SEGMENTS) {
                return error.TooManyLoadableSegments;
            }
            if (program_header.vaddr == 0 or program_header.memsz == 0) {
                return error.InvalidLoadableSegment;
            }
            if (program_header.filesz > program_header.memsz) return error.InvalidLoadableSegment;

            const segment_offset = std.math.cast(usize, program_header.offset) orelse
                return error.InvalidLoadableSegment;
            const segment_file_size = std.math.cast(usize, program_header.filesz) orelse
                return error.InvalidLoadableSegment;
            const segment_end = std.math.add(usize, segment_offset, segment_file_size) catch
                return error.InvalidLoadableSegment;
            if (segment_end > file.byte_len) return error.InvalidLoadableSegment;

            executable_image.segments[loadable_segment_count] = .{
                .virtual_address = @intCast(program_header.vaddr),
                .file_offset = std.math.cast(u32, program_header.offset) orelse return error.InvalidLoadableSegment,
                .file_size = std.math.cast(u32, program_header.filesz) orelse return error.InvalidLoadableSegment,
                .memory_size = std.math.cast(u32, program_header.memsz) orelse return error.InvalidLoadableSegment,
                .alignment = std.math.cast(
                    u32,
                    @max(@as(u64, userspace_layout.page_size), @as(u64, program_header.@"align")),
                ) orelse return error.InvalidLoadableSegment,
                .access = .{
                    .read = program_header.flags.R,
                    .write = program_header.flags.W,
                    .execute = program_header.flags.X,
                },
            };
            loadable_segment_count += 1;
        }
        offset = program_end;
    }
    if (loadable_segment_count == 0) return error.MissingLoadableSegment;
    executable_image.segment_count = @intCast(loadable_segment_count);
    if (!mailboxFitsWritableLoad(&executable_image, bootstrap_mailbox_address)) {
        return error.InvalidBootstrapMailboxSection;
    }

    executable_image.file_sha256 = reader.sha256();

    return .{
        .entry_point = @intCast(header.entry),
        .loadable_segment_count = @intCast(loadable_segment_count),
        .byte_len = file.byte_len,
        .bootstrap_mailbox_address = bootstrap_mailbox_address,
        .file_sha256 = executable_image.file_sha256,
        .executable_image = executable_image,
    };
}

fn findRequiredMailboxSectionAddress(
    comptime SectionHeader: type,
    reader: embedded_file.Reader,
    header: anytype,
    section_name: []const u8,
) Error!u64 {
    const section_count: usize = header.shnum;
    if (header.shoff == 0 or
        header.shentsize != @sizeOf(SectionHeader) or
        section_count == 0)
    {
        return error.InvalidSectionHeaderTable;
    }
    if (header.shstrndx == 0 or header.shstrndx >= section_count) {
        return error.InvalidSectionHeaderTable;
    }

    const section_headers_bytes = std.math.mul(usize, @as(usize, header.shentsize), section_count) catch
        return error.InvalidSectionHeaderTable;
    const section_headers_offset = std.math.cast(usize, header.shoff) orelse
        return error.InvalidSectionHeaderTable;
    const section_headers_end = std.math.add(usize, section_headers_offset, section_headers_bytes) catch
        return error.InvalidSectionHeaderTable;
    if (section_headers_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;

    const names_header_delta = std.math.mul(usize, @as(usize, header.shstrndx), @sizeOf(SectionHeader)) catch
        return error.InvalidSectionHeaderTable;
    const names_header_offset = std.math.add(usize, section_headers_offset, names_header_delta) catch
        return error.InvalidSectionHeaderTable;
    const names_header_end = std.math.add(usize, names_header_offset, @sizeOf(SectionHeader)) catch
        return error.InvalidSectionHeaderTable;
    if (names_header_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;
    var names_header: SectionHeader = undefined;
    if (!reader.readInto(names_header_offset, std.mem.asBytes(&names_header))) return error.InvalidSectionHeaderTable;

    const names_start = std.math.cast(usize, names_header.offset) orelse
        return error.InvalidSectionHeaderTable;
    const names_len = std.math.cast(usize, names_header.size) orelse
        return error.InvalidSectionHeaderTable;
    const names_end = std.math.add(usize, names_start, names_len) catch
        return error.InvalidSectionHeaderTable;
    if (names_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section_delta = std.math.mul(usize, index, @sizeOf(SectionHeader)) catch
            return error.InvalidSectionHeaderTable;
        const section_offset = std.math.add(usize, section_headers_offset, section_delta) catch
            return error.InvalidSectionHeaderTable;
        const section_end = std.math.add(usize, section_offset, @sizeOf(SectionHeader)) catch
            return error.InvalidSectionHeaderTable;
        if (section_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;
        var section: SectionHeader = undefined;
        if (!reader.readInto(section_offset, std.mem.asBytes(&section))) return error.InvalidSectionHeaderTable;
        if (!sectionNameEquals(reader, names_start, names_len, section.name, section_name)) continue;

        if (section.addr == 0 or
            section.size < userspace_bootstrap_mailbox.ABI_SIZE_BYTES or
            !section.flags.shf.WRITE or
            !section.flags.shf.ALLOC)
        {
            return error.InvalidBootstrapMailboxSection;
        }
        const section_file_offset = std.math.cast(usize, section.offset) orelse
            return error.InvalidBootstrapMailboxSection;
        const section_file_size = std.math.cast(usize, section.size) orelse
            return error.InvalidBootstrapMailboxSection;
        const section_file_end = std.math.add(usize, section_file_offset, section_file_size) catch
            return error.InvalidBootstrapMailboxSection;
        if (section_file_end > reader.file.byte_len) return error.InvalidBootstrapMailboxSection;
        return @intCast(section.addr);
    }
    return error.MissingBootstrapMailbox;
}

fn mailboxFitsWritableLoad(image: *const task_runtime.ExecutableImageSpec, mailbox_address: u64) bool {
    const mailbox_end = std.math.add(
        u64,
        mailbox_address,
        userspace_bootstrap_mailbox.ABI_SIZE_BYTES,
    ) catch return false;
    for (image.segments[0..image.segment_count]) |segment| {
        if (!segment.access.write) continue;
        const segment_end = std.math.add(u64, segment.virtual_address, segment.memory_size) catch continue;
        if (mailbox_address >= segment.virtual_address and mailbox_end <= segment_end) return true;
    }
    return false;
}

fn sectionNameEquals(
    reader: embedded_file.Reader,
    names_start: usize,
    names_len: usize,
    offset_raw: u32,
    expected: []const u8,
) bool {
    const offset: usize = offset_raw;
    if (offset >= names_len or expected.len >= names_len - offset) return false;
    for (expected, 0..) |byte, index| {
        const actual = reader.byteAt(names_start + offset + index) orelse return false;
        if (actual != byte) return false;
    }
    return (reader.byteAt(names_start + offset + expected.len) orelse return false) == 0;
}
