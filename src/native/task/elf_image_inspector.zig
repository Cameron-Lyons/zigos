const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const embedded_file = @import("embedded_file.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");

pub const Inspection = struct {
    entry_point: u64,
    loadable_segment_count: u16,
    byte_len: usize,
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
    if (file.byte_len < @sizeOf(std.elf.Elf32_Ehdr)) return error.InvalidElfHeader;

    var header: std.elf.Elf32_Ehdr = undefined;
    if (!reader.readInto(0, std.mem.asBytes(&header))) return error.InvalidElfHeader;

    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS32) return error.UnsupportedElfClass;
    if (header.e_ident[std.elf.EI_DATA] != std.elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != .@"386") return error.UnsupportedElfMachine;
    if (header.e_phentsize != @sizeOf(std.elf.Elf32_Phdr)) return error.InvalidProgramHeaderTable;

    const program_headers_bytes = std.math.mul(
        usize,
        @as(usize, header.e_phentsize),
        @as(usize, header.e_phnum),
    ) catch return error.InvalidProgramHeaderTable;
    const program_headers_end = std.math.add(
        usize,
        @as(usize, header.e_phoff),
        program_headers_bytes,
    ) catch return error.InvalidProgramHeaderTable;
    if (header.e_phoff == 0 or program_headers_end > file.byte_len) {
        return error.InvalidProgramHeaderTable;
    }

    const bootstrap_mailbox_address = try findRequiredMailboxSectionAddress(
        reader,
        header,
        userspace_bootstrap_mailbox.SECTION_NAME,
    );

    var executable_image = task_runtime.ExecutableImageSpec{};
    executable_image.entry_point = header.e_entry;
    executable_image.bootstrap_mailbox_address = bootstrap_mailbox_address;
    executable_image.stack_top = task_runtime.DEFAULT_USER_STACK_TOP;
    executable_image.stack_size_bytes = task_runtime.DEFAULT_USER_STACK_SIZE_BYTES;
    executable_image.file_size_bytes = file.byte_len;

    var loadable_segment_count: usize = 0;
    var offset: usize = header.e_phoff;
    var index: usize = 0;
    while (index < header.e_phnum) : (index += 1) {
        var program_header: std.elf.Elf32_Phdr = undefined;
        const program_end = std.math.add(usize, offset, @sizeOf(std.elf.Elf32_Phdr)) catch
            return error.InvalidProgramHeaderTable;
        if (program_end > file.byte_len) return error.InvalidProgramHeaderTable;
        if (!reader.readInto(offset, std.mem.asBytes(&program_header))) return error.InvalidProgramHeaderTable;
        if (program_header.p_type == std.elf.PT_LOAD) {
            if (loadable_segment_count >= task_runtime.MAX_EXECUTABLE_SEGMENTS) {
                return error.TooManyLoadableSegments;
            }
            if (program_header.p_vaddr == 0 or program_header.p_memsz == 0) {
                return error.InvalidLoadableSegment;
            }
            if (program_header.p_filesz > program_header.p_memsz) return error.InvalidLoadableSegment;

            const segment_end = std.math.add(
                usize,
                @as(usize, program_header.p_offset),
                @as(usize, program_header.p_filesz),
            ) catch return error.InvalidLoadableSegment;
            if (segment_end > file.byte_len) return error.InvalidLoadableSegment;

            executable_image.segments[loadable_segment_count] = .{
                .virtual_address = program_header.p_vaddr,
                .file_offset = program_header.p_offset,
                .file_size = @intCast(program_header.p_filesz),
                .memory_size = @intCast(program_header.p_memsz),
                .alignment = if (program_header.p_align == 0) 1 else program_header.p_align,
                .access = .{
                    .read = (program_header.p_flags & std.elf.PF_R) != 0,
                    .write = (program_header.p_flags & std.elf.PF_W) != 0,
                    .execute = (program_header.p_flags & std.elf.PF_X) != 0,
                },
            };
            loadable_segment_count += 1;
        }
        offset = program_end;
    }
    if (loadable_segment_count == 0) return error.MissingLoadableSegment;
    executable_image.segment_count = loadable_segment_count;
    if (!mailboxFitsWritableLoad(&executable_image, bootstrap_mailbox_address)) {
        return error.InvalidBootstrapMailboxSection;
    }

    executable_image.file_sha256 = reader.sha256();

    return .{
        .entry_point = header.e_entry,
        .loadable_segment_count = @intCast(loadable_segment_count),
        .byte_len = file.byte_len,
        .bootstrap_mailbox_address = bootstrap_mailbox_address,
        .file_sha256 = executable_image.file_sha256,
        .executable_image = executable_image,
    };
}

fn findRequiredMailboxSectionAddress(
    reader: embedded_file.Reader,
    header: std.elf.Elf32_Ehdr,
    section_name: []const u8,
) Error!u64 {
    const section_count: usize = header.e_shnum;
    if (header.e_shoff == 0 or
        header.e_shentsize != @sizeOf(std.elf.Elf32_Shdr) or
        section_count == 0)
    {
        return error.InvalidSectionHeaderTable;
    }
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) {
        return error.InvalidSectionHeaderTable;
    }

    const section_headers_bytes = std.math.mul(usize, @as(usize, header.e_shentsize), section_count) catch
        return error.InvalidSectionHeaderTable;
    const section_headers_end = std.math.add(usize, @as(usize, header.e_shoff), section_headers_bytes) catch
        return error.InvalidSectionHeaderTable;
    if (section_headers_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;

    const names_header_delta = std.math.mul(usize, @as(usize, header.e_shstrndx), @sizeOf(std.elf.Elf32_Shdr)) catch
        return error.InvalidSectionHeaderTable;
    const names_header_offset = std.math.add(usize, @as(usize, header.e_shoff), names_header_delta) catch
        return error.InvalidSectionHeaderTable;
    const names_header_end = std.math.add(usize, names_header_offset, @sizeOf(std.elf.Elf32_Shdr)) catch
        return error.InvalidSectionHeaderTable;
    if (names_header_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;
    var names_header: std.elf.Elf32_Shdr = undefined;
    if (!reader.readInto(names_header_offset, std.mem.asBytes(&names_header))) return error.InvalidSectionHeaderTable;

    const names_start = @as(usize, names_header.sh_offset);
    const names_end = std.math.add(usize, names_start, @as(usize, names_header.sh_size)) catch
        return error.InvalidSectionHeaderTable;
    if (names_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section_delta = std.math.mul(usize, index, @sizeOf(std.elf.Elf32_Shdr)) catch
            return error.InvalidSectionHeaderTable;
        const section_offset = std.math.add(usize, @as(usize, header.e_shoff), section_delta) catch
            return error.InvalidSectionHeaderTable;
        const section_end = std.math.add(usize, section_offset, @sizeOf(std.elf.Elf32_Shdr)) catch
            return error.InvalidSectionHeaderTable;
        if (section_end > reader.file.byte_len) return error.InvalidSectionHeaderTable;
        var section: std.elf.Elf32_Shdr = undefined;
        if (!reader.readInto(section_offset, std.mem.asBytes(&section))) return error.InvalidSectionHeaderTable;
        if (!sectionNameEquals(reader, names_start, names_header.sh_size, section.sh_name, section_name)) continue;

        const required_flags: u32 = 0x1 | 0x2; // SHF_WRITE | SHF_ALLOC
        if (section.sh_addr == 0 or
            section.sh_size < userspace_bootstrap_mailbox.ABI_SIZE_BYTES or
            (section.sh_flags & required_flags) != required_flags)
        {
            return error.InvalidBootstrapMailboxSection;
        }
        const section_file_end = std.math.add(
            usize,
            @as(usize, section.sh_offset),
            @as(usize, section.sh_size),
        ) catch return error.InvalidBootstrapMailboxSection;
        if (section_file_end > reader.file.byte_len) return error.InvalidBootstrapMailboxSection;
        return section.sh_addr;
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
    names_len_raw: u32,
    offset_raw: u32,
    expected: []const u8,
) bool {
    const names_len: usize = names_len_raw;
    const offset: usize = offset_raw;
    if (offset >= names_len or expected.len >= names_len - offset) return false;
    for (expected, 0..) |byte, index| {
        const actual = reader.byteAt(names_start + offset + index) orelse return false;
        if (actual != byte) return false;
    }
    return (reader.byteAt(names_start + offset + expected.len) orelse return false) == 0;
}
