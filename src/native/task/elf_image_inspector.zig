const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
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
    InvalidElfMagic,
    InvalidLoadableSegment,
    InvalidProgramHeaderTable,
    MissingLoadableSegment,
    TooManyLoadableSegments,
    UnsupportedElfClass,
    UnsupportedElfEndian,
    UnsupportedElfMachine,
};

pub fn inspect(elf_bytes: []const u8) Error!Inspection {
    if (elf_bytes.len < @sizeOf(std.elf.Elf32_Ehdr)) return error.InvalidElfHeader;

    var header: std.elf.Elf32_Ehdr = undefined;
    @memcpy(std.mem.asBytes(&header), elf_bytes[0..@sizeOf(std.elf.Elf32_Ehdr)]);

    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
    if (header.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS32) return error.UnsupportedElfClass;
    if (header.e_ident[std.elf.EI_DATA] != std.elf.ELFDATA2LSB) return error.UnsupportedElfEndian;
    if (header.e_machine != .@"386") return error.UnsupportedElfMachine;
    if (header.e_phentsize != @sizeOf(std.elf.Elf32_Phdr)) return error.InvalidProgramHeaderTable;

    const program_headers_end = @as(usize, header.e_phoff) +
        @as(usize, header.e_phentsize) * @as(usize, header.e_phnum);
    if (header.e_phoff == 0 or program_headers_end > elf_bytes.len) {
        return error.InvalidProgramHeaderTable;
    }

    const bootstrap_mailbox_address = findOptionalSectionAddress(
        elf_bytes,
        header,
        userspace_bootstrap_mailbox.SECTION_NAME,
    ) orelse 0;

    var executable_image = task_runtime.ExecutableImageSpec{};
    executable_image.entry_point = header.e_entry;
    executable_image.stack_top = task_runtime.DEFAULT_USER_STACK_TOP;
    executable_image.stack_size_bytes = task_runtime.DEFAULT_USER_STACK_SIZE_BYTES;
    executable_image.file_size_bytes = elf_bytes.len;

    var loadable_segment_count: usize = 0;
    var offset: usize = header.e_phoff;
    var index: usize = 0;
    while (index < header.e_phnum) : (index += 1) {
        var program_header: std.elf.Elf32_Phdr = undefined;
        @memcpy(
            std.mem.asBytes(&program_header),
            elf_bytes[offset..][0..@sizeOf(std.elf.Elf32_Phdr)],
        );
        if (program_header.p_type == std.elf.PT_LOAD) {
            if (loadable_segment_count >= task_runtime.MAX_EXECUTABLE_SEGMENTS) {
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
                    .read = (program_header.p_flags & std.elf.PF_R) != 0,
                    .write = (program_header.p_flags & std.elf.PF_W) != 0,
                    .execute = (program_header.p_flags & std.elf.PF_X) != 0,
                },
            };
            loadable_segment_count += 1;
        }
        offset += @sizeOf(std.elf.Elf32_Phdr);
    }
    if (loadable_segment_count == 0) return error.MissingLoadableSegment;

    var hasher = crypto_hash.init();
    hasher.update(elf_bytes);

    executable_image.segment_count = loadable_segment_count;
    executable_image.file_sha256 = crypto_hash.finalize(&hasher);

    return .{
        .entry_point = header.e_entry,
        .loadable_segment_count = @intCast(loadable_segment_count),
        .byte_len = elf_bytes.len,
        .bootstrap_mailbox_address = bootstrap_mailbox_address,
        .file_sha256 = executable_image.file_sha256,
        .executable_image = executable_image,
    };
}

fn findOptionalSectionAddress(
    elf_bytes: []const u8,
    header: std.elf.Elf32_Ehdr,
    section_name: []const u8,
) ?u64 {
    const section_count: usize = header.e_shnum;
    if (header.e_shoff == 0 or header.e_shentsize != @sizeOf(std.elf.Elf32_Shdr)) return null;
    if (header.e_shstrndx == 0 or header.e_shstrndx >= section_count) return null;

    const section_headers_end = @as(usize, header.e_shoff) + @as(usize, header.e_shentsize) * section_count;
    if (section_headers_end > elf_bytes.len) return null;

    const names_header_offset = @as(usize, header.e_shoff) + @as(usize, header.e_shstrndx) * @sizeOf(std.elf.Elf32_Shdr);
    var names_header: std.elf.Elf32_Shdr = undefined;
    @memcpy(std.mem.asBytes(&names_header), elf_bytes[names_header_offset..][0..@sizeOf(std.elf.Elf32_Shdr)]);

    const names_start = @as(usize, names_header.sh_offset);
    const names_end = names_start + @as(usize, names_header.sh_size);
    if (names_end > elf_bytes.len) return null;
    const section_names = elf_bytes[names_start..names_end];

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const section_offset = @as(usize, header.e_shoff) + index * @sizeOf(std.elf.Elf32_Shdr);
        var section: std.elf.Elf32_Shdr = undefined;
        @memcpy(std.mem.asBytes(&section), elf_bytes[section_offset..][0..@sizeOf(std.elf.Elf32_Shdr)]);
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
