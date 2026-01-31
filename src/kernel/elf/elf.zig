// zlint-disable suppressed-errors
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const process = @import("../process/process.zig");
const vfs = @import("../fs/vfs.zig");
const dynamic = @import("dynamic.zig");

const ELF_MAGIC = 0x464C457F;

const ElfClass = enum(u8) {
    None = 0,
    ELF32 = 1,
    ELF64 = 2,
};

const ElfData = enum(u8) {
    None = 0,
    LittleEndian = 1,
    BigEndian = 2,
};

const ElfType = enum(u16) {
    None = 0,
    Relocatable = 1,
    Executable = 2,
    SharedObject = 3,
    Core = 4,
};

const ElfMachine = enum(u16) {
    None = 0,
    I386 = 3,
    AMD64 = 62,
};

const ProgramType = enum(u32) {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    Shlib = 5,
    Phdr = 6,
    TLS = 7,
};

const ProgramFlags = struct {
    const EXECUTE = 1;
    const WRITE = 2;
    const READ = 4;
};

const Elf32Header = packed struct {
    magic: u32,
    class: u8,
    data: u8,
    version: u8,
    osabi: u8,
    abiversion: u8,
    pad0: u8,
    pad1: u8,
    pad2: u8,
    pad3: u8,
    pad4: u8,
    pad5: u8,
    pad6: u8,
    type: u16,
    machine: u16,
    version2: u32,
    entry: u32,
    phoff: u32,
    shoff: u32,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};

const Elf32ProgramHeader = packed struct {
    type: u32,
    offset: u32,
    vaddr: u32,
    paddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
    alignment: u32,
};

pub const ElfLoadError = error{
    InvalidMagic,
    InvalidClass,
    InvalidEndianness,
    InvalidType,
    InvalidMachine,
    NoLoadableSegments,
    OutOfMemory,
    FileReadError,
    InvalidAlignment,
};

pub const LoadedElf = struct {
    entry_point: u32,
    base_addr: u32,
    size: u32,
};

fn validateElfHeader(header: *const Elf32Header) ElfLoadError!void {
    if (header.magic != ELF_MAGIC) {
        return ElfLoadError.InvalidMagic;
    }

    if (header.class != @intFromEnum(ElfClass.ELF32)) {
        return ElfLoadError.InvalidClass;
    }

    if (header.data != @intFromEnum(ElfData.LittleEndian)) {
        return ElfLoadError.InvalidEndianness;
    }

    if (header.type != @intFromEnum(ElfType.Executable) and header.type != @intFromEnum(ElfType.SharedObject)) {
        return ElfLoadError.InvalidType;
    }

    if (header.machine != @intFromEnum(ElfMachine.I386)) {
        return ElfLoadError.InvalidMachine;
    }
}

pub fn loadElfFromFile(path: []const u8) !LoadedElf {
    const file = vfs.open(path, vfs.O_RDONLY) catch {
        return ElfLoadError.FileReadError;
    };
    defer vfs.close(file) catch {};

    // SAFETY: Populated by vfs.read call below
    var header: Elf32Header = undefined;
    const bytes_read = vfs.read(file, @as([*]u8, @ptrCast(&header))[0..@sizeOf(Elf32Header)]) catch {
        return ElfLoadError.FileReadError;
    };

    if (bytes_read != @sizeOf(Elf32Header)) {
        return ElfLoadError.FileReadError;
    }

    try validateElfHeader(&header);

    var result = LoadedElf{
        .entry_point = header.entry,
        .base_addr = 0xFFFFFFFF,
        .size = 0,
    };

    var lowest_vaddr: u32 = 0xFFFFFFFF;
    var highest_vaddr: u32 = 0;
    var dynamic_vaddr: u32 = 0;
    var has_dynamic: bool = false;

    var ph_offset = header.phoff;
    var i: u16 = 0;
    while (i < header.phnum) : (i += 1) {
        // SAFETY: Populated by vfs.read call below
        var phdr: Elf32ProgramHeader = undefined;

        _ = vfs.lseek(file, @intCast(ph_offset), vfs.SEEK_SET) catch {
            return ElfLoadError.FileReadError;
        };

        const ph_read = vfs.read(file, @as([*]u8, @ptrCast(&phdr))[0..@sizeOf(Elf32ProgramHeader)]) catch {
            return ElfLoadError.FileReadError;
        };

        if (ph_read != @sizeOf(Elf32ProgramHeader)) {
            return ElfLoadError.FileReadError;
        }

        if (phdr.type == @intFromEnum(ProgramType.Load)) {
            if (phdr.vaddr < lowest_vaddr) {
                lowest_vaddr = phdr.vaddr;
            }
            if (phdr.vaddr + phdr.memsz > highest_vaddr) {
                highest_vaddr = phdr.vaddr + phdr.memsz;
            }

            if (!loadSegment(file, &phdr)) {
                return ElfLoadError.OutOfMemory;
            }
        } else if (phdr.type == @intFromEnum(ProgramType.Dynamic)) {
            dynamic_vaddr = phdr.vaddr;
            has_dynamic = true;
        }

        ph_offset += header.phentsize;
    }

    if (lowest_vaddr == 0xFFFFFFFF) {
        return ElfLoadError.NoLoadableSegments;
    }

    result.base_addr = lowest_vaddr;
    result.size = highest_vaddr - lowest_vaddr;

    if (has_dynamic and dynamic_vaddr != 0) {
        const dyn_ptr: [*]dynamic.Elf32Dyn = @ptrFromInt(dynamic_vaddr);
        dynamic.linkExecutable(dyn_ptr, lowest_vaddr) catch {};
    }

    return result;
}

fn loadSegment(file: u32, phdr: *const Elf32ProgramHeader) bool {
    const page_size = 0x1000;
    const start_page = phdr.vaddr & ~@as(u32, page_size - 1);
    const end_page = (phdr.vaddr + phdr.memsz + page_size - 1) & ~@as(u32, page_size - 1);
    const num_pages = (end_page - start_page) / page_size;

    var page_addr = start_page;
    var i: u32 = 0;
    while (i < num_pages) : (i += 1) {
        const phys_addr = memory.allocatePhysicalPage() orelse return false;

        var flags = paging.PAGE_PRESENT | paging.PAGE_USER;
        if (phdr.flags & ProgramFlags.WRITE != 0) {
            flags |= paging.PAGE_WRITABLE;
        }

        paging.mapPage(page_addr, phys_addr, flags);
        page_addr += page_size;
    }

    if (phdr.filesz > 0) {
        _ = vfs.lseek(file, @intCast(phdr.offset), vfs.SEEK_SET) catch return false;

        const dest: [*]u8 = @ptrFromInt(phdr.vaddr);
        const bytes_read = vfs.read(file, dest[0..phdr.filesz]) catch return false;

        if (bytes_read != phdr.filesz) {
            return false;
        }
    }

    if (phdr.memsz > phdr.filesz) {
        const zero_start = phdr.vaddr + phdr.filesz;
        const zero_size = phdr.memsz - phdr.filesz;
        const zero_dest: [*]u8 = @ptrFromInt(zero_start);
        @memset(zero_dest[0..zero_size], 0);
    }

    return true;
}

pub fn loadElfIntoProcess(proc: *process.Process, path: []const u8) !LoadedElf {
    const old_page_dir = paging.getCurrentPageDirectory();
    if (proc.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    }
    defer paging.switchPageDirectory(old_page_dir);

    const elf_info = try loadElfFromFile(path);

    proc.entry_point = @ptrFromInt(elf_info.entry_point);

    return elf_info;
}

pub fn execve(path: []const u8, argv: []const []const u8, envp: []const []const u8) !void {
    _ = argv;
    _ = envp;

    const current_proc = process.getCurrentProcess();
    if (current_proc == null) {
        return error.NoCurrentProcess;
    }

    const elf_info = try loadElfIntoProcess(current_proc.?, path);

    current_proc.?.entry_point = @ptrFromInt(elf_info.entry_point);

    const stack_top = 0xC0000000;
    const stack_size = 0x10000;
    const stack_bottom = stack_top - stack_size;

    var page_addr = stack_bottom;
    while (page_addr < stack_top) : (page_addr += 0x1000) {
        const phys_addr = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
        paging.mapPage(page_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    }

    current_proc.?.context.esp = stack_top - 16;
    current_proc.?.context.eip = @intFromPtr(current_proc.?.entry_point);

    process.switchToProcess(current_proc.?);
}