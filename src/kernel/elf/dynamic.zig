const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const vfs = @import("../fs/vfs.zig");
const vga = @import("../drivers/vga.zig");

const DT_NULL: i32 = 0;
const DT_NEEDED: i32 = 1;
const DT_PLTRELSZ: i32 = 2;
const DT_PLTGOT: i32 = 3;
const DT_HASH: i32 = 4;
const DT_STRTAB: i32 = 5;
const DT_SYMTAB: i32 = 6;
const DT_RELA: i32 = 7;
const DT_RELASZ: i32 = 8;
const DT_RELAENT: i32 = 9;
const DT_STRSZ: i32 = 10;
const DT_SYMENT: i32 = 11;
const DT_REL: i32 = 17;
const DT_RELSZ: i32 = 18;
const DT_RELENT: i32 = 19;
const DT_PLTREL: i32 = 20;
const DT_JMPREL: i32 = 23;

const R_386_NONE: u8 = 0;
const R_386_32: u8 = 1;
const R_386_PC32: u8 = 2;
const R_386_GLOB_DAT: u8 = 6;
const R_386_JMP_SLOT: u8 = 7;
const R_386_RELATIVE: u8 = 8;

pub const Elf32Dyn = packed struct {
    tag: i32,
    val: u32,
};

pub const Elf32Sym = packed struct {
    name: u32,
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    shndx: u16,
};

pub const Elf32Rel = packed struct {
    offset: u32,
    info: u32,

    fn getType(self: *const Elf32Rel) u8 {
        return @intCast(self.info & 0xFF);
    }

    fn getSym(self: *const Elf32Rel) u32 {
        return self.info >> 8;
    }
};

pub const Elf32Rela = packed struct {
    offset: u32,
    info: u32,
    addend: i32,

    fn getType(self: *const Elf32Rela) u8 {
        return @intCast(self.info & 0xFF);
    }

    fn getSym(self: *const Elf32Rela) u32 {
        return self.info >> 8;
    }
};

pub const SharedObject = struct {
    base_addr: u32,
    dynamic: ?[*]Elf32Dyn,
    strtab: ?[*]const u8,
    symtab: ?[*]Elf32Sym,
    strtab_size: u32,
    symtab_entry_size: u32,
    name: [64]u8,
    loaded: bool,
};

const MAX_LOADED_OBJECTS = 16;
var loaded_objects: [MAX_LOADED_OBJECTS]SharedObject = [_]SharedObject{SharedObject{
    .base_addr = 0,
    .dynamic = null,
    .strtab = null,
    .symtab = null,
    .strtab_size = 0,
    .symtab_entry_size = 0,
    .name = [_]u8{0} ** 64,
    .loaded = false,
}} ** MAX_LOADED_OBJECTS;

var num_loaded: u8 = 0;

const ELF_MAGIC = 0x464C457F;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

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
    elf_type: u16,
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
    p_type: u32,
    offset: u32,
    vaddr: u32,
    paddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
    alignment: u32,
};

pub fn loadSharedObject(path: []const u8, base: u32) !*SharedObject {
    if (num_loaded >= MAX_LOADED_OBJECTS) return error.TooManyObjects;

    const file = vfs.open(path, vfs.O_RDONLY) catch return error.FileNotFound;
    defer vfs.close(file) catch {};

    // SAFETY: populated by vfs.read call below
    var header: Elf32Header = undefined;
    const bytes_read = vfs.read(file, @as([*]u8, @ptrCast(&header))[0..@sizeOf(Elf32Header)]) catch return error.ReadError;
    if (bytes_read != @sizeOf(Elf32Header)) return error.ReadError;

    if (header.magic != ELF_MAGIC) return error.InvalidELF;
    if (header.elf_type != ET_DYN and header.elf_type != 2) return error.NotSharedObject;

    var dynamic_phdr: ?Elf32ProgramHeader = null;
    var ph_offset = header.phoff;
    var i: u16 = 0;
    while (i < header.phnum) : (i += 1) {
        // SAFETY: populated by vfs.read call below
        var phdr: Elf32ProgramHeader = undefined;
        _ = vfs.lseek(file, @intCast(ph_offset), vfs.SEEK_SET) catch return error.ReadError;
        const ph_read = vfs.read(file, @as([*]u8, @ptrCast(&phdr))[0..@sizeOf(Elf32ProgramHeader)]) catch return error.ReadError;
        if (ph_read != @sizeOf(Elf32ProgramHeader)) return error.ReadError;

        if (phdr.p_type == PT_LOAD) {
            const page_size: u32 = 0x1000;
            const vaddr = base + phdr.vaddr;
            const start_page = vaddr & ~@as(u32, page_size - 1);
            const end_page = (vaddr + phdr.memsz + page_size - 1) & ~@as(u32, page_size - 1);
            var page_addr = start_page;
            while (page_addr < end_page) : (page_addr += page_size) {
                const phys = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
                paging.mapPage(page_addr, phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
            }

            if (phdr.filesz > 0) {
                _ = vfs.lseek(file, @intCast(phdr.offset), vfs.SEEK_SET) catch return error.ReadError;
                const dest: [*]u8 = @ptrFromInt(vaddr);
                _ = vfs.read(file, dest[0..phdr.filesz]) catch return error.ReadError;
            }

            if (phdr.memsz > phdr.filesz) {
                const zero_dest: [*]u8 = @ptrFromInt(vaddr + phdr.filesz);
                @memset(zero_dest[0 .. phdr.memsz - phdr.filesz], 0);
            }
        } else if (phdr.p_type == PT_DYNAMIC) {
            dynamic_phdr = phdr;
        }

        ph_offset += header.phentsize;
    }

    const obj = &loaded_objects[num_loaded];
    obj.base_addr = base;
    obj.loaded = true;

    @memset(&obj.name, 0);
    const name_len = @min(path.len, obj.name.len - 1);
    @memcpy(obj.name[0..name_len], path[0..name_len]);

    if (dynamic_phdr) |dyn_phdr| {
        obj.dynamic = @ptrFromInt(base + dyn_phdr.vaddr);
        parseDynamic(obj);
    }

    num_loaded += 1;
    return obj;
}

fn parseDynamic(obj: *SharedObject) void {
    const dyn = obj.dynamic orelse return;

    var idx: usize = 0;
    while (true) : (idx += 1) {
        const entry = dyn[idx];
        if (entry.tag == DT_NULL) break;

        switch (entry.tag) {
            DT_STRTAB => obj.strtab = @ptrFromInt(obj.base_addr + entry.val),
            DT_SYMTAB => obj.symtab = @ptrFromInt(obj.base_addr + entry.val),
            DT_STRSZ => obj.strtab_size = entry.val,
            DT_SYMENT => obj.symtab_entry_size = entry.val,
            else => {},
        }
    }
}

pub fn resolveSymbol(name: []const u8) ?u32 {
    for (&loaded_objects) |*obj| {
        if (!obj.loaded) continue;

        const symtab = obj.symtab orelse continue;
        const strtab = obj.strtab orelse continue;

        if (obj.symtab_entry_size == 0) continue;

        var idx: usize = 0;
        while (idx < 1024) : (idx += 1) {
            const sym = symtab[idx];
            if (sym.name == 0) continue;
            if (sym.shndx == 0) continue;

            if (sym.name < obj.strtab_size) {
                const sym_name_ptr = strtab + sym.name;
                var sym_name_len: usize = 0;
                while (sym_name_len < 256 and sym_name_ptr[sym_name_len] != 0) : (sym_name_len += 1) {}

                if (sym_name_len == name.len) {
                    var match = true;
                    for (0..name.len) |j| {
                        if (sym_name_ptr[j] != name[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        return obj.base_addr + sym.value;
                    }
                }
            }
        }
    }
    return null;
}

pub fn processRelocations(obj: *SharedObject) !void {
    const dyn = obj.dynamic orelse return;

    var rel_addr: u32 = 0;
    var rel_size: u32 = 0;
    var jmprel_addr: u32 = 0;
    var jmprel_size: u32 = 0;

    var idx: usize = 0;
    while (true) : (idx += 1) {
        const entry = dyn[idx];
        if (entry.tag == DT_NULL) break;

        switch (entry.tag) {
            DT_REL => rel_addr = entry.val,
            DT_RELSZ => rel_size = entry.val,
            DT_JMPREL => jmprel_addr = entry.val,
            DT_PLTRELSZ => jmprel_size = entry.val,
            else => {},
        }
    }

    if (rel_addr != 0 and rel_size > 0) {
        try applyRelocations(obj, obj.base_addr + rel_addr, rel_size);
    }

    if (jmprel_addr != 0 and jmprel_size > 0) {
        try applyRelocations(obj, obj.base_addr + jmprel_addr, jmprel_size);
    }
}

fn applyRelocations(obj: *SharedObject, rel_table: u32, rel_size: u32) !void {
    const num_entries = rel_size / @sizeOf(Elf32Rel);
    const rels: [*]const Elf32Rel = @ptrFromInt(rel_table);

    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const rel = &rels[i];
        const target: *u32 = @ptrFromInt(obj.base_addr + rel.offset);

        switch (rel.getType()) {
            R_386_RELATIVE => {
                target.* += obj.base_addr;
            },
            R_386_GLOB_DAT, R_386_JMP_SLOT => {
                const sym_idx = rel.getSym();
                if (obj.symtab) |symtab| {
                    const sym = symtab[sym_idx];
                    if (sym.shndx != 0) {
                        target.* = obj.base_addr + sym.value;
                    } else if (obj.strtab) |strtab| {
                        if (sym.name < obj.strtab_size) {
                            const name_ptr = strtab + sym.name;
                            var name_len: usize = 0;
                            while (name_len < 256 and name_ptr[name_len] != 0) : (name_len += 1) {}
                            if (resolveSymbol(name_ptr[0..name_len])) |addr| {
                                target.* = addr;
                            }
                        }
                    }
                }
            },
            R_386_32 => {
                const sym_idx = rel.getSym();
                if (obj.symtab) |symtab| {
                    const sym = symtab[sym_idx];
                    target.* += obj.base_addr + sym.value;
                }
            },
            R_386_PC32 => {
                const sym_idx = rel.getSym();
                if (obj.symtab) |symtab| {
                    const sym = symtab[sym_idx];
                    target.* += obj.base_addr + sym.value - (obj.base_addr + rel.offset);
                }
            },
            else => {},
        }
    }
}

pub fn linkExecutable(exe_dynamic: [*]Elf32Dyn, exe_base: u32) !void {
    var exe_obj = SharedObject{
        .base_addr = exe_base,
        .dynamic = exe_dynamic,
        .strtab = null,
        .symtab = null,
        .strtab_size = 0,
        .symtab_entry_size = 0,
        .name = [_]u8{0} ** 64,
        .loaded = true,
    };

    parseDynamic(&exe_obj);

    const dyn = exe_dynamic;
    var idx: usize = 0;
    while (true) : (idx += 1) {
        const entry = dyn[idx];
        if (entry.tag == DT_NULL) break;

        if (entry.tag == DT_NEEDED) {
            if (exe_obj.strtab) |strtab| {
                if (entry.val < exe_obj.strtab_size) {
                    const name_ptr = strtab + entry.val;
                    var name_len: usize = 0;
                    while (name_len < 256 and name_ptr[name_len] != 0) : (name_len += 1) {}

                    // SAFETY: filled by the following memcpy call
                    var path_buf: [256]u8 = undefined;
                    const prefix = "/lib/";
                    @memcpy(path_buf[0..prefix.len], prefix);
                    @memcpy(path_buf[prefix.len .. prefix.len + name_len], name_ptr[0..name_len]);

                    const lib_base: u32 = 0x40000000 + @as(u32, num_loaded) * 0x400000;
                    _ = loadSharedObject(path_buf[0 .. prefix.len + name_len], lib_base) catch continue;
                }
            }
        }
    }

    for (&loaded_objects) |*obj| {
        if (obj.loaded) {
            processRelocations(obj) catch {};
        }
    }

    if (num_loaded < MAX_LOADED_OBJECTS) {
        loaded_objects[num_loaded] = exe_obj;
        num_loaded += 1;
    }

    processRelocations(&loaded_objects[num_loaded - 1]) catch {};
}
