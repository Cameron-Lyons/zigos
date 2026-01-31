pub const GdtEntry = packed struct {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
};

pub const GdtPtr = packed struct {
    limit: u16,
    base: u32,
};

pub const Tss = packed struct {
    prev_tss: u32,
    esp0: u32,
    ss0: u32,
    esp1: u32,
    ss1: u32,
    esp2: u32,
    ss2: u32,
    cr3: u32,
    eip: u32,
    eflags: u32,
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
    esp: u32,
    ebp: u32,
    esi: u32,
    edi: u32,
    es: u32,
    cs: u32,
    ss: u32,
    ds: u32,
    fs: u32,
    gs: u32,
    ldt: u32,
    trap: u16,
    iomap_base: u16,
};

pub const KERNEL_CODE_SEG = 0x08;
pub const KERNEL_DATA_SEG = 0x10;
pub const USER_CODE_SEG = 0x18;
pub const USER_DATA_SEG = 0x20;
pub const TSS_SEG = 0x28;

const PRESENT = 0x80;
const DPL_USER = 0x60;
const SEGMENT = 0x10;
const EXECUTABLE = 0x08;
const RW = 0x02;
const ACCESSED = 0x01;

const GRANULARITY = 0x80;
const SIZE_32 = 0x40;

// SAFETY: fully initialized in init() via setGdtEntry calls
var gdt: [6]GdtEntry align(8) = undefined;
// SAFETY: fully initialized in init() before gdt_flush
var gdt_ptr: GdtPtr = undefined;
// SAFETY: fully initialized in init() before tss_flush
var tss: Tss align(8) = undefined;

extern fn gdt_flush(gdt_ptr: *const GdtPtr) void;
extern fn tss_flush() void;

pub fn init() void {
    setGdtEntry(0, 0, 0, 0, 0);

    setGdtEntry(1, 0, 0xFFFFF, PRESENT | SEGMENT | EXECUTABLE | RW, GRANULARITY | SIZE_32);

    setGdtEntry(2, 0, 0xFFFFF, PRESENT | SEGMENT | RW, GRANULARITY | SIZE_32);

    setGdtEntry(3, 0, 0xFFFFF, PRESENT | DPL_USER | SEGMENT | EXECUTABLE | RW, GRANULARITY | SIZE_32);

    setGdtEntry(4, 0, 0xFFFFF, PRESENT | DPL_USER | SEGMENT | RW, GRANULARITY | SIZE_32);

    writeTss(5, KERNEL_DATA_SEG, 0);

    gdt_ptr.limit = @sizeOf(@TypeOf(gdt)) - 1;
    gdt_ptr.base = @intFromPtr(&gdt);

    gdt_flush(&gdt_ptr);
    tss_flush();
}

fn setGdtEntry(num: usize, base: u32, limit: u32, access: u8, gran: u8) void {
    gdt[num].base_low = @truncate(base & 0xFFFF);
    gdt[num].base_middle = @truncate((base >> 16) & 0xFF);
    gdt[num].base_high = @truncate((base >> 24) & 0xFF);

    gdt[num].limit_low = @truncate(limit & 0xFFFF);
    gdt[num].granularity = @truncate((limit >> 16) & 0x0F);

    gdt[num].granularity |= gran & 0xF0;
    gdt[num].access = access;
}

fn writeTss(num: usize, ss0: u16, esp0: u32) void {
    const base = @intFromPtr(&tss);
    const limit = base + @sizeOf(Tss);

    setGdtEntry(num, base, limit, PRESENT | EXECUTABLE | ACCESSED, 0);

    @memset(@as([*]u8, @ptrCast(&tss))[0..@sizeOf(Tss)], 0);

    tss.ss0 = ss0;
    tss.esp0 = esp0;

    tss.cs = KERNEL_CODE_SEG | 0x3;
    tss.ds = KERNEL_DATA_SEG | 0x3;
    tss.es = KERNEL_DATA_SEG | 0x3;
    tss.fs = KERNEL_DATA_SEG | 0x3;
    tss.gs = KERNEL_DATA_SEG | 0x3;
}

pub fn setKernelStack(stack: u32) void {
    tss.esp0 = stack;
}

