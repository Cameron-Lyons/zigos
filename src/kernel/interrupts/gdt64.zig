pub const GdtPtr = extern struct {
    limit: u16,
    base: usize align(1),
};

pub const Tss = extern struct {
    reserved0: u32 = 0,
    rsp0: u64 align(1) = 0,
    rsp1: u64 align(1) = 0,
    rsp2: u64 align(1) = 0,
    reserved1: u64 align(1) = 0,
    ist1: u64 align(1) = 0,
    ist2: u64 align(1) = 0,
    ist3: u64 align(1) = 0,
    ist4: u64 align(1) = 0,
    ist5: u64 align(1) = 0,
    ist6: u64 align(1) = 0,
    ist7: u64 align(1) = 0,
    reserved2: u64 align(1) = 0,
    reserved3: u16 = 0,
    iomap_base: u16 = @sizeOf(Tss),
};

pub const KERNEL_CODE_SEG: u16 = 0x08;
pub const KERNEL_DATA_SEG: u16 = 0x10;
pub const USER_DATA_SEG: u16 = 0x18;
pub const USER_CODE_SEG: u16 = 0x20;
pub const TSS_SEG: u16 = 0x28;
pub const DOUBLE_FAULT_IST_INDEX: u3 = 1;

const NULL_DESCRIPTOR_INDEX = 0;
const KERNEL_CODE_DESCRIPTOR_INDEX = 1;
const KERNEL_DATA_DESCRIPTOR_INDEX = 2;
const USER_DATA_DESCRIPTOR_INDEX = 3;
const USER_CODE_DESCRIPTOR_INDEX = 4;
const TSS_DESCRIPTOR_LOW_INDEX = 5;
const TSS_DESCRIPTOR_HIGH_INDEX = 6;

const PRESENT: u8 = 0x80;
const DPL_USER: u8 = 0x60;
const SEGMENT: u8 = 0x10;
const EXECUTABLE: u8 = 0x08;
const RW: u8 = 0x02;
const ACCESSED: u8 = 0x01;
const AVAILABLE_TSS: u8 = 0x09;
const GRANULARITY: u4 = 0x8;
const LONG_MODE: u4 = 0x2;
const SIZE_32: u4 = 0x4;
const FLAT_SEGMENT_LIMIT: u20 = 0xFFFFF;
pub const DOUBLE_FAULT_STACK_GUARD_BYTES: usize = 4096;
pub const DOUBLE_FAULT_STACK_USABLE_BYTES: usize = 16 * 1024;
pub const DOUBLE_FAULT_STACK_TOTAL_BYTES: usize = DOUBLE_FAULT_STACK_GUARD_BYTES + DOUBLE_FAULT_STACK_USABLE_BYTES;
pub const DOUBLE_FAULT_STACK_ALIGNMENT: usize = DOUBLE_FAULT_STACK_GUARD_BYTES;
pub const DoubleFaultStackStorage = [DOUBLE_FAULT_STACK_TOTAL_BYTES]u8;

var gdt: [7]u64 align(8) = [_]u64{0} ** 7;
var gdt_ptr: GdtPtr = undefined;
var tss: Tss align(16) = .{};
var double_fault_stack: ?*align(DOUBLE_FAULT_STACK_ALIGNMENT) DoubleFaultStackStorage = null;

const KERNEL_CODE_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | SEGMENT | EXECUTABLE | RW | ACCESSED,
    GRANULARITY | LONG_MODE,
);
const KERNEL_DATA_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | SEGMENT | RW | ACCESSED,
    GRANULARITY | SIZE_32,
);
const USER_CODE_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | DPL_USER | SEGMENT | EXECUTABLE | RW | ACCESSED,
    GRANULARITY | LONG_MODE,
);
const USER_DATA_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | DPL_USER | SEGMENT | RW | ACCESSED,
    GRANULARITY | SIZE_32,
);

extern fn gdt_flush(gdt_ptr: *const GdtPtr) void;
extern fn tss_flush() void;

pub fn bindDoubleFaultStack(storage: *anyopaque) bool {
    if (double_fault_stack != null) return false;
    double_fault_stack = @ptrCast(@alignCast(storage));
    return true;
}

pub fn doubleFaultStackGuardAddress() usize {
    return @intFromPtr(doubleFaultStackStorage());
}

fn doubleFaultStackStorage() *align(DOUBLE_FAULT_STACK_ALIGNMENT) DoubleFaultStackStorage {
    return double_fault_stack orelse @panic("double-fault stack storage is not bound");
}

pub fn init() void {
    gdt[NULL_DESCRIPTOR_INDEX] = 0;
    gdt[KERNEL_CODE_DESCRIPTOR_INDEX] = KERNEL_CODE_DESCRIPTOR;
    gdt[KERNEL_DATA_DESCRIPTOR_INDEX] = KERNEL_DATA_DESCRIPTOR;
    gdt[USER_CODE_DESCRIPTOR_INDEX] = USER_CODE_DESCRIPTOR;
    gdt[USER_DATA_DESCRIPTOR_INDEX] = USER_DATA_DESCRIPTOR;

    tss = .{};
    configureDoubleFaultIst();
    writeTssDescriptor();

    gdt_ptr = .{
        .limit = @sizeOf(@TypeOf(gdt)) - 1,
        .base = @intFromPtr(&gdt),
    };
    gdt_flush(&gdt_ptr);
    tss_flush();
}

pub fn setKernelStack(stack: usize) void {
    tss.rsp0 = stack;
}

pub fn configureDoubleFaultIst() void {
    tss.ist1 = @intFromPtr(doubleFaultStackStorage()) + DOUBLE_FAULT_STACK_TOTAL_BYTES;
}

pub fn userDataDescriptor() u64 {
    return gdt[USER_DATA_DESCRIPTOR_INDEX];
}

pub fn userCodeDescriptor() u64 {
    return gdt[USER_CODE_DESCRIPTOR_INDEX];
}

fn segmentDescriptor(base: u32, limit: u20, access: u8, flags: u4) u64 {
    return @as(u64, limit & 0xFFFF) |
        (@as(u64, base & 0xFF_FFFF) << 16) |
        (@as(u64, access) << 40) |
        (@as(u64, (limit >> 16) & 0xF) << 48) |
        (@as(u64, flags) << 52) |
        (@as(u64, (base >> 24) & 0xFF) << 56);
}

fn writeTssDescriptor() void {
    const base: u64 = @intFromPtr(&tss);
    const limit: u20 = @sizeOf(Tss) - 1;
    gdt[TSS_DESCRIPTOR_LOW_INDEX] = segmentDescriptor(
        @truncate(base),
        limit,
        PRESENT | AVAILABLE_TSS,
        0,
    );
    gdt[TSS_DESCRIPTOR_HIGH_INDEX] = base >> 32;
}

comptime {
    if (@sizeOf(Tss) != 104) @compileError("x86-64 TSS must be 104 bytes");
    if (@sizeOf(GdtPtr) != 10) @compileError("x86-64 GDTR operand must be 10 bytes");
    if (@sizeOf(DoubleFaultStackStorage) != 20 * 1024 or
        DOUBLE_FAULT_STACK_USABLE_BYTES != 16 * 1024)
    {
        @compileError("double-fault stack must retain a guarded 16 KiB emergency capacity");
    }
    if (KERNEL_CODE_DESCRIPTOR != 0x00AF_9B00_0000_FFFF or
        KERNEL_DATA_DESCRIPTOR != 0x00CF_9300_0000_FFFF or
        USER_CODE_DESCRIPTOR != 0x00AF_FB00_0000_FFFF or
        USER_DATA_DESCRIPTOR != 0x00CF_F300_0000_FFFF)
    {
        @compileError("x86-64 flat descriptors must be valid without processor mutation");
    }
    if (segmentDescriptor(0, FLAT_SEGMENT_LIMIT, 0x9A, 0xA) != 0x00AF_9A00_0000_FFFF) {
        @compileError("x86-64 code descriptor encoding diverged from the hardware ABI");
    }
    if (segmentDescriptor(0x1234_5678, 103, 0x89, 0) != 0x1200_8934_5678_0067) {
        @compileError("x86-64 TSS descriptor encoding diverged from the hardware ABI");
    }
}
