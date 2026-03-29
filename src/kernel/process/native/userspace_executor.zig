const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../boot/markers.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_loader = @import("userspace_loader.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const freestanding = if (builtin.target.os.tag == .freestanding)
    struct {
        pub const gdt = @import("../../interrupts/gdt.zig");
        pub const isr = @import("../../interrupts/isr.zig");
        pub const paging = @import("../../memory/paging.zig");
    }
else
    struct {
        pub const gdt = struct {
            pub fn setKernelStack(_: u32) void {}
        };

        pub const isr = struct {
            pub const InterruptFrame = opaque {};
            pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

            pub fn registerHandler(_: u8, _: InterruptHandler) void {}
        };

        pub const paging = struct {
            pub const PageDirectory = opaque {};
            pub const PAGE_PRESENT: u32 = 0;
            pub const PAGE_WRITABLE: u32 = 0;
            pub const PAGE_USER: u32 = 0;

            pub fn createUserPageDirectory() !*PageDirectory {
                return error.Unsupported;
            }

            pub fn getCurrentPageDirectory() *PageDirectory {
                unreachable;
            }

            pub fn switchPageDirectory(_: *PageDirectory) void {}
            pub fn alloc_frames(_: u32) ?u32 {
                return null;
            }
            pub fn map_range(_: u32, _: u32, _: u32, _: u32) void {}
            pub fn set_current_page_flags(_: u32, _: u32) void {}
        };
    };

const PAGE_SIZE: usize = 4096;
const USERSPACE_TRAP_VECTOR: u8 = 129;

pub export var zigos_userspace_resume_requested: u32 = 0;
pub export var zigos_userspace_resume_esp: u32 = 0;
pub export var zigos_userspace_resume_eip: u32 = 0;

extern fn zigos_enter_userspace(entry: u32, stack_top: u32) callconv(.c) u32;

const MappingEntry = struct {
    in_use: bool = false,
    address_space_id: u64 = 0,
    page_directory_ptr: usize = 0,
    resume_valid: bool = false,
    resume_instruction_pointer: u32 = 0,
    resume_stack_pointer: u32 = 0,
    yield_count: u64 = 0,
    last_user_counter: u32 = 0,

    fn pageDirectory(self: *const MappingEntry) *freestanding.paging.PageDirectory {
        return @ptrFromInt(self.page_directory_ptr);
    }
};

var initialized = false;
var probe_marker_printed = false;
var resume_marker_printed = false;
var active_task_id: u64 = 0;
var active_address_space_id: u64 = 0;
var kernel_page_directory_ptr: usize = 0;
var handoff_completed = false;
var mappings: [task_runtime.MAX_TASKS]MappingEntry = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS;
var userspace_kernel_stack: [16 * 1024]u8 align(16) = [_]u8{0} ** (16 * 1024);

pub fn init() void {
    if (builtin.target.os.tag != .freestanding or initialized) return;
    freestanding.isr.registerHandler(USERSPACE_TRAP_VECTOR, userspaceTrapHandler);
    initialized = true;
}

pub fn reset() void {
    initialized = false;
    probe_marker_printed = false;
    resume_marker_printed = false;
    active_task_id = 0;
    active_address_space_id = 0;
    kernel_page_directory_ptr = 0;
    handoff_completed = false;
    zigos_userspace_resume_requested = 0;
    zigos_userspace_resume_esp = 0;
    zigos_userspace_resume_eip = 0;
    mappings = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS;
}

pub fn executeTask(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    task_id: u64,
) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    init();

    const task = runtime.find(task_id) orelse return false;
    if (!task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return false;

    const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
    const image = catalog.findById(task.launch.image_id) orelse return false;
    if (image.elf_bytes.len == 0) return false;

    const mapping = ensureMaterialized(address_space, image) orelse return false;
    const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
    kernel_page_directory_ptr = @intFromPtr(kernel_page_directory);
    freestanding.gdt.setKernelStack(@truncate(trapStackTop()));
    const instruction_pointer = if (mapping.resume_valid)
        mapping.resume_instruction_pointer
    else
        @as(u32, @intCast(address_space.entry_point));
    const stack_pointer = if (mapping.resume_valid)
        mapping.resume_stack_pointer
    else
        @as(u32, @intCast(address_space.stack_pointer - 16));

    active_task_id = task_id;
    active_address_space_id = address_space.id;
    handoff_completed = false;
    zigos_userspace_resume_requested = 0;

    freestanding.paging.switchPageDirectory(mapping.pageDirectory());
    _ = zigos_enter_userspace(
        instruction_pointer,
        stack_pointer,
    );

    if (freestanding.paging.getCurrentPageDirectory() != kernel_page_directory) {
        freestanding.paging.switchPageDirectory(kernel_page_directory);
    }

    active_task_id = 0;
    active_address_space_id = 0;
    zigos_userspace_resume_requested = 0;

    if (handoff_completed and !probe_marker_printed) {
        common.printBootMarker(boot_markers.userspace_exec_probe_ok);
        probe_marker_printed = true;
    }
    if (handoff_completed and
        mapping.yield_count >= 2 and
        mapping.last_user_counter >= 2 and
        !resume_marker_printed)
    {
        common.printBootMarker("ZIGOS:USERSPACE:RESUME:OK");
        resume_marker_printed = true;
    }
    return handoff_completed;
}

fn userspaceTrapHandler(frame: *freestanding.isr.InterruptFrame) void {
    if (active_task_id == 0) return;

    if (findMapping(active_address_space_id)) |mapping| {
        mapping.resume_valid = true;
        mapping.resume_instruction_pointer = frame.eip;
        mapping.resume_stack_pointer = frame.useresp;
        mapping.yield_count += 1;
        mapping.last_user_counter = frame.eax;
    }

    handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    if (kernel_page_directory_ptr != 0) {
        freestanding.paging.switchPageDirectory(@ptrFromInt(kernel_page_directory_ptr));
    }
}

fn ensureMaterialized(
    address_space: *const task_runtime.AddressSpaceRecord,
    image: *const userspace_loader.ImageRecord,
) ?*MappingEntry {
    if (findMapping(address_space.id)) |entry| return entry;

    const page_directory = freestanding.paging.createUserPageDirectory() catch return null;
    const previous_directory = freestanding.paging.getCurrentPageDirectory();
    freestanding.paging.switchPageDirectory(page_directory);
    defer freestanding.paging.switchPageDirectory(previous_directory);

    for (address_space.regions[0..address_space.region_count]) |region| {
        switch (region.kind) {
            .load_segment => mapLoadRegion(region, image.elf_bytes) orelse return null,
            .stack => mapZeroedRegion(region.virtual_address, region.size_bytes, region.access) orelse return null,
        }
    }

    for (&mappings) |*entry| {
        if (entry.in_use) continue;
        entry.in_use = true;
        entry.address_space_id = address_space.id;
        entry.page_directory_ptr = @intFromPtr(page_directory);
        entry.resume_valid = false;
        entry.resume_instruction_pointer = 0;
        entry.resume_stack_pointer = 0;
        entry.yield_count = 0;
        entry.last_user_counter = 0;
        return entry;
    }
    return null;
}

fn mapLoadRegion(region: task_runtime.AddressSpaceRegionRecord, elf_bytes: []const u8) ?void {
    mapZeroedRegion(region.virtual_address, region.size_bytes, .{
        .read = true,
        .write = true,
    }) orelse return null;

    const start = region.file_offset;
    const end = start + region.file_size;
    if (end > elf_bytes.len) return null;

    const destination: [*]u8 = @ptrFromInt(@as(usize, @intCast(region.virtual_address)));
    @memcpy(destination[0..region.file_size], elf_bytes[start..end]);
    tightenRegionPermissions(region.virtual_address, region.size_bytes, region.access);
}

fn mapZeroedRegion(virtual_address: u64, size_bytes: usize, access: task_runtime.SegmentAccess) ?void {
    const page_count = divCeil(size_bytes, PAGE_SIZE);
    const physical_start = freestanding.paging.alloc_frames(@intCast(page_count)) orelse return null;
    const mapped_size = page_count * PAGE_SIZE;
    freestanding.paging.map_range(
        @intCast(virtual_address),
        physical_start,
        @intCast(mapped_size),
        freestanding.paging.PAGE_PRESENT |
            freestanding.paging.PAGE_USER |
            freestanding.paging.PAGE_WRITABLE,
    );

    const destination: [*]u8 = @ptrFromInt(@as(usize, @intCast(virtual_address)));
    @memset(destination[0..mapped_size], 0);
    tightenRegionPermissions(virtual_address, mapped_size, access);
}

fn tightenRegionPermissions(virtual_address: u64, size_bytes: usize, access: task_runtime.SegmentAccess) void {
    var flags: u32 = freestanding.paging.PAGE_PRESENT | freestanding.paging.PAGE_USER;
    if (access.write) flags |= freestanding.paging.PAGE_WRITABLE;

    var offset: usize = 0;
    while (offset < size_bytes) : (offset += PAGE_SIZE) {
        freestanding.paging.set_current_page_flags(@intCast(virtual_address + offset), flags);
    }
}

fn findMapping(address_space_id: u64) ?*MappingEntry {
    for (&mappings) |*entry| {
        if (entry.in_use and entry.address_space_id == address_space_id) return entry;
    }
    return null;
}

fn divCeil(value: usize, divisor: usize) usize {
    return (value + divisor - 1) / divisor;
}

fn trapStackTop() usize {
    return @intFromPtr(&userspace_kernel_stack) + userspace_kernel_stack.len;
}
