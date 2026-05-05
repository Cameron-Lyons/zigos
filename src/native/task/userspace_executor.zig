const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const task_runtime = @import("task_runtime.zig");
const native_util = @import("../core/util.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_loader = @import("userspace_loader.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const freestanding = if (builtin.target.os.tag == .freestanding)
    struct {
        pub const gdt = @import("../../kernel/interrupts/gdt.zig");
        pub const isr = @import("../../kernel/interrupts/isr.zig");
        pub const paging = @import("../../kernel/memory/paging.zig");
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
                native_util.impossibleByInvariant("host tests never request a live userspace page directory");
            }

            pub fn switchPageDirectory(_: *PageDirectory) void {}
            pub fn alloc_frames(_: u32) ?u32 {
                return null;
            }
            pub fn map_range(_: u32, _: u32, _: u32, _: u32) void {}
            pub fn set_current_page_flags(_: u32, _: u32) void {}
            pub fn page_fault_handler(_: *const isr.InterruptFrame) void {}
        };
    };

const PAGE_SIZE: usize = 4096;
const USERSPACE_TRAP_VECTOR: u8 = 129;
const PAGE_FAULT_VECTOR: u8 = 14;

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
    page_fault_count: u64 = 0,
    last_fault_address: u32 = 0,
    last_fault_error_code: u32 = 0,

    fn pageDirectory(self: *const MappingEntry) *freestanding.paging.PageDirectory {
        return @ptrFromInt(self.page_directory_ptr);
    }
};

var trap_handler_registered = false;
var registered_executor: ?*Executor = null;

pub fn activeTaskId() u64 {
    const executor = registered_executor orelse return 0;
    return executor.activeTaskId();
}

pub const Executor = struct {
    initialized: bool = false,
    probe_marker_printed: bool = false,
    resume_marker_printed: bool = false,
    active_task_id: u64 = 0,
    active_address_space_id: u64 = 0,
    kernel_page_directory_ptr: usize = 0,
    handoff_completed: bool = false,
    pending_instruction_pointer: u32 = 0,
    pending_stack_pointer: u32 = 0,
    last_trap_instruction_pointer: u32 = 0,
    last_trap_stack_pointer: u32 = 0,
    last_trap_counter: u32 = 0,
    last_fault_task_id: u64 = 0,
    last_fault_address: u32 = 0,
    last_fault_error_code: u32 = 0,
    user_page_fault_count: u64 = 0,
    mappings: [task_runtime.MAX_TASKS]MappingEntry = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS,
    userspace_kernel_stack: [16 * 1024]u8 align(16) = [_]u8{0} ** (16 * 1024),

    pub fn init(self: *Executor) void {
        if (builtin.target.os.tag != .freestanding) return;
        registered_executor = self;
        if (!trap_handler_registered) {
            freestanding.isr.registerHandler(USERSPACE_TRAP_VECTOR, userspaceTrapHandler);
            freestanding.isr.registerHandler(PAGE_FAULT_VECTOR, userspacePageFaultHandler);
            trap_handler_registered = true;
        }
        self.initialized = true;
    }

    pub fn reset(self: *Executor) void {
        self.initialized = false;
        self.probe_marker_printed = false;
        self.resume_marker_printed = false;
        self.active_task_id = 0;
        self.active_address_space_id = 0;
        self.kernel_page_directory_ptr = 0;
        self.handoff_completed = false;
        self.pending_instruction_pointer = 0;
        self.pending_stack_pointer = 0;
        self.last_trap_instruction_pointer = 0;
        self.last_trap_stack_pointer = 0;
        self.last_trap_counter = 0;
        self.last_fault_task_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
        self.user_page_fault_count = 0;
        self.mappings = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS;
        zigos_userspace_resume_requested = 0;
        zigos_userspace_resume_esp = 0;
        zigos_userspace_resume_eip = 0;
        publishRootActiveTaskId(0);
        if (registered_executor == self) {
            registered_executor = null;
        }
    }

    pub fn activeTaskId(self: *const Executor) u64 {
        return self.active_task_id;
    }

    pub fn consumeUserPageFault(
        self: *Executor,
        task_id: u64,
        expected_fault_address: u32,
    ) bool {
        if (self.last_fault_task_id != task_id) return false;
        if (self.last_fault_address != expected_fault_address) return false;
        if ((self.last_fault_error_code & 0x4) == 0) return false;
        self.last_fault_task_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
        return true;
    }

    pub fn observedUserCounter(
        self: *Executor,
        address_space_id: u64,
        expected_counter: u32,
    ) bool {
        const mapping = self.findMapping(address_space_id) orelse return false;
        return mapping.last_user_counter == expected_counter;
    }

    pub fn observedUserCounterStagePulse(
        self: *Executor,
        address_space_id: u64,
        expected_stage: userspace_bootstrap_mailbox.Stage,
        expected_pulse: u16,
    ) bool {
        const mapping = self.findMapping(address_space_id) orelse return false;
        return @as(u8, @truncate(mapping.last_user_counter >> 24)) == @intFromEnum(expected_stage) and
            @as(u16, @truncate(mapping.last_user_counter)) == expected_pulse;
    }

    pub fn executeTask(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
        task_id: u64,
        now_ticks: u64,
    ) bool {
        if (builtin.target.os.tag != .freestanding) return false;
        self.init();

        const task = runtime.find(task_id) orelse return false;
        if (!task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return false;

        const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        const image = catalog.findById(task.launch.image_id) orelse return false;
        if (image.elf_bytes.len == 0) return false;

        const mapping = self.ensureMaterialized(address_space, image) orelse return false;
        self.initializeBootstrapMailbox(mapping, image, task, capability_table, now_ticks);
        const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
        self.kernel_page_directory_ptr = @intFromPtr(kernel_page_directory);
        freestanding.gdt.setKernelStack(@truncate(self.trapStackTop()));
        const instruction_pointer = if (mapping.resume_valid)
            mapping.resume_instruction_pointer
        else
            @as(u32, @intCast(address_space.entry_point));
        const stack_pointer = if (mapping.resume_valid)
            mapping.resume_stack_pointer
        else
            @as(u32, @intCast(address_space.stack_pointer - 16));
        @call(.never_inline, recordPendingHandoff, .{
            self,
            instruction_pointer,
            stack_pointer,
        });

        self.active_task_id = task_id;
        self.active_address_space_id = address_space.id;
        publishRootActiveTaskId(task_id);
        self.handoff_completed = false;
        zigos_userspace_resume_requested = 0;

        freestanding.paging.switchPageDirectory(mapping.pageDirectory());
        _ = @call(.never_inline, enterUserspace, .{
            self,
        });

        if (freestanding.paging.getCurrentPageDirectory() != kernel_page_directory) {
            freestanding.paging.switchPageDirectory(kernel_page_directory);
        }

        self.active_task_id = 0;
        self.active_address_space_id = 0;
        publishRootActiveTaskId(0);
        zigos_userspace_resume_requested = 0;

        if (self.handoff_completed and !self.probe_marker_printed) {
            common.printBootMarker(boot_markers.userspace_exec_probe_ok);
            self.probe_marker_printed = true;
        }
        if (self.handoff_completed and
            mapping.yield_count >= 2 and
            mapping.last_user_counter >= 2 and
            !self.resume_marker_printed)
        {
            common.printBootMarker(boot_markers.userspace_resume_ok);
            self.resume_marker_printed = true;
        }
        return self.handoff_completed;
    }

    fn initializeBootstrapMailbox(
        self: *Executor,
        mapping: *const MappingEntry,
        image: *const userspace_loader.ImageRecord,
        task: *const task_runtime.TaskRecord,
        capability_table: *const capability.CapabilityTable,
        now_ticks: u64,
    ) void {
        _ = self;
        if (image.bootstrap_mailbox_address == 0) return;

        const bootstrap = selectBootstrapCapability(task, capability_table, now_ticks);
        const previous_directory = freestanding.paging.getCurrentPageDirectory();
        freestanding.paging.switchPageDirectory(mapping.pageDirectory());
        defer freestanding.paging.switchPageDirectory(previous_directory);

        const mailbox_ptr: *userspace_bootstrap_mailbox.Mailbox = @ptrFromInt(@as(usize, @intCast(image.bootstrap_mailbox_address)));
        mailbox_ptr.* = .{
            .version = userspace_bootstrap_mailbox.VERSION,
            .stage = @intFromEnum(userspace_bootstrap_mailbox.Stage.boot),
            .detail = @intFromEnum(userspace_bootstrap_mailbox.classifyDetail(@intFromEnum(task.component_class), image.contract_flags)),
            .fault_code = 0,
            ._reserved0 = [_]u8{0} ** 3,
            .authority_capability_id = bootstrap.capability_id,
            .task_id = task.id,
            .service_id = bootstrap.service_id,
            .resource_mask = 0,
            .last_counter = 0,
        };
    }

    fn ensureMaterialized(
        self: *Executor,
        address_space: *const task_runtime.AddressSpaceRecord,
        image: *const userspace_loader.ImageRecord,
    ) ?*MappingEntry {
        if (self.findMapping(address_space.id)) |entry| return entry;

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

        for (&self.mappings) |*entry| {
            if (entry.in_use) continue;
            entry.in_use = true;
            entry.address_space_id = address_space.id;
            entry.page_directory_ptr = @intFromPtr(page_directory);
            entry.resume_valid = false;
            entry.resume_instruction_pointer = 0;
            entry.resume_stack_pointer = 0;
            entry.yield_count = 0;
            entry.last_user_counter = 0;
            entry.page_fault_count = 0;
            entry.last_fault_address = 0;
            entry.last_fault_error_code = 0;
            return entry;
        }
        return null;
    }

    fn findMapping(self: *Executor, address_space_id: u64) ?*MappingEntry {
        for (&self.mappings) |*entry| {
            if (entry.in_use and entry.address_space_id == address_space_id) return entry;
        }
        return null;
    }

    fn trapStackTop(self: *Executor) usize {
        return @intFromPtr(&self.userspace_kernel_stack) + self.userspace_kernel_stack.len;
    }
};

fn selectBootstrapCapability(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
) struct { capability_id: u64, service_id: u64 } {
    for (task.capabilityIds()) |capability_id| {
        const granted = capability_table.query(capability_id) orelse continue;
        if (!capability_table.isUsable(granted, now_ticks)) continue;
        if (!granted.rights.has(.time_query) and !granted.rights.has(.resource_query) and !granted.rights.has(.accounting_query)) continue;
        const service_id = if (granted.target.kind == .service) granted.target.id else 0;
        return .{ .capability_id = capability_id, .service_id = service_id };
    }
    return .{ .capability_id = 0, .service_id = 0 };
}

fn userspaceTrapHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse return;
    if (executor.active_task_id == 0) return;
    @call(.never_inline, recordTrapState, .{
        executor,
        frame.eip,
        frame.useresp,
        frame.eax,
    });

    if (executor.findMapping(executor.active_address_space_id)) |mapping| {
        mapping.resume_valid = true;
        mapping.resume_instruction_pointer = executor.last_trap_instruction_pointer;
        mapping.resume_stack_pointer = executor.last_trap_stack_pointer;
        mapping.yield_count += 1;
        mapping.last_user_counter = executor.last_trap_counter;
    }

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    if (executor.kernel_page_directory_ptr != 0) {
        freestanding.paging.switchPageDirectory(@ptrFromInt(executor.kernel_page_directory_ptr));
    }
}

fn userspacePageFaultHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse {
        freestanding.paging.page_fault_handler(frame);
        return;
    };
    if (executor.active_task_id == 0 or (frame.err_code & 0x4) == 0) {
        freestanding.paging.page_fault_handler(frame);
        return;
    }

    const faulting_address = readFaultAddress();
    @call(.never_inline, recordUserPageFault, .{
        executor,
        executor.active_task_id,
        faulting_address,
        frame.err_code,
    });

    if (executor.findMapping(executor.active_address_space_id)) |mapping| {
        mapping.page_fault_count += 1;
        mapping.last_fault_address = faulting_address;
        mapping.last_fault_error_code = frame.err_code;
    }

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    if (executor.kernel_page_directory_ptr != 0) {
        freestanding.paging.switchPageDirectory(@ptrFromInt(executor.kernel_page_directory_ptr));
    }
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

fn divCeil(value: usize, divisor: usize) usize {
    return (value + divisor - 1) / divisor;
}

fn enterUserspace(executor: *const Executor) u32 {
    return zigos_enter_userspace(
        executor.pending_instruction_pointer,
        executor.pending_stack_pointer,
    );
}

fn recordPendingHandoff(self: *Executor, instruction_pointer: u32, stack_pointer: u32) void {
    self.pending_instruction_pointer = instruction_pointer;
    self.pending_stack_pointer = stack_pointer;
}

fn recordTrapState(self: *Executor, instruction_pointer: u32, stack_pointer: u32, counter: u32) void {
    self.last_trap_instruction_pointer = instruction_pointer;
    self.last_trap_stack_pointer = stack_pointer;
    self.last_trap_counter = counter;
}

fn recordUserPageFault(self: *Executor, task_id: u64, faulting_address: u32, error_code: u32) void {
    self.last_fault_task_id = task_id;
    self.last_fault_address = faulting_address;
    self.last_fault_error_code = error_code;
    self.user_page_fault_count += 1;
}

fn publishRootActiveTaskId(task_id: u64) void {
    if (builtin.target.os.tag != .freestanding) return;
    const root = @import("root");
    if (@hasDecl(root, "publishUserspaceActiveTaskId")) {
        root.publishUserspaceActiveTaskId(task_id);
    }
}

fn readFaultAddress() u32 {
    return asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (-> u32),
    );
}

test "executor matches userspace counters by stage and pulse" {
    var executor = Executor{};
    executor.mappings[0] = .{
        .in_use = true,
        .address_space_id = 42,
        .last_user_counter = userspace_bootstrap_mailbox.packCounter(.syscall_ready, .proof, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE),
    };

    try @import("std").testing.expect(executor.observedUserCounterStagePulse(42, .syscall_ready, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE));
    try @import("std").testing.expect(!executor.observedUserCounterStagePulse(42, .steady, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE));
    try @import("std").testing.expect(!executor.observedUserCounterStagePulse(42, .syscall_ready, 0x42));
}
