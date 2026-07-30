const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const embedded_file = @import("embedded_file.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_flags = @import("userspace_flags.zig");
const userspace_loader = @import("userspace_loader.zig");

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn readCr2() usize {
            return 0;
        }
    };

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const kernel_config = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/config.zig")
else
    struct {
        pub fn includesVerificationEvidence() bool {
            return true;
        }
    };
const include_verification_evidence = kernel_config.includesVerificationEvidence();
const NxProbeTarget = if (include_verification_evidence) u32 else void;

const freestanding = if (builtin.target.os.tag == .freestanding)
    struct {
        pub const gdt = @import("../../kernel/interrupts/gdt64.zig");
        pub const isr = @import("../../kernel/interrupts/isr.zig");
        pub const paging = @import("../../kernel/memory/paging64.zig");
        pub const syscall64 = @import("../../kernel/interrupts/syscall64.zig");
    }
else
    struct {
        pub const gdt = struct {
            pub fn setKernelStack(_: usize) void {}
        };

        pub const syscall64 = struct {
            pub fn setKernelStack(_: usize) void {}
        };

        pub const isr = struct {
            pub const InterruptFrame = opaque {};
            pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

            pub fn registerHandler(_: u8, _: InterruptHandler) void {}
        };

        pub const paging = struct {
            pub const PageDirectory = opaque {};
            pub const UserPermissions = struct {
                writable: bool,
                executable: bool = false,
                write_through: bool = false,
                cache_disabled: bool = false,
            };
            pub const UserAddressSpace = struct {
                directory: *PageDirectory,
                pcid: u16,
            };
            pub const UserAddressSpaceCreateError = error{ OutOfMemory, ProcessContextExhausted };
            pub const UserMapError = error{
                OutOfMemory,
                InvalidRange,
                AddressOverflow,
                KernelMappingCollision,
                AlreadyMapped,
                WritableExecutable,
            };
            pub const UserWriteError = error{
                InvalidRange,
                AddressOverflow,
                PageNotOwned,
            };
            pub const UserAddressSpaceDestroyError = error{AddressSpaceActive};
            pub const FrameStats = struct {
                total: u32 = 0,
                reserved: u32 = 0,
                allocated: u32 = 0,
                free: u32 = 0,
            };

            pub fn createUserAddressSpace() UserAddressSpaceCreateError!UserAddressSpace {
                return error.OutOfMemory;
            }

            pub fn getCurrentPageDirectory() *PageDirectory {
                native_util.impossibleByInvariant("host tests never request a live userspace page directory");
            }

            pub fn switchToUserAddressSpace(_: *const UserAddressSpace) void {}
            pub fn switchToKernelAddressSpace() void {}
            pub fn mapOwnedUserRange(_: *UserAddressSpace, _: u32, _: u32, _: UserPermissions) UserMapError!void {
                return error.OutOfMemory;
            }
            pub fn writeOwnedUserRange(_: *const UserAddressSpace, _: u32, _: []const u8) UserWriteError!void {
                return error.PageNotOwned;
            }
            pub fn ownedUserPageIsExecutable(_: *const UserAddressSpace, _: u32) ?bool {
                return null;
            }
            pub fn destroyUserAddressSpace(_: *UserAddressSpace) UserAddressSpaceDestroyError!void {}
            pub fn unmapBorrowedCurrentPage(_: u32) bool {
                return true;
            }
            pub fn frameStats() FrameStats {
                return .{};
            }
            pub fn page_fault_handler(_: *const isr.InterruptFrame) void {}
        };
    };

const PAGE_SIZE: usize = 4096;
pub const USER_RFLAGS_RESERVED: u64 = 1 << 1;
pub const DEFAULT_USER_RFLAGS: u64 = USER_RFLAGS_RESERVED | (1 << 9);
const USERSPACE_TRAP_VECTOR: u8 = 129;
const PAGE_FAULT_VECTOR: u8 = 14;
const TRAP_STACK_BYTES: usize = units.kibibytes(48);
const TRAP_STACK_GUARD_BYTES: usize = PAGE_SIZE;

const TRAP_STACK_PAINT_PATTERN: u32 = 0x57ACC0DE;
const MAPPING_INDEX_CAPACITY: usize = task_runtime.MAX_TASKS * 2;
const MappingIndex = indexed_arena.UniqueIndex(MAPPING_INDEX_CAPACITY);
const MaterializationError = freestanding.paging.UserAddressSpaceCreateError || freestanding.paging.UserMapError || freestanding.paging.UserWriteError || error{
    MappingTableFull,
    ImageExtentInvalid,
};

var trap_stack: [TRAP_STACK_BYTES]u8 align(PAGE_SIZE) = [_]u8{0} ** TRAP_STACK_BYTES;
var trap_stack_guard_armed: bool = false;

fn trapStackPaintableBase() usize {
    return @intFromPtr(&trap_stack) + TRAP_STACK_GUARD_BYTES;
}

fn armTrapStackGuard() void {
    if (builtin.target.os.tag != .freestanding) return;
    if (trap_stack_guard_armed) return;
    const guard_address = @intFromPtr(&trap_stack);
    _ = freestanding.paging.unmapBorrowedCurrentPage(guard_address);
    const base = trapStackPaintableBase();
    const words: [*]u32 = @ptrFromInt(base);
    const count = (TRAP_STACK_BYTES - TRAP_STACK_GUARD_BYTES) / @sizeOf(u32);
    var index: usize = 0;
    while (index < count) : (index += 1) {
        words[index] = TRAP_STACK_PAINT_PATTERN;
    }
    trap_stack_guard_armed = true;
}

pub fn prepareKernelStack() usize {
    if (builtin.target.os.tag != .freestanding) return 0;
    armTrapStackGuard();
    return @intFromPtr(&trap_stack) + trap_stack.len;
}

pub fn reportTrapStackPeak() void {
    if (builtin.target.os.tag != .freestanding) return;
    if (!trap_stack_guard_armed) return;
    const base = trapStackPaintableBase();
    const top = @intFromPtr(&trap_stack) + trap_stack.len;
    var addr = base;
    var untouched: usize = 0;
    while (addr < top) : (addr += @sizeOf(u32)) {
        const word: *const u32 = @ptrFromInt(addr);
        if (word.* != TRAP_STACK_PAINT_PATTERN) break;
        untouched += @sizeOf(u32);
    }
    const used = (top - base) - untouched;

    var line_buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:PLATFORM:TRAP_STACK:PEAK used_bytes={d} capacity_bytes={d}",
        .{ used, top - base },
    ) catch return;
    common.printBootMarker(line);
}

pub export var zigos_userspace_resume_requested: u32 = 0;
pub export var zigos_userspace_resume_esp: usize = 0;
pub export var zigos_userspace_resume_eip: usize = 0;

pub const UserContext64 = extern struct {
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rbp: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    instruction_pointer: u64 = 0,
    flags: u64 = DEFAULT_USER_RFLAGS,
    stack_pointer: u64 = 0,
};

comptime {
    if (TRAP_STACK_BYTES % PAGE_SIZE != 0 or TRAP_STACK_BYTES <= TRAP_STACK_GUARD_BYTES) {
        @compileError("userspace trap stack must retain a page-aligned guarded capacity");
    }
    if (@offsetOf(UserContext64, "instruction_pointer") != 120 or
        @offsetOf(UserContext64, "flags") != 128 or
        @offsetOf(UserContext64, "stack_pointer") != 136 or
        @sizeOf(UserContext64) != 144)
    {
        @compileError("x86-64 userspace context layout diverged from userspace_entry64.S");
    }
}

extern fn zigos_enter_userspace(context: usize, reserved: usize) callconv(.c) u32;

pub fn enterPreparedUserContext(context: *const UserContext64) u32 {
    if (builtin.target.os.tag != .freestanding) return 0;
    return zigos_enter_userspace(@intFromPtr(context), 0);
}

const MappingState = enum(u8) {
    free,
    building,
    live,
    retire_pending,
};

const MappingEntry = struct {
    state: MappingState = .free,
    address_space_id: u64 = 0,
    address_space: ?freestanding.paging.UserAddressSpace = null,
    resume_valid: bool = false,
    resume_instruction_pointer: u32 = 0,
    resume_stack_pointer: u32 = 0,
    user_context64: UserContext64 = .{},
    yield_count: u64 = 0,
    last_user_counter: u32 = 0,
    page_fault_count: u64 = 0,
    last_fault_address: u32 = 0,
    last_fault_error_code: u32 = 0,

    fn pageDirectory(self: *const MappingEntry) *freestanding.paging.PageDirectory {
        return self.address_space.?.directory;
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
    binding_owner: ?*const anyopaque = null,
    bound_runtime: ?*task_runtime.Runtime = null,
    probe_marker_printed: bool = false,
    resume_marker_printed: bool = false,
    active_task_id: u64 = 0,
    active_mapping: ?*MappingEntry = null,
    handoff_completed: bool = false,
    pending_user_context64: UserContext64 = .{},
    last_trap_instruction_pointer: u32 = 0,
    last_trap_stack_pointer: u32 = 0,
    last_trap_counter: u32 = 0,
    last_fault_task_id: u64 = 0,
    last_fault_address_space_id: u64 = 0,
    last_fault_address: u32 = 0,
    last_fault_error_code: u32 = 0,
    user_page_fault_count: u64 = 0,
    active_nx_probe_target: NxProbeTarget = if (include_verification_evidence) 0 else {},
    mappings: [task_runtime.MAX_TASKS]MappingEntry = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS,
    mapping_index: MappingIndex = MappingIndex.init(),

    pub fn init(self: *Executor) void {
        if (builtin.target.os.tag != .freestanding) return;
        registered_executor = self;
        if (!trap_handler_registered) {
            freestanding.isr.registerHandler(USERSPACE_TRAP_VECTOR, userspaceTrapHandler);
            freestanding.isr.registerHandler(PAGE_FAULT_VECTOR, userspacePageFaultHandler);
            trap_handler_registered = true;
        }
        _ = prepareKernelStack();
        self.initialized = true;
    }

    pub fn claimRuntimeBinding(
        self: *Executor,
        owner: *const anyopaque,
        runtime: *task_runtime.Runtime,
    ) bool {
        if (self.binding_owner != null or self.bound_runtime != null) return false;
        self.binding_owner = owner;
        self.bound_runtime = runtime;
        return true;
    }

    pub fn releaseRuntimeBinding(
        self: *Executor,
        expected_owner: *const anyopaque,
        expected_runtime: *task_runtime.Runtime,
    ) bool {
        const owner = self.binding_owner orelse return false;
        const runtime = self.bound_runtime orelse return false;
        if (owner != expected_owner or runtime != expected_runtime) return false;
        self.binding_owner = null;
        self.bound_runtime = null;
        return true;
    }

    pub fn deinit(self: *Executor) void {
        self.reset();
    }

    pub fn retirementSink(self: *Executor) task_runtime.AddressSpaceRetirementSink {
        return task_runtime.AddressSpaceRetirementSink.init(Executor, self);
    }

    pub fn retireAddressSpace(self: *Executor, event: task_runtime.AddressSpaceRetirementEvent) void {
        if (self.last_fault_address_space_id == event.address_space_id) {
            self.clearUserPageFaultObservation();
        }
        const mapping = self.findMapping(event.address_space_id) orelse return;
        if (self.active_task_id != 0 and self.active_mapping == mapping) {
            mapping.state = .retire_pending;
            self.handoff_completed = true;
            zigos_userspace_resume_requested = 1;
            return;
        }
        self.releaseMapping(mapping);
    }

    pub fn materializedCount(self: *const Executor) usize {
        var count: usize = 0;
        for (self.mappings) |entry| {
            if (entry.state == .live or entry.state == .retire_pending) count += 1;
        }
        return count;
    }

    pub fn reset(self: *Executor) void {
        if (self.active_task_id != 0) {
            native_util.impossibleByInvariant("cannot reset userspace executor while an address space is active");
        }
        self.releaseAllMappings();
        self.initialized = false;
        self.probe_marker_printed = false;
        self.resume_marker_printed = false;
        self.active_task_id = 0;
        self.active_mapping = null;
        self.handoff_completed = false;
        self.pending_user_context64 = .{};
        self.last_trap_instruction_pointer = 0;
        self.last_trap_stack_pointer = 0;
        self.last_trap_counter = 0;
        self.last_fault_task_id = 0;
        self.last_fault_address_space_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
        self.user_page_fault_count = 0;
        if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
        self.mappings = [_]MappingEntry{MappingEntry{}} ** task_runtime.MAX_TASKS;
        self.mapping_index.reset();
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
        address_space_id: u64,
        expected_fault_address: u32,
    ) bool {
        if (self.last_fault_task_id != task_id) return false;
        if (self.last_fault_address_space_id != address_space_id) return false;
        if (self.last_fault_address != expected_fault_address) return false;
        if ((self.last_fault_error_code & 0x4) == 0) return false;
        self.clearUserPageFaultObservation();
        return true;
    }

    pub fn consumeUserExecuteFault(
        self: *Executor,
        task_id: u64,
        address_space_id: u64,
        expected_fault_address: u32,
    ) bool {
        const required = @as(u32, 0x1 | 0x4 | 0x10);
        const forbidden = @as(u32, 0x2);
        if (self.last_fault_task_id != task_id) return false;
        if (self.last_fault_address_space_id != address_space_id) return false;
        if (self.last_fault_address != expected_fault_address) return false;
        if ((self.last_fault_error_code & required) != required) return false;
        if ((self.last_fault_error_code & forbidden) != 0) return false;
        self.clearUserPageFaultObservation();
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
        if (self.bound_runtime != runtime) return false;
        self.init();

        const task = runtime.find(task_id) orelse return false;
        if (!task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return false;

        const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        const image = catalog.findById(task.launch.image_id) orelse return false;
        if (!image.elf_file.isPresent()) return false;

        const mapping = self.ensureMaterialized(address_space, image) catch return false;
        self.initializeBootstrapMailbox(mapping, image, task, capability_table, now_ticks);
        const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
        const trap_stack_top = prepareKernelStack();
        freestanding.gdt.setKernelStack(trap_stack_top);
        freestanding.syscall64.setKernelStack(trap_stack_top);
        const instruction_pointer = if (mapping.resume_valid)
            mapping.resume_instruction_pointer
        else
            @as(u32, @intCast(address_space.entry_point));
        const stack_pointer = if (mapping.resume_valid)
            mapping.resume_stack_pointer
        else
            @as(u32, @intCast(address_space.stack_pointer - 16));
        self.pending_user_context64 = if (mapping.resume_valid)
            mapping.user_context64
        else
            .{
                .instruction_pointer = instruction_pointer,
                .stack_pointer = stack_pointer,
            };

        const nx_probe_target = if (include_verification_evidence and
            (image.contract_flags & userspace_flags.FLAG_NX_PROOF_PROBE) != 0)
            std.math.cast(u32, image.bootstrap_mailbox_address) orelse return false
        else
            0;

        self.active_mapping = mapping;
        self.active_task_id = task_id;
        if (comptime include_verification_evidence) self.active_nx_probe_target = nx_probe_target;
        publishRootActiveTaskId(task_id);
        self.handoff_completed = false;
        zigos_userspace_resume_requested = 0;

        freestanding.paging.switchToUserAddressSpace(&mapping.address_space.?);
        _ = @call(.never_inline, enterUserspace, .{
            self,
        });

        if (freestanding.paging.getCurrentPageDirectory() != kernel_page_directory) {
            freestanding.paging.switchToKernelAddressSpace();
        }

        self.active_task_id = 0;
        self.active_mapping = null;
        if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
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
        self.drainPendingRetirements();
        return self.handoff_completed;
    }

    pub fn materializeTaskForProof(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        task_id: u64,
    ) bool {
        if (builtin.target.os.tag != .freestanding) return false;
        if (self.bound_runtime != runtime) return false;
        self.init();
        const task = runtime.find(task_id) orelse return false;
        if (!task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return false;
        const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        const image = catalog.findById(task.launch.image_id) orelse return false;
        if (!image.elf_file.isPresent()) return false;
        _ = self.ensureMaterialized(address_space, image) catch return false;
        return true;
    }

    pub fn rehostActiveTaskForProof(
        self: *Executor,
        runtime: *task_runtime.Runtime,
        task_id: u64,
        now_ticks: u64,
    ) bool {
        if (builtin.target.os.tag != .freestanding) return false;
        if (self.bound_runtime != runtime) return false;
        if (self.active_task_id != 0) return false;
        const task = runtime.find(task_id) orelse return false;
        const retired_address_space_id = task.address_space_id;
        const mapping = self.findMapping(retired_address_space_id) orelse return false;
        if (mapping.state != .live) return false;

        const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
        if (kernel_page_directory == mapping.pageDirectory()) return false;
        const user_page_directory = mapping.pageDirectory();
        const frames_before = freestanding.paging.frameStats().allocated;

        self.active_mapping = mapping;
        self.active_task_id = task_id;
        publishRootActiveTaskId(task_id);
        self.handoff_completed = false;
        zigos_userspace_resume_requested = 0;
        freestanding.paging.switchToUserAddressSpace(&mapping.address_space.?);

        const rehosted = runtime.rehostTask(task_id, now_ticks) catch false;
        const deferred = rehosted and
            freestanding.paging.getCurrentPageDirectory() == user_page_directory and
            mapping.state == .retire_pending and
            self.handoff_completed and
            zigos_userspace_resume_requested == 1 and
            freestanding.paging.frameStats().allocated == frames_before;

        freestanding.paging.switchToKernelAddressSpace();
        self.active_task_id = 0;
        self.active_mapping = null;
        publishRootActiveTaskId(0);
        zigos_userspace_resume_requested = 0;
        self.drainPendingRetirements();
        return deferred and self.findMapping(retired_address_space_id) == null;
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
        freestanding.paging.switchToUserAddressSpace(&mapping.address_space.?);
        defer freestanding.paging.switchToKernelAddressSpace();

        const mailbox_ptr: *userspace_bootstrap_mailbox.Mailbox = @ptrFromInt(@as(usize, @intCast(image.bootstrap_mailbox_address)));
        mailbox_ptr.* = .{
            .version = userspace_bootstrap_mailbox.VERSION,
            .stage = @intFromEnum(userspace_bootstrap_mailbox.Stage.boot),
            .detail = @intFromEnum(userspace_bootstrap_mailbox.classifyDetail(@intFromEnum(task.component_class), image.contract_flags)),
            .fault_code = 0,
            ._reserved0 = [_]u8{0} ** userspace_bootstrap_mailbox.MAILBOX_RESERVED_BYTES,
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
    ) MaterializationError!*MappingEntry {
        if (self.findMapping(address_space.id)) |entry| return entry;

        var slot_index: ?usize = null;
        for (self.mappings, 0..) |entry, index| {
            if (entry.state == .free) {
                slot_index = index;
                break;
            }
        }
        const reserved_slot = slot_index orelse return error.MappingTableFull;
        const entry = &self.mappings[reserved_slot];
        entry.* = .{
            .state = .building,
            .address_space_id = address_space.id,
        };
        errdefer {
            if (entry.address_space) |*space| {
                freestanding.paging.destroyUserAddressSpace(space) catch
                    native_util.impossibleByInvariant("failed to roll back an inactive userspace address space");
            }
            entry.* = .{};
        }

        entry.address_space = try freestanding.paging.createUserAddressSpace();

        for (address_space.regions[0..address_space.region_count]) |region| {
            switch (region.kind) {
                .load_segment => try mapLoadRegion(&entry.address_space.?, region, image.elf_file),
                .stack => try mapZeroedRegion(&entry.address_space.?, region.virtual_address, region.size_bytes, region.access),
            }
        }

        entry.state = .live;
        self.mapping_index.insert(address_space.id, reserved_slot);
        return entry;
    }

    fn findMapping(self: *Executor, address_space_id: u64) ?*MappingEntry {
        const slot_index = self.mapping_index.lookup(address_space_id) orelse {
            self.debugAssertMappingIndexMissAbsent(address_space_id);
            return null;
        };
        if (slot_index >= self.mappings.len) native_util.impossibleByInvariant("executor mapping index points outside mappings");
        const entry = &self.mappings[slot_index];
        if (entry.state != .live and entry.state != .retire_pending) {
            native_util.impossibleByInvariant("executor mapping index points at a non-live mapping");
        }
        if (entry.address_space_id != address_space_id) native_util.impossibleByInvariant("executor mapping index points at the wrong mapping");
        return entry;
    }

    fn rebuildMappingIndex(self: *Executor) void {
        self.mapping_index.reset();
        for (self.mappings, 0..) |entry, slot_index| {
            if ((entry.state == .live or entry.state == .retire_pending) and entry.address_space_id != 0) {
                self.mapping_index.insert(entry.address_space_id, slot_index);
            }
        }
    }

    fn debugAssertMappingIndexMissAbsent(self: *const Executor, address_space_id: u64) void {
        if (!debugIndexChecksEnabled()) return;
        for (self.mappings) |entry| {
            if ((entry.state == .live or entry.state == .retire_pending) and entry.address_space_id == address_space_id) {
                native_util.impossibleByInvariant("executor mapping index missed a live address space");
            }
        }
    }

    fn releaseMapping(self: *Executor, entry: *MappingEntry) void {
        if (entry.state == .live or entry.state == .retire_pending) {
            self.mapping_index.remove(entry.address_space_id);
        }
        if (entry.address_space) |*space| {
            freestanding.paging.destroyUserAddressSpace(space) catch
                native_util.impossibleByInvariant("attempted to destroy the active userspace address space");
        }
        entry.* = .{};
    }

    fn releaseAllMappings(self: *Executor) void {
        for (&self.mappings) |*entry| {
            if (entry.state != .free) self.releaseMapping(entry);
        }
    }

    fn drainPendingRetirements(self: *Executor) void {
        if (self.active_task_id != 0) {
            native_util.impossibleByInvariant("cannot drain userspace retirements while an address space is active");
        }
        for (&self.mappings) |*entry| {
            if (entry.state == .retire_pending) self.releaseMapping(entry);
        }
    }

    fn clearUserPageFaultObservation(self: *Executor) void {
        self.last_fault_task_id = 0;
        self.last_fault_address_space_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
    }
};

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

fn selectBootstrapCapability(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
) struct { capability_id: u64, service_id: u64 } {
    for (task.capabilityIds()) |capability_id| {
        const granted = capability_table.requireUsable(capability_id, now_ticks) catch continue;
        if (!granted.rights.has(.time_query) and !granted.rights.has(.resource_query) and !granted.rights.has(.accounting_query)) continue;
        const service_id = if (granted.target.kind == .service) granted.target.id else 0;
        return .{ .capability_id = capability_id, .service_id = service_id };
    }
    return .{ .capability_id = 0, .service_id = 0 };
}

fn userspaceTrapHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse return;
    if (executor.active_task_id == 0) return;
    const mapping = executor.active_mapping orelse
        native_util.impossibleByInvariant("active userspace task has no materialized mapping");
    const instruction_pointer = std.math.cast(u32, frame.eip) orelse
        native_util.impossibleByInvariant("userspace instruction pointer exceeds the low-address sandbox");
    const stack_pointer = std.math.cast(u32, frame.useresp) orelse
        native_util.impossibleByInvariant("userspace stack pointer exceeds the low-address sandbox");
    const counter = std.math.cast(u32, frame.eax) orelse
        native_util.impossibleByInvariant("userspace trap counter exceeds its ABI width");
    @call(.never_inline, recordTrapState, .{
        executor,
        instruction_pointer,
        stack_pointer,
        counter,
    });

    mapping.resume_valid = true;
    mapping.resume_instruction_pointer = executor.last_trap_instruction_pointer;
    mapping.resume_stack_pointer = executor.last_trap_stack_pointer;
    captureUserContext64(mapping, frame);
    mapping.yield_count += 1;
    mapping.last_user_counter = executor.last_trap_counter;

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    freestanding.paging.switchToKernelAddressSpace();
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
    const mapping = executor.active_mapping orelse
        native_util.impossibleByInvariant("active userspace task has no materialized mapping");

    const faulting_address = std.math.cast(u32, x86.readCr2()) orelse {
        freestanding.paging.page_fault_handler(frame);
        return;
    };
    const error_code = std.math.cast(u32, frame.err_code) orelse
        native_util.impossibleByInvariant("userspace page-fault code exceeds its ABI width");
    @call(.never_inline, recordUserPageFault, .{
        executor,
        executor.active_task_id,
        mapping.address_space_id,
        faulting_address,
        error_code,
    });

    mapping.page_fault_count += 1;
    mapping.last_fault_address = faulting_address;
    mapping.last_fault_error_code = error_code;

    if (nxProbeRecoveryContext(executor, mapping, frame, faulting_address, error_code)) {
        mapping.resume_valid = true;
        mapping.resume_instruction_pointer = @intCast(frame.eip);
        mapping.resume_stack_pointer = @intCast(frame.useresp);
        captureUserContext64(mapping, frame);
    }

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    freestanding.paging.switchToKernelAddressSpace();
}

fn nxProbeRecoveryContext(
    executor: *const Executor,
    mapping: *MappingEntry,
    frame: *freestanding.isr.InterruptFrame,
    faulting_address: u32,
    error_code: u32,
) bool {
    if (comptime !include_verification_evidence) return false;
    if (executor.active_nx_probe_target == 0 or faulting_address != executor.active_nx_probe_target) return false;
    const required = @as(u32, 0x1 | 0x4 | 0x10);
    if ((error_code & required) != required or (error_code & 0x2) != 0) return false;
    const target_is_executable = freestanding.paging.ownedUserPageIsExecutable(
        &mapping.address_space.?,
        faulting_address,
    ) orelse return false;
    if (target_is_executable) return false;

    const recovery_address = std.math.cast(u32, frame.r15) orelse return false;
    const runtime = executor.bound_runtime orelse return false;
    const task = runtime.find(executor.active_task_id) orelse return false;
    const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
    if (!addressSpaceAllowsExecution(address_space, recovery_address)) return false;
    if (!(freestanding.paging.ownedUserPageIsExecutable(&mapping.address_space.?, recovery_address) orelse false)) return false;
    frame.eip = recovery_address;
    return true;
}

fn addressSpaceAllowsExecution(address_space: *const task_runtime.AddressSpaceRecord, address: u32) bool {
    const address64: u64 = address;
    for (address_space.regions[0..address_space.region_count]) |region| {
        if (region.kind != .load_segment or !region.access.execute) continue;
        const region_end = std.math.add(u64, region.virtual_address, region.size_bytes) catch continue;
        if (address64 >= region.virtual_address and address64 < region_end) return true;
    }
    return false;
}

fn mapLoadRegion(
    space: *freestanding.paging.UserAddressSpace,
    region: task_runtime.AddressSpaceRegionRecord,
    elf_file: embedded_file.File,
) MaterializationError!void {
    const virtual_address = std.math.cast(u32, region.virtual_address) orelse return error.InvalidRange;
    const size_bytes = std.math.cast(u32, region.size_bytes) orelse return error.InvalidRange;
    const start: usize = region.file_offset;
    const file_size: usize = region.file_size;
    const end = std.math.add(usize, start, file_size) catch return error.ImageExtentInvalid;
    if (end > elf_file.byte_len) return error.ImageExtentInvalid;
    const reader = elf_file.reader() orelse return error.ImageExtentInvalid;
    try freestanding.paging.mapOwnedUserRange(space, virtual_address, size_bytes, .{
        .writable = region.access.write,
        .executable = region.access.execute,
    });

    var source_offset = start;
    var target_offset: u32 = 0;
    while (source_offset < end) {
        const bytes = reader.logicalSliceAt(source_offset) orelse return error.ImageExtentInvalid;
        const copy_len = @min(bytes.len, end - source_offset);
        const target_address = std.math.add(u32, virtual_address, target_offset) catch return error.InvalidRange;
        try freestanding.paging.writeOwnedUserRange(space, target_address, bytes[0..copy_len]);
        source_offset += copy_len;
        target_offset += @intCast(copy_len);
    }
}

fn mapZeroedRegion(
    space: *freestanding.paging.UserAddressSpace,
    virtual_address_raw: u64,
    size_bytes_raw: usize,
    access: task_runtime.SegmentAccess,
) MaterializationError!void {
    const virtual_address = std.math.cast(u32, virtual_address_raw) orelse return error.InvalidRange;
    const size_bytes = std.math.cast(u32, size_bytes_raw) orelse return error.InvalidRange;
    try freestanding.paging.mapOwnedUserRange(space, virtual_address, size_bytes, .{
        .writable = access.write,
        .executable = access.execute,
    });
}

fn enterUserspace(executor: *const Executor) u32 {
    return enterPreparedUserContext(&executor.pending_user_context64);
}

fn captureUserContext64(mapping: *MappingEntry, frame: *freestanding.isr.InterruptFrame) void {
    mapping.user_context64 = .{
        .rax = frame.eax,
        .rbx = frame.ebx,
        .rcx = frame.ecx,
        .rdx = frame.edx,
        .rbp = frame.ebp,
        .rsi = frame.esi,
        .rdi = frame.edi,
        .r8 = frame.r8,
        .r9 = frame.r9,
        .r10 = frame.r10,
        .r11 = frame.r11,
        .r12 = frame.r12,
        .r13 = frame.r13,
        .r14 = frame.r14,
        .r15 = frame.r15,
        .instruction_pointer = frame.eip,
        .flags = frame.eflags,
        .stack_pointer = frame.useresp,
    };
}

fn recordTrapState(self: *Executor, instruction_pointer: u32, stack_pointer: u32, counter: u32) void {
    self.last_trap_instruction_pointer = instruction_pointer;
    self.last_trap_stack_pointer = stack_pointer;
    self.last_trap_counter = counter;
}

fn recordUserPageFault(self: *Executor, task_id: u64, address_space_id: u64, faulting_address: u32, error_code: u32) void {
    self.last_fault_task_id = task_id;
    self.last_fault_address_space_id = address_space_id;
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

test "executor matches userspace counters by stage and pulse" {
    var executor = Executor{};
    executor.mappings[0] = .{
        .state = .live,
        .address_space_id = 42,
        .last_user_counter = userspace_bootstrap_mailbox.packCounter(.syscall_ready, .proof, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE),
    };
    executor.rebuildMappingIndex();

    try @import("std").testing.expect(executor.observedUserCounterStagePulse(42, .syscall_ready, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE));
    try @import("std").testing.expect(!executor.observedUserCounterStagePulse(42, .steady, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE));
    try @import("std").testing.expect(!executor.observedUserCounterStagePulse(42, .syscall_ready, 0x42));
}

test "executor runtime binding has one owner and compare-release semantics" {
    var executor = Executor{};
    var first_runtime = task_runtime.Runtime.init();
    var second_runtime = task_runtime.Runtime.init();
    var first_owner: u8 = 0;
    var second_owner: u8 = 0;

    try std.testing.expect(executor.claimRuntimeBinding(&first_owner, &first_runtime));
    try std.testing.expect(!executor.claimRuntimeBinding(&first_owner, &first_runtime));
    try std.testing.expect(!executor.claimRuntimeBinding(&second_owner, &second_runtime));
    try std.testing.expect(!executor.releaseRuntimeBinding(&second_owner, &first_runtime));
    try std.testing.expect(!executor.releaseRuntimeBinding(&first_owner, &second_runtime));
    try std.testing.expect(executor.releaseRuntimeBinding(&first_owner, &first_runtime));

    try std.testing.expect(executor.claimRuntimeBinding(&second_owner, &second_runtime));
    try std.testing.expect(executor.releaseRuntimeBinding(&second_owner, &second_runtime));
}

test "executor retires inactive address spaces idempotently and reuses slots" {
    var executor = Executor{};
    executor.mappings[0] = .{ .state = .live, .address_space_id = 42 };
    executor.rebuildMappingIndex();

    const event = task_runtime.AddressSpaceRetirementEvent{
        .address_space_id = 42,
        .reason = .rehost,
    };
    executor.retireAddressSpace(event);
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);

    executor.retireAddressSpace(event);
    executor.mappings[0] = .{ .state = .live, .address_space_id = 43 };
    executor.rebuildMappingIndex();
    try std.testing.expect(executor.findMapping(43) == &executor.mappings[0]);
}

test "executor defers active address-space retirement until kernel handoff" {
    var executor = Executor{};
    executor.mappings[0] = .{ .state = .live, .address_space_id = 42 };
    executor.rebuildMappingIndex();
    executor.active_mapping = &executor.mappings[0];
    executor.active_task_id = 7;

    executor.retireAddressSpace(.{ .address_space_id = 42, .reason = .terminate });
    try std.testing.expectEqual(MappingState.retire_pending, executor.mappings[0].state);
    try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
    try std.testing.expect(executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);

    executor.active_task_id = 0;
    executor.active_mapping = null;
    executor.drainPendingRetirements();
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);
    executor.reset();
}

test "executor page-fault observations are scoped to an address-space incarnation" {
    var executor = Executor{
        .last_fault_task_id = 7,
        .last_fault_address_space_id = 42,
        .last_fault_address = 0x7000_0000,
        .last_fault_error_code = 0x4,
    };

    try std.testing.expect(!executor.consumeUserPageFault(7, 43, 0x7000_0000));
    try std.testing.expect(executor.consumeUserPageFault(7, 42, 0x7000_0000));

    executor.last_fault_task_id = 7;
    executor.last_fault_address_space_id = 42;
    executor.last_fault_address = 0x7000_0000;
    executor.last_fault_error_code = 0x4;
    executor.retireAddressSpace(.{ .address_space_id = 42, .reason = .snapshot_restore });
    try std.testing.expectEqual(@as(u64, 0), executor.last_fault_task_id);
    try std.testing.expectEqual(@as(u64, 0), executor.last_fault_address_space_id);
}

test "executor distinguishes a present user NX instruction-fetch fault" {
    var executor = Executor{
        .last_fault_task_id = 7,
        .last_fault_address_space_id = 42,
        .last_fault_address = 0x4000_3000,
        .last_fault_error_code = 0x15,
    };

    try std.testing.expect(!executor.consumeUserExecuteFault(7, 42, 0x4000_4000));
    try std.testing.expect(executor.consumeUserExecuteFault(7, 42, 0x4000_3000));
    executor.last_fault_task_id = 7;
    executor.last_fault_address_space_id = 42;
    executor.last_fault_address = 0x4000_3000;
    executor.last_fault_error_code = 0x14;
    try std.testing.expect(!executor.consumeUserExecuteFault(7, 42, 0x4000_3000));
}
