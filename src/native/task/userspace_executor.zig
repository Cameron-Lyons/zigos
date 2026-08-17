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

pub const ExecutionOutcome = enum(u8) {
    unavailable,
    yielded,
    wait_for_event,

    pub fn handedOff(self: ExecutionOutcome) bool {
        return self != .unavailable;
    }
};

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
pub const USER_ADDRESS_SPACE_ACTIVATIONS_PER_DISPATCH: u8 = 1;
pub const STATIC_HANDOFF_STACK_INSTALLS_PER_BIND: u8 = 1;
pub const STEADY_ADDRESS_SPACE_IMAGE_INDEX_LOOKUPS: u8 = 0;
pub const STEADY_MAPPING_INDEX_LOOKUPS_PER_DISPATCH: u8 = 0;
pub const MappingHandle = indexed_arena.GenerationalHandle("UserspaceMappingHandle");
const MaterializationError = freestanding.paging.UserAddressSpaceCreateError || freestanding.paging.UserMapError || freestanding.paging.UserWriteError || error{
    MappingTableFull,
    ImageExtentInvalid,
    AddressSpaceOwnerInvalid,
    AddressSpaceImageMismatch,
    AddressSpaceRetiring,
    InitialContextInvalid,
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

const MappingDispatchMetadata = struct {
    owner_task_id: u64 = 0,
    image_id: u64 = 0,
    initial_instruction_pointer: u32 = 0,
    initial_stack_pointer: u32 = 0,
    bootstrap_mailbox_address: u32 = 0,
    contract_flags: u32 = 0,
};

const MappingEntry = struct {
    state: MappingState = .free,
    handle_generation: u32 = 0,
    address_space_id: u64 = 0,
    address_space: ?freestanding.paging.UserAddressSpace = null,
    dispatch_metadata: MappingDispatchMetadata = .{},
    resume_valid: bool = false,
    resume_instruction_pointer: u32 = 0,
    resume_stack_pointer: u32 = 0,
    user_context64: UserContext64 = .{},
    yield_count: u64 = 0,
    last_user_counter: u32 = 0,
    page_fault_count: u64 = 0,
    last_fault_address: u32 = 0,
    last_fault_error_code: u32 = 0,
    mailbox_authority_cache: MailboxAuthorityCache = .{},

    fn pageDirectory(self: *const MappingEntry) *freestanding.paging.PageDirectory {
        return self.address_space.?.directory;
    }
};

const MappingResolution = struct {
    entry: *MappingEntry,
    handle: MappingHandle,
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
    last_yield_disposition: userspace_bootstrap_mailbox.YieldDisposition = .runnable,
    last_yield_ui_revision: u64 = 0,
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
        if (self.initialized) return;
        if (!trap_handler_registered) {
            freestanding.isr.registerHandler(USERSPACE_TRAP_VECTOR, userspaceTrapHandler);
            freestanding.isr.registerHandler(PAGE_FAULT_VECTOR, userspacePageFaultHandler);
            trap_handler_registered = true;
        }
        const trap_stack_top = prepareKernelStack();
        freestanding.gdt.setKernelStack(trap_stack_top);
        freestanding.syscall64.setKernelStack(trap_stack_top);
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

    pub fn lastYieldUiRevision(self: *const Executor) u64 {
        return self.last_yield_ui_revision;
    }

    pub fn bootstrapMailboxSnapshot(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *const task_runtime.Runtime,
        task_id: u64,
    ) ?userspace_bootstrap_mailbox.Mailbox {
        if (builtin.target.os.tag != .freestanding) return null;
        if (self.active_task_id != 0) return null;
        const task = runtime.findConst(task_id) orelse return null;
        if (task.state != .active) return null;
        const mapping = self.findMapping(task.address_space_id) orelse return null;
        if (mapping.state != .live or mapping.address_space == null) return null;
        const image = catalog.findById(task.launch.image_id) orelse return null;
        if (image.bootstrap_mailbox_address == 0) return null;

        freestanding.paging.switchToUserAddressSpace(&mapping.address_space.?);
        defer freestanding.paging.switchToKernelAddressSpace();
        const mailbox_ptr: *const userspace_bootstrap_mailbox.Mailbox = @ptrFromInt(@as(usize, @intCast(image.bootstrap_mailbox_address)));
        if (mailbox_ptr.version != userspace_bootstrap_mailbox.VERSION) return null;
        return mailbox_ptr.*;
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
        task: *const task_runtime.TaskRecord,
        mapping_handle: *MappingHandle,
        now_ticks: u64,
    ) ExecutionOutcome {
        if (builtin.target.os.tag != .freestanding) return .unavailable;
        if (!self.initialized) return .unavailable;
        if (self.bound_runtime != runtime) return .unavailable;
        if (debugIndexChecksEnabled()) {
            const bound_task = runtime.findConst(task.id) orelse
                native_util.impossibleByInvariant("prepared userspace task is absent from the bound runtime");
            if (bound_task != task) native_util.impossibleByInvariant("prepared userspace task does not belong to the bound runtime");
        }
        if (!task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return .unavailable;

        const mapping = self.resolveMappingForDispatch(mapping_handle, task.address_space_id) orelse blk: {
            const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return .unavailable;
            if (address_space.owner_task_id != task.id or address_space.image_id != task.launch.image_id) return .unavailable;
            const image = catalog.findById(task.launch.image_id) orelse return .unavailable;
            if (!image.elf_file.isPresent()) return .unavailable;
            const resolution = self.ensureMaterialized(address_space, image) catch return .unavailable;
            mapping_handle.* = resolution.handle;
            break :blk resolution.entry;
        };
        if (mapping.dispatch_metadata.owner_task_id != task.id or
            mapping.dispatch_metadata.image_id != task.launch.image_id)
        {
            native_util.impossibleByInvariant("materialized userspace mapping identity changed without retirement");
        }

        const mailbox_update = self.prepareBootstrapMailbox(mapping, task, capability_table, now_ticks);
        const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
        const instruction_pointer = if (mapping.resume_valid)
            mapping.resume_instruction_pointer
        else
            mapping.dispatch_metadata.initial_instruction_pointer;
        const stack_pointer = if (mapping.resume_valid)
            mapping.resume_stack_pointer
        else
            mapping.dispatch_metadata.initial_stack_pointer;
        self.pending_user_context64 = if (mapping.resume_valid)
            mapping.user_context64
        else
            .{
                .instruction_pointer = instruction_pointer,
                .stack_pointer = stack_pointer,
            };

        const nx_probe_target = if (include_verification_evidence and
            (mapping.dispatch_metadata.contract_flags & userspace_flags.FLAG_NX_PROOF_PROBE) != 0)
            mapping.dispatch_metadata.bootstrap_mailbox_address
        else
            0;

        self.active_mapping = mapping;
        self.active_task_id = task.id;
        if (comptime include_verification_evidence) self.active_nx_probe_target = nx_probe_target;
        publishRootActiveTaskId(task.id);
        self.handoff_completed = false;
        self.last_yield_disposition = .runnable;
        self.last_yield_ui_revision = 0;
        zigos_userspace_resume_requested = 0;

        activateMappingForDispatch(mapping, mailbox_update);
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
        if (!self.handoff_completed) return .unavailable;
        return switch (self.last_yield_disposition) {
            .runnable => .yielded,
            .wait_for_event => .wait_for_event,
        };
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

    fn prepareBootstrapMailbox(
        self: *Executor,
        mapping: *MappingEntry,
        task: *const task_runtime.TaskRecord,
        capability_table: *const capability.CapabilityTable,
        now_ticks: u64,
    ) ?BootstrapMailboxUpdate {
        _ = self;
        if (mapping.dispatch_metadata.bootstrap_mailbox_address == 0) return null;

        const authorities = resolveMailboxAuthoritiesCached(task, capability_table, now_ticks, &mapping.mailbox_authority_cache);
        return prepareBootstrapMailboxUpdate(
            mapping.dispatch_metadata.bootstrap_mailbox_address,
            mapping.resume_valid,
            task.component_class,
            mapping.dispatch_metadata.contract_flags,
            task.id,
            task.ui_surface_id orelse 0,
            authorities,
        );
    }

    fn ensureMaterialized(
        self: *Executor,
        address_space: *const task_runtime.AddressSpaceRecord,
        image: *const userspace_loader.ImageRecord,
    ) MaterializationError!MappingResolution {
        const dispatch_metadata = try prepareMappingDispatchMetadata(
            address_space.owner_task_id,
            address_space.image_id,
            address_space.entry_point,
            address_space.stack_pointer,
            image.id,
            image.bootstrap_mailbox_address,
            image.contract_flags,
        );
        if (self.findMappingWithHandle(address_space.id)) |resolution| {
            if (resolution.entry.state != .live) return error.AddressSpaceRetiring;
            if (!std.meta.eql(resolution.entry.dispatch_metadata, dispatch_metadata)) {
                native_util.impossibleByInvariant("materialized userspace dispatch metadata changed without retirement");
            }
            return resolution;
        }

        var slot_index: ?usize = null;
        for (self.mappings, 0..) |entry, index| {
            if (entry.state == .free) {
                slot_index = index;
                break;
            }
        }
        const reserved_slot = slot_index orelse return error.MappingTableFull;
        const entry = &self.mappings[reserved_slot];
        const handle_generation = if (entry.handle_generation == 0) 1 else entry.handle_generation;
        entry.* = .{
            .state = .building,
            .handle_generation = handle_generation,
            .address_space_id = address_space.id,
            .dispatch_metadata = dispatch_metadata,
        };
        errdefer self.releaseMapping(entry);

        entry.address_space = try freestanding.paging.createUserAddressSpace();

        for (address_space.regions[0..address_space.region_count]) |region| {
            switch (region.kind) {
                .load_segment => try mapLoadRegion(&entry.address_space.?, region, image.elf_file),
                .stack => try mapZeroedRegion(&entry.address_space.?, region.virtual_address, region.size_bytes, region.access),
            }
        }

        entry.state = .live;
        self.mapping_index.insert(address_space.id, reserved_slot);
        return .{
            .entry = entry,
            .handle = MappingHandle.fromParts(reserved_slot, handle_generation),
        };
    }

    fn findMapping(self: *Executor, address_space_id: u64) ?*MappingEntry {
        const resolution = self.findMappingWithHandle(address_space_id) orelse return null;
        return resolution.entry;
    }

    pub fn mappingHandle(self: *Executor, address_space_id: u64) ?MappingHandle {
        const resolution = self.findMappingWithHandle(address_space_id) orelse return null;
        if (resolution.entry.state != .live) return null;
        return resolution.handle;
    }

    fn findMappingWithHandle(self: *Executor, address_space_id: u64) ?MappingResolution {
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
        if (entry.handle_generation == 0) native_util.impossibleByInvariant("live executor mapping has no handle generation");
        return .{
            .entry = entry,
            .handle = MappingHandle.fromParts(slot_index, entry.handle_generation),
        };
    }

    fn findMappingByHandle(self: *Executor, handle: MappingHandle, expected_address_space_id: u64) ?*MappingEntry {
        if (handle.isZero()) return null;
        const slot_index = handle.slotIndex();
        if (slot_index >= self.mappings.len) return null;
        const entry = &self.mappings[slot_index];
        if (entry.state != .live) return null;
        if (entry.handle_generation != handle.generation()) return null;
        if (entry.address_space_id != expected_address_space_id) return null;
        return entry;
    }

    fn resolveMappingForDispatch(
        self: *Executor,
        cached_handle: *MappingHandle,
        expected_address_space_id: u64,
    ) ?*MappingEntry {
        if (self.findMappingByHandle(cached_handle.*, expected_address_space_id)) |entry| return entry;
        const resolution = self.findMappingWithHandle(expected_address_space_id) orelse return null;
        if (resolution.entry.state != .live) return null;
        cached_handle.* = resolution.handle;
        return resolution.entry;
    }

    fn rebuildMappingIndex(self: *Executor) void {
        self.mapping_index.reset();
        for (&self.mappings, 0..) |*entry, slot_index| {
            if ((entry.state == .live or entry.state == .retire_pending) and entry.address_space_id != 0) {
                if (entry.handle_generation == 0) entry.handle_generation = 1;
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
        const next_generation = nextMappingGeneration(entry.handle_generation);
        entry.* = .{ .handle_generation = next_generation };
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

fn prepareMappingDispatchMetadata(
    owner_task_id: u64,
    address_space_image_id: u64,
    entry_point: u64,
    stack_pointer: u64,
    image_id: u64,
    bootstrap_mailbox_address: u64,
    contract_flags: u32,
) MaterializationError!MappingDispatchMetadata {
    if (owner_task_id == 0) return error.AddressSpaceOwnerInvalid;
    if (image_id == 0 or address_space_image_id != image_id) return error.AddressSpaceImageMismatch;
    const initial_stack_pointer = std.math.sub(u64, stack_pointer, 16) catch return error.InitialContextInvalid;
    return .{
        .owner_task_id = owner_task_id,
        .image_id = image_id,
        .initial_instruction_pointer = std.math.cast(u32, entry_point) orelse return error.InitialContextInvalid,
        .initial_stack_pointer = std.math.cast(u32, initial_stack_pointer) orelse return error.InitialContextInvalid,
        .bootstrap_mailbox_address = std.math.cast(u32, bootstrap_mailbox_address) orelse return error.InitialContextInvalid,
        .contract_flags = contract_flags,
    };
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

fn nextMappingGeneration(current: u32) u32 {
    const next = current +% 1;
    return if (next == 0) 1 else next;
}

pub const MailboxAuthorities = struct {
    bootstrap_capability_id: u64 = 0,
    bootstrap_service_id: u64 = 0,
    input_capability_id: u64 = 0,
    surface_presentation_capability_id: u64 = 0,
};

const BootstrapMailboxUpdate = struct {
    address: usize,
    preserve_runtime_state: bool,
    detail: u8,
    authorities: MailboxAuthorities,
    task_id: u64,
    ui_surface_id: u64,
};

fn prepareBootstrapMailboxUpdate(
    address: u64,
    preserve_runtime_state: bool,
    component_class: task_runtime.ComponentClass,
    contract_flags: u32,
    task_id: u64,
    ui_surface_id: u64,
    authorities: MailboxAuthorities,
) ?BootstrapMailboxUpdate {
    if (address == 0) return null;
    return .{
        .address = @intCast(address),
        .preserve_runtime_state = preserve_runtime_state,
        .detail = @intFromEnum(userspace_bootstrap_mailbox.classifyDetail(@intFromEnum(component_class), contract_flags)),
        .authorities = authorities,
        .task_id = task_id,
        .ui_surface_id = ui_surface_id,
    };
}

fn activateMappingForDispatch(mapping: *MappingEntry, mailbox_update: ?BootstrapMailboxUpdate) void {
    freestanding.paging.switchToUserAddressSpace(&mapping.address_space.?);
    writeBootstrapMailbox(mailbox_update);
}

fn writeBootstrapMailbox(prepared: ?BootstrapMailboxUpdate) void {
    const update = prepared orelse return;
    const mailbox_ptr: *userspace_bootstrap_mailbox.Mailbox = @ptrFromInt(update.address);
    if (!update.preserve_runtime_state) {
        mailbox_ptr.* = .{
            .version = userspace_bootstrap_mailbox.VERSION,
            .stage = @intFromEnum(userspace_bootstrap_mailbox.Stage.boot),
            .detail = update.detail,
            .fault_code = 0,
            ._reserved0 = [_]u8{0} ** userspace_bootstrap_mailbox.MAILBOX_RESERVED_BYTES,
            .authority_capability_id = update.authorities.bootstrap_capability_id,
            .input_capability_id = update.authorities.input_capability_id,
            .surface_presentation_capability_id = update.authorities.surface_presentation_capability_id,
            .ui_surface_id = update.ui_surface_id,
            .task_id = update.task_id,
            .service_id = update.authorities.bootstrap_service_id,
            .resource_mask = 0,
            .last_counter = 0,
        };
        return;
    }
    mailbox_ptr.version = userspace_bootstrap_mailbox.VERSION;
    mailbox_ptr.authority_capability_id = update.authorities.bootstrap_capability_id;
    mailbox_ptr.input_capability_id = update.authorities.input_capability_id;
    mailbox_ptr.surface_presentation_capability_id = update.authorities.surface_presentation_capability_id;
    mailbox_ptr.ui_surface_id = update.ui_surface_id;
    mailbox_ptr.task_id = update.task_id;
    mailbox_ptr.service_id = update.authorities.bootstrap_service_id;
}

pub const MailboxAuthorityCache = struct {
    authorities: MailboxAuthorities = .{},
    task_id: u64 = 0,
    task_capability_generation: u64 = 0,
    table_mutation_generation: u64 = 0,
    resolved_at_ticks: u64 = 0,
    valid_until_ticks: u64 = 0,
    refresh_count: u64 = 0,
    initialized: bool = false,
};

const MailboxAuthorityResolution = struct {
    authorities: MailboxAuthorities = .{},
    valid_until_ticks: u64 = std.math.maxInt(u64),
};

pub fn resolveMailboxAuthorities(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
) MailboxAuthorities {
    return scanMailboxAuthorities(task, capability_table, now_ticks).authorities;
}

pub fn resolveMailboxAuthoritiesCached(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
    cache: *MailboxAuthorityCache,
) MailboxAuthorities {
    const task_capability_generation = task.capabilityGeneration();
    const table_mutation_generation = capability_table.mutationGeneration();
    if (cache.initialized and
        cache.task_id == task.id and
        cache.task_capability_generation == task_capability_generation and
        cache.table_mutation_generation == table_mutation_generation and
        now_ticks >= cache.resolved_at_ticks and
        now_ticks <= cache.valid_until_ticks)
    {
        return cache.authorities;
    }

    const refresh_count = cache.refresh_count +| 1;
    const resolution = scanMailboxAuthorities(task, capability_table, now_ticks);
    cache.* = .{
        .authorities = resolution.authorities,
        .task_id = task.id,
        .task_capability_generation = task_capability_generation,
        .table_mutation_generation = table_mutation_generation,
        .resolved_at_ticks = now_ticks,
        .valid_until_ticks = resolution.valid_until_ticks,
        .refresh_count = refresh_count,
        .initialized = true,
    };
    return resolution.authorities;
}

fn scanMailboxAuthorities(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
) MailboxAuthorityResolution {
    var resolution = MailboxAuthorityResolution{};
    const resolved = &resolution.authorities;
    var query_fallback: u64 = 0;
    var query_service_id: u64 = 0;
    const accepts_surface_presentation = task.ui_surface_id != null and task.ui_surface_id.? != 0;

    for (task.capabilityIds()) |capability_id| {
        const inspected = capability_table.inspect(capability_id, now_ticks) orelse continue;
        const granted = inspected.capability;
        const service_id = if (granted.target.kind == .service) granted.target.id else 0;
        const endpoint_candidate = granted.target.kind == .service and granted.rights.has(.endpoint_create);
        const query_candidate = granted.rights.has(.time_query) or
            granted.rights.has(.resource_query) or
            granted.rights.has(.accounting_query);
        const input_candidate = granted.target.kind == .task and
            granted.target.id == task.id and
            granted.scope.task_id == task.id and
            granted.rights.has(.input_recv);
        const surface_candidate = accepts_surface_presentation and
            granted.target.kind == .task and
            granted.target.id == task.id and
            granted.scope.task_id == task.id and
            granted.rights.has(.surface_present);

        if (endpoint_candidate or query_candidate or input_candidate or surface_candidate) {
            if (now_ticks < granted.lease.issued_at_ticks) {
                resolution.valid_until_ticks = @min(resolution.valid_until_ticks, granted.lease.issued_at_ticks - 1);
            } else if (now_ticks <= granted.lease.expires_at_ticks) {
                resolution.valid_until_ticks = @min(resolution.valid_until_ticks, granted.lease.expires_at_ticks);
            }
        }
        if (!inspected.usable) continue;

        if (resolved.bootstrap_capability_id == 0 and endpoint_candidate) {
            resolved.bootstrap_capability_id = capability_id;
            resolved.bootstrap_service_id = service_id;
        }
        if (query_fallback == 0 and query_candidate) {
            query_fallback = capability_id;
            query_service_id = service_id;
        }
        if (resolved.input_capability_id == 0 and input_candidate) {
            resolved.input_capability_id = capability_id;
        }
        if (resolved.surface_presentation_capability_id == 0 and surface_candidate) {
            resolved.surface_presentation_capability_id = capability_id;
        }
    }
    if (resolved.bootstrap_capability_id == 0) {
        resolved.bootstrap_capability_id = query_fallback;
        resolved.bootstrap_service_id = query_service_id;
    }
    return resolution;
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
    const disposition_raw = std.math.cast(u32, frame.esi) orelse
        native_util.impossibleByInvariant("userspace yield disposition exceeds its ABI width");
    const ui_revision: u64 = @intCast(frame.edx);
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
    executor.last_yield_disposition = userspace_bootstrap_mailbox.yieldDisposition(disposition_raw) orelse .runnable;
    executor.last_yield_ui_revision = ui_revision;

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

test "mapping dispatch metadata is compact and bound to one address-space image" {
    const metadata = try prepareMappingDispatchMetadata(
        40,
        41,
        0x4000_1000,
        0x7FFF_F000,
        41,
        0x4000_3000,
        userspace_flags.FLAG_NX_PROOF_PROBE,
    );
    try std.testing.expectEqual(@as(u64, 40), metadata.owner_task_id);
    try std.testing.expectEqual(@as(u64, 41), metadata.image_id);
    try std.testing.expectEqual(@as(u32, 0x4000_1000), metadata.initial_instruction_pointer);
    try std.testing.expectEqual(@as(u32, 0x7FFF_EFF0), metadata.initial_stack_pointer);
    try std.testing.expectEqual(@as(u32, 0x4000_3000), metadata.bootstrap_mailbox_address);
    try std.testing.expectEqual(userspace_flags.FLAG_NX_PROOF_PROBE, metadata.contract_flags);
    try std.testing.expectEqual(@as(u8, 0), STEADY_ADDRESS_SPACE_IMAGE_INDEX_LOOKUPS);

    try std.testing.expectError(
        error.AddressSpaceOwnerInvalid,
        prepareMappingDispatchMetadata(0, 41, 0x4000_1000, 0x7FFF_F000, 41, 0x4000_3000, 0),
    );
    try std.testing.expectError(
        error.AddressSpaceImageMismatch,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 42, 0x4000_3000, 0),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 15, 41, 0x4000_3000, 0),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, @as(u64, std.math.maxInt(u32)) + 1, 0x7FFF_F000, 41, 0x4000_3000, 0),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 41, @as(u64, std.math.maxInt(u32)) + 1, 0),
    );
}

test "mailbox publication preserves resume state and resets first launch" {
    var mailbox = userspace_bootstrap_mailbox.Mailbox{
        .stage = @intFromEnum(userspace_bootstrap_mailbox.Stage.steady),
        .fault_code = 0x72,
        .resource_mask = 0x7,
        .service_operation_count = 9,
        .last_counter = 41,
        .input_event_count = 12,
        .ui_state_revision = 15,
    };
    const authorities = MailboxAuthorities{
        .bootstrap_capability_id = 101,
        .bootstrap_service_id = 102,
        .input_capability_id = 103,
        .surface_presentation_capability_id = 104,
    };
    const address: u64 = @intCast(@intFromPtr(&mailbox));

    const resumed = prepareBootstrapMailboxUpdate(address, true, .app_component, 0, 105, 106, authorities).?;
    writeBootstrapMailbox(resumed);
    try std.testing.expect(resumed.preserve_runtime_state);
    try std.testing.expectEqual(userspace_bootstrap_mailbox.VERSION, mailbox.version);
    try std.testing.expectEqual(@as(u64, 101), mailbox.authority_capability_id);
    try std.testing.expectEqual(@as(u64, 102), mailbox.service_id);
    try std.testing.expectEqual(@as(u64, 103), mailbox.input_capability_id);
    try std.testing.expectEqual(@as(u64, 104), mailbox.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 105), mailbox.task_id);
    try std.testing.expectEqual(@as(u64, 106), mailbox.ui_surface_id);
    try std.testing.expectEqual(@as(u8, @intFromEnum(userspace_bootstrap_mailbox.Stage.steady)), mailbox.stage);
    try std.testing.expectEqual(@as(u8, 0x72), mailbox.fault_code);
    try std.testing.expectEqual(@as(u32, 0x7), mailbox.resource_mask);
    try std.testing.expectEqual(@as(u16, 9), mailbox.service_operation_count);
    try std.testing.expectEqual(@as(u32, 41), mailbox.last_counter);
    try std.testing.expectEqual(@as(u64, 12), mailbox.input_event_count);
    try std.testing.expectEqual(@as(u64, 15), mailbox.ui_state_revision);

    const first_launch = prepareBootstrapMailboxUpdate(address, false, .app_component, 0, 107, 108, authorities).?;
    writeBootstrapMailbox(first_launch);
    try std.testing.expect(!first_launch.preserve_runtime_state);
    try std.testing.expectEqual(@as(u8, @intFromEnum(userspace_bootstrap_mailbox.Stage.boot)), mailbox.stage);
    try std.testing.expectEqual(@as(u8, 0), mailbox.fault_code);
    try std.testing.expectEqual(@as(u32, 0), mailbox.resource_mask);
    try std.testing.expectEqual(@as(u16, 0), mailbox.service_operation_count);
    try std.testing.expectEqual(@as(u32, 0), mailbox.last_counter);
    try std.testing.expectEqual(@as(u64, 0), mailbox.input_event_count);
    try std.testing.expectEqual(@as(u64, 0), mailbox.ui_state_revision);
    try std.testing.expectEqual(@as(u64, 107), mailbox.task_id);
    try std.testing.expectEqual(@as(u64, 108), mailbox.ui_surface_id);

    try std.testing.expect(prepareBootstrapMailboxUpdate(0, false, .app_component, 0, 1, 0, .{}) == null);
    try std.testing.expectEqual(@as(u8, 1), USER_ADDRESS_SPACE_ACTIVATIONS_PER_DISPATCH);
}

test "executor separates service, input, and surface presentation authority" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 41 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(4),
        },
        .ui_surface_id = 7,
        .local_only = true,
    });
    const query_authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 8 },
        .rights = .{ .service = .{ .resource_query = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const service_authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 9 },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const input_authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = task.id },
        .rights = .{ .task = .{ .input_recv = true } },
        .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const presentation_authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = task.id },
        .rights = .{ .task = .{ .surface_present = true } },
        .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    try runtime.grantCapability(task.id, query_authority.id);
    try runtime.grantCapability(task.id, service_authority.id);
    try runtime.grantCapability(task.id, input_authority.id);
    try runtime.grantCapability(task.id, presentation_authority.id);

    var cache = MailboxAuthorityCache{};
    var authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 10, &cache);
    try std.testing.expectEqual(service_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(@as(u64, 9), authorities.bootstrap_service_id);
    try std.testing.expectEqual(input_authority.id, authorities.input_capability_id);
    try std.testing.expectEqual(presentation_authority.id, authorities.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);

    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);

    try capabilities.revokeGrant(service_authority.id);
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(query_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(@as(u64, 8), authorities.bootstrap_service_id);
    try std.testing.expectEqual(input_authority.id, authorities.input_capability_id);
    try std.testing.expectEqual(presentation_authority.id, authorities.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 2), cache.refresh_count);

    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 101, &cache);
    try std.testing.expectEqual(MailboxAuthorities{}, authorities);
    try std.testing.expectEqual(@as(u64, 3), cache.refresh_count);

    const future_authority = try capabilities.mintBootRoot(.{
        .holder = task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 10 },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = task.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 120, .expires_at_ticks = 200 },
    });
    try runtime.grantCapability(task.id, future_authority.id);
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 110, &cache);
    try std.testing.expectEqual(MailboxAuthorities{}, authorities);
    try std.testing.expectEqual(@as(u64, 119), cache.valid_until_ticks);
    try std.testing.expectEqual(@as(u64, 4), cache.refresh_count);
    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 119, &cache);
    try std.testing.expectEqual(@as(u64, 4), cache.refresh_count);

    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 120, &cache);
    try std.testing.expectEqual(future_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(@as(u64, 10), authorities.bootstrap_service_id);
    try std.testing.expectEqual(@as(u64, 5), cache.refresh_count);

    try std.testing.expect(try runtime.revokeCapability(task.id, future_authority.id));
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 120, &cache);
    try std.testing.expectEqual(MailboxAuthorities{}, authorities);
    try std.testing.expectEqual(@as(u64, 6), cache.refresh_count);
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

test "executor retires inactive address spaces with mailbox caches and reuses slots" {
    var executor = Executor{};
    executor.mappings[0] = .{
        .state = .live,
        .address_space_id = 42,
        .dispatch_metadata = .{
            .owner_task_id = 8,
            .image_id = 9,
            .initial_instruction_pointer = 0x4000_1000,
            .initial_stack_pointer = 0x7FFF_EFF0,
            .bootstrap_mailbox_address = 0x4000_3000,
            .contract_flags = userspace_flags.FLAG_NX_PROOF_PROBE,
        },
        .mailbox_authority_cache = .{ .initialized = true, .refresh_count = 7 },
    };
    executor.rebuildMappingIndex();
    const retired_handle = executor.mappingHandle(42).?;
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == &executor.mappings[0]);
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 43) == null);
    var cached_handle = MappingHandle{};
    try std.testing.expect(executor.resolveMappingForDispatch(&cached_handle, 42) == &executor.mappings[0]);
    try std.testing.expect(cached_handle.eql(retired_handle));
    executor.mapping_index.reset();
    try std.testing.expect(executor.resolveMappingForDispatch(&cached_handle, 42) == &executor.mappings[0]);
    executor.rebuildMappingIndex();

    const event = task_runtime.AddressSpaceRetirementEvent{
        .address_space_id = 42,
        .reason = .snapshot_restore,
    };
    executor.retireAddressSpace(event);
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == null);
    try std.testing.expectEqual(MappingDispatchMetadata{}, executor.mappings[0].dispatch_metadata);
    try std.testing.expectEqual(@as(u64, 0), executor.mappings[0].mailbox_authority_cache.refresh_count);

    executor.retireAddressSpace(event);
    const reused_generation = executor.mappings[0].handle_generation;
    executor.mappings[0] = .{
        .state = .live,
        .handle_generation = reused_generation,
        .address_space_id = 42,
    };
    executor.rebuildMappingIndex();
    const reused_handle = executor.mappingHandle(42).?;
    try std.testing.expect(!reused_handle.eql(retired_handle));
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == null);
    try std.testing.expect(executor.findMappingByHandle(reused_handle, 42) == &executor.mappings[0]);
    try std.testing.expectEqual(@as(u8, 0), STEADY_MAPPING_INDEX_LOOKUPS_PER_DISPATCH);
    try std.testing.expectEqual(@as(u32, 1), nextMappingGeneration(std.math.maxInt(u32)));
}

test "executor defers active address-space retirement until kernel handoff" {
    var executor = Executor{};
    executor.mappings[0] = .{ .state = .live, .address_space_id = 42 };
    executor.rebuildMappingIndex();
    const active_handle = executor.mappingHandle(42).?;
    executor.active_mapping = &executor.mappings[0];
    executor.active_task_id = 7;

    executor.retireAddressSpace(.{ .address_space_id = 42, .reason = .terminate });
    try std.testing.expectEqual(MappingState.retire_pending, executor.mappings[0].state);
    try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
    try std.testing.expect(executor.mappingHandle(42) == null);
    try std.testing.expect(executor.findMappingByHandle(active_handle, 42) == null);
    try std.testing.expect(executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);

    executor.active_task_id = 0;
    executor.active_mapping = null;
    executor.drainPendingRetirements();
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);
    try std.testing.expect(executor.findMappingByHandle(active_handle, 42) == null);
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
