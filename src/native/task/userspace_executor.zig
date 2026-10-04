const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const embedded_file = @import("embedded_file.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
const userspace_bootstrap_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_flags = @import("userspace_flags.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_registry = @import("userspace_registry.zig");
const smp = @import("../../kernel/smp.zig");
const xstate = @import("../../arch/xstate.zig");
const timer = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/timer/timer.zig")
else
    struct {};
const demand_paging = @import("../../kernel/memory/demand_paging.zig");
const xhci_driver_task = @import("../drivers/xhci_driver_task.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const table_backing = @import("../core/table_backing.zig");
const root = @import("root");

pub const SHARES_GROUP_PAGE_TABLES = userspace_registry.SHARES_GROUP_PAGE_TABLES;
pub const USES_PKU_WITHIN_SHARED_TABLES = false;
const GROUP_SPACE_COUNT = userspace_registry.PRODUCTION_ADDRESS_SPACE_COUNT;

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn readCr2() usize {
            return 0;
        }

        pub fn allowSupervisorUserMemory() void {}
        pub fn forbidSupervisorUserMemory() void {}
        pub fn allowUserProtectionKey(_: u4) void {}
        pub fn wrpkru(_: u32) void {}
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
const NxProbeTarget = if (include_verification_evidence) u64 else void;

// A dispatch is bounded even when no other task is ready yet. This returns the
// runtime owner to deferred device work before it can discover new runnable work.
pub const DISPATCH_QUANTUM_TICKS: u64 = 2;
pub const DispatchQuantum = struct {
    task_id: u64 = 0,
    deadline_tick: u64 = 0,

    pub fn begin(task_id: u64, now_ticks: u64) DispatchQuantum {
        if (task_id == 0) native_util.impossibleByInvariant("dispatch quantum requires an active task");
        return .{ .task_id = task_id, .deadline_tick = now_ticks +| DISPATCH_QUANTUM_TICKS };
    }

    pub fn expired(self: DispatchQuantum, task_id: u64, now_ticks: u64) bool {
        return self.task_id != 0 and self.task_id == task_id and now_ticks >= self.deadline_tick;
    }
};

pub const ExecutionOutcome = enum(u8) {
    unavailable,
    yielded,
    wait_for_event,
    faulted,

    pub fn handedOff(self: ExecutionOutcome) bool {
        return self != .unavailable;
    }
};

pub const UserException = struct {
    vector: u8,
    error_code: u32,
    instruction_pointer: u64,
    fault_address: u64 = 0,

    pub fn reasonFingerprint(self: UserException) u64 {
        var fingerprint = native_util.fnv1a64AppendByte(native_util.FNV1A_64_OFFSET_BASIS, self.vector);
        fingerprint = native_util.fnv1a64AppendU32LittleEndian(fingerprint, self.error_code);
        fingerprint = native_util.fnv1a64AppendU64LittleEndian(fingerprint, self.instruction_pointer);
        return native_util.fnv1a64AppendU64LittleEndian(fingerprint, self.fault_address);
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
            pub const InterruptFrame = @import("../../kernel/interrupts/isr.zig").InterruptFrame;
            pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

            pub fn registerHandler(_: u8, _: InterruptHandler) void {}
            pub fn setRuntimePreemption(_: *const fn (regs: *InterruptFrame) void) void {}
        };

        pub const paging = struct {
            pub const PageDirectory = opaque {};
            pub const UserPermissions = struct {
                writable: bool,
                executable: bool = false,
                write_through: bool = false,
                cache_disabled: bool = false,
                protection_key: u4 = 0,
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
            pub fn activateUserDomain(_: *const UserAddressSpace, _: u4) void {}
            pub fn switchToKernelAddressSpace() void {}
            pub fn mapOwnedUserRange(_: *UserAddressSpace, _: usize, _: usize, _: UserPermissions) UserMapError!void {
                return error.OutOfMemory;
            }
            pub fn validateUserRangeAvailable(_: *const UserAddressSpace, _: usize, _: usize) UserMapError!void {}
            pub fn releaseUserRange(_: *const UserAddressSpace, _: usize, _: usize) UserMapError!void {}
            pub fn mapBorrowedPhysicalUserRange(
                _: *UserAddressSpace,
                _: usize,
                _: u64,
                _: usize,
                _: UserPermissions,
            ) UserMapError!void {
                return error.OutOfMemory;
            }
            pub fn writeOwnedUserRange(_: *const UserAddressSpace, _: usize, _: []const u8) UserWriteError!void {
                return error.PageNotOwned;
            }
            pub fn readOwnedUserRange(_: *const UserAddressSpace, _: usize, _: []u8) UserWriteError!void {
                return error.PageNotOwned;
            }
            pub fn copyOwnedUserPageFromPhysical(_: *const UserAddressSpace, _: usize, _: u64) UserWriteError!void {
                return error.PageNotOwned;
            }
            pub fn ownedUserPageIsExecutable(_: *const UserAddressSpace, _: usize) ?bool {
                return null;
            }
            pub fn destroyUserAddressSpace(_: *UserAddressSpace) UserAddressSpaceDestroyError!void {}
            pub fn unmapBorrowedCurrentPage(_: usize) bool {
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
const GENERAL_PROTECTION_FAULT_VECTOR: u8 = 13;
const PAGE_FAULT_VECTOR: u8 = 14;
const CONTAINABLE_USER_EXCEPTION_VECTORS = [_]u8{
    0, // Divide error.
    1, // Debug exception.
    3, // Breakpoint.
    4, // Overflow.
    5, // Bound-range exceeded.
    6, // Invalid opcode.
    7, // Device not available.
    10, // Invalid TSS.
    11, // Segment not present.
    12, // Stack-segment fault.
    GENERAL_PROTECTION_FAULT_VECTOR,
    16, // x87 floating-point exception.
    17, // Alignment check.
    19, // SIMD floating-point exception.
    21, // Control-protection exception.
};
const TRAP_STACK_GUARD_BYTES: usize = PAGE_SIZE;
// Native smoke requires at least 25% unused watermark headroom.
pub const TRAP_STACK_USABLE_BYTES: usize = units.kibibytes(36);
pub const TRAP_STACK_TOTAL_BYTES: usize = TRAP_STACK_GUARD_BYTES + TRAP_STACK_USABLE_BYTES;

const TRAP_STACK_PAINT_PATTERN: u32 = 0x57ACC0DE;
const MAPPING_INDEX_CAPACITY: usize = task_runtime.MAX_TASKS * 2;
pub const USER_ADDRESS_SPACE_ACTIVATIONS_PER_DISPATCH: u8 = 1;
pub const STATIC_HANDOFF_STACK_INSTALLS_PER_BIND: u8 = 1;
pub const STEADY_ADDRESS_SPACE_IMAGE_INDEX_LOOKUPS: u8 = 0;
pub const STEADY_MAPPING_INDEX_LOOKUPS_PER_DISPATCH: u8 = 0;
pub const COLD_MAPPING_LINEAR_SLOT_SCANS: u8 = 0;
pub const STEADY_RETIREMENT_SLOT_SCANS_PER_DISPATCH: u8 = 0;
pub const RETIREMENT_MAPPING_HANDLE_RELOOKUPS: u8 = 0;
pub const UNRELATED_CAPABILITY_MUTATION_AUTHORITY_SCANS: u8 = 0;
pub const UNCHANGED_RESUME_KERNEL_MAILBOX_FIELD_WRITES_PER_DISPATCH: u8 = 0;
pub const MAPPING_RELEASE_RESOLUTION_RELOOKUPS: u8 = 0;
const MaterializationError = freestanding.paging.UserAddressSpaceCreateError || freestanding.paging.UserMapError || freestanding.paging.UserWriteError || error{
    MappingTableFull,
    ImageExtentInvalid,
    AddressSpaceOwnerInvalid,
    AddressSpaceImageMismatch,
    AddressSpaceRetiring,
    InitialContextInvalid,
    LaunchPolicyInvalid,
};

var trap_stack: ?*align(PAGE_SIZE) [TRAP_STACK_TOTAL_BYTES]u8 = null;
var trap_stack_guard_armed: bool = false;

pub fn reserveTrapStackStorage() error{OutOfMemory}!void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (trap_stack != null) return;
    const storage = kernel_memory.claimEarly(TRAP_STACK_TOTAL_BYTES, PAGE_SIZE) orelse return error.OutOfMemory;
    trap_stack = @ptrCast(@alignCast(storage));
}

fn trapStackStorage() *align(PAGE_SIZE) [TRAP_STACK_TOTAL_BYTES]u8 {
    return trap_stack orelse unreachable;
}

fn trapStackPaintableBase() usize {
    return @intFromPtr(trapStackStorage()) + TRAP_STACK_GUARD_BYTES;
}

fn armTrapStackGuard() void {
    if (builtin.target.os.tag != .freestanding) return;
    if (trap_stack_guard_armed) return;
    const guard_address = @intFromPtr(trapStackStorage());
    _ = freestanding.paging.unmapBorrowedCurrentPage(guard_address);
    const base = trapStackPaintableBase();
    const words: [*]u32 = @ptrFromInt(base);
    const count = TRAP_STACK_USABLE_BYTES / @sizeOf(u32);
    var index: usize = 0;
    while (index < count) : (index += 1) {
        words[index] = TRAP_STACK_PAINT_PATTERN;
    }
    trap_stack_guard_armed = true;
}

pub fn prepareKernelStack() usize {
    if (builtin.target.os.tag != .freestanding) return 0;
    armTrapStackGuard();
    return @intFromPtr(trapStackStorage()) + TRAP_STACK_TOTAL_BYTES;
}

pub fn reportTrapStackPeak() void {
    if (builtin.target.os.tag != .freestanding) return;
    if (!trap_stack_guard_armed) return;
    const base = trapStackPaintableBase();
    const top = @intFromPtr(trapStackStorage()) + TRAP_STACK_TOTAL_BYTES;
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
const PreemptCheck = *const fn (u64) bool;
var preempt_check: ?PreemptCheck = null;

pub fn setPreemptCheck(check: ?PreemptCheck) void {
    preempt_check = check;
}
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
    if (TRAP_STACK_TOTAL_BYTES % PAGE_SIZE != 0 or TRAP_STACK_TOTAL_BYTES <= TRAP_STACK_GUARD_BYTES) {
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

extern var zigos_userspace_xstate: usize;
extern var zigos_kernel_xstate: usize;
extern fn zigos_enter_userspace(context: usize, state: usize) callconv(.c) u32;

pub fn enterPreparedUserContext(context: *const UserContext64) u32 {
    if (builtin.target.os.tag != .freestanding) return 0;
    var storage: xstate.Storage = .{};
    storage.initialize();
    defer storage.erase();
    return enterUserContextWithState(context, storage.state());
}

fn enterUserContextWithState(context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
    if (!smp.isRuntimeOwner()) native_util.impossibleByInvariant("one runtime CPU owns the userspace entry state");
    const result = zigos_enter_userspace(@intFromPtr(context), @intFromPtr(state));
    zigos_userspace_resume_eip = 0;
    zigos_userspace_resume_esp = 0;
    zigos_userspace_xstate = 0;
    zigos_kernel_xstate = 0;
    return result;
}

const MappingState = enum(u8) {
    building,
    live,
    retire_pending,
};

const MappingLaunchPolicy = packed struct(u32) {
    contract_flags: u16 = 0,
    heartbeat_increment: u12 = 1,
    protection_key: u4 = 0,
};

const MappingDispatchMetadata = struct {
    owner_task_id: u64 = 0,
    image_id: u64 = 0,
    initial_instruction_pointer: u64 = 0,
    initial_stack_pointer: u64 = 0,
    bootstrap_mailbox_address: u32 = 0,
    launch_policy: MappingLaunchPolicy = .{},

    fn contractFlags(self: MappingDispatchMetadata) u32 {
        return self.launch_policy.contract_flags;
    }

    fn heartbeatIncrement(self: MappingDispatchMetadata) u32 {
        return self.launch_policy.heartbeat_increment;
    }

    fn protectionKey(self: MappingDispatchMetadata) u4 {
        return self.launch_policy.protection_key;
    }
};

const MAPPING_DISPATCH_METADATA_SIZE_CEILING_BYTES: usize = 40;
const MAPPING_ENTRY_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding) 688 else 464;
const MAPPING_ARENA_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding) 98_304 else 66_560;

const MappedImageRegions = struct {
    const Range = struct { start: usize = 0, size: usize = 0 };
    ranges: [task_runtime.MAX_EXECUTABLE_SEGMENTS]Range = @as([task_runtime.MAX_EXECUTABLE_SEGMENTS]Range, @splat(.{})),
    count: usize = 0,
    stack: Range = .{},
};

const MappingEntry = struct {
    state: MappingState = .building,
    address_space_id: u64 = 0,
    address_space: ?freestanding.paging.UserAddressSpace = null,
    image_regions: ?*MappedImageRegions = null,
    owned_xstate: ?*xstate.Storage = null,
    dispatch_metadata: MappingDispatchMetadata = .{},
    resume_valid: bool = false,
    resume_instruction_pointer: u64 = 0,
    resume_stack_pointer: u64 = 0,
    user_context64: UserContext64 = .{},
    yield_count: u64 = 0,
    last_user_counter: u32 = 0,
    page_fault_count: u64 = 0,
    last_fault_address: u64 = 0,
    last_fault_error_code: u32 = 0,
    mailbox_authority_cache: MailboxAuthorityCache = .{},
    mailbox_publication_cache: MailboxPublicationCache = .{},
    initial_mailbox_prepared: bool = false,
    captured_mailbox: if (builtin.target.os.tag == .freestanding) userspace_bootstrap_mailbox.Mailbox else void =
        if (builtin.target.os.tag == .freestanding) .{} else {},
    mailbox_captured: bool = false,

    fn pageDirectory(self: *const MappingEntry) *freestanding.paging.PageDirectory {
        return self.address_space.?.directory;
    }
};

const MappingSlot = struct {
    in_use: bool = false,
    mapping: MappingEntry = .{},
};

fn mappingSlotAddressSpaceId(slot: *const MappingSlot) u64 {
    return slot.mapping.address_space_id;
}

pub const MappingArena = indexed_arena.PagedIndexedArena(
    MappingSlot,
    task_runtime.MAX_TASKS,
    1,
    MAPPING_INDEX_CAPACITY,
    mappingSlotAddressSpaceId,
);
comptime {
    if (@sizeOf(MappingDispatchMetadata) > MAPPING_DISPATCH_METADATA_SIZE_CEILING_BYTES) {
        @compileError("userspace mapping dispatch metadata exceeds its compact size ceiling");
    }
    if (@sizeOf(MappingEntry) > MAPPING_ENTRY_SIZE_CEILING_BYTES) {
        @compileError("userspace mapping entry exceeds its compact size ceiling");
    }
    if (@sizeOf(MappingArena) > MAPPING_ARENA_SIZE_CEILING_BYTES) {
        @compileError("userspace mapping arena exceeds its compact size ceiling");
    }
}
const heap_backed_mappings = builtin.target.os.tag == .freestanding;
const MappingArenaBacking = if (heap_backed_mappings) ?*MappingArena else MappingArena;

pub const MappingHandle = MappingArena.Handle;

const MappingResolution = struct {
    mappings: *MappingArena,
    slot_index: usize,
    entry: *MappingEntry,
    handle: MappingHandle,
};

var trap_handler_registered = false;
var registered_executor: ?*Executor = null;

fn activeUserMemoryMapping(executor: *Executor, caller_task_id: u64) ?*MappingEntry {
    if (caller_task_id == 0 or executor.active_task_id != caller_task_id) return null;
    const mapping = executor.active_mapping orelse return null;
    const mappings = executor.mappingArena() orelse return null;
    const slot = mappings.getByHandle(executor.active_mapping_handle) orelse return null;
    if (&slot.mapping != mapping) return null;
    if (mapping.state != .live or mapping.dispatch_metadata.owner_task_id != caller_task_id or mapping.address_space == null) return null;
    return mapping;
}

pub fn prepareUserMemory(caller_task_id: u64, addr: usize, len: usize, write: bool) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    const executor = registered_executor orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    return demand_paging.prepareUserRange(&mapping.address_space.?, addr, len, write);
}

pub fn readUserMemory(caller_task_id: u64, addr: usize, destination: []u8) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    const executor = registered_executor orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    const space = &mapping.address_space.?;
    if (!demand_paging.prepareUserRange(space, addr, destination.len, false)) return false;
    freestanding.paging.readOwnedUserRange(space, addr, destination) catch return false;
    return true;
}

pub fn writeUserMemory(caller_task_id: u64, addr: usize, source: []const u8) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    const executor = registered_executor orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    const space = &mapping.address_space.?;
    if (!demand_paging.prepareUserRange(space, addr, source.len, true)) return false;
    freestanding.paging.writeOwnedUserRange(space, addr, source) catch return false;
    return true;
}

pub fn activeTaskId() u64 {
    const executor = registered_executor orelse return 0;
    return executor.activeTaskId();
}

pub fn requestEventWait() void {
    const executor = registered_executor orelse return;
    executor.last_yield_disposition = .wait_for_event;
}

pub const Executor = struct {
    initialized: bool = false,
    binding_owner: ?*const anyopaque = null,
    bound_runtime: ?*task_runtime.Runtime = null,
    mapped_object_table: ?*shared_memory.Table = null,
    mapped_object_count: u16 = 0,
    probe_marker_printed: bool = false,
    resume_marker_printed: bool = false,
    active_task_id: u64 = 0,
    dispatch_quantum: DispatchQuantum = .{},
    active_mapping: ?*MappingEntry = null,
    active_mapping_handle: MappingHandle = .{},
    handoff_completed: bool = false,
    pending_user_context64: UserContext64 = .{},
    last_trap_instruction_pointer: u64 = 0,
    last_trap_stack_pointer: u64 = 0,
    last_trap_counter: u32 = 0,
    last_yield_disposition: userspace_bootstrap_mailbox.YieldDisposition = .runnable,
    last_yield_ui_revision: u64 = 0,
    last_user_exception: ?UserException = null,
    last_fault_task_id: u64 = 0,
    last_fault_address_space_id: u64 = 0,
    last_fault_address: u64 = 0,
    last_fault_error_code: u32 = 0,
    user_page_fault_count: u64 = 0,
    active_nx_probe_target: NxProbeTarget = if (include_verification_evidence) 0 else {},
    mappings: MappingArenaBacking = if (heap_backed_mappings) null else MappingArena.init(),
    group_spaces: [GROUP_SPACE_COUNT]?freestanding.paging.UserAddressSpace = @splat(null),
    group_refs: [GROUP_SPACE_COUNT]u8 = @splat(0),

    comptime {
        if (heap_backed_mappings and @sizeOf(@This()) > units.kibibytes(1)) {
            @compileError("heap-backed userspace executors exceed their compact resident layout");
        }
    }

    fn mappingArena(self: *Executor) ?*MappingArena {
        if (comptime heap_backed_mappings) return self.mappings;
        return &self.mappings;
    }

    fn mappingArenaConst(self: *const Executor) ?*const MappingArena {
        if (comptime heap_backed_mappings) return self.mappings;
        return &self.mappings;
    }

    fn ensureMappingArena(self: *Executor) error{OutOfMemory}!*MappingArena {
        if (self.mappingArena()) |mappings| return mappings;
        if (comptime heap_backed_mappings) {
            const mappings = table_backing.alloc(MappingArena) orelse return error.OutOfMemory;
            initializeMappingArena(mappings);
            self.mappings = mappings;
            return mappings;
        }
        return &self.mappings;
    }

    fn releaseMappingArena(self: *Executor) void {
        if (comptime heap_backed_mappings) {
            if (self.mappings) |mappings| {
                table_backing.free(MappingArena, mappings);
                self.mappings = null;
            }
        }
    }

    pub fn init(self: *Executor) void {
        if (comptime builtin.target.os.tag == .freestanding) shared_memory.setMappedObjectLifetime(.{
            .context = self,
            .register = registerMappedObject,
            .unregister = unregisterMappedObject,
        });
        if (builtin.target.os.tag != .freestanding) return;
        registered_executor = self;
        if (self.initialized) return;
        if (!trap_handler_registered) {
            freestanding.isr.registerHandler(USERSPACE_TRAP_VECTOR, userspaceTrapHandler);
            for (CONTAINABLE_USER_EXCEPTION_VECTORS) |vector| {
                freestanding.isr.registerHandler(vector, userspaceExceptionHandler);
            }
            freestanding.isr.registerHandler(PAGE_FAULT_VECTOR, userspacePageFaultHandler);
            freestanding.isr.setRuntimePreemption(userspaceInterruptPreemption);
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
        const resolution = self.findMappingWithHandle(event.address_space_id) orelse return;
        const mapping = resolution.entry;
        if (self.active_task_id != 0 and self.active_mapping == mapping) {
            if (!resolution.handle.eql(self.active_mapping_handle)) {
                native_util.impossibleByInvariant("active userspace mapping handle points at a different slot");
            }
            mapping.state = .retire_pending;
            self.handoff_completed = true;
            zigos_userspace_resume_requested = 1;
            return;
        }
        releaseMapping(self, resolution.mappings, resolution.slot_index, mapping);
    }

    pub fn materializedCount(self: *const Executor) usize {
        const mappings = self.mappingArenaConst() orelse return 0;
        return mappings.countInUse();
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
        self.dispatch_quantum = .{};
        self.active_mapping = null;
        self.active_mapping_handle = .{};
        self.handoff_completed = false;
        self.pending_user_context64 = .{};
        self.last_trap_instruction_pointer = 0;
        self.last_trap_stack_pointer = 0;
        self.last_trap_counter = 0;
        self.last_user_exception = null;
        self.last_fault_task_id = 0;
        self.last_fault_address_space_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
        self.user_page_fault_count = 0;
        if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
        zigos_userspace_resume_requested = 0;
        zigos_userspace_resume_esp = 0;
        zigos_userspace_resume_eip = 0;
        publishRootActiveTaskId(0);
        if (registered_executor == self) {
            shared_memory.clearMappedObjectLifetime(self);
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
        expected_fault_address: u64,
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
        expected_fault_address: u64,
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

    pub fn lastUserException(self: *const Executor) ?UserException {
        return self.last_user_exception;
    }

    pub fn bootstrapMailboxSnapshot(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *const task_runtime.Runtime,
        task_id: u64,
    ) ?userspace_bootstrap_mailbox.Mailbox {
        return switch (self.inspectBootstrapMailbox(catalog, runtime, task_id)) {
            .ready => |mailbox| mailbox,
            .miss => null,
        };
    }

    pub fn bootstrapMailboxSnapshotMissReason(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *const task_runtime.Runtime,
        task_id: u64,
    ) []const u8 {
        return switch (self.inspectBootstrapMailbox(catalog, runtime, task_id)) {
            .ready => "ok",
            .miss => |reason| @tagName(reason),
        };
    }

    fn inspectBootstrapMailbox(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *const task_runtime.Runtime,
        task_id: u64,
    ) MailboxSnapshotInspection {
        if (builtin.target.os.tag != .freestanding) return .{ .miss = .host };
        const task = runtime.findConst(task_id) orelse return .{ .miss = .task };
        if (task.state != .active) return .{ .miss = .inactive };
        const mapping = self.findMapping(task.address_space_id) orelse return .{ .miss = .mapping };
        if ((mapping.state != .live and mapping.state != .retire_pending) or mapping.address_space == null) {
            return .{ .miss = .mapping_state };
        }
        const mailbox_address = mailboxAddressForSnapshot(mapping, catalog.findById(task.launch.image_id));
        if (mailbox_address == 0) return .{ .miss = .address };
        if (readUserspaceMailboxFromMapping(mapping, mailbox_address)) |mailbox| {
            if (mailboxBelongsToTask(mailbox, task_id)) {
                storeCapturedMailbox(mapping, mailbox);
                return .{ .ready = mailbox };
            }
        }
        if (mapping.mailbox_captured) {
            if (comptime builtin.target.os.tag == .freestanding) {
                const captured = mapping.captured_mailbox;
                if (mailboxBelongsToTask(captured, task_id)) return .{ .ready = captured };
                if (captured.version == userspace_bootstrap_mailbox.VERSION) return .{ .miss = .sibling };
                return .{ .miss = .version };
            }
        }
        return .{ .miss = .unread };
    }

    // Publish an opened document before the first instruction of a fresh app.
    // Capture it immediately: a sibling may use the shared mailbox before this
    // task's first dispatch.
    pub fn bindInitialDocument(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
        task_id: u64,
        binding: userspace_bootstrap_mailbox.DocumentBinding,
        clipboard: userspace_bootstrap_mailbox.ClipboardBinding,
        now_ticks: u64,
    ) bool {
        if (builtin.target.os.tag != .freestanding) return false;
        if (self.active_task_id != 0 or self.bound_runtime != runtime or !binding.isValid()) return false;
        const task = runtime.find(task_id) orelse return false;
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable() or
            !task.hasCapability(binding.endpoint_capability_id)) return false;
        const granted = capability_table.requireUsable(binding.endpoint_capability_id, now_ticks) catch return false;
        if (!granted.holder.eql(task.owner) or granted.scope.task_id != task_id or
            granted.target.kind != .endpoint or !granted.rights.has(.endpoint_send) or
            !granted.rights.has(.endpoint_recv)) return false;
        const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        if (address_space.owner_task_id != task.id or address_space.image_id != task.launch.image_id) return false;
        const image = catalog.findById(task.launch.image_id) orelse return false;
        if (!image.elf_file.isPresent() or image.bootstrap_mailbox_address == 0) return false;
        self.init();
        const mapping = (self.ensureMaterialized(address_space, image) catch return false).entry;
        if (mapping.resume_valid or mapping.initial_mailbox_prepared or mapping.mailbox_publication_cache.initialized) return false;
        var update = self.prepareBootstrapMailbox(mapping, task, capability_table, now_ticks) orelse return false;
        update.document = binding;
        var mailbox = kernelPublishedMailbox(update, null);
        if (clipboard.isValid()) {
            if (!task.hasCapability(clipboard.endpoint_capability_id)) return false;
            const transport = capability_table.requireUsable(clipboard.endpoint_capability_id, now_ticks) catch return false;
            if (!transport.holder.eql(task.owner) or transport.scope.task_id != task_id or
                transport.target.kind != .endpoint or !transport.rights.has(.endpoint_send) or !transport.rights.has(.endpoint_recv)) return false;
            mailbox.auxiliary_kind = .clipboard;
            mailbox.auxiliary = .{ .clipboard = clipboard };
        }
        freestanding.paging.writeOwnedUserRange(&mapping.address_space.?, update.address, std.mem.asBytes(&mailbox)) catch return false;
        storeCapturedMailbox(mapping, mailbox);
        mapping.initial_mailbox_prepared = true;
        return true;
    }

    // The compositor can receive its launcher after bootstrap. Read the task's
    // captured state when a sibling owns the shared mailbox, then capture the
    // binding immediately so the next sibling cannot erase it.
    pub fn bindLauncherChannel(self: *Executor, catalog: *userspace_loader.Catalog, runtime: *task_runtime.Runtime, capability_table: *const capability.CapabilityTable, task_id: u64, binding: userspace_bootstrap_mailbox.LauncherBinding, now_ticks: u64) bool {
        return self.bindNativeChannel(catalog, runtime, capability_table, task_id, .{ .launcher = binding }, now_ticks);
    }

    pub fn bindIdentityChannel(self: *Executor, catalog: *userspace_loader.Catalog, runtime: *task_runtime.Runtime, capability_table: *const capability.CapabilityTable, task_id: u64, binding: userspace_bootstrap_mailbox.IdentityBinding, now_ticks: u64) bool {
        return self.bindNativeChannel(catalog, runtime, capability_table, task_id, .{ .identity = binding }, now_ticks);
    }

    const NativeChannelBinding = union(enum) { launcher: userspace_bootstrap_mailbox.LauncherBinding, identity: userspace_bootstrap_mailbox.IdentityBinding };

    fn bindNativeChannel(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
        task_id: u64,
        binding: NativeChannelBinding,
        now_ticks: u64,
    ) bool {
        if (builtin.target.os.tag != .freestanding) return false;
        const transport = switch (binding) {
            inline else => |value| blk: {
                if (!value.isValid()) return false;
                break :blk value.endpoint_capability_id;
            },
        };
        if (self.active_task_id != 0 or self.bound_runtime != runtime) return false;
        const task = runtime.find(task_id) orelse return false;
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable() or
            !task.hasCapability(transport)) return false;
        const granted = capability_table.requireUsable(transport, now_ticks) catch return false;
        if (!granted.holder.eql(task.owner) or granted.scope.task_id != task_id or
            granted.target.kind != .endpoint or !granted.rights.has(.endpoint_send) or
            !granted.rights.has(.endpoint_recv)) return false;
        const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        if (address_space.owner_task_id != task_id or address_space.image_id != task.launch.image_id) return false;
        const image = catalog.findById(task.launch.image_id) orelse return false;
        if (!image.elf_file.isPresent() or image.bootstrap_mailbox_address == 0) return false;
        self.init();
        const mapping = (self.ensureMaterialized(address_space, image) catch return false).entry;
        var update = self.prepareBootstrapMailbox(mapping, task, capability_table, now_ticks) orelse return false;
        update.preserve_runtime_state = mapping.resume_valid or mapping.initial_mailbox_prepared;
        const preserved = preservedMailboxForUpdate(mapping, readUserspaceMailboxFromMapping(mapping, update.address), update);
        if (update.preserve_runtime_state and preserved == null) return false;
        var mailbox = kernelPublishedMailbox(update, preserved);
        switch (binding) {
            .launcher => |value| {
                if (mailbox.ui_channel_kind == .document) return false;
                mailbox.ui_channel_kind = .launcher;
                mailbox.ui_channel = .{ .launcher = value };
            },
            .identity => |value| {
                if (mailbox.auxiliary_kind == .clipboard) return false;
                if (mailbox.auxiliary_kind == .identity) {
                    if (capability_table.requireUsable(mailbox.auxiliary.identity.endpoint_capability_id, now_ticks)) |_| return false else |_| {}
                }
                mailbox.auxiliary_kind = .identity;
                mailbox.auxiliary = .{ .identity = value };
            },
        }
        freestanding.paging.writeOwnedUserRange(&mapping.address_space.?, update.address, std.mem.asBytes(&mailbox)) catch return false;
        storeCapturedMailbox(mapping, mailbox);
        mapping.initial_mailbox_prepared = true;
        return true;
    }

    pub fn observedUserCounterStagePulse(
        self: *Executor,
        address_space_id: u64,
        expected_stage: userspace_bootstrap_mailbox.Stage,
        expected_pulse: u16,
    ) bool {
        const mapping = self.findMapping(address_space_id) orelse return false;
        return @as(u8, @truncate(mapping.last_user_counter >> 24)) == @backingInt(expected_stage) and
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
        if (!smp.isRuntimeOwner()) return .unavailable;
        if (!self.initialized) return .unavailable;
        if (self.bound_runtime != runtime) return .unavailable;
        var task_borrow = runtime.borrowResolvedTask(task);
        defer task_borrow.release();
        _ = xhci_driver_task.dispatchForTask(task.id);
        if (debugIndexChecksEnabled()) {
            const bound_task = runtime.findConst(task.id) orelse
                native_util.impossibleByInvariant("prepared userspace task is absent from the bound runtime");
            if (bound_task != task) native_util.impossibleByInvariant("prepared userspace task does not belong to the bound runtime");
        }
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return .unavailable;

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
            (mapping.dispatch_metadata.contractFlags() & userspace_flags.FLAG_NX_PROOF_PROBE) != 0)
            mapping.dispatch_metadata.bootstrap_mailbox_address
        else
            0;

        self.active_mapping = mapping;
        self.active_mapping_handle = mapping_handle.*;
        self.active_task_id = task.id;
        if (comptime include_verification_evidence) self.active_nx_probe_target = nx_probe_target;
        publishRootActiveTaskId(task.id);
        self.handoff_completed = false;
        self.last_yield_disposition = .runnable;
        self.last_yield_ui_revision = 0;
        self.last_user_exception = null;
        zigos_userspace_resume_requested = 0;

        activateMappingForDispatch(mapping, mailbox_update);
        _ = @call(.never_inline, enterUserspace, .{
            self,
        });

        if (freestanding.paging.getCurrentPageDirectory() != kernel_page_directory) {
            freestanding.paging.switchToKernelAddressSpace();
        }

        const completed_mapping_handle = self.active_mapping_handle;
        self.active_task_id = 0;
        self.dispatch_quantum = .{};
        self.active_mapping = null;
        self.active_mapping_handle = .{};
        if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
        publishRootActiveTaskId(0);
        zigos_userspace_resume_requested = 0;

        const user_faulted = self.last_user_exception != null;
        if (!user_faulted and self.handoff_completed and !self.probe_marker_printed) {
            common.printBootMarker(boot_markers.userspace_exec_probe_ok);
            self.probe_marker_printed = true;
        }
        if (!user_faulted and
            self.handoff_completed and
            mapping.yield_count >= 2 and
            mapping.last_user_counter >= 2 and
            !self.resume_marker_printed)
        {
            common.printBootMarker(boot_markers.userspace_resume_ok);
            self.resume_marker_printed = true;
        }
        self.releaseRetiredMappingAfterHandoff(completed_mapping_handle, mapping);
        if (!self.handoff_completed) return .unavailable;
        if (user_faulted) return .faulted;
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
        const resolution = self.findMappingWithHandle(retired_address_space_id) orelse return false;
        const mapping = resolution.entry;
        if (mapping.state != .live) return false;

        const kernel_page_directory = freestanding.paging.getCurrentPageDirectory();
        if (kernel_page_directory == mapping.pageDirectory()) return false;
        const user_page_directory = mapping.pageDirectory();
        const frames_before = freestanding.paging.frameStats().allocated;

        self.active_mapping = mapping;
        self.active_mapping_handle = resolution.handle;
        self.active_task_id = task_id;
        publishRootActiveTaskId(task_id);
        self.handoff_completed = false;
        zigos_userspace_resume_requested = 0;
        freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());

        const rehosted = runtime.rehostTask(task_id, now_ticks) catch false;
        const deferred = rehosted and
            freestanding.paging.getCurrentPageDirectory() == user_page_directory and
            mapping.state == .retire_pending and
            self.handoff_completed and
            zigos_userspace_resume_requested == 1 and
            freestanding.paging.frameStats().allocated == frames_before;

        freestanding.paging.switchToKernelAddressSpace();
        const completed_mapping_handle = self.active_mapping_handle;
        self.active_task_id = 0;
        self.active_mapping = null;
        self.active_mapping_handle = .{};
        publishRootActiveTaskId(0);
        zigos_userspace_resume_requested = 0;
        self.releaseRetiredMappingAfterHandoff(completed_mapping_handle, mapping);
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
            mapping.resume_valid or mapping.initial_mailbox_prepared,
            task.component_class,
            mapping.dispatch_metadata.contractFlags(),
            mapping.dispatch_metadata.heartbeatIncrement(),
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
            image.heartbeat_increment,
            userspace_registry.protectionKeyForBundle(image.bundleIdSlice()),
        );
        if (self.findMappingWithHandle(address_space.id)) |resolution| {
            if (resolution.entry.state != .live) return error.AddressSpaceRetiring;
            if (!mappingDispatchMetadataCompatible(resolution.entry.dispatch_metadata, dispatch_metadata)) {
                native_util.impossibleByInvariant("materialized userspace dispatch metadata changed without retirement");
            }
            return resolution;
        }

        const mappings = try self.ensureMappingArena();
        const handle = mappings.reserveHandle(address_space.id) orelse return error.MappingTableFull;
        const slot = mappings.getByHandle(handle) orelse
            native_util.impossibleByInvariant("reserved userspace mapping handle is not live");
        const entry = &slot.mapping;
        entry.* = .{
            .state = .building,
            .address_space_id = address_space.id,
            .dispatch_metadata = dispatch_metadata,
        };
        errdefer self.releaseMapping(mappings, handle.slotIndex(), entry);

        entry.owned_xstate = table_backing.alloc(xstate.Storage) orelse return error.OutOfMemory;
        entry.owned_xstate.?.initialize();
        entry.address_space = try self.acquireUserAddressSpace(image.bundleIdSlice());
        entry.image_regions = table_backing.alloc(MappedImageRegions) orelse return error.OutOfMemory;

        for (address_space.regions[0..address_space.region_count]) |region| {
            switch (region.kind) {
                .load_segment => {
                    if (try userRangeOccupied(&entry.address_space.?, region.virtual_address, region.size_bytes)) continue;
                    const image_regions = entry.image_regions.?;
                    image_regions.ranges[image_regions.count] = .{ .start = @intCast(region.virtual_address), .size = region.size_bytes };
                    image_regions.count += 1;
                    try mapLoadRegion(&entry.address_space.?, region, image.elf_file, dispatch_metadata.protectionKey());
                },
                .stack => {
                    const mapped_base = try mapUniqueZeroedStack(
                        &entry.address_space.?,
                        region.virtual_address,
                        @as(usize, region.size_bytes),
                        region.access,
                        dispatch_metadata.protectionKey(),
                    );
                    entry.image_regions.?.stack = .{ .start = @intCast(mapped_base), .size = region.size_bytes };
                    const runtime = self.bound_runtime orelse return error.AddressSpaceOwnerInvalid;
                    const live = runtime.findAddressSpace(address_space.id) orelse return error.AddressSpaceOwnerInvalid;
                    if (!live.relocateStack(mapped_base, region.size_bytes)) return error.InitialContextInvalid;
                    entry.dispatch_metadata.initial_stack_pointer = std.math.sub(u64, live.stack_top, 16) catch
                        return error.InitialContextInvalid;
                },
            }
        }

        entry.state = .live;
        return .{
            .mappings = mappings,
            .slot_index = handle.slotIndex(),
            .entry = entry,
            .handle = handle,
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
        const mappings = self.mappingArena() orelse return null;
        const slot_index = mappings.slotIndexOf(address_space_id) orelse return null;
        const slot = mappings.slotAt(slot_index);
        const entry = &slot.mapping;
        if (entry.state != .live and entry.state != .retire_pending) {
            native_util.impossibleByInvariant("executor mapping index points at a non-live mapping");
        }
        if (entry.address_space_id != address_space_id) native_util.impossibleByInvariant("executor mapping index points at the wrong mapping");
        const handle = mappings.handleForIndex(slot_index) orelse
            native_util.impossibleByInvariant("executor mapping index points at an unclaimed slot");
        return .{
            .mappings = mappings,
            .slot_index = slot_index,
            .entry = entry,
            .handle = handle,
        };
    }

    fn findMappingByHandle(self: *Executor, handle: MappingHandle, expected_address_space_id: u64) ?*MappingEntry {
        const mappings = self.mappingArena() orelse return null;
        const slot = mappings.getByHandle(handle) orelse return null;
        const entry = &slot.mapping;
        if (entry.state != .live) return null;
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

    fn acquireUserAddressSpace(self: *Executor, bundle_id: []const u8) MaterializationError!freestanding.paging.UserAddressSpace {
        if (comptime !SHARES_GROUP_PAGE_TABLES) {
            return freestanding.paging.createUserAddressSpace();
        }
        const group = userspace_registry.addressSpaceGroupForBundle(bundle_id) orelse
            return freestanding.paging.createUserAddressSpace();
        const index = @backingInt(group);
        if (self.group_refs[index] == 0) {
            const space = try freestanding.paging.createUserAddressSpace();
            self.group_spaces[index] = space;
            self.group_refs[index] = 1;
            return space;
        }
        self.group_refs[index] += 1;
        return self.group_spaces[index].?;
    }

    fn releaseSharedGroupSpace(self: *Executor, space: *freestanding.paging.UserAddressSpace) bool {
        if (comptime !SHARES_GROUP_PAGE_TABLES) return false;
        var index: usize = 0;
        while (index < GROUP_SPACE_COUNT) : (index += 1) {
            const shared = self.group_spaces[index] orelse continue;
            if (shared.directory != space.directory) continue;
            self.group_refs[index] -= 1;
            if (self.group_refs[index] != 0) return true;
            self.group_spaces[index] = null;
            return false;
        }
        return false;
    }

    fn releaseMapping(
        self: *Executor,
        mappings: *MappingArena,
        slot_index: usize,
        entry: *MappingEntry,
    ) void {
        if (builtin.mode == .debug) {
            std.debug.assert(&mappings.slotAt(slot_index).mapping == entry);
        }
        if (self.mapped_object_table) |table| {
            const handle = mappings.handleForIndex(slot_index) orelse
                native_util.impossibleByInvariant("shared-memory retirement retains its materialized mapping handle");
            table.retireMappingLifetime(handle.value);
        }
        if (entry.address_space) |*space| {
            if (entry.image_regions) |regions| {
                const stack = regions.stack;
                if (stack.size != 0 and !demand_paging.unregisterRegionForSpace(space, stack.start, stack.start + stack.size)) {
                    freestanding.paging.releaseUserRange(space, stack.start, stack.size) catch
                        native_util.impossibleByInvariant("invalid retired stack mapping range");
                }
            }
            const retain_shared = self.releaseSharedGroupSpace(space);
            if (!retain_shared) {
                demand_paging.unregisterSpace(space);
                if (entry.image_regions) |image_regions| {
                    for (image_regions.ranges[0..image_regions.count]) |range| {
                        freestanding.paging.releaseUserRange(space, range.start, range.size) catch
                            native_util.impossibleByInvariant("invalid retired image mapping range");
                    }
                }
                freestanding.paging.destroyUserAddressSpace(space) catch
                    native_util.impossibleByInvariant("attempted to destroy the active userspace address space");
            }
            entry.address_space = null;
        }
        if (entry.image_regions) |image_regions| {
            table_backing.free(MappedImageRegions, image_regions);
            entry.image_regions = null;
        }
        if (entry.owned_xstate) |state| {
            state.erase();
            table_backing.free(xstate.Storage, state);
            entry.owned_xstate = null;
        }
        if (!mappings.removeIndex(slot_index)) {
            native_util.impossibleByInvariant("live userspace mapping disappeared during release");
        }
    }

    fn releaseAllMappings(self: *Executor) void {
        const mappings = self.mappingArena() orelse return;
        const claimed_count = mappings.claimedCount();
        var slot_index: usize = 0;
        while (slot_index < claimed_count) : (slot_index += 1) {
            const slot = mappings.slotAt(slot_index);
            if (!slot.in_use) continue;
            self.releaseMapping(mappings, slot_index, &slot.mapping);
        }
        self.group_spaces = @splat(null);
        self.group_refs = @splat(0);
        self.releaseMappingArena();
    }

    fn releaseRetiredMappingAfterHandoff(
        self: *Executor,
        completed_mapping_handle: MappingHandle,
        completed_mapping: *MappingEntry,
    ) void {
        if (self.active_task_id != 0) {
            native_util.impossibleByInvariant("cannot release a userspace mapping while an address space is active");
        }
        if (completed_mapping.state != .retire_pending) return;
        const mappings = self.mappingArena() orelse
            native_util.impossibleByInvariant("completed userspace mapping has no arena");
        if (builtin.mode == .debug) {
            const slot = mappings.getByHandle(completed_mapping_handle) orelse
                native_util.impossibleByInvariant("completed userspace mapping handle is no longer live");
            std.debug.assert(&slot.mapping == completed_mapping);
        }
        releaseMapping(self, mappings, completed_mapping_handle.slotIndex(), completed_mapping);
    }

    fn clearUserPageFaultObservation(self: *Executor) void {
        self.last_fault_task_id = 0;
        self.last_fault_address_space_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
    }
};

fn initializeMappingArena(mappings: *MappingArena) void {
    @memset(std.mem.asBytes(mappings), 0);
    const free_no_index = indexed_arena.reusableNoIndex(MappingArena.slot_capacity);
    @memset(mappings.free_next[0..], free_no_index);
    mappings.free_head = free_no_index;
}

fn prepareMappingDispatchMetadata(
    owner_task_id: u64,
    address_space_image_id: u64,
    entry_point: u64,
    stack_pointer: u64,
    image_id: u64,
    bootstrap_mailbox_address: u64,
    contract_flags: u32,
    heartbeat_increment: u32,
    protection_key: u4,
) MaterializationError!MappingDispatchMetadata {
    if (owner_task_id == 0) return error.AddressSpaceOwnerInvalid;
    if (image_id == 0 or address_space_image_id != image_id) return error.AddressSpaceImageMismatch;
    const initial_stack_pointer = std.math.sub(u64, stack_pointer, 16) catch return error.InitialContextInvalid;
    const compact_contract_flags = std.math.cast(u16, contract_flags) orelse return error.LaunchPolicyInvalid;
    const compact_heartbeat_increment = std.math.cast(u12, heartbeat_increment) orelse return error.LaunchPolicyInvalid;
    if (compact_heartbeat_increment == 0) return error.LaunchPolicyInvalid;
    if (entry_point < userspace_layout.image_start or
        entry_point >= userspace_layout.image_end_exclusive)
    {
        return error.InitialContextInvalid;
    }
    if (bootstrap_mailbox_address < userspace_layout.image_start or
        bootstrap_mailbox_address >= userspace_layout.image_end_exclusive)
    {
        return error.InitialContextInvalid;
    }
    return .{
        .owner_task_id = owner_task_id,
        .image_id = image_id,
        .initial_instruction_pointer = entry_point,
        .initial_stack_pointer = initial_stack_pointer,
        .bootstrap_mailbox_address = std.math.cast(u32, bootstrap_mailbox_address) orelse return error.InitialContextInvalid,
        .launch_policy = .{
            .contract_flags = compact_contract_flags,
            .heartbeat_increment = compact_heartbeat_increment,
            .protection_key = protection_key,
        },
    };
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .debug;
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
    heartbeat_increment: u32,
    authorities: MailboxAuthorities,
    task_id: u64,
    ui_surface_id: u64,
    document: userspace_bootstrap_mailbox.DocumentBinding = .{},
};

const MailboxSnapshotMiss = enum {
    host,
    task,
    inactive,
    mapping,
    mapping_state,
    address,
    unread,
    sibling,
    version,
};

const MailboxSnapshotInspection = union(enum) {
    ready: userspace_bootstrap_mailbox.Mailbox,
    miss: MailboxSnapshotMiss,
};

const MailboxPublicationCache = struct {
    published_authority_generation: u64 = 0,
    initialized: bool = false,
};

fn prepareCachedBootstrapMailboxUpdate(
    cache: *MailboxPublicationCache,
    address: u64,
    preserve_runtime_state: bool,
    component_class: task_runtime.ComponentClass,
    contract_flags: u32,
    heartbeat_increment: u32,
    task_id: u64,
    ui_surface_id: u64,
    authorities: MailboxAuthorities,
    authority_generation: u64,
) ?BootstrapMailboxUpdate {
    if (authority_generation == 0) native_util.impossibleByInvariant("resolved mailbox authorities require a nonzero generation");
    const update = prepareBootstrapMailboxUpdate(
        address,
        preserve_runtime_state,
        component_class,
        contract_flags,
        heartbeat_increment,
        task_id,
        ui_surface_id,
        authorities,
    ) orelse return null;
    if (preserve_runtime_state and
        cache.initialized and
        cache.published_authority_generation == authority_generation)
    {
        return null;
    }

    cache.* = .{
        .published_authority_generation = authority_generation,
        .initialized = true,
    };
    return update;
}

fn prepareBootstrapMailboxUpdate(
    address: u64,
    preserve_runtime_state: bool,
    component_class: task_runtime.ComponentClass,
    contract_flags: u32,
    heartbeat_increment: u32,
    task_id: u64,
    ui_surface_id: u64,
    authorities: MailboxAuthorities,
) ?BootstrapMailboxUpdate {
    if (address == 0) return null;
    return .{
        .address = @intCast(address),
        .preserve_runtime_state = preserve_runtime_state,
        .detail = @backingInt(userspace_bootstrap_mailbox.classifyDetail(@backingInt(component_class), contract_flags)),
        .heartbeat_increment = heartbeat_increment,
        .authorities = authorities,
        .task_id = task_id,
        .ui_surface_id = ui_surface_id,
    };
}

fn activateMappingForDispatch(mapping: *MappingEntry, mailbox_update: ?BootstrapMailboxUpdate) void {
    freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());
    const update = mailboxWriteForDispatch(mapping, mailbox_update);
    if (writeUserspaceMailboxThroughMapping(mapping, update)) return;
    writeBootstrapMailbox(update);
}

fn mailboxWriteForDispatch(mapping: *MappingEntry, update: ?BootstrapMailboxUpdate) ?BootstrapMailboxUpdate {
    const candidate = update orelse return null;
    const cache = &mapping.mailbox_publication_cache;
    const generation = mapping.mailbox_authority_cache.authority_generation;
    if (generation == 0) native_util.impossibleByInvariant("resolved mailbox authorities require a nonzero generation");
    const unchanged = candidate.preserve_runtime_state and
        cache.initialized and
        cache.published_authority_generation == generation;
    if (unchanged and liveMailboxBelongsToTask(mapping, candidate.task_id)) return null;
    cache.* = .{
        .published_authority_generation = generation,
        .initialized = true,
    };
    return candidate;
}

fn liveMailboxBelongsToTask(mapping: *MappingEntry, task_id: u64) bool {
    if (comptime builtin.target.os.tag != .freestanding) return true;
    const mailbox = readUserspaceMailboxFromMapping(mapping, mapping.dispatch_metadata.bootstrap_mailbox_address) orelse
        return false;
    return mailboxBelongsToTask(mailbox, task_id);
}

fn kernelPublishedMailbox(
    update: BootstrapMailboxUpdate,
    preserved: ?userspace_bootstrap_mailbox.Mailbox,
) userspace_bootstrap_mailbox.Mailbox {
    var mailbox: userspace_bootstrap_mailbox.Mailbox = preserved orelse .{
        .version = userspace_bootstrap_mailbox.VERSION,
        .stage = @backingInt(userspace_bootstrap_mailbox.Stage.boot),
        .detail = update.detail,
        .fault_code = 0,
        ._reserved0 = @as([userspace_bootstrap_mailbox.MAILBOX_RESERVED_BYTES]u8, @splat(0)),
        .resource_mask = 0,
        .last_counter = 0,
    };
    mailbox.version = userspace_bootstrap_mailbox.VERSION;
    mailbox.authority_capability_id = update.authorities.bootstrap_capability_id;
    mailbox.input_capability_id = update.authorities.input_capability_id;
    mailbox.surface_presentation_capability_id = update.authorities.surface_presentation_capability_id;
    mailbox.ui_surface_id = update.ui_surface_id;
    mailbox.task_id = update.task_id;
    mailbox.service_id = update.authorities.bootstrap_service_id;
    mailbox.heartbeat_increment = update.heartbeat_increment;
    if (preserved == null) {
        mailbox.detail = update.detail;
        mailbox.ui_channel_kind = if (update.document.isValid()) .document else .none;
        mailbox.ui_channel = .{ .document = update.document };
    }
    return mailbox;
}

fn writeUserspaceMailboxThroughMapping(mapping: *MappingEntry, prepared: ?BootstrapMailboxUpdate) bool {
    const update = prepared orelse return true;
    if (comptime builtin.target.os.tag != .freestanding) return false;
    const space = if (mapping.address_space) |*address_space| address_space else return false;
    const existing = readUserspaceMailboxFromMapping(mapping, update.address);
    const preserved = preservedMailboxForUpdate(mapping, existing, update);
    const mailbox = kernelPublishedMailbox(update, preserved);
    freestanding.paging.writeOwnedUserRange(space, update.address, std.mem.asBytes(&mailbox)) catch return false;
    return true;
}

fn writeBootstrapMailbox(prepared: ?BootstrapMailboxUpdate) void {
    const update = prepared orelse return;
    x86.allowSupervisorUserMemory();
    defer x86.forbidSupervisorUserMemory();
    const mailbox_ptr: *userspace_bootstrap_mailbox.Mailbox = @ptrFromInt(update.address);
    const preserved = if (update.preserve_runtime_state) mailbox_ptr.* else null;
    mailbox_ptr.* = kernelPublishedMailbox(update, preserved);
}

fn mailboxAddressForSnapshot(
    mapping: *const MappingEntry,
    image: ?*const userspace_loader.ImageRecord,
) usize {
    if (mapping.dispatch_metadata.bootstrap_mailbox_address != 0) {
        return mapping.dispatch_metadata.bootstrap_mailbox_address;
    }
    if (image) |record| {
        return std.math.cast(usize, record.bootstrap_mailbox_address) orelse 0;
    }
    return 0;
}

fn readUserspaceMailboxFromMapping(
    mapping: *const MappingEntry,
    address: usize,
) ?userspace_bootstrap_mailbox.Mailbox {
    if (comptime builtin.target.os.tag != .freestanding) return null;
    if (address == 0) return null;
    const space = mapping.address_space orelse return null;
    var mailbox: userspace_bootstrap_mailbox.Mailbox = undefined;
    freestanding.paging.readOwnedUserRange(
        &space,
        address,
        std.mem.asBytes(&mailbox),
    ) catch return null;
    if (mailbox.version != userspace_bootstrap_mailbox.VERSION) return null;
    return mailbox;
}

fn storeCapturedMailbox(mapping: *MappingEntry, mailbox: userspace_bootstrap_mailbox.Mailbox) void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    mapping.captured_mailbox = mailbox;
    mapping.mailbox_captured = true;
}

fn captureMailbox(mapping: *MappingEntry) void {
    const mailbox = readUserspaceMailboxFromMapping(mapping, mapping.dispatch_metadata.bootstrap_mailbox_address) orelse return;
    if (!mailboxBelongsToTask(mailbox, mapping.dispatch_metadata.owner_task_id)) return;
    storeCapturedMailbox(mapping, mailbox);
}

fn mailboxBelongsToTask(mailbox: userspace_bootstrap_mailbox.Mailbox, task_id: u64) bool {
    return mailbox.version == userspace_bootstrap_mailbox.VERSION and mailbox.task_id == task_id;
}

fn preservedMailboxForUpdate(
    mapping: *const MappingEntry,
    existing: ?userspace_bootstrap_mailbox.Mailbox,
    update: BootstrapMailboxUpdate,
) ?userspace_bootstrap_mailbox.Mailbox {
    const captured: ?userspace_bootstrap_mailbox.Mailbox = if (comptime builtin.target.os.tag == .freestanding)
        if (mapping.mailbox_captured) mapping.captured_mailbox else null
    else
        null;
    return preservedMailboxBytes(existing, captured, update);
}

fn preservedMailboxBytes(
    existing: ?userspace_bootstrap_mailbox.Mailbox,
    captured: ?userspace_bootstrap_mailbox.Mailbox,
    update: BootstrapMailboxUpdate,
) ?userspace_bootstrap_mailbox.Mailbox {
    if (existing) |live| {
        if (mailboxBelongsToTask(live, update.task_id)) return live;
    }
    if (!update.preserve_runtime_state) return null;
    const snapshot = captured orelse return null;
    if (!mailboxBelongsToTask(snapshot, update.task_id)) return null;
    return snapshot;
}

fn mappingDispatchMetadataCompatible(live: MappingDispatchMetadata, expected: MappingDispatchMetadata) bool {
    var normalized = live;
    normalized.initial_stack_pointer = expected.initial_stack_pointer;
    return std.meta.eql(normalized, expected);
}

pub const MailboxAuthorityCache = struct {
    authorities: MailboxAuthorities = .{},
    task_id: u64 = 0,
    task_capability_generation: u64 = 0,
    table_mutation_generation: u64 = 0,
    resolved_at_ticks: u64 = 0,
    valid_until_ticks: u64 = 0,
    refresh_count: u64 = 0,
    revalidation_count: u64 = 0,
    authority_generation: u64 = 0,
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
        now_ticks >= cache.resolved_at_ticks and
        now_ticks <= cache.valid_until_ticks)
    {
        if (cache.table_mutation_generation == table_mutation_generation) return cache.authorities;
        if (cachedMailboxAuthoritiesRemainValid(task, capability_table, now_ticks, cache.authorities)) {
            cache.table_mutation_generation = table_mutation_generation;
            cache.revalidation_count +|= 1;
            return cache.authorities;
        }
    }

    const refresh_count = cache.refresh_count +| 1;
    const revalidation_count = cache.revalidation_count;
    const resolution = scanMailboxAuthorities(task, capability_table, now_ticks);
    const authority_generation = if (cache.initialized and std.meta.eql(cache.authorities, resolution.authorities))
        cache.authority_generation
    else
        nextMailboxAuthorityGeneration(cache.authority_generation);
    cache.* = .{
        .authorities = resolution.authorities,
        .task_id = task.id,
        .task_capability_generation = task_capability_generation,
        .table_mutation_generation = table_mutation_generation,
        .resolved_at_ticks = now_ticks,
        .valid_until_ticks = resolution.valid_until_ticks,
        .refresh_count = refresh_count,
        .revalidation_count = revalidation_count,
        .authority_generation = authority_generation,
        .initialized = true,
    };
    return resolution.authorities;
}

fn cachedMailboxAuthoritiesRemainValid(
    task: *const task_runtime.TaskRecord,
    capability_table: *const capability.CapabilityTable,
    now_ticks: u64,
    authorities: MailboxAuthorities,
) bool {
    if (authorities.bootstrap_capability_id != 0) {
        const inspected = capability_table.inspect(authorities.bootstrap_capability_id, now_ticks) orelse return false;
        if (!inspected.usable) return false;
        const granted = inspected.capability;
        const service_id = if (granted.target.kind == .service) granted.target.id else 0;
        const endpoint_candidate = granted.target.kind == .service and granted.rights.has(.endpoint_create);
        const query_candidate = granted.rights.has(.time_query) or
            granted.rights.has(.resource_query) or
            granted.rights.has(.accounting_query);
        if ((!endpoint_candidate and !query_candidate) or service_id != authorities.bootstrap_service_id) return false;
    }

    if (authorities.input_capability_id != 0) {
        const inspected = capability_table.inspect(authorities.input_capability_id, now_ticks) orelse return false;
        const granted = inspected.capability;
        if (!inspected.usable or
            granted.target.kind != .task or
            granted.target.id != task.id or
            granted.scope.task_id != task.id or
            !granted.rights.has(.input_recv))
        {
            return false;
        }
    }

    if (authorities.surface_presentation_capability_id != 0) {
        if (task.ui_surface_id == null or task.ui_surface_id.? == 0) return false;
        const inspected = capability_table.inspect(authorities.surface_presentation_capability_id, now_ticks) orelse return false;
        const granted = inspected.capability;
        if (!inspected.usable or
            granted.target.kind != .task or
            granted.target.id != task.id or
            granted.scope.task_id != task.id or
            !granted.rights.has(.surface_present))
        {
            return false;
        }
    }
    return true;
}

fn nextMailboxAuthorityGeneration(current: u64) u64 {
    const next = current +% 1;
    return if (next == 0) 1 else next;
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

fn shouldPreemptUserDispatch(executor: *const Executor, from_userspace: bool, now_ticks: u64, check: ?PreemptCheck) bool {
    if (executor.active_task_id == 0 or !from_userspace or executor.active_mapping == null) return false;
    // A missing policy callback never disables the finite dispatch watchdog.
    if (executor.dispatch_quantum.expired(executor.active_task_id, now_ticks)) return true;
    return if (check) |priority_check| priority_check(executor.active_task_id) else false;
}

fn userspaceTimerPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    const executor = registered_executor orelse return;
    if (!shouldPreemptUserDispatch(executor, (frame.cs & 0x3) == 0x3, timer.getTicks(), preempt_check)) return;
    const mapping = executor.active_mapping orelse return;
    handoffInterruptedUser(executor, mapping, frame);
}

fn userspaceInterruptPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if (frame.int_no == @import("../../kernel/timer/timer.zig").INTERRUPT_VECTOR) {
        userspaceTimerPreemption(frame);
    } else {
        userspaceDevicePreemption(frame);
    }
}

fn userspaceDevicePreemption(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse return;
    if ((frame.cs & 0x3) != 0x3 or executor.active_task_id == 0 or
        executor.dispatch_quantum.task_id != executor.active_task_id) return;
    // Dispatch pins this task until handoff. Monotonic task IDs and the exact
    // live mapping handle authenticate its incarnation without scheduler work.
    const mapping = activeUserMemoryMapping(executor, executor.active_task_id) orelse return;
    if (mapping.owned_xstate == null) return;
    handoffInterruptedUser(executor, mapping, frame);
}

fn handoffInterruptedUser(executor: *Executor, mapping: *MappingEntry, frame: anytype) void {
    // Multiple device interrupts may be queued for one user frame. Preserve an
    // earlier retirement/exception handoff and charge/capture this resume once.
    if (executor.handoff_completed or zigos_userspace_resume_requested != 0) return;
    mapping.resume_valid = true;
    mapping.resume_instruction_pointer = frame.eip;
    mapping.resume_stack_pointer = frame.useresp;
    captureUserContext64(mapping, frame);
    mapping.yield_count += 1;
    executor.last_yield_disposition = .runnable;
    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;
    captureMailbox(mapping);
    freestanding.paging.switchToKernelAddressSpace();
}

fn userspaceTrapHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse return;
    handleUserspaceYield(executor, frame);
}

fn handleUserspaceYield(executor: *Executor, frame: anytype) void {
    if (executor.active_task_id == 0) return;
    const mapping = executor.active_mapping orelse
        native_util.impossibleByInvariant("active userspace task has no materialized mapping");
    const instruction_pointer = frame.eip;
    const stack_pointer = frame.useresp;
    const counter = std.math.cast(u32, frame.eax) orelse
        return containMalformedYield(executor, frame.eip);
    const disposition_raw = std.math.cast(u32, frame.esi) orelse
        return containMalformedYield(executor, frame.eip);
    const disposition = userspace_bootstrap_mailbox.yieldDisposition(disposition_raw) orelse
        return containMalformedYield(executor, frame.eip);
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
    executor.last_yield_disposition = disposition;
    executor.last_yield_ui_revision = ui_revision;

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    captureMailbox(mapping);
    freestanding.paging.switchToKernelAddressSpace();
}

fn containMalformedYield(executor: *Executor, instruction_pointer: u64) void {
    requestUserExceptionHandoff(executor, .{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = 0,
        .instruction_pointer = instruction_pointer,
    });
}

fn requestUserExceptionHandoff(executor: *Executor, exception: UserException) void {
    executor.last_user_exception = exception;
    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;
    freestanding.paging.switchToKernelAddressSpace();
}

fn userspaceExceptionHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = registered_executor orelse freestanding.isr.haltUnhandledException(frame);
    if (executor.active_task_id == 0 or (frame.cs & 0x3) != 0x3) {
        freestanding.isr.haltUnhandledException(frame);
    }
    _ = executor.active_mapping orelse
        native_util.impossibleByInvariant("active userspace task has no materialized mapping");
    const vector = std.math.cast(u8, frame.int_no) orelse
        native_util.impossibleByInvariant("userspace exception vector exceeds the IDT range");
    if (!containUserException(executor, vector, @intCast(frame.err_code), @intCast(frame.eip))) {
        freestanding.isr.haltUnhandledException(frame);
    }
}

fn containUserException(executor: *Executor, vector: u8, error_code: u32, instruction_pointer: u64) bool {
    if (!isContainableUserExceptionVector(vector)) return false;
    requestUserExceptionHandoff(executor, .{
        .vector = vector,
        .error_code = error_code,
        .instruction_pointer = instruction_pointer,
    });
    return true;
}

pub export fn zigos_handle_invalid_interrupt_return(frame: *freestanding.isr.InterruptFrame) void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    const executor = registered_executor orelse
        @call(.never_inline, freestanding.isr.haltUnhandledException, .{frame});
    if (executor.active_task_id == 0 or (frame.cs & 0x3) != 0x3) {
        @call(.never_inline, freestanding.isr.haltUnhandledException, .{frame});
    }
    _ = executor.active_mapping orelse
        @call(.never_inline, freestanding.isr.haltUnhandledException, .{frame});

    @call(.never_inline, freestanding.isr.reportInvalidInterruptReturn, .{frame});
    executor.last_user_exception = .{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = @truncate(frame.ss & ~@as(usize, 0x3)),
        .instruction_pointer = frame.eip,
    };
    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;
    freestanding.paging.switchToKernelAddressSpace();
}

fn isContainableUserExceptionVector(vector: u8) bool {
    return for (CONTAINABLE_USER_EXCEPTION_VECTORS) |candidate| {
        if (vector == candidate) break true;
    } else false;
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

    const faulting_address = x86.readCr2();
    const error_code = std.math.cast(u32, frame.err_code) orelse
        native_util.impossibleByInvariant("userspace page-fault code exceeds its ABI width");
    if (mapping.address_space) |*space| {
        if (demand_paging.resolveFault(space, faulting_address, error_code)) return;
    }
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
    } else {
        executor.last_user_exception = .{
            .vector = PAGE_FAULT_VECTOR,
            .error_code = error_code,
            .instruction_pointer = @intCast(frame.eip),
            .fault_address = faulting_address,
        };
    }

    executor.handoff_completed = true;
    zigos_userspace_resume_requested = 1;

    freestanding.paging.switchToKernelAddressSpace();
}

fn nxProbeRecoveryContext(
    executor: *const Executor,
    mapping: *MappingEntry,
    frame: *freestanding.isr.InterruptFrame,
    faulting_address: u64,
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

    const recovery_address = frame.r15;
    const runtime = executor.bound_runtime orelse return false;
    const task = runtime.find(executor.active_task_id) orelse return false;
    const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
    if (!addressSpaceAllowsExecution(address_space, recovery_address)) return false;
    if (!(freestanding.paging.ownedUserPageIsExecutable(&mapping.address_space.?, recovery_address) orelse false)) return false;
    frame.eip = recovery_address;
    return true;
}

fn addressSpaceAllowsExecution(address_space: *const task_runtime.AddressSpaceRecord, address: u64) bool {
    for (address_space.regions[0..address_space.region_count]) |region| {
        if (region.kind != .load_segment or !region.access.execute) continue;
        const region_end = std.math.add(u64, region.virtual_address, @as(u64, region.size_bytes)) catch continue;
        if (address >= region.virtual_address and address < region_end) return true;
    }
    return false;
}

fn mapLoadRegion(
    space: *freestanding.paging.UserAddressSpace,
    region: task_runtime.AddressSpaceRegionRecord,
    elf_file: embedded_file.File,
    protection_key: u4,
) MaterializationError!void {
    const virtual_address = region.virtual_address;
    const size_bytes = region.size_bytes;
    const start: usize = region.file_offset;
    const file_size: usize = region.file_size;
    const end = std.math.add(usize, start, file_size) catch return error.ImageExtentInvalid;
    if (end > elf_file.byte_len) return error.ImageExtentInvalid;
    const reader = elf_file.reader() orelse return error.ImageExtentInvalid;
    try freestanding.paging.mapOwnedUserRange(space, @intCast(virtual_address), @intCast(size_bytes), .{
        .writable = region.access.write,
        .executable = region.access.execute,
        .protection_key = protection_key,
    });

    var source_offset = start;
    var target_offset: u64 = 0;
    while (source_offset < end) {
        const bytes = reader.logicalSliceAt(source_offset) orelse return error.ImageExtentInvalid;
        const copy_len = @min(bytes.len, end - source_offset);
        const target_address = std.math.add(u64, virtual_address, target_offset) catch return error.InvalidRange;
        try freestanding.paging.writeOwnedUserRange(space, @intCast(target_address), bytes[0..copy_len]);
        source_offset += copy_len;
        target_offset += copy_len;
    }
}

fn mapZeroedRegion(
    space: *freestanding.paging.UserAddressSpace,
    virtual_address_raw: u64,
    size_bytes_raw: usize,
    access: task_runtime.SegmentAccess,
    protection_key: u4,
) MaterializationError!void {
    const virtual_address = virtual_address_raw;
    const size_bytes = size_bytes_raw;
    if (access.execute) {
        try freestanding.paging.mapOwnedUserRange(space, @intCast(virtual_address), size_bytes, .{
            .writable = access.write,
            .executable = access.execute,
            .protection_key = protection_key,
        });
        return;
    }
    const region_end = std.math.add(u64, virtual_address, size_bytes) catch return error.InvalidRange;
    if (!demand_paging.registerForSpace(space, .{
        .virt_start = virtual_address,
        .virt_end_exclusive = region_end,
        .writable = access.write,
        .kind = .anonymous_zero,
        .protection_key = protection_key,
    })) return error.OutOfMemory;
}

const SHARED_STACK_SLOT_ATTEMPTS: usize = 32;

fn userRangeOccupied(
    space: *const freestanding.paging.UserAddressSpace,
    virtual_address: u64,
    size_bytes: usize,
) MaterializationError!bool {
    freestanding.paging.validateUserRangeAvailable(space, @intCast(virtual_address), size_bytes) catch |err| switch (err) {
        error.AlreadyMapped => return true,
        else => return err,
    };
    const end = std.math.add(u64, virtual_address, size_bytes) catch return error.InvalidRange;
    return demand_paging.regionOverlapsSpace(space, virtual_address, end);
}

fn uniqueStackBase(preferred_base: u64, size_bytes: u64, attempt: usize) ?u64 {
    if (attempt == 0) return preferred_base;
    const top = userspace_layout.stackTopForSlot(attempt - 1);
    const base = std.math.sub(u64, top, size_bytes) catch return null;
    if (base < userspace_layout.stack_start) return null;
    if (base == preferred_base) return null;
    return base;
}

fn mapUniqueZeroedStack(
    space: *freestanding.paging.UserAddressSpace,
    preferred_base: u64,
    size_bytes: usize,
    access: task_runtime.SegmentAccess,
    protection_key: u4,
) MaterializationError!u64 {
    var attempt: usize = 0;
    while (attempt < SHARED_STACK_SLOT_ATTEMPTS) : (attempt += 1) {
        const base = uniqueStackBase(preferred_base, size_bytes, attempt) orelse continue;
        if (try userRangeOccupied(space, base, size_bytes)) continue;
        try mapZeroedRegion(space, base, size_bytes, access, protection_key);
        return base;
    }
    return error.AlreadyMapped;
}

fn registerMappedObject(
    context: *anyopaque,
    table: *shared_memory.Table,
    descriptor: shared_memory.FreestandingMappingDescriptor,
    writable: bool,
    copy_on_write: bool,
) ?u64 {
    const executor: *Executor = @ptrCast(@alignCast(context));
    if (comptime builtin.target.os.tag == .freestanding) {
        if (registered_executor != executor) return null;
    }
    if (descriptor.size_bytes == 0 or descriptor.task_id.raw() == 0 or descriptor.target != null) return null;
    if (executor.mapped_object_table) |bound_table| {
        if (bound_table != table) return null;
    }
    if (executor.mapped_object_count >= shared_memory.MAX_SHARED_MEMORY_OBJECTS * shared_memory.MAX_MAPPINGS_PER_OBJECT) return null;
    const mapped_size = std.math.mul(usize, descriptor.page_count, shared_memory.PAGE_SIZE) catch return null;
    if (mapped_size == 0 or descriptor.size_bytes > mapped_size or (descriptor.virtual_base & (shared_memory.PAGE_SIZE - 1)) != 0) return null;
    const mapped_end = std.math.add(u64, descriptor.virtual_base, mapped_size) catch return null;
    const end = std.math.add(u64, descriptor.virtual_base, descriptor.size_bytes) catch return null;
    const task_id = descriptor.task_id.raw();
    const mapping = blk: {
        if (executor.active_mapping) |active| {
            if (active.dispatch_metadata.owner_task_id == task_id) break :blk active;
        }
        const runtime = executor.bound_runtime orelse return null;
        const task = runtime.findConst(task_id) orelse return null;
        break :blk executor.findMapping(task.address_space_id) orelse return null;
    };
    if (mapping.state != .live or mapping.dispatch_metadata.owner_task_id != task_id) return null;
    const resolution = executor.findMappingWithHandle(mapping.address_space_id) orelse return null;
    if (resolution.entry != mapping) return null;
    const space = if (mapping.address_space) |*address_space| address_space else return null;
    if (demand_paging.regionOverlapsSpace(space, descriptor.virtual_base, mapped_end)) return null;
    freestanding.paging.validateUserRangeAvailable(space, @intCast(descriptor.virtual_base), mapped_size) catch return null;
    if (!demand_paging.registerForSpace(space, .{
        .virt_start = descriptor.virtual_base,
        .virt_end_exclusive = end,
        .writable = writable,
        .kind = if (copy_on_write) .object_cow else .object_physical,
        .physical_base = descriptor.physical_base,
    })) return null;
    executor.mapped_object_table = table;
    executor.mapped_object_count += 1;
    return resolution.handle.value;
}

fn unregisterMappedObject(
    context: *anyopaque,
    table: *shared_memory.Table,
    registration_token: u64,
    descriptor: shared_memory.FreestandingMappingDescriptor,
) bool {
    const executor: *Executor = @ptrCast(@alignCast(context));
    if (registration_token == 0 or descriptor.size_bytes == 0 or descriptor.target != null) return false;
    if (executor.mapped_object_table != table or executor.mapped_object_count == 0) return false;
    const mappings = executor.mappingArena() orelse return false;
    const slot = mappings.getByHandle(MappingHandle{ .value = registration_token }) orelse return false;
    const mapping = &slot.mapping;
    if (mapping.state != .live and mapping.state != .retire_pending) return false;
    if (mapping.dispatch_metadata.owner_task_id != descriptor.task_id.raw()) return false;
    const space = if (mapping.address_space) |*address_space| address_space else return false;
    const end = std.math.add(u64, descriptor.virtual_base, descriptor.size_bytes) catch return false;
    if (!demand_paging.unregisterRegionForSpace(space, descriptor.virtual_base, end)) return false;
    executor.mapped_object_count -= 1;
    if (executor.mapped_object_count == 0) executor.mapped_object_table = null;
    return true;
}

fn enterUserspace(executor: *Executor) u32 {
    return enterUserspaceWithClock(executor, timer, UserEntry{});
}

const UserEntry = struct {
    fn enter(_: @This(), context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
        return enterUserContextWithState(context, state);
    }
};

// Both scheduled and direct Executor dispatch reach this boundary. Arming here
// includes the first entry after an idle one-shot/disarmed timer and measures
// the user quantum after materialization/mailbox work has completed.
fn enterUserspaceWithClock(executor: *Executor, clock: anytype, entry: anytype) u32 {
    const mapping = executor.active_mapping orelse
        native_util.impossibleByInvariant("userspace entry requires the active mapping owner");
    const storage = mapping.owned_xstate orelse
        native_util.impossibleByInvariant("userspace entry requires private extended state");
    clock.armSchedulerTick();
    executor.dispatch_quantum = DispatchQuantum.begin(executor.active_task_id, clock.getTicks());
    return entry.enter(&executor.pending_user_context64, storage.state());
}

fn captureUserContext64(mapping: *MappingEntry, frame: anytype) void {
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

fn recordTrapState(self: *Executor, instruction_pointer: u64, stack_pointer: u64, counter: u32) void {
    self.last_trap_instruction_pointer = instruction_pointer;
    self.last_trap_stack_pointer = stack_pointer;
    self.last_trap_counter = counter;
}

fn recordUserPageFault(self: *Executor, task_id: u64, address_space_id: u64, faulting_address: u64, error_code: u32) void {
    self.last_fault_task_id = task_id;
    self.last_fault_address_space_id = address_space_id;
    self.last_fault_address = faulting_address;
    self.last_fault_error_code = error_code;
    self.user_page_fault_count += 1;
}

fn publishRootActiveTaskId(task_id: u64) void {
    if (builtin.target.os.tag != .freestanding) return;
    if (@hasDecl(root, "publishUserspaceActiveTaskId")) {
        root.publishUserspaceActiveTaskId(task_id);
    }
}

fn installTestMappingAt(executor: *Executor, slot_index: usize, mapping: MappingEntry) MappingHandle {
    if (mapping.address_space_id == 0) {
        native_util.impossibleByInvariant("test userspace mapping requires a nonzero address-space identifier");
    }
    const reserved_index = executor.mappings.reserveIndexAt(mapping.address_space_id, slot_index) orelse
        native_util.impossibleByInvariant("test userspace mapping slot could not be reserved");
    executor.mappings.slotAt(reserved_index).mapping = mapping;
    return executor.mappings.handleForIndex(reserved_index) orelse
        native_util.impossibleByInvariant("test userspace mapping has no handle");
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
        9,
        3,
    );
    try std.testing.expectEqual(@as(u64, 40), metadata.owner_task_id);
    try std.testing.expectEqual(@as(u64, 41), metadata.image_id);
    try std.testing.expectEqual(@as(u64, 0x4000_1000), metadata.initial_instruction_pointer);
    try std.testing.expectEqual(@as(u64, 0x7FFF_EFF0), metadata.initial_stack_pointer);
    try std.testing.expectEqual(@as(u32, 0x4000_3000), metadata.bootstrap_mailbox_address);
    try std.testing.expectEqual(userspace_flags.FLAG_NX_PROOF_PROBE, metadata.contractFlags());
    try std.testing.expectEqual(@as(u32, 9), metadata.heartbeatIncrement());
    try std.testing.expectEqual(@as(u4, 3), metadata.protectionKey());
    try std.testing.expectEqual(MAPPING_DISPATCH_METADATA_SIZE_CEILING_BYTES, @sizeOf(MappingDispatchMetadata));
    try std.testing.expect(@sizeOf(MappingEntry) <= MAPPING_ENTRY_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(MappingArena) <= MAPPING_ARENA_SIZE_CEILING_BYTES);
    try std.testing.expectEqual(@as(u8, 0), STEADY_ADDRESS_SPACE_IMAGE_INDEX_LOOKUPS);
    const empty_mapping = MappingEntry{};
    try std.testing.expect(!empty_mapping.mailbox_captured);

    try std.testing.expectError(
        error.AddressSpaceOwnerInvalid,
        prepareMappingDispatchMetadata(0, 41, 0x4000_1000, 0x7FFF_F000, 41, 0x4000_3000, 0, 1, 1),
    );
    try std.testing.expectError(
        error.AddressSpaceImageMismatch,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 42, 0x4000_3000, 0, 1, 1),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 15, 41, 0x4000_3000, 0, 1, 1),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, @as(u64, std.math.maxInt(u32)) + 1, 0x7FFF_F000, 41, 0x4000_3000, 0, 1, 1),
    );
    try std.testing.expectError(
        error.InitialContextInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 41, @as(u64, std.math.maxInt(u32)) + 1, 0, 1, 1),
    );
    try std.testing.expectError(
        error.LaunchPolicyInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 41, 0x4000_3000, @as(u32, std.math.maxInt(u16)) + 1, 1, 1),
    );
    try std.testing.expectError(
        error.LaunchPolicyInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 41, 0x4000_3000, 0, 0, 1),
    );
    try std.testing.expectError(
        error.LaunchPolicyInvalid,
        prepareMappingDispatchMetadata(40, 41, 0x4000_1000, 0x7FFF_F000, 41, 0x4000_3000, 0, @as(u32, std.math.maxInt(u12)) + 1, 1),
    );
}

test "mailbox snapshot uses the mapping address and rejects an invalid version" {
    var mapping = MappingEntry{
        .dispatch_metadata = .{ .bootstrap_mailbox_address = 0x4000_3000 },
    };
    try std.testing.expectEqual(@as(usize, 0x4000_3000), mailboxAddressForSnapshot(&mapping, null));
    try std.testing.expect(readUserspaceMailboxFromMapping(&mapping, 0x4000_3000) == null);

    var mailbox = userspace_bootstrap_mailbox.Mailbox{};
    try std.testing.expectEqual(userspace_bootstrap_mailbox.VERSION, mailbox.version);
    mailbox.version = 0;
    try std.testing.expect(mailbox.version != userspace_bootstrap_mailbox.VERSION);
}

test "shared mailbox restore keeps the dispatching task snapshot" {
    const captured = userspace_bootstrap_mailbox.Mailbox{
        .version = userspace_bootstrap_mailbox.VERSION,
        .stage = @backingInt(userspace_bootstrap_mailbox.Stage.steady),
        .task_id = 10,
        .ui_state_revision = 4,
        .ui_presented_revision = 4,
        .ui_last_presentation_status = 0,
    };
    const sibling = userspace_bootstrap_mailbox.Mailbox{
        .version = userspace_bootstrap_mailbox.VERSION,
        .stage = @backingInt(userspace_bootstrap_mailbox.Stage.runtime_ready),
        .task_id = 11,
    };
    const update = BootstrapMailboxUpdate{
        .address = 0x4000,
        .preserve_runtime_state = true,
        .detail = @backingInt(userspace_bootstrap_mailbox.Detail.ui),
        .heartbeat_increment = 15,
        .authorities = .{ .bootstrap_capability_id = 101, .surface_presentation_capability_id = 104 },
        .task_id = 10,
        .ui_surface_id = 2,
    };
    const preserved = preservedMailboxBytes(sibling, captured, update).?;
    const restored = kernelPublishedMailbox(update, preserved);
    try std.testing.expectEqual(@as(u64, 10), restored.task_id);
    try std.testing.expectEqual(@as(u64, 2), restored.ui_surface_id);
    try std.testing.expectEqual(@as(u64, 101), restored.authority_capability_id);
    try std.testing.expectEqual(@as(u8, @backingInt(userspace_bootstrap_mailbox.Stage.steady)), restored.stage);
    try std.testing.expectEqual(@as(u64, 4), restored.ui_presented_revision);
    var first_launch = update;
    first_launch.preserve_runtime_state = false;
    try std.testing.expect(preservedMailboxBytes(sibling, captured, first_launch) == null);
}

test "mailbox snapshot ignores a sibling task identity" {
    try std.testing.expect(mailboxBelongsToTask(.{
        .version = userspace_bootstrap_mailbox.VERSION,
        .task_id = 7,
    }, 7));
    try std.testing.expect(!mailboxBelongsToTask(.{
        .version = userspace_bootstrap_mailbox.VERSION,
        .task_id = 8,
    }, 7));
    try std.testing.expect(!mailboxBelongsToTask(.{
        .version = 0,
        .task_id = 7,
    }, 7));
}

test "prepared document survives a sibling dispatch before first launch" {
    const binding = userspace_bootstrap_mailbox.DocumentBinding{
        .endpoint_capability_id = 10,
        .service_endpoint_id = 11,
        .object_id = 12,
        .version_id = 13,
    };
    var update = BootstrapMailboxUpdate{
        .address = 0x4000,
        .preserve_runtime_state = false,
        .detail = @backingInt(userspace_bootstrap_mailbox.Detail.ui),
        .heartbeat_increment = 1,
        .authorities = .{ .bootstrap_capability_id = 101 },
        .task_id = 1,
        .ui_surface_id = 2,
        .document = binding,
    };
    const prepared = kernelPublishedMailbox(update, null);
    const sibling = userspace_bootstrap_mailbox.Mailbox{ .task_id = 2 };
    update.document = .{};
    update.preserve_runtime_state = true;
    update.authorities.input_capability_id = 102;
    const restored = kernelPublishedMailbox(update, preservedMailboxBytes(sibling, prepared, update));
    try std.testing.expectEqualDeep(binding, restored.documentBinding());
    try std.testing.expectEqual(@as(u64, 1), restored.task_id);
    try std.testing.expectEqual(@as(u64, 102), restored.input_capability_id);
    try std.testing.expectEqual(@as(u64, 0), restored.ui_state_revision);
}

test "shared-group stacks walk to the next free slot" {
    const preferred = userspace_layout.default_stack_top - userspace_layout.default_stack_size;
    try std.testing.expectEqual(preferred, uniqueStackBase(preferred, userspace_layout.default_stack_size, 0).?);
    try std.testing.expect(uniqueStackBase(preferred, userspace_layout.default_stack_size, 1) == null);
    try std.testing.expectEqual(
        userspace_layout.stackTopForSlot(1) - userspace_layout.default_stack_size,
        uniqueStackBase(preferred, userspace_layout.default_stack_size, 2).?,
    );
}

test "materialized dispatch metadata may relocate a shared-group stack" {
    const baseline = try prepareMappingDispatchMetadata(
        40,
        41,
        0x4000_1000,
        0x7FFF_F000,
        41,
        0x4000_3000,
        userspace_flags.FLAG_NX_PROOF_PROBE,
        9,
        3,
    );
    var relocated = baseline;
    relocated.initial_stack_pointer = baseline.initial_stack_pointer - userspace_layout.STACK_SLOT_STRIDE;
    try std.testing.expect(mappingDispatchMetadataCompatible(relocated, baseline));
    var mutated = relocated;
    mutated.image_id = baseline.image_id + 1;
    try std.testing.expect(!mappingDispatchMetadataCompatible(mutated, baseline));
}

test "mailbox publication preserves resume state and resets first launch" {
    var mailbox = userspace_bootstrap_mailbox.Mailbox{
        .stage = @backingInt(userspace_bootstrap_mailbox.Stage.steady),
        .fault_code = 0x72,
        .resource_mask = 0x7,
        .service_operation_count = 9,
        .last_counter = 41,
        .input_event_count = 12,
        .ui_state_revision = 15,
        .ui_channel_kind = .document,
        .ui_channel = .{ .document = .{ .endpoint_capability_id = 201, .service_endpoint_id = 202, .object_id = 203, .version_id = 204 } },
    };
    const authorities = MailboxAuthorities{
        .bootstrap_capability_id = 101,
        .bootstrap_service_id = 102,
        .input_capability_id = 103,
        .surface_presentation_capability_id = 104,
    };
    const address: u64 = @intCast(@intFromPtr(&mailbox));

    const resumed = prepareBootstrapMailboxUpdate(address, true, .app_component, 0, 9, 105, 106, authorities).?;
    writeBootstrapMailbox(resumed);
    try std.testing.expect(resumed.preserve_runtime_state);
    try std.testing.expectEqual(userspace_bootstrap_mailbox.VERSION, mailbox.version);
    try std.testing.expectEqual(@as(u64, 101), mailbox.authority_capability_id);
    try std.testing.expectEqual(@as(u64, 102), mailbox.service_id);
    try std.testing.expectEqual(@as(u64, 103), mailbox.input_capability_id);
    try std.testing.expectEqual(@as(u64, 104), mailbox.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 105), mailbox.task_id);
    try std.testing.expectEqual(@as(u64, 106), mailbox.ui_surface_id);
    try std.testing.expectEqual(@as(u8, @backingInt(userspace_bootstrap_mailbox.Stage.steady)), mailbox.stage);
    try std.testing.expectEqual(@as(u8, 0x72), mailbox.fault_code);
    try std.testing.expectEqual(@as(u32, 0x7), mailbox.resource_mask);
    try std.testing.expectEqual(@as(u16, 9), mailbox.service_operation_count);
    try std.testing.expectEqual(@as(u32, 41), mailbox.last_counter);
    try std.testing.expectEqual(@as(u32, 9), mailbox.heartbeat_increment);
    try std.testing.expectEqual(@as(u64, 12), mailbox.input_event_count);
    try std.testing.expectEqual(@as(u64, 15), mailbox.ui_state_revision);
    try std.testing.expectEqual(@as(u64, 201), mailbox.documentBinding().endpoint_capability_id);
    try std.testing.expectEqual(@as(u64, 204), mailbox.documentBinding().version_id);

    const first_launch = prepareBootstrapMailboxUpdate(address, false, .app_component, 0, 11, 107, 108, authorities).?;
    writeBootstrapMailbox(first_launch);
    try std.testing.expect(!first_launch.preserve_runtime_state);
    try std.testing.expectEqual(@as(u8, @backingInt(userspace_bootstrap_mailbox.Stage.boot)), mailbox.stage);
    try std.testing.expectEqual(@as(u8, 0), mailbox.fault_code);
    try std.testing.expectEqual(@as(u32, 0), mailbox.resource_mask);
    try std.testing.expectEqual(@as(u16, 0), mailbox.service_operation_count);
    try std.testing.expectEqual(@as(u32, 0), mailbox.last_counter);
    try std.testing.expectEqual(@as(u32, 11), mailbox.heartbeat_increment);
    try std.testing.expectEqual(@as(u64, 0), mailbox.input_event_count);
    try std.testing.expectEqual(@as(u64, 0), mailbox.ui_state_revision);
    try std.testing.expectEqual(userspace_bootstrap_mailbox.DocumentBinding{}, mailbox.documentBinding());
    try std.testing.expectEqual(@as(u64, 107), mailbox.task_id);
    try std.testing.expectEqual(@as(u64, 108), mailbox.ui_surface_id);

    try std.testing.expect(prepareBootstrapMailboxUpdate(0, false, .app_component, 0, 1, 1, 0, .{}) == null);
    try std.testing.expectEqual(@as(u8, 1), USER_ADDRESS_SPACE_ACTIVATIONS_PER_DISPATCH);
}

test "mailbox publication cache suppresses unchanged resumed kernel writes" {
    var mailbox = userspace_bootstrap_mailbox.Mailbox{};
    var cache = MailboxPublicationCache{};
    const address: u64 = @intCast(@intFromPtr(&mailbox));
    const initial_authorities = MailboxAuthorities{
        .bootstrap_capability_id = 201,
        .bootstrap_service_id = 202,
        .input_capability_id = 203,
        .surface_presentation_capability_id = 204,
    };

    const first_launch = prepareCachedBootstrapMailboxUpdate(
        &cache,
        address,
        false,
        .app_component,
        userspace_flags.FLAG_OWNS_UI_SURFACE,
        9,
        205,
        206,
        initial_authorities,
        1,
    );
    try std.testing.expect(first_launch != null);
    writeBootstrapMailbox(first_launch);
    try std.testing.expectEqual(@as(u64, 1), cache.published_authority_generation);

    const first_launch_retry = prepareCachedBootstrapMailboxUpdate(
        &cache,
        address,
        false,
        .app_component,
        userspace_flags.FLAG_OWNS_UI_SURFACE,
        9,
        205,
        206,
        initial_authorities,
        1,
    );
    try std.testing.expect(first_launch_retry != null);
    writeBootstrapMailbox(first_launch_retry);
    try std.testing.expectEqual(@as(u64, 1), cache.published_authority_generation);

    mailbox.stage = @backingInt(userspace_bootstrap_mailbox.Stage.steady);
    mailbox.last_counter = 207;
    const unchanged_resume = prepareCachedBootstrapMailboxUpdate(
        &cache,
        address,
        true,
        .app_component,
        userspace_flags.FLAG_OWNS_UI_SURFACE,
        9,
        205,
        206,
        initial_authorities,
        1,
    );
    try std.testing.expect(unchanged_resume == null);
    writeBootstrapMailbox(unchanged_resume);
    try std.testing.expectEqual(@as(u64, 1), cache.published_authority_generation);
    try std.testing.expectEqual(@as(u8, @backingInt(userspace_bootstrap_mailbox.Stage.steady)), mailbox.stage);
    try std.testing.expectEqual(@as(u32, 207), mailbox.last_counter);

    var refreshed_authorities = initial_authorities;
    refreshed_authorities.input_capability_id = 208;
    const authority_refresh = prepareCachedBootstrapMailboxUpdate(
        &cache,
        address,
        true,
        .app_component,
        userspace_flags.FLAG_OWNS_UI_SURFACE,
        9,
        205,
        206,
        refreshed_authorities,
        2,
    );
    try std.testing.expect(authority_refresh != null);
    writeBootstrapMailbox(authority_refresh);
    try std.testing.expectEqual(@as(u64, 2), cache.published_authority_generation);
    try std.testing.expectEqual(@as(u64, 208), mailbox.input_capability_id);
    try std.testing.expectEqual(@as(u32, 207), mailbox.last_counter);

    const unchanged_refreshed_resume = prepareCachedBootstrapMailboxUpdate(
        &cache,
        address,
        true,
        .app_component,
        userspace_flags.FLAG_OWNS_UI_SURFACE,
        9,
        205,
        206,
        refreshed_authorities,
        2,
    );
    try std.testing.expect(unchanged_refreshed_resume == null);
    writeBootstrapMailbox(unchanged_refreshed_resume);
    try std.testing.expectEqual(@as(u64, 2), cache.published_authority_generation);
    try std.testing.expectEqual(@as(u8, 0), UNCHANGED_RESUME_KERNEL_MAILBOX_FIELD_WRITES_PER_DISPATCH);
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
    try std.testing.expectEqual(@as(u64, 1), cache.authority_generation);

    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 0), cache.revalidation_count);
    try std.testing.expectEqual(@as(u64, 1), cache.authority_generation);

    const unrelated_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 900 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 901 },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = 902, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(service_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(input_authority.id, authorities.input_capability_id);
    try std.testing.expectEqual(presentation_authority.id, authorities.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 1), cache.revalidation_count);
    try std.testing.expectEqual(@as(u64, 1), cache.authority_generation);

    try capabilities.revokeGrant(unrelated_authority.id);
    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 2), cache.revalidation_count);
    try std.testing.expectEqual(@as(u64, 1), cache.authority_generation);

    const target_revoker = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 903 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 9 },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = 904, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(@as(u64, 1), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 3), cache.revalidation_count);

    try capabilities.revokeTargetAuthority(target_revoker.id);
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 11, &cache);
    try std.testing.expectEqual(query_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(@as(u64, 8), authorities.bootstrap_service_id);
    try std.testing.expectEqual(input_authority.id, authorities.input_capability_id);
    try std.testing.expectEqual(presentation_authority.id, authorities.surface_presentation_capability_id);
    try std.testing.expectEqual(@as(u64, 2), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 3), cache.revalidation_count);
    try std.testing.expectEqual(@as(u64, 2), cache.authority_generation);

    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 101, &cache);
    try std.testing.expectEqual(MailboxAuthorities{}, authorities);
    try std.testing.expectEqual(@as(u64, 3), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 3), cache.authority_generation);

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
    try std.testing.expectEqual(@as(u64, 3), cache.authority_generation);
    _ = resolveMailboxAuthoritiesCached(task, &capabilities, 119, &cache);
    try std.testing.expectEqual(@as(u64, 4), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 3), cache.authority_generation);

    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 120, &cache);
    try std.testing.expectEqual(future_authority.id, authorities.bootstrap_capability_id);
    try std.testing.expectEqual(@as(u64, 10), authorities.bootstrap_service_id);
    try std.testing.expectEqual(@as(u64, 5), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 4), cache.authority_generation);

    try std.testing.expect(try runtime.revokeCapability(task.id, future_authority.id));
    authorities = resolveMailboxAuthoritiesCached(task, &capabilities, 120, &cache);
    try std.testing.expectEqual(MailboxAuthorities{}, authorities);
    try std.testing.expectEqual(@as(u64, 6), cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 5), cache.authority_generation);
    try std.testing.expectEqual(@as(u8, 0), UNRELATED_CAPABILITY_MUTATION_AUTHORITY_SCANS);
    try std.testing.expectEqual(@as(u64, 1), nextMailboxAuthorityGeneration(std.math.maxInt(u64)));
}

test "executor matches userspace counters by stage and pulse" {
    var executor = Executor{};
    _ = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .last_user_counter = userspace_bootstrap_mailbox.packCounter(.syscall_ready, .proof, userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE),
    });

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

test "user memory copies require the live active owner and exact mapping generation" {
    var executor = Executor{};
    const handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 },
        .dispatch_metadata = .{ .owner_task_id = 8 },
    });
    const mapping = &executor.mappingArena().?.getByHandle(handle).?.mapping;
    executor.active_mapping = mapping;
    executor.active_mapping_handle = handle;
    executor.active_task_id = 8;
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == mapping);
    try std.testing.expect(activeUserMemoryMapping(&executor, 0) == null);
    try std.testing.expect(activeUserMemoryMapping(&executor, 9) == null);

    mapping.dispatch_metadata.owner_task_id = 9;
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == null);
    mapping.dispatch_metadata.owner_task_id = 8;
    mapping.state = .retire_pending;
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == null);
    mapping.state = .live;
    mapping.address_space = null;
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == null);
    mapping.address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 };

    const saved_mapping = mapping.*;
    try std.testing.expect(executor.mappingArena().?.removeHandle(handle));
    const replacement = installTestMappingAt(&executor, 0, saved_mapping);
    try std.testing.expect(!handle.eql(replacement));
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == null);
    executor.active_mapping_handle = replacement;
    try std.testing.expect(activeUserMemoryMapping(&executor, 8) == mapping);
}

test "zero-initialized mapping arenas preserve generational reuse" {
    var mappings: MappingArena = undefined;
    initializeMappingArena(&mappings);

    const first = mappings.reserveHandle(41).?;
    mappings.getByHandle(first).?.mapping.address_space_id = 41;
    try std.testing.expectEqual(@as(usize, 1), mappings.countInUse());
    try std.testing.expect(mappings.removeHandle(first));

    const replacement = mappings.reserveHandle(42).?;
    mappings.getByHandle(replacement).?.mapping.address_space_id = 42;
    try std.testing.expectEqual(first.slotIndex(), replacement.slotIndex());
    try std.testing.expect(!first.eql(replacement));
    try std.testing.expect(mappings.getByHandle(first) == null);
    try std.testing.expect(mappings.getByHandle(replacement) != null);
}

test "executor retires inactive address spaces with mailbox caches and reuses slots" {
    var executor = Executor{};
    const retired_handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .dispatch_metadata = .{
            .owner_task_id = 8,
            .image_id = 9,
            .initial_instruction_pointer = 0x4000_1000,
            .initial_stack_pointer = 0x7FFF_EFF0,
            .bootstrap_mailbox_address = 0x4000_3000,
            .launch_policy = .{ .contract_flags = userspace_flags.FLAG_NX_PROOF_PROBE },
        },
        .mailbox_authority_cache = .{ .initialized = true, .refresh_count = 7, .authority_generation = 7 },
        .mailbox_publication_cache = .{ .initialized = true, .published_authority_generation = 7 },
    });
    const retired_entry = &executor.mappings.slotAt(0).mapping;
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == retired_entry);
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 43) == null);
    var cached_handle = MappingHandle{};
    try std.testing.expect(executor.resolveMappingForDispatch(&cached_handle, 42) == retired_entry);
    try std.testing.expect(cached_handle.eql(retired_handle));

    const event = task_runtime.AddressSpaceRetirementEvent{
        .address_space_id = 42,
        .reason = .snapshot_restore,
    };
    executor.retireAddressSpace(event);
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == null);
    const cleared_entry = &executor.mappings.slotAt(0).mapping;
    try std.testing.expectEqual(MappingDispatchMetadata{}, cleared_entry.dispatch_metadata);
    try std.testing.expectEqual(@as(u64, 0), cleared_entry.mailbox_authority_cache.refresh_count);
    try std.testing.expectEqual(@as(u64, 0), cleared_entry.mailbox_authority_cache.authority_generation);
    try std.testing.expectEqual(@as(u64, 0), cleared_entry.mailbox_publication_cache.published_authority_generation);

    executor.retireAddressSpace(event);
    const reused_handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
    });
    const reused_entry = &executor.mappings.slotAt(0).mapping;
    try std.testing.expect(!reused_handle.eql(retired_handle));
    try std.testing.expect(executor.findMappingByHandle(retired_handle, 42) == null);
    try std.testing.expect(executor.findMappingByHandle(reused_handle, 42) == reused_entry);
    try std.testing.expectEqual(@as(u8, 0), STEADY_MAPPING_INDEX_LOOKUPS_PER_DISPATCH);
    executor.releaseRetiredMappingAfterHandoff(reused_handle, reused_entry);
    try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
}

test "executor defers active address-space retirement until kernel handoff" {
    var executor = Executor{};
    const active_handle = installTestMappingAt(&executor, 0, .{ .state = .live, .address_space_id = 42 });
    const active_entry = &executor.mappings.slotAt(0).mapping;
    executor.active_mapping = active_entry;
    executor.active_mapping_handle = active_handle;
    executor.active_task_id = 7;

    executor.retireAddressSpace(.{ .address_space_id = 42, .reason = .terminate });
    try std.testing.expectEqual(MappingState.retire_pending, active_entry.state);
    try std.testing.expectEqual(@as(usize, 1), executor.materializedCount());
    try std.testing.expect(executor.mappingHandle(42) == null);
    try std.testing.expect(executor.findMappingByHandle(active_handle, 42) == null);
    try std.testing.expect(executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);

    executor.active_task_id = 0;
    executor.active_mapping = null;
    executor.active_mapping_handle = .{};
    executor.releaseRetiredMappingAfterHandoff(active_handle, active_entry);
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMapping(42) == null);
    try std.testing.expect(executor.findMappingByHandle(active_handle, 42) == null);
    try std.testing.expectEqual(@as(u8, 0), STEADY_RETIREMENT_SLOT_SCANS_PER_DISPATCH);
    executor.reset();
}

test "executor mapping arena enforces capacity and invalidates reused handles" {
    var executor = Executor{};
    var handles: [task_runtime.MAX_TASKS]MappingHandle = undefined;

    for (&handles, 0..) |*handle, slot_index| {
        const address_space_id: u64 = @intCast(slot_index + 1);
        handle.* = installTestMappingAt(&executor, slot_index, .{
            .state = .live,
            .address_space_id = address_space_id,
        });
    }
    try std.testing.expectEqual(task_runtime.MAX_TASKS, executor.materializedCount());
    try std.testing.expect(executor.mappings.reserveHandle(task_runtime.MAX_TASKS + 1) == null);

    const retired_handle = handles[task_runtime.MAX_TASKS / 2];
    const retired_slot_index = retired_handle.slotIndex();
    const retired_mappings = executor.mappingArena().?;
    const retired_slot = retired_mappings.slotAt(retired_slot_index);
    executor.releaseMapping(retired_mappings, retired_slot_index, &retired_slot.mapping);
    const replacement_address_space_id: u64 = task_runtime.MAX_TASKS + 1;
    const replacement_handle = executor.mappings.reserveHandle(replacement_address_space_id).?;
    executor.mappings.getByHandle(replacement_handle).?.mapping = .{
        .state = .live,
        .address_space_id = replacement_address_space_id,
    };

    try std.testing.expectEqual(retired_slot_index, replacement_handle.slotIndex());
    try std.testing.expect(!retired_handle.eql(replacement_handle));
    try std.testing.expect(executor.findMappingByHandle(retired_handle, replacement_address_space_id) == null);
    try std.testing.expect(executor.findMappingByHandle(replacement_handle, replacement_address_space_id) != null);
    try std.testing.expectEqual(@as(u8, 0), COLD_MAPPING_LINEAR_SLOT_SCANS);
    try std.testing.expectEqual(task_runtime.MAX_TASKS, executor.materializedCount());

    executor.reset();
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expect(executor.findMappingByHandle(replacement_handle, replacement_address_space_id) == null);
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

test "userspace exception records bind vector error and instruction context" {
    const baseline = UserException{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = 0,
        .instruction_pointer = 0x4000_3000,
    };
    try std.testing.expect(baseline.reasonFingerprint() != (UserException{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = 1,
        .instruction_pointer = 0x4000_3000,
    }).reasonFingerprint());
    try std.testing.expect(baseline.reasonFingerprint() != (UserException{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = 0,
        .instruction_pointer = 0x4000_3001,
    }).reasonFingerprint());
    try std.testing.expect(baseline.reasonFingerprint() != (UserException{
        .vector = PAGE_FAULT_VECTOR,
        .error_code = 0x4,
        .instruction_pointer = 0x4000_3000,
        .fault_address = 0x7000_0000,
    }).reasonFingerprint());
    try std.testing.expectEqual(@as(u64, 0), baseline.fault_address);
    try std.testing.expect(ExecutionOutcome.faulted.handedOff());
}

test "userspace exception containment excludes system-fatal and dedicated vectors" {
    try std.testing.expect(isContainableUserExceptionVector(0));
    try std.testing.expect(isContainableUserExceptionVector(6));
    try std.testing.expect(isContainableUserExceptionVector(GENERAL_PROTECTION_FAULT_VECTOR));
    try std.testing.expect(!isContainableUserExceptionVector(2));
    try std.testing.expect(!isContainableUserExceptionVector(8));
    try std.testing.expect(!isContainableUserExceptionVector(PAGE_FAULT_VECTOR));
    try std.testing.expect(!isContainableUserExceptionVector(18));
}

const YieldTestFrame = struct {
    eax: u64,
    ebx: u64 = 13,
    ecx: u64 = 15,
    edx: u64 = 14,
    ebp: u64 = 11,
    esi: u64,
    edi: u64 = 9,
    r8: u64 = 8,
    r9: u64 = 7,
    r10: u64 = 6,
    r11: u64 = 5,
    r12: u64 = 4,
    r13: u64 = 3,
    r14: u64 = 2,
    r15: u64 = 1,
    eip: u64 = 0x4000_1008,
    eflags: u64 = DEFAULT_USER_RFLAGS,
    useresp: u64 = 0x7fff_eff0,
};

fn expectYieldHandler(counter: u64, disposition: u64, expected: ?userspace_bootstrap_mailbox.YieldDisposition) !void {
    var executor = Executor{};
    const previous_executor = registered_executor;
    const previous_requested = zigos_userspace_resume_requested;
    const previous_esp = zigos_userspace_resume_esp;
    const previous_eip = zigos_userspace_resume_eip;
    defer {
        executor.active_task_id = 0;
        executor.active_mapping = null;
        executor.reset();
        registered_executor = previous_executor;
        zigos_userspace_resume_requested = previous_requested;
        zigos_userspace_resume_esp = previous_esp;
        zigos_userspace_resume_eip = previous_eip;
    }
    const handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .yield_count = 8,
        .last_user_counter = 9,
    });
    const mapping = &executor.mappingArena().?.getByHandle(handle).?.mapping;
    executor.active_mapping = mapping;
    executor.active_mapping_handle = handle;
    executor.active_task_id = 7;
    zigos_userspace_resume_requested = 0;
    var frame = YieldTestFrame{ .eax = counter, .esi = disposition };
    const before = frame;
    // This is the production handler body; only the compiler-known frame type
    // differs from the entry assembly's Registers pointer.
    handleUserspaceYield(&executor, &frame);
    try std.testing.expectEqualDeep(before, frame);
    try std.testing.expect(executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);
    try std.testing.expectEqual(@as(u64, 7), executor.active_task_id);
    try std.testing.expect(executor.active_mapping == mapping);
    if (expected) |valid| {
        try std.testing.expect(executor.last_user_exception == null);
        try std.testing.expectEqual(valid, executor.last_yield_disposition);
        try std.testing.expectEqual(@as(u32, @intCast(counter)), mapping.last_user_counter);
        try std.testing.expectEqual(@as(u64, 9), mapping.yield_count);
        try std.testing.expect(mapping.resume_valid);
        try std.testing.expectEqual(frame.eip, mapping.resume_instruction_pointer);
        try std.testing.expectEqual(frame.useresp, mapping.resume_stack_pointer);
        try std.testing.expectEqual(frame.eax, mapping.user_context64.rax);
        try std.testing.expectEqual(frame.esi, mapping.user_context64.rsi);
        try std.testing.expectEqual(frame.r12, mapping.user_context64.r12);
        try std.testing.expectEqual(frame.r13, mapping.user_context64.r13);
        try std.testing.expectEqual(frame.eflags, mapping.user_context64.flags);
        try std.testing.expectEqual(frame.edx, executor.last_yield_ui_revision);
    } else {
        try std.testing.expectEqualDeep(UserException{
            .vector = GENERAL_PROTECTION_FAULT_VECTOR,
            .error_code = 0,
            .instruction_pointer = frame.eip,
        }, executor.last_user_exception.?);
        try std.testing.expectEqual(@as(u32, 9), mapping.last_user_counter);
        try std.testing.expectEqual(@as(u64, 8), mapping.yield_count);
        try std.testing.expect(!mapping.resume_valid);
        try std.testing.expectEqual(UserContext64{}, mapping.user_context64);
        try std.testing.expectEqual(@as(u32, 0), executor.last_trap_counter);
        try std.testing.expectEqual(@as(u64, 0), executor.last_yield_ui_revision);
    }
}

test "yield handler contains counter overflow before publishing a resume" {
    try expectYieldHandler(@as(u64, std.math.maxInt(u32)) + 1, 0, null);
    try expectYieldHandler(std.math.maxInt(u64), 1, null);
}

test "yield handler contains disposition overflow before publishing a resume" {
    try expectYieldHandler(1, @as(u64, std.math.maxInt(u32)) + 1, null);
    try expectYieldHandler(1, std.math.maxInt(u64), null);
}

test "yield handler contains unknown disposition enums" {
    try expectYieldHandler(1, 2, null);
    try expectYieldHandler(1, std.math.maxInt(u32), null);
}

test "yield handler preserves maximum valid counters and both dispositions" {
    try expectYieldHandler(std.math.maxInt(u32), 0, .runnable);
    try expectYieldHandler(std.math.maxInt(u32), 1, .wait_for_event);
}

test "owned state exceptions use user containment without lazy retry" {
    var executor = Executor{ .active_task_id = 7 };
    const previous_requested = zigos_userspace_resume_requested;
    defer zigos_userspace_resume_requested = previous_requested;
    for ([_]u8{ 7, GENERAL_PROTECTION_FAULT_VECTOR }) |vector| {
        zigos_userspace_resume_requested = 0;
        executor.handoff_completed = false;
        try std.testing.expect(containUserException(&executor, vector, 0, 0x4000_1008));
        try std.testing.expectEqual(vector, executor.last_user_exception.?.vector);
        try std.testing.expect(executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);
    }
    executor.last_user_exception = null;
    executor.handoff_completed = false;
    zigos_userspace_resume_requested = 0;
    try std.testing.expect(!containUserException(&executor, 2, 0, 0x4000_1008));
    try std.testing.expect(executor.last_user_exception == null);
    try std.testing.expect(!executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 0), zigos_userspace_resume_requested);
}

const DeviceInterruptFixture = struct {
    const isr = @import("../../kernel/interrupts/isr.zig");
    const wake = @import("../../kernel/event_wake.zig");
    executor: Executor = .{},
    mapping: *MappingEntry = undefined,
    frame: isr.Registers = undefined,
    previous_executor: ?*Executor = null,
    previous_requested: u32 = 0,
    previous_esp: usize = 0,
    previous_eip: usize = 0,
    previous_wakes: wake.Pending = .{},

    fn init(self: *@This()) !void {
        const storage = table_backing.alloc(xstate.Storage) orelse return error.OutOfMemory;
        storage.initialize();
        self.previous_executor = registered_executor;
        self.previous_requested = zigos_userspace_resume_requested;
        self.previous_esp = zigos_userspace_resume_esp;
        self.previous_eip = zigos_userspace_resume_eip;
        self.previous_wakes = wake.take();
        const handle = installTestMappingAt(&self.executor, 0, .{
            .state = .live,
            .address_space_id = 42,
            .address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 },
            .dispatch_metadata = .{ .owner_task_id = 7, .image_id = 41 },
            .owned_xstate = storage,
            .last_user_counter = 9,
            .yield_count = 8,
        });
        self.mapping = &self.executor.mappingArena().?.getByHandle(handle).?.mapping;
        self.executor.active_task_id = 7;
        self.executor.active_mapping = self.mapping;
        self.executor.active_mapping_handle = handle;
        self.executor.dispatch_quantum = DispatchQuantum.begin(7, 100);
        registered_executor = &self.executor;
        zigos_userspace_resume_requested = 0;
        zigos_userspace_resume_esp = 0xfeed_1000;
        zigos_userspace_resume_eip = 0xfeed_2000;
        self.frame = std.mem.zeroes(isr.Registers);
        inline for (.{ "eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }, 0..) |field, index|
            @field(self.frame, field) = 0x1234_0000 + index * 0x101;
        self.frame.eip = 0x4000_1008;
        self.frame.cs = 0x23;
        self.frame.eflags = 0x246;
        self.frame.useresp = 0x7fff_eff0;
        self.frame.ss = 0x1b;
    }

    fn deinit(self: *@This()) void {
        self.executor.active_task_id = 0;
        self.executor.active_mapping = null;
        self.executor.reset();
        registered_executor = self.previous_executor;
        zigos_userspace_resume_requested = self.previous_requested;
        zigos_userspace_resume_esp = self.previous_esp;
        zigos_userspace_resume_eip = self.previous_eip;
        _ = wake.take();
        inline for (.{ "timer", "xhci", "network", "nvme", "scheduler" }) |field|
            if (@field(self.previous_wakes, field)) wake.raise(@field(wake.Kind, field));
    }

    const Latch = struct {
        var kind: ?wake.Kind = null;
        fn receive(_: *isr.InterruptFrame) void {
            if (!@import("../../kernel/interrupts/context.zig").active())
                @panic("device fixture must execute in the real ISR context");
            if (kind) |work| wake.raise(work);
        }
    };

    fn dispatch(self: *@This(), vector: u8, kind: ?wake.Kind) !void {
        const Case = struct {
            fixture: *DeviceInterruptFixture,
            vector: u8,
            kind: ?wake.Kind,
            fn run(self_case: *@This()) !void {
                const previous_kind = Latch.kind;
                defer Latch.kind = previous_kind;
                Latch.kind = self_case.kind;
                isr.registerHandler(self_case.vector, Latch.receive);
                isr.setRuntimePreemption(userspaceInterruptPreemption);
                self_case.fixture.frame.int_no = self_case.vector;
                isr.isrHandler(&self_case.fixture.frame);
            }
        };
        var case = Case{ .fixture = self, .vector = vector, .kind = kind };
        try isr.withTestHandlers(&case, Case.run);
        try std.testing.expect(!@import("../../kernel/interrupts/context.zig").active());
    }

    fn expectResume(self: *const @This()) !void {
        try std.testing.expect(self.executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 1), zigos_userspace_resume_requested);
        try std.testing.expect(self.mapping.resume_valid);
        try std.testing.expectEqual(@as(u64, 9), self.mapping.yield_count);
        try std.testing.expectEqual(@as(u32, 9), self.mapping.last_user_counter);
        try std.testing.expectEqual(self.frame.eip, self.mapping.resume_instruction_pointer);
        try std.testing.expectEqual(self.frame.useresp, self.mapping.resume_stack_pointer);
        inline for (.{ "rax", "rbx", "rcx", "rdx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }, .{ "eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }) |user_field, frame_field|
            try std.testing.expectEqual(@field(self.frame, frame_field), @field(self.mapping.user_context64, user_field));
        try std.testing.expectEqual(self.frame.eflags, self.mapping.user_context64.flags);
        try std.testing.expectEqual(self.frame.eip, self.mapping.user_context64.instruction_pointer);
        try std.testing.expectEqual(self.frame.useresp, self.mapping.user_context64.stack_pointer);
        try std.testing.expectEqual(userspace_bootstrap_mailbox.YieldDisposition.runnable, self.executor.last_yield_disposition);
        try std.testing.expect(self.executor.last_user_exception == null);
        try std.testing.expectEqual(DispatchQuantum.begin(7, 100), self.executor.dispatch_quantum);
        try std.testing.expectEqual(@as(usize, 0xfeed_1000), zigos_userspace_resume_esp);
        try std.testing.expectEqual(@as(usize, 0xfeed_2000), zigos_userspace_resume_eip);
    }

    fn expectNoResume(self: *const @This()) !void {
        try std.testing.expect(!self.executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 0), zigos_userspace_resume_requested);
        try std.testing.expect(!self.mapping.resume_valid);
        try std.testing.expectEqual(@as(u64, 8), self.mapping.yield_count);
    }
};

test "device IRQ real ISR hands off allowlisted users before their watchdog" {
    inline for (.{ .{ @as(u8, 65), DeviceInterruptFixture.wake.Kind.network }, .{ @as(u8, 66), DeviceInterruptFixture.wake.Kind.nvme }, .{ @as(u8, 67), DeviceInterruptFixture.wake.Kind.xhci } }) |case| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        const state_before = fixture.mapping.owned_xstate.?.*;
        try std.testing.expect(!shouldPreemptUserDispatch(&fixture.executor, true, 100, null));
        try fixture.dispatch(case[0], case[1]);
        try fixture.expectResume();
        try std.testing.expectEqualDeep(state_before, fixture.mapping.owned_xstate.?.*);
        const pending = DeviceInterruptFixture.wake.peek();
        try std.testing.expect(switch (case[1]) {
            .network => pending.network,
            .nvme => pending.nvme,
            .xhci => pending.xhci,
            else => false,
        });
        try std.testing.expect(shouldPreemptUserDispatch(&fixture.executor, true, 102, null));
    }
}

test "device IRQ real ISR requires the matching latch and excludes other vectors" {
    for ([_]u8{ 7, 13, 64, 112, 129, 255 }) |vector| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        try fixture.dispatch(vector, .network);
        try fixture.expectNoResume();
        try std.testing.expect(DeviceInterruptFixture.wake.peek().network);
    }
    for ([_]?DeviceInterruptFixture.wake.Kind{ null, .network }) |kind| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        try fixture.dispatch(67, kind);
        try fixture.expectNoResume();
    }
}

test "device IRQ real ISR preserves kernel continuation and missing active dispatch" {
    const Absent = enum { kernel, executor, task, quantum, mapping, address_space, xstate };
    for (std.enums.values(Absent)) |absent| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        const storage = fixture.mapping.owned_xstate;
        defer fixture.mapping.owned_xstate = storage;
        switch (absent) {
            .kernel => fixture.frame.cs = 0x08,
            .executor => registered_executor = null,
            .task => fixture.executor.active_task_id = 0,
            .quantum => fixture.executor.dispatch_quantum = .{},
            .mapping => fixture.executor.active_mapping = null,
            .address_space => fixture.mapping.address_space = null,
            .xstate => fixture.mapping.owned_xstate = null,
        }
        try fixture.dispatch(67, .xhci);
        try fixture.expectNoResume();
        try std.testing.expect(DeviceInterruptFixture.wake.peek().xhci);
    }
}

test "device IRQ real ISR rejects foreign retired and recycled mapping incarnations" {
    const Invalid = enum { foreign_owner, retired, stale_handle, foreign_mapping };
    for (std.enums.values(Invalid)) |invalid| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        switch (invalid) {
            .foreign_owner => fixture.mapping.dispatch_metadata.owner_task_id = 8,
            .retired => fixture.mapping.state = .retire_pending,
            .stale_handle => {
                const old_handle = fixture.executor.active_mapping_handle;
                const mapping_copy = fixture.mapping.*;
                try std.testing.expect(fixture.executor.mappingArena().?.removeHandle(old_handle));
                const replacement = installTestMappingAt(&fixture.executor, 0, mapping_copy);
                try std.testing.expect(!old_handle.eql(replacement));
                fixture.mapping = &fixture.executor.mappingArena().?.getByHandle(replacement).?.mapping;
                fixture.executor.active_mapping = fixture.mapping;
            },
            .foreign_mapping => {
                const other = installTestMappingAt(&fixture.executor, 1, .{ .address_space_id = 43 });
                fixture.executor.active_mapping = &fixture.executor.mappingArena().?.getByHandle(other).?.mapping;
            },
        }
        try fixture.dispatch(65, .network);
        try fixture.expectNoResume();
        try std.testing.expect(DeviceInterruptFixture.wake.peek().network);
    }
}

test "device IRQ real ISR coalesces duplicate handoffs and preserves existing containment" {
    var fixture = DeviceInterruptFixture{};
    try fixture.init();
    defer fixture.deinit();
    try fixture.dispatch(67, .xhci);
    try fixture.expectResume();
    const captured = fixture.mapping.user_context64;
    fixture.frame.eip += 4;
    fixture.frame.eax += 1;
    try fixture.dispatch(67, .xhci);
    try fixture.dispatch(65, .network);
    try std.testing.expectEqual(captured, fixture.mapping.user_context64);
    try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
    const wakes = DeviceInterruptFixture.wake.take();
    try std.testing.expect(wakes.xhci and wakes.network);
    try std.testing.expect(!DeviceInterruptFixture.wake.any());

    fixture.executor.last_user_exception = .{ .vector = 13, .error_code = 0, .instruction_pointer = 0x4000_0000 };
    fixture.mapping.state = .retire_pending;
    try fixture.dispatch(66, .nvme);
    try std.testing.expectEqual(@as(u8, 13), fixture.executor.last_user_exception.?.vector);
    try std.testing.expectEqual(captured, fixture.mapping.user_context64);
    try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
}

test "device IRQ actual FRED captured context resumes through the shared ISR handler" {
    const Probe = struct {
        extern fn zigos_fred_capture_probe(*const [15]u64, *const [8]u64, *[32]u64) callconv(.c) void;
    };
    var fixture = DeviceInterruptFixture{};
    try fixture.init();
    defer fixture.deinit();
    var seeds: [15]u64 = undefined;
    for (&seeds, 0..) |*value, index| value.* = 0x1234_0000 + index * 0x101;
    const raw = [8]u64{ 0, 0x4000_1008, 0x23, 0x246, 0x7fff_eff0, 0x1b | (@as(u64, 67) << 32) | (@as(u64, 1) << 57), 0, 0 };
    var captured: [32]u64 = undefined;
    Probe.zigos_fred_capture_probe(&seeds, &raw, &captured);
    @memcpy(std.mem.asBytes(&fixture.frame), std.mem.sliceAsBytes(captured[0..24]));
    try fixture.dispatch(67, .xhci);
    try fixture.expectResume();
    try std.testing.expectEqualSlices(u64, &seeds, std.mem.bytesAsSlice(u64, std.mem.asBytes(&fixture.mapping.user_context64))[0..15]);
}

test "production address-space groups share page tables" {
    try std.testing.expect(SHARES_GROUP_PAGE_TABLES);
    try std.testing.expect(!USES_PKU_WITHIN_SHARED_TABLES);
    try std.testing.expectEqual(@as(usize, 8), GROUP_SPACE_COUNT);
}

test "syscall failure wait response validation preserves the executor disposition" {
    var executor = Executor{};
    const previous = registered_executor;
    defer registered_executor = previous;
    registered_executor = &executor;
    const failure_tests = if (builtin.is_test) @import("../kernel_api/syscall_failure_test.zig") else struct {};
    try failure_tests.expectWaitResponseFailures(&executor);
}

test "shared lifetime registration rejects foreign tail ownership before publication" {
    const ids = @import("../core/ids.zig");
    demand_paging.reset();
    defer demand_paging.reset();
    var executor = Executor{};
    defer executor.reset();
    const handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 },
        .dispatch_metadata = .{ .owner_task_id = 7 },
    });
    const mapping = &executor.mappingArena().?.getByHandle(handle).?.mapping;
    executor.active_mapping = mapping;
    var table = shared_memory.Table.initWithMappingLifetime(.{
        .context = &executor,
        .register = registerMappedObject,
        .unregister = unregisterMappedObject,
    });
    defer table.deinit();
    const object = try table.create(ids.task(7), 1);
    const first = userspace_layout.shared_start + shared_memory.PAGE_SIZE;
    const foreign_start = first + 64;
    try std.testing.expect(demand_paging.registerForSpace(&mapping.address_space.?, .{
        .virt_start = foreign_start,
        .virt_end_exclusive = foreign_start + 64,
        .writable = true,
    }));
    try std.testing.expectError(error.MappingRegistrationFailed, table.map(object.id, ids.task(7)));
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(object.id)).mapped_task_count);
    try std.testing.expectEqual(@as(usize, 0), table.activeFreestandingMappings(object.id));
    try std.testing.expectEqual(@as(u16, 0), executor.mapped_object_count);
    try std.testing.expect(executor.mapped_object_table == null);
    try std.testing.expect(demand_paging.resolveFault(&mapping.address_space.?, foreign_start, 4));
    try std.testing.expect(demand_paging.unregisterRegionForSpace(&mapping.address_space.?, foreign_start, foreign_start + 64));
    try table.map(object.id, ids.task(7));
    const registered = try table.freestandingTaskMappingDescriptor(object.id, ids.task(7));
    try std.testing.expectEqual(first, registered.virtual_base);
    try std.testing.expect(try table.unmap(object.id, ids.task(7)));
    try std.testing.expect(!demand_paging.resolveFault(&mapping.address_space.?, first, 4));
    try std.testing.expect(executor.mapped_object_table == null);
}

test "shared lifetime executor retirement rejects recycled handles and preserves grouped peers" {
    const ids = @import("../core/ids.zig");
    demand_paging.reset();
    defer demand_paging.reset();
    var executor = Executor{};
    defer executor.reset();
    const space = freestanding.paging.UserAddressSpace{ .directory = @ptrFromInt(0x1000), .pcid = 1 };
    executor.group_spaces[0] = space;
    executor.group_refs[0] = 2;
    const first_handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 42,
        .address_space = space,
        .dispatch_metadata = .{ .owner_task_id = 7 },
    });
    const peer_handle = installTestMappingAt(&executor, 1, .{
        .state = .live,
        .address_space_id = 43,
        .address_space = space,
        .dispatch_metadata = .{ .owner_task_id = 8 },
    });
    var table = shared_memory.Table.initWithMappingLifetime(.{
        .context = &executor,
        .register = registerMappedObject,
        .unregister = unregisterMappedObject,
    });
    defer table.deinit();
    const object = try table.create(ids.task(7), shared_memory.PAGE_SIZE);
    executor.active_mapping = &executor.mappingArena().?.getByHandle(first_handle).?.mapping;
    try table.map(object.id, ids.task(7));
    const retired = try table.freestandingTaskMappingDescriptor(object.id, ids.task(7));
    executor.active_mapping = &executor.mappingArena().?.getByHandle(peer_handle).?.mapping;
    try table.map(object.id, ids.task(8));
    const peer = try table.freestandingTaskMappingDescriptor(object.id, ids.task(8));
    executor.active_mapping = null;
    try std.testing.expectEqual(@as(u16, 2), executor.mapped_object_count);
    try std.testing.expect(!unregisterMappedObject(&executor, &table, peer_handle.value, retired));
    executor.retireAddressSpace(.{ .address_space_id = 42, .reason = .snapshot_restore });
    try std.testing.expectEqual(@as(u16, 1), executor.mapped_object_count);
    try std.testing.expect(!table.hasMapping(object.id, ids.task(7)));
    try std.testing.expect(table.hasMapping(object.id, ids.task(8)));
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
    try std.testing.expect(!demand_paging.resolveFault(&space, retired.virtual_base, 4));
    try std.testing.expect(demand_paging.resolveFault(&space, peer.virtual_base, 4));
    const replacement = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = 44,
        .address_space = space,
        .dispatch_metadata = .{ .owner_task_id = 7 },
    });
    executor.group_refs[0] += 1;
    try std.testing.expect(!first_handle.eql(replacement));
    executor.active_mapping = &executor.mappingArena().?.getByHandle(replacement).?.mapping;
    try table.map(object.id, ids.task(7));
    const remapped = try table.freestandingTaskMappingDescriptor(object.id, ids.task(7));
    executor.active_mapping = null;
    try std.testing.expect(!unregisterMappedObject(&executor, &table, first_handle.value, retired));
    try std.testing.expect(!unregisterMappedObject(&executor, &table, replacement.value, retired));
    try std.testing.expectEqual(@as(u16, 2), executor.mapped_object_count);
    try std.testing.expect(demand_paging.resolveFault(&space, remapped.virtual_base, 4));
    try std.testing.expect(demand_paging.resolveFault(&space, peer.virtual_base, 4));
    executor.reset();
    try std.testing.expectEqual(@as(u16, 0), executor.mapped_object_count);
    try std.testing.expect(executor.mapped_object_table == null);
    try std.testing.expectEqual(@as(usize, 0), executor.materializedCount());
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
    try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(object.id)).mapped_task_count);
    try std.testing.expect(!demand_paging.resolveFault(&space, remapped.virtual_base, 4));
    try std.testing.expect(!demand_paging.resolveFault(&space, peer.virtual_base, 4));
}

test "userspace quantum arms at actual entry after idle and retains private extended state" {
    const Clock = struct {
        now: u64,
        armed: bool = false,
        fn armSchedulerTick(self: *@This()) void {
            self.armed = true;
        }
        fn getTicks(self: *@This()) u64 {
            return self.now;
        }
    };
    const Entry = struct {
        executor: *Executor,
        clock: *Clock,
        expected_state: *align(xstate.alignment) xstate.State,
        called: bool = false,
        fn enter(self: *@This(), context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
            if (!self.clock.armed or state != self.expected_state or context != &self.executor.pending_user_context64)
                @panic("user entry requires its armed timer and owned context");
            if (shouldPreemptUserDispatch(self.executor, true, self.clock.now, null) or
                !shouldPreemptUserDispatch(self.executor, true, self.clock.now + DISPATCH_QUANTUM_TICKS, null) or
                shouldPreemptUserDispatch(self.executor, false, self.clock.now + DISPATCH_QUANTUM_TICKS, null))
                @panic("actual user entry starts a finite fresh quantum");
            self.called = true;
            return 7;
        }
    };
    var storage: xstate.Storage = .{};
    storage.initialize();
    var mapping = MappingEntry{ .owned_xstate = &storage };
    var executor = Executor{ .active_task_id = 42, .active_mapping = &mapping };
    var clock = Clock{ .now = 500 };
    var entry = Entry{ .executor = &executor, .clock = &clock, .expected_state = storage.state() };
    try std.testing.expectEqual(@as(u32, 7), enterUserspaceWithClock(&executor, &clock, &entry));
    try std.testing.expect(entry.called);
    // A later dispatch does not inherit the prior task's deadline.
    clock.armed = false;
    clock.now = 1000;
    entry.called = false;
    try std.testing.expectEqual(@as(u32, 7), enterUserspaceWithClock(&executor, &clock, &entry));
    try std.testing.expect(entry.called);
    try std.testing.expectEqual(@as(u64, 1002), executor.dispatch_quantum.deadline_tick);
    try std.testing.expect(!executor.dispatch_quantum.expired(43, 1002));
    const Priority = struct {
        fn ready(_: u64) bool {
            return true;
        }
    };
    try std.testing.expect(shouldPreemptUserDispatch(&executor, true, 1000, Priority.ready));
    try std.testing.expect(!shouldPreemptUserDispatch(&executor, false, 1000, Priority.ready));
    executor.dispatch_quantum = .{};
    executor.active_task_id = 0;
    try std.testing.expect(!shouldPreemptUserDispatch(&executor, true, 1002, Priority.ready));
}

test "userspace mapping retirement releases its private extended state allocation" {
    var executor = Executor{};
    defer executor.reset();
    const mappings = executor.mappingArena().?;
    const storage = table_backing.alloc(xstate.Storage) orelse return error.OutOfMemory;
    storage.initialize();
    const handle = installTestMappingAt(&executor, 0, .{ .address_space_id = 11, .owned_xstate = storage });
    const mapping = &mappings.getByHandle(handle).?.mapping;
    executor.releaseMapping(mappings, handle.slotIndex(), mapping);
    try std.testing.expect(mappings.getByHandle(handle) == null);
    try std.testing.expect(mapping.owned_xstate == null);
}
