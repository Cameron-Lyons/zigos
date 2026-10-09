const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const dispatch_ownership = @import("dispatch_ownership.zig");
const dispatch_transport = @import("dispatch_transport.zig");
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
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const interrupt_context = @import("../../kernel/interrupts/context.zig");
const native_entry = @import("../../arch/x86_64/native_entry_state.zig");
const xstate = @import("../../arch/xstate.zig");
const timer = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/timer/timer.zig")
else
    struct {};
const demand_paging = @import("../../kernel/memory/demand_paging.zig");
const xhci_driver_task = @import("../drivers/xhci_driver_task.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const syscall_broker = @import("../kernel_api/syscall_broker.zig");
const syscall_dispatch = @import("../kernel_api/syscall_dispatch.zig");
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
        pub const CR3_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
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

// Keep resident invariant diagnostics in one immutable blob. Compile-time
// concatenation preserves its address with the pinned compiler; independently
// stored offsets avoid copying a locally filled array into an anonymous table.
const ExecutorInvariant = enum(u8) {
    dispatch_quantum_requires_an_active_task,
    selected_cpu_trap_stack_must_be_provisioned_before_entry,
    published_trap_stack_must_retain_its_backing,
    one_runtime_cpu_owns_the_userspace_entry_state,
    shared_executor_services_require_the_bsp_runtime_owner,
    selected_cpu_executor_registration_requires_its_exact_owner,
    executor_retirement_requires_its_exact_cpu_registration_owner,
    active_userspace_mapping_handle_points_at_a_different_slot,
    native_dispatch_acknowledges_its_exact_execution_lease,
    executor_reset_requires_its_exact_cpu_registration_owner,
    cannot_reset_userspace_executor_while_an_address_space_is_active,
    executor_reset_must_release_its_exact_registration,
    materialized_userspace_mapping_identity_changed_without_retirement,
    native_dispatch_starts_its_exact_bound_execution_lease,
    native_dispatch_acknowledges_only_its_cleared_kernel_continuation,
    materialized_userspace_dispatch_metadata_changed_without_retirement,
    reserved_userspace_mapping_handle_is_not_live,
    executor_mapping_index_points_at_a_non_live_mapping,
    executor_mapping_index_points_at_the_wrong_mapping,
    executor_mapping_index_points_at_an_unclaimed_slot,
    pending_userspace_retirement_retains_its_mapping_incarnation,
    userspace_retirement_requires_a_quiescent_mapping_and_physical_root,
    invalid_retired_stack_mapping_range,
    invalid_retired_image_mapping_range,
    attempted_to_destroy_the_active_userspace_address_space,
    live_userspace_mapping_disappeared_during_release,
    resolved_mailbox_authorities_require_a_nonzero_generation,
    active_userspace_task_has_no_materialized_mapping,
    userspace_exception_vector_exceeds_the_idt_range,
    userspace_page_fault_code_exceeds_its_abi_width,
    userspace_entry_requires_the_active_mapping_owner,
    userspace_entry_requires_private_extended_state,
};

const executor_invariant_messages = [_][]const u8{
    "dispatch quantum requires an active task",
    "selected CPU trap stack must be provisioned before entry",
    "published trap stack must retain its backing",
    "one runtime CPU owns the userspace entry state",
    "shared executor services require the BSP runtime owner",
    "selected CPU executor registration requires its exact owner",
    "executor retirement requires its exact CPU registration owner",
    "active userspace mapping handle points at a different slot",
    "native dispatch acknowledges its exact execution lease",
    "executor reset requires its exact CPU registration owner",
    "cannot reset userspace executor while an address space is active",
    "executor reset must release its exact registration",
    "materialized userspace mapping identity changed without retirement",
    "native dispatch starts its exact bound execution lease",
    "native dispatch acknowledges only its cleared kernel continuation",
    "materialized userspace dispatch metadata changed without retirement",
    "reserved userspace mapping handle is not live",
    "executor mapping index points at a non-live mapping",
    "executor mapping index points at the wrong mapping",
    "executor mapping index points at an unclaimed slot",
    "pending userspace retirement retains its mapping incarnation",
    "userspace retirement requires a quiescent mapping and physical root",
    "invalid retired stack mapping range",
    "invalid retired image mapping range",
    "attempted to destroy the active userspace address space",
    "live userspace mapping disappeared during release",
    "resolved mailbox authorities require a nonzero generation",
    "active userspace task has no materialized mapping",
    "userspace exception vector exceeds the IDT range",
    "userspace page-fault code exceeds its ABI width",
    "userspace entry requires the active mapping owner",
    "userspace entry requires private extended state",
};

const executor_invariant_message_bytes: []const u8 = blk: {
    if (executor_invariant_messages.len != @typeInfo(ExecutorInvariant).@"enum".field_names.len)
        @compileError("executor invariant messages must cover every selector");
    var bytes: []const u8 = "";
    for (executor_invariant_messages) |message| bytes = bytes ++ message;
    if (bytes.len > std.math.maxInt(u16)) @compileError("executor invariant message offsets must fit u16");
    break :blk bytes;
};

const executor_invariant_message_offsets = blk: {
    var offsets: [executor_invariant_messages.len + 1]u16 = undefined;
    var cursor: usize = 0;
    for (executor_invariant_messages, 0..) |message, index| {
        offsets[index] = @intCast(cursor);
        cursor += message.len;
    }
    offsets[executor_invariant_messages.len] = @intCast(cursor);
    break :blk offsets;
};

fn executorInvariantMessage(selector: ExecutorInvariant) []const u8 {
    const index: usize = @backingInt(selector);
    return executor_invariant_message_bytes[executor_invariant_message_offsets[index]..executor_invariant_message_offsets[index + 1]];
}

fn executorInvariantFailure(selector: ExecutorInvariant) noreturn {
    @branchHint(.cold);
    native_util.impossibleByInvariant(@call(.always_inline, executorInvariantMessage, .{selector}));
}

test "executor invariant diagnostics retain every exact message under runtime selection" {
    var index: usize = 0;
    while (index < executor_invariant_messages.len) : (index += 1) {
        std.mem.doNotOptimizeAway(&index);
        const selector: ExecutorInvariant = @fromBackingInt(@intCast(index));
        const message = @call(.never_inline, executorInvariantMessage, .{selector});
        try std.testing.expectEqualStrings(executor_invariant_messages[index], message);
    }
    try std.testing.expectEqual(executor_invariant_message_bytes.len, executor_invariant_message_offsets[executor_invariant_messages.len]);
}

// A dispatch is bounded even when no other task is ready yet. This returns the
// runtime owner to deferred device work before it can discover new runnable work.
pub const DISPATCH_QUANTUM_TICKS: u64 = 2;
pub const DispatchQuantum = struct {
    task_id: u64 = 0,
    deadline_tick: u64 = 0,

    pub fn begin(task_id: u64, now_ticks: u64) DispatchQuantum {
        if (task_id == 0) @call(.never_inline, executorInvariantFailure, .{.dispatch_quantum_requires_an_active_task});
        return .{ .task_id = task_id, .deadline_tick = now_ticks +| DISPATCH_QUANTUM_TICKS };
    }

    pub fn expired(self: DispatchQuantum, task_id: u64, now_ticks: u64) bool {
        return self.task_id != 0 and self.task_id == task_id and now_ticks >= self.deadline_tick;
    }
};

pub const ExecutionOutcome = dispatch_ownership.Outcome;
pub const ReturnRecord = dispatch_ownership.ReturnRecord;

// BSP-owned preparation publishes only lease identity and private entry data.
// No task, capability, catalog or Runtime pointer crosses the owner boundary.
const PreparedDispatch = dispatch_transport.Command;

const architecture_smp_proof = @hasDecl(root, "ARCHITECTURE_SMP_PROOF") and root.ARCHITECTURE_SMP_PROOF;
pub const ArchitecturePreparedCommand = if (architecture_smp_proof) PreparedDispatch else void;
pub const ArchitecturePreparedEntry = struct {
    task_id: u64,
    physical_root: u64,
    trap_stack_top: usize,
    user_context: *const UserContext64,
    xstate_address: usize,
    dispatch_quantum: DispatchQuantum,
};
pub const ArchitecturePreparedCallback = *const fn (*anyopaque, *const ArchitecturePreparedEntry) ReturnRecord;
pub const ArchitecturePreparedBeforeRun = *const fn (*anyopaque) void;
pub const ArchitecturePreparedAfterReturn = *const fn (*anyopaque, bool) void;

comptime {
    if (@sizeOf(PreparedDispatch) != 32) @compileError("prepared command must retain its compact scalar shell");
}

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
            pub fn setKernelStack(_: usize) bool {
                return true;
            }
        };

        pub const isr = struct {
            pub const InterruptFrame = @import("../../kernel/interrupts/isr.zig").InterruptFrame;
            pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

            pub fn registerHandler(_: u8, _: InterruptHandler) void {}
            pub fn setRuntimePreemption(_: *const fn (regs: *InterruptFrame) void) void {}
        };

        pub const paging = struct {
            pub const PageDirectory = opaque {};
            pub const WritableUserSegment = struct { address: usize, bytes: usize };
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
                switch_cr3: u64 = 0,
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
            pub fn mapOwnedUserPageFromPhysical(_: *UserAddressSpace, _: usize, _: u64, _: UserPermissions) UserMapError!void {
                return error.OutOfMemory;
            }
            pub fn ownedUserPageIsExecutable(_: *const UserAddressSpace, _: usize) ?bool {
                return null;
            }
            pub fn destroyUserAddressSpace(_: *UserAddressSpace) UserAddressSpaceDestroyError!void {}
            pub fn checkedUserAddressSpacePhysicalRoot(space: *const UserAddressSpace) ?u64 {
                const physical = @intFromPtr(space.directory);
                if (physical == 0 or physical % PAGE_SIZE != 0) return null;
                if (space.switch_cr3 != 0 and space.switch_cr3 & x86.CR3_ADDRESS_MASK != physical) return null;
                return physical;
            }
            pub fn userAddressSpaceQuiescent(_: *const UserAddressSpace) bool {
                return true;
            }
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
    AddressSpaceLeased,
    InitialContextInvalid,
    LaunchPolicyInvalid,
};

const TrapStackStorage = *align(PAGE_SIZE) [TRAP_STACK_TOTAL_BYTES]u8;
const TrapStackSlot = struct {
    storage: ?TrapStackStorage align(64) = null,
    ready: bool = false,
    failed: bool = false,
};
var trap_stacks: [cpu_identity.MAX_CPUS]TrapStackSlot = @splat(.{});

pub const TrapStackReserveError = error{
    OutOfMemory,
    InvalidCpu,
    WrongCpu,
    InterruptContext,
    UserAddressSpaceActive,
    ActiveTrapStack,
    InvalidTrapStackGeometry,
    InvalidTrapStackMapping,
    TrapStackGuardFailure,
};

pub fn reserveTrapStackStorage() TrapStackReserveError!void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    return reserveTrapStackStorageForCpu(cpu_identity.currentIndex());
}

// Provisioning is serialized by the BSP, outside entry/interrupt execution.
// Only requested CPUs consume backing. Allocations remain retained after any
// guard failure: a span containing an unmapped page must never enter kfree.
pub fn reserveTrapStackStorageForCpu(index: u8) TrapStackReserveError!void {
    if (index >= cpu_identity.MAX_CPUS) return error.InvalidCpu;
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (!smp.isRuntimeOwner()) return error.WrongCpu;
    if (@import("../../kernel/interrupts/context.zig").active()) return error.InterruptContext;
    if (!freestanding.paging.kernelAddressSpaceActive()) return error.UserAddressSpaceActive;
    const entry = native_entry.stateForCpu(index);
    if (entry.active_task_id != 0 or entry.userspace_xstate != 0 or entry.kernel_xstate != 0 or
        entry.resume_rsp != 0 or entry.resume_rip != 0 or entry.resume_requested != 0)
        return error.ActiveTrapStack;
    const slot = &trap_stacks[index];
    if (@atomicLoad(bool, &slot.ready, .acquire)) return;
    if (slot.failed) return error.TrapStackGuardFailure;
    const allocation: struct { address: usize, bytes: usize } = if (kernel_memory.claimEarly(TRAP_STACK_TOTAL_BYTES, PAGE_SIZE)) |early|
        .{ .address = @intFromPtr(early), .bytes = TRAP_STACK_TOTAL_BYTES }
    else blk: {
        const bytes = TRAP_STACK_TOTAL_BYTES + PAGE_SIZE - 1;
        const backing = kernel_memory.kmalloc(bytes) orelse return error.OutOfMemory;
        break :blk .{ .address = @intFromPtr(backing), .bytes = bytes };
    };
    const guard = checkedTrapStackGeometry(allocation.address, allocation.bytes) orelse {
        slot.failed = true;
        return error.InvalidTrapStackGeometry;
    };
    try initializeTrapStackSlot(slot, @ptrFromInt(guard), TrapStackPaging{});
}

fn checkedTrapStackGeometry(allocation: usize, bytes: usize) ?usize {
    if (allocation == 0) return null;
    const rounded = std.math.add(usize, allocation, PAGE_SIZE - 1) catch return null;
    const guard = rounded & ~(PAGE_SIZE - 1);
    const end = std.math.add(usize, allocation, bytes) catch return null;
    const top = std.math.add(usize, guard, TRAP_STACK_TOTAL_BYTES) catch return null;
    if (top > end) return null;
    return guard;
}

const TrapStackPaging = struct {
    fn permissions(_: @This(), address: usize) struct { user: bool, writable: bool, executable: bool } {
        const page = freestanding.paging.currentPagePermissions(address) orelse return .{ .user = true, .writable = false, .executable = true };
        return .{ .user = page.user, .writable = page.writable, .executable = page.executable };
    }

    fn unmap(_: @This(), address: usize) bool {
        return freestanding.paging.unmapBorrowedCurrentPage(address);
    }

    fn guardAbsent(_: @This(), address: usize) bool {
        return freestanding.paging.currentPagePermissions(address) == null;
    }
};

fn initializeTrapStack(storage: TrapStackStorage, backend: anytype) error{ InvalidTrapStackMapping, TrapStackGuardFailure }!void {
    const guard = @intFromPtr(storage);
    var address = guard + TRAP_STACK_GUARD_BYTES;
    while (address < guard + TRAP_STACK_TOTAL_BYTES) : (address += PAGE_SIZE) {
        const permissions = backend.permissions(address);
        if (permissions.user or !permissions.writable or permissions.executable) return error.InvalidTrapStackMapping;
    }
    if (!backend.unmap(guard) or !backend.guardAbsent(guard)) return error.TrapStackGuardFailure;
    const words: []u32 = std.mem.bytesAsSlice(u32, storage[TRAP_STACK_GUARD_BYTES..]);
    @memset(words, TRAP_STACK_PAINT_PATTERN);
}

fn initializeTrapStackSlot(slot: *TrapStackSlot, storage: TrapStackStorage, backend: anytype) error{ InvalidTrapStackMapping, TrapStackGuardFailure }!void {
    slot.storage = storage;
    initializeTrapStack(storage, backend) catch |err| {
        slot.failed = true;
        return err;
    };
    @atomicStore(bool, &slot.ready, true, .release);
}

fn trapStackStorage() TrapStackStorage {
    return currentTrapStackStorage() orelse
        @call(.never_inline, executorInvariantFailure, .{.selected_cpu_trap_stack_must_be_provisioned_before_entry});
}

fn currentTrapStackStorage() ?TrapStackStorage {
    return trapStackStorageForCpu(cpu_identity.currentIndex());
}

inline fn trapStackStorageForCpu(index: u8) ?TrapStackStorage {
    if (index >= cpu_identity.MAX_CPUS) return null;
    const slot = &trap_stacks[index];
    if (!@atomicLoad(bool, &slot.ready, .acquire)) return null;
    return slot.storage orelse @call(.never_inline, executorInvariantFailure, .{.published_trap_stack_must_retain_its_backing});
}

pub inline fn preparedKernelStackForCpu(index: u8) ?usize {
    const storage = trapStackStorageForCpu(index) orelse return null;
    return @intFromPtr(storage) + TRAP_STACK_TOTAL_BYTES;
}

fn trapStackPaintableBase() usize {
    return @intFromPtr(trapStackStorage()) + TRAP_STACK_GUARD_BYTES;
}

pub fn prepareKernelStack() usize {
    if (builtin.target.os.tag != .freestanding) return 0;
    return @intFromPtr(trapStackStorage()) + TRAP_STACK_TOTAL_BYTES;
}

pub fn reportTrapStackPeak() void {
    if (builtin.target.os.tag != .freestanding) return;
    if (!@atomicLoad(bool, &trap_stacks[cpu_identity.currentIndex()].ready, .acquire)) return;
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

const PreemptCheck = *const fn (u64) bool;
var preempt_check: ?PreemptCheck = null;

pub fn setPreemptCheck(check: ?PreemptCheck) void {
    preempt_check = check;
}

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

extern fn zigos_enter_userspace(context: usize, state: usize) callconv(.c) u32;

pub fn enterPreparedUserContext(context: *const UserContext64) u32 {
    if (builtin.target.os.tag != .freestanding) return 0;
    var storage: xstate.Storage = .{};
    storage.initialize();
    defer storage.erase();
    return enterUserContextWithState(context, storage.state());
}

fn enterUserContextWithState(context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
    if (!smp.isRuntimeOwner()) @call(.never_inline, executorInvariantFailure, .{.one_runtime_cpu_owns_the_userspace_entry_state});
    const result = zigos_enter_userspace(@intFromPtr(context), @intFromPtr(state));
    requireIdleSyscallReturn();
    native_entry.clearContinuation();
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
const MAPPING_ENTRY_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding) 672 else 448;
const MAPPING_ARENA_SIZE_CEILING_BYTES: usize = if (builtin.target.os.tag == .freestanding) 96_256 else 64_512;

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
    interrupted_before_yield: bool = false,
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
const ExecutorRegistration = struct {
    executor: ?*Executor align(64) = null,
};
var executor_registrations: [cpu_identity.MAX_CPUS]ExecutorRegistration = @splat(.{});

fn currentExecutorSlot() *?*Executor {
    return &executor_registrations[cpu_identity.currentIndex()].executor;
}

inline fn registeredExecutor(cpu: u8) ?*Executor {
    if (cpu >= cpu_identity.MAX_CPUS) return null;
    return @atomicLoad(?*Executor, &executor_registrations[cpu].executor, .acquire);
}

inline fn currentRegisteredExecutor() ?*Executor {
    return registeredExecutor(cpu_identity.currentIndex());
}

inline fn bspMappingTransaction() bool {
    if (cpu_identity.currentIndex() != 0) return false;
    return if (comptime builtin.target.os.tag == .freestanding) !x86.interruptsEnabled() else true;
}

inline fn registeredDomainExecutor(cpu: u8, owner: *const anyopaque, runtime: *task_runtime.Runtime) ?*Executor {
    const source = registeredExecutor(cpu) orelse return null;
    if (source.registration_cpu != cpu or source.binding_owner != owner or source.bound_runtime != runtime) return null;
    return source;
}

inline fn executionOwnershipOutstanding(runtime: *task_runtime.Runtime) bool {
    return runtime.execution.hasLeases() or dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution);
}

fn claimCurrentExecutor(executor: *Executor) bool {
    const index = cpu_identity.currentIndex();
    const current = currentRegisteredExecutor();
    if (executor.registration_cpu) |owner| return owner == index and current == executor;
    if (current != null) return false;
    if (executor.bound_runtime) |runtime| if (executionOwnershipOutstanding(runtime)) return false;
    executor.registration_cpu = index;
    @atomicStore(?*Executor, currentExecutorSlot(), executor, .release);
    return true;
}

fn releaseCurrentExecutor(executor: *Executor) bool {
    if (executor.registration_cpu != cpu_identity.currentIndex() or currentRegisteredExecutor() != executor) return false;
    if (executor.bound_runtime) |runtime| if (executionOwnershipOutstanding(runtime)) return false;
    @atomicStore(?*Executor, currentExecutorSlot(), null, .release);
    executor.registration_cpu = null;
    return true;
}

const RetirementOwnerError = error{ WrongCpu, RegistrationMismatch };

fn requireRetirementOwner(executor: *const Executor) RetirementOwnerError!void {
    const index = cpu_identity.currentIndex();
    if (executor.registration_cpu) |owner| {
        if (registeredExecutor(owner) != executor) return error.RegistrationMismatch;
        if (owner != index and !(index == 0 and executor.binding_owner != null and executor.bound_runtime != null)) return error.WrongCpu;
    } else {
        if (index != 0) return error.WrongCpu;
        if (comptime builtin.target.os.tag == .freestanding) return error.RegistrationMismatch;
    }
    if (comptime builtin.target.os.tag == .freestanding) {
        if (!smp.isRuntimeOwner()) return error.WrongCpu;
    }
}

inline fn domainRoutesValid(owner: *const anyopaque, runtime: *task_runtime.Runtime) bool {
    if (!bspMappingTransaction()) return false;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredExecutor(@intCast(index)) orelse continue;
        if (source.binding_owner == owner and source.bound_runtime == runtime and source.registration_cpu != @as(u8, @intCast(index))) return false;
    }
    return true;
}

pub fn retireRegisteredAddressSpace(owner: *const anyopaque, runtime: *task_runtime.Runtime, event: task_runtime.AddressSpaceRetirementEvent) bool {
    if (!domainRoutesValid(owner, runtime)) return false;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredDomainExecutor(@intCast(index), owner, runtime) orelse continue;
        source.retireAddressSpaceChecked(event) catch return false;
    }
    return true;
}

pub fn collectRegisteredRetiredMappings(owner: *const anyopaque, runtime: *task_runtime.Runtime) bool {
    if (!domainRoutesValid(owner, runtime)) return false;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredDomainExecutor(@intCast(index), owner, runtime) orelse continue;
        source.collectRetiredMappings();
    }
    return true;
}

// All routes remain published throughout preflight and callback-driven mapping
// release. Only the selected BSP anchor outlives this metadata teardown.
pub fn releaseRegisteredDomain(owner: *const anyopaque, runtime: *task_runtime.Runtime) bool {
    if (!domainRoutesValid(owner, runtime) or executionOwnershipOutstanding(runtime) or runtime.lifecycle_transition_active) return false;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredDomainExecutor(@intCast(index), owner, runtime) orelse continue;
        if (source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null) return false;
        if (source.mappingArena()) |mappings| for (0..mappings.claimedCount()) |slot_index| {
            const slot = mappings.slotAt(slot_index);
            if (slot.in_use and !source.mappingRetirementReady(&slot.mapping)) return false;
        };
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredDomainExecutor(@intCast(index), owner, runtime) orelse continue;
        source.releaseAllMappings();
        if (index != 0) {
            if (!source.releaseMappingRegistration(@intCast(index), owner, runtime) or !source.releaseRuntimeBinding(owner, runtime)) unreachable;
        }
    }
    return true;
}

const LifetimeMapping = struct { cpu: u8, handle: MappingHandle };
comptime {
    if (task_runtime.MAX_TASKS > 256 or cpu_identity.MAX_CPUS > 16) @compileError("mapping lifetime namespace exceeds token geometry");
}

inline fn mappingLifetimeToken(cpu: u8, handle: MappingHandle) ?u64 {
    if (cpu >= cpu_identity.MAX_CPUS or handle.generation() == 0 or handle.slotIndex() >= task_runtime.MAX_TASKS) return null;
    return handle.value | (@as(u64, cpu) << 8);
}

inline fn decodeMappingLifetimeToken(token: u64, out: *LifetimeMapping) bool {
    if (token >> 32 == 0 or token & 0xffff_f000 != 0) return false;
    const cpu: u8 = @intCast((token >> 8) & 0xf);
    const handle = MappingHandle{ .value = token & ~@as(u64, 0xf00) };
    if (cpu >= cpu_identity.MAX_CPUS or handle.slotIndex() >= task_runtime.MAX_TASKS) return false;
    out.* = .{ .cpu = cpu, .handle = handle };
    return true;
}

inline fn continuationCleared(state: *const volatile native_entry.State) bool {
    return state.active_task_id == 0 and state.userspace_xstate == 0 and state.kernel_xstate == 0 and
        state.resume_rsp == 0 and state.resume_rip == 0 and state.resume_requested == 0;
}

inline fn requireIdleSyscallReturn() void {
    const executor = currentRegisteredExecutor() orelse return;
    const ticket = executor.active_dispatch_lease orelse return;
    if (!@constCast(ticket.issuer).syscallIdle(ticket))
        @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
}

const RemoteSyscallHardware = struct {
    inline fn mask(_: @This()) bool {
        const enabled = x86.interruptsEnabled();
        x86.cli();
        return enabled;
    }
    inline fn restore(_: @This(), enabled: bool) void {
        if (enabled) x86.sti();
    }
    inline fn switchToKernel(_: @This()) void {
        freestanding.paging.switchToKernelAddressSpace();
    }
    inline fn kernelActive(_: @This()) bool {
        return freestanding.paging.kernelAddressSpaceActive();
    }
    inline fn restoreUser(_: @This(), mapping: *MappingEntry) void {
        freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());
    }
    inline fn notify(_: @This()) bool {
        return smp.notifySyscallRequest();
    }
    inline fn wait(_: @This()) void {
        // Caller tested completion with IF clear. STI's interrupt shadow makes
        // this HLT atomic with respect to the completion nudge; nested kernel
        // gates preserve the parked frame/xstate and only service architecture.
        x86.stiHlt();
        x86.cli();
    }
    fn fail(_: @This()) noreturn {
        x86.cli();
        while (true) x86.hlt();
    }
};

pub fn remoteSyscall(frame: *freestanding.isr.InterruptFrame) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    return remoteSyscallWithHardware(frame, RemoteSyscallHardware{});
}

// This owner path never reads Runtime/Kernel/Table records. The exact running
// receipt pins its local Mapping and native continuation until BSP completion
// is consumed (or pending work is cancelled) and the mailbox is idle again.
fn remoteSyscallWithHardware(frame: *freestanding.isr.InterruptFrame, hardware: anytype) bool {
    const previous_if = hardware.mask();
    defer hardware.restore(previous_if);
    if (previous_if or smp.isRuntimeOwner() or (frame.cs & 3) != 3) return false;
    const executor = currentRegisteredExecutor() orelse return false;
    const ticket = executor.active_dispatch_lease orelse return false;
    if (executor.registration_cpu != cpu_identity.currentIndex() or ticket.cpu != cpu_identity.currentIndex() or
        executor.bound_runtime == null or ticket.issuer != &executor.bound_runtime.?.execution) return false;
    const execution = @constCast(ticket.issuer);
    var bound: dispatch_ownership.BoundIdentity = undefined;
    execution.boundIdentityInto(ticket, &bound) catch return false;
    const mapping = activeUserMemoryMapping(executor, bound.identity.task_id) orelse return false;
    if (executor.active_mapping_handle.value != bound.mapping_handle or mapping.address_space_id != bound.identity.address_space_id or
        mappingPhysicalRoot(mapping) != bound.physical_root or mapping.owned_xstate == null) return false;
    const entry = native_entry.current();
    if (entry.active_task_id != bound.identity.task_id or entry.userspace_xstate != @intFromPtr(mapping.owned_xstate.?.state()) or
        entry.kernel_xstate == 0 or entry.resume_rsp == 0 or entry.resume_rip == 0 or entry.resume_requested != 0 or
        !execution.syscallIdle(ticket)) return false;

    hardware.switchToKernel();
    if (!hardware.kernelActive()) hardware.fail();
    var key: dispatch_ownership.RequestKey = undefined;
    execution.submitSyscallInto(ticket, .{
        .opcode = @truncate(frame.eax),
        .request_addr = frame.edi,
        .response_addr = frame.esi,
        .response_len = frame.edx,
    }, &key) catch |err| {
        if (err != error.StopRequested) hardware.fail();
        if (!execution.syscallIdle(ticket)) hardware.fail();
        handoffInterruptedUser(executor, mapping, frame);
        return true;
    };
    if (!hardware.notify()) hardware.fail();
    var reply: dispatch_ownership.Reply = undefined;
    var cancelled = false;
    while (true) {
        if (execution.stopRequested(ticket) and execution.cancelPendingSyscall(key)) {
            cancelled = true;
            break;
        }
        if (execution.consumeSyscallInto(key, &reply)) |_| {
            break;
        } else |err| {
            if (err != error.NotReady) hardware.fail();
        }
        hardware.wait();
    }
    if (!execution.syscallIdle(ticket) or !hardware.kernelActive()) hardware.fail();
    if (!cancelled) {
        frame.eax = reply.status;
        frame.edx = reply.bytes_written;
        frame.r10 = reply.denial_reason;
    }
    // A kernel-origin STOP interrupt only acknowledges the APIC. Decide using
    // the exact lease here, before SYSRET/ERETU can resume the original user.
    if (execution.stopRequested(ticket)) {
        handoffInterruptedUser(executor, mapping, frame);
    } else {
        hardware.restoreUser(mapping);
    }
    return true;
}

fn activeUserMemoryMapping(executor: *Executor, caller_task_id: u64) ?*MappingEntry {
    if (caller_task_id == 0 or executor.active_task_id != caller_task_id) return null;
    const mapping = executor.active_mapping orelse return null;
    const mappings = executor.mappingArena() orelse return null;
    const slot = mappings.getByHandle(executor.active_mapping_handle) orelse return null;
    if (&slot.mapping != mapping) return null;
    if (mapping.state != .live or mapping.dispatch_metadata.owner_task_id != caller_task_id or mapping.address_space == null) return null;
    return mapping;
}

// Shared Table and demand registrations belong to the BSP. Keep admission,
// page preparation and the immediate physical-alias copy in one nonreentrant
// interval; this authority must not survive a callback, yield or IRQ enable.
fn serializedSharedMemoryExecutor(interrupts_enabled: bool) ?*Executor {
    if (interrupts_enabled or !smp.isRuntimeOwner()) return null;
    const executor = currentRegisteredExecutor() orelse return null;
    if (executor.registration_cpu != cpu_identity.currentIndex()) return null;
    return executor;
}

fn sharedUserAddress(addr: usize) bool {
    return addr >= userspace_layout.shared_start and addr < userspace_layout.shared_end_exclusive;
}

const SharedUserMemory = struct {
    space: *freestanding.paging.UserAddressSpace,
    authority: demand_paging.SharedCopyAuthority,
};

fn sharedUserMemoryAuthority(executor: *Executor, caller_task_id: u64, addr: usize, len: usize, write: bool) ?SharedUserMemory {
    if (!sharedUserAddress(addr)) return null;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return null;
    return sharedMappingAuthority(executor, mapping, executor.active_mapping_handle, caller_task_id, addr, len, write);
}

fn sharedMappingAuthority(executor: *Executor, mapping: *MappingEntry, handle: MappingHandle, caller_task_id: u64, addr: usize, len: usize, write: bool) ?SharedUserMemory {
    const table = executor.mapped_object_table orelse return null;
    if (executor.mapped_object_count == 0) return null;
    var span: shared_memory.TaskCopySpan = undefined;
    table.taskCopySpanInto(@import("../core/ids.zig").task(caller_task_id), mappingLifetimeToken(executor.registration_cpu orelse 0, handle) orelse return null, addr, len, &span) catch return null;
    const authority = demand_paging.SharedCopyAuthority{
        .virtual_base = span.virtual_base,
        .physical_base = span.physical_base,
        .size_bytes = span.size_bytes,
    };
    const space = &mapping.address_space.?;
    if (!demand_paging.validateSharedUserRangeRegistration(space, authority, addr, len, write, 0)) return null;
    return .{ .space = space, .authority = authority };
}

inline fn mappingPhysicalRoot(mapping: *const MappingEntry) u64 {
    const space = mapping.address_space orelse return 0;
    return if (comptime builtin.target.os.tag == .freestanding)
        space.switch_cr3 & x86.CR3_ADDRESS_MASK
    else if (space.switch_cr3 != 0) space.switch_cr3 & x86.CR3_ADDRESS_MASK else @intFromPtr(space.directory);
}

// A processing mailbox keeps this exact lease alive. Resolve every callback
// against that receipt again; no current-BSP active-task substitution and no
// reusable user alias survives a copy, service callback or IRQ enable.
const SyscallCopyMapping = struct { executor: *Executor, mapping: *MappingEntry };

fn syscallCopyMappingInto(executor: *Executor, claim: *const dispatch_ownership.ClaimedSyscall, interrupts_enabled: bool, kernel_root_active: bool, out: *SyscallCopyMapping) bool {
    if (interrupts_enabled or !kernel_root_active or !bspMappingTransaction() or
        executor.registration_cpu != 0 or currentRegisteredExecutor() != executor) return false;
    const runtime = executor.bound_runtime orelse return false;
    const owner = executor.binding_owner orelse return false;
    if (claim.key.ticket.issuer != &runtime.execution) return false;
    var bound: dispatch_ownership.BoundIdentity = undefined;
    var stopped: bool = undefined;
    runtime.execution.validateClaimInto(claim, &bound, &stopped) catch return false;
    if (stopped) return false;
    const task = runtime.findConstByHandle(.{ .value = bound.identity.task_handle }, bound.identity.task_id) orelse return false;
    const borrow = runtime.execution_borrows[claim.key.ticket.cpu] orelse return false;
    if (task.state != .active or task.process_generation != bound.identity.process_generation or
        task.address_space_id != bound.identity.address_space_id or borrow.runtime != runtime or
        borrow.task_id != task.id or borrow.handle.value != bound.identity.task_handle) return false;
    const source = registeredDomainExecutor(claim.key.ticket.cpu, owner, runtime) orelse return false;
    const mappings = source.mappingArena() orelse return false;
    const slot = mappings.getByHandle(.{ .value = bound.mapping_handle }) orelse return false;
    const mapping = &slot.mapping;
    if (mapping.state != .live or mapping.address_space_id != bound.identity.address_space_id or
        mapping.dispatch_metadata.owner_task_id != bound.identity.task_id or mapping.address_space == null or
        mappingPhysicalRoot(mapping) != bound.physical_root or
        freestanding.paging.checkedUserAddressSpacePhysicalRoot(&mapping.address_space.?) != bound.physical_root) return false;
    out.* = .{ .executor = source, .mapping = mapping };
    return true;
}

fn readSyscallCopy(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, addr: usize, destination: []u8) bool {
    const executor: *Executor = @ptrCast(@alignCast(context));
    const interrupts_enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    const kernel_active = if (comptime builtin.target.os.tag == .freestanding) freestanding.paging.kernelAddressSpaceActive() else true;
    var resolved: SyscallCopyMapping = undefined;
    if (!syscallCopyMappingInto(executor, claim, interrupts_enabled, kernel_active, &resolved)) return false;
    const source = resolved.executor;
    const mapping = resolved.mapping;
    if (sharedUserAddress(addr)) {
        const memory = sharedMappingAuthority(source, mapping, .{ .value = claim.bound.mapping_handle }, claim.bound.identity.task_id, addr, destination.len, false) orelse return false;
        if (comptime builtin.target.os.tag != .freestanding) {
            return if (builtin.is_test) SyscallCopyTesting.read(memory.space, addr, destination) else false;
        }
        const alias = demand_paging.prepareSharedUserRange(memory.space, memory.authority, addr, destination.len, false, 0) orelse return false;
        @memcpy(destination, @as([*]const u8, @ptrFromInt(alias))[0..destination.len]);
        return true;
    }
    const runtime = executor.bound_runtime.?;
    const record = runtime.findAddressSpaceConst(claim.bound.identity.address_space_id) orelse return false;
    if (record.owner_task_id != claim.bound.identity.task_id or record.region_count == 0) return false;
    const memory = syscall_dispatch.UserMemoryContext{ .address_space = record, .caller_task_id = claim.bound.identity.task_id };
    if (!syscall_dispatch.validateUserRange(memory, addr, destination.len, 1, .read)) return false;
    const space = &mapping.address_space.?;
    if (comptime builtin.target.os.tag != .freestanding) {
        return if (builtin.is_test) SyscallCopyTesting.read(space, addr, destination) else false;
    }
    if (!demand_paging.prepareUserRange(space, addr, destination.len, false)) return false;
    freestanding.paging.readOwnedUserRange(space, addr, destination) catch return false;
    return true;
}

inline fn outputRangeGeometry(range: syscall_broker.OutputRange) bool {
    if (range.prepared_bytes > range.declared_bytes or range.prepared_bytes > 88) return false;
    if (range.declared_bytes == 0) return true;
    if (range.alignment == 0 or !std.math.isPowerOfTwo(range.alignment) or
        range.address < 0x10000 or range.address % range.alignment != 0) return false;
    const end = std.math.add(usize, range.address, range.declared_bytes) catch return false;
    return end <= 0x0000_8000_0000_0000;
}

inline fn privateCopyMetadata(executor: *Executor, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, bytes: usize) bool {
    const runtime = executor.bound_runtime orelse return false;
    const record = runtime.findAddressSpaceConst(claim.bound.identity.address_space_id) orelse return false;
    if (record.owner_task_id != claim.bound.identity.task_id or record.region_count == 0) return false;
    return syscall_dispatch.validateUserRange(.{ .address_space = record, .caller_task_id = claim.bound.identity.task_id }, address, bytes, 1, .write);
}

fn prepareSyscallOutput(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, range: syscall_broker.OutputRange) bool {
    const anchor: *Executor = @ptrCast(@alignCast(context));
    const enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    const kernel_active = if (comptime builtin.target.os.tag == .freestanding) freestanding.paging.kernelAddressSpaceActive() else true;
    var resolved: SyscallCopyMapping = undefined;
    if (!syscallCopyMappingInto(anchor, claim, enabled, kernel_active, &resolved) or !outputRangeGeometry(range)) return false;
    if (range.declared_bytes == 0) return true;
    const space = &resolved.mapping.address_space.?;
    if (sharedUserAddress(range.address)) {
        const memory = sharedMappingAuthority(resolved.executor, resolved.mapping, .{ .value = claim.bound.mapping_handle }, claim.bound.identity.task_id, range.address, range.declared_bytes, true) orelse return false;
        if (range.prepared_bytes == 0) return true;
        if (comptime builtin.target.os.tag == .freestanding)
            return demand_paging.prepareSharedUserRange(memory.space, memory.authority, range.address, range.prepared_bytes, true, 0) != null;
    } else {
        if (!privateCopyMetadata(anchor, claim, range.address, range.declared_bytes)) return false;
        if (range.prepared_bytes == 0) return true;
        if (comptime builtin.target.os.tag == .freestanding)
            return demand_paging.prepareUserRange(space, range.address, range.prepared_bytes, true);
    }
    return if (builtin.is_test) SyscallCopyTesting.prepare(space, range.address, range.prepared_bytes) else false;
}

fn resolveSyscallOutputInto(anchor: *Executor, resolved: *const SyscallCopyMapping, claim: *const dispatch_ownership.ClaimedSyscall, address: usize, bytes: usize, out: *[2]freestanding.paging.WritableUserSegment, count: *u8) bool {
    const space = &resolved.mapping.address_space.?;
    if (sharedUserAddress(address)) {
        const memory = sharedMappingAuthority(resolved.executor, resolved.mapping, .{ .value = claim.bound.mapping_handle }, claim.bound.identity.task_id, address, bytes, true) orelse return false;
        if (comptime builtin.target.os.tag == .freestanding) {
            const alias = demand_paging.prepareSharedUserRange(memory.space, memory.authority, address, bytes, true, 0) orelse return false;
            out[0] = .{ .address = alias, .bytes = bytes };
            count.* = 1;
            return true;
        }
    } else {
        if (!privateCopyMetadata(anchor, claim, address, bytes)) return false;
        if (comptime builtin.target.os.tag == .freestanding)
            return freestanding.paging.resolveOwnedUserOutputInto(space, address, bytes, out, count);
    }
    return if (builtin.is_test) SyscallCopyTesting.resolveInto(space, address, bytes, out, count) else false;
}

inline fn byteRangesOverlap(first: usize, first_len: usize, second: usize, second_len: usize) bool {
    return first < second + second_len and second < first + first_len;
}

fn writeSyscallOutputs(context: *anyopaque, claim: *const dispatch_ownership.ClaimedSyscall, outputs: []const syscall_broker.Output) bool {
    const anchor: *Executor = @ptrCast(@alignCast(context));
    const enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    const kernel_active = if (comptime builtin.target.os.tag == .freestanding) freestanding.paging.kernelAddressSpaceActive() else true;
    var resolved: SyscallCopyMapping = undefined;
    if (!syscallCopyMappingInto(anchor, claim, enabled, kernel_active, &resolved) or outputs.len > syscall_broker.MAX_OUTPUTS) return false;
    var total: usize = 0;
    // Reject all geometry before even preparing a shared absent leaf.
    for (outputs, 0..) |output, index| {
        if (!outputRangeGeometry(.{ .address = output.address, .declared_bytes = output.bytes.len, .prepared_bytes = output.bytes.len, .alignment = 1 })) return false;
        total += output.bytes.len;
        if (total > syscall_broker.MAX_OUTPUT_BYTES) return false;
        if (output.bytes.len == 0) continue;
        for (outputs[0..index]) |previous| {
            if (previous.bytes.len != 0 and byteRangesOverlap(output.address, output.bytes.len, previous.address, previous.bytes.len)) return false;
        }
    }
    const Commit = struct { address: usize, bytes: []const u8 };
    var commits: [2 * syscall_broker.MAX_OUTPUTS]Commit = undefined;
    var count: usize = 0;
    for (outputs) |output| {
        if (output.bytes.len == 0) continue;
        var segments: [2]freestanding.paging.WritableUserSegment = undefined;
        var segment_count: u8 = undefined;
        if (!resolveSyscallOutputInto(anchor, &resolved, claim, output.address, output.bytes.len, &segments, &segment_count)) return false;
        var offset: usize = 0;
        for (segments[0..segment_count]) |segment| {
            for (commits[0..count]) |previous| {
                if (byteRangesOverlap(segment.address, segment.bytes, previous.address, previous.bytes.len)) return false;
            }
            commits[count] = .{ .address = segment.address, .bytes = output.bytes[offset..][0..segment.bytes] };
            count += 1;
            offset += segment.bytes;
        }
    }
    // Reauthenticate after every destination is resolved, then perform only
    // local copies. No callbacks, allocation, yield or IRQ enable follows.
    var final: SyscallCopyMapping = undefined;
    const final_enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    const final_kernel_active = if (comptime builtin.target.os.tag == .freestanding) freestanding.paging.kernelAddressSpaceActive() else true;
    if (!syscallCopyMappingInto(anchor, claim, final_enabled, final_kernel_active, &final) or
        final.executor != resolved.executor or final.mapping != resolved.mapping) return false;
    for (commits[0..count]) |commit| @memcpy(@as([*]u8, @ptrFromInt(commit.address))[0..commit.bytes.len], commit.bytes);
    return true;
}

// Hosted page storage substitutes only privileged page preparation/aliases. The public
// session callback still performs real key/lease/Runtime/Mapping/Table admission
// first; native builds retain the actual checked demand and page-walk readers.
const SyscallCopyTesting = if (builtin.is_test) struct {
    const Pages = struct {
        directory: *freestanding.paging.PageDirectory,
        virtual_base: usize,
        bytes: []u8,
        readable: bool = true,
        writable: bool = true,
        invalid_page: ?usize = null,
        forced_alias_offset: ?usize = null,
        before_resolve: ?*const fn () void = null,
        reads: usize = 0,
        preparations: usize = 0,
    };
    var pages: ?*Pages = null;

    fn read(space: *const freestanding.paging.UserAddressSpace, address: usize, destination: []u8) bool {
        const storage = pages orelse return false;
        if (!storage.readable or space.directory != storage.directory or address < storage.virtual_base) return false;
        const offset = address - storage.virtual_base;
        if (offset > storage.bytes.len or destination.len > storage.bytes.len - offset) return false;
        storage.reads += 1;
        @memcpy(destination, storage.bytes[offset..][0..destination.len]);
        return true;
    }

    fn prepare(space: *const freestanding.paging.UserAddressSpace, address: usize, bytes: usize) bool {
        var segments: [2]freestanding.paging.WritableUserSegment = undefined;
        var count: u8 = undefined;
        if (!resolveInto(space, address, bytes, &segments, &count)) return false;
        pages.?.preparations += 1;
        return true;
    }

    fn resolveInto(space: *const freestanding.paging.UserAddressSpace, address: usize, bytes: usize, out: *[2]freestanding.paging.WritableUserSegment, count_out: *u8) bool {
        const storage = pages orelse return false;
        if (storage.before_resolve) |callback| callback();
        if (!storage.writable or space.directory != storage.directory or address < storage.virtual_base) return false;
        const offset = address - storage.virtual_base;
        if (bytes == 0 or bytes > 88 or offset > storage.bytes.len or bytes > storage.bytes.len - offset) return false;
        if (storage.invalid_page) |page| {
            if (offset / PAGE_SIZE <= page and (offset + bytes - 1) / PAGE_SIZE >= page) return false;
        }
        const first = @min(bytes, PAGE_SIZE - address % PAGE_SIZE);
        const alias_offset = storage.forced_alias_offset orelse offset;
        if (alias_offset > storage.bytes.len or bytes > storage.bytes.len - alias_offset) return false;
        out[0] = .{ .address = @intFromPtr(storage.bytes.ptr) + alias_offset, .bytes = first };
        if (first < bytes) out[1] = .{ .address = @intFromPtr(storage.bytes.ptr) + alias_offset + first, .bytes = bytes - first };
        count_out.* = if (first < bytes) 2 else 1;
        return true;
    }
} else struct {};

pub fn validateSharedUserMemory(caller_task_id: u64, addr: usize, len: usize, write: bool) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    const executor = serializedSharedMemoryExecutor(x86.interruptsEnabled()) orelse return false;
    return sharedUserMemoryAuthority(executor, caller_task_id, addr, len, write) != null;
}

pub fn prepareUserMemory(caller_task_id: u64, addr: usize, len: usize, write: bool) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (sharedUserAddress(addr)) {
        const executor = serializedSharedMemoryExecutor(x86.interruptsEnabled()) orelse return false;
        const memory = sharedUserMemoryAuthority(executor, caller_task_id, addr, len, write) orelse return false;
        return demand_paging.prepareSharedUserRange(memory.space, memory.authority, addr, len, write, 0) != null;
    }
    const executor = currentRegisteredExecutor() orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    return demand_paging.prepareUserRange(&mapping.address_space.?, addr, len, write);
}

pub fn readUserMemory(caller_task_id: u64, addr: usize, destination: []u8) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (sharedUserAddress(addr)) {
        const executor = serializedSharedMemoryExecutor(x86.interruptsEnabled()) orelse return false;
        const memory = sharedUserMemoryAuthority(executor, caller_task_id, addr, destination.len, false) orelse return false;
        const alias = demand_paging.prepareSharedUserRange(memory.space, memory.authority, addr, destination.len, false, 0) orelse return false;
        const source: [*]const u8 = @ptrFromInt(alias);
        @memcpy(destination, source[0..destination.len]);
        return true;
    }
    const executor = currentRegisteredExecutor() orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    const space = &mapping.address_space.?;
    if (!demand_paging.prepareUserRange(space, addr, destination.len, false)) return false;
    freestanding.paging.readOwnedUserRange(space, addr, destination) catch return false;
    return true;
}

pub fn writeUserMemory(caller_task_id: u64, addr: usize, source: []const u8) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (sharedUserAddress(addr)) {
        const executor = serializedSharedMemoryExecutor(x86.interruptsEnabled()) orelse return false;
        const memory = sharedUserMemoryAuthority(executor, caller_task_id, addr, source.len, true) orelse return false;
        const alias = demand_paging.prepareSharedUserRange(memory.space, memory.authority, addr, source.len, true, 0) orelse return false;
        const destination: [*]u8 = @ptrFromInt(alias);
        @memcpy(destination[0..source.len], source);
        return true;
    }
    const executor = currentRegisteredExecutor() orelse return false;
    const mapping = activeUserMemoryMapping(executor, caller_task_id) orelse return false;
    const space = &mapping.address_space.?;
    if (!demand_paging.prepareUserRange(space, addr, source.len, true)) return false;
    freestanding.paging.writeOwnedUserRange(space, addr, source) catch return false;
    return true;
}

// Called only by the isolated privileged architecture image. This constructs
// real executor lifetime registrations and uses the freestanding syscall-copy
// helpers and endpoint handlers. It supplies no evidence of native user traps,
// opcode dispatch, wake callbacks or execution of a userspace image.
pub fn proveSharedSyscallCopyPath() bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (comptime !@hasDecl(root, "ARCHITECTURE_SMP_PROOF")) @compileError("shared-copy proof requires the isolated architecture image");
    if (comptime !root.ARCHITECTURE_SMP_PROOF) @compileError("shared-copy proof requires the isolated architecture image");
    const ids = @import("../core/ids.zig");
    const abi = @import("../core/abi.zig");
    const dispatch = @import("../kernel_api/syscall_dispatch.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const endpoint_syscalls = @import("../kernel_api/endpoint_syscalls.zig");
    const component_port = @import("../kernel_api/component_port.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const page_table = @import("../../kernel/memory/page_table64.zig");
    // Keep every helper inside this guarded entry: the production image must
    // not retain fixture metadata or another callable proof namespace.
    const Fixture = struct {
        const request_offset = 0;
        const capability_offset = 256;
        const response_offset = 512;
        const payload_offset = PAGE_SIZE - 16;
        const payload_bytes = 32;
        const Negative = enum {
            padding,
            foreign_response,
            foreign_payload,
            short_response,
            short_payload,
            primary_payload,
            primary_capability,
            payload_capability,
            advertised_tail,
            forged_late_leaf,
        };

        executor: *Executor,
        mappings: *MappingArena,
        handles: [2]MappingHandle,
        tasks: [2]*task_runtime.TaskRecord,
        capabilities: *capability.CapabilityTable,
        endpoints: *endpoint.Table,
        port: *component_port.KernelPort,
        aliases: [2]usize,
        object: shared_memory.Object,
        backing: []u8,
        saved: *[2 * PAGE_SIZE]u8,
        source: ids.EndpointId,
        destination: ids.EndpointId,
        sending_id: u64,
        receiving_id: u64,
        gift_id: u64,

        fn fail(message: []const u8) bool {
            common.printBootMarker(message);
            return false;
        }

        fn select(self: *@This(), index: usize) dispatch.UserMemoryContext {
            self.executor.active_task_id = self.tasks[index].id;
            self.executor.active_mapping_handle = self.handles[index];
            self.executor.active_mapping = &self.mappings.getByHandle(self.handles[index]).?.mapping;
            self.port.syscall_caller_task_id = self.tasks[index].id;
            return dispatch.UserMemoryContext.init(self.port, self.tasks[index].id);
        }

        fn leafSlot(self: *@This(), address: usize) ?*page_table.Entry {
            var table: *page_table.Table = self.executor.active_mapping.?.address_space.?.directory;
            for ([_]u6{ page_table.PML4_SHIFT, page_table.PDPT_SHIFT, page_table.PAGE_DIRECTORY_SHIFT }) |shift| {
                const entry = @atomicLoad(page_table.Entry, &table[page_table.index(address, shift)], .acquire);
                const required = page_table.PRESENT | page_table.USER | page_table.WRITABLE;
                if (entry & required != required or page_table.isLargePage(entry)) return null;
                const alias = freestanding.paging.mappedRamSpan(page_table.address(entry), PAGE_SIZE) orelse return null;
                table = @ptrFromInt(alias);
            }
            return &table[page_table.index(address, page_table.PAGE_TABLE_SHIFT)];
        }

        fn receiveRequest(self: *@This()) abi.EndpointRecvWireRequest {
            return .{
                .header = component_port.makeHeader(.endpoint_recv, self.tasks[1].id),
                .endpoint_capability_id = self.receiving_id,
                .receiver_task_id = self.tasks[1].id,
                .payload_address = self.aliases[1] + payload_offset,
                .payload_capacity = payload_bytes,
                .attached_capability_address = self.aliases[1] + capability_offset,
            };
        }

        fn rejectReceive(self: *@This(), which: Negative) bool {
            const memory = self.select(1);
            defer self.port.syscall_caller_task_id = 0;
            @memset(self.backing, 0xa5);
            var request = self.receiveRequest();
            var response = self.aliases[1] + response_offset;
            var response_len: usize = @sizeOf(abi.EndpointRecvResponse);
            switch (which) {
                .padding => response_len = self.object.size_bytes - response_offset + 1,
                .foreign_response => response = self.aliases[0] + response_offset,
                .foreign_payload => request.payload_address = self.aliases[0] + payload_offset,
                .short_response => response_len -= 1,
                .short_payload => request.payload_capacity -= 1,
                .primary_payload => request.payload_address = response + 8,
                .primary_capability => request.attached_capability_address = response,
                .payload_capability => {
                    request.payload_address = self.aliases[1] + capability_offset;
                    request.attached_capability_address = self.aliases[1] + capability_offset;
                },
                .advertised_tail => {
                    response_len = 128;
                    request.payload_address = response + 64;
                },
                .forged_late_leaf => {},
            }
            if (!dispatch.writeUserValue(memory, self.aliases[1] + request_offset, request)) return false;
            @memcpy(self.saved, self.backing);
            const queued = self.endpoints.descriptor(self.destination) catch return false;
            const gift = self.capabilities.query(self.gift_id) orelse return false;
            const grant_count = self.capabilities.activeCount();
            const grant_generation = self.capabilities.mutationGeneration();
            var attachments: [2][task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(@splat(0));
            const generations = [_]u64{ self.tasks[0].capabilityGeneration(), self.tasks[1].capabilityGeneration() };
            const counts = [_]u8{ self.tasks[0].capability_count, self.tasks[1].capability_count };
            for (self.tasks, &attachments) |task, *out| @memcpy(out[0..task.capability_count], task.capabilityIds());
            if (queued.queued_messages != 1 or self.tasks[0].hasCapability(self.gift_id) or
                self.tasks[1].hasCapability(self.gift_id) or !self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id)) or
                self.endpoints.hasPendingForTask(ids.task(self.tasks[0].id))) return false;

            // This root is inactive: the deliberate physical forgery is never
            // used by hardware, and exact restoration precedes any next case.
            var forged_slot: ?*page_table.Entry = null;
            var original: page_table.Entry = 0;
            var forged: page_table.Entry = 0;
            if (which == .forged_late_leaf) {
                forged_slot = self.leafSlot(self.aliases[1] + PAGE_SIZE) orelse return false;
                original = @atomicLoad(page_table.Entry, forged_slot.?, .acquire);
                if (!page_table.isPresent(original) or page_table.address(original) != self.object.page_base + PAGE_SIZE) return false;
                forged = (original ^ @as(u64, @intCast(page_table.address(original)))) | self.object.page_base;
                @atomicStore(page_table.Entry, forged_slot.?, forged, .release);
            }
            defer if (forged_slot) |slot| @atomicStore(page_table.Entry, slot, original, .release);
            const result = endpoint_syscalls.dispatchEndpointRecv(self.port, memory, 12, self.aliases[1] + request_offset, response, response_len);
            const expected = if (which == .short_response or which == .short_payload)
                abi.SyscallStatus.buffer_too_small
            else
                abi.SyscallStatus.invalid_response_buffer;
            if (result.status != expected or result.bytes_written != 0 or
                !std.mem.eql(u8, self.saved, self.backing) or self.capabilities.activeCount() != grant_count or
                self.capabilities.mutationGeneration() != grant_generation or
                !std.meta.eql(queued, self.endpoints.descriptor(self.destination) catch return false) or
                !std.meta.eql(gift, self.capabilities.query(self.gift_id) orelse return false) or
                !self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id)) or
                self.endpoints.hasPendingForTask(ids.task(self.tasks[0].id))) return false;
            for (self.tasks, attachments, generations, counts) |task, before, generation, count| {
                if (task.capability_count != count or task.capabilityGeneration() != generation or
                    !std.mem.eql(u64, task.capabilityIds(), before[0..count])) return false;
            }
            if (forged_slot) |slot| if (@atomicLoad(page_table.Entry, slot, .acquire) != forged) return false;
            // Preparation can materialize valid pages before rejecting output
            // overlap. Queue/authority/payload preservation does not promise
            // rollback of that retained page-table progress.
            return true;
        }

        fn endpointFlow(self: *@This()) bool {
            const sender_memory = self.select(0);
            const payload_address = self.aliases[0] + payload_offset;
            var payload: [payload_bytes]u8 = undefined;
            for (&payload, 0..) |*byte, index| byte.* = @intCast(0x40 + index * 3);
            if (!dispatch.writeUserValue(sender_memory, payload_address, payload)) return fail("shared endpoint source payload");
            const request = abi.EndpointSendWireRequest{
                .header = component_port.makeHeader(.endpoint_send, self.tasks[0].id),
                .endpoint_capability_id = self.sending_id,
                .correlation_id = 91,
                .payload_address = payload_address,
                .payload_bytes = payload.len,
                .attached_capability_id = self.gift_id,
                .flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT,
            };
            if (!dispatch.writeUserValue(sender_memory, self.aliases[0] + request_offset, request)) return fail("shared endpoint send request");
            const sent = endpoint_syscalls.dispatchEndpointSend(self.port, sender_memory, 11, self.aliases[0] + request_offset, 0, 0);
            self.port.syscall_caller_task_id = 0;
            if (sent.status != .success or sent.bytes_written != 0 or
                self.tasks[0].hasCapability(self.gift_id) or self.capabilities.query(self.gift_id) == null or
                (self.endpoints.descriptor(self.destination) catch return false).queued_messages != 1 or
                !self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id))) return fail("shared endpoint moved publication");
            const overwritten: [payload_bytes]u8 = @splat(0xee);
            if (!dispatch.writeUserValue(sender_memory, payload_address, overwritten)) return fail("shared endpoint source reuse");
            for (std.enums.values(Negative)) |which| {
                if (!self.rejectReceive(which)) {
                    common.printBootMarker(@tagName(which));
                    return fail("shared endpoint rejected output preservation");
                }
            }

            const memory = self.select(1);
            defer self.port.syscall_caller_task_id = 0;
            @memset(self.backing, 0xa5);
            if (!dispatch.writeUserValue(memory, self.aliases[1] + request_offset, self.receiveRequest())) return fail("shared endpoint receive request");
            @memcpy(self.saved, self.backing);
            const grants_before = self.capabilities.activeCount();
            const receiver_grants = self.tasks[1].capability_count;
            const received = endpoint_syscalls.dispatchEndpointRecv(self.port, memory, 13, self.aliases[1] + request_offset, self.aliases[1] + response_offset, @sizeOf(abi.EndpointRecvResponse));
            const response = dispatch.readUserValue(abi.EndpointRecvResponse, memory, self.aliases[1] + response_offset) orelse return false;
            const attached = dispatch.readUserValue(abi.CapabilityDescriptor, memory, self.aliases[1] + capability_offset) orelse return false;
            const copied = dispatch.readUserValue([payload_bytes]u8, memory, self.aliases[1] + payload_offset) orelse return false;
            const transferred = self.capabilities.query(attached.capability_id) orelse return false;
            if (received.status != .success or received.bytes_written != @sizeOf(abi.EndpointRecvResponse) or
                response.present != 1 or response.has_attached_capability != 1 or response.message.payload_len != payload.len or
                response.message.endpoint_id != self.destination.raw() or response.message.sender_endpoint_id != self.source.raw() or
                response.message.sender_task_id != self.tasks[0].id or response.message.correlation_id != 91 or
                response.message.attached_capability_id != self.gift_id or !std.mem.eql(u8, &copied, &payload) or
                attached.capability_id == self.gift_id or attached.scope_task_id != self.tasks[1].id or attached.target_id != 900 or
                !transferred.holder.eql(self.tasks[1].owner) or transferred.scope.task_id != self.tasks[1].id or
                !transferred.scope.local_only or !transferred.rights.has(.time_query) or !transferred.rights.has(.capability_pass) or
                self.capabilities.query(self.gift_id) != null or !self.tasks[1].hasCapability(attached.capability_id) or
                self.tasks[0].hasCapability(attached.capability_id) or self.tasks[1].capability_count != receiver_grants + 1 or
                self.capabilities.activeCount() != grants_before or
                (self.endpoints.descriptor(self.destination) catch return false).queued_messages != 0 or
                self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id))) return fail("shared endpoint consume and retarget");
            @memcpy(self.saved[payload_offset..][0..payload.len], &payload);
            @memcpy(self.saved[capability_offset..][0..@sizeOf(abi.CapabilityDescriptor)], std.mem.asBytes(&attached));
            @memcpy(self.saved[response_offset..][0..@sizeOf(abi.EndpointRecvResponse)], std.mem.asBytes(&response));
            if (!std.mem.eql(u8, self.saved, self.backing)) return fail("shared endpoint exact output publication");
            const generation = self.tasks[1].capabilityGeneration();
            const sender_generation = self.tasks[0].capabilityGeneration();
            const grant_generation = self.capabilities.mutationGeneration();
            const empty = endpoint_syscalls.dispatchEndpointRecv(self.port, memory, 14, self.aliases[1] + request_offset, self.aliases[1] + response_offset, @sizeOf(abi.EndpointRecvResponse));
            const empty_response = dispatch.readUserValue(abi.EndpointRecvResponse, memory, self.aliases[1] + response_offset) orelse return false;
            if (empty.status != .success or empty.bytes_written != @sizeOf(abi.EndpointRecvResponse) or
                !std.meta.eql(empty_response, std.mem.zeroes(abi.EndpointRecvResponse)) or
                self.capabilities.activeCount() != grants_before or self.tasks[1].capability_count != receiver_grants + 1 or
                self.capabilities.mutationGeneration() != grant_generation or
                !std.meta.eql(transferred, self.capabilities.query(attached.capability_id) orelse return false) or
                self.tasks[0].capabilityGeneration() != sender_generation or self.tasks[1].capabilityGeneration() != generation or
                self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id)))
                return fail("shared endpoint empty retry");
            @memcpy(self.saved[response_offset..][0..@sizeOf(abi.EndpointRecvResponse)], std.mem.asBytes(&empty_response));
            if (!std.mem.eql(u8, self.saved, self.backing)) return fail("shared endpoint empty output preservation");
            // A second message reaches the distinct postdequeue failure path:
            // endpoint authority remains live, but its moved gift has expired.
            // The failed transfer disposes the move without publishing output.
            const expired = self.capabilities.mintBootRoot(.{
                .holder = self.tasks[0].owner,
                .issuer = self.port.kernel.policy_authority,
                .target = .{ .kind = .service, .id = 901 },
                .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
                .scope = .{ .task_id = self.tasks[0].id, .local_only = true },
                .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 30 },
            }) catch return fail("shared endpoint expiring gift");
            self.port.kernel.runtime.grantCapability(self.tasks[0].id, expired.id) catch return false;
            const late_sender = self.select(0);
            if (!dispatch.writeUserValue(late_sender, self.aliases[0] + payload_offset, payload)) return false;
            const late_request = abi.EndpointSendWireRequest{
                .header = component_port.makeHeader(.endpoint_send, self.tasks[0].id),
                .endpoint_capability_id = self.sending_id,
                .correlation_id = 92,
                .payload_address = self.aliases[0] + payload_offset,
                .payload_bytes = payload.len,
                .attached_capability_id = expired.id,
                .flags = abi.ENDPOINT_SEND_MOVE_ATTACHMENT,
            };
            if (!dispatch.writeUserValue(late_sender, self.aliases[0] + request_offset, late_request)) return false;
            const late_sent = endpoint_syscalls.dispatchEndpointSend(self.port, late_sender, 20, self.aliases[0] + request_offset, 0, 0);
            if (late_sent.status != .success or self.tasks[0].hasCapability(expired.id) or
                self.capabilities.query(expired.id) == null or !self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id)) or
                (self.endpoints.descriptor(self.destination) catch return false).queued_messages != 1)
                return fail("shared endpoint expiring move publication");
            const late_receiver = self.select(1);
            @memset(self.backing, 0xa5);
            if (!dispatch.writeUserValue(late_receiver, self.aliases[1] + request_offset, self.receiveRequest())) return false;
            @memcpy(self.saved, self.backing);
            var before_ids: [task_runtime.MAX_TASK_CAPABILITIES]u64 = @splat(0);
            @memcpy(before_ids[0..self.tasks[1].capability_count], self.tasks[1].capabilityIds());
            const before_generation = self.tasks[1].capabilityGeneration();
            const before_count = self.capabilities.activeCount();
            const failed_transfer = endpoint_syscalls.dispatchEndpointRecv(self.port, late_receiver, 31, self.aliases[1] + request_offset, self.aliases[1] + response_offset, @sizeOf(abi.EndpointRecvResponse));
            if (failed_transfer.status != .denied or failed_transfer.denial_reason != .capability_revoked or failed_transfer.bytes_written != 0 or
                !std.mem.eql(u8, self.saved, self.backing) or self.capabilities.query(expired.id) != null or
                self.capabilities.activeCount() != before_count - 1 or self.tasks[1].capability_count != receiver_grants + 1 or
                self.tasks[1].capabilityGeneration() != before_generation or
                !std.mem.eql(u64, self.tasks[1].capabilityIds(), before_ids[0..self.tasks[1].capability_count]) or
                self.endpoints.hasPendingForTask(ids.task(self.tasks[1].id)) or
                (self.endpoints.descriptor(self.destination) catch return false).queued_messages != 0)
                return fail("shared endpoint expired move disposal");
            // Preconsume output rejection preserves the queue; operational
            // failure after dequeue instead releases the undelivered move.
            return true;
        }
    };
    if (currentRegisteredExecutor() != null or !smp.isRuntimeOwner() or x86.interruptsEnabled()) return false;
    freestanding.paging.drainFrameCachesForArchitectureProof();
    const baseline = freestanding.paging.frameStats().allocated;
    const kernel_cr3 = x86.readCr3();
    var executor = Executor{};
    if (!claimCurrentExecutor(&executor)) return false;
    defer if (executor.registration_cpu != null) {
        executor.active_task_id = 0;
        executor.active_mapping = null;
        executor.reset();
    };
    {
        // The real runtime and authority tables exceed the early stack budget.
        // Their storage and the Kernel callback address stay stable until reset.
        const runtime = table_backing.alloc(task_runtime.Runtime) orelse return Fixture.fail("shared endpoint runtime allocation");
        runtime.initializeAllocated();
        defer table_backing.free(task_runtime.Runtime, runtime);
        const capabilities = table_backing.alloc(capability.CapabilityTable) orelse return Fixture.fail("shared endpoint capability allocation");
        capabilities.initializeAllocated();
        defer table_backing.free(capability.CapabilityTable, capabilities);
        const endpoints = table_backing.alloc(endpoint.Table) orelse return Fixture.fail("shared endpoint queue allocation");
        endpoints.initializeAllocated();
        defer {
            endpoints.deinit();
            table_backing.free(endpoint.Table, endpoints);
        }
        var table = shared_memory.Table.initWithMappingLifetime(.{
            .context = &executor,
            .register = registerMappedObject,
            .unregister = unregisterMappedObject,
        });
        defer table.deinit();
        const policy_authority = @import("../core/principal.zig").PrincipalId{ .kind = .policy_authority, .serial = 1 };
        var kernel: native_kernel.Kernel = undefined;
        kernel.initInPlace(policy_authority, runtime, capabilities, endpoints, &table);
        defer kernel.deinit();
        if (!executor.claimRuntimeBinding(&kernel, runtime)) return Fixture.fail("shared endpoint runtime binding");
        defer {
            executor.active_task_id = 0;
            executor.active_mapping = null;
            // Task retirement must run while Kernel, the queues, shared Table and
            // exact mapping handles still live. It disposes queued moves as well
            // as recipient grants; plain queue deinit cannot supply that proof.
            runtime.reset();
            if (endpoints.activeCount() != 0 or capabilities.activeCount() != 0 or executor.mapped_object_count != 0)
                native_util.impossibleByInvariant("shared endpoint proof retires all task authority");
            executor.releaseAllMappings();
            if (!executor.releaseRuntimeBinding(&kernel, runtime))
                native_util.impossibleByInvariant("shared endpoint proof releases its exact runtime binding");
        }
        var port = component_port.KernelPort.init(&kernel);
        var tasks: [2]*task_runtime.TaskRecord = undefined;
        for (&tasks, 0..) |*task, index| {
            task.* = runtime.createTask(.{
                .owner = .{ .kind = .app, .serial = index + 2 },
                .component_class = .app_component,
                .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 2 * PAGE_SIZE, .endpoint_slots = 2, .shared_memory_bytes = 2 * PAGE_SIZE },
                .local_only = true,
            }) catch return Fixture.fail("shared endpoint task construction");
            if (runtime.findAddressSpaceConst(task.*.address_space_id) == null or task.*.hasLoadedExecutable())
                return Fixture.fail("shared endpoint real empty runtime space");
        }
        const mappings = executor.ensureMappingArena() catch return false;
        var handles: [2]MappingHandle = undefined;
        for (&handles, 0..) |*handle, index| {
            const space_id = tasks[index].address_space_id;
            handle.* = mappings.reserveHandle(space_id) orelse return false;
        }
        const space = freestanding.paging.createUserAddressSpace() catch return false;
        executor.group_spaces[0] = space;
        executor.group_refs[0] = 2;
        for (handles, tasks) |handle, task| {
            mappings.getByHandle(handle).?.mapping = .{
                .state = .live,
                .address_space_id = task.address_space_id,
                .address_space = space,
                .dispatch_metadata = .{ .owner_task_id = task.id },
            };
        }
        const object = table.createWithAccess(ids.task(tasks[0].id), PAGE_SIZE + 37, .{ .ring = true }) catch return false;
        var aliases: [2]usize = undefined;
        for (&aliases, 0..) |*alias, index| {
            executor.active_task_id = tasks[index].id;
            executor.active_mapping_handle = handles[index];
            executor.active_mapping = &mappings.getByHandle(handles[index]).?.mapping;
            table.map(object.id, ids.task(tasks[index].id)) catch return false;
            const descriptor = table.freestandingTaskMappingDescriptor(object.id, ids.task(tasks[index].id)) catch return false;
            alias.* = @intCast(descriptor.virtual_base);
        }
        table.seal(object.id) catch return false;
        // Empty real records admit no private ELF range: shared authority still
        // comes solely from the selected Executor, live Table and exact token.
        const peer_context = dispatch.UserMemoryContext.init(&port, tasks[1].id);
        const peer_address = aliases[1] + PAGE_SIZE - 16;
        var bytes: [32]u8 = undefined;
        for (&bytes, 0..) |*byte, index| byte.* = @intCast(0x80 + index);
        const destination: [*]u8 = @ptrFromInt(peer_address);
        if (!dispatch.copyToUser(peer_context, destination[0..bytes.len], &bytes)) return false;
        const observed = dispatch.readUserValue([32]u8, peer_context, peer_address) orelse return false;
        if (!std.mem.eql(u8, &bytes, &observed) or
            dispatch.validateUserRange(peer_context, aliases[0], 1, 1, .read) or
            dispatch.preflightResponse(peer_context, aliases[1], object.size_bytes + 1, 1) == null) return false;
        executor.active_task_id = tasks[0].id;
        executor.active_mapping_handle = handles[0];
        executor.active_mapping = &mappings.getByHandle(handles[0]).?.mapping;
        const owner_context = dispatch.UserMemoryContext.init(&port, tasks[0].id);
        const owner_address = aliases[0] + PAGE_SIZE - 16;
        const owner_observed = dispatch.readUserValue([32]u8, owner_context, owner_address) orelse return false;
        if (!std.mem.eql(u8, &bytes, &owner_observed) or
            dispatch.validateUserRange(owner_context, aliases[1], 1, 1, .write) or
            dispatch.preflightResponse(owner_context, owner_address, bytes.len, bytes.len) != null) return false;
        const replacement: [32]u8 = @splat(0x5a);
        const published = dispatch.writeResponse(owner_context, owner_address, replacement.len, replacement);
        if (published.status != .success or published.bytes_written != replacement.len) return false;
        const reread = dispatch.readUserValue([32]u8, owner_context, owner_address) orelse return false;
        if (!std.mem.eql(u8, &replacement, &reread)) return false;
        const source = endpoints.create(ids.task(tasks[0].id), "shared-sender", .{ .local_only = true }) catch return false;
        const target = endpoints.create(ids.task(tasks[1].id), "shared-receiver", .{ .local_only = true }) catch return false;
        endpoints.connect(source.id, target.id) catch return false;
        const sending = capabilities.mintBootRoot(.{
            .holder = tasks[0].owner,
            .issuer = policy_authority,
            .target = .{ .kind = .endpoint, .id = source.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true } },
            .scope = .{ .task_id = tasks[0].id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch return false;
        const receiving = capabilities.mintBootRoot(.{
            .holder = tasks[1].owner,
            .issuer = policy_authority,
            .target = .{ .kind = .endpoint, .id = target.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_recv = true, .endpoint_close = true } },
            .scope = .{ .task_id = tasks[1].id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch return false;
        const gift = capabilities.mintBootRoot(.{
            .holder = tasks[0].owner,
            .issuer = policy_authority,
            .target = .{ .kind = .service, .id = 900 },
            .rights = .{ .service = .{ .capability_pass = true, .time_query = true } },
            .scope = .{ .task_id = tasks[0].id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch return false;
        runtime.grantCapability(tasks[0].id, sending.id) catch return false;
        runtime.grantCapability(tasks[0].id, gift.id) catch return false;
        runtime.grantCapability(tasks[1].id, receiving.id) catch return false;
        const saved = table_backing.alloc([2 * PAGE_SIZE]u8) orelse return false;
        defer table_backing.free([2 * PAGE_SIZE]u8, saved);
        const backing_base = freestanding.paging.mappedRamSpan(object.page_base, object.page_count * PAGE_SIZE) orelse return false;
        var fixture = Fixture{
            .executor = &executor,
            .mappings = mappings,
            .handles = handles,
            .tasks = tasks,
            .capabilities = capabilities,
            .endpoints = endpoints,
            .port = &port,
            .aliases = aliases,
            .object = object,
            .backing = @as([*]u8, @ptrFromInt(backing_base))[0 .. object.page_count * PAGE_SIZE],
            .saved = saved,
            .source = source.id,
            .destination = target.id,
            .sending_id = sending.id,
            .receiving_id = receiving.id,
            .gift_id = gift.id,
        };
        if (!fixture.endpointFlow()) return false;
        const stale_memory = fixture.select(0);
        const stale_send = abi.EndpointSendWireRequest{
            .header = component_port.makeHeader(.endpoint_send, tasks[0].id),
            .endpoint_capability_id = sending.id,
            .payload_address = owner_address,
            .payload_bytes = bytes.len,
        };
        if (!dispatch.writeUserValue(stale_memory, aliases[0], stale_send)) return false;
        _ = table.revoke(object.id) catch return false;
        if (dispatch.writeResponse(owner_context, owner_address, bytes.len, bytes).status != .invalid_response_buffer or
            dispatch.readUserValue([32]u8, owner_context, owner_address) != null) return false;
        const grants_after = capabilities.activeCount();
        const stale = endpoint_syscalls.dispatchEndpointSend(&port, stale_memory, 32, aliases[0], 0, 0);
        port.syscall_caller_task_id = 0;
        if (stale.status != .invalid_request_pointer or stale.bytes_written != 0 or capabilities.activeCount() != grants_after or
            (endpoints.descriptor(target.id) catch return false).queued_messages != 0 or endpoints.hasPendingForTask(ids.task(tasks[1].id)))
            return Fixture.fail("shared endpoint retired request consumption");
        if (x86.readCr3() != kernel_cr3 or x86.interruptsEnabled() or !smp.isRuntimeOwner()) return false;
    }
    executor.active_task_id = 0;
    executor.active_mapping = null;
    executor.reset();
    freestanding.paging.drainFrameCachesForArchitectureProof();
    return freestanding.paging.frameStats().allocated == baseline and x86.readCr3() == kernel_cr3;
}

pub fn activeTaskId() u64 {
    const executor = currentRegisteredExecutor() orelse return 0;
    return executor.activeTaskId();
}

pub const Executor = struct {
    initialized: bool = false,
    registration_cpu: ?u8 = null,
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
    active_dispatch_lease: ?dispatch_ownership.Ticket = null,
    handoff_completed: bool = false,
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
    pending_retirements: [(task_runtime.MAX_TASKS + 63) / 64]u64 = @splat(0),

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
        if (comptime builtin.target.os.tag == .freestanding) {
            if (!smp.isRuntimeOwner()) @call(.never_inline, executorInvariantFailure, .{.shared_executor_services_require_the_bsp_runtime_owner});
            if (!claimCurrentExecutor(self)) @call(.never_inline, executorInvariantFailure, .{.selected_cpu_executor_registration_requires_its_exact_owner});
        }
        if (builtin.target.os.tag != .freestanding) return;
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
        if (!freestanding.syscall64.setKernelStack(trap_stack_top))
            @call(.never_inline, executorInvariantFailure, .{.selected_cpu_trap_stack_must_be_provisioned_before_entry});
        self.initialized = true;
    }

    pub fn claimRuntimeBinding(
        self: *Executor,
        owner: *const anyopaque,
        runtime: *task_runtime.Runtime,
    ) bool {
        if (!bspMappingTransaction() or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime) or self.binding_owner != null or self.bound_runtime != null) return false;
        self.binding_owner = owner;
        self.bound_runtime = runtime;
        return true;
    }

    // The BSP provisions a mapping route, never AP native entry. Publication
    // happens before any lease; a lease pins every member of its Runtime domain.
    pub fn claimMappingRegistration(self: *Executor, cpu: u8, owner: *const anyopaque, runtime: *task_runtime.Runtime) bool {
        if (!bspMappingTransaction() or cpu >= cpu_identity.MAX_CPUS or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime) or
            self.binding_owner != owner or self.bound_runtime != runtime) return false;
        if (self.registration_cpu) |selected| return selected == cpu and registeredExecutor(cpu) == self;
        if (registeredExecutor(cpu) != null) return false;
        self.registration_cpu = cpu;
        @atomicStore(?*Executor, &executor_registrations[cpu].executor, self, .release);
        return true;
    }

    pub inline fn releaseMappingRegistration(self: *Executor, cpu: u8, owner: *const anyopaque, runtime: *task_runtime.Runtime) bool {
        if (!bspMappingTransaction() or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime) or registeredDomainExecutor(cpu, owner, runtime) != self or
            self.active_task_id != 0 or self.active_mapping != null or self.active_dispatch_lease != null or self.materializedCount() != 0 or
            self.mapped_object_count != 0 or self.mappedObjectLifetimeIsBound()) return false;
        @atomicStore(?*Executor, &executor_registrations[cpu].executor, null, .release);
        self.registration_cpu = null;
        return true;
    }

    fn mappedObjectLifetime(self: *Executor) shared_memory.MappingLifetime {
        return .{ .context = self, .register = registerMappedObject, .unregister = unregisterMappedObject };
    }

    pub fn bindMappedObjectLifetime(self: *Executor) bool {
        const runtime = self.bound_runtime orelse return false;
        if (!bspMappingTransaction() or self.binding_owner == null or executionOwnershipOutstanding(runtime) or
            self.registration_cpu != 0 or currentRegisteredExecutor() != self) return false;
        return shared_memory.bindMappedObjectLifetime(self.mappedObjectLifetime());
    }

    pub fn mappedObjectLifetimeIsBound(self: *Executor) bool {
        return shared_memory.mappedObjectLifetimeIsBound(self.mappedObjectLifetime());
    }

    pub fn unbindMappedObjectLifetime(self: *Executor) bool {
        const runtime = self.bound_runtime orelse return false;
        if (!bspMappingTransaction() or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime)) return false;
        return shared_memory.unbindMappedObjectLifetime(self.mappedObjectLifetime());
    }

    // Isolated CPL0 fixture admission uses the real arena/root/lifetime checks,
    // without AP native-entry setup, executable images or fabricated xstate.
    pub fn installPreparedMappingForArchitectureProof(self: *Executor, task: *const task_runtime.TaskRecord, space: freestanding.paging.UserAddressSpace, out: *MappingHandle) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (comptime !@hasDecl(root, "ARCHITECTURE_SMP_PROOF") or !root.ARCHITECTURE_SMP_PROOF)
            @compileError("prepared architecture mappings require an isolated proof root");
        const runtime = self.bound_runtime orelse return false;
        const owner = self.binding_owner orelse return false;
        const cpu = self.registration_cpu orelse return false;
        if (!bspMappingTransaction() or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime) or registeredDomainExecutor(cpu, owner, runtime) != self or
            runtime.findConst(task.id) != task or task.state != .active or self.findMapping(task.address_space_id) != null) return false;
        const record = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
        if (record.owner_task_id != task.id or freestanding.paging.checkedUserAddressSpacePhysicalRoot(&space) == null) return false;
        const mappings = self.ensureMappingArena() catch return false;
        const handle = mappings.reserveHandle(task.address_space_id) orelse return false;
        mappings.getByHandle(handle).?.mapping = .{
            .state = .live,
            .address_space_id = task.address_space_id,
            .address_space = space,
            .dispatch_metadata = .{ .owner_task_id = task.id },
        };
        out.* = handle;
        return true;
    }

    // The isolated CPL0 callback needs the same pinned context/private storage
    // as the production runner. This fixture never admits native user entry.
    pub fn installPreparedExecutionMappingForArchitectureProof(
        self: *Executor,
        task: *const task_runtime.TaskRecord,
        space: freestanding.paging.UserAddressSpace,
        context: UserContext64,
        out: *MappingHandle,
    ) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (comptime !architecture_smp_proof) @compileError("prepared execution fixtures require an isolated proof root");
        if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or
            self.active_task_id != 0 or self.active_mapping != null or self.active_dispatch_lease != null or
            context.instruction_pointer == 0 or context.stack_pointer == 0) return false;
        const storage = table_backing.alloc(xstate.Storage) orelse return false;
        storage.initialize();
        var handle: MappingHandle = undefined;
        if (!self.installPreparedMappingForArchitectureProof(task, space, &handle)) {
            storage.erase();
            table_backing.free(xstate.Storage, storage);
            return false;
        }
        const mapping = self.findMappingByHandle(handle, task.address_space_id).?;
        mapping.owned_xstate = storage;
        mapping.user_context64 = context;
        mapping.dispatch_metadata.initial_instruction_pointer = context.instruction_pointer;
        mapping.dispatch_metadata.initial_stack_pointer = context.stack_pointer;
        self.initialized = true;
        self.probe_marker_printed = true;
        self.resume_marker_printed = true;
        out.* = handle;
        return true;
    }

    pub fn bindPreparedExecutionForArchitectureProof(
        self: *Executor,
        task: *const task_runtime.TaskRecord,
        handle: MappingHandle,
        ticket: dispatch_ownership.Ticket,
        out: *ArchitecturePreparedCommand,
    ) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (comptime !architecture_smp_proof) @compileError("prepared execution binding requires an isolated proof root");
        if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or
            !self.initialized or self.active_task_id != 0 or self.active_mapping != null or self.active_dispatch_lease != null) return false;
        const runtime = self.bound_runtime orelse return false;
        const owner = self.binding_owner orelse return false;
        const cpu = self.registration_cpu orelse return false;
        if (cpu == 0 or ticket.cpu != cpu or registeredDomainExecutor(cpu, owner, runtime) != self or
            runtime.findConst(task.id) != task or task.state != .active) return false;
        var identity: dispatch_ownership.Identity = undefined;
        runtime.execution.identityInto(ticket, &identity) catch return false;
        if (identity.task_handle != runtime.taskHandleForResolved(task).value or identity.task_id != task.id or
            identity.process_generation != task.process_generation or identity.address_space_id != task.address_space_id) return false;
        const mapping = self.findMappingByHandle(handle, task.address_space_id) orelse return false;
        const space = if (mapping.address_space) |*value| value else return false;
        if (mapping.dispatch_metadata.owner_task_id != task.id or mapping.owned_xstate == null or
            !self.userAddressSpacePreparationReady(space)) return false;
        const physical_root = freestanding.paging.checkedUserAddressSpacePhysicalRoot(space) orelse return false;
        const top = preparedKernelStackForCpu(cpu) orelse return false;
        const candidate: PreparedDispatch = .{ .ticket = ticket, .trap_stack_top = top };
        runtime.execution.bindPrepared(ticket, handle.value, physical_root) catch return false;
        out.* = candidate;
        return true;
    }

    pub fn runPreparedExecutionForArchitectureProof(
        self: *Executor,
        command: *const ArchitecturePreparedCommand,
        callback: ArchitecturePreparedCallback,
        callback_context: *anyopaque,
    ) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (comptime !architecture_smp_proof) @compileError("prepared execution owner requires an isolated proof root");
        return self.runPreparedTaskSlice(command, ArchitecturePreparedBackend{
            .callback = callback,
            .callback_context = callback_context,
        });
    }

    pub fn publishPreparedExecutionForArchitectureProof(
        self: *Executor,
        command: *const ArchitecturePreparedCommand,
        out: *dispatch_transport.Key,
    ) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (comptime !architecture_smp_proof) @compileError("queued execution fixtures require an isolated proof root");
        return self.publishPreparedCommandInto(command, out);
    }

    fn publishPreparedCommandInto(self: *Executor, command: *const PreparedDispatch, out: *dispatch_transport.Key) bool {
        if (!bspMappingTransaction() or !freestanding.paging.kernelAddressSpaceActive() or !self.initialized or
            self.active_task_id != 0 or self.active_mapping != null or self.active_dispatch_lease != null) return false;
        const runtime = self.bound_runtime orelse return false;
        const owner = self.binding_owner orelse return false;
        const ticket = command.ticket;
        if (ticket.issuer != &runtime.execution or self.registration_cpu != ticket.cpu or
            registeredDomainExecutor(ticket.cpu, owner, runtime) != self or
            preparedKernelStackForCpu(ticket.cpu) != command.trap_stack_top) return false;
        runtime.execution.preparedReady(ticket) catch return false;
        var identity: dispatch_ownership.Identity = undefined;
        runtime.execution.identityInto(ticket, &identity) catch return false;
        const mapping = self.findMapping(identity.address_space_id) orelse return false;
        if (mapping.dispatch_metadata.owner_task_id != identity.task_id or mapping.owned_xstate == null or
            mappingPhysicalRoot(mapping) == 0) return false;
        dispatch_transport.global.publishInto(command.*, out) catch return false;
        return true;
    }

    pub fn prepareSyscallCopySession(self: *Executor, claim: *const dispatch_ownership.ClaimedSyscall, out: *syscall_broker.CopySession) bool {
        const interrupts_enabled = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        const kernel_active = if (comptime builtin.target.os.tag == .freestanding) freestanding.paging.kernelAddressSpaceActive() else true;
        var resolved: SyscallCopyMapping = undefined;
        if (!syscallCopyMappingInto(self, claim, interrupts_enabled, kernel_active, &resolved)) return false;
        out.* = .{ .context = self, .key = claim.key, .bound = claim.bound, .read = readSyscallCopy, .prepare_output = prepareSyscallOutput, .write_outputs = writeSyscallOutputs };
        return true;
    }

    pub fn releaseRuntimeBinding(
        self: *Executor,
        expected_owner: *const anyopaque,
        expected_runtime: *task_runtime.Runtime,
    ) bool {
        const owner = self.binding_owner orelse return false;
        const runtime = self.bound_runtime orelse return false;
        if (!bspMappingTransaction() or runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime) or owner != expected_owner or runtime != expected_runtime or
            self.materializedCount() != 0 or self.mapped_object_count != 0 or self.active_task_id != 0 or self.active_mapping != null or
            self.active_dispatch_lease != null or self.mappedObjectLifetimeIsBound()) return false;
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
        self.retireAddressSpaceChecked(event) catch
            @call(.never_inline, executorInvariantFailure, .{.executor_retirement_requires_its_exact_cpu_registration_owner});
    }

    fn retireAddressSpaceChecked(self: *Executor, event: task_runtime.AddressSpaceRetirementEvent) RetirementOwnerError!void {
        try requireRetirementOwner(self);
        const restore_interrupts = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_interrupts) x86.sti();
        };
        if (self.last_fault_address_space_id == event.address_space_id) {
            self.clearUserPageFaultObservation();
        }
        const resolution = self.findMappingWithHandle(event.address_space_id) orelse return;
        const mapping = resolution.entry;
        if (self.active_task_id != 0 and self.active_mapping == mapping) {
            if (!resolution.handle.eql(self.active_mapping_handle)) {
                @call(.never_inline, executorInvariantFailure, .{.active_userspace_mapping_handle_points_at_a_different_slot});
            }
            self.queueMappingRetirement(resolution.slot_index, mapping);
            if (self.active_dispatch_lease) |ticket| {
                const runtime = self.bound_runtime orelse
                    @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
                runtime.requestExecutionStop(ticket) catch
                    @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
            }
            self.handoff_completed = true;
            if (self.registration_cpu == cpu_identity.currentIndex() or
                (builtin.target.os.tag != .freestanding and self.registration_cpu == null and cpu_identity.currentIndex() == 0))
                native_entry.current().resume_requested = 1;
            return;
        }
        if (!self.mappingRetirementReady(mapping)) {
            self.queueMappingRetirement(resolution.slot_index, mapping);
            return;
        }
        releaseMapping(self, resolution.mappings, resolution.slot_index, mapping);
    }

    pub fn materializedCount(self: *const Executor) usize {
        const mappings = self.mappingArenaConst() orelse return 0;
        return mappings.countInUse();
    }

    pub fn reset(self: *Executor) void {
        self.resetChecked() catch @call(.never_inline, executorInvariantFailure, .{.executor_reset_requires_its_exact_cpu_registration_owner});
    }

    fn resetChecked(self: *Executor) error{ WrongCpu, RegistrationMismatch, ExecutionLeased, AddressSpaceActive }!void {
        try requireRetirementOwner(self);
        if ((self.registration_cpu == null and currentRegisteredExecutor() == self) or self.mappedObjectLifetimeIsBound()) return error.RegistrationMismatch;
        const restore_interrupts = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_interrupts) x86.sti();
        };
        if (self.active_task_id != 0) {
            @call(.never_inline, executorInvariantFailure, .{.cannot_reset_userspace_executor_while_an_address_space_is_active});
        }
        if (self.bound_runtime) |runtime| if (runtime.lifecycle_transition_active or executionOwnershipOutstanding(runtime)) return error.ExecutionLeased;
        if (self.mappingArena()) |mappings| {
            for (0..mappings.claimedCount()) |index| {
                const slot = mappings.slotAt(index);
                if (!slot.in_use) continue;
                if (!self.mappingRetirementReady(&slot.mapping)) return error.AddressSpaceActive;
            }
        }
        self.releaseAllMappings();
        self.initialized = false;
        self.probe_marker_printed = false;
        self.resume_marker_printed = false;
        self.active_task_id = 0;
        self.dispatch_quantum = .{};
        self.active_mapping = null;
        self.active_mapping_handle = .{};
        self.active_dispatch_lease = null;
        self.handoff_completed = false;
        self.last_trap_counter = 0;
        self.last_user_exception = null;
        self.last_fault_task_id = 0;
        self.last_fault_address_space_id = 0;
        self.last_fault_address = 0;
        self.last_fault_error_code = 0;
        self.user_page_fault_count = 0;
        if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
        if (self.registration_cpu) |cpu| {
            if (cpu == cpu_identity.currentIndex()) {
                native_entry.clearContinuation();
                publishRootActiveTaskId(0);
            }
            @atomicStore(?*Executor, &executor_registrations[cpu].executor, null, .release);
            self.registration_cpu = null;
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
        var resolution: MappingResolution = undefined;
        self.ensureMaterializedInto(address_space, image, &resolution) catch return false;
        const mapping = resolution.entry;
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
        var resolution: MappingResolution = undefined;
        self.ensureMaterializedInto(address_space, image, &resolution) catch return false;
        const mapping = resolution.entry;
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
        ticket: dispatch_ownership.Ticket,
    ) ReturnRecord {
        if (builtin.target.os.tag != .freestanding) return .{};
        if (!smp.isRuntimeOwner()) return .{};
        // BSP preparation and synchronous receipt collection share the same
        // nonreentrant transaction; entry independently restores the user's IF.
        const restore_interrupts = x86.interruptsEnabled();
        x86.cli();
        defer if (restore_interrupts) x86.sti();
        var prepared: PreparedDispatch = undefined;
        if (!self.prepareTaskDispatchInto(catalog, runtime, capability_table, task, mapping_handle, now_ticks, ticket, &prepared, NativePreparedDispatch{})) return .{};
        if (!self.runPreparedTaskSlice(&prepared, NativePreparedDispatch{})) {
            runtime.execution.cancelUnstarted(ticket) catch
                @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
        }
        var returned: ReturnRecord = undefined;
        runtime.execution.consumePreparedReturnInto(ticket, &returned) catch
            @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
        return returned;
    }

    // BSP materialization remains serialized. The image-static channel keeps
    // the resulting lease and route owned until the selected CPU completes.
    pub fn prepareQueuedTaskInto(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
        task: *const task_runtime.TaskRecord,
        mapping_handle: *MappingHandle,
        now_ticks: u64,
        ticket: dispatch_ownership.Ticket,
        out: *dispatch_transport.Key,
    ) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        if (!smp.isRuntimeOwner()) return false;
        const restore_interrupts = x86.interruptsEnabled();
        x86.cli();
        defer if (restore_interrupts) x86.sti();
        var command: PreparedDispatch = undefined;
        if (!self.prepareTaskDispatchInto(catalog, runtime, capability_table, task, mapping_handle, now_ticks, ticket, &command, NativePreparedDispatch{})) return false;
        return self.publishPreparedCommandInto(&command, out);
    }

    fn prepareTaskDispatchInto(
        self: *Executor,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
        task: *const task_runtime.TaskRecord,
        mapping_handle: *MappingHandle,
        now_ticks: u64,
        ticket: dispatch_ownership.Ticket,
        out: *PreparedDispatch,
        backend: anytype,
    ) bool {
        if (!bspMappingTransaction() or !backend.preparationReady()) return false;
        if (!self.initialized or self.bound_runtime != runtime or self.registration_cpu != ticket.cpu or
            registeredExecutor(ticket.cpu) != self or self.active_task_id != 0 or self.active_dispatch_lease != null) return false;
        var identity: dispatch_ownership.Identity = undefined;
        runtime.execution.identityInto(ticket, &identity) catch return false;
        if (identity.task_handle != runtime.taskHandleForResolved(task).value or identity.task_id != task.id or
            identity.process_generation != task.process_generation or identity.address_space_id != task.address_space_id) return false;
        backend.dispatchService(task.id);
        if (debugIndexChecksEnabled()) {
            const bound_task = runtime.findConst(task.id) orelse
                native_util.impossibleByInvariant("prepared userspace task is absent from the bound runtime");
            if (bound_task != task) native_util.impossibleByInvariant("prepared userspace task does not belong to the bound runtime");
        }
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) return false;
        const mapping = self.resolveMappingForDispatch(mapping_handle, task.address_space_id) orelse blk: {
            const address_space = runtime.findAddressSpaceConst(task.address_space_id) orelse return false;
            if (address_space.owner_task_id != task.id or address_space.image_id != task.launch.image_id) return false;
            const image = catalog.findById(task.launch.image_id) orelse return false;
            if (!image.elf_file.isPresent()) return false;
            var resolution: MappingResolution = undefined;
            self.ensureMaterializedInto(address_space, image, &resolution) catch return false;
            mapping_handle.* = resolution.handle;
            break :blk resolution.entry;
        };
        if (mapping.dispatch_metadata.owner_task_id != task.id or mapping.dispatch_metadata.image_id != task.launch.image_id)
            @call(.never_inline, executorInvariantFailure, .{.materialized_userspace_mapping_identity_changed_without_retirement});
        const space = if (mapping.address_space) |*value| value else return false;
        if (!self.userAddressSpacePreparationReady(space) or mapping.owned_xstate == null) return false;
        const physical_root = freestanding.paging.checkedUserAddressSpacePhysicalRoot(space) orelse return false;
        const trap_stack_top = backend.stackTop(ticket.cpu) orelse return false;
        const mailbox_update = self.prepareBootstrapMailbox(mapping, task, capability_table, now_ticks);
        if (!publishMailboxForDispatch(mapping, mailbox_update, backend)) return false;
        // The lease makes this mapping's prepared context immutable until the
        // selected owner captures its next user frame. Preserve resumed state.
        if (!mapping.resume_valid) mapping.user_context64 = .{
            .instruction_pointer = mapping.dispatch_metadata.initial_instruction_pointer,
            .stack_pointer = mapping.dispatch_metadata.initial_stack_pointer,
        };
        const candidate: PreparedDispatch = .{ .ticket = ticket, .trap_stack_top = trap_stack_top };
        // Publication follows all materialization, authority and mailbox work.
        runtime.execution.bindPrepared(ticket, mapping_handle.value, physical_root) catch return false;
        // The synchronous caller owns this shell; queued publication copies it
        // into image-owned transport before another CPU can claim it.
        out.* = candidate;
        return true;
    }

    fn runPreparedTaskSlice(self: *Executor, prepared: *const PreparedDispatch, backend: anytype) bool {
        const ticket = prepared.ticket;
        const coordinator = @constCast(ticket.issuer);
        const restore_interrupts = backend.mask();
        defer backend.restore(restore_interrupts);
        if (!backend.ownerAvailable()) return false;
        var bound: dispatch_ownership.BoundIdentity = undefined;
        // Claim before touching entry payload, Executor or local arena backing.
        coordinator.startPreparedInto(ticket, &bound) catch return false;
        const authenticated_mapping: ?*MappingEntry = blk: {
            if (self.bound_runtime == null or &self.bound_runtime.?.execution != coordinator or
                self.registration_cpu != ticket.cpu or currentRegisteredExecutor() != self or !self.initialized or
                self.active_task_id != 0 or self.active_dispatch_lease != null or !backend.entryReady(prepared.trap_stack_top)) break :blk null;
            const selected = self.findMappingByHandle(.{ .value = bound.mapping_handle }, bound.identity.address_space_id) orelse break :blk null;
            if (selected.dispatch_metadata.owner_task_id != bound.identity.task_id or mappingPhysicalRoot(selected) != bound.physical_root or
                selected.owned_xstate == null) break :blk null;
            break :blk selected;
        };
        var returned: ReturnRecord = .{};
        if (authenticated_mapping) |mapping| {
            self.active_mapping = mapping;
            self.active_mapping_handle = .{ .value = bound.mapping_handle };
            self.active_dispatch_lease = ticket;
            self.active_task_id = bound.identity.task_id;
            if (comptime include_verification_evidence) self.active_nx_probe_target = if ((mapping.dispatch_metadata.contractFlags() & userspace_flags.FLAG_NX_PROOF_PROBE) != 0) mapping.dispatch_metadata.bootstrap_mailbox_address else 0;
            publishRootActiveTaskId(bound.identity.task_id);
            self.handoff_completed = false;
            self.last_yield_disposition = .runnable;
            self.last_yield_ui_revision = 0;
            self.last_user_exception = null;
            native_entry.current().resume_requested = 0;
            backend.activate(mapping);
            backend.enter(self);
            requireIdleSyscallReturn();
            backend.switchToKernel();
            self.active_task_id = 0;
            self.dispatch_quantum = .{};
            self.active_mapping = null;
            self.active_mapping_handle = .{};
            if (comptime include_verification_evidence) self.active_nx_probe_target = 0;
            publishRootActiveTaskId(0);
            native_entry.current().resume_requested = 0;
            const user_faulted = self.last_user_exception != null;
            if (!user_faulted and self.handoff_completed and !self.probe_marker_printed) {
                common.printBootMarker(boot_markers.userspace_exec_probe_ok);
                self.probe_marker_printed = true;
            }
            if (!user_faulted and self.handoff_completed and mapping.yield_count >= 2 and
                mapping.last_user_counter >= 2 and !self.resume_marker_printed)
            {
                common.printBootMarker(boot_markers.userspace_resume_ok);
                self.resume_marker_printed = true;
            }
            returned.outcome = if (!self.handoff_completed) .unavailable else if (user_faulted) .faulted else switch (self.last_yield_disposition) {
                .runnable => .yielded,
                .wait_for_event => .wait_for_event,
            };
            returned.ui_revision = self.last_yield_ui_revision;
            if (self.last_user_exception) |fault| {
                returned.fault_vector = fault.vector;
                returned.fault_error_code = fault.error_code;
                returned.fault_instruction_pointer = fault.instruction_pointer;
                returned.fault_address = fault.fault_address;
            }
            if (!continuationCleared(native_entry.current()) or !backend.kernelActive())
                @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_only_its_cleared_kernel_continuation});
            self.active_dispatch_lease = null;
        }
        // This release ends owner access to Executor, Mapping, Runtime and the
        // prepared payload. Only local scalars and interrupt restoration remain.
        coordinator.ackPreparedReturn(ticket, returned) catch
            @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
        return true;
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
        var resolution: MappingResolution = undefined;
        self.ensureMaterializedInto(address_space, image, &resolution) catch return false;
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
        native_entry.current().resume_requested = 0;
        freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());

        const rehosted = runtime.rehostTask(task_id, now_ticks) catch false;
        const deferred = rehosted and
            freestanding.paging.getCurrentPageDirectory() == user_page_directory and
            mapping.state == .retire_pending and
            self.handoff_completed and
            native_entry.current().resume_requested == 1 and
            freestanding.paging.frameStats().allocated == frames_before;

        freestanding.paging.switchToKernelAddressSpace();
        const completed_mapping_handle = self.active_mapping_handle;
        self.active_task_id = 0;
        self.active_mapping = null;
        self.active_mapping_handle = .{};
        publishRootActiveTaskId(0);
        native_entry.current().resume_requested = 0;
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

    fn ensureMaterializedInto(
        self: *Executor,
        address_space: *const task_runtime.AddressSpaceRecord,
        image: *const userspace_loader.ImageRecord,
        out: *MappingResolution,
    ) MaterializationError!void {
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
            const space = if (resolution.entry.address_space) |*value| value else return error.AddressSpaceOwnerInvalid;
            if (!self.userAddressSpacePreparationReady(space)) return error.AddressSpaceLeased;
            if (!mappingDispatchMetadataCompatible(resolution.entry.dispatch_metadata, dispatch_metadata)) {
                @call(.never_inline, executorInvariantFailure, .{.materialized_userspace_dispatch_metadata_changed_without_retirement});
            }
            out.* = resolution;
            return;
        }

        if (comptime SHARES_GROUP_PAGE_TABLES) {
            if (userspace_registry.addressSpaceGroupForBundle(image.bundleIdSlice())) |group| {
                const index = @backingInt(group);
                if (self.group_refs[index] != 0 and !self.userAddressSpacePreparationReady(&self.group_spaces[index].?))
                    return error.AddressSpaceLeased;
            }
        }
        const mappings = try self.ensureMappingArena();
        const handle = mappings.reserveHandle(address_space.id) orelse return error.MappingTableFull;
        const slot = mappings.getByHandle(handle) orelse
            @call(.never_inline, executorInvariantFailure, .{.reserved_userspace_mapping_handle_is_not_live});
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
        out.* = .{
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
            @call(.never_inline, executorInvariantFailure, .{.executor_mapping_index_points_at_a_non_live_mapping});
        }
        if (entry.address_space_id != address_space_id) @call(.never_inline, executorInvariantFailure, .{.executor_mapping_index_points_at_the_wrong_mapping});
        const handle = mappings.handleForIndex(slot_index) orelse
            @call(.never_inline, executorInvariantFailure, .{.executor_mapping_index_points_at_an_unclaimed_slot});
        return .{
            .mappings = mappings,
            .slot_index = slot_index,
            .entry = entry,
            .handle = handle,
        };
    }

    inline fn findMappingByHandle(self: *Executor, handle: MappingHandle, expected_address_space_id: u64) ?*MappingEntry {
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
        if (!self.userAddressSpacePreparationReady(&self.group_spaces[index].?)) return error.AddressSpaceLeased;
        self.group_refs[index] += 1;
        return self.group_spaces[index].?;
    }

    inline fn userAddressSpacePreparationReady(self: *Executor, space: *const freestanding.paging.UserAddressSpace) bool {
        const runtime = self.bound_runtime orelse return true;
        const physical_root = if (comptime builtin.target.os.tag == .freestanding)
            space.switch_cr3 & x86.CR3_ADDRESS_MASK
        else
            @intFromPtr(space.directory);
        return runtime.execution.rootAvailable(physical_root);
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

    fn queueMappingRetirement(self: *Executor, index: usize, mapping: *MappingEntry) void {
        mapping.state = .retire_pending;
        self.pending_retirements[index / 64] |= @as(u64, 1) << @as(u6, @intCast(index % 64));
    }

    fn mappingRetirementReady(self: *Executor, entry: *const MappingEntry) bool {
        if (self.active_task_id != 0 and self.active_mapping == entry) return false;
        if (entry.state != .building) {
            if (self.bound_runtime) |runtime| {
                if (!runtime.execution.canRetireMapping(entry.address_space_id)) return false;
                if (entry.address_space) |space| {
                    const physical = if (comptime builtin.target.os.tag == .freestanding)
                        space.switch_cr3 & x86.CR3_ADDRESS_MASK
                    else
                        @intFromPtr(space.directory);
                    if (!runtime.execution.canRetireRoot(physical)) return false;
                }
            }
        }
        if (entry.address_space) |*space| if (!freestanding.paging.userAddressSpaceQuiescent(space)) return false;
        return true;
    }

    // A bitmap records only queued incarnations; a claimed slot cannot be
    // recycled until its pending bit is cleared by releaseMapping. Empty steady
    // dispatches do not scan the mapping arena, and busy shared roots stay held.
    pub fn collectRetiredMappings(self: *Executor) void {
        requireRetirementOwner(self) catch
            @call(.never_inline, executorInvariantFailure, .{.executor_retirement_requires_its_exact_cpu_registration_owner});
        const restore_interrupts = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_interrupts) x86.sti();
        };
        const mappings = self.mappingArena() orelse return;
        for (self.pending_retirements, 0..) |bits, word_index| {
            var remaining = bits;
            while (remaining != 0) {
                const bit = @ctz(remaining);
                remaining &= remaining - 1;
                const index = word_index * 64 + bit;
                const handle = mappings.handleForIndex(index) orelse
                    @call(.never_inline, executorInvariantFailure, .{.pending_userspace_retirement_retains_its_mapping_incarnation});
                const slot = mappings.getByHandle(handle) orelse unreachable;
                if (slot.mapping.state != .retire_pending)
                    @call(.never_inline, executorInvariantFailure, .{.pending_userspace_retirement_retains_its_mapping_incarnation});
                if (self.mappingRetirementReady(&slot.mapping)) self.releaseMapping(mappings, index, &slot.mapping);
            }
        }
    }

    fn releaseMapping(
        self: *Executor,
        mappings: *MappingArena,
        slot_index: usize,
        entry: *MappingEntry,
    ) void {
        requireRetirementOwner(self) catch
            @call(.never_inline, executorInvariantFailure, .{.executor_retirement_requires_its_exact_cpu_registration_owner});
        const restore_interrupts = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
        if (comptime builtin.target.os.tag == .freestanding) x86.cli();
        defer if (comptime builtin.target.os.tag == .freestanding) {
            if (restore_interrupts) x86.sti();
        };
        const handle = mappings.handleForIndex(slot_index) orelse
            @call(.never_inline, executorInvariantFailure, .{.pending_userspace_retirement_retains_its_mapping_incarnation});
        if (!self.mappingRetirementReady(entry))
            @call(.never_inline, executorInvariantFailure, .{.userspace_retirement_requires_a_quiescent_mapping_and_physical_root});
        if (builtin.mode == .debug) {
            std.debug.assert(&mappings.slotAt(slot_index).mapping == entry);
        }
        if (self.mapped_object_table) |table| {
            table.retireTaskMappingLifetime(@import("../core/ids.zig").task(entry.dispatch_metadata.owner_task_id), mappingLifetimeToken(self.registration_cpu orelse 0, handle) orelse unreachable);
        }
        if (entry.address_space) |*space| {
            if (entry.image_regions) |regions| {
                const stack = regions.stack;
                if (stack.size != 0 and !demand_paging.unregisterRegionForSpace(space, stack.start, stack.start + stack.size)) {
                    freestanding.paging.releaseUserRange(space, stack.start, stack.size) catch
                        @call(.never_inline, executorInvariantFailure, .{.invalid_retired_stack_mapping_range});
                }
            }
            const retain_shared = self.releaseSharedGroupSpace(space);
            if (!retain_shared) {
                demand_paging.unregisterSpace(space);
                if (entry.image_regions) |image_regions| {
                    for (image_regions.ranges[0..image_regions.count]) |range| {
                        freestanding.paging.releaseUserRange(space, range.start, range.size) catch
                            @call(.never_inline, executorInvariantFailure, .{.invalid_retired_image_mapping_range});
                    }
                }
                freestanding.paging.destroyUserAddressSpace(space) catch
                    @call(.never_inline, executorInvariantFailure, .{.attempted_to_destroy_the_active_userspace_address_space});
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
            @call(.never_inline, executorInvariantFailure, .{.live_userspace_mapping_disappeared_during_release});
        }
        self.pending_retirements[slot_index / 64] &= ~(@as(u64, 1) << @as(u6, @intCast(slot_index % 64)));
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
        self.pending_retirements = @splat(0);
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
        const slot = mappings.getByHandle(completed_mapping_handle) orelse
            native_util.impossibleByInvariant("completed userspace mapping handle is no longer live");
        if (&slot.mapping != completed_mapping)
            native_util.impossibleByInvariant("completed userspace mapping handle is no longer live");
        if (self.mappingRetirementReady(completed_mapping)) {
            releaseMapping(self, mappings, completed_mapping_handle.slotIndex(), completed_mapping);
        } else self.queueMappingRetirement(completed_mapping_handle.slotIndex(), completed_mapping);
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
    if (authority_generation == 0) @call(.never_inline, executorInvariantFailure, .{.resolved_mailbox_authorities_require_a_nonzero_generation});
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

const NativePreparedDispatch = struct {
    inline fn preparationReady(_: @This()) bool {
        return smp.isRuntimeOwner() and freestanding.paging.kernelAddressSpaceActive();
    }
    inline fn dispatchService(_: @This(), task_id: u64) void {
        _ = xhci_driver_task.dispatchForTask(task_id);
    }
    inline fn stackTop(_: @This(), cpu: u8) ?usize {
        return preparedKernelStackForCpu(cpu);
    }
    inline fn writeMailbox(_: @This(), mapping: *MappingEntry, update: ?BootstrapMailboxUpdate) bool {
        return writeUserspaceMailboxThroughMapping(mapping, update);
    }
    inline fn ownerAvailable(_: @This()) bool {
        // AP native entry remains gated until hardware admission is proven.
        return smp.isRuntimeOwner() and continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();
    }
    inline fn entryReady(_: @This(), stack_top: usize) bool {
        return stack_top != 0 and preparedKernelStackForCpu(cpu_identity.currentIndex()) == stack_top and
            native_entry.current().kernel_stack_top == stack_top and continuationCleared(native_entry.current()) and
            freestanding.paging.kernelAddressSpaceActive();
    }
    inline fn mask(_: @This()) bool {
        const enabled = x86.interruptsEnabled();
        x86.cli();
        return enabled;
    }
    inline fn restore(_: @This(), enabled: bool) void {
        if (enabled) x86.sti();
    }
    inline fn activate(_: @This(), mapping: *MappingEntry) void {
        freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());
    }
    inline fn enter(_: @This(), executor: *Executor) void {
        _ = @call(.never_inline, enterUserspace, .{executor});
    }
    inline fn switchToKernel(_: @This()) void {
        freestanding.paging.switchToKernelAddressSpace();
    }
    inline fn kernelActive(_: @This()) bool {
        return freestanding.paging.kernelAddressSpaceActive();
    }
};

// After interrupt return, the selected CPU consumes its prompt and claims
// image-owned storage before resolving a registered route. Runtime collection
// pins that route until this independent completion.
pub fn runQueuedPreparedTask() bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    return runQueuedPreparedTaskSlice(true, NativePreparedDispatch{}, null, null, null, null);
}

pub fn runQueuedPreparedExecutionForArchitectureProof(
    callback: ArchitecturePreparedCallback,
    callback_context: *anyopaque,
    saved_entry: *const native_entry.State,
    before_run: ?ArchitecturePreparedBeforeRun,
    after_return: ?ArchitecturePreparedAfterReturn,
    hook_context: *anyopaque,
) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (comptime !architecture_smp_proof) @compileError("queued owner fixtures require an isolated proof root");
    return runQueuedPreparedTaskSlice(false, ArchitecturePreparedBackend{
        .callback = callback,
        .callback_context = callback_context,
    }, saved_entry, before_run, after_return, hook_context);
}

pub fn runPromptedPreparedExecutionForArchitectureProof(
    callback: ArchitecturePreparedCallback,
    callback_context: *anyopaque,
    saved_entry: *const native_entry.State,
    before_run: ?ArchitecturePreparedBeforeRun,
    after_return: ?ArchitecturePreparedAfterReturn,
    hook_context: *anyopaque,
) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (comptime !architecture_smp_proof) @compileError("prompted owner fixtures require an isolated proof root");
    return runQueuedPreparedTaskSlice(true, ArchitecturePreparedBackend{
        .callback = callback,
        .callback_context = callback_context,
    }, saved_entry, before_run, after_return, hook_context);
}

fn runQueuedPreparedTaskSlice(
    comptime require_prompt: bool,
    backend: anytype,
    saved_entry: ?*const native_entry.State,
    before_run: ?ArchitecturePreparedBeforeRun,
    after_return: ?ArchitecturePreparedAfterReturn,
    hook_context: ?*anyopaque,
) bool {
    const restore_interrupts = backend.mask();
    defer backend.restore(restore_interrupts);
    if (require_prompt) {
        if (interrupt_context.active()) return false;
        if (!(dispatch_transport.global.takePrompt(cpu_identity.currentIndex()) catch return false)) return false;
    }
    var claimed: dispatch_transport.ClaimedCommand = undefined;
    dispatch_transport.global.claimInto(cpu_identity.currentIndex(), &claimed) catch return false;
    const key = claimed.key;
    if (before_run) |hook| hook(hook_context.?);
    const source = currentRegisteredExecutor();
    const ran = if (source) |executor| executor.runPreparedTaskSlice(&claimed.command, backend) else false;
    // ACK ended every issuer/source/command access. Only retained GS backing,
    // permanent fixture hooks and captured scalars precede static completion.
    if (saved_entry) |state| native_entry.current().* = state.*;
    if (after_return) |hook| hook(hook_context.?, ran);
    dispatch_transport.global.complete(key, if (ran) .owner_returned else .unstarted) catch
        @call(.never_inline, executorInvariantFailure, .{.native_dispatch_acknowledges_its_exact_execution_lease});
    return true;
}

// This backend is absent from native images. The isolated guest keeps its
// existing CPL0 stack and standard xstate policy; only user entry is replaced.
const ArchitecturePreparedBackend = if (architecture_smp_proof) struct {
    callback: ArchitecturePreparedCallback,
    callback_context: *anyopaque,

    fn ownerAvailable(_: @This()) bool {
        return !smp.isRuntimeOwner() and native_entry.current().native_entry_modes == 0 and
            continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();
    }
    fn entryReady(_: @This(), top: usize) bool {
        return top != 0 and preparedKernelStackForCpu(cpu_identity.currentIndex()) == top and
            native_entry.current().kernel_stack_top == top and native_entry.current().native_entry_modes == 0 and
            continuationCleared(native_entry.current()) and freestanding.paging.kernelAddressSpaceActive();
    }
    fn mask(_: @This()) bool {
        const enabled = x86.interruptsEnabled();
        x86.cli();
        return enabled;
    }
    fn restore(_: @This(), enabled: bool) void {
        if (enabled) x86.sti();
    }
    fn activate(_: @This(), mapping: *MappingEntry) void {
        freestanding.paging.activateUserDomain(&mapping.address_space.?, mapping.dispatch_metadata.protectionKey());
    }
    fn enter(self: @This(), executor: *Executor) void {
        _ = enterUserspaceWithClock(executor, timer, Entry{ .backend = self, .executor = executor });
        native_entry.clearContinuation();
    }
    fn switchToKernel(_: @This()) void {
        freestanding.paging.switchToKernelAddressSpace();
    }
    fn kernelActive(_: @This()) bool {
        return freestanding.paging.kernelAddressSpaceActive();
    }
    const Entry = struct {
        backend: ArchitecturePreparedBackend,
        executor: *Executor,

        fn enter(self: @This(), context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
            const entry: ArchitecturePreparedEntry = .{
                .task_id = self.executor.active_task_id,
                .physical_root = x86.readCr3() & x86.CR3_ADDRESS_MASK,
                .trap_stack_top = native_entry.current().kernel_stack_top,
                .user_context = context,
                .xstate_address = @intFromPtr(state),
                .dispatch_quantum = self.executor.dispatch_quantum,
            };
            const record = self.backend.callback(self.backend.callback_context, &entry);
            if (record.reserved != 0) @panic("isolated prepared callback returned reserved bits");
            var frame = architecturePreparedFrame(context);
            switch (record.outcome) {
                .unavailable => {},
                .yielded, .wait_for_event => {
                    frame.eax = 1;
                    frame.edx = record.ui_revision;
                    frame.esi = @backingInt(if (record.outcome == .wait_for_event)
                        userspace_bootstrap_mailbox.YieldDisposition.wait_for_event
                    else
                        userspace_bootstrap_mailbox.YieldDisposition.runnable);
                    frame.eip = context.instruction_pointer + 4;
                    handleUserspaceYield(self.executor, &frame);
                },
                .faulted => {
                    frame.int_no = record.fault_vector;
                    frame.err_code = record.fault_error_code;
                    frame.eip = record.fault_instruction_pointer;
                    if (record.fault_vector == PAGE_FAULT_VECTOR) {
                        if (record.fault_error_code & 4 == 0) @panic("isolated prepared fault must describe a user frame");
                        handleUserspacePageFaultWith(&frame, ArchitecturePreparedFault{ .address = record.fault_address });
                    } else {
                        requestUserExceptionHandoff(self.executor, .{
                            .vector = record.fault_vector,
                            .error_code = record.fault_error_code,
                            .instruction_pointer = record.fault_instruction_pointer,
                            .fault_address = record.fault_address,
                        });
                    }
                },
            }
            return 1;
        }
    };
} else struct {};

fn architecturePreparedFrame(context: *const UserContext64) freestanding.isr.InterruptFrame {
    if (comptime !architecture_smp_proof) @compileError("prepared frames require an isolated proof root");
    return .{
        .ds = freestanding.gdt.USER_DATA_SEG | 3,
        .r15 = context.r15,
        .r14 = context.r14,
        .r13 = context.r13,
        .r12 = context.r12,
        .r11 = context.r11,
        .r10 = context.r10,
        .r9 = context.r9,
        .r8 = context.r8,
        .edi = context.rdi,
        .esi = context.rsi,
        .ebp = context.rbp,
        .esp = 0,
        .ebx = context.rbx,
        .edx = context.rdx,
        .ecx = context.rcx,
        .eax = context.rax,
        .int_no = USERSPACE_TRAP_VECTOR,
        .err_code = 0,
        .eip = context.instruction_pointer,
        .cs = freestanding.gdt.USER_CODE_SEG | 3,
        .eflags = context.flags,
        .useresp = context.stack_pointer,
        .ss = freestanding.gdt.USER_DATA_SEG | 3,
    };
}

const ArchitecturePreparedFault = if (architecture_smp_proof) struct {
    address: u64,
    fn kernelFault(_: @This(), _: *freestanding.isr.InterruptFrame) void {
        @panic("isolated prepared callback escaped its user fault owner");
    }
    fn faultAddress(self: @This()) u64 {
        return self.address;
    }
    fn resolve(_: @This(), _: *freestanding.paging.UserAddressSpace, _: u64, _: u32) bool {
        @panic("AP prepared fault entered BSP demand mutation");
    }
    fn recover(_: @This(), _: *const Executor, _: *MappingEntry, _: *freestanding.isr.InterruptFrame, _: u64, _: u32) bool {
        @panic("AP prepared fault entered BSP NX recovery");
    }
    fn restoreKernel(_: @This()) void {
        freestanding.paging.switchToKernelAddressSpace();
    }
} else struct {};

inline fn publishMailboxForDispatch(mapping: *MappingEntry, update: ?BootstrapMailboxUpdate, backend: anytype) bool {
    const previous = mapping.mailbox_publication_cache;
    const publication = mailboxWriteForDispatch(mapping, update);
    if (!backend.writeMailbox(mapping, publication)) {
        mapping.mailbox_publication_cache = previous;
        return false;
    }
    if (publication != null) mapping.initial_mailbox_prepared = true;
    return true;
}

inline fn mailboxWriteForDispatch(mapping: *MappingEntry, update: ?BootstrapMailboxUpdate) ?BootstrapMailboxUpdate {
    const candidate = update orelse return null;
    const cache = &mapping.mailbox_publication_cache;
    const generation = mapping.mailbox_authority_cache.authority_generation;
    if (generation == 0) @call(.never_inline, executorInvariantFailure, .{.resolved_mailbox_authorities_require_a_nonzero_generation});
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

inline fn liveMailboxBelongsToTask(mapping: *MappingEntry, task_id: u64) bool {
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
    if (!builtin.is_test) @compileError("direct mailbox writes are hosted fixtures only");
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
    if (executor.active_dispatch_lease) |ticket| {
        const runtime = executor.bound_runtime orelse return true;
        if (runtime.execution.stopRequested(ticket)) return true;
    }
    // A missing policy callback never disables the finite dispatch watchdog.
    if (executor.dispatch_quantum.expired(executor.active_task_id, now_ticks)) return true;
    return if (smp.isRuntimeOwner()) (if (check) |priority_check| priority_check(executor.active_task_id) else false) else false;
}

fn userspaceTimerPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    const executor = currentRegisteredExecutor() orelse return;
    const priority_check = if (smp.isRuntimeOwner()) preempt_check else null;
    if (!shouldPreemptUserDispatch(executor, (frame.cs & 0x3) == 0x3, timer.getTicks(), priority_check)) return;
    const mapping = executor.active_mapping orelse return;
    handoffInterruptedUser(executor, mapping, frame);
}

fn userspaceInterruptPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if (frame.int_no == @import("../../kernel/timer/timer.zig").INTERRUPT_VECTOR) {
        userspaceTimerPreemption(frame);
    } else if (frame.int_no == smp.EXECUTION_STOP_IPI_VECTOR) {
        userspaceExecutionStopPreemption(frame);
    } else if (frame.int_no == smp.SYSCALL_REQUEST_IPI_VECTOR) {
        userspaceBrokerPreemption(frame);
    } else {
        userspaceDevicePreemption(frame);
    }
}

fn userspaceBrokerPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if (!smp.isRuntimeOwner() or (frame.cs & 3) != 3) return;
    const executor = currentRegisteredExecutor() orelse return;
    if (executor.registration_cpu != cpu_identity.currentIndex()) return;
    const mapping = activeUserMemoryMapping(executor, executor.active_task_id) orelse return;
    if (mapping.owned_xstate == null) return;
    handoffInterruptedUser(executor, mapping, frame);
}

fn userspaceExecutionStopPreemption(frame: *freestanding.isr.InterruptFrame) void {
    if ((frame.cs & 0x3) != 0x3) return;
    const index = cpu_identity.currentIndex();
    const executor = currentRegisteredExecutor() orelse return;
    if (executor.registration_cpu != index or executor.active_task_id == 0) return;
    const runtime = executor.bound_runtime orelse return;
    const ticket = executor.active_dispatch_lease orelse return;
    // The vector carries no authority. Authenticate the currently owned lease
    // on every delivery; a stale nudge must not yield a replacement execution.
    if (ticket.cpu != index or ticket.issuer != &runtime.execution or
        !runtime.execution.stopRequested(ticket)) return;
    const mapping = activeUserMemoryMapping(executor, executor.active_task_id) orelse return;
    if (mapping.owned_xstate == null) return;
    handoffInterruptedUser(executor, mapping, frame);
}

fn userspaceDevicePreemption(frame: *freestanding.isr.InterruptFrame) void {
    const executor = currentRegisteredExecutor() orelse return;
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
    if (executor.handoff_completed or native_entry.current().resume_requested != 0) return;
    mapping.resume_valid = true;
    mapping.interrupted_before_yield = true;
    captureUserContext64(mapping, frame);
    mapping.yield_count += 1;
    executor.last_yield_disposition = .runnable;
    executor.handoff_completed = true;
    native_entry.current().resume_requested = 1;
    captureMailbox(mapping);
    freestanding.paging.switchToKernelAddressSpace();
}

fn userspaceTrapHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = currentRegisteredExecutor() orelse return;
    handleUserspaceYield(executor, frame);
}

fn handleUserspaceYield(executor: *Executor, frame: anytype) void {
    if (executor.active_task_id == 0) return;
    if (executor.handoff_completed or native_entry.current().resume_requested != 0) return;
    const mapping = executor.active_mapping orelse
        @call(.never_inline, executorInvariantFailure, .{.active_userspace_task_has_no_materialized_mapping});
    const counter = std.math.cast(u32, frame.eax) orelse
        return containMalformedYield(executor, frame.eip);
    const disposition_raw = std.math.cast(u32, frame.esi) orelse
        return containMalformedYield(executor, frame.eip);
    const disposition = userspace_bootstrap_mailbox.yieldDisposition(disposition_raw) orelse
        return containMalformedYield(executor, frame.eip);
    const interrupted_before_yield = mapping.interrupted_before_yield;
    mapping.interrupted_before_yield = false;
    // An IRQ continuation may carry a parking decision made before new work
    // arrived. Return through SYSRET/ERETU for a fresh loop in this same quantum,
    // without another Scheduler dispatch charge or a new context handoff.
    if (disposition == .wait_for_event and interrupted_before_yield) return;
    const ui_revision: u64 = @intCast(frame.edx);
    executor.last_trap_counter = counter;

    mapping.resume_valid = true;
    captureUserContext64(mapping, frame);
    mapping.yield_count += 1;
    mapping.last_user_counter = executor.last_trap_counter;
    executor.last_yield_disposition = disposition;
    executor.last_yield_ui_revision = ui_revision;

    executor.handoff_completed = true;
    native_entry.current().resume_requested = 1;

    captureMailbox(mapping);
    freestanding.paging.switchToKernelAddressSpace();
}

inline fn containMalformedYield(executor: *Executor, instruction_pointer: u64) void {
    requestUserExceptionHandoff(executor, .{
        .vector = GENERAL_PROTECTION_FAULT_VECTOR,
        .error_code = 0,
        .instruction_pointer = instruction_pointer,
    });
}

inline fn requestUserExceptionHandoff(executor: *Executor, exception: UserException) void {
    executor.last_user_exception = exception;
    executor.handoff_completed = true;
    native_entry.current().resume_requested = 1;
    freestanding.paging.switchToKernelAddressSpace();
}

fn userspaceExceptionHandler(frame: *freestanding.isr.InterruptFrame) void {
    const executor = currentRegisteredExecutor() orelse freestanding.isr.haltUnhandledException(frame);
    if (executor.active_task_id == 0 or (frame.cs & 0x3) != 0x3) {
        freestanding.isr.haltUnhandledException(frame);
    }
    _ = executor.active_mapping orelse
        @call(.never_inline, executorInvariantFailure, .{.active_userspace_task_has_no_materialized_mapping});
    const vector = std.math.cast(u8, frame.int_no) orelse
        @call(.never_inline, executorInvariantFailure, .{.userspace_exception_vector_exceeds_the_idt_range});
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
    const executor = currentRegisteredExecutor() orelse
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
    native_entry.current().resume_requested = 1;
    freestanding.paging.switchToKernelAddressSpace();
}

fn isContainableUserExceptionVector(vector: u8) bool {
    return for (CONTAINABLE_USER_EXCEPTION_VECTORS) |candidate| {
        if (vector == candidate) break true;
    } else false;
}

fn userspacePageFaultHandler(frame: *freestanding.isr.InterruptFrame) void {
    handleUserspacePageFaultWith(frame, UserPageFaultHardware{});
}

const UserPageFaultHardware = struct {
    inline fn kernelFault(_: @This(), frame: *freestanding.isr.InterruptFrame) void {
        freestanding.paging.page_fault_handler(frame);
    }

    inline fn faultAddress(_: @This()) u64 {
        return x86.readCr2();
    }

    inline fn resolve(_: @This(), space: *freestanding.paging.UserAddressSpace, address: u64, code: u32) bool {
        return demand_paging.resolveFault(space, address, code);
    }

    inline fn recover(_: @This(), executor: *const Executor, mapping: *MappingEntry, frame: *freestanding.isr.InterruptFrame, address: u64, code: u32) bool {
        return nxProbeRecoveryContext(executor, mapping, frame, address, code);
    }

    inline fn restoreKernel(_: @This()) void {
        freestanding.paging.switchToKernelAddressSpace();
    }
};

inline fn handleUserspacePageFaultWith(frame: *freestanding.isr.InterruptFrame, hardware: anytype) void {
    const executor = currentRegisteredExecutor() orelse {
        hardware.kernelFault(frame);
        return;
    };
    if (executor.active_task_id == 0 or (frame.err_code & 0x4) == 0) {
        hardware.kernelFault(frame);
        return;
    }
    const mapping = executor.active_mapping orelse
        @call(.never_inline, executorInvariantFailure, .{.active_userspace_task_has_no_materialized_mapping});

    const runtime_owner = smp.isRuntimeOwner();
    const faulting_address = hardware.faultAddress();
    const error_code = std.math.cast(u32, frame.err_code) orelse
        @call(.never_inline, executorInvariantFailure, .{.userspace_page_fault_code_exceeds_its_abi_width});
    // Remote entry owns only its pinned local mapping and continuation. Demand
    // registry/COW mutation and verification Runtime lookups remain BSP work.
    if (runtime_owner) {
        if (mapping.address_space) |*space| {
            if (hardware.resolve(space, faulting_address, error_code)) return;
        }
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

    if (runtime_owner and hardware.recover(executor, mapping, frame, faulting_address, error_code)) {
        mapping.resume_valid = true;
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
    native_entry.current().resume_requested = 1;

    hardware.restoreKernel();
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

fn mappingRegistrationSource(anchor: *Executor, task_id: u64) ?*Executor {
    if (!bspMappingTransaction()) return null;
    const runtime = anchor.bound_runtime orelse return if (comptime builtin.target.os.tag == .freestanding) null else anchor;
    const owner = anchor.binding_owner orelse return if (comptime builtin.target.os.tag == .freestanding) null else anchor;
    if (registeredDomainExecutor(0, owner, runtime) != anchor) return null;
    const task = runtime.findConst(task_id) orelse return null;
    if (task.state == .terminated) return null;
    if (runtime.execution.taskTicket(task_id)) |ticket| return registeredDomainExecutor(ticket.cpu, owner, runtime);
    var selected: ?*Executor = null;
    for (0..cpu_identity.MAX_CPUS) |index| {
        const source = registeredDomainExecutor(@intCast(index), owner, runtime) orelse continue;
        const mapping = source.findMapping(task.address_space_id) orelse continue;
        if (mapping.state != .live or mapping.dispatch_metadata.owner_task_id != task_id) continue;
        if (selected != null) return null;
        selected = source;
    }
    return selected;
}

inline fn lifetimeMappingSource(anchor: *Executor, decoded: LifetimeMapping) ?*Executor {
    if (!bspMappingTransaction()) return null;
    if (anchor.bound_runtime) |runtime| {
        if (anchor.binding_owner) |owner| {
            if (registeredDomainExecutor(0, owner, runtime) != anchor) return null;
            return registeredDomainExecutor(decoded.cpu, owner, runtime);
        }
    }
    if (comptime builtin.target.os.tag == .freestanding) return null;
    return if (decoded.cpu == (anchor.registration_cpu orelse 0)) anchor else null;
}

fn registerMappedObject(
    context: *anyopaque,
    table: *shared_memory.Table,
    descriptor: shared_memory.FreestandingMappingDescriptor,
    writable: bool,
    copy_on_write: bool,
) ?u64 {
    const anchor: *Executor = @ptrCast(@alignCast(context));
    const executor = mappingRegistrationSource(anchor, descriptor.task_id.raw()) orelse return null;
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
        if (executor.bound_runtime) |runtime| {
            const task = runtime.findConst(task_id) orelse return null;
            break :blk executor.findMapping(task.address_space_id) orelse return null;
        }
        if (comptime builtin.target.os.tag != .freestanding) {
            // Custom hosted fixtures have no Runtime; production always resolves
            // BSP-owned task metadata rather than another CPU's native state.
            const active = executor.active_mapping orelse return null;
            if (active.dispatch_metadata.owner_task_id == task_id) break :blk active;
        }
        return null;
    };
    if (mapping.state != .live or mapping.dispatch_metadata.owner_task_id != task_id) return null;
    const resolution = executor.findMappingWithHandle(mapping.address_space_id) orelse return null;
    if (resolution.entry != mapping) return null;
    const token = mappingLifetimeToken(executor.registration_cpu orelse 0, resolution.handle) orelse return null;
    const space = if (mapping.address_space) |*address_space| address_space else return null;
    if (demand_paging.regionOverlapsSpace(space, descriptor.virtual_base, mapped_end)) return null;
    freestanding.paging.validateUserRangeAvailable(space, @intCast(descriptor.virtual_base), mapped_size) catch return null;
    if (!demand_paging.registerForSpace(space, .{
        .virt_start = descriptor.virtual_base,
        .virt_end_exclusive = end,
        .writable = writable,
        .kind = if (copy_on_write) .object_cow else .shared_ram,
        .physical_base = descriptor.physical_base,
    })) return null;
    executor.mapped_object_table = table;
    executor.mapped_object_count += 1;
    return token;
}

fn unregisterMappedObject(
    context: *anyopaque,
    table: *shared_memory.Table,
    registration_token: u64,
    descriptor: shared_memory.FreestandingMappingDescriptor,
) bool {
    const anchor: *Executor = @ptrCast(@alignCast(context));
    var decoded: LifetimeMapping = undefined;
    if (!decodeMappingLifetimeToken(registration_token, &decoded)) return false;
    const executor = lifetimeMappingSource(anchor, decoded) orelse return false;
    requireRetirementOwner(executor) catch return false;
    const restore_interrupts = if (comptime builtin.target.os.tag == .freestanding) x86.interruptsEnabled() else false;
    if (comptime builtin.target.os.tag == .freestanding) x86.cli();
    defer if (comptime builtin.target.os.tag == .freestanding) {
        if (restore_interrupts) x86.sti();
    };
    if (registration_token == 0 or descriptor.size_bytes == 0 or descriptor.target != null) return false;
    if (executor.mapped_object_table != table or executor.mapped_object_count == 0) return false;
    const mappings = executor.mappingArena() orelse return false;
    const slot = mappings.getByHandle(decoded.handle) orelse return false;
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
        @call(.never_inline, executorInvariantFailure, .{.userspace_entry_requires_the_active_mapping_owner});
    const storage = mapping.owned_xstate orelse
        @call(.never_inline, executorInvariantFailure, .{.userspace_entry_requires_private_extended_state});
    clock.armSchedulerTick();
    executor.dispatch_quantum = DispatchQuantum.begin(executor.active_task_id, clock.getTicks());
    // The active execution lease retains this stable arena slot through entry
    // and frame capture. Entry consumes the context before capture replaces it;
    // this borrow ends before the owner publishes its return acknowledgement.
    return entry.enter(&mapping.user_context64, storage.state());
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

fn recordUserPageFault(self: *Executor, task_id: u64, address_space_id: u64, faulting_address: u64, error_code: u32) void {
    self.last_fault_task_id = task_id;
    self.last_fault_address_space_id = address_space_id;
    self.last_fault_address = faulting_address;
    self.last_fault_error_code = error_code;
    self.user_page_fault_count += 1;
}

fn publishRootActiveTaskId(task_id: u64) void {
    if (builtin.target.os.tag != .freestanding) {
        native_entry.current().active_task_id = task_id;
        return;
    }
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

test "mapping lifetime CPU namespace retains full generations and rejects malformed tokens" {
    for (0..cpu_identity.MAX_CPUS) |index| {
        const cpu: u8 = @intCast(index);
        for ([_]u32{ 1, 0x8000_0000, std.math.maxInt(u32) }) |generation| {
            for ([_]u32{ 0, task_runtime.MAX_TASKS - 1 }) |slot| {
                const handle = MappingHandle{ .value = (@as(u64, generation) << 32) | slot };
                const token = mappingLifetimeToken(cpu, handle).?;
                var decoded: LifetimeMapping = undefined;
                try std.testing.expect(decodeMappingLifetimeToken(token, &decoded));
                try std.testing.expectEqual(cpu, decoded.cpu);
                try std.testing.expect(handle.eql(decoded.handle));
                try std.testing.expectEqual(generation, decoded.handle.generation());
            }
        }
    }
    const handle = MappingHandle{ .value = 0x0000_0001_0000_0000 };
    try std.testing.expect(mappingLifetimeToken(cpu_identity.MAX_CPUS, handle) == null);
    try std.testing.expect(mappingLifetimeToken(0, .{}) == null);
    try std.testing.expect(mappingLifetimeToken(0, .{ .value = (@as(u64, 1) << 32) | task_runtime.MAX_TASKS }) == null);
    var out = LifetimeMapping{ .cpu = 9, .handle = handle };
    const sentinel = out;
    for ([_]u64{ 0, 0xf00, handle.value | task_runtime.MAX_TASKS, handle.value | 0x1000, handle.value | 0x8000_0000 }) |invalid| {
        try std.testing.expect(!decodeMappingLifetimeToken(invalid, &out));
        try std.testing.expectEqualDeep(sentinel, out);
    }
}

test "mapping domain binding remains pinned by mappings tokens callbacks and every lease phase" {
    const previous_cpu = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    cpu_identity.setIndexForTest(0);
    executor_registrations = @splat(.{});
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    var anchor = Executor{};
    var source = Executor{};
    var owner: u8 = 0;
    var foreign_owner: u8 = 0;
    var replacement = Executor{};
    try std.testing.expect(anchor.claimRuntimeBinding(&owner, runtime));
    try std.testing.expect(source.claimRuntimeBinding(&owner, runtime));
    try std.testing.expect(anchor.claimMappingRegistration(0, &owner, runtime));
    try std.testing.expect(source.claimMappingRegistration(15, &owner, runtime));
    defer {
        cpu_identity.setIndexForTest(0);
        source.reset();
        anchor.reset();
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(previous_cpu);
    }
    try std.testing.expect(anchor.bindMappedObjectLifetime());
    const bound_anchor = anchor;
    try std.testing.expect(!anchor.releaseRuntimeBinding(&owner, runtime));
    try std.testing.expect(!anchor.releaseMappingRegistration(0, &owner, runtime));
    try std.testing.expectError(error.RegistrationMismatch, anchor.resetChecked());
    try std.testing.expectEqualDeep(bound_anchor, anchor);
    try std.testing.expect(anchor.mappedObjectLifetimeIsBound());
    try std.testing.expect(anchor.unbindMappedObjectLifetime());
    const mapping_handle = installTestMappingAt(&source, 0, .{
        .state = .live,
        .address_space_id = 42,
        .address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 },
    });
    const before_source = source;
    try std.testing.expect(!source.releaseRuntimeBinding(&owner, runtime));
    try std.testing.expect(!source.releaseMappingRegistration(15, &owner, runtime));
    try std.testing.expectEqualDeep(before_source, source);
    const ticket = try runtime.execution.prepare(15, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
    for ([_]dispatch_ownership.Phase{ .reserved, .ready, .running, .returned, .collecting }) |phase| {
        switch (phase) {
            .ready => try runtime.execution.bindOwnedRoot(ticket, mapping_handle.value, 0x1000),
            .running => {
                cpu_identity.setIndexForTest(15);
                _ = try runtime.execution.start(ticket);
                cpu_identity.setIndexForTest(0);
            },
            .returned => {
                cpu_identity.setIndexForTest(15);
                try runtime.execution.acknowledgeOwnedRootReturn(ticket);
                cpu_identity.setIndexForTest(0);
            },
            .collecting => _ = try runtime.execution.beginCollect(ticket),
            else => {},
        }
        try std.testing.expect(!source.releaseRuntimeBinding(&owner, runtime));
        try std.testing.expect(!anchor.releaseRuntimeBinding(&owner, runtime));
        try std.testing.expect(!source.releaseMappingRegistration(15, &owner, runtime));
        try std.testing.expect(!replacement.claimRuntimeBinding(&foreign_owner, runtime));
        try std.testing.expect(!releaseRegisteredDomain(&owner, runtime));
        try std.testing.expectError(error.ExecutionLeased, source.resetChecked());
        try std.testing.expectEqualDeep(before_source, source);
        try std.testing.expect(registeredExecutor(15) == &source);
    }
    try runtime.execution.finishCollect(ticket);
    runtime.lifecycle_transition_active = true;
    try std.testing.expect(!releaseRegisteredDomain(&owner, runtime));
    try std.testing.expect(!anchor.releaseRuntimeBinding(&owner, runtime));
    try std.testing.expectError(error.ExecutionLeased, source.resetChecked());
    runtime.lifecycle_transition_active = false;
    try std.testing.expect(releaseRegisteredDomain(&owner, runtime));
    try std.testing.expect(registeredExecutor(15) == null);
    try std.testing.expect(source.bound_runtime == null);
    try std.testing.expect(registeredExecutor(0) == &anchor);
    try std.testing.expectEqual(@as(usize, 0), source.materializedCount());
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

test "shared copy admission requires the registered BSP executor and IRQ exclusion" {
    const previous_index = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    defer {
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(previous_index);
    }
    executor_registrations = @splat(.{});
    cpu_identity.setIndexForTest(smp.runtimeOwnerCpu());
    var executor = Executor{};
    try std.testing.expect(serializedSharedMemoryExecutor(false) == null);
    try std.testing.expect(claimCurrentExecutor(&executor));
    try std.testing.expect(serializedSharedMemoryExecutor(false) == &executor);
    try std.testing.expect(serializedSharedMemoryExecutor(true) == null);
    executor.registration_cpu = null;
    try std.testing.expect(serializedSharedMemoryExecutor(false) == null);
    executor.registration_cpu = smp.runtimeOwnerCpu();
    const other_cpu = (smp.runtimeOwnerCpu() + 1) % cpu_identity.MAX_CPUS;
    cpu_identity.setIndexForTest(@intCast(other_cpu));
    var remote_executor = Executor{};
    try std.testing.expect(claimCurrentExecutor(&remote_executor));
    try std.testing.expect(serializedSharedMemoryExecutor(false) == null);
}

test "shared copy authority isolates grouped peers and matches the current demand registration" {
    const ids = @import("../core/ids.zig");
    demand_paging.reset();
    defer demand_paging.reset();
    var executor = Executor{};
    defer {
        executor.active_task_id = 0;
        executor.active_mapping = null;
        executor.reset();
    }
    const space = freestanding.paging.UserAddressSpace{ .directory = @ptrFromInt(0x1000), .pcid = 1 };
    const owner_handle = installTestMappingAt(&executor, 0, .{
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
    const owner_mapping = &executor.mappingArena().?.getByHandle(owner_handle).?.mapping;
    const peer_mapping = &executor.mappingArena().?.getByHandle(peer_handle).?.mapping;
    executor.active_mapping = owner_mapping;
    executor.active_mapping_handle = owner_handle;
    executor.active_task_id = 7;
    var table = shared_memory.Table.initWithMappingLifetime(.{
        .context = &executor,
        .register = registerMappedObject,
        .unregister = unregisterMappedObject,
    });
    defer table.deinit();
    const object = try table.createWithAccess(ids.task(7), PAGE_SIZE + 37, .{ .ring = true });
    try table.map(object.id, ids.task(7));
    const owner = try table.freestandingTaskMappingDescriptor(object.id, ids.task(7));
    executor.active_mapping = peer_mapping;
    executor.active_mapping_handle = peer_handle;
    executor.active_task_id = 8;
    try table.map(object.id, ids.task(8));
    const peer = try table.freestandingTaskMappingDescriptor(object.id, ids.task(8));
    try table.seal(object.id);

    const address: usize = @intCast(peer.virtual_base + PAGE_SIZE - 16);
    const accepted = sharedUserMemoryAuthority(&executor, 8, address, 32, true).?;
    try std.testing.expectEqual(peer.physical_base, accepted.authority.physical_base);
    try std.testing.expectEqual(object.size_bytes, accepted.authority.size_bytes);
    try std.testing.expect(accepted.space.directory == space.directory);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, address, 32, true) == null);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 8, @intCast(owner.virtual_base), 1, false) == null);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 8, @intCast(peer.virtual_base), object.size_bytes + 1, false) == null);

    // Both tasks share a hardware directory; only the selected task's Table
    // membership authorizes a supervisor copy of its own registered alias.
    executor.active_mapping = owner_mapping;
    executor.active_mapping_handle = owner_handle;
    executor.active_task_id = 7;
    const owner_address: usize = @intCast(owner.virtual_base);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, object.size_bytes, true) != null);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, @intCast(peer.virtual_base), 1, false) == null);
    const owner_end = owner.virtual_base + owner.size_bytes;
    const bad_regions = [_]demand_paging.Region{
        .{ .virt_start = owner.virtual_base, .virt_end_exclusive = owner_end, .writable = true, .kind = .anonymous_zero, .physical_base = owner.physical_base },
        .{ .virt_start = owner.virtual_base, .virt_end_exclusive = owner_end, .writable = true, .kind = .shared_ram, .physical_base = owner.physical_base + PAGE_SIZE },
        .{ .virt_start = owner.virtual_base, .virt_end_exclusive = owner_end, .writable = false, .kind = .shared_ram, .physical_base = owner.physical_base },
        .{ .virt_start = owner.virtual_base, .virt_end_exclusive = owner_end, .writable = true, .kind = .shared_ram, .physical_base = owner.physical_base, .protection_key = 1 },
        .{ .virt_start = owner.virtual_base, .virt_end_exclusive = owner_end + 1, .writable = true, .kind = .shared_ram, .physical_base = owner.physical_base },
    };
    for (bad_regions) |region| {
        try std.testing.expect(demand_paging.unregisterRegionForSpace(&space, owner.virtual_base, owner_end));
        try std.testing.expect(demand_paging.registerForSpace(&space, region));
        try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, 1, false) == null);
        try std.testing.expect(demand_paging.unregisterRegionForSpace(&space, region.virt_start, region.virt_end_exclusive));
        try std.testing.expect(demand_paging.registerForSpace(&space, .{
            .virt_start = owner.virtual_base,
            .virt_end_exclusive = owner_end,
            .writable = true,
            .kind = .shared_ram,
            .physical_base = owner.physical_base,
        }));
    }
    var foreign_table = shared_memory.Table.init();
    defer foreign_table.deinit();
    executor.mapped_object_table = &foreign_table;
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, 1, false) == null);
    executor.mapped_object_table = &table;
    owner_mapping.state = .retire_pending;
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, 1, false) == null);
    owner_mapping.state = .live;
    executor.active_mapping_handle = peer_handle;
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, 1, false) == null);
    executor.active_mapping_handle = owner_handle;
    _ = try table.revoke(object.id);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 7, owner_address, 1, false) == null);
    try std.testing.expect(sharedUserMemoryAuthority(&executor, 8, @intCast(peer.virtual_base), 1, false) == null);
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
    const previous_entry = native_entry.current().*;
    defer native_entry.current().* = previous_entry;
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
    try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);

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

test "foreign executor retirement rejects before mapping observations or selected GS mutation" {
    const previous_index = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    const previous_entry = native_entry.stateForCpu(1).*;
    defer {
        cpu_identity.setIndexForTest(0);
        executor_registrations = previous_registrations;
        native_entry.stateForCpu(1).* = previous_entry;
        cpu_identity.setIndexForTest(previous_index);
    }
    executor_registrations = @splat(.{});
    cpu_identity.setIndexForTest(0);
    var executor = Executor{};
    try std.testing.expect(claimCurrentExecutor(&executor));
    const handle = installTestMappingAt(&executor, 0, .{ .state = .live, .address_space_id = 42 });
    const entry = &executor.mappings.getByHandle(handle).?.mapping;
    executor.active_mapping = entry;
    executor.active_mapping_handle = handle;
    executor.active_task_id = 7;
    executor.last_fault_address_space_id = 42;
    executor.last_fault_task_id = 7;
    native_entry.stateForCpu(1).* = .{ .active_task_id = 8, .resume_requested = 19, .userspace_xstate = 0x1234 };
    const neighbor = native_entry.stateForCpu(1).*;
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.WrongCpu, executor.retireAddressSpaceChecked(.{ .address_space_id = 42, .reason = .terminate }));
    try std.testing.expectEqual(MappingState.live, entry.state);
    try std.testing.expectEqual(@as(u64, 42), executor.last_fault_address_space_id);
    try std.testing.expectEqual(@as(u64, 7), executor.last_fault_task_id);
    try std.testing.expectEqualDeep(neighbor, native_entry.stateForCpu(1).*);
    try std.testing.expect(!executor.handoff_completed);
    try std.testing.expectEqual(@as(u64, 0), executor.pending_retirements[0]);
    cpu_identity.setIndexForTest(0);
    executor.active_task_id = 0;
    executor.active_mapping = null;
    executor.active_mapping_handle = .{};
    try executor.resetChecked();
}

test "foreign unregistered executor reset preserves metadata and every continuation" {
    const previous_index = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    var previous_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_entries, 0..) |*entry, index| entry.* = native_entry.stateForCpu(@intCast(index)).*;
    defer {
        executor_registrations = previous_registrations;
        for (previous_entries, 0..) |entry, index| native_entry.stateForCpu(@intCast(index)).* = entry;
        cpu_identity.setIndexForTest(previous_index);
    }
    executor_registrations = @splat(.{});
    var executor = Executor{
        .initialized = true,
        .probe_marker_printed = true,
        .resume_marker_printed = true,
        .last_trap_counter = 19,
        .last_fault_task_id = 27,
        .last_fault_address_space_id = 42,
        .last_fault_address = 0x2000,
        .last_fault_error_code = 7,
        .user_page_fault_count = 11,
    };
    const expected = executor;
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expectError(error.WrongCpu, executor.resetChecked());
        try std.testing.expectEqualDeep(expected, executor);
        for (previous_entries, 0..) |entry, neighbor| {
            try std.testing.expectEqualDeep(entry, native_entry.stateForCpu(@intCast(neighbor)).*);
            try std.testing.expect(executor_registrations[neighbor].executor == null);
        }
    }
    cpu_identity.setIndexForTest(0);
    try executor.resetChecked();
    try std.testing.expect(!executor.initialized);
    try std.testing.expectEqual(@as(u64, 0), executor.last_fault_address_space_id);
}

test "executor pending group retirement waits for lease collection and coalesces its bitmap" {
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    cpu_identity.setIndexForTest(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    var executor = Executor{ .bound_runtime = runtime };
    defer executor.reset();
    const space = freestanding.paging.UserAddressSpace{ .directory = @ptrFromInt(0x1000), .pcid = 1 };
    executor.group_spaces[0] = space;
    executor.group_refs[0] = 2;
    const first = installTestMappingAt(&executor, 0, .{ .state = .live, .address_space_id = 42, .address_space = space });
    const peer = installTestMappingAt(&executor, 1, .{ .state = .live, .address_space_id = 43, .address_space = space });
    const ticket = try runtime.execution.prepare(0, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
    try runtime.execution.bindOwnedRoot(ticket, first.value, 0x1000);
    _ = try runtime.execution.start(ticket);
    try std.testing.expectError(error.ExecutionLeased, executor.resetChecked());
    const retirement = task_runtime.AddressSpaceRetirementEvent{ .address_space_id = 43, .reason = .terminate };
    try executor.retireAddressSpaceChecked(retirement);
    try executor.retireAddressSpaceChecked(retirement);
    try std.testing.expectEqual(MappingState.retire_pending, executor.mappings.getByHandle(peer).?.mapping.state);
    try std.testing.expectEqual(@as(u64, 2), executor.pending_retirements[0]);
    executor.collectRetiredMappings();
    try std.testing.expectEqual(@as(usize, 2), executor.materializedCount());
    try std.testing.expectEqual(@as(u8, 2), executor.group_refs[0]);
    try runtime.execution.acknowledgeOwnedRootReturn(ticket);
    executor.collectRetiredMappings();
    try std.testing.expectEqual(@as(usize, 2), executor.materializedCount());
    _ = try runtime.execution.beginCollect(ticket);
    executor.collectRetiredMappings();
    try std.testing.expect(executor.mappings.getByHandle(peer) == null);
    try std.testing.expect(executor.mappings.getByHandle(first) != null);
    try std.testing.expectEqual(@as(u8, 1), executor.group_refs[0]);
    try std.testing.expectEqual(@as(u64, 0), executor.pending_retirements[0]);
    try runtime.execution.finishCollect(ticket);
}

test "executor leased group roots reject preparation before refs mappings and mailbox change" {
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    cpu_identity.setIndexForTest(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    var executor = Executor{ .bound_runtime = runtime };
    defer executor.reset();
    const space = freestanding.paging.UserAddressSpace{ .directory = @ptrFromInt(0x1000), .pcid = 1 };
    const group = @backingInt(userspace_registry.addressSpaceGroupForBundle("app.notes").?);
    executor.group_spaces[group] = space;
    executor.group_refs[group] = 1;
    var image = std.mem.zeroes(userspace_loader.ImageRecord);
    image.id = 41;
    image.heartbeat_increment = 1;
    image.bootstrap_mailbox_address = 0x4000_3000;
    image.bundle_id_len = "app.notes".len;
    @memcpy(image.bundle_id[0..image.bundle_id_len], "app.notes");
    var address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    address_space.id = 42;
    address_space.owner_task_id = 7;
    address_space.image_id = image.id;
    address_space.entry_point = 0x4000_1000;
    address_space.stack_pointer = 0x7fff_f000;
    const metadata = try prepareMappingDispatchMetadata(7, image.id, address_space.entry_point, address_space.stack_pointer, image.id, image.bootstrap_mailbox_address, 0, 1, userspace_registry.protectionKeyForBundle("app.notes"));
    const handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = address_space.id,
        .address_space = space,
        .dispatch_metadata = metadata,
        .mailbox_captured = true,
    });
    const entry = &executor.mappings.getByHandle(handle).?.mapping;
    const expected = executor;
    const ticket = try runtime.execution.prepare(0, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
    try runtime.execution.bindOwnedRoot(ticket, handle.value, 0x1000);
    var out = MappingResolution{ .mappings = &executor.mappings, .slot_index = 99, .entry = entry, .handle = .{ .value = 77 } };
    const unchanged = out;
    for ([_]dispatch_ownership.Phase{ .ready, .running, .returned, .collecting }) |phase| {
        switch (phase) {
            .running => _ = try runtime.execution.start(ticket),
            .returned => try runtime.execution.acknowledgeOwnedRootReturn(ticket),
            .collecting => _ = try runtime.execution.beginCollect(ticket),
            else => {},
        }
        try std.testing.expect(!executor.userAddressSpacePreparationReady(&space));
        try std.testing.expectError(error.AddressSpaceLeased, executor.acquireUserAddressSpace("app.notes"));
        try std.testing.expectError(error.AddressSpaceLeased, executor.ensureMaterializedInto(&address_space, &image, &out));
        address_space.id = 43;
        address_space.owner_task_id = 8;
        try std.testing.expectError(error.AddressSpaceLeased, executor.ensureMaterializedInto(&address_space, &image, &out));
        address_space.id = 42;
        address_space.owner_task_id = 7;
        try std.testing.expectEqualDeep(unchanged, out);
        try std.testing.expectEqualDeep(expected, executor);
    }
    try runtime.execution.finishCollect(ticket);
    try std.testing.expect(executor.userAddressSpacePreparationReady(&space));
    try executor.ensureMaterializedInto(&address_space, &image, &out);
    try std.testing.expectEqual(handle.value, out.handle.value);
    try std.testing.expectEqualDeep(expected, executor);
}

test "executor owner stop preempts without invoking foreign shared scheduling policy" {
    const Policy = struct {
        var called = false;
        fn preempt(_: u64) bool {
            called = true;
            return true;
        }
    };
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    cpu_identity.setIndexForTest(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    const ticket = try runtime.execution.prepare(1, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
    try runtime.execution.bindOwnedRoot(ticket, 2, 0x1000);
    cpu_identity.setIndexForTest(1);
    _ = try runtime.execution.start(ticket);
    var mapping = MappingEntry{};
    var executor = Executor{
        .bound_runtime = runtime,
        .active_task_id = 7,
        .active_mapping = &mapping,
        .active_dispatch_lease = ticket,
        .dispatch_quantum = DispatchQuantum.begin(7, 100),
    };
    Policy.called = false;
    try std.testing.expect(!shouldPreemptUserDispatch(&executor, true, 100, Policy.preempt));
    try std.testing.expect(!Policy.called);
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(try runtime.execution.requestStop(ticket));
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(!shouldPreemptUserDispatch(&executor, false, 100, Policy.preempt));
    try std.testing.expect(shouldPreemptUserDispatch(&executor, true, 100, Policy.preempt));
    try std.testing.expect(!Policy.called);
    try runtime.execution.acknowledgeOwnedRootReturn(ticket);
    cpu_identity.setIndexForTest(0);
    _ = try runtime.execution.beginCollect(ticket);
    try runtime.execution.finishCollect(ticket);
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
    const previous_executor = currentRegisteredExecutor();
    const previous_entry = native_entry.current().*;
    defer {
        executor.active_task_id = 0;
        executor.active_mapping = null;
        executor.reset();
        currentExecutorSlot().* = previous_executor;
        native_entry.current().* = previous_entry;
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
    native_entry.current().resume_requested = 0;
    var frame = YieldTestFrame{ .eax = counter, .esi = disposition };
    // The explicit owner yield frame replaces any previous dispatch outcome.
    executor.last_yield_disposition = if (expected == .wait_for_event) .runnable else .wait_for_event;
    const before = frame;
    // This is the production handler body; only the compiler-known frame type
    // differs from the entry assembly's Registers pointer.
    handleUserspaceYield(&executor, &frame);
    try std.testing.expectEqualDeep(before, frame);
    try std.testing.expect(executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
    try std.testing.expectEqual(@as(u64, 7), executor.active_task_id);
    try std.testing.expect(executor.active_mapping == mapping);
    if (expected) |valid| {
        try std.testing.expect(executor.last_user_exception == null);
        try std.testing.expectEqual(valid, executor.last_yield_disposition);
        try std.testing.expectEqual(@as(u32, @intCast(counter)), mapping.last_user_counter);
        try std.testing.expectEqual(@as(u64, 9), mapping.yield_count);
        try std.testing.expect(mapping.resume_valid);
        try std.testing.expectEqual(frame.eip, mapping.user_context64.instruction_pointer);
        try std.testing.expectEqual(frame.useresp, mapping.user_context64.stack_pointer);
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
    const previous_entry = native_entry.current().*;
    defer native_entry.current().* = previous_entry;
    for ([_]u8{ 7, GENERAL_PROTECTION_FAULT_VECTOR }) |vector| {
        native_entry.current().resume_requested = 0;
        executor.handoff_completed = false;
        try std.testing.expect(containUserException(&executor, vector, 0, 0x4000_1008));
        try std.testing.expectEqual(vector, executor.last_user_exception.?.vector);
        try std.testing.expect(executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
    }
    executor.last_user_exception = null;
    executor.handoff_completed = false;
    native_entry.current().resume_requested = 0;
    try std.testing.expect(!containUserException(&executor, 2, 0, 0x4000_1008));
    try std.testing.expect(executor.last_user_exception == null);
    try std.testing.expect(!executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 0), native_entry.current().resume_requested);
}

const RemoteSyscallTestHardware = if (builtin.is_test) struct {
    const Mode = enum { complete, stop_pending, stop_processing };
    runtime: *task_runtime.Runtime,
    ticket: dispatch_ownership.Ticket,
    mode: Mode,
    enabled: bool = false,
    kernel: bool = false,
    notified: u8 = 0,
    waits: u8 = 0,
    restored_user: bool = false,
    claim: ?dispatch_ownership.ClaimedSyscall = null,

    fn mask(self: *@This()) bool {
        const previous = self.enabled;
        self.enabled = false;
        return previous;
    }
    fn restore(self: *@This(), enabled: bool) void {
        self.enabled = enabled;
    }
    fn switchToKernel(self: *@This()) void {
        self.kernel = true;
    }
    fn kernelActive(self: *@This()) bool {
        return self.kernel;
    }
    fn restoreUser(self: *@This(), _: *MappingEntry) void {
        std.testing.expect(!self.enabled and self.runtime.execution.syscallIdle(self.ticket)) catch @panic("restore only drained user");
        self.kernel = false;
        self.restored_user = true;
    }
    fn notify(self: *@This()) bool {
        std.testing.expect(self.kernel and !self.enabled) catch @panic("publish only parked kernel");
        std.testing.expectError(error.SyscallInFlight, self.runtime.execution.acknowledgeOwnedRootReturn(self.ticket)) catch @panic("pending request blocks return ACK");
        self.notified += 1;
        const owner = cpu_identity.currentIndex();
        cpu_identity.setIndexForTest(0);
        defer cpu_identity.setIndexForTest(owner);
        if (self.mode == .stop_pending) {
            _ = self.runtime.execution.requestStop(self.ticket) catch @panic("publish pending STOP");
        } else if (self.mode == .stop_processing) {
            var claim: dispatch_ownership.ClaimedSyscall = undefined;
            self.runtime.execution.claimSyscallInto(owner, &claim) catch @panic("claim before STOP");
            self.claim = claim;
            _ = self.runtime.execution.requestStop(self.ticket) catch @panic("publish processing STOP");
        }
        return true;
    }
    fn wait(self: *@This()) void {
        std.testing.expect(!self.enabled and self.kernel) catch @panic("wait must start parked IF0");
        self.enabled = true;
        self.waits += 1;
        // The real owner body allows architecture interrupts while waiting.
        // This hardware callback models BSP progress, using the real protocol.
        const owner = cpu_identity.currentIndex();
        cpu_identity.setIndexForTest(0);
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        if (self.claim) |prior| claim = prior else self.runtime.execution.claimSyscallInto(owner, &claim) catch @panic("claim queued syscall");
        self.runtime.execution.completeSyscall(claim.key, .{ .status = 9, .denial_reason = 4, .bytes_written = 17 }) catch @panic("complete exact syscall");
        cpu_identity.setIndexForTest(owner);
        self.enabled = false;
        std.testing.expectError(error.SyscallInFlight, self.runtime.execution.acknowledgeOwnedRootReturn(self.ticket)) catch @panic("unconsumed reply blocks return ACK");
    }
    fn fail(_: *@This()) noreturn {
        @panic("unexpected remote syscall ownership failure");
    }

    fn expectRejected(self: *@This(), fixture: *DeviceInterruptFixture) !void {
        const before_frame = fixture.frame;
        const before_entry = native_entry.current().*;
        const before_context = fixture.mapping.user_context64;
        const before_if = self.enabled;
        try std.testing.expect(!remoteSyscallWithHardware(&fixture.frame, self));
        try std.testing.expectEqual(before_if, self.enabled);
        try std.testing.expect(!self.kernel and !self.restored_user);
        try std.testing.expectEqual(@as(u8, 0), self.notified);
        try std.testing.expectEqual(@as(u8, 0), self.waits);
        try std.testing.expectEqualDeep(before_frame, fixture.frame);
        try std.testing.expectEqualDeep(before_entry, native_entry.current().*);
        try std.testing.expectEqualDeep(before_context, fixture.mapping.user_context64);
        try std.testing.expect(!fixture.executor.handoff_completed);
    }
} else struct {};

test "broker copy session authenticates processing receipt without BSP active-task substitution" {
    const previous_cpu = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    cpu_identity.setIndexForTest(0);
    executor_registrations = @splat(.{});
    const runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.OutOfMemory;
    runtime.initializeAllocated();
    var executor = Executor{};
    var anchor = Executor{};
    const owner: *const anyopaque = runtime;
    try std.testing.expect(anchor.claimRuntimeBinding(owner, runtime));
    try std.testing.expect(anchor.claimMappingRegistration(0, owner, runtime));
    try std.testing.expect(executor.claimRuntimeBinding(owner, runtime));
    try std.testing.expect(executor.claimMappingRegistration(1, owner, runtime));
    defer {
        cpu_identity.setIndexForTest(0);
        executor.active_mapping = null;
        executor.active_task_id = 0;
        executor.reset();
        anchor.reset();
        runtime.reset();
        table_backing.free(task_runtime.Runtime, runtime);
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(previous_cpu);
    }

    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 41 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = units.kibibytes(64), .endpoint_slots = 2, .shared_memory_bytes = units.kibibytes(4) },
        .ui_surface_id = 7,
        .local_only = true,
    });
    const handle = installTestMappingAt(&executor, 0, .{
        .state = .live,
        .address_space_id = task.address_space_id,
        .address_space = .{ .directory = @ptrFromInt(0x1000), .pcid = 1 },
        .dispatch_metadata = .{ .owner_task_id = task.id },
    });
    const mapping = &executor.mappingArena().?.getByHandle(handle).?.mapping;
    const record = runtime.findAddressSpace(task.address_space_id).?;
    record.region_count = 1;
    record.regions[0] = .{ .kind = .load_segment, .virtual_address = 0x4000_0000, .size_bytes = 8192, .file_offset = 0, .file_size = 0, .access = .{ .read = true } };
    var backing: [8192]u8 = undefined;
    for (&backing, 0..) |*byte, index| byte.* = @truncate(index * 13);
    var pages = SyscallCopyTesting.Pages{ .directory = mapping.address_space.?.directory, .virtual_base = 0x4000_0000, .bytes = &backing };
    const previous_pages = SyscallCopyTesting.pages;
    SyscallCopyTesting.pages = &pages;
    defer SyscallCopyTesting.pages = previous_pages;
    executor.active_task_id = task.id + 1;
    // The BSP has an unrelated active identity. Only the claimed receipt may
    // select the remote mapping; changing that incidental identity is irrelevant.
    const ticket = try runtime.reserveExecution(task, 1);
    try runtime.execution.bindOwnedRoot(ticket, handle.value, 0x1000);
    cpu_identity.setIndexForTest(1);
    _ = try runtime.execution.start(ticket);
    var key: dispatch_ownership.RequestKey = undefined;
    try runtime.execution.submitSyscallInto(ticket, .{ .opcode = 0x101, .request_addr = 0x4000_1000, .response_addr = 0, .response_len = 0 }, &key);
    cpu_identity.setIndexForTest(0);
    var claim: dispatch_ownership.ClaimedSyscall = undefined;
    try runtime.execution.claimSyscallInto(1, &claim);
    var session: syscall_broker.CopySession = undefined;
    try std.testing.expect(anchor.prepareSyscallCopySession(&claim, &session));
    try std.testing.expect(session.context == @as(*anyopaque, &anchor));
    try std.testing.expectEqualDeep(claim.key, session.key);
    var bytes: [16]u8 = @splat(0x5a);
    try std.testing.expect(session.read(session.context, &claim, 0x4000_0ff8, &bytes));
    try std.testing.expectEqualSlices(u8, backing[4088..4104], &bytes);
    try std.testing.expectEqual(@as(usize, 1), pages.reads);
    pages.readable = false;
    bytes = @splat(0x5a);
    try std.testing.expect(!session.read(session.context, &claim, 0x4000_0ff8, &bytes));
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x5a)), &bytes);
    pages.readable = true;
    try std.testing.expect(!session.read(session.context, &claim, 0x4000_1ff8, &bytes));
    try std.testing.expectEqual(@as(usize, 1), pages.reads);
    var denied: SyscallCopyMapping = undefined;
    try std.testing.expect(!syscallCopyMappingInto(&anchor, &claim, true, true, &denied));
    try std.testing.expect(!syscallCopyMappingInto(&anchor, &claim, false, false, &denied));
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    cpu_identity.setIndexForTest(0);
    const original_session = session;
    inline for (.{ "mapping_handle", "physical_root" }) |field| {
        var forged = claim;
        @field(forged.bound, field) += 4096;
        try std.testing.expect(!anchor.prepareSyscallCopySession(&forged, &session));
        try std.testing.expectEqualDeep(original_session, session);
    }
    inline for (.{ "task_handle", "task_id", "process_generation", "address_space_id" }) |field| {
        var forged = claim;
        @field(forged.bound.identity, field) += 1;
        try std.testing.expect(!anchor.prepareSyscallCopySession(&forged, &session));
        try std.testing.expectEqualDeep(original_session, session);
    }
    mapping.dispatch_metadata.owner_task_id += 1;
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    mapping.dispatch_metadata.owner_task_id -= 1;
    mapping.address_space.?.directory = @ptrFromInt(0x2000);
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    mapping.address_space.?.directory = @ptrFromInt(0x1000);
    mapping.state = .retire_pending;
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    mapping.state = .live;
    task.process_generation += 1;
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    task.process_generation -= 1;
    try std.testing.expect(anchor.prepareSyscallCopySession(&claim, &session));
    demand_paging.reset();
    defer demand_paging.reset();
    var table = shared_memory.Table.initWithMappingLifetime(.{ .context = &anchor, .register = registerMappedObject, .unregister = unregisterMappedObject });
    defer table.deinit();
    const object = try table.createWithAccess(@import("../core/ids.zig").task(task.id), PAGE_SIZE + 37, .{ .ring = true });
    try table.map(object.id, @import("../core/ids.zig").task(task.id));
    try table.seal(object.id);
    const shared = try table.freestandingTaskMappingDescriptor(object.id, @import("../core/ids.zig").task(task.id));
    pages.virtual_base = @intCast(shared.virtual_base);
    bytes = @splat(0x5a);
    try std.testing.expect(session.read(session.context, &claim, pages.virtual_base + PAGE_SIZE - 8, &bytes));
    try std.testing.expectEqualSlices(u8, backing[4088..4104], &bytes);
    const successful_reads = pages.reads;
    bytes = @splat(0x5a);
    try std.testing.expect(!session.read(session.context, &claim, pages.virtual_base + object.size_bytes - 8, &bytes));
    try std.testing.expectEqual(successful_reads, pages.reads);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x5a)), &bytes);
    _ = try table.revoke(object.id);
    try std.testing.expect(!session.read(session.context, &claim, pages.virtual_base, &bytes));
    try std.testing.expectEqual(successful_reads, pages.reads);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x5a)), &bytes);
    try runtime.execution.completeSyscall(key, .{ .status = 0, .denial_reason = 0, .bytes_written = 0 });
    bytes = @splat(0x5a);
    try std.testing.expect(!session.read(session.context, &claim, 0x4000_1000, &bytes));
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x5a)), &bytes);
    try std.testing.expect(!anchor.prepareSyscallCopySession(&claim, &session));
    cpu_identity.setIndexForTest(1);
    var reply: dispatch_ownership.Reply = undefined;
    try runtime.execution.consumeSyscallInto(key, &reply);
    try runtime.execution.acknowledgeOwnedRootReturn(ticket);
    cpu_identity.setIndexForTest(0);
    try runtime.collectExecution(ticket);
}

test "broker mapping domain routes all sixteen colliding handles and retains exact shared tokens" {
    const ids = @import("../core/ids.zig");
    const previous_cpu = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    cpu_identity.setIndexForTest(0);
    executor_registrations = @splat(.{});
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    const sources = try std.testing.allocator.alloc(Executor, cpu_identity.MAX_CPUS);
    defer std.testing.allocator.free(sources);
    var owner: u8 = 0;
    var foreign_owner: u8 = 0;
    var tasks: [cpu_identity.MAX_CPUS]*task_runtime.TaskRecord = undefined;
    var tickets: [cpu_identity.MAX_CPUS]?dispatch_ownership.Ticket = @splat(null);
    var keys: [cpu_identity.MAX_CPUS]?dispatch_ownership.RequestKey = @splat(null);
    var handles: [cpu_identity.MAX_CPUS]MappingHandle = undefined;
    for (sources, 0..) |*source, index| {
        source.* = .{};
        try std.testing.expect(source.claimRuntimeBinding(&owner, runtime));
        try std.testing.expect(source.claimMappingRegistration(@intCast(index), &owner, runtime));
        const task = try runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = index + 1 },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 8192, .endpoint_slots = 2, .shared_memory_bytes = 8192 },
            .local_only = true,
        });
        tasks[index] = task;
        const physical: usize = (index + 1) * PAGE_SIZE;
        handles[index] = installTestMappingAt(source, 0, .{
            .state = .live,
            .address_space_id = task.address_space_id,
            .address_space = .{ .directory = @ptrFromInt(physical), .pcid = @intCast(index), .switch_cr3 = physical | index },
            .dispatch_metadata = .{ .owner_task_id = task.id },
        });
        try std.testing.expect(handles[index].eql(handles[0]));
        const record = runtime.findAddressSpace(task.address_space_id).?;
        record.region_count = 1;
        record.regions[0] = .{ .kind = .load_segment, .virtual_address = 0x4000_0000, .size_bytes = 8192, .file_offset = 0, .file_size = 0, .access = .{ .read = true, .write = true } };
    }
    defer {
        for (tickets, 0..) |optional, index| if (optional) |ticket| {
            cpu_identity.setIndexForTest(0);
            if (keys[index]) |key| runtime.execution.completeSyscall(key, .{ .status = 0, .denial_reason = 0, .bytes_written = 0 }) catch {};
            cpu_identity.setIndexForTest(ticket.cpu);
            if (keys[index]) |key| {
                _ = runtime.execution.cancelPendingSyscall(key);
                var reply: dispatch_ownership.Reply = undefined;
                runtime.execution.consumeSyscallInto(key, &reply) catch {};
            }
            runtime.execution.acknowledgeOwnedRootReturn(ticket) catch {};
            cpu_identity.setIndexForTest(0);
            runtime.collectExecution(ticket) catch {};
        };
        cpu_identity.setIndexForTest(0);
        _ = releaseRegisteredDomain(&owner, runtime);
        sources[0].reset();
        runtime.reset();
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(previous_cpu);
    }
    demand_paging.reset();
    defer demand_paging.reset();
    var table = shared_memory.Table.initWithMappingLifetime(sources[0].mappedObjectLifetime());
    defer table.deinit();
    const objects = [_]shared_memory.Object{
        try table.createWithAccess(ids.task(tasks[0].id), PAGE_SIZE + 37, .{ .ring = true }),
        try table.createWithAccess(ids.task(tasks[8].id), PAGE_SIZE + 37, .{ .ring = true }),
    };
    // A task's live lease resolves the otherwise coincident arena-local handle.
    for (tasks, 0..) |task, index| {
        const cpu: u8 = @intCast(index);
        const ticket = try runtime.reserveExecution(task, cpu);
        tickets[index] = ticket;
        try runtime.execution.bindOwnedRoot(ticket, handles[index].value, (index + 1) * PAGE_SIZE);
        cpu_identity.setIndexForTest(cpu);
        _ = try runtime.execution.start(ticket);
        var key: dispatch_ownership.RequestKey = undefined;
        try runtime.execution.submitSyscallInto(ticket, .{ .opcode = 0x101, .request_addr = 0x4000_0010, .response_addr = 0, .response_len = 0 }, &key);
        keys[index] = key;
        cpu_identity.setIndexForTest(0);
        try table.map(objects[index / shared_memory.MAX_MAPPINGS_PER_OBJECT].id, ids.task(task.id));
    }
    for (objects) |object| try table.seal(object.id);
    var backing: [8192]u8 = undefined;
    var pages = SyscallCopyTesting.Pages{ .directory = @ptrFromInt(PAGE_SIZE), .virtual_base = 0x4000_0000, .bytes = &backing };
    const previous_pages = SyscallCopyTesting.pages;
    SyscallCopyTesting.pages = &pages;
    defer SyscallCopyTesting.pages = previous_pages;
    for (tasks, 0..) |task, index| {
        const source = &sources[index];
        const mapping = &source.mappingArena().?.getByHandle(handles[index]).?.mapping;
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        try runtime.execution.claimSyscallInto(@intCast(index), &claim);
        var session: syscall_broker.CopySession = undefined;
        try std.testing.expect(sources[0].prepareSyscallCopySession(&claim, &session));
        const expected_session = session;
        pages.directory = mapping.address_space.?.directory;
        pages.virtual_base = 0x4000_0000;
        @memset(&backing, @intCast(index + 1));
        var output: [16]u8 = @splat(0x5a);
        try std.testing.expect(session.read(session.context, &claim, 0x4000_0010, &output));
        try std.testing.expectEqualSlices(u8, backing[16..32], &output);
        const private_base = pages.virtual_base;
        const before_preparation = pages.preparations;
        try std.testing.expect(session.prepare_output(session.context, &claim, .{ .address = private_base, .declared_bytes = backing.len, .prepared_bytes = 0, .alignment = 8 }));
        try std.testing.expectEqual(before_preparation, pages.preparations);
        try std.testing.expect(!session.prepare_output(session.context, &claim, .{ .address = private_base, .declared_bytes = backing.len + 1, .prepared_bytes = 32, .alignment = 1 }));
        try std.testing.expectEqual(before_preparation, pages.preparations);
        try std.testing.expect(session.prepare_output(session.context, &claim, .{ .address = private_base + PAGE_SIZE - 16, .declared_bytes = 88, .prepared_bytes = 88, .alignment = 1 }));
        const first_payload: [88]u8 = @splat(0x31);
        const second_payload: [64]u8 = @splat(0x62);
        const third_payload: [56]u8 = @splat(0x93);
        const outputs = [_]syscall_broker.Output{
            .{ .address = private_base + PAGE_SIZE - 16, .bytes = &first_payload },
            .{ .address = private_base + PAGE_SIZE + 128, .bytes = &second_payload },
            .{ .address = private_base + 128, .bytes = &third_payload },
        };
        const saved_payload = backing;
        pages.invalid_page = 1;
        try std.testing.expect(!session.write_outputs(session.context, &claim, &outputs));
        try std.testing.expectEqualSlices(u8, &saved_payload, &backing);
        // A valid early output must remain untouched when a later output's
        // second page is invalid, rather than copying one output at a time.
        try std.testing.expect(!session.write_outputs(session.context, &claim, &.{ outputs[2], outputs[0], outputs[1] }));
        try std.testing.expectEqualSlices(u8, &saved_payload, &backing);
        pages.invalid_page = null;
        var overlapping = outputs;
        overlapping[2].address = outputs[1].address;
        try std.testing.expect(!session.write_outputs(session.context, &claim, &overlapping));
        try std.testing.expectEqualSlices(u8, &saved_payload, &backing);
        const oversized: [89]u8 = @splat(0);
        try std.testing.expect(!session.write_outputs(session.context, &claim, &.{.{ .address = private_base, .bytes = &oversized }}));
        try std.testing.expect(!session.write_outputs(session.context, &claim, &.{ outputs[0], outputs[1], outputs[2], outputs[2] }));
        try std.testing.expect(!session.write_outputs(session.context, &claim, &.{ outputs[0], .{ .address = private_base + 512, .bytes = &first_payload }, .{ .address = private_base + 1024, .bytes = &first_payload } }));
        inline for (.{
            syscall_broker.OutputRange{ .address = private_base + 1, .declared_bytes = 64, .prepared_bytes = 64, .alignment = 8 },
            syscall_broker.OutputRange{ .address = private_base, .declared_bytes = 64, .prepared_bytes = 64, .alignment = 3 },
            syscall_broker.OutputRange{ .address = private_base, .declared_bytes = 64, .prepared_bytes = 65, .alignment = 1 },
            syscall_broker.OutputRange{ .address = private_base, .declared_bytes = 89, .prepared_bytes = 89, .alignment = 1 },
            syscall_broker.OutputRange{ .address = std.math.maxInt(usize) - 7, .declared_bytes = 64, .prepared_bytes = 64, .alignment = 1 },
            syscall_broker.OutputRange{ .address = 0x0000_8000_0000_0000, .declared_bytes = 64, .prepared_bytes = 64, .alignment = 1 },
        }) |range| try std.testing.expect(!session.prepare_output(session.context, &claim, range));
        try std.testing.expect(session.prepare_output(session.context, &claim, .{ .address = std.math.maxInt(usize), .declared_bytes = 0, .prepared_bytes = 0, .alignment = 0 }));
        pages.forced_alias_offset = 0;
        try std.testing.expect(!session.write_outputs(session.context, &claim, &outputs));
        try std.testing.expectEqualSlices(u8, &saved_payload, &backing);
        pages.forced_alias_offset = null;
        try std.testing.expect(session.write_outputs(session.context, &claim, &outputs));
        var expected = saved_payload;
        for (outputs) |destination| @memcpy(expected[destination.address - private_base ..][0..destination.bytes.len], destination.bytes);
        try std.testing.expectEqualSlices(u8, &expected, &backing);
        const successful_reads = pages.reads;
        const saved_space = mapping.address_space.?;
        mapping.address_space.?.directory = @ptrFromInt((cpu_identity.MAX_CPUS + 1) * PAGE_SIZE);
        try std.testing.expect(!sources[0].prepareSyscallCopySession(&claim, &session));
        try std.testing.expectEqualDeep(expected_session, session);
        mapping.address_space = saved_space;
        mapping.address_space.?.switch_cr3 += PAGE_SIZE;
        try std.testing.expect(!session.read(session.context, &claim, 0x4000_0010, &output));
        mapping.address_space = saved_space;
        if (index != 0) {
            source.binding_owner = &foreign_owner;
            try std.testing.expect(!session.read(session.context, &claim, 0x4000_0010, &output));
            source.binding_owner = &owner;
        }
        source.registration_cpu = @intCast((index + 1) % cpu_identity.MAX_CPUS);
        try std.testing.expect(!session.read(session.context, &claim, 0x4000_0010, &output));
        source.registration_cpu = @intCast(index);
        try std.testing.expectEqual(successful_reads, pages.reads);
        const object = objects[index / shared_memory.MAX_MAPPINGS_PER_OBJECT];
        const shared = try table.freestandingTaskMappingDescriptor(object.id, ids.task(task.id));
        pages.virtual_base = @intCast(shared.virtual_base);
        var span: shared_memory.TaskCopySpan = undefined;
        const token = mappingLifetimeToken(@intCast(index), handles[index]).?;
        try table.taskCopySpanInto(ids.task(task.id), token, pages.virtual_base, 1, &span);
        const wrong_cpu: u8 = @intCast((index + 1) % cpu_identity.MAX_CPUS);
        try std.testing.expectError(error.StaleMappingDescriptor, table.taskCopySpanInto(ids.task(task.id), mappingLifetimeToken(wrong_cpu, handles[index]).?, pages.virtual_base, 1, &span));
        try std.testing.expect(session.read(session.context, &claim, pages.virtual_base + PAGE_SIZE - 8, &output));
        try std.testing.expectEqualSlices(u8, backing[PAGE_SIZE - 8 .. PAGE_SIZE + 8], &output);
        const shared_address = pages.virtual_base;
        const shared_preparations = pages.preparations;
        try std.testing.expect(session.prepare_output(session.context, &claim, .{ .address = shared_address, .declared_bytes = object.size_bytes, .prepared_bytes = 0, .alignment = 1 }));
        try std.testing.expectEqual(shared_preparations, pages.preparations);
        try std.testing.expect(!session.prepare_output(session.context, &claim, .{ .address = shared_address, .declared_bytes = object.size_bytes + 1, .prepared_bytes = 16, .alignment = 1 }));
        try std.testing.expectEqual(shared_preparations, pages.preparations);
        const shared_payload: [32]u8 = @splat(0xC4);
        const shared_outputs = [_]syscall_broker.Output{
            .{ .address = shared_address + PAGE_SIZE - 16, .bytes = &shared_payload },
            .{ .address = shared_address + 128, .bytes = &shared_payload },
        };
        try std.testing.expect(session.prepare_output(session.context, &claim, .{ .address = shared_outputs[0].address, .declared_bytes = 32, .prepared_bytes = 32, .alignment = 1 }));
        const shared_before = backing;
        pages.invalid_page = 1;
        try std.testing.expect(!session.write_outputs(session.context, &claim, &shared_outputs));
        try std.testing.expectEqualSlices(u8, &shared_before, &backing);
        pages.invalid_page = null;
        try std.testing.expect(session.write_outputs(session.context, &claim, &shared_outputs));
        @memcpy(expected[0..], &shared_before);
        for (shared_outputs) |destination| @memcpy(expected[destination.address - shared_address ..][0..destination.bytes.len], destination.bytes);
        try std.testing.expectEqualSlices(u8, &expected, &backing);
        const before_source = source.*;
        try std.testing.expect(!source.releaseRuntimeBinding(&owner, runtime));
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&before_source), std.mem.asBytes(source));
        const StopDuringResolution = struct {
            var selected_runtime: *task_runtime.Runtime = undefined;
            var selected_source: *Executor = undefined;
            var selected_ticket: dispatch_ownership.Ticket = undefined;
            var observed_retention = false;
            fn run() void {
                const prior = selected_source.*;
                const selected_owner = selected_source.binding_owner.?;
                observed_retention = !selected_source.releaseRuntimeBinding(selected_owner, selected_runtime);
                selected_source.resetChecked() catch {};
                observed_retention = observed_retention and std.mem.eql(u8, std.mem.asBytes(&prior), std.mem.asBytes(selected_source));
                _ = selected_runtime.execution.requestStop(selected_ticket) catch unreachable;
            }
        };
        StopDuringResolution.selected_runtime = runtime;
        StopDuringResolution.selected_source = source;
        StopDuringResolution.selected_ticket = tickets[index].?;
        StopDuringResolution.observed_retention = false;
        pages.before_resolve = StopDuringResolution.run;
        const stopped_before = backing;
        try std.testing.expect(!session.write_outputs(session.context, &claim, &shared_outputs));
        try std.testing.expect(StopDuringResolution.observed_retention);
        try std.testing.expectEqualSlices(u8, &stopped_before, &backing);
        pages.before_resolve = null;
        try runtime.execution.completeSyscall(keys[index].?, .{ .status = 0, .denial_reason = 0, .bytes_written = 0 });
        try std.testing.expect(!session.read(session.context, &claim, pages.virtual_base, &output));
        cpu_identity.setIndexForTest(@intCast(index));
        var reply: dispatch_ownership.Reply = undefined;
        try runtime.execution.consumeSyscallInto(keys[index].?, &reply);
        try runtime.execution.acknowledgeOwnedRootReturn(tickets[index].?);
        cpu_identity.setIndexForTest(0);
        try runtime.collectExecution(tickets[index].?);
        tickets[index] = null;
        keys[index] = null;
        // Releasing this exact task/token leaves every foreign CPU's equal
        // numeric MappingHandle membership and demand registration intact.
        source.retireAddressSpace(.{ .address_space_id = task.address_space_id, .reason = .terminate });
        try std.testing.expect(!table.hasMapping(object.id, ids.task(task.id)));
        for (tasks[index + 1 ..], index + 1..) |neighbor, cpu| {
            try std.testing.expect(table.hasMapping(objects[cpu / shared_memory.MAX_MAPPINGS_PER_OBJECT].id, ids.task(neighbor.id)));
            try std.testing.expectEqual(@as(u16, 1), sources[cpu].mapped_object_count);
        }
    }
    for (objects) |object| try std.testing.expectEqual(@as(u16, 0), (try table.descriptor(object.id)).mapped_task_count);
    try std.testing.expect(releaseRegisteredDomain(&owner, runtime));
    for (sources[1..]) |*source| {
        try std.testing.expect(source.registration_cpu == null and source.bound_runtime == null);
        try std.testing.expectEqual(@as(usize, 0), source.materializedCount());
    }
}

test "scheduler broker drain services exact remote mappings and excludes callback reentry" {
    const abi = @import("../core/abi.zig");
    const component_port = @import("../kernel_api/component_port.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const userspace_scheduler = @import("userspace_scheduler.zig");
    const previous_cpu = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    cpu_identity.setIndexForTest(0);
    executor_registrations = @splat(.{});
    const runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.OutOfMemory;
    runtime.initializeAllocated();
    const foreign_runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.OutOfMemory;
    foreign_runtime.initializeAllocated();
    var executor = Executor{};
    var sources: [3]Executor = @splat(.{});
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, runtime, &capabilities, &endpoints, &shared);
    var port = component_port.KernelPort.init(&kernel);
    scheduler.bind(&catalog, runtime, &capabilities);
    try std.testing.expect(executor.claimMappingRegistration(0, &scheduler, runtime));
    for (&sources, 0..) |*source, index| {
        try std.testing.expect(source.claimRuntimeBinding(&scheduler, runtime));
        try std.testing.expect(source.claimMappingRegistration(@intCast(index + 1), &scheduler, runtime));
    }
    var tickets: [3]?dispatch_ownership.Ticket = @splat(null);
    var keys: [3]?dispatch_ownership.RequestKey = @splat(null);
    defer {
        for (tickets, 0..) |optional_ticket, index| if (optional_ticket) |ticket| {
            cpu_identity.setIndexForTest(ticket.cpu);
            if (keys[index]) |key| {
                _ = runtime.execution.cancelPendingSyscall(key);
                cpu_identity.setIndexForTest(0);
                runtime.execution.completeSyscall(key, .{ .status = 0, .denial_reason = 0, .bytes_written = 0 }) catch {};
                cpu_identity.setIndexForTest(ticket.cpu);
                var reply: dispatch_ownership.Reply = undefined;
                runtime.execution.consumeSyscallInto(key, &reply) catch {};
            }
            runtime.execution.acknowledgeOwnedRootReturn(ticket) catch {};
            cpu_identity.setIndexForTest(0);
            runtime.collectExecution(ticket) catch {};
        };
        cpu_identity.setIndexForTest(0);
        scheduler.deinit();
        runtime.reset();
        endpoints.deinit();
        shared.deinit();
        kernel.deinit();
        table_backing.free(task_runtime.Runtime, foreign_runtime);
        table_backing.free(task_runtime.Runtime, runtime);
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(previous_cpu);
    }
    const Reentry = struct {
        scheduler: *userspace_scheduler.Scheduler,
        port: *component_port.KernelPort,
        calls: usize = 0,
        fn notify(context: *anyopaque, _: dispatch_ownership.Ticket) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            std.testing.expectEqual(@as(u8, 0), self.scheduler.servicePendingSyscalls(self.port, 10)) catch @panic("broker callback cannot recursively claim work");
        }
    };
    var reentry = Reentry{ .scheduler = &scheduler, .port = &port };
    const sink = task_runtime.ExecutionStopSink{ .context = &reentry, .notify = Reentry.notify };
    try std.testing.expect(runtime.bindExecutionStopSink(sink));
    var tasks: [3]*task_runtime.TaskRecord = undefined;
    var first_mapping: *MappingEntry = undefined;
    for (&tasks, 0..) |*task_out, index| {
        const cpu: u8 = @intCast(index + 1);
        const task = try runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = @as(u64, cpu) + 1 },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 8192, .endpoint_slots = 2, .shared_memory_bytes = 0 },
            .local_only = true,
        });
        task_out.* = task;
        const physical_root: usize = (@as(usize, cpu) + 1) * PAGE_SIZE;
        var handle = MappingHandle{ .value = 0xffff };
        if (index < 2) {
            handle = installTestMappingAt(&sources[index], 0, .{
                .state = .live,
                .address_space_id = task.address_space_id,
                .address_space = .{ .directory = @ptrFromInt(physical_root), .pcid = cpu },
                .dispatch_metadata = .{ .owner_task_id = task.id },
            });
            if (index == 0) first_mapping = &sources[index].mappingArena().?.getByHandle(handle).?.mapping;
        }
        const record = runtime.findAddressSpace(task.address_space_id).?;
        record.region_count = 1;
        record.regions[0] = .{ .kind = .load_segment, .virtual_address = 0x4000_0000, .size_bytes = 8192, .file_offset = 0, .file_size = 0, .access = .{ .read = true } };
        const ticket = try runtime.reserveExecution(task, cpu);
        tickets[index] = ticket;
        try runtime.execution.bindOwnedRoot(ticket, handle.value, physical_root);
        cpu_identity.setIndexForTest(cpu);
        _ = try runtime.execution.start(ticket);
        var key: dispatch_ownership.RequestKey = undefined;
        try runtime.execution.submitSyscallInto(ticket, .{ .opcode = if (index == 1) 0xffff else abi.opcode(.task_terminate), .request_addr = 0x4000_0ff8, .response_addr = 0, .response_len = 0 }, &key);
        keys[index] = key;
        cpu_identity.setIndexForTest(0);
    }
    const authority = try capabilities.mintBootRoot(.{
        .holder = tasks[0].owner,
        .issuer = kernel.policy_authority,
        .target = .{ .kind = .task, .id = tasks[0].id },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = tasks[0].id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    });
    try runtime.grantCapability(tasks[0].id, authority.id);
    const request = abi.TaskTerminateWireRequest{ .header = component_port.makeHeader(.task_terminate, tasks[0].id), .task_capability_id = authority.id };
    var backing: [8192]u8 = @splat(0x7a);
    @memcpy(backing[4088..][0..@sizeOf(@TypeOf(request))], std.mem.asBytes(&request));
    const before_backing = backing;
    var pages = SyscallCopyTesting.Pages{ .directory = first_mapping.address_space.?.directory, .virtual_base = 0x4000_0000, .bytes = &backing };
    const previous_pages = SyscallCopyTesting.pages;
    SyscallCopyTesting.pages = &pages;
    defer SyscallCopyTesting.pages = previous_pages;
    var foreign_kernel = kernel;
    foreign_kernel.runtime = foreign_runtime;
    var foreign_port = port;
    foreign_port.kernel = &foreign_kernel;
    try std.testing.expectEqual(@as(u8, 0), scheduler.servicePendingSyscalls(&foreign_port, 10));
    scheduler.initialized = false;
    try std.testing.expectEqual(@as(u8, 0), scheduler.servicePendingSyscalls(&port, 10));
    scheduler.initialized = true;
    cpu_identity.setIndexForTest(1);
    try std.testing.expectEqual(@as(u8, 0), scheduler.servicePendingSyscalls(&port, 10));
    cpu_identity.setIndexForTest(0);
    try std.testing.expectEqual(@as(u8, 3), scheduler.servicePendingSyscalls(&port, 10));
    try std.testing.expectEqual(@as(u8, 0), scheduler.servicePendingSyscalls(&port, 10));
    try std.testing.expectEqual(@as(usize, 1), pages.reads);
    try std.testing.expectEqual(@as(usize, 1), reentry.calls);
    try std.testing.expectEqualSlices(u8, &before_backing, &backing);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, tasks[0].state);
    try std.testing.expect(capabilities.resolve(authority.id) != null);
    inline for (.{ abi.SyscallStatus.success, abi.SyscallStatus.unsupported_operation, abi.SyscallStatus.unavailable }, 0..) |status, index| {
        const ticket = tickets[index].?;
        cpu_identity.setIndexForTest(ticket.cpu);
        try std.testing.expectError(error.SyscallInFlight, runtime.execution.acknowledgeOwnedRootReturn(ticket));
        var reply: dispatch_ownership.Reply = undefined;
        try runtime.execution.consumeSyscallInto(keys[index].?, &reply);
        try std.testing.expectEqual(@as(u16, @intCast(@backingInt(status))), reply.status);
        try runtime.execution.acknowledgeOwnedRootReturn(ticket);
        cpu_identity.setIndexForTest(0);
        try runtime.collectExecution(ticket);
        tickets[index] = null;
    }
    try std.testing.expect(capabilities.resolve(authority.id) == null);
    try std.testing.expect(runtime.unbindExecutionStopSink(sink));
}

test "remote syscall real owner path parks drains STOP and preserves all CPU neighbors" {
    const previous_cpu = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    const runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.OutOfMemory;
    runtime.initializeAllocated();
    defer {
        executor_registrations = previous_registrations;
        cpu_identity.setIndexForTest(0);
        runtime.reset();
        table_backing.free(task_runtime.Runtime, runtime);
        cpu_identity.setIndexForTest(previous_cpu);
    }
    executor_registrations = @splat(.{});
    for (1..cpu_identity.MAX_CPUS) |index| {
        inline for (std.meta.tags(RemoteSyscallTestHardware.Mode)) |mode| {
            const cpu: u8 = @intCast(index);
            cpu_identity.setIndexForTest(cpu);
            var fixture = DeviceInterruptFixture{};
            try fixture.init();
            fixture.executor.bound_runtime = runtime;
            native_entry.current().active_task_id = 7;
            native_entry.current().userspace_xstate = @intFromPtr(fixture.mapping.owned_xstate.?.state());
            cpu_identity.setIndexForTest(0);
            const ticket = try runtime.execution.prepare(cpu, .{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 });
            try runtime.execution.bindOwnedRoot(ticket, fixture.executor.active_mapping_handle.value, 0x1000);
            cpu_identity.setIndexForTest(cpu);
            _ = try runtime.execution.start(ticket);
            fixture.executor.active_dispatch_lease = ticket;
            var neighbors: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
            for (&neighbors, 0..) |*entry, neighbor| entry.* = native_entry.stateForCpu(@intCast(neighbor)).*;
            const before = fixture.frame;
            if (mode == .complete) {
                var guard = RemoteSyscallTestHardware{ .runtime = runtime, .ticket = ticket, .mode = mode };
                guard.enabled = true;
                try guard.expectRejected(&fixture);
                guard.enabled = false;
                cpu_identity.setIndexForTest(0);
                try guard.expectRejected(&fixture);
                cpu_identity.setIndexForTest(cpu);
                fixture.frame.cs = 8;
                try guard.expectRejected(&fixture);
                fixture.frame = before;
                fixture.executor.registration_cpu = 0;
                try guard.expectRejected(&fixture);
                fixture.executor.registration_cpu = cpu;
                fixture.executor.active_dispatch_lease.?.epoch += 1;
                try guard.expectRejected(&fixture);
                fixture.executor.active_dispatch_lease = ticket;
                fixture.executor.active_dispatch_lease.?.issuer = @ptrFromInt(@intFromPtr(ticket.issuer) + 64);
                try guard.expectRejected(&fixture);
                fixture.executor.active_dispatch_lease = ticket;
                fixture.executor.active_mapping_handle.value += 1;
                try guard.expectRejected(&fixture);
                fixture.executor.active_mapping_handle.value -= 1;
                fixture.mapping.address_space.?.directory = @ptrFromInt(0x2000);
                try guard.expectRejected(&fixture);
                fixture.mapping.address_space.?.directory = @ptrFromInt(0x1000);
                inline for (.{ "active_task_id", "userspace_xstate", "kernel_xstate", "resume_rsp", "resume_rip" }) |field| {
                    const original = @field(native_entry.current(), field);
                    @field(native_entry.current(), field) = 0;
                    try guard.expectRejected(&fixture);
                    @field(native_entry.current(), field) = original;
                }
                native_entry.current().resume_requested = 1;
                try guard.expectRejected(&fixture);
                native_entry.current().resume_requested = 0;
                var pending_key: dispatch_ownership.RequestKey = undefined;
                try runtime.execution.submitSyscallInto(ticket, .{ .opcode = 0x101, .request_addr = 0, .response_addr = 0, .response_len = 0 }, &pending_key);
                try guard.expectRejected(&fixture);
                try std.testing.expect(runtime.execution.cancelPendingSyscall(pending_key));
            }
            var hardware = RemoteSyscallTestHardware{ .runtime = runtime, .ticket = ticket, .mode = mode };
            try std.testing.expect(remoteSyscallWithHardware(&fixture.frame, &hardware));
            try std.testing.expect(!hardware.enabled);
            try std.testing.expectEqual(@as(u8, 1), hardware.notified);
            try std.testing.expect(runtime.execution.syscallIdle(ticket));
            if (mode == .complete) {
                try std.testing.expect(hardware.restored_user and !hardware.kernel);
                try std.testing.expectEqual(@as(u8, 1), hardware.waits);
                var expected = before;
                expected.eax = 9;
                expected.edx = 17;
                expected.r10 = 4;
                try std.testing.expectEqualDeep(expected, fixture.frame);
                try std.testing.expect(!fixture.executor.handoff_completed);
                try std.testing.expectEqualDeep(neighbors[cpu], native_entry.current().*);
            } else {
                try std.testing.expect(hardware.kernel and !hardware.restored_user);
                try std.testing.expectEqual(@as(u8, if (mode == .stop_pending) 0 else 1), hardware.waits);
                try fixture.expectResumeWithXstate(neighbors[cpu].userspace_xstate);
                if (mode == .stop_pending) try std.testing.expectEqualDeep(before, fixture.frame);
            }
            for (neighbors, 0..) |entry, neighbor| {
                if (neighbor != cpu) try std.testing.expectEqualDeep(entry, native_entry.stateForCpu(@intCast(neighbor)).*);
            }
            requireIdleSyscallReturn();
            try runtime.execution.acknowledgeOwnedRootReturn(ticket);
            cpu_identity.setIndexForTest(0);
            _ = try runtime.execution.beginCollect(ticket);
            try runtime.execution.finishCollect(ticket);
            cpu_identity.setIndexForTest(cpu);
            fixture.executor.active_dispatch_lease = null;
            fixture.executor.bound_runtime = null;
            fixture.deinit();
        }
    }
}

const DeviceInterruptFixture = struct {
    const isr = @import("../../kernel/interrupts/isr.zig");
    const wake = @import("../../kernel/event_wake.zig");
    executor: Executor = .{},
    mapping: *MappingEntry = undefined,
    frame: isr.Registers = undefined,
    previous_executor: ?*Executor = null,
    previous_entry: native_entry.State = .{},
    previous_wakes: wake.Pending = .{},

    fn init(self: *@This()) !void {
        const storage = table_backing.alloc(xstate.Storage) orelse return error.OutOfMemory;
        storage.initialize();
        self.previous_executor = currentRegisteredExecutor();
        self.previous_entry = native_entry.current().*;
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
        self.executor.registration_cpu = cpu_identity.currentIndex();
        currentExecutorSlot().* = &self.executor;
        native_entry.clearContinuation();
        native_entry.current().resume_rsp = 0xfeed_1000;
        native_entry.current().resume_rip = 0xfeed_2000;
        native_entry.current().userspace_xstate = 0xfeed_3000;
        native_entry.current().kernel_xstate = 0xfeed_4000;
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
        currentExecutorSlot().* = &self.executor;
        self.executor.reset();
        currentExecutorSlot().* = self.previous_executor;
        native_entry.current().* = self.previous_entry;
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
        return self.expectResumeWithXstate(0xfeed_3000);
    }

    fn expectResumeWithXstate(self: *const @This(), userspace_xstate: usize) !void {
        try std.testing.expect(self.executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
        try std.testing.expect(self.mapping.resume_valid);
        try std.testing.expectEqual(@as(u64, 9), self.mapping.yield_count);
        try std.testing.expectEqual(@as(u32, 9), self.mapping.last_user_counter);
        inline for (.{ "rax", "rbx", "rcx", "rdx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }, .{ "eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }) |user_field, frame_field|
            try std.testing.expectEqual(@field(self.frame, frame_field), @field(self.mapping.user_context64, user_field));
        try std.testing.expectEqual(self.frame.eflags, self.mapping.user_context64.flags);
        try std.testing.expectEqual(self.frame.eip, self.mapping.user_context64.instruction_pointer);
        try std.testing.expectEqual(self.frame.useresp, self.mapping.user_context64.stack_pointer);
        try std.testing.expectEqual(userspace_bootstrap_mailbox.YieldDisposition.runnable, self.executor.last_yield_disposition);
        try std.testing.expect(self.executor.last_user_exception == null);
        try std.testing.expectEqual(DispatchQuantum.begin(self.executor.active_task_id, 100), self.executor.dispatch_quantum);
        try std.testing.expectEqual(@as(usize, 0xfeed_1000), native_entry.current().resume_rsp);
        try std.testing.expectEqual(@as(usize, 0xfeed_2000), native_entry.current().resume_rip);
        try std.testing.expectEqual(userspace_xstate, native_entry.current().userspace_xstate);
        try std.testing.expectEqual(@as(usize, 0xfeed_4000), native_entry.current().kernel_xstate);
    }

    fn expectNoResume(self: *const @This()) !void {
        try std.testing.expect(!self.executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 0), native_entry.current().resume_requested);
        try std.testing.expect(!self.mapping.resume_valid);
        try std.testing.expectEqual(@as(u64, 8), self.mapping.yield_count);
    }
};

const UserPageFaultObserver = if (builtin.is_test) struct {
    fixture: *DeviceInterruptFixture,
    address: u64,
    resolves: bool = false,
    recovers: bool = false,
    address_reads: usize = 0,
    registry_calls: usize = 0,
    recovery_calls: usize = 0,
    kernel_faults: usize = 0,
    kernel_switches: usize = 0,

    fn kernelFault(self: *@This(), _: *freestanding.isr.InterruptFrame) void {
        self.kernel_faults += 1;
    }

    fn faultAddress(self: *@This()) u64 {
        self.address_reads += 1;
        return self.address;
    }

    fn resolve(self: *@This(), space: *freestanding.paging.UserAddressSpace, address: u64, code: u32) bool {
        std.debug.assert(space == &self.fixture.mapping.address_space.?);
        std.debug.assert(address == self.address and code == self.fixture.frame.err_code);
        self.registry_calls += 1;
        return self.resolves;
    }

    fn recover(self: *@This(), executor: *const Executor, mapping: *MappingEntry, frame: *freestanding.isr.InterruptFrame, address: u64, code: u32) bool {
        std.debug.assert(executor == &self.fixture.executor and mapping == self.fixture.mapping);
        std.debug.assert(address == self.address and code == self.fixture.frame.err_code);
        self.recovery_calls += 1;
        if (self.recovers) frame.eip = 0x4000_1040;
        return self.recovers;
    }

    fn restoreKernel(self: *@This()) void {
        // The native adapter switches CR3 here. Observe the actual handler's
        // completed local fault publication before that handoff boundary.
        std.debug.assert(self.fixture.executor.handoff_completed);
        std.debug.assert(native_entry.current().resume_requested == 1);
        self.kernel_switches += 1;
    }

    fn dispatch(self: *@This()) !void {
        const Case = struct {
            var observer: ?*UserPageFaultObserver = null;

            fn receive(frame: *freestanding.isr.InterruptFrame) void {
                std.debug.assert(@import("../../kernel/interrupts/context.zig").active());
                handleUserspacePageFaultWith(frame, observer.?);
            }

            fn run(active: *UserPageFaultObserver) !void {
                const previous = observer;
                defer observer = previous;
                observer = active;
                DeviceInterruptFixture.isr.registerHandler(PAGE_FAULT_VECTOR, receive);
                active.fixture.frame.int_no = PAGE_FAULT_VECTOR;
                DeviceInterruptFixture.isr.isrHandler(&active.fixture.frame);
            }
        };
        try DeviceInterruptFixture.isr.withTestHandlers(self, Case.run);
        try std.testing.expect(!@import("../../kernel/interrupts/context.zig").active());
    }
} else struct {};

test "remote user page faults contain locally without registry COW or verification lookups on all APs" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    var entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&entries, 0..) |*entry, index| entry.* = native_entry.stateForCpu(@intCast(index)).*;
    defer for (entries, 0..) |entry, index| {
        native_entry.stateForCpu(@intCast(index)).* = entry;
    };
    // Absent data, present COW write, instruction-fetch and protection-key
    // failures must all avoid the foreign BSP mutation/recovery paths.
    for (1..cpu_identity.MAX_CPUS) |cpu| {
        cpu_identity.setIndexForTest(@intCast(cpu));
        for ([_]u32{ 0x4, 0x7, 0x15, 0x25 }) |code| {
            var fixture = DeviceInterruptFixture{};
            try fixture.init();
            defer fixture.deinit();
            fixture.frame.int_no = PAGE_FAULT_VECTOR;
            fixture.frame.err_code = code;
            fixture.mapping.user_context64 = .{ .instruction_pointer = 0x4000_0200, .stack_pointer = 0x7000_0200 };
            fixture.mapping.interrupted_before_yield = true;
            const neighbor_handle = installTestMappingAt(&fixture.executor, 1, .{
                .state = .live,
                .address_space_id = 43,
                .dispatch_metadata = .{ .owner_task_id = 8, .image_id = 42 },
                .page_fault_count = 11,
            });
            const neighbor = &fixture.executor.mappingArena().?.getByHandle(neighbor_handle).?.mapping;
            const neighbor_before = neighbor.*;
            const context_before = fixture.mapping.user_context64;
            const frame_before = fixture.frame;
            const xstate_before = fixture.mapping.owned_xstate.?.*;
            var states_before: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
            for (&states_before, 0..) |*entry, index| entry.* = native_entry.stateForCpu(@intCast(index)).*;
            var observer = UserPageFaultObserver{ .fixture = &fixture, .address = 0x7000_0FF0 + cpu * PAGE_SIZE, .resolves = true, .recovers = true };
            try observer.dispatch();
            try std.testing.expectEqual(@as(usize, 1), observer.address_reads);
            try std.testing.expectEqual(@as(usize, 0), observer.registry_calls);
            try std.testing.expectEqual(@as(usize, 0), observer.recovery_calls);
            try std.testing.expectEqual(@as(usize, 0), observer.kernel_faults);
            try std.testing.expectEqual(@as(usize, 1), observer.kernel_switches);
            try std.testing.expectEqualDeep(frame_before, fixture.frame);
            try std.testing.expectEqualDeep(context_before, fixture.mapping.user_context64);
            try std.testing.expectEqualDeep(xstate_before, fixture.mapping.owned_xstate.?.*);
            try std.testing.expectEqualDeep(neighbor_before, neighbor.*);
            try std.testing.expectEqual(@as(u64, 1), fixture.executor.user_page_fault_count);
            try std.testing.expectEqual(@as(u64, 7), fixture.executor.last_fault_task_id);
            try std.testing.expectEqual(@as(u64, 42), fixture.executor.last_fault_address_space_id);
            try std.testing.expectEqual(observer.address, fixture.executor.last_fault_address);
            try std.testing.expectEqual(code, fixture.executor.last_fault_error_code);
            try std.testing.expectEqual(@as(u64, 1), fixture.mapping.page_fault_count);
            try std.testing.expectEqual(observer.address, fixture.mapping.last_fault_address);
            try std.testing.expectEqual(code, fixture.mapping.last_fault_error_code);
            try std.testing.expectEqualDeep(UserException{ .vector = PAGE_FAULT_VECTOR, .error_code = code, .instruction_pointer = frame_before.eip, .fault_address = observer.address }, fixture.executor.last_user_exception.?);
            try std.testing.expect(fixture.executor.handoff_completed);
            try std.testing.expect(!fixture.mapping.resume_valid);
            try std.testing.expect(fixture.mapping.interrupted_before_yield);
            try std.testing.expectEqual(@as(u64, 8), fixture.mapping.yield_count);
            try std.testing.expectEqual(@as(u32, 9), fixture.mapping.last_user_counter);
            try std.testing.expectEqual(DispatchQuantum.begin(7, 100), fixture.executor.dispatch_quantum);
            for (states_before, 0..) |before, index| {
                var expected = before;
                if (index == cpu) expected.resume_requested = 1;
                try std.testing.expectEqualDeep(expected, native_entry.stateForCpu(@intCast(index)).*);
            }
        }
    }
}

test "user page fault BSP resolution recovery and containment retain their native ordering" {
    const previous_cpu = cpu_identity.currentIndex();
    cpu_identity.setIndexForTest(0);
    defer cpu_identity.setIndexForTest(previous_cpu);
    for ([_]enum { resolved, recovered, contained }{ .resolved, .recovered, .contained }) |mode| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        fixture.frame.int_no = PAGE_FAULT_VECTOR;
        fixture.frame.err_code = 0x7;
        const frame_before = fixture.frame;
        var observer = UserPageFaultObserver{ .fixture = &fixture, .address = 0x7000_0FF0, .resolves = mode == .resolved, .recovers = mode == .recovered };
        try observer.dispatch();
        try std.testing.expectEqual(@as(usize, 1), observer.registry_calls);
        try std.testing.expectEqual(@as(usize, 0), observer.kernel_faults);
        if (mode == .resolved) {
            try std.testing.expectEqual(@as(usize, 0), observer.recovery_calls);
            try std.testing.expectEqual(@as(usize, 0), observer.kernel_switches);
            try std.testing.expectEqual(@as(u64, 0), fixture.executor.user_page_fault_count);
            try std.testing.expectEqual(@as(u64, 0), fixture.mapping.page_fault_count);
            try std.testing.expectEqualDeep(frame_before, fixture.frame);
            try fixture.expectNoResume();
        } else {
            try std.testing.expectEqual(@as(usize, 1), observer.recovery_calls);
            try std.testing.expectEqual(@as(usize, 1), observer.kernel_switches);
            try std.testing.expectEqual(@as(u64, 1), fixture.executor.user_page_fault_count);
            try std.testing.expectEqual(@as(u64, 1), fixture.mapping.page_fault_count);
            try std.testing.expect(fixture.executor.handoff_completed);
            try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
            if (mode == .recovered) {
                var expected = frame_before;
                expected.eip = 0x4000_1040;
                try std.testing.expectEqualDeep(expected, fixture.frame);
                try std.testing.expect(fixture.mapping.resume_valid);
                try std.testing.expectEqual(@as(u64, 0x4000_1040), fixture.mapping.user_context64.instruction_pointer);
                try std.testing.expectEqual(frame_before.eax, fixture.mapping.user_context64.rax);
                try std.testing.expectEqual(frame_before.r15, fixture.mapping.user_context64.r15);
                try std.testing.expect(fixture.executor.last_user_exception == null);
            } else {
                try std.testing.expectEqualDeep(frame_before, fixture.frame);
                try std.testing.expect(!fixture.mapping.resume_valid);
                try std.testing.expectEqualDeep(UserException{ .vector = PAGE_FAULT_VECTOR, .error_code = 0x7, .instruction_pointer = frame_before.eip, .fault_address = observer.address }, fixture.executor.last_user_exception.?);
            }
        }
    }
}

test "user page fault kernel fallback precedes local CR2 and owner state access" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    for ([_]u8{ 0, 15 }) |cpu| {
        cpu_identity.setIndexForTest(cpu);
        for ([_]enum { kernel, inactive, unregistered }{ .kernel, .inactive, .unregistered }) |mode| {
            var fixture = DeviceInterruptFixture{};
            try fixture.init();
            defer fixture.deinit();
            fixture.frame.int_no = PAGE_FAULT_VECTOR;
            fixture.frame.err_code = if (mode == .kernel) 0x2 else 0x4;
            if (mode == .kernel) fixture.frame.cs = 0x8;
            if (mode == .inactive) fixture.executor.active_task_id = 0;
            if (mode == .unregistered) currentExecutorSlot().* = null;
            const frame_before = fixture.frame;
            const entry_before = native_entry.current().*;
            var observer = UserPageFaultObserver{ .fixture = &fixture, .address = 0x7000_0FF0, .resolves = true, .recovers = true };
            try observer.dispatch();
            try std.testing.expectEqual(@as(usize, 1), observer.kernel_faults);
            try std.testing.expectEqual(@as(usize, 0), observer.address_reads);
            try std.testing.expectEqual(@as(usize, 0), observer.registry_calls);
            try std.testing.expectEqual(@as(usize, 0), observer.recovery_calls);
            try std.testing.expectEqual(@as(usize, 0), observer.kernel_switches);
            try std.testing.expectEqualDeep(frame_before, fixture.frame);
            try std.testing.expectEqualDeep(entry_before, native_entry.current().*);
            try std.testing.expectEqual(@as(u64, 0), fixture.executor.user_page_fault_count);
            try std.testing.expectEqual(@as(u64, 0), fixture.mapping.page_fault_count);
            try fixture.expectNoResume();
        }
    }
}

const ExecutionStopInterruptFixture = struct {
    const isr = @import("../../kernel/interrupts/isr.zig");
    const x2apic = @import("../../kernel/interrupts/x2apic.zig");
    var eois: [cpu_identity.MAX_CPUS]usize = @splat(0);

    fn observeWrite(msr: u32, value: u64) void {
        if (msr != x2apic.Testing.EOI_MSR or value != 0 or
            !@import("../../kernel/interrupts/context.zig").active())
            @panic("execution stop fixture observes one real in-context EOI");
        eois[cpu_identity.currentIndex()] += 1;
    }

    fn dispatch(fixture: *DeviceInterruptFixture) !void {
        const Case = struct {
            fixture: *DeviceInterruptFixture,
            fn run(self: *@This()) !void {
                isr.setRuntimePreemption(userspaceInterruptPreemption);
                self.fixture.frame.int_no = smp.EXECUTION_STOP_IPI_VECTOR;
                isr.isrHandler(&self.fixture.frame);
            }
        };
        const before = eois;
        var case = Case{ .fixture = fixture };
        try isr.withTestHandlers(&case, Case.run);
        try std.testing.expect(!@import("../../kernel/interrupts/context.zig").active());
        for (eois, 0..) |count, index|
            try std.testing.expectEqual(before[index] + @intFromBool(index == cpu_identity.currentIndex()), count);
    }
};

test "execution stop real ISR authenticates all CPU leases without foreign policy or acknowledgements" {
    const Policy = struct {
        fn preempt(_: u64) bool {
            @panic("execution stop must not consult BSP scheduling policy");
        }
    };
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    const previous_policy = preempt_check;
    preempt_check = Policy.preempt;
    defer preempt_check = previous_policy;
    const previous_observer = ExecutionStopInterruptFixture.x2apic.Testing.swapWriteObserver(ExecutionStopInterruptFixture.observeWrite);
    defer _ = ExecutionStopInterruptFixture.x2apic.Testing.swapWriteObserver(previous_observer);
    ExecutionStopInterruptFixture.eois = @splat(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    const fixtures = try std.testing.allocator.alloc(DeviceInterruptFixture, cpu_identity.MAX_CPUS);
    defer std.testing.allocator.free(fixtures);
    var initialized: usize = 0;
    defer {
        // The fixture uses Coordinator identities, not Runtime TaskBorrows.
        // Detach its fake bindings before releasing hosted mapping storage.
        var index = initialized;
        while (index != 0) {
            index -= 1;
            cpu_identity.setIndexForTest(@intCast(index));
            fixtures[index].executor.bound_runtime = null;
            fixtures[index].executor.active_dispatch_lease = null;
            fixtures[index].deinit();
        }
    }
    var tickets: [cpu_identity.MAX_CPUS]dispatch_ownership.Ticket = undefined;
    var expected_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (fixtures, 0..) |*fixture, index| {
        cpu_identity.setIndexForTest(@intCast(index));
        fixture.* = .{};
        try fixture.init();
        initialized += 1;
        const task_id: u64 = 7 + index;
        fixture.executor.active_task_id = task_id;
        fixture.executor.dispatch_quantum = DispatchQuantum.begin(task_id, 100);
        fixture.mapping.dispatch_metadata.owner_task_id = task_id;
        fixture.mapping.address_space_id = 42 + index;
        fixture.executor.bound_runtime = runtime;
        native_entry.current().active_task_id = task_id;
        native_entry.current().kernel_stack_top = 0xabcd_0000 + index * 0x1000;
        native_entry.current().kernel_port = 0xabcd_8000 + index * 64;
        expected_entries[index] = native_entry.current().*;
        cpu_identity.setIndexForTest(0);
        tickets[index] = try runtime.execution.prepare(@intCast(index), .{
            .task_handle = 1 + index,
            .task_id = task_id,
            .process_generation = 1,
            .address_space_id = fixture.mapping.address_space_id,
        });
        try runtime.execution.bindOwnedRoot(tickets[index], fixture.executor.active_mapping_handle.value, (index + 1) * PAGE_SIZE);
        cpu_identity.setIndexForTest(@intCast(index));
        _ = try runtime.execution.start(tickets[index]);
        fixture.executor.active_dispatch_lease = tickets[index];
        // A bare or delayed vector has no stop authority.
        try ExecutionStopInterruptFixture.dispatch(fixture);
        try fixture.expectNoResume();
    }
    cpu_identity.setIndexForTest(0);
    for (tickets) |ticket| try std.testing.expect(try runtime.execution.requestStop(ticket));
    var foreign: dispatch_ownership.Coordinator = .{};
    const Invalid = enum { no_ticket, foreign_issuer, foreign_cpu, stale_epoch, no_registration, foreign_registration, kernel, no_mapping, wrong_mapping_owner, no_xstate };
    for (fixtures, 0..) |*fixture, index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const xstate_before = fixture.mapping.owned_xstate.?.*;
        for (std.enums.values(Invalid)) |invalid| {
            const lease = fixture.executor.active_dispatch_lease;
            const owner = fixture.executor.registration_cpu;
            const mapping = fixture.executor.active_mapping;
            const task_owner = fixture.mapping.dispatch_metadata.owner_task_id;
            const storage = fixture.mapping.owned_xstate;
            const cs = fixture.frame.cs;
            defer {
                fixture.executor.active_dispatch_lease = lease;
                fixture.executor.registration_cpu = owner;
                fixture.executor.active_mapping = mapping;
                fixture.mapping.dispatch_metadata.owner_task_id = task_owner;
                fixture.mapping.owned_xstate = storage;
                fixture.frame.cs = cs;
            }
            switch (invalid) {
                .no_ticket => fixture.executor.active_dispatch_lease = null,
                .foreign_issuer => fixture.executor.active_dispatch_lease.?.issuer = &foreign,
                .foreign_cpu => fixture.executor.active_dispatch_lease.?.cpu = @intCast((index + 1) % cpu_identity.MAX_CPUS),
                .stale_epoch => fixture.executor.active_dispatch_lease.?.epoch += 1,
                .no_registration => fixture.executor.registration_cpu = null,
                .foreign_registration => fixture.executor.registration_cpu = @intCast((index + 1) % cpu_identity.MAX_CPUS),
                .kernel => fixture.frame.cs = 0x08,
                .no_mapping => fixture.executor.active_mapping = null,
                .wrong_mapping_owner => fixture.mapping.dispatch_metadata.owner_task_id += 1,
                .no_xstate => fixture.mapping.owned_xstate = null,
            }
            try ExecutionStopInterruptFixture.dispatch(fixture);
            try fixture.expectNoResume();
            fixture.executor.active_dispatch_lease = lease;
            fixture.executor.registration_cpu = owner;
            fixture.executor.active_mapping = mapping;
            fixture.mapping.dispatch_metadata.owner_task_id = task_owner;
            fixture.mapping.owned_xstate = storage;
            fixture.frame.cs = cs;
        }
        try ExecutionStopInterruptFixture.dispatch(fixture);
        try fixture.expectResume();
        const captured = fixture.mapping.user_context64;
        fixture.frame.eax += 1;
        fixture.frame.eip += 4;
        try ExecutionStopInterruptFixture.dispatch(fixture);
        try std.testing.expectEqual(captured, fixture.mapping.user_context64);
        try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
        try std.testing.expectEqualDeep(xstate_before, fixture.mapping.owned_xstate.?.*);
        expected_entries[index] = native_entry.current().*;
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(dispatch_ownership.Phase.running, try runtime.execution.phase(tickets[index]));
        for (fixtures, 0..) |*neighbor, neighbor_index| {
            cpu_identity.setIndexForTest(@intCast(neighbor_index));
            try std.testing.expectEqual(expected_entries[neighbor_index], native_entry.current().*);
            try std.testing.expectEqual(neighbor_index <= index, neighbor.executor.handoff_completed);
            try std.testing.expectEqual(@as(u64, if (neighbor_index <= index) 9 else 8), neighbor.mapping.yield_count);
        }
    }
    try std.testing.expect(!DeviceInterruptFixture.wake.any());
}

test "execution stop real ISR ignores returned and replacement leases until their own stop" {
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    const previous_observer = ExecutionStopInterruptFixture.x2apic.Testing.swapWriteObserver(ExecutionStopInterruptFixture.observeWrite);
    defer _ = ExecutionStopInterruptFixture.x2apic.Testing.swapWriteObserver(previous_observer);
    ExecutionStopInterruptFixture.eois = @splat(0);
    const runtime = try std.testing.allocator.create(task_runtime.Runtime);
    defer std.testing.allocator.destroy(runtime);
    runtime.* = .{};
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer {
            cpu_identity.setIndexForTest(@intCast(index));
            fixture.executor.bound_runtime = null;
            fixture.executor.active_dispatch_lease = null;
            fixture.deinit();
        }
        fixture.executor.bound_runtime = runtime;
        cpu_identity.setIndexForTest(0);
        const identity = dispatch_ownership.Identity{ .task_handle = 1, .task_id = 7, .process_generation = 1, .address_space_id = 42 };
        const old = try runtime.execution.prepare(@intCast(index), identity);
        try runtime.execution.bindOwnedRoot(old, fixture.executor.active_mapping_handle.value, PAGE_SIZE);
        cpu_identity.setIndexForTest(@intCast(index));
        _ = try runtime.execution.start(old);
        fixture.executor.active_dispatch_lease = old;
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(try runtime.execution.requestStop(old));
        cpu_identity.setIndexForTest(@intCast(index));
        try runtime.execution.acknowledgeOwnedRootReturn(old);
        try ExecutionStopInterruptFixture.dispatch(&fixture);
        try fixture.expectNoResume();
        cpu_identity.setIndexForTest(0);
        _ = try runtime.execution.beginCollect(old);
        try runtime.execution.finishCollect(old);
        const replacement = try runtime.execution.prepare(@intCast(index), identity);
        try runtime.execution.bindOwnedRoot(replacement, fixture.executor.active_mapping_handle.value, PAGE_SIZE);
        try std.testing.expectError(error.StaleTicket, runtime.execution.requestStop(old));
        cpu_identity.setIndexForTest(@intCast(index));
        _ = try runtime.execution.start(replacement);
        fixture.executor.active_dispatch_lease = replacement;
        try ExecutionStopInterruptFixture.dispatch(&fixture);
        try fixture.expectNoResume();
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(try runtime.execution.requestStop(replacement));
        cpu_identity.setIndexForTest(@intCast(index));
        try ExecutionStopInterruptFixture.dispatch(&fixture);
        try fixture.expectResume();
        try runtime.execution.acknowledgeOwnedRootReturn(replacement);
        cpu_identity.setIndexForTest(0);
        _ = try runtime.execution.beginCollect(replacement);
        try runtime.execution.finishCollect(replacement);
        cpu_identity.setIndexForTest(@intCast(index));
    }
}

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

test "device IRQ continuation skips its first stale event yield in the same quantum and isolates other mappings" {
    var fixture = DeviceInterruptFixture{};
    try fixture.init();
    defer fixture.deinit();
    const neighbor_handle = installTestMappingAt(&fixture.executor, 1, .{
        .state = .live,
        .address_space_id = 43,
        .dispatch_metadata = .{ .owner_task_id = 8, .image_id = 42 },
    });
    const neighbor = &fixture.executor.mappingArena().?.getByHandle(neighbor_handle).?.mapping;
    const neighbor_before = neighbor.*;
    try std.testing.expect(!fixture.mapping.interrupted_before_yield);
    try fixture.dispatch(67, null);
    try fixture.expectNoResume();
    try std.testing.expect(!fixture.mapping.interrupted_before_yield);
    try fixture.dispatch(67, .xhci);
    try fixture.expectResume();
    try std.testing.expect(fixture.mapping.interrupted_before_yield);
    const captured = fixture.mapping.user_context64;
    fixture.frame.eip += 4;
    try fixture.dispatch(67, .xhci);
    try std.testing.expectEqualDeep(captured, fixture.mapping.user_context64);
    try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
    try std.testing.expect(fixture.mapping.interrupted_before_yield);
    // Redispatch resets the owner handoff fields, retaining the cached mapping.
    fixture.executor.handoff_completed = false;
    native_entry.current().resume_requested = 0;
    fixture.frame.eax = 10;
    fixture.frame.esi = @backingInt(userspace_bootstrap_mailbox.YieldDisposition.wait_for_event);
    const frame_before = fixture.frame;
    const quantum_before = fixture.executor.dispatch_quantum;
    const context_before = fixture.mapping.user_context64;
    const counter_before = fixture.executor.last_trap_counter;
    const ui_before = fixture.executor.last_yield_ui_revision;
    const user_counter_before = fixture.mapping.last_user_counter;
    handleUserspaceYield(&fixture.executor, &fixture.frame);
    try std.testing.expectEqualDeep(frame_before, fixture.frame);
    try std.testing.expectEqual(userspace_bootstrap_mailbox.YieldDisposition.runnable, fixture.executor.last_yield_disposition);
    try std.testing.expect(!fixture.mapping.interrupted_before_yield);
    try std.testing.expect(!fixture.executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 0), native_entry.current().resume_requested);
    try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
    try std.testing.expectEqualDeep(context_before, fixture.mapping.user_context64);
    try std.testing.expectEqualDeep(quantum_before, fixture.executor.dispatch_quantum);
    try std.testing.expectEqual(counter_before, fixture.executor.last_trap_counter);
    try std.testing.expectEqual(ui_before, fixture.executor.last_yield_ui_revision);
    try std.testing.expectEqual(user_counter_before, fixture.mapping.last_user_counter);
    try std.testing.expectEqualDeep(neighbor_before, neighbor.*);
    fixture.executor.handoff_completed = false;
    native_entry.current().resume_requested = 0;
    fixture.frame.eax = 11;
    handleUserspaceYield(&fixture.executor, &fixture.frame);
    try std.testing.expectEqual(userspace_bootstrap_mailbox.YieldDisposition.wait_for_event, fixture.executor.last_yield_disposition);
    try std.testing.expect(!fixture.mapping.interrupted_before_yield);
    try std.testing.expect(fixture.executor.handoff_completed);
    try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
    try std.testing.expectEqual(@as(u64, 10), fixture.mapping.yield_count);
    try std.testing.expectEqual(fixture.frame.eip, fixture.mapping.user_context64.instruction_pointer);
    try std.testing.expectEqual(fixture.frame.useresp, fixture.mapping.user_context64.stack_pointer);
    try std.testing.expectEqualDeep(neighbor_before, neighbor.*);
}

test "IRQ continuation retry is consumed by runnable yields and retained by malformed frames" {
    for ([_]struct { counter: u64, disposition: u64, valid: bool }{
        .{ .counter = 10, .disposition = 0, .valid = true },
        .{ .counter = @as(u64, std.math.maxInt(u32)) + 1, .disposition = 1, .valid = false },
        .{ .counter = 10, .disposition = 2, .valid = false },
        .{ .counter = 10, .disposition = @as(u64, std.math.maxInt(u32)) + 1, .valid = false },
    }) |case| {
        var fixture = DeviceInterruptFixture{};
        try fixture.init();
        defer fixture.deinit();
        fixture.frame.cs = 0x08;
        try fixture.dispatch(67, .xhci);
        try fixture.expectNoResume();
        try std.testing.expect(!fixture.mapping.interrupted_before_yield);
        fixture.frame.cs = 0x23;
        try fixture.dispatch(67, .xhci);
        try fixture.expectResume();
        const captured = fixture.mapping.user_context64;
        fixture.executor.handoff_completed = false;
        native_entry.current().resume_requested = 0;
        fixture.frame.eax = case.counter;
        fixture.frame.esi = case.disposition;
        handleUserspaceYield(&fixture.executor, &fixture.frame);
        try std.testing.expectEqual(!case.valid, fixture.mapping.interrupted_before_yield);
        try std.testing.expect(fixture.executor.handoff_completed);
        try std.testing.expectEqual(@as(u32, 1), native_entry.current().resume_requested);
        if (case.valid) {
            try std.testing.expect(fixture.executor.last_user_exception == null);
            try std.testing.expectEqual(userspace_bootstrap_mailbox.YieldDisposition.runnable, fixture.executor.last_yield_disposition);
            try std.testing.expectEqual(@as(u64, 10), fixture.mapping.yield_count);
        } else {
            try std.testing.expectEqual(GENERAL_PROTECTION_FAULT_VECTOR, fixture.executor.last_user_exception.?.vector);
            try std.testing.expectEqualDeep(captured, fixture.mapping.user_context64);
            try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
            const exception = fixture.executor.last_user_exception.?;
            fixture.frame.eax = 11;
            fixture.frame.esi = 1;
            handleUserspaceYield(&fixture.executor, &fixture.frame);
            try std.testing.expect(fixture.mapping.interrupted_before_yield);
            try std.testing.expectEqualDeep(exception, fixture.executor.last_user_exception.?);
            try std.testing.expectEqualDeep(captured, fixture.mapping.user_context64);
            try std.testing.expectEqual(@as(u64, 9), fixture.mapping.yield_count);
        }
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
            .executor => currentExecutorSlot().* = null,
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
    {
        const previous_index = cpu_identity.currentIndex();
        cpu_identity.setIndexForTest(1);
        defer cpu_identity.setIndexForTest(previous_index);
        try std.testing.expect(!unregisterMappedObject(&executor, &table, handle.value, registered));
        try std.testing.expectEqual(@as(u16, 1), executor.mapped_object_count);
        try std.testing.expect(table.hasMapping(object.id, ids.task(7)));
        try std.testing.expect(demand_paging.regionOverlapsSpace(&mapping.address_space.?, first, first + shared_memory.PAGE_SIZE));
    }
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
        expected_mapping: *MappingEntry,
        expected_context: UserContext64,
        expected_state: *align(xstate.alignment) xstate.State,
        called: bool = false,
        fn enter(self: *@This(), context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
            if (!self.clock.armed or state != self.expected_state or self.executor.active_mapping != self.expected_mapping or
                context != &self.expected_mapping.user_context64)
                @panic("user entry requires its armed timer and owned context");
            std.testing.expectEqualDeep(self.expected_context, context.*) catch @panic("user entry borrows its complete current mapping context");
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
    const initial_context = UserContext64{
        .rax = 0x101,
        .rbx = 0x102,
        .rcx = 0x103,
        .rdx = 0x104,
        .rbp = 0x105,
        .rsi = 0x106,
        .rdi = 0x107,
        .r8 = 0x108,
        .r9 = 0x109,
        .r10 = 0x10a,
        .r11 = 0x10b,
        .r12 = 0x10c,
        .r13 = 0x10d,
        .r14 = 0x10e,
        .r15 = 0x10f,
        .instruction_pointer = 0x4000_1234,
        .flags = 0x202,
        .stack_pointer = 0x7fff_8880,
    };
    var mappings = [_]MappingEntry{
        .{ .owned_xstate = &storage, .user_context64 = initial_context },
        .{ .address_space_id = 73, .resume_valid = true, .user_context64 = initial_context },
    };
    const mapping = &mappings[0];
    const neighbor = &mappings[1];
    neighbor.user_context64.rax = 0xfeed_1234;
    const neighbor_before = neighbor.*;
    var executor = Executor{ .active_task_id = 42, .active_mapping = mapping };
    var clock = Clock{ .now = 500 };
    var entry = Entry{
        .executor = &executor,
        .clock = &clock,
        .expected_mapping = mapping,
        .expected_context = initial_context,
        .expected_state = storage.state(),
    };
    try std.testing.expectEqual(@as(u32, 7), enterUserspaceWithClock(&executor, &clock, &entry));
    try std.testing.expect(entry.called);
    const resumed_context = UserContext64{
        .rax = 0x201,
        .rbx = 0x202,
        .rcx = 0x203,
        .rdx = 0x204,
        .rbp = 0x205,
        .rsi = 0x206,
        .rdi = 0x207,
        .r8 = 0x208,
        .r9 = 0x209,
        .r10 = 0x20a,
        .r11 = 0x20b,
        .r12 = 0x20c,
        .r13 = 0x20d,
        .r14 = 0x20e,
        .r15 = 0x20f,
        .instruction_pointer = 0x4000_5678,
        .flags = 0x246,
        .stack_pointer = 0x7fff_9990,
    };
    var frame = std.mem.zeroes(freestanding.isr.InterruptFrame);
    frame.eax = 0x201;
    frame.ebx = 0x202;
    frame.ecx = 0x203;
    frame.edx = 0x204;
    frame.ebp = 0x205;
    frame.esi = 0x206;
    frame.edi = 0x207;
    frame.r8 = 0x208;
    frame.r9 = 0x209;
    frame.r10 = 0x20a;
    frame.r11 = 0x20b;
    frame.r12 = 0x20c;
    frame.r13 = 0x20d;
    frame.r14 = 0x20e;
    frame.r15 = 0x20f;
    frame.eip = 0x4000_5678;
    frame.eflags = 0x246;
    frame.useresp = 0x7fff_9990;
    captureUserContext64(mapping, &frame);
    try std.testing.expectEqualDeep(resumed_context, mapping.user_context64);
    try std.testing.expectEqualDeep(neighbor_before, neighbor.*);
    // A later entry borrows the captured context and starts a fresh quantum.
    clock.armed = false;
    clock.now = 1000;
    entry.expected_context = resumed_context;
    entry.called = false;
    try std.testing.expectEqual(@as(u32, 7), enterUserspaceWithClock(&executor, &clock, &entry));
    try std.testing.expect(entry.called);
    try std.testing.expectEqualDeep(neighbor_before, neighbor.*);
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

test "executor CPU registrations reject replacement and reset only their selected continuation" {
    const previous_index = cpu_identity.currentIndex();
    const previous_registrations = executor_registrations;
    var previous_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_entries, 0..) |*state, index| state.* = native_entry.stateForCpu(@intCast(index)).*;
    defer {
        executor_registrations = previous_registrations;
        for (&previous_entries, 0..) |*state, index| native_entry.stateForCpu(@intCast(index)).* = state.*;
        cpu_identity.setIndexForTest(previous_index);
    }
    executor_registrations = @splat(.{});
    const executors = try std.testing.allocator.alloc(Executor, cpu_identity.MAX_CPUS);
    defer std.testing.allocator.free(executors);
    var expected_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (executors, &expected_entries, 0..) |*executor, *state, index| {
        executor.* = .{};
        state.* = .{
            .kernel_stack_top = 0xffff_8000_1000_0000 + index * PAGE_SIZE,
            .user_stack_pointer = 0x7000_0000 + index * PAGE_SIZE,
            .kernel_port = 0xffff_8000_2000_0000 + index * 64,
            .active_task_id = 100 + index,
            .native_entry_modes = native_entry.ENTRY_READY | @as(u8, @intCast(index & 3)),
            .userspace_xstate = 0xffff_8000_3000_0000 + index * PAGE_SIZE,
            .kernel_xstate = 0xffff_8000_4000_0000 + index * PAGE_SIZE,
            .resume_rsp = 0xffff_8000_5000_0000 + index * PAGE_SIZE,
            .resume_rip = 0xffff_ffff_8000_0000 + index * 64,
            .resume_requested = @intCast(200 + index),
        };
        native_entry.stateForCpu(@intCast(index)).* = state.*;
    }
    var admitted: [cpu_identity.MAX_CPUS]bool = @splat(false);
    var unrelated = Executor{};
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        try std.testing.expect(claimCurrentExecutor(&executors[index]));
        try std.testing.expect(claimCurrentExecutor(&executors[index]));
        try std.testing.expect(!claimCurrentExecutor(&unrelated));
        try std.testing.expect(!releaseCurrentExecutor(&unrelated));
        admitted[index] = true;
        for (0..cpu_identity.MAX_CPUS) |neighbor| {
            const expected: ?*Executor = if (admitted[neighbor]) &executors[neighbor] else null;
            try std.testing.expectEqual(expected, executor_registrations[neighbor].executor);
            try std.testing.expectEqualDeep(expected_entries[neighbor], native_entry.stateForCpu(@intCast(neighbor)).*);
        }
    }
    const handle = installTestMappingAt(&executors[0], 0, .{ .state = .live, .address_space_id = 42 });
    cpu_identity.setIndexForTest(1);
    try std.testing.expect(!claimCurrentExecutor(&executors[0]));
    try std.testing.expect(!releaseCurrentExecutor(&executors[0]));
    try std.testing.expectError(error.WrongCpu, executors[0].resetChecked());
    try std.testing.expect(executors[0].findMappingByHandle(handle, 42) != null);
    try std.testing.expectEqual(@as(usize, 1), executors[0].materializedCount());
    try std.testing.expectError(error.WrongCpu, unrelated.resetChecked());
    for (&expected_entries, 0..) |*state, index| {
        try std.testing.expectEqualDeep(state.*, native_entry.stateForCpu(@intCast(index)).*);
        try std.testing.expectEqual(@as(?*Executor, &executors[index]), executor_registrations[index].executor);
    }
    var retired: [cpu_identity.MAX_CPUS]bool = @splat(false);
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) position / 2 else cpu_identity.MAX_CPUS - 1 - position / 2);
        cpu_identity.setIndexForTest(index);
        try executors[index].resetChecked();
        retired[index] = true;
        expected_entries[index].active_task_id = 0;
        expected_entries[index].userspace_xstate = 0;
        expected_entries[index].kernel_xstate = 0;
        expected_entries[index].resume_rsp = 0;
        expected_entries[index].resume_rip = 0;
        expected_entries[index].resume_requested = 0;
        for (0..cpu_identity.MAX_CPUS) |neighbor| {
            const expected: ?*Executor = if (retired[neighbor]) null else &executors[neighbor];
            try std.testing.expectEqual(expected, executor_registrations[neighbor].executor);
            try std.testing.expectEqualDeep(expected_entries[neighbor], native_entry.stateForCpu(@intCast(neighbor)).*);
        }
        try std.testing.expect(executors[index].registration_cpu == null);
    }
    try std.testing.expectEqual(@as(usize, 0), executors[0].materializedCount());
    try std.testing.expect(executors[0].findMappingByHandle(handle, 42) == null);
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(claimCurrentExecutor(&unrelated));
    try std.testing.expect(releaseCurrentExecutor(&unrelated));
}

test "trap stack geometry bounds the complete guard and usable extent" {
    try std.testing.expectEqual(@as(?usize, 0x1000), checkedTrapStackGeometry(0x1000, TRAP_STACK_TOTAL_BYTES));
    try std.testing.expectEqual(@as(?usize, 0x2000), checkedTrapStackGeometry(0x1001, TRAP_STACK_TOTAL_BYTES + PAGE_SIZE - 1));
    try std.testing.expect(checkedTrapStackGeometry(0x1001, TRAP_STACK_TOTAL_BYTES + PAGE_SIZE - 2) == null);
    try std.testing.expect(checkedTrapStackGeometry(0x1000, TRAP_STACK_TOTAL_BYTES - 1) == null);
    try std.testing.expect(checkedTrapStackGeometry(0, TRAP_STACK_TOTAL_BYTES) == null);
    try std.testing.expect(checkedTrapStackGeometry(std.math.maxInt(usize) - PAGE_SIZE + 1, TRAP_STACK_TOTAL_BYTES) == null);
    try std.testing.expect(checkedTrapStackGeometry(0x1000, std.math.maxInt(usize)) == null);
    for (0..cpu_identity.MAX_CPUS) |index| {
        const allocation = 0xffff_8000_1000_0000 + index * 16 * PAGE_SIZE + index * 31;
        const guard = checkedTrapStackGeometry(allocation, TRAP_STACK_TOTAL_BYTES + PAGE_SIZE - 1).?;
        try std.testing.expectEqual(@as(usize, 0), guard % PAGE_SIZE);
        try std.testing.expect(guard >= allocation and guard + TRAP_STACK_TOTAL_BYTES <= allocation + TRAP_STACK_TOTAL_BYTES + PAGE_SIZE - 1);
    }
    try std.testing.expectError(error.InvalidCpu, reserveTrapStackStorageForCpu(@intCast(cpu_identity.MAX_CPUS)));
}

const TrapStackTestBackend = struct {
    const Permissions = struct { user: bool = false, writable: bool = true, executable: bool = false };
    guard: usize,
    bad_page: ?usize = null,
    bad_permissions: Permissions = .{},
    checked: usize = 0,
    unmapped: usize = 0,
    unmap_succeeds: bool = true,
    guard_absent: bool = true,

    fn permissions(self: *@This(), address: usize) Permissions {
        if (address != self.guard + (self.checked + 1) * PAGE_SIZE) @panic("trap stack preflight must validate every usable leaf in order");
        self.checked += 1;
        return if (self.bad_page == address) self.bad_permissions else .{};
    }

    fn unmap(self: *@This(), address: usize) bool {
        if (address != self.guard or self.checked != TRAP_STACK_USABLE_BYTES / PAGE_SIZE) @panic("trap guard retirement requires complete usable-leaf preflight");
        self.unmapped += 1;
        return self.unmap_succeeds;
    }

    fn guardAbsent(self: *@This(), address: usize) bool {
        if (address != self.guard or self.unmapped != 1) @panic("trap guard absence follows one unmap");
        return self.guard_absent;
    }
};

test "trap stack provisioning validates every leaf before retiring its guard and retains failures" {
    const Buffer = struct { bytes: [TRAP_STACK_TOTAL_BYTES]u8 align(PAGE_SIZE) };
    const buffer = try std.testing.allocator.create(Buffer);
    defer std.testing.allocator.destroy(buffer);
    const guard = @intFromPtr(&buffer.bytes);
    for (0..TRAP_STACK_USABLE_BYTES / PAGE_SIZE) |page| {
        for ([_]TrapStackTestBackend.Permissions{
            .{ .user = true },
            .{ .writable = false },
            .{ .executable = true },
            .{ .user = true, .writable = false, .executable = true },
        }) |permissions| {
            @memset(&buffer.bytes, 0xa5);
            var slot = TrapStackSlot{};
            var backend = TrapStackTestBackend{ .guard = guard, .bad_page = guard + (page + 1) * PAGE_SIZE, .bad_permissions = permissions };
            try std.testing.expectError(error.InvalidTrapStackMapping, initializeTrapStackSlot(&slot, &buffer.bytes, &backend));
            try std.testing.expectEqual(@as(usize, 0), backend.unmapped);
            try std.testing.expect(slot.storage == &buffer.bytes and slot.failed and !@atomicLoad(bool, &slot.ready, .acquire));
            try std.testing.expect(std.mem.allEqual(u8, &buffer.bytes, 0xa5));
        }
    }
    for ([_]bool{ false, true }) |unmap_succeeds| {
        @memset(&buffer.bytes, 0xa5);
        var slot = TrapStackSlot{};
        var backend = TrapStackTestBackend{ .guard = guard, .unmap_succeeds = unmap_succeeds, .guard_absent = false };
        try std.testing.expectError(error.TrapStackGuardFailure, initializeTrapStackSlot(&slot, &buffer.bytes, &backend));
        try std.testing.expectEqual(@as(usize, 1), backend.unmapped);
        try std.testing.expect(slot.storage == &buffer.bytes and slot.failed and !@atomicLoad(bool, &slot.ready, .acquire));
        try std.testing.expect(std.mem.allEqual(u8, &buffer.bytes, 0xa5));
    }
    @memset(&buffer.bytes, 0xa5);
    var slot = TrapStackSlot{};
    var backend = TrapStackTestBackend{ .guard = guard };
    try initializeTrapStackSlot(&slot, &buffer.bytes, &backend);
    try std.testing.expect(@atomicLoad(bool, &slot.ready, .acquire) and !slot.failed);
    try std.testing.expectEqual(@as(usize, 1), backend.unmapped);
    try std.testing.expect(std.mem.allEqual(u8, buffer.bytes[0..TRAP_STACK_GUARD_BYTES], 0xa5));
    try std.testing.expect(std.mem.allEqual(u32, std.mem.bytesAsSlice(u32, buffer.bytes[TRAP_STACK_GUARD_BYTES..]), TRAP_STACK_PAINT_PATTERN));
}

test "trap stack slots publish only requested CPUs and preserve every neighbor" {
    const previous_index = cpu_identity.currentIndex();
    const previous_stacks = trap_stacks;
    defer {
        trap_stacks = previous_stacks;
        cpu_identity.setIndexForTest(previous_index);
    }
    trap_stacks = @splat(.{});
    const Buffer = struct { bytes: [TRAP_STACK_TOTAL_BYTES]u8 align(PAGE_SIZE) };
    const buffers = try std.testing.allocator.alloc(Buffer, cpu_identity.MAX_CPUS);
    defer std.testing.allocator.free(buffers);
    var admitted: [cpu_identity.MAX_CPUS]bool = @splat(false);
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        try std.testing.expect(currentTrapStackStorage() == null);
        try std.testing.expect(preparedKernelStackForCpu(index) == null);
        var backend = TrapStackTestBackend{ .guard = @intFromPtr(&buffers[index].bytes) };
        try initializeTrapStackSlot(&trap_stacks[index], &buffers[index].bytes, &backend);
        admitted[index] = true;
        for (0..cpu_identity.MAX_CPUS) |neighbor| {
            cpu_identity.setIndexForTest(@intCast(neighbor));
            if (admitted[neighbor]) {
                try std.testing.expect(currentTrapStackStorage() == &buffers[neighbor].bytes);
                const selected_top = @intFromPtr(trapStackStorage()) + TRAP_STACK_TOTAL_BYTES;
                try std.testing.expectEqual(@intFromPtr(&buffers[neighbor].bytes) + TRAP_STACK_TOTAL_BYTES, selected_top);
                try std.testing.expectEqual(@as(?usize, selected_top), preparedKernelStackForCpu(@intCast(neighbor)));
                try std.testing.expect(std.mem.allEqual(u32, std.mem.bytesAsSlice(u32, buffers[neighbor].bytes[TRAP_STACK_GUARD_BYTES..]), TRAP_STACK_PAINT_PATTERN));
            } else {
                try std.testing.expect(currentTrapStackStorage() == null);
                try std.testing.expect(trap_stacks[neighbor].storage == null);
                try std.testing.expect(preparedKernelStackForCpu(@intCast(neighbor)) == null);
            }
        }
    }
    try std.testing.expect(preparedKernelStackForCpu(@intCast(cpu_identity.MAX_CPUS)) == null);
    try std.testing.expect(preparedKernelStackForCpu(std.math.maxInt(u8)) == null);
}

const PreparedDispatchTestBackend = if (builtin.is_test) struct {
    coordinator: *dispatch_ownership.Coordinator,
    ticket: dispatch_ownership.Ticket,
    expected_context: UserContext64 = .{},
    expected_state: ?*align(xstate.alignment) xstate.State = null,
    fault: UserException = .{ .vector = 14, .error_code = 0x8000_0017, .instruction_pointer = 0x4000_1234, .fault_address = 0x4000_5678 },
    outcome: ExecutionOutcome = .yielded,
    writes: usize = 0,
    entered: usize = 0,
    activated: usize = 0,
    restored: usize = 0,
    queue_key: ?dispatch_transport.Key = null,
    expected_completion: dispatch_transport.Completion = .owner_returned,
    fail_write: bool = false,
    stack_ready: bool = true,
    kernel: bool = true,
    mailbox: userspace_bootstrap_mailbox.Mailbox = undefined,

    fn preparationReady(_: *@This()) bool {
        return true;
    }
    fn dispatchService(_: *@This(), _: u64) void {}
    fn stackTop(self: *@This(), cpu: u8) ?usize {
        return if (self.stack_ready) 0x8000_0000 + @as(usize, cpu) * 0x10000 else null;
    }
    fn writeMailbox(self: *@This(), _: *MappingEntry, update: ?BootstrapMailboxUpdate) bool {
        std.testing.expectEqual(dispatch_ownership.Phase.reserved, self.coordinator.phase(self.ticket) catch @panic("exact preparation ticket")) catch @panic("mailbox must finish before lease publication");
        const publication = update orelse return true;
        self.writes += 1;
        if (self.fail_write) return false;
        self.mailbox = kernelPublishedMailbox(publication, null);
        return true;
    }
    fn ownerAvailable(_: *@This()) bool {
        return true;
    }
    fn entryReady(self: *@This(), stack_top: usize) bool {
        return self.stackTop(cpu_identity.currentIndex()) == stack_top and self.kernel and continuationCleared(native_entry.current());
    }
    fn mask(_: *@This()) bool {
        return true;
    }
    fn restore(self: *@This(), enabled: bool) void {
        if (!enabled) @panic("fixture restores the local saved interrupt state");
        if (self.queue_key) |key| {
            const owner_cpu = cpu_identity.currentIndex();
            cpu_identity.setIndexForTest(0);
            defer cpu_identity.setIndexForTest(owner_cpu);
            var completion: dispatch_transport.Completion = undefined;
            if (self.restored == 0) {
                std.testing.expectError(error.WrongPhase, dispatch_transport.global.completionInto(key, &completion)) catch
                    @panic("inner runner return must precede independent completion");
            } else {
                dispatch_transport.global.completionInto(key, &completion) catch @panic("outer interrupt restoration follows transport completion");
                std.testing.expectEqual(self.expected_completion, completion) catch @panic("queued outcome has the exact completion kind");
            }
        }
        self.restored += 1;
    }
    fn activate(self: *@This(), _: *MappingEntry) void {
        var bound: dispatch_ownership.BoundIdentity = undefined;
        self.coordinator.boundIdentityInto(self.ticket, &bound) catch @panic("activation requires the claimed prepared lease");
        self.kernel = false;
        self.activated += 1;
    }
    fn enter(self: *@This(), executor: *Executor) void {
        var clock = Clock{};
        var entry = Entry{ .backend = self, .executor = executor };
        _ = enterUserspaceWithClock(executor, &clock, &entry);
        std.testing.expectEqual(@as(u8, 1), clock.armed) catch @panic("actual entry arms the quantum once");
        std.testing.expectEqual(DispatchQuantum.begin(executor.active_task_id, 100), executor.dispatch_quantum) catch @panic("quantum begins after preparation");
        native_entry.clearContinuation();
    }
    fn switchToKernel(self: *@This()) void {
        self.kernel = true;
    }
    fn kernelActive(self: *@This()) bool {
        return self.kernel;
    }
    const Clock = struct {
        armed: u8 = 0,
        fn armSchedulerTick(self: *@This()) void {
            self.armed += 1;
        }
        fn getTicks(_: *@This()) u64 {
            return 100;
        }
    };
    const Entry = struct {
        backend: *PreparedDispatchTestBackend,
        executor: *Executor,
        fn enter(self: *@This(), context: *const UserContext64, state: *align(xstate.alignment) xstate.State) u32 {
            std.testing.expect(context == &self.executor.active_mapping.?.user_context64) catch @panic("prepared entry borrows its exact selected mapping context");
            std.testing.expectEqualDeep(self.backend.expected_context, context.*) catch @panic("entry uses the immutable prepared context");
            std.testing.expect(state == self.backend.expected_state.?) catch @panic("entry uses private selected mapping xstate");
            self.backend.entered += 1;
            native_entry.current().resume_rsp = 0xfeed_1000;
            native_entry.current().resume_rip = 0xfeed_2000;
            native_entry.current().userspace_xstate = @intFromPtr(state);
            native_entry.current().kernel_xstate = 0xfeed_3000;
            switch (self.backend.outcome) {
                .unavailable => {},
                .faulted => requestUserExceptionHandoff(self.executor, self.backend.fault),
                .yielded, .wait_for_event => {
                    var frame = std.mem.zeroes(freestanding.isr.InterruptFrame);
                    frame.eax = 37;
                    frame.edx = 71;
                    frame.esi = @backingInt(if (self.backend.outcome == .wait_for_event)
                        userspace_bootstrap_mailbox.YieldDisposition.wait_for_event
                    else
                        userspace_bootstrap_mailbox.YieldDisposition.runnable);
                    frame.eip = context.instruction_pointer + 4;
                    frame.useresp = context.stack_pointer;
                    frame.eflags = context.flags;
                    handleUserspaceYield(self.executor, &frame);
                },
            }
            return 37;
        }
    };
} else struct {};

const PreparedDispatchTestFixture = if (builtin.is_test) struct {
    runtime: *task_runtime.Runtime = undefined,
    executor: Executor = .{},
    task: *task_runtime.TaskRecord = undefined,
    mapping: *MappingEntry = undefined,
    handle: MappingHandle = .{},
    ticket: dispatch_ownership.Ticket = undefined,
    previous_registration: ?*Executor = null,
    cpu: u8 = 0,
    catalog: userspace_loader.Catalog = userspace_loader.Catalog.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),

    fn init(self: *@This(), cpu: u8) !void {
        self.cpu = cpu;
        self.runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.OutOfMemory;
        self.runtime.initializeAllocated();
        errdefer table_backing.free(task_runtime.Runtime, self.runtime);
        var image = try @import("generated_image_fixtures.zig").appImage();
        self.task = try self.runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = @as(u64, cpu) + 1 },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 8192, .endpoint_slots = 2, .shared_memory_bytes = 0 },
            .local_only = true,
            .launch = .{ .boundary = .userspace_process, .image_id = 41, .component_abi_version = 1, .signed = true, .bundle_id = "app.notes" },
            .userspace_image = &image,
        });
        const storage = table_backing.alloc(xstate.Storage) orelse return error.OutOfMemory;
        storage.initialize();
        self.handle = installTestMappingAt(&self.executor, 0, .{
            .state = .live,
            .address_space_id = self.task.address_space_id,
            .address_space = .{ .directory = @ptrFromInt((@as(usize, cpu) + 1) * PAGE_SIZE), .pcid = cpu + 1 },
            .dispatch_metadata = .{ .owner_task_id = self.task.id, .image_id = 41, .initial_instruction_pointer = 0x4000_1000, .initial_stack_pointer = 0x7fff_fff0, .bootstrap_mailbox_address = 0x4000_4000 },
            .owned_xstate = storage,
        });
        self.mapping = self.executor.findMappingByHandle(self.handle, self.task.address_space_id).?;
        self.executor.initialized = true;
        self.executor.bound_runtime = self.runtime;
        self.executor.registration_cpu = cpu;
        self.previous_registration = registeredExecutor(cpu);
        executor_registrations[cpu].executor = &self.executor;
        self.ticket = try self.runtime.reserveExecution(self.task, cpu);
    }
    fn prepare(self: *@This(), out: *PreparedDispatch, backend: *PreparedDispatchTestBackend) bool {
        return self.executor.prepareTaskDispatchInto(&self.catalog, self.runtime, &self.capabilities, self.task, &self.handle, 10, self.ticket, out, backend);
    }
    fn makeBackend(self: *@This()) PreparedDispatchTestBackend {
        return .{ .coordinator = &self.runtime.execution, .ticket = self.ticket, .expected_state = self.mapping.owned_xstate.?.state() };
    }
    fn collect(self: *@This(), out: *ReturnRecord) !void {
        try std.testing.expectError(error.WrongPhase, self.runtime.collectExecution(self.ticket));
        try self.runtime.execution.consumePreparedReturnInto(self.ticket, out);
        try self.runtime.collectExecution(self.ticket);
    }
    fn deinit(self: *@This()) void {
        if (self.runtime.execution.hasLeases()) @panic("fixture must collect its exact lease before cleanup");
        executor_registrations[self.cpu].executor = self.previous_registration;
        self.executor.registration_cpu = null;
        self.executor.bound_runtime = null;
        self.executor.reset();
        self.runtime.reset();
        table_backing.free(task_runtime.Runtime, self.runtime);
    }
} else struct {};

test "prepared owner boundary runs all selected private contexts and consumes exact receipts" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    var previous_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_entries, 0..) |*entry, cpu| entry.* = native_entry.stateForCpu(@intCast(cpu)).*;
    defer for (previous_entries, 0..) |entry, cpu| {
        native_entry.stateForCpu(@intCast(cpu)).* = entry;
    };
    for (0..cpu_identity.MAX_CPUS) |index| {
        for ([_]ExecutionOutcome{ .unavailable, .yielded, .wait_for_event, .faulted }) |outcome| {
            cpu_identity.setIndexForTest(0);
            var fixture = PreparedDispatchTestFixture{};
            try fixture.init(@intCast(index));
            defer fixture.deinit();
            if (index % 2 != 0) {
                fixture.mapping.resume_valid = true;
                fixture.mapping.user_context64 = .{ .rax = 91, .r15 = 93, .instruction_pointer = 0x4000_9876, .stack_pointer = 0x7fff_8880 };
            }
            var backend = fixture.makeBackend();
            backend.outcome = outcome;
            var prepared: PreparedDispatch = undefined;
            try std.testing.expect(fixture.prepare(&prepared, &backend));
            backend.expected_context = fixture.mapping.user_context64;
            try std.testing.expectEqual(@as(usize, 1), backend.writes);
            try std.testing.expectEqual(fixture.task.id, backend.mailbox.task_id);
            try std.testing.expectEqual(dispatch_ownership.Phase.ready, try fixture.runtime.execution.phase(fixture.ticket));
            const context_before = fixture.mapping.user_context64;
            const command_before = prepared;
            try std.testing.expect(!fixture.executor.userAddressSpacePreparationReady(&fixture.mapping.address_space.?));
            try std.testing.expect(!fixture.prepare(&prepared, &backend));
            try std.testing.expectEqualDeep(context_before, fixture.mapping.user_context64);
            try std.testing.expectEqual(command_before, prepared);

            var neighbors: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
            for (&neighbors, 0..) |*entry, cpu| entry.* = native_entry.stateForCpu(@intCast(cpu)).*;
            cpu_identity.setIndexForTest(@intCast(index));
            native_entry.current().active_task_id = 0;
            native_entry.clearContinuation();
            try std.testing.expect(fixture.executor.runPreparedTaskSlice(&prepared, &backend));
            try std.testing.expectEqual(@as(usize, 1), backend.activated);
            try std.testing.expectEqual(@as(usize, 1), backend.entered);
            try std.testing.expectEqual(@as(usize, 1), backend.restored);
            try std.testing.expectEqual(@as(usize, 1), backend.writes);
            try std.testing.expect(continuationCleared(native_entry.current()));
            try std.testing.expectEqual(@as(u64, 0), fixture.executor.active_task_id);
            try std.testing.expect(fixture.executor.active_mapping == null and fixture.executor.active_dispatch_lease == null);
            for (neighbors, 0..) |neighbor, cpu| if (cpu != index)
                try std.testing.expectEqualDeep(neighbor, native_entry.stateForCpu(@intCast(cpu)).*);
            cpu_identity.setIndexForTest(0);
            var record: ReturnRecord = undefined;
            try fixture.collect(&record);
            try std.testing.expectEqual(outcome, record.outcome);
            try std.testing.expectEqual(@as(u64, if (outcome == .yielded or outcome == .wait_for_event) 71 else 0), record.ui_revision);
            if (outcome == .faulted) {
                try std.testing.expectEqual(backend.fault.vector, record.fault_vector);
                try std.testing.expectEqual(backend.fault.error_code, record.fault_error_code);
                try std.testing.expectEqual(backend.fault.instruction_pointer, record.fault_instruction_pointer);
                try std.testing.expectEqual(backend.fault.fault_address, record.fault_address);
            }
        }
    }
}

test "queued prepared owner completes durable transport after ACK on every CPU" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    var previous_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_entries, 0..) |*state, cpu| state.* = native_entry.stateForCpu(@intCast(cpu)).*;
    defer for (previous_entries, 0..) |state, cpu| {
        native_entry.stateForCpu(@intCast(cpu)).* = state;
    };
    for (0..cpu_identity.MAX_CPUS) |index| {
        for ([_]ExecutionOutcome{ .unavailable, .yielded, .wait_for_event, .faulted }) |outcome| {
            cpu_identity.setIndexForTest(0);
            var fixture = PreparedDispatchTestFixture{};
            try fixture.init(@intCast(index));
            defer fixture.deinit();
            var backend = fixture.makeBackend();
            backend.outcome = outcome;
            var command: PreparedDispatch = undefined;
            try std.testing.expect(fixture.prepare(&command, &backend));
            backend.expected_context = fixture.mapping.user_context64;
            var key: dispatch_transport.Key = undefined;
            try dispatch_transport.global.publishInto(command, &key);
            backend.queue_key = key;
            try std.testing.expectError(error.Busy, fixture.runtime.collectExecution(fixture.ticket));
            var neighbors: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
            for (&neighbors, 0..) |*state, cpu| state.* = native_entry.stateForCpu(@intCast(cpu)).*;
            cpu_identity.setIndexForTest(@intCast(index));
            native_entry.current().active_task_id = 0;
            native_entry.clearContinuation();
            try std.testing.expect(runQueuedPreparedTaskSlice(false, &backend, null, null, null, null));
            try std.testing.expectEqual(@as(usize, 1), backend.activated);
            try std.testing.expectEqual(@as(usize, 1), backend.entered);
            try std.testing.expectEqual(@as(usize, 2), backend.restored);
            try std.testing.expect(!runQueuedPreparedTaskSlice(false, &backend, null, null, null, null));
            try std.testing.expect(continuationCleared(native_entry.current()));
            try std.testing.expect(fixture.executor.active_mapping == null and fixture.executor.active_dispatch_lease == null);
            for (neighbors, 0..) |neighbor, cpu| if (cpu != index)
                try std.testing.expectEqualDeep(neighbor, native_entry.stateForCpu(@intCast(cpu)).*);
            cpu_identity.setIndexForTest(0);
            try std.testing.expect(executionOwnershipOutstanding(fixture.runtime));
            var record: ReturnRecord = undefined;
            // The first collection fails receipt admission and must return the
            // channel to completed before exact receipt consumption and retry.
            try fixture.collect(&record);
            try std.testing.expectEqual(outcome, record.outcome);
            if (outcome == .faulted) {
                try std.testing.expectEqual(backend.fault.vector, record.fault_vector);
                try std.testing.expectEqual(backend.fault.error_code, record.fault_error_code);
                try std.testing.expectEqual(backend.fault.fault_address, record.fault_address);
            }
            try std.testing.expect(!executionOwnershipOutstanding(fixture.runtime));
            var completion: dispatch_transport.Completion = undefined;
            try std.testing.expectError(error.StaleKey, dispatch_transport.global.completionInto(key, &completion));
        }
    }
}

test "prompted queued owner waits for interrupt return and authenticates delayed replacement hints" {
    const prompted_isr = @import("../../kernel/interrupts/isr.zig");
    const prompted_gdt = @import("../../kernel/interrupts/gdt64.zig");
    const Case = struct {
        fn prompt() void {
            var frame = std.mem.zeroes(prompted_isr.InterruptFrame);
            frame.int_no = smp.PREPARED_EXECUTION_IPI_VECTOR;
            frame.cs = prompted_gdt.KERNEL_CODE_SEG;
            prompted_isr.isrHandler(&frame);
        }
        fn run(_: void) !void {
            for (0..cpu_identity.MAX_CPUS) |index| {
                const cpu: u8 = @intCast(index);
                cpu_identity.setIndexForTest(cpu);
                _ = try dispatch_transport.global.takePrompt(cpu);
                cpu_identity.setIndexForTest(0);
                var fixture = PreparedDispatchTestFixture{};
                try fixture.init(cpu);
                defer fixture.deinit();
                var backend = fixture.makeBackend();
                var command: PreparedDispatch = undefined;
                try std.testing.expect(fixture.prepare(&command, &backend));
                backend.expected_context = fixture.mapping.user_context64;
                var key: dispatch_transport.Key = undefined;
                try dispatch_transport.global.publishInto(command, &key);
                const context_before = fixture.mapping.user_context64;
                cpu_identity.setIndexForTest(cpu);
                native_entry.current().active_task_id = 0;
                native_entry.clearContinuation();
                try std.testing.expect(!runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                try std.testing.expectEqual(@as(usize, 0), backend.activated);
                try std.testing.expectEqual(@as(usize, 1), backend.restored);
                try std.testing.expectEqualDeep(context_before, fixture.mapping.user_context64);
                // A received prompt is retained during interrupt context. Its
                // immutable handler never claims the pending command itself.
                prompt();
                prompt();
                cpu_identity.setIndexForTest(0);
                try std.testing.expectEqual(dispatch_ownership.Phase.ready, try fixture.runtime.execution.phase(fixture.ticket));
                cpu_identity.setIndexForTest(cpu);
                try std.testing.expectEqual(@as(usize, 0), backend.entered);
                interrupt_context.enter();
                const entered_in_interrupt = runQueuedPreparedTaskSlice(true, &backend, null, null, null, null);
                interrupt_context.leave();
                try std.testing.expect(!entered_in_interrupt);
                try std.testing.expectEqual(@as(usize, 0), backend.entered);
                backend.restored = 0;
                backend.queue_key = key;
                try std.testing.expect(runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                try std.testing.expectEqual(@as(usize, 1), backend.activated);
                try std.testing.expectEqual(@as(usize, 1), backend.entered);
                try std.testing.expectEqual(@as(usize, 2), backend.restored);
                try std.testing.expect(!runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                // A duplicate doorbell can inspect only the completed channel;
                // it cannot repeat the callback or acknowledge the lease.
                prompt();
                try std.testing.expect(!runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                try std.testing.expectEqual(@as(usize, 1), backend.entered);
                cpu_identity.setIndexForTest(0);
                var record: ReturnRecord = undefined;
                try fixture.collect(&record);
                try std.testing.expectEqual(ExecutionOutcome.yielded, record.outcome);
                const old_key = key;
                // Retain a delayed hint while the channel is idle. A later
                // publication must keep it and authenticate its own new epoch.
                cpu_identity.setIndexForTest(cpu);
                prompt();
                cpu_identity.setIndexForTest(0);
                fixture.ticket = try fixture.runtime.reserveExecution(fixture.task, cpu);
                backend = fixture.makeBackend();
                try std.testing.expect(fixture.prepare(&command, &backend));
                backend.expected_context = fixture.mapping.user_context64;
                try dispatch_transport.global.publishInto(command, &key);
                try std.testing.expect(key.sequence > old_key.sequence);
                backend.queue_key = key;
                cpu_identity.setIndexForTest(cpu);
                try std.testing.expect(runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                try std.testing.expectEqual(@as(usize, 1), backend.entered);
                try std.testing.expectEqual(@as(usize, 2), backend.restored);
                cpu_identity.setIndexForTest(0);
                var completion: dispatch_transport.Completion = undefined;
                try std.testing.expectError(error.StaleKey, dispatch_transport.global.completionInto(old_key, &completion));
                try fixture.collect(&record);
                try std.testing.expectEqual(ExecutionOutcome.yielded, record.outcome);
                try std.testing.expect(!executionOwnershipOutstanding(fixture.runtime));
                backend.queue_key = null;
                cpu_identity.setIndexForTest(cpu);
                prompt();
                try std.testing.expect(!runQueuedPreparedTaskSlice(true, &backend, null, null, null, null));
                try std.testing.expectEqual(@as(usize, 1), backend.entered);
                cpu_identity.setIndexForTest(0);
            }
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    var previous_entries: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_entries, 0..) |*state, cpu| state.* = native_entry.stateForCpu(@intCast(cpu)).*;
    defer for (previous_entries, 0..) |state, cpu| {
        native_entry.stateForCpu(@intCast(cpu)).* = state;
    };
    try prompted_isr.withTestHandlers({}, Case.run);
}

test "queued claimed cancellation retains the source until unstarted owner completion" {
    const Hook = struct {
        fixture: *PreparedDispatchTestFixture,
        receipt: ReturnRecord = .{},
        fn cancel(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const owner_cpu = cpu_identity.currentIndex();
            cpu_identity.setIndexForTest(0);
            defer cpu_identity.setIndexForTest(owner_cpu);
            self.fixture.runtime.cancelUnstartedExecution(self.fixture.ticket) catch @panic("cancel exact claimed ready lease");
            self.fixture.runtime.execution.consumePreparedReturnInto(self.fixture.ticket, &self.receipt) catch @panic("consume canceled prepared receipt");
            std.testing.expectEqual(ExecutionOutcome.unavailable, self.receipt.outcome) catch @panic("cancellation returns unavailable");
            std.testing.expectError(error.Busy, self.fixture.runtime.collectExecution(self.fixture.ticket)) catch @panic("claimed reader retains its source after cancellation");
            std.testing.expectError(error.TaskRuntimeBorrowed, self.fixture.runtime.requireExecutionQuiescent()) catch @panic("reset retains a claimed reader");
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(0);
        var fixture = PreparedDispatchTestFixture{};
        try fixture.init(@intCast(index));
        defer fixture.deinit();
        const previous_entry = native_entry.stateForCpu(@intCast(index)).*;
        defer native_entry.stateForCpu(@intCast(index)).* = previous_entry;
        var backend = fixture.makeBackend();
        var command: PreparedDispatch = undefined;
        try std.testing.expect(fixture.prepare(&command, &backend));
        var key: dispatch_transport.Key = undefined;
        try dispatch_transport.global.publishInto(command, &key);
        backend.queue_key = key;
        backend.expected_completion = .unstarted;
        var hook = Hook{ .fixture = &fixture };
        cpu_identity.setIndexForTest(@intCast(index));
        native_entry.current().active_task_id = 0;
        native_entry.clearContinuation();
        try std.testing.expect(runQueuedPreparedTaskSlice(false, &backend, null, Hook.cancel, null, &hook));
        try std.testing.expectEqual(@as(usize, 0), backend.activated);
        try std.testing.expectEqual(@as(usize, 0), backend.entered);
        try std.testing.expectEqual(@as(usize, 2), backend.restored);
        cpu_identity.setIndexForTest(0);
        var completion: dispatch_transport.Completion = undefined;
        try dispatch_transport.global.completionInto(key, &completion);
        try std.testing.expectEqual(dispatch_transport.Completion.unstarted, completion);
        try fixture.runtime.collectExecution(fixture.ticket);
        try std.testing.expect(!executionOwnershipOutstanding(fixture.runtime));
    }
}

test "prepared BSP boundary preserves failed output and retries mailbox publication" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var fixture = PreparedDispatchTestFixture{};
    try fixture.init(3);
    defer fixture.deinit();
    var backend = fixture.makeBackend();
    var prepared: PreparedDispatch = .{ .ticket = fixture.ticket, .trap_stack_top = 0x98000 };
    const canary = prepared;
    const original_cache = fixture.mapping.mailbox_publication_cache;
    backend.stack_ready = false;
    try std.testing.expect(!fixture.prepare(&prepared, &backend));
    try std.testing.expectEqualDeep(canary, prepared);
    try std.testing.expectEqual(@as(usize, 0), backend.writes);
    backend.stack_ready = true;
    backend.fail_write = true;
    try std.testing.expect(!fixture.prepare(&prepared, &backend));
    try std.testing.expectEqualDeep(canary, prepared);
    try std.testing.expectEqual(original_cache, fixture.mapping.mailbox_publication_cache);
    try std.testing.expect(!fixture.mapping.initial_mailbox_prepared);
    try std.testing.expectEqual(dispatch_ownership.Phase.reserved, try fixture.runtime.execution.phase(fixture.ticket));
    backend.fail_write = false;
    try std.testing.expect(fixture.prepare(&prepared, &backend));
    try std.testing.expectEqual(@as(usize, 2), backend.writes);
    try std.testing.expect(fixture.mapping.initial_mailbox_prepared);
    try fixture.runtime.execution.cancelUnstarted(fixture.ticket);
    var record: ReturnRecord = undefined;
    try fixture.collect(&record);
    try std.testing.expectEqualDeep(ReturnRecord{}, record);
}

test "prepared owner rejects wrong local authority and stale commands before user activation" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    const previous_entry = native_entry.stateForCpu(3).*;
    defer native_entry.stateForCpu(3).* = previous_entry;
    for ([_]enum { domain, handle, root, owner, stack, missing_xstate }{ .domain, .handle, .root, .owner, .stack, .missing_xstate }) |failure| {
        cpu_identity.setIndexForTest(0);
        var fixture = PreparedDispatchTestFixture{};
        try fixture.init(3);
        defer fixture.deinit();
        var backend = fixture.makeBackend();
        var prepared: PreparedDispatch = undefined;
        try std.testing.expect(fixture.prepare(&prepared, &backend));
        const valid = prepared;
        const storage = fixture.mapping.owned_xstate;
        const owner = fixture.mapping.dispatch_metadata.owner_task_id;
        const directory = fixture.mapping.address_space.?.directory;
        const runtime_binding = fixture.executor.bound_runtime;
        const saved_mapping = fixture.mapping.*;
        switch (failure) {
            .domain => fixture.executor.bound_runtime = null,
            .handle => {
                fixture.executor.mappingArena().?.getByHandle(fixture.handle).?.mapping.state = .retire_pending;
            },
            .root => fixture.mapping.address_space.?.directory = @ptrFromInt(0x99000),
            .owner => fixture.mapping.dispatch_metadata.owner_task_id += 1,
            .stack => prepared.trap_stack_top += PAGE_SIZE,
            .missing_xstate => fixture.mapping.owned_xstate = null,
        }
        cpu_identity.setIndexForTest(3);
        native_entry.current().active_task_id = 0;
        native_entry.clearContinuation();
        try std.testing.expect(fixture.executor.runPreparedTaskSlice(&prepared, &backend));
        try std.testing.expectEqual(@as(usize, 0), backend.activated);
        try std.testing.expectEqual(@as(usize, 0), backend.entered);
        fixture.mapping.owned_xstate = storage;
        fixture.mapping.dispatch_metadata.owner_task_id = owner;
        fixture.mapping.address_space.?.directory = directory;
        fixture.mapping.state = saved_mapping.state;
        fixture.executor.bound_runtime = runtime_binding;
        cpu_identity.setIndexForTest(0);
        var record: ReturnRecord = undefined;
        try fixture.collect(&record);
        try std.testing.expectEqualDeep(ReturnRecord{}, record);
        fixture.ticket = try fixture.runtime.reserveExecution(fixture.task, 3);
        backend.ticket = fixture.ticket;
        try std.testing.expect(fixture.prepare(&prepared, &backend));
        cpu_identity.setIndexForTest(3);
        try std.testing.expect(!fixture.executor.runPreparedTaskSlice(&valid, &backend));
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(dispatch_ownership.Phase.ready, try fixture.runtime.execution.phase(fixture.ticket));
        try fixture.runtime.execution.cancelUnstarted(fixture.ticket);
        try fixture.collect(&record);
    }
}

test "prepared owner rejects a foreign Coordinator despite colliding bound mapping authority" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    const previous_entry = native_entry.stateForCpu(3).*;
    defer native_entry.stateForCpu(3).* = previous_entry;
    cpu_identity.setIndexForTest(0);
    var fixture = PreparedDispatchTestFixture{};
    try fixture.init(3);
    defer fixture.deinit();
    var backend = fixture.makeBackend();
    var prepared: PreparedDispatch = undefined;
    try std.testing.expect(fixture.prepare(&prepared, &backend));
    var foreign = dispatch_ownership.Coordinator{};
    const identity = try fixture.runtime.execution.identity(fixture.ticket);
    const foreign_ticket = try foreign.prepare(3, identity);
    try foreign.bindPrepared(foreign_ticket, fixture.handle.value, mappingPhysicalRoot(fixture.mapping));
    const before = fixture.mapping.*;
    const command = PreparedDispatch{ .ticket = foreign_ticket, .trap_stack_top = prepared.trap_stack_top };
    cpu_identity.setIndexForTest(3);
    native_entry.current().active_task_id = 0;
    native_entry.clearContinuation();
    try std.testing.expect(fixture.executor.runPreparedTaskSlice(&command, &backend));
    try std.testing.expectEqual(@as(usize, 0), backend.activated);
    try std.testing.expectEqual(@as(usize, 0), backend.entered);
    try std.testing.expectEqualDeep(before, fixture.mapping.*);
    cpu_identity.setIndexForTest(0);
    var record: ReturnRecord = undefined;
    try foreign.consumePreparedReturnInto(foreign_ticket, &record);
    try std.testing.expectEqualDeep(ReturnRecord{}, record);
    _ = try foreign.beginCollect(foreign_ticket);
    try foreign.finishCollect(foreign_ticket);
    try std.testing.expectEqual(dispatch_ownership.Phase.ready, try fixture.runtime.execution.phase(fixture.ticket));
    try fixture.runtime.execution.cancelUnstarted(fixture.ticket);
    try fixture.collect(&record);
}
