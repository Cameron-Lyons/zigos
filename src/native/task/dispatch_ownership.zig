const std = @import("std");
const cpu_identity = @import("../../kernel/cpu_identity.zig");

pub const CAPACITY = cpu_identity.MAX_CPUS;
pub const Ticket = struct { cpu: u8, epoch: u64, issuer: *const Coordinator };
pub const Identity = struct {
    task_handle: u64 = 0,
    task_id: u64 = 0,
    process_generation: u64 = 0,
    address_space_id: u64 = 0,
};
pub const BoundIdentity = struct {
    identity: Identity,
    mapping_handle: u64,
    physical_root: u64,
};
pub const Outcome = enum(u8) {
    unavailable,
    yielded,
    wait_for_event,
    faulted,

    pub inline fn handedOff(self: @This()) bool {
        return self != .unavailable;
    }
};
// The owner publishes this execution receipt only after its last access to
// task backing. BSP consumption is required before prepared lease collection.
pub const ReturnRecord = extern struct {
    ui_revision: u64 = 0,
    fault_instruction_pointer: u64 = 0,
    fault_address: u64 = 0,
    fault_error_code: u32 = 0,
    outcome: Outcome = .unavailable,
    fault_vector: u8 = 0,
    reserved: u16 = 0,
};
// These are transport metadata. Only the BSP broker authenticates the opcode
// and user spans; publishing an envelope confers no memory or syscall authority.
pub const Envelope = extern struct {
    opcode: u16,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
};
pub const Reply = extern struct { status: u16, denial_reason: u16, bytes_written: u32 };
pub const RequestKey = struct { ticket: Ticket, sequence: u64 };
pub const ClaimedSyscall = struct { key: RequestKey, envelope: Envelope, bound: BoundIdentity };
pub const Phase = enum(u3) { idle, reserved, ready, running, returned, collecting, returning, return_consumed };
pub const Error = error{
    WrongCpu,
    WrongCoordinator,
    InvalidCpu,
    InvalidIdentity,
    Busy,
    EpochExhausted,
    StaleTicket,
    WrongPhase,
    WrongPurpose,
    InvalidReturnRecord,
    StopRequested,
    InvalidMapping,
    RootAlreadyLeased,
    NoRequest,
    NotReady,
    StaleRequest,
    SequenceExhausted,
    SyscallInFlight,
};

const STOP: u64 = 8;
const PREPARED: u64 = 16;
const PHASE_MASK: u64 = 7;
const EPOCH_SHIFT = 5;
const MAX_EPOCH = std.math.maxInt(u64) >> EPOCH_SHIFT;
const SYSCALL_IDLE: u64 = 0;
const SYSCALL_PENDING: u64 = 1;
const SYSCALL_PROCESSING: u64 = 2;
const SYSCALL_COMPLETE: u64 = 3;
// Reserve before touching the envelope, so a nested owner cannot overwrite it
// and a BSP reader cannot claim a partially published request.
const SYSCALL_PUBLISHING: u64 = 4;
const SYSCALL_PHASE_MASK: u64 = 7;
const SYSCALL_SEQUENCE_SHIFT = 3;
const MAX_SYSCALL_SEQUENCE = std.math.maxInt(u64) >> SYSCALL_SEQUENCE_SHIFT;

// Runtime backing has eight-byte alignment. A 136-byte active payload followed
// by 56 bytes of padding keeps neighboring CPU payloads on disjoint cache lines
// without imposing an unsupported alignment requirement on its heap allocation.
const Slot = struct {
    control: u64 = 0,
    identity: Identity = .{},
    mapping_handle: u64 = 0,
    physical_root: u64 = 0,
    syscall_control: u64 = 0,
    envelope: Envelope = .{ .opcode = 0, .request_addr = 0, .response_addr = 0, .response_len = 0 },
    reply: Reply = .{ .status = 0, .denial_reason = 0, .bytes_written = 0 },
    return_record: ReturnRecord = .{},
    padding: [56]u8 = @splat(0),
};

pub const Coordinator = struct {
    slots: [CAPACITY]Slot = @splat(.{}),
    next_epoch: u64 = 1,

    pub fn prepare(self: *@This(), cpu: u8, task: Identity) Error!Ticket {
        var ticket: Ticket = undefined;
        try self.prepareInto(cpu, task, &ticket);
        return ticket;
    }

    pub fn prepareInto(self: *@This(), cpu: u8, task: Identity, out: *Ticket) Error!void {
        try requireBsp();
        if (cpu >= CAPACITY) return error.InvalidCpu;
        if (task.task_handle == 0 or task.task_id == 0 or task.process_generation == 0 or task.address_space_id == 0)
            return error.InvalidIdentity;
        if (self.next_epoch == 0 or self.next_epoch > MAX_EPOCH) return error.EpochExhausted;
        const slot = &self.slots[cpu];
        if (phaseOf(@atomicLoad(u64, &slot.control, .acquire)) != .idle or self.hasLeaseForTask(task.task_id))
            return error.Busy;
        try requireSyscallIdle(slot);
        const epoch = self.next_epoch;
        self.next_epoch = if (epoch == MAX_EPOCH) 0 else epoch + 1;
        slot.identity = task;
        slot.mapping_handle = 0;
        slot.physical_root = 0;
        @atomicStore(u64, &slot.control, packControl(epoch, .reserved, false, false), .release);
        out.* = .{ .cpu = cpu, .epoch = epoch, .issuer = self };
    }

    pub fn bindOwnedRoot(self: *@This(), ticket: Ticket, mapping_handle: u64, physical_root: u64) Error!void {
        try self.bindForPurpose(ticket, mapping_handle, physical_root, false);
    }

    pub inline fn bindPrepared(self: *@This(), ticket: Ticket, mapping_handle: u64, physical_root: u64) Error!void {
        try self.bindForPurpose(ticket, mapping_handle, physical_root, true);
    }

    // A queued shell retains this exact prepared lease before a selected CPU
    // can claim it. Publication confers no running-owner or mapping authority.
    pub fn preparedReady(self: *const @This(), ticket: Ticket) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (control & PREPARED == 0) return error.WrongPurpose;
        if (phaseOf(control) != .ready) return error.WrongPhase;
        if (control & STOP != 0) return error.StopRequested;
        try requireSyscallIdle(slot);
    }

    inline fn bindForPurpose(self: *@This(), ticket: Ticket, mapping_handle: u64, physical_root: u64, prepared: bool) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (phaseOf(control) != .reserved) return error.WrongPhase;
        if (control & STOP != 0) return error.StopRequested;
        if (mapping_handle == 0 or physical_root == 0 or physical_root % 4096 != 0 or physical_root >= (@as(u64, 1) << 52))
            return error.InvalidMapping;
        if (!self.rootAvailable(physical_root)) return error.RootAlreadyLeased;
        slot.mapping_handle = mapping_handle;
        slot.physical_root = physical_root;
        @atomicStore(u64, &slot.control, packControl(ticket.epoch, .ready, false, prepared), .release);
    }

    pub fn start(self: *@This(), ticket: Ticket) Error!BoundIdentity {
        var bound: BoundIdentity = undefined;
        try self.startInto(ticket, &bound);
        return bound;
    }

    pub fn startInto(self: *@This(), ticket: Ticket, out: *BoundIdentity) Error!void {
        try self.startForPurpose(ticket, out, false);
    }

    pub inline fn startPreparedInto(self: *@This(), ticket: Ticket, out: *BoundIdentity) Error!void {
        try self.startForPurpose(ticket, out, true);
    }

    inline fn startForPurpose(self: *@This(), ticket: Ticket, out: *BoundIdentity, require_prepared: bool) Error!void {
        try requireOwner(ticket);
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (require_prepared and control & PREPARED == 0) return error.WrongPurpose;
        if (phaseOf(control) != .ready) return error.WrongPhase;
        if (control & STOP != 0) return error.StopRequested;
        try requireSyscallIdle(slot);
        // Claim running before reading immutable payload. Otherwise BSP could
        // cancel/collect/reuse a ready slot while its owner was copying identity.
        if (@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .running), .acq_rel, .acquire)) |changed| {
            try requireTicket(changed, ticket);
            return if (changed & STOP != 0) error.StopRequested else error.WrongPhase;
        }
        out.* = .{ .identity = slot.identity, .mapping_handle = slot.mapping_handle, .physical_root = slot.physical_root };
    }

    // Owner calls are serialized on the selected CPU (native callers keep IF
    // clear). A running lease pins this immutable receipt without BSP lookups.
    pub fn boundIdentityInto(self: *@This(), ticket: Ticket, out: *BoundIdentity) Error!void {
        try requireOwner(ticket);
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        try requireRunning(@atomicLoad(u64, &slot.control, .acquire), ticket);
        out.* = .{ .identity = slot.identity, .mapping_handle = slot.mapping_handle, .physical_root = slot.physical_root };
    }

    pub fn submitSyscallInto(self: *@This(), ticket: Ticket, envelope: Envelope, out: *RequestKey) Error!void {
        try requireOwner(ticket);
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireRunning(control, ticket);
        if (control & STOP != 0) return error.StopRequested;
        const previous = @atomicLoad(u64, &slot.syscall_control, .acquire);
        if (syscallPhase(previous) != SYSCALL_IDLE) return error.Busy;
        const sequence = syscallSequence(previous);
        if (sequence == MAX_SYSCALL_SEQUENCE) return error.SequenceExhausted;
        const next = sequence + 1;
        if (@cmpxchgStrong(u64, &slot.syscall_control, previous, packSyscall(next, SYSCALL_PUBLISHING), .acq_rel, .acquire) != null)
            return error.Busy;
        const admitted = @atomicLoad(u64, &slot.control, .acquire);
        requireRunning(admitted, ticket) catch |err| {
            @atomicStore(u64, &slot.syscall_control, packSyscall(next, SYSCALL_IDLE), .release);
            return err;
        };
        if (admitted & STOP != 0) {
            @atomicStore(u64, &slot.syscall_control, packSyscall(next, SYSCALL_IDLE), .release);
            return error.StopRequested;
        }
        slot.envelope = envelope;
        @atomicStore(u64, &slot.syscall_control, packSyscall(next, SYSCALL_PENDING), .release);
        out.* = .{ .ticket = ticket, .sequence = next };
    }

    pub fn claimSyscallInto(self: *@This(), cpu: u8, out: *ClaimedSyscall) Error!void {
        try requireBsp();
        if (cpu >= CAPACITY) return error.InvalidCpu;
        const slot = &self.slots[cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        if (phaseOf(control) != .running) return error.WrongPhase;
        if (control & STOP != 0) return error.StopRequested;
        const request = @atomicLoad(u64, &slot.syscall_control, .acquire);
        if (syscallPhase(request) != SYSCALL_PENDING) return error.NoRequest;
        const sequence = syscallSequence(request);
        if (sequence == 0) return error.StaleRequest;
        if (@cmpxchgStrong(u64, &slot.syscall_control, request, packSyscall(sequence, SYSCALL_PROCESSING), .acq_rel, .acquire) != null)
            return error.NoRequest;
        out.* = .{
            .key = .{ .ticket = .{ .cpu = cpu, .epoch = epochOf(control), .issuer = self }, .sequence = sequence },
            .envelope = slot.envelope,
            .bound = .{ .identity = slot.identity, .mapping_handle = slot.mapping_handle, .physical_root = slot.physical_root },
        };
    }

    // Authenticate the complete claimed receipt before any copied request is
    // invoked. STOP after claim must still produce a reply that the owner drains.
    pub fn validateClaimInto(self: *@This(), claim: *const ClaimedSyscall, out: *BoundIdentity, out_stopped: *bool) Error!void {
        try requireBsp();
        const slot = try self.processingSlot(claim.key);
        const bound = BoundIdentity{ .identity = slot.identity, .mapping_handle = slot.mapping_handle, .physical_root = slot.physical_root };
        if (!std.meta.eql(claim.envelope, slot.envelope) or !std.meta.eql(claim.bound, bound)) return error.StaleRequest;
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireRunning(control, claim.key.ticket);
        out.* = bound;
        out_stopped.* = control & STOP != 0;
    }

    pub fn completeSyscall(self: *@This(), key: RequestKey, reply: Reply) Error!void {
        try requireBsp();
        const slot = try self.processingSlot(key);
        slot.reply = reply;
        @atomicStore(u64, &slot.syscall_control, packSyscall(key.sequence, SYSCALL_COMPLETE), .release);
    }

    pub fn consumeSyscallInto(self: *@This(), key: RequestKey, out: *Reply) Error!void {
        try requireOwner(key.ticket);
        try self.checkTicket(key.ticket);
        const slot = &self.slots[key.ticket.cpu];
        try requireRunning(@atomicLoad(u64, &slot.control, .acquire), key.ticket);
        const request = @atomicLoad(u64, &slot.syscall_control, .acquire);
        try requireSequence(request, key.sequence);
        if (syscallPhase(request) == SYSCALL_IDLE) return error.StaleRequest;
        if (syscallPhase(request) != SYSCALL_COMPLETE) return error.NotReady;
        out.* = slot.reply;
        @atomicStore(u64, &slot.syscall_control, packSyscall(key.sequence, SYSCALL_IDLE), .release);
    }

    pub fn cancelPendingSyscall(self: *@This(), key: RequestKey) bool {
        if (requireOwner(key.ticket)) |_| {} else |_| return false;
        if (self.checkTicket(key.ticket)) |_| {} else |_| return false;
        const slot = &self.slots[key.ticket.cpu];
        if (requireRunning(@atomicLoad(u64, &slot.control, .acquire), key.ticket)) |_| {} else |_| return false;
        const request = @atomicLoad(u64, &slot.syscall_control, .acquire);
        if (syscallSequence(request) != key.sequence or key.sequence == 0 or syscallPhase(request) != SYSCALL_PENDING) return false;
        return @cmpxchgStrong(u64, &slot.syscall_control, request, packSyscall(key.sequence, SYSCALL_IDLE), .acq_rel, .acquire) == null;
    }

    pub fn syscallIdle(self: *@This(), ticket: Ticket) bool {
        if (cpu_identity.currentIndex() != 0 and ticket.cpu != cpu_identity.currentIndex()) return false;
        if (self.checkTicket(ticket)) |_| {} else |_| return false;
        const slot = &self.slots[ticket.cpu];
        if (requireRunning(@atomicLoad(u64, &slot.control, .acquire), ticket)) |_| {} else |_| return false;
        return syscallPhase(@atomicLoad(u64, &slot.syscall_control, .acquire)) == SYSCALL_IDLE;
    }

    inline fn processingSlot(self: *@This(), key: RequestKey) Error!*Slot {
        try self.checkTicket(key.ticket);
        const slot = &self.slots[key.ticket.cpu];
        try requireRunning(@atomicLoad(u64, &slot.control, .acquire), key.ticket);
        const request = @atomicLoad(u64, &slot.syscall_control, .acquire);
        try requireSequence(request, key.sequence);
        if (syscallPhase(request) != SYSCALL_PROCESSING) return error.WrongPhase;
        return slot;
    }

    // The result authorizes an asynchronous prompt only when the acquired
    // control was running. A ready owner can win start between the initial
    // load and STOP CAS, so notification must use the successful CAS phase.
    pub fn requestStop(self: *@This(), ticket: Ticket) Error!bool {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        var control = @atomicLoad(u64, &slot.control, .acquire);
        while (true) {
            try requireTicket(control, ticket);
            const phase_value = phaseOf(control);
            if (control & STOP != 0 or phase_value == .returned or phase_value == .return_consumed or phase_value == .collecting)
                return phase_value == .running;
            if (@cmpxchgStrong(u64, &slot.control, control, control | STOP, .acq_rel, .acquire)) |changed| {
                control = changed;
            } else return phase_value == .running;
        }
    }

    pub fn stopRequested(self: *@This(), ticket: Ticket) bool {
        if (ticket.issuer != self or ticket.cpu != cpu_identity.currentIndex() or ticket.cpu >= CAPACITY or ticket.epoch == 0 or ticket.epoch > MAX_EPOCH) return false;
        const control = @atomicLoad(u64, &self.slots[ticket.cpu].control, .acquire);
        return epochOf(control) == ticket.epoch and phaseOf(control) == .running and control & STOP != 0;
    }

    // The owner may publish this only after its hardware/kernel continuation has
    // returned and its final task/mapping access is complete. A TLB ACK is not
    // an execution ACK. Identity remains resident until BSP collection finishes.
    pub fn acknowledgeOwnedRootReturn(self: *@This(), ticket: Ticket) Error!void {
        try requireOwner(ticket);
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        var control = @atomicLoad(u64, &slot.control, .acquire);
        while (true) {
            try requireTicket(control, ticket);
            if (control & PREPARED != 0) return error.WrongPurpose;
            if (phaseOf(control) != .running) return error.WrongPhase;
            try requireSyscallIdle(slot);
            if (@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .returned), .release, .acquire)) |changed| {
                control = changed;
            } else return;
        }
    }

    // This is the execution ACK for a prepared task. Native owners keep IF
    // clear and publish only after restoring the verified kernel root, clearing
    // continuation/xstate pointers, and completing their final backing reads.
    // After success the owner must not access its issuer or task backing again.
    pub inline fn ackPreparedReturn(self: *@This(), ticket: Ticket, record: ReturnRecord) Error!void {
        try requireOwner(ticket);
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        var control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (control & PREPARED == 0) return error.WrongPurpose;
        if (phaseOf(control) != .running) return error.WrongPhase;
        try requireSyscallIdle(slot);
        if (record.reserved != 0) return error.InvalidReturnRecord;
        slot.return_record = record;
        while (true) {
            // The BSP may publish STOP while the serialized owner writes the
            // record. Preserve that bit and purpose when publishing the ACK.
            if (@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .returned), .release, .acquire)) |changed| {
                try requireTicket(changed, ticket);
                if (phaseOf(changed) != .running or changed & PREPARED == 0) return error.WrongPhase;
                control = changed;
            } else return;
        }
    }

    pub fn consumePreparedReturnInto(self: *@This(), ticket: Ticket, out: *ReturnRecord) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (control & PREPARED == 0) return error.WrongPurpose;
        if (phaseOf(control) != .returned) return error.WrongPhase;
        try requireSyscallIdle(slot);
        const record = slot.return_record;
        if (@cmpxchgStrong(u64, &slot.control, control, controlWithPhase(control, .return_consumed), .acq_rel, .acquire) != null)
            return error.WrongPhase;
        out.* = record;
    }

    pub inline fn cancelUnstarted(self: *@This(), ticket: Ticket) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (phaseOf(control) != .reserved and phaseOf(control) != .ready) return error.WrongPhase;
        try requireSyscallIdle(slot);
        const prepared = control & PREPARED != 0;
        const cancelled = controlWithPhase(control, if (prepared) .returning else .returned);
        if (@cmpxchgStrong(u64, &slot.control, control, cancelled, .acq_rel, .acquire) != null)
            return error.WrongPhase;
        if (prepared) {
            // Reserve cancellation before writing so a racing owner cannot
            // start and publish its own receipt over this unavailable return.
            slot.return_record = .{};
            var publishing = cancelled;
            while (@cmpxchgStrong(u64, &slot.control, publishing, controlWithPhase(publishing, .returned), .release, .acquire)) |changed|
                publishing = changed;
        }
    }

    pub fn beginCollect(self: *@This(), ticket: Ticket) Error!Identity {
        var task: Identity = undefined;
        try self.beginCollectInto(ticket, &task);
        return task;
    }

    pub fn beginCollectInto(self: *@This(), ticket: Ticket, out: *Identity) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        const expected_phase: Phase = if (control & PREPARED != 0) .return_consumed else .returned;
        if (phaseOf(control) != expected_phase) return error.WrongPhase;
        try requireSyscallIdle(slot);
        const task = slot.identity;
        @atomicStore(u64, &slot.control, controlWithPhase(control, .collecting), .release);
        out.* = task;
    }

    pub fn finishCollect(self: *@This(), ticket: Ticket) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        if (phaseOf(control) != .collecting) return error.WrongPhase;
        try requireSyscallIdle(slot);
        @atomicStore(u64, &slot.control, packControl(ticket.epoch, .idle, false, false), .release);
    }

    pub fn identity(self: *@This(), ticket: Ticket) Error!Identity {
        var task: Identity = undefined;
        try self.identityInto(ticket, &task);
        return task;
    }

    pub fn identityInto(self: *@This(), ticket: Ticket, out: *Identity) Error!void {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        try requireTicket(@atomicLoad(u64, &slot.control, .acquire), ticket);
        out.* = slot.identity;
    }

    pub inline fn phase(self: *@This(), ticket: Ticket) Error!Phase {
        try requireBsp();
        try self.checkTicket(ticket);
        const slot = &self.slots[ticket.cpu];
        const control = @atomicLoad(u64, &slot.control, .acquire);
        try requireTicket(control, ticket);
        return phaseOf(control);
    }

    pub fn taskTicket(self: *@This(), task_id: u64) ?Ticket {
        if (cpu_identity.currentIndex() != 0 or task_id == 0) return null;
        for (&self.slots, 0..) |*slot, index| {
            const control = @atomicLoad(u64, &slot.control, .acquire);
            if (phaseOf(control) != .idle and slot.identity.task_id == task_id)
                return .{ .cpu = @intCast(index), .epoch = epochOf(control), .issuer = self };
        }
        return null;
    }

    pub inline fn hasLeaseForTask(self: *@This(), task_id: u64) bool {
        // A foreign caller must not interpret unavailable BSP ownership as an
        // absence of leases and begin destructive work.
        return cpu_identity.currentIndex() != 0 or self.taskTicket(task_id) != null;
    }

    pub fn hasLeases(self: *@This()) bool {
        if (cpu_identity.currentIndex() != 0) return true;
        for (&self.slots) |*slot| if (phaseOf(@atomicLoad(u64, &slot.control, .acquire)) != .idle) return true;
        return false;
    }

    pub fn canRetireMapping(self: *@This(), address_space_id: u64) bool {
        if (cpu_identity.currentIndex() != 0) return false;
        // Address-space IDs are Runtime-wide, whereas a mapping handle belongs
        // to its Executor arena. Coincident handles in another arena confer no
        // retirement authority and must not exclude unrelated address spaces.
        for (&self.slots) |*slot| {
            const phase_value = phaseOf(@atomicLoad(u64, &slot.control, .acquire));
            if (phase_value == .idle or phase_value == .collecting) continue;
            if (slot.identity.address_space_id == address_space_id) return false;
        }
        return true;
    }

    pub fn canRetireRoot(self: *@This(), physical_root: u64) bool {
        if (cpu_identity.currentIndex() != 0) return false;
        for (&self.slots) |*slot| {
            const phase_value = phaseOf(@atomicLoad(u64, &slot.control, .acquire));
            if (phase_value != .idle and phase_value != .collecting and slot.physical_root == physical_root) return false;
        }
        return true;
    }

    // Preparation must exclude even a returned/collecting root: its immutable
    // lease identity remains live until collection callbacks complete. bind
    // repeats this admission immediately before publishing the ready phase.
    pub fn rootAvailable(self: *@This(), physical_root: u64) bool {
        if (cpu_identity.currentIndex() != 0 or physical_root == 0 or physical_root % 4096 != 0 or physical_root >= (@as(u64, 1) << 52)) return false;
        for (&self.slots) |*slot| {
            if (phaseOf(@atomicLoad(u64, &slot.control, .acquire)) != .idle and slot.physical_root == physical_root) return false;
        }
        return true;
    }

    inline fn checkTicket(self: *const @This(), ticket: Ticket) Error!void {
        if (ticket.issuer != self) return error.WrongCoordinator;
        if (ticket.cpu >= CAPACITY) return error.InvalidCpu;
        if (ticket.epoch == 0 or ticket.epoch > MAX_EPOCH) return error.StaleTicket;
    }
};

inline fn requireBsp() Error!void {
    if (cpu_identity.currentIndex() != 0) return error.WrongCpu;
}
inline fn requireOwner(ticket: Ticket) Error!void {
    if (ticket.cpu >= CAPACITY) return error.InvalidCpu;
    if (ticket.cpu != cpu_identity.currentIndex()) return error.WrongCpu;
}
inline fn packControl(epoch: u64, phase_value: Phase, stopped: bool, prepared: bool) u64 {
    return (epoch << EPOCH_SHIFT) | @backingInt(phase_value) | (if (stopped) STOP else @as(u64, 0)) | (if (prepared) PREPARED else @as(u64, 0));
}
inline fn controlWithPhase(control: u64, phase_value: Phase) u64 {
    return (control & ~PHASE_MASK) | @backingInt(phase_value);
}
inline fn epochOf(control: u64) u64 {
    return control >> EPOCH_SHIFT;
}
inline fn phaseOf(control: u64) Phase {
    return @fromBackingInt(@intCast(control & PHASE_MASK));
}
inline fn requireTicket(control: u64, ticket: Ticket) Error!void {
    if (epochOf(control) != ticket.epoch or phaseOf(control) == .idle) return error.StaleTicket;
}
inline fn requireRunning(control: u64, ticket: Ticket) Error!void {
    try requireTicket(control, ticket);
    if (phaseOf(control) != .running) return error.WrongPhase;
}
inline fn packSyscall(sequence: u64, phase_value: u64) u64 {
    return (sequence << SYSCALL_SEQUENCE_SHIFT) | phase_value;
}
inline fn syscallSequence(control: u64) u64 {
    return control >> SYSCALL_SEQUENCE_SHIFT;
}
inline fn syscallPhase(control: u64) u64 {
    return control & SYSCALL_PHASE_MASK;
}
inline fn requireSequence(control: u64, sequence: u64) Error!void {
    if (sequence == 0 or sequence > MAX_SYSCALL_SEQUENCE or syscallSequence(control) != sequence) return error.StaleRequest;
}
inline fn requireSyscallIdle(slot: *const Slot) Error!void {
    if (syscallPhase(@atomicLoad(u64, &slot.syscall_control, .acquire)) != SYSCALL_IDLE) return error.SyscallInFlight;
}

comptime {
    if (@sizeOf(Envelope) != 32 or @sizeOf(Reply) != 8 or @sizeOf(ReturnRecord) != 32 or @alignOf(ReturnRecord) != 8 or @sizeOf(Slot) != 192 or @alignOf(Slot) != 8 or @offsetOf(Slot, "return_record") != 96 or @offsetOf(Slot, "padding") != 136 or @alignOf(Coordinator) != 8 or @sizeOf(Coordinator) != 3080)
        @compileError("dispatch ownership slots must isolate active cache lines without strengthening Runtime alignment");
    if (@offsetOf(ReturnRecord, "ui_revision") != 0 or @offsetOf(ReturnRecord, "fault_instruction_pointer") != 8 or @offsetOf(ReturnRecord, "fault_address") != 16 or @offsetOf(ReturnRecord, "fault_error_code") != 24 or @offsetOf(ReturnRecord, "outcome") != 28 or @offsetOf(ReturnRecord, "fault_vector") != 29 or @offsetOf(ReturnRecord, "reserved") != 30)
        @compileError("prepared returns require an exact scalar execution receipt");
}

fn testIdentity(index: usize) Identity {
    return .{ .task_handle = 0x100 + index, .task_id = 10 + index, .process_generation = 1 + index, .address_space_id = 20 + index };
}

fn testReturn(index: usize) ReturnRecord {
    return .{
        .ui_revision = 1000 + index,
        .fault_instruction_pointer = 0xffff_ffff_8000_1000 + index,
        .fault_address = 0x5000 + index,
        .fault_error_code = @intCast(0x8000 + index),
        .outcome = @fromBackingInt(@intCast(index % 4)),
        .fault_vector = @intCast(10 + index),
    };
}

test "prepared receipts bind every owner and must be consumed exactly once before collection" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var tickets: [CAPACITY]Ticket = undefined;
    for (&tickets, 0..) |*ticket, cpu| {
        ticket.* = try coordinator.prepare(@intCast(cpu), testIdentity(cpu));
        try coordinator.bindPrepared(ticket.*, 100 + cpu, (100 + cpu) * 4096);
    }
    for (tickets, 0..) |ticket, cpu| {
        var out = testReturn(99);
        const before = out;
        try std.testing.expectError(error.WrongPhase, coordinator.consumePreparedReturnInto(ticket, &out));
        try std.testing.expectEqualDeep(before, out);
        cpu_identity.setIndexForTest(@intCast(cpu));
        _ = try coordinator.start(ticket);
        try std.testing.expectError(error.WrongPurpose, coordinator.acknowledgeOwnedRootReturn(ticket));
        try std.testing.expectError(error.WrongCpu, coordinator.ackPreparedReturn(tickets[(cpu + 1) % CAPACITY], testReturn(cpu)));
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(try coordinator.requestStop(ticket));
        cpu_identity.setIndexForTest(@intCast(cpu));
        try coordinator.ackPreparedReturn(ticket, testReturn(cpu));
        // No owner access is needed after the execution ACK; BSP alone consumes
        // the recorded outcome while all task backing stays pinned.
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(Phase.returned, try coordinator.phase(ticket));
        try std.testing.expectError(error.WrongPhase, coordinator.beginCollect(ticket));
        try std.testing.expect(!coordinator.canRetireMapping(20 + cpu));
        try std.testing.expect(!coordinator.canRetireRoot((100 + cpu) * 4096));
        try coordinator.consumePreparedReturnInto(ticket, &out);
        try std.testing.expectEqualDeep(testReturn(cpu), out);
        try std.testing.expectEqual(cpu % 4 != 0, out.outcome.handedOff());
        try std.testing.expectEqual(Phase.return_consumed, try coordinator.phase(ticket));
        try std.testing.expect(!try coordinator.requestStop(ticket));
        out = before;
        try std.testing.expectError(error.WrongPhase, coordinator.consumePreparedReturnInto(ticket, &out));
        try std.testing.expectEqualDeep(before, out);
        try std.testing.expect(!coordinator.canRetireMapping(20 + cpu));
        try std.testing.expectEqualDeep(testIdentity(cpu), try coordinator.beginCollect(ticket));
        try std.testing.expect(coordinator.canRetireMapping(20 + cpu));
        try std.testing.expect(!coordinator.rootAvailable((100 + cpu) * 4096));
        try coordinator.finishCollect(ticket);
        try std.testing.expectError(error.StaleTicket, coordinator.consumePreparedReturnInto(ticket, &out));
        try std.testing.expectEqualDeep(before, out);
    }
    try std.testing.expect(!coordinator.hasLeases());
}

test "prepared return admission rejects foreign stale purpose and reserved records without publication" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var other: Coordinator = .{};
    const owned = try coordinator.prepare(0, testIdentity(0));
    try coordinator.bindOwnedRoot(owned, 1, 4096);
    var denied_bound = BoundIdentity{ .identity = testIdentity(99), .mapping_handle = 99, .physical_root = 40960 };
    const bound_before = denied_bound;
    try std.testing.expectError(error.WrongPurpose, coordinator.startPreparedInto(owned, &denied_bound));
    try std.testing.expectEqualDeep(bound_before, denied_bound);
    try std.testing.expectEqual(Phase.ready, try coordinator.phase(owned));
    _ = try coordinator.start(owned);
    const owned_before = coordinator;
    try std.testing.expectError(error.WrongPurpose, coordinator.ackPreparedReturn(owned, .{}));
    var out = testReturn(90);
    const out_before = out;
    try std.testing.expectError(error.WrongPurpose, coordinator.consumePreparedReturnInto(owned, &out));
    try std.testing.expectEqualDeep(out_before, out);
    try std.testing.expectEqualDeep(owned_before, coordinator);
    try coordinator.acknowledgeOwnedRootReturn(owned);
    _ = try coordinator.beginCollect(owned);
    try coordinator.finishCollect(owned);
    const ticket = try coordinator.prepare(1, testIdentity(1));
    const foreign = try other.prepare(1, testIdentity(2));
    try coordinator.bindPrepared(ticket, 2, 8192);
    try other.bindPrepared(foreign, 3, 12288);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(ticket);
    var malformed = testReturn(1);
    malformed.reserved = 1;
    const before = coordinator;
    try std.testing.expectError(error.InvalidReturnRecord, coordinator.ackPreparedReturn(ticket, malformed));
    try std.testing.expectError(error.WrongCoordinator, coordinator.ackPreparedReturn(foreign, .{}));
    var stale = ticket;
    stale.epoch -= 1;
    try std.testing.expectError(error.StaleTicket, coordinator.ackPreparedReturn(stale, .{}));
    try std.testing.expectEqualDeep(before, coordinator);
    try std.testing.expectError(error.WrongCpu, coordinator.consumePreparedReturnInto(ticket, &out));
    try coordinator.ackPreparedReturn(ticket, testReturn(1));
    cpu_identity.setIndexForTest(0);
    try std.testing.expectError(error.WrongCoordinator, coordinator.consumePreparedReturnInto(foreign, &out));
    try std.testing.expectEqualDeep(out_before, out);
    try coordinator.consumePreparedReturnInto(ticket, &out);
    _ = try coordinator.beginCollect(ticket);
    try coordinator.finishCollect(ticket);
    const replacement = try coordinator.prepare(1, testIdentity(1));
    try coordinator.bindPrepared(replacement, 2, 8192);
    out = out_before;
    try std.testing.expectError(error.StaleTicket, coordinator.consumePreparedReturnInto(ticket, &out));
    try std.testing.expectEqualDeep(out_before, out);
    try coordinator.cancelUnstarted(replacement);
    try std.testing.expectError(error.WrongPhase, coordinator.beginCollect(replacement));
    try coordinator.consumePreparedReturnInto(replacement, &out);
    try std.testing.expectEqualDeep(ReturnRecord{}, out);
    _ = try coordinator.beginCollect(replacement);
    try coordinator.finishCollect(replacement);
    try other.cancelUnstarted(foreign);
    try other.consumePreparedReturnInto(foreign, &out);
    _ = try other.beginCollect(foreign);
    try other.finishCollect(foreign);
}

test "prepared ACK waits for every mailbox phase including a stopped claimed request" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    const ticket = try coordinator.prepare(1, testIdentity(1));
    try coordinator.bindPrepared(ticket, 2, 8192);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(ticket);
    const record_before = coordinator.slots[1].return_record;
    coordinator.slots[1].syscall_control = packSyscall(1, SYSCALL_PUBLISHING);
    try std.testing.expectError(error.SyscallInFlight, coordinator.ackPreparedReturn(ticket, testReturn(1)));
    coordinator.slots[1].syscall_control = packSyscall(1, SYSCALL_IDLE);
    var key: RequestKey = undefined;
    try coordinator.submitSyscallInto(ticket, testEnvelope(1, 1), &key);
    try std.testing.expectError(error.SyscallInFlight, coordinator.ackPreparedReturn(ticket, testReturn(1)));
    cpu_identity.setIndexForTest(0);
    var claim: ClaimedSyscall = undefined;
    try coordinator.claimSyscallInto(1, &claim);
    try std.testing.expect(try coordinator.requestStop(ticket));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.SyscallInFlight, coordinator.ackPreparedReturn(ticket, testReturn(1)));
    cpu_identity.setIndexForTest(0);
    try coordinator.completeSyscall(key, testReply(1, 1));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.SyscallInFlight, coordinator.ackPreparedReturn(ticket, testReturn(1)));
    try std.testing.expectEqualDeep(record_before, coordinator.slots[1].return_record);
    var reply: Reply = undefined;
    try coordinator.consumeSyscallInto(key, &reply);
    try coordinator.ackPreparedReturn(ticket, testReturn(1));
    cpu_identity.setIndexForTest(0);
    var out: ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(ticket, &out);
    try std.testing.expectEqualDeep(testReturn(1), out);
    _ = try coordinator.beginCollect(ticket);
    try coordinator.finishCollect(ticket);
}

test "prepared cancellation races owner start and preserves the exact winning receipt" {
    const Model = struct {
        coordinator: *Coordinator,
        ticket: Ticket,
        expected: ReturnRecord,
        started: bool = false,
        valid: bool = false,

        fn owner(self: *@This()) void {
            cpu_identity.setIndexForTest(self.ticket.cpu);
            var bound: BoundIdentity = undefined;
            self.coordinator.startInto(self.ticket, &bound) catch |err| {
                self.valid = err == error.StaleTicket or err == error.WrongPhase;
                return;
            };
            self.started = true;
            self.valid = bound.identity.task_id == 10 + self.ticket.cpu;
            self.coordinator.ackPreparedReturn(self.ticket, self.expected) catch {
                self.valid = false;
            };
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    for (0..CAPACITY * 8) |round| {
        const cpu: u8 = @intCast(round % CAPACITY);
        const ticket = try coordinator.prepare(cpu, testIdentity(cpu));
        try coordinator.bindPrepared(ticket, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        var model = Model{ .coordinator = &coordinator, .ticket = ticket, .expected = testReturn(round) };
        const thread = try std.Thread.spawn(.{}, Model.owner, .{&model});
        var cancelled = false;
        if (coordinator.cancelUnstarted(ticket)) |_| {
            cancelled = true;
        } else |err| try std.testing.expectEqual(error.WrongPhase, err);
        thread.join();
        try std.testing.expect(model.valid);
        try std.testing.expectEqual(!cancelled, model.started);
        var out: ReturnRecord = undefined;
        try coordinator.consumePreparedReturnInto(ticket, &out);
        try std.testing.expectEqualDeep(if (cancelled) ReturnRecord{} else model.expected, out);
        _ = try coordinator.beginCollect(ticket);
        try coordinator.finishCollect(ticket);
    }
}

test "prepared cancellation publication and last epoch preserve all control bits" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{ .next_epoch = MAX_EPOCH };
    const ticket = try coordinator.prepare(0, testIdentity(0));
    try coordinator.bindPrepared(ticket, 1, 4096);
    try std.testing.expect(!try coordinator.requestStop(ticket));
    try coordinator.cancelUnstarted(ticket);
    const control = coordinator.slots[0].control;
    try std.testing.expectEqual(MAX_EPOCH, epochOf(control));
    try std.testing.expect(control & PREPARED != 0 and control & STOP != 0);
    var out: ReturnRecord = undefined;
    try coordinator.consumePreparedReturnInto(ticket, &out);
    try std.testing.expectEqualDeep(ReturnRecord{}, out);
    _ = try coordinator.beginCollect(ticket);
    try coordinator.finishCollect(ticket);
    try std.testing.expectError(error.EpochExhausted, coordinator.prepare(0, testIdentity(0)));
    try std.testing.expectError(error.StaleTicket, coordinator.ackPreparedReturn(ticket, .{}));
    var invalid_epoch: Coordinator = .{ .next_epoch = MAX_EPOCH + 1 };
    const epoch_before = invalid_epoch;
    try std.testing.expectError(error.EpochExhausted, invalid_epoch.prepare(0, testIdentity(0)));
    try std.testing.expectEqualDeep(epoch_before, invalid_epoch);

    var publishing: Coordinator = .{};
    const held = try publishing.prepare(0, testIdentity(0));
    try publishing.bindPrepared(held, 1, 4096);
    publishing.slots[0].control = packControl(held.epoch, .returning, false, true);
    var canary = testReturn(99);
    const before = canary;
    try std.testing.expectError(error.WrongPhase, publishing.start(held));
    try std.testing.expectError(error.WrongPhase, publishing.cancelUnstarted(held));
    try std.testing.expectError(error.WrongPhase, publishing.beginCollect(held));
    try std.testing.expectError(error.WrongPhase, publishing.consumePreparedReturnInto(held, &canary));
    try std.testing.expectEqualDeep(before, canary);
    try std.testing.expect(!try publishing.requestStop(held));
    try std.testing.expect(publishing.slots[0].control & PREPARED != 0 and publishing.slots[0].control & STOP != 0);
}

test "prepared receipt release races STOP without losing purpose or waiting for owner consumption" {
    const Model = struct {
        coordinator: *Coordinator,
        ticket: Ticket,
        record: ReturnRecord,
        started: bool = false,
        go: bool = false,
        valid: bool = false,

        fn owner(self: *@This()) void {
            cpu_identity.setIndexForTest(self.ticket.cpu);
            var bound: BoundIdentity = undefined;
            self.coordinator.startPreparedInto(self.ticket, &bound) catch {
                @atomicStore(bool, &self.started, true, .release);
                return;
            };
            self.valid = bound.identity.task_id == 10 + self.ticket.cpu;
            @atomicStore(bool, &self.started, true, .release);
            while (!@atomicLoad(bool, &self.go, .acquire)) std.atomic.spinLoopHint();
            self.coordinator.ackPreparedReturn(self.ticket, self.record) catch {
                self.valid = false;
            };
            // Success needs no issuer poll or BSP-consumed acknowledgement.
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    for (0..CAPACITY * 8) |round| {
        const cpu: u8 = @intCast(round % CAPACITY);
        const ticket = try coordinator.prepare(cpu, testIdentity(cpu));
        try coordinator.bindPrepared(ticket, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        var model = Model{ .coordinator = &coordinator, .ticket = ticket, .record = testReturn(round) };
        const thread = try std.Thread.spawn(.{}, Model.owner, .{&model});
        var joined = false;
        defer if (!joined) {
            @atomicStore(bool, &model.go, true, .release);
            thread.join();
        };
        while (!@atomicLoad(bool, &model.started, .acquire)) std.atomic.spinLoopHint();
        try std.testing.expect(model.valid);
        @atomicStore(bool, &model.go, true, .release);
        const prompted = try coordinator.requestStop(ticket);
        while (try coordinator.phase(ticket) == .running) std.atomic.spinLoopHint();
        const control = coordinator.slots[cpu].control;
        try std.testing.expect(control & PREPARED != 0);
        if (prompted) try std.testing.expect(control & STOP != 0);
        var out: ReturnRecord = undefined;
        try coordinator.consumePreparedReturnInto(ticket, &out);
        try std.testing.expectEqualDeep(model.record, out);
        _ = try coordinator.beginCollect(ticket);
        try coordinator.finishCollect(ticket);
        thread.join();
        joined = true;
        try std.testing.expect(model.valid);
    }
}

test "all dispatch slots require exact owner epoch and collecting preserves exclusion" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var tickets: [CAPACITY]Ticket = undefined;
    for (&tickets, 0..) |*ticket, index| {
        ticket.* = try coordinator.prepare(@intCast(index), testIdentity(index));
        try coordinator.bindOwnedRoot(ticket.*, 100 + index, (@as(u64, 100) + index) * 4096);
    }
    for (0..CAPACITY) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) CAPACITY - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        const bound = try coordinator.start(tickets[index]);
        try std.testing.expectEqualDeep(testIdentity(index), bound.identity);
        try std.testing.expectEqual(@as(u64, (@as(u64, 100) + index) * 4096), bound.physical_root);
        try std.testing.expectError(error.WrongCpu, coordinator.acknowledgeOwnedRootReturn(tickets[(index + 1) % CAPACITY]));
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(try coordinator.requestStop(tickets[index]));
        try std.testing.expectError(error.WrongPhase, coordinator.beginCollect(tickets[index]));
        try std.testing.expectError(error.WrongPhase, coordinator.cancelUnstarted(tickets[index]));
        cpu_identity.setIndexForTest(index);
        try std.testing.expect(coordinator.stopRequested(tickets[index]));
        try coordinator.acknowledgeOwnedRootReturn(tickets[index]);
        try std.testing.expectError(error.WrongPhase, coordinator.acknowledgeOwnedRootReturn(tickets[index]));
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(!coordinator.canRetireMapping(20 + index));
        try std.testing.expect(!coordinator.canRetireRoot((@as(u64, 100) + index) * 4096));
        try std.testing.expectEqualDeep(testIdentity(index), try coordinator.beginCollect(tickets[index]));
        try std.testing.expect(coordinator.hasLeaseForTask(10 + index));
        try std.testing.expect(coordinator.canRetireMapping(20 + index));
        try std.testing.expect(coordinator.canRetireRoot((@as(u64, 100) + index) * 4096));
        try std.testing.expect(!coordinator.rootAvailable((@as(u64, 100) + index) * 4096));
        try std.testing.expectError(error.Busy, coordinator.prepare(index, testIdentity(index)));
        for (0..CAPACITY) |neighbor| {
            if (neighbor == index or (try coordinator.phase(tickets[neighbor])) == .collecting) continue;
            try std.testing.expectEqualDeep(testIdentity(neighbor), try coordinator.identity(tickets[neighbor]));
        }
        // Collection is delayed until all slots have reached it, so no stale
        // ticket can accidentally authenticate a newly reused neighbor.
    }
    for (tickets) |ticket| try coordinator.finishCollect(ticket);
    try std.testing.expect(!coordinator.hasLeases());
    for (0..CAPACITY) |index| try std.testing.expect(coordinator.rootAvailable((@as(u64, 100) + index) * 4096));
    for (tickets, 0..) |stale, index| {
        const replacement = try coordinator.prepare(@intCast(index), testIdentity(index));
        try std.testing.expect(replacement.epoch != stale.epoch);
        try std.testing.expectError(error.StaleTicket, coordinator.bindOwnedRoot(stale, 1, 4096));
        try std.testing.expectError(error.StaleTicket, coordinator.requestStop(stale));
        try std.testing.expectError(error.StaleTicket, coordinator.cancelUnstarted(stale));
        try std.testing.expectError(error.StaleTicket, coordinator.beginCollect(stale));
        try coordinator.cancelUnstarted(replacement);
        _ = try coordinator.beginCollect(replacement);
        try coordinator.finishCollect(replacement);
    }
}

test "dispatch admission rejects duplicate roots malformed identities and stopped starts" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    try std.testing.expect(!coordinator.rootAvailable(0));
    try std.testing.expect(!coordinator.rootAvailable(1));
    try std.testing.expect(!coordinator.rootAvailable(@as(u64, 1) << 52));
    try std.testing.expectError(error.InvalidCpu, coordinator.prepare(CAPACITY, testIdentity(0)));
    inline for (.{ "task_handle", "task_id", "process_generation", "address_space_id" }) |field| {
        var identity_value = testIdentity(0);
        @field(identity_value, field) = 0;
        try std.testing.expectError(error.InvalidIdentity, coordinator.prepare(0, identity_value));
    }
    const first = try coordinator.prepare(0, testIdentity(0));
    try std.testing.expectError(error.Busy, coordinator.prepare(1, testIdentity(0)));
    const second = try coordinator.prepare(1, testIdentity(1));
    try std.testing.expectError(error.InvalidMapping, coordinator.bindOwnedRoot(first, 0, 4096));
    try std.testing.expectError(error.InvalidMapping, coordinator.bindOwnedRoot(first, 1, 4097));
    try coordinator.bindOwnedRoot(first, 1, 4096);
    try std.testing.expectError(error.RootAlreadyLeased, coordinator.bindOwnedRoot(second, 2, 4096));
    try coordinator.bindOwnedRoot(second, 2, 8192);
    try std.testing.expect(!try coordinator.requestStop(second));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.StopRequested, coordinator.start(second));
    try std.testing.expectError(error.WrongCpu, coordinator.prepare(2, testIdentity(2)));
    try std.testing.expectError(error.WrongCpu, coordinator.bindOwnedRoot(second, 2, 8192));
    try std.testing.expectError(error.WrongCpu, coordinator.requestStop(second));
    try std.testing.expectError(error.WrongCpu, coordinator.cancelUnstarted(second));
    try std.testing.expect(coordinator.hasLeases());
    try std.testing.expect(!coordinator.canRetireRoot(4096));
    try std.testing.expect(!coordinator.rootAvailable(12288));
    cpu_identity.setIndexForTest(0);
    try coordinator.cancelUnstarted(second);
    _ = try coordinator.beginCollect(second);
    const third = try coordinator.prepare(2, testIdentity(2));
    try std.testing.expectError(error.RootAlreadyLeased, coordinator.bindOwnedRoot(third, 3, 8192));
    try coordinator.finishCollect(second);
    try coordinator.bindOwnedRoot(third, 3, 8192);
    try coordinator.cancelUnstarted(third);
    _ = try coordinator.beginCollect(third);
    try coordinator.finishCollect(third);
    try coordinator.cancelUnstarted(first);
    _ = try coordinator.beginCollect(first);
    try coordinator.finishCollect(first);
}

test "dispatch epoch exhaustion is permanent and cannot reuse a stale ticket" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{ .next_epoch = MAX_EPOCH };
    const last = try coordinator.prepare(0, testIdentity(0));
    try std.testing.expectEqual(MAX_EPOCH, last.epoch);
    try coordinator.cancelUnstarted(last);
    _ = try coordinator.beginCollect(last);
    try coordinator.finishCollect(last);
    try std.testing.expectError(error.EpochExhausted, coordinator.prepare(0, testIdentity(0)));
    try std.testing.expectError(error.EpochExhausted, coordinator.prepare(1, testIdentity(1)));
    try std.testing.expectError(error.StaleTicket, coordinator.finishCollect(last));
}

test "colliding tickets authenticate their issuing coordinator before slot access" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var first: Coordinator = .{};
    var second: Coordinator = .{};
    const first_ticket = try first.prepare(1, testIdentity(0));
    const second_ticket = try second.prepare(1, testIdentity(1));
    try std.testing.expectEqual(first_ticket.cpu, second_ticket.cpu);
    try std.testing.expectEqual(first_ticket.epoch, second_ticket.epoch);
    try first.bindOwnedRoot(first_ticket, 1, 4096);
    try second.bindOwnedRoot(second_ticket, 1, 8192);
    try std.testing.expect(first.canRetireMapping(99));
    try std.testing.expectError(error.WrongCoordinator, first.bindOwnedRoot(second_ticket, 0, 0));
    try std.testing.expectError(error.WrongCoordinator, first.requestStop(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.cancelUnstarted(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.beginCollect(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.finishCollect(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.identity(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.phase(second_ticket));
    cpu_identity.setIndexForTest(1);
    try std.testing.expectError(error.WrongCoordinator, first.start(second_ticket));
    try std.testing.expectError(error.WrongCoordinator, first.acknowledgeOwnedRootReturn(second_ticket));
    try std.testing.expect(!first.stopRequested(second_ticket));
    _ = try first.start(first_ticket);
    try first.acknowledgeOwnedRootReturn(first_ticket);
    cpu_identity.setIndexForTest(0);
    try std.testing.expectEqualDeep(testIdentity(0), try first.beginCollect(first_ticket));
    try first.finishCollect(first_ticket);
    try std.testing.expectEqual(Phase.ready, try second.phase(second_ticket));
    try std.testing.expectEqualDeep(testIdentity(1), try second.identity(second_ticket));
    try second.cancelUnstarted(second_ticket);
    _ = try second.beginCollect(second_ticket);
    try second.finishCollect(second_ticket);
}

test "caller-owned dispatch outputs survive rejected admission and stale collection" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var other: Coordinator = .{};
    var ticket = Ticket{ .cpu = 15, .epoch = 99, .issuer = &other };
    const ticket_before = ticket;
    try std.testing.expectError(error.InvalidCpu, coordinator.prepareInto(CAPACITY, testIdentity(0), &ticket));
    try std.testing.expectEqualDeep(ticket_before, ticket);
    try std.testing.expectError(error.InvalidIdentity, coordinator.prepareInto(0, .{}, &ticket));
    try std.testing.expectEqualDeep(ticket_before, ticket);
    try coordinator.prepareInto(0, testIdentity(0), &ticket);
    var identity_value = testIdentity(9);
    const identity_before = identity_value;
    try std.testing.expectError(error.WrongCoordinator, other.identityInto(ticket, &identity_value));
    try std.testing.expectEqualDeep(identity_before, identity_value);
    var bound = BoundIdentity{ .identity = identity_before, .mapping_handle = 99, .physical_root = 40960 };
    const bound_before = bound;
    try std.testing.expectError(error.WrongPhase, coordinator.startInto(ticket, &bound));
    try std.testing.expectEqualDeep(bound_before, bound);
    try coordinator.bindOwnedRoot(ticket, 1, 4096);
    try coordinator.startInto(ticket, &bound);
    try std.testing.expectEqualDeep(testIdentity(0), bound.identity);
    try std.testing.expectEqual(@as(u64, 1), bound.mapping_handle);
    try std.testing.expectEqual(@as(u64, 4096), bound.physical_root);
    try std.testing.expectError(error.WrongPhase, coordinator.beginCollectInto(ticket, &identity_value));
    try std.testing.expectEqualDeep(identity_before, identity_value);
    try coordinator.acknowledgeOwnedRootReturn(ticket);
    try coordinator.beginCollectInto(ticket, &identity_value);
    try std.testing.expectEqualDeep(testIdentity(0), identity_value);
    try coordinator.finishCollect(ticket);
    identity_value = identity_before;
    try std.testing.expectError(error.StaleTicket, coordinator.identityInto(ticket, &identity_value));
    try std.testing.expectEqualDeep(identity_before, identity_value);
    try std.testing.expectError(error.StaleTicket, coordinator.beginCollectInto(ticket, &identity_value));
    try std.testing.expectEqualDeep(identity_before, identity_value);
    bound = bound_before;
    try std.testing.expectError(error.StaleTicket, coordinator.startInto(ticket, &bound));
    try std.testing.expectEqualDeep(bound_before, bound);
}

test "owner start races BSP cancellation and reuse without reading another identity" {
    const Model = struct {
        coordinator: *Coordinator,
        ticket: Ticket,
        expected: Identity,
        valid: bool = false,

        fn owner(self: *@This()) void {
            cpu_identity.setIndexForTest(1);
            var bound: BoundIdentity = undefined;
            self.coordinator.startInto(self.ticket, &bound) catch |err| {
                self.valid = err == error.StaleTicket or err == error.WrongPhase;
                return;
            };
            self.valid = std.meta.eql(bound.identity, self.expected) and bound.mapping_handle == self.expected.task_id and
                bound.physical_root == self.expected.task_id * 4096;
            self.coordinator.acknowledgeOwnedRootReturn(self.ticket) catch {
                self.valid = false;
            };
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    for (0..128) |index| {
        const identity_value = testIdentity(index);
        const ticket = try coordinator.prepare(1, identity_value);
        try coordinator.bindOwnedRoot(ticket, identity_value.task_id, identity_value.task_id * 4096);
        var model = Model{ .coordinator = &coordinator, .ticket = ticket, .expected = identity_value };
        const thread = try std.Thread.spawn(.{}, Model.owner, .{&model});
        var replacement: ?Ticket = null;
        if (coordinator.cancelUnstarted(ticket)) |_| {
            _ = try coordinator.beginCollect(ticket);
            try coordinator.finishCollect(ticket);
            const next = testIdentity(index + 1000);
            replacement = try coordinator.prepare(1, next);
            try coordinator.bindOwnedRoot(replacement.?, next.task_id, next.task_id * 4096);
        } else |err| try std.testing.expectEqual(error.WrongPhase, err);
        thread.join();
        try std.testing.expect(model.valid);
        if (replacement) |next| {
            try coordinator.cancelUnstarted(next);
            _ = try coordinator.beginCollect(next);
            try coordinator.finishCollect(next);
        } else {
            _ = try coordinator.beginCollect(ticket);
            try coordinator.finishCollect(ticket);
        }
    }
}

test "stop prompts only running owners across every phase and CPU" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    for (0..CAPACITY) |position| {
        const cpu: u8 = @intCast(if (position % 2 == 0) CAPACITY - 1 - position / 2 else position / 2);
        const reserved = try coordinator.prepare(cpu, testIdentity(position));
        try std.testing.expect(!try coordinator.requestStop(reserved));
        try std.testing.expect(!try coordinator.requestStop(reserved));
        try std.testing.expectError(error.StopRequested, coordinator.bindOwnedRoot(reserved, 1, 4096));
        try coordinator.cancelUnstarted(reserved);
        try std.testing.expect(!try coordinator.requestStop(reserved));
        _ = try coordinator.beginCollect(reserved);
        try std.testing.expect(!try coordinator.requestStop(reserved));
        try coordinator.finishCollect(reserved);

        const ready = try coordinator.prepare(cpu, testIdentity(position));
        try coordinator.bindOwnedRoot(ready, 1, 4096);
        try std.testing.expect(!try coordinator.requestStop(ready));
        try std.testing.expect(!try coordinator.requestStop(ready));
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expectError(error.StopRequested, coordinator.start(ready));
        cpu_identity.setIndexForTest(0);
        try coordinator.cancelUnstarted(ready);
        _ = try coordinator.beginCollect(ready);
        try coordinator.finishCollect(ready);

        const running = try coordinator.prepare(cpu, testIdentity(position));
        try coordinator.bindOwnedRoot(running, 1, 4096);
        cpu_identity.setIndexForTest(cpu);
        _ = try coordinator.start(running);
        cpu_identity.setIndexForTest(0);
        const before_stale_stop = coordinator;
        try std.testing.expectError(error.StaleTicket, coordinator.requestStop(ready));
        try std.testing.expectEqualDeep(before_stale_stop, coordinator);
        try std.testing.expect(try coordinator.requestStop(running));
        const stopped_control = @atomicLoad(u64, &coordinator.slots[cpu].control, .acquire);
        try std.testing.expect(try coordinator.requestStop(running));
        try std.testing.expectEqual(stopped_control, @atomicLoad(u64, &coordinator.slots[cpu].control, .acquire));
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(coordinator.stopRequested(running));
        try coordinator.acknowledgeOwnedRootReturn(running);
        cpu_identity.setIndexForTest(0);
        try std.testing.expect(!try coordinator.requestStop(running));
        _ = try coordinator.beginCollect(running);
        try std.testing.expect(!try coordinator.requestStop(running));
        try coordinator.finishCollect(running);
        try std.testing.expectError(error.StaleTicket, coordinator.requestStop(running));
    }
    try std.testing.expect(!coordinator.hasLeases());
}

test "stop result follows the winning owner start CAS in all CPU slots" {
    const Model = struct {
        coordinator: *Coordinator,
        ticket: Ticket,
        go: bool = false,
        done: bool = false,
        can_return: bool = false,
        started: bool = false,
        valid: bool = false,

        fn owner(self: *@This()) void {
            cpu_identity.setIndexForTest(self.ticket.cpu);
            while (!@atomicLoad(bool, &self.go, .acquire)) std.atomic.spinLoopHint();
            var bound: BoundIdentity = undefined;
            if (self.coordinator.startInto(self.ticket, &bound)) |_| {
                self.started = true;
                self.valid = bound.identity.task_id == 10 + self.ticket.cpu;
            } else |err| self.valid = err == error.StopRequested;
            @atomicStore(bool, &self.done, true, .release);
            while (!@atomicLoad(bool, &self.can_return, .acquire)) std.atomic.spinLoopHint();
            if (self.started) {
                self.valid = self.valid and self.coordinator.stopRequested(self.ticket);
                self.coordinator.acknowledgeOwnedRootReturn(self.ticket) catch {
                    self.valid = false;
                };
            }
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var running_prompts: usize = 0;
    var ready_stops: usize = 0;
    for (0..CAPACITY * 8) |round| {
        const cpu: u8 = @intCast(round % CAPACITY);
        const ticket = try coordinator.prepare(cpu, testIdentity(cpu));
        try coordinator.bindOwnedRoot(ticket, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        var model = Model{ .coordinator = &coordinator, .ticket = ticket };
        const thread = try std.Thread.spawn(.{}, Model.owner, .{&model});
        var joined = false;
        defer if (!joined) {
            @atomicStore(bool, &model.go, true, .release);
            @atomicStore(bool, &model.can_return, true, .release);
            thread.join();
        };
        const ordering = round / CAPACITY % 4;
        if (ordering != 1) @atomicStore(bool, &model.go, true, .release);
        if (ordering == 0) while (!@atomicLoad(bool, &model.done, .acquire)) std.atomic.spinLoopHint();
        const prompt = try coordinator.requestStop(ticket);
        @atomicStore(bool, &model.go, true, .release);
        while (!@atomicLoad(bool, &model.done, .acquire)) std.atomic.spinLoopHint();
        if (prompt) running_prompts += 1 else ready_stops += 1;
        @atomicStore(bool, &model.can_return, true, .release);
        thread.join();
        joined = true;
        try std.testing.expectEqual(model.started, prompt);
        try std.testing.expect(model.valid);
        if (!model.started) try coordinator.cancelUnstarted(ticket);
        _ = try coordinator.beginCollect(ticket);
        try coordinator.finishCollect(ticket);
    }
    try std.testing.expect(running_prompts >= CAPACITY * 2);
    try std.testing.expect(ready_stops >= CAPACITY * 2);
}

fn testEnvelope(cpu: usize, ordinal: usize) Envelope {
    return .{ .opcode = @intCast(0x100 + cpu), .request_addr = 0x10000 + cpu * 4096 + ordinal, .response_addr = 0x20000 + cpu * 4096 + ordinal, .response_len = 64 + ordinal };
}

fn testReply(cpu: usize, ordinal: usize) Reply {
    return .{ .status = @intCast(cpu), .denial_reason = @intCast(ordinal), .bytes_written = @intCast(64 + ordinal) };
}

test "mailbox slot geometry isolates every naturally aligned neighboring CPU payload" {
    try std.testing.expectEqual(@as(usize, 3080), @sizeOf(Coordinator));
    try std.testing.expectEqual(@as(usize, 192), @sizeOf(Slot));
    var base_offset: usize = 0;
    while (base_offset < 64) : (base_offset += @alignOf(Slot)) {
        for (0..CAPACITY - 1) |cpu| {
            const last_active_line = (base_offset + cpu * @sizeOf(Slot) + @offsetOf(Slot, "padding") - 1) / 64;
            const next_active_line = (base_offset + (cpu + 1) * @sizeOf(Slot)) / 64;
            try std.testing.expect(last_active_line < next_active_line);
        }
    }
}

test "all mailbox owners require claimed work and consumed reply before return" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var tickets: [CAPACITY]Ticket = undefined;
    for (&tickets, 0..) |*ticket, cpu| {
        ticket.* = try coordinator.prepare(@intCast(cpu), testIdentity(cpu));
        try coordinator.bindOwnedRoot(ticket.*, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        cpu_identity.setIndexForTest(@intCast(cpu));
        var bound: BoundIdentity = undefined;
        try coordinator.startInto(ticket.*, &bound);
        var owner_bound: BoundIdentity = undefined;
        try coordinator.boundIdentityInto(ticket.*, &owner_bound);
        try std.testing.expectEqualDeep(bound, owner_bound);
        cpu_identity.setIndexForTest(0);
    }
    for (0..CAPACITY) |position| {
        const cpu: u8 = @intCast(if (position % 2 == 0) CAPACITY - 1 - position / 2 else position / 2);
        const ticket = tickets[cpu];
        cpu_identity.setIndexForTest(cpu);
        var key: RequestKey = undefined;
        try coordinator.submitSyscallInto(ticket, testEnvelope(cpu, 0), &key);
        try std.testing.expect(!coordinator.syscallIdle(ticket));
        const key_before = key;
        try std.testing.expectError(error.Busy, coordinator.submitSyscallInto(ticket, testEnvelope(cpu, 1), &key));
        try std.testing.expectEqualDeep(key_before, key);
        try std.testing.expectError(error.SyscallInFlight, coordinator.acknowledgeOwnedRootReturn(ticket));
        var reply = testReply(7, 99);
        const reply_before = reply;
        try std.testing.expectError(error.NotReady, coordinator.consumeSyscallInto(key, &reply));
        try std.testing.expectEqualDeep(reply_before, reply);
        cpu_identity.setIndexForTest(0);
        var claim: ClaimedSyscall = undefined;
        try coordinator.claimSyscallInto(cpu, &claim);
        try std.testing.expectEqualDeep(key, claim.key);
        try std.testing.expectEqualDeep(testEnvelope(cpu, 0), claim.envelope);
        try std.testing.expectEqualDeep(testIdentity(cpu), claim.bound.identity);
        const claim_before = claim;
        try std.testing.expectError(error.NoRequest, coordinator.claimSyscallInto(cpu, &claim));
        try std.testing.expectEqualDeep(claim_before, claim);
        var checked_bound: BoundIdentity = undefined;
        var stopped = true;
        try coordinator.validateClaimInto(&claim, &checked_bound, &stopped);
        try std.testing.expect(!stopped);
        try std.testing.expectEqualDeep(claim.bound, checked_bound);
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(!coordinator.cancelPendingSyscall(key));
        try std.testing.expectError(error.SyscallInFlight, coordinator.acknowledgeOwnedRootReturn(ticket));
        cpu_identity.setIndexForTest(0);
        try coordinator.completeSyscall(key, testReply(cpu, 0));
        try std.testing.expectError(error.WrongPhase, coordinator.completeSyscall(key, testReply(cpu, 1)));
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(!coordinator.cancelPendingSyscall(key));
        try std.testing.expectError(error.SyscallInFlight, coordinator.acknowledgeOwnedRootReturn(ticket));
        try coordinator.consumeSyscallInto(key, &reply);
        try std.testing.expectEqualDeep(testReply(cpu, 0), reply);
        try std.testing.expect(coordinator.syscallIdle(ticket));
        const consumed = reply;
        try std.testing.expectError(error.StaleRequest, coordinator.consumeSyscallInto(key, &reply));
        try std.testing.expectEqualDeep(consumed, reply);
        try coordinator.acknowledgeOwnedRootReturn(ticket);
        cpu_identity.setIndexForTest(0);
        _ = try coordinator.beginCollect(ticket);
    }
    for (tickets) |ticket| try coordinator.finishCollect(ticket);
    try std.testing.expect(!coordinator.hasLeases());
}

test "mailbox STOP before claim is cancelable while claimed STOP must drain" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    for (0..CAPACITY) |cpu| {
        const ticket = try coordinator.prepare(@intCast(cpu), testIdentity(cpu));
        try coordinator.bindOwnedRoot(ticket, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        cpu_identity.setIndexForTest(@intCast(cpu));
        _ = try coordinator.start(ticket);
        var key: RequestKey = undefined;
        try coordinator.submitSyscallInto(ticket, testEnvelope(cpu, 0), &key);
        cpu_identity.setIndexForTest(0);
        var claim = ClaimedSyscall{ .key = key, .envelope = testEnvelope(99, 99), .bound = .{ .identity = testIdentity(99), .mapping_handle = 999, .physical_root = 4096 } };
        if (cpu % 2 == 0) {
            const before = claim;
            try std.testing.expect(try coordinator.requestStop(ticket));
            try std.testing.expectError(error.StopRequested, coordinator.claimSyscallInto(@intCast(cpu), &claim));
            try std.testing.expectEqualDeep(before, claim);
            cpu_identity.setIndexForTest(@intCast(cpu));
            try std.testing.expect(coordinator.cancelPendingSyscall(key));
        } else {
            try coordinator.claimSyscallInto(@intCast(cpu), &claim);
            try std.testing.expect(try coordinator.requestStop(ticket));
            var bound: BoundIdentity = undefined;
            var stopped = false;
            try coordinator.validateClaimInto(&claim, &bound, &stopped);
            try std.testing.expect(stopped);
            try coordinator.completeSyscall(key, testReply(cpu, 3));
            cpu_identity.setIndexForTest(@intCast(cpu));
            try std.testing.expect(!coordinator.cancelPendingSyscall(key));
            var reply: Reply = undefined;
            try coordinator.consumeSyscallInto(key, &reply);
            try std.testing.expectEqualDeep(testReply(cpu, 3), reply);
        }
        const old_key = key;
        try std.testing.expectError(error.StopRequested, coordinator.submitSyscallInto(ticket, testEnvelope(cpu, 1), &key));
        try std.testing.expectEqualDeep(old_key, key);
        try std.testing.expect(coordinator.syscallIdle(ticket));
        try coordinator.acknowledgeOwnedRootReturn(ticket);
        cpu_identity.setIndexForTest(0);
        _ = try coordinator.beginCollect(ticket);
        try coordinator.finishCollect(ticket);
    }
}

test "mailbox authenticates issuer lease sequence envelope and bound before output" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var other: Coordinator = .{};
    const ticket = try coordinator.prepare(1, testIdentity(1));
    const colliding = try other.prepare(1, testIdentity(1));
    try coordinator.bindOwnedRoot(ticket, 7, 4096);
    try other.bindOwnedRoot(colliding, 8, 8192);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(ticket);
    _ = try other.start(colliding);
    var key: RequestKey = undefined;
    try coordinator.submitSyscallInto(ticket, testEnvelope(1, 0), &key);
    var rejected_reply = testReply(99, 99);
    const rejected_before = rejected_reply;
    try std.testing.expectError(error.WrongCoordinator, other.consumeSyscallInto(key, &rejected_reply));
    try std.testing.expectEqualDeep(rejected_before, rejected_reply);
    cpu_identity.setIndexForTest(2);
    try std.testing.expect(!coordinator.syscallIdle(ticket));
    try std.testing.expect(!coordinator.cancelPendingSyscall(key));
    var receipt = BoundIdentity{ .identity = testIdentity(99), .mapping_handle = 999, .physical_root = 4096 };
    const receipt_before = receipt;
    try std.testing.expectError(error.WrongCpu, coordinator.boundIdentityInto(ticket, &receipt));
    try std.testing.expectEqualDeep(receipt_before, receipt);
    cpu_identity.setIndexForTest(0);
    var claim: ClaimedSyscall = undefined;
    try coordinator.claimSyscallInto(1, &claim);
    const real = claim;
    var stopped = true;
    inline for (.{ "opcode", "request_addr", "response_addr", "response_len" }) |field| {
        claim = real;
        @field(claim.envelope, field) += 1;
        try std.testing.expectError(error.StaleRequest, coordinator.validateClaimInto(&claim, &receipt, &stopped));
        try std.testing.expectEqualDeep(receipt_before, receipt);
        try std.testing.expect(stopped);
    }
    inline for (.{ "task_handle", "task_id", "process_generation", "address_space_id" }) |field| {
        claim = real;
        @field(claim.bound.identity, field) += 1;
        try std.testing.expectError(error.StaleRequest, coordinator.validateClaimInto(&claim, &receipt, &stopped));
        try std.testing.expectEqualDeep(receipt_before, receipt);
        try std.testing.expect(stopped);
    }
    inline for (.{ "mapping_handle", "physical_root" }) |field| {
        claim = real;
        @field(claim.bound, field) += 4096;
        try std.testing.expectError(error.StaleRequest, coordinator.validateClaimInto(&claim, &receipt, &stopped));
        try std.testing.expectEqualDeep(receipt_before, receipt);
    }
    claim = real;
    claim.key.sequence += 1;
    try std.testing.expectError(error.StaleRequest, coordinator.completeSyscall(claim.key, testReply(1, 1)));
    try std.testing.expectError(error.StaleRequest, coordinator.validateClaimInto(&claim, &receipt, &stopped));
    claim = real;
    claim.key.ticket = colliding;
    try std.testing.expectError(error.WrongCoordinator, coordinator.validateClaimInto(&claim, &receipt, &stopped));
    try std.testing.expectError(error.WrongCoordinator, coordinator.completeSyscall(claim.key, testReply(1, 1)));
    try coordinator.completeSyscall(key, testReply(1, 0));
    cpu_identity.setIndexForTest(1);
    var reply: Reply = undefined;
    try coordinator.consumeSyscallInto(key, &reply);
    try coordinator.acknowledgeOwnedRootReturn(ticket);
    try other.acknowledgeOwnedRootReturn(colliding);
    cpu_identity.setIndexForTest(0);
    _ = try coordinator.beginCollect(ticket);
    try coordinator.finishCollect(ticket);
    _ = try other.beginCollect(colliding);
    try other.finishCollect(colliding);
    const replacement = try coordinator.prepare(1, testIdentity(2));
    try coordinator.bindOwnedRoot(replacement, 9, 12288);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(replacement);
    var replacement_key: RequestKey = undefined;
    try coordinator.submitSyscallInto(replacement, testEnvelope(1, 1), &replacement_key);
    try std.testing.expect(replacement_key.sequence > key.sequence);
    const replacement_before = replacement_key;
    try std.testing.expectError(error.StaleTicket, coordinator.submitSyscallInto(ticket, testEnvelope(1, 2), &replacement_key));
    try std.testing.expectEqualDeep(replacement_before, replacement_key);
    try std.testing.expectError(error.StaleTicket, coordinator.consumeSyscallInto(key, &reply));
    try std.testing.expect(!coordinator.cancelPendingSyscall(key));
    try std.testing.expect(coordinator.cancelPendingSyscall(replacement_key));
    try coordinator.acknowledgeOwnedRootReturn(replacement);
    cpu_identity.setIndexForTest(0);
    try std.testing.expectError(error.StaleTicket, coordinator.completeSyscall(key, testReply(1, 2)));
    _ = try coordinator.beginCollect(replacement);
    try coordinator.finishCollect(replacement);
}

test "mailbox publishing and corrupt retirement phases cannot bypass idle admission" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    const ticket = try coordinator.prepare(1, testIdentity(1));
    try coordinator.bindOwnedRoot(ticket, 7, 4096);
    // Even impossible nonidle mailboxes under unstarted/returned leases fail
    // closed instead of silently abandoning a queued request during retirement.
    coordinator.slots[1].syscall_control = packSyscall(1, SYSCALL_PUBLISHING);
    try std.testing.expectError(error.SyscallInFlight, coordinator.cancelUnstarted(ticket));
    cpu_identity.setIndexForTest(1);
    var bound = BoundIdentity{ .identity = testIdentity(99), .mapping_handle = 999, .physical_root = 4096 };
    try std.testing.expectError(error.SyscallInFlight, coordinator.startInto(ticket, &bound));
    coordinator.slots[1].syscall_control = packSyscall(1, SYSCALL_IDLE);
    try coordinator.startInto(ticket, &bound);
    coordinator.slots[1].syscall_control = packSyscall(2, SYSCALL_PUBLISHING);
    const before = coordinator;
    var key = RequestKey{ .ticket = ticket, .sequence = 2 };
    try std.testing.expectError(error.Busy, coordinator.submitSyscallInto(ticket, testEnvelope(1, 0), &key));
    try std.testing.expectError(error.SyscallInFlight, coordinator.acknowledgeOwnedRootReturn(ticket));
    try std.testing.expect(!coordinator.cancelPendingSyscall(key));
    try std.testing.expectEqualDeep(before, coordinator);
    cpu_identity.setIndexForTest(0);
    var claim: ClaimedSyscall = undefined;
    try std.testing.expectError(error.NoRequest, coordinator.claimSyscallInto(1, &claim));
    coordinator.slots[1].control = packControl(ticket.epoch, .returned, false, false);
    try std.testing.expectError(error.SyscallInFlight, coordinator.beginCollectInto(ticket, &bound.identity));
    coordinator.slots[1].control = packControl(ticket.epoch, .collecting, false, false);
    try std.testing.expectError(error.SyscallInFlight, coordinator.finishCollect(ticket));
    coordinator.slots[1].syscall_control = packSyscall(2, SYSCALL_IDLE);
    try coordinator.finishCollect(ticket);
}

test "mailbox sequence exhaustion survives cancellation and replacement leases" {
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    const ticket = try coordinator.prepare(1, testIdentity(1));
    try coordinator.bindOwnedRoot(ticket, 7, 4096);
    coordinator.slots[1].syscall_control = packSyscall(MAX_SYSCALL_SEQUENCE - 1, SYSCALL_IDLE);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(ticket);
    var key: RequestKey = undefined;
    try coordinator.submitSyscallInto(ticket, testEnvelope(1, 0), &key);
    try std.testing.expectEqual(MAX_SYSCALL_SEQUENCE, key.sequence);
    try std.testing.expect(coordinator.cancelPendingSyscall(key));
    const before = key;
    try std.testing.expectError(error.SequenceExhausted, coordinator.submitSyscallInto(ticket, testEnvelope(1, 1), &key));
    try std.testing.expectEqualDeep(before, key);
    try coordinator.acknowledgeOwnedRootReturn(ticket);
    cpu_identity.setIndexForTest(0);
    _ = try coordinator.beginCollect(ticket);
    try coordinator.finishCollect(ticket);
    const replacement = try coordinator.prepare(1, testIdentity(2));
    try coordinator.bindOwnedRoot(replacement, 8, 8192);
    cpu_identity.setIndexForTest(1);
    _ = try coordinator.start(replacement);
    try std.testing.expectError(error.SequenceExhausted, coordinator.submitSyscallInto(replacement, testEnvelope(1, 2), &key));
    try std.testing.expectEqualDeep(before, key);
    try coordinator.acknowledgeOwnedRootReturn(replacement);
    cpu_identity.setIndexForTest(0);
    _ = try coordinator.beginCollect(replacement);
    try coordinator.finishCollect(replacement);
}

test "mailbox owner cancellation races actual BSP claim without losing or duplicating work" {
    const Model = struct {
        coordinator: *Coordinator,
        ticket: Ticket,
        ordinal: usize,
        key: RequestKey = undefined,
        ready: bool = false,
        allow_cancel: bool = false,
        attempted_cancel: bool = false,
        canceled: bool = false,
        valid: bool = false,

        fn owner(self: *@This()) void {
            cpu_identity.setIndexForTest(self.ticket.cpu);
            var bound: BoundIdentity = undefined;
            self.coordinator.startInto(self.ticket, &bound) catch {
                @atomicStore(bool, &self.ready, true, .release);
                return;
            };
            self.valid = std.meta.eql(bound.identity, testIdentity(self.ticket.cpu));
            self.coordinator.submitSyscallInto(self.ticket, testEnvelope(self.ticket.cpu, self.ordinal), &self.key) catch {
                self.valid = false;
                @atomicStore(bool, &self.ready, true, .release);
                return;
            };
            @atomicStore(bool, &self.ready, true, .release);
            while (!@atomicLoad(bool, &self.allow_cancel, .acquire)) std.atomic.spinLoopHint();
            self.canceled = self.coordinator.cancelPendingSyscall(self.key);
            @atomicStore(bool, &self.attempted_cancel, true, .release);
            if (!self.canceled) {
                var reply: Reply = undefined;
                while (true) {
                    if (self.coordinator.consumeSyscallInto(self.key, &reply)) |_| {
                        self.valid = self.valid and std.meta.eql(reply, testReply(self.ticket.cpu, self.ordinal));
                        break;
                    } else |err| {
                        if (err != error.NotReady) {
                            self.valid = false;
                            break;
                        }
                        std.atomic.spinLoopHint();
                    }
                }
            }
            self.valid = self.valid and self.coordinator.syscallIdle(self.ticket);
            self.coordinator.acknowledgeOwnedRootReturn(self.ticket) catch {
                self.valid = false;
            };
        }
    };
    const previous = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous);
    cpu_identity.setIndexForTest(0);
    var coordinator: Coordinator = .{};
    var claimed_count: usize = 0;
    var canceled_count: usize = 0;
    for (0..CAPACITY * 6) |round| {
        const cpu: u8 = @intCast(round % CAPACITY);
        const ticket = try coordinator.prepare(cpu, testIdentity(cpu));
        try coordinator.bindOwnedRoot(ticket, 100 + cpu, (@as(u64, 100) + cpu) * 4096);
        var model = Model{ .coordinator = &coordinator, .ticket = ticket, .ordinal = round };
        const thread = try std.Thread.spawn(.{}, Model.owner, .{&model});
        var joined = false;
        var claimed = false;
        var completed = false;
        defer if (!joined) {
            if (claimed and !completed) coordinator.completeSyscall(model.key, testReply(cpu, round)) catch {};
            @atomicStore(bool, &model.allow_cancel, true, .release);
            thread.join();
        };
        while (!@atomicLoad(bool, &model.ready, .acquire)) std.atomic.spinLoopHint();
        try std.testing.expect(model.valid);
        const ordering = round / CAPACITY % 3;
        if (ordering != 0) @atomicStore(bool, &model.allow_cancel, true, .release);
        if (ordering == 1) while (!@atomicLoad(bool, &model.attempted_cancel, .acquire)) std.atomic.spinLoopHint();
        var claim: ClaimedSyscall = undefined;
        if (coordinator.claimSyscallInto(cpu, &claim)) |_| {
            claimed = true;
            claimed_count += 1;
            try std.testing.expectEqualDeep(model.key, claim.key);
            try std.testing.expectEqualDeep(testEnvelope(cpu, round), claim.envelope);
            try std.testing.expectEqualDeep(testIdentity(cpu), claim.bound.identity);
            try std.testing.expectEqual(@as(u64, 100 + cpu), claim.bound.mapping_handle);
            try std.testing.expectEqual((@as(u64, 100) + cpu) * 4096, claim.bound.physical_root);
            var checked: BoundIdentity = undefined;
            var stopped = false;
            if (round % 2 == 0) try std.testing.expect(try coordinator.requestStop(ticket));
            try coordinator.validateClaimInto(&claim, &checked, &stopped);
            try std.testing.expectEqual(round % 2 == 0, stopped);
            try std.testing.expectEqualDeep(claim.bound, checked);
            try coordinator.completeSyscall(model.key, testReply(cpu, round));
            completed = true;
        } else |err| {
            try std.testing.expect(err == error.NoRequest or err == error.WrongPhase);
            canceled_count += 1;
        }
        @atomicStore(bool, &model.allow_cancel, true, .release);
        thread.join();
        joined = true;
        try std.testing.expectEqual(!claimed, model.canceled);
        try std.testing.expect(model.valid);
        _ = try coordinator.beginCollect(ticket);
        try coordinator.finishCollect(ticket);
    }
    // Forced claim-first and cancel-first rounds cover both CAS outcomes on all
    // slots; the remaining rounds exercise the actual concurrent handoff.
    try std.testing.expect(claimed_count >= CAPACITY * 2);
    try std.testing.expect(canceled_count >= CAPACITY * 2);
    try std.testing.expect(!coordinator.hasLeases());
}
