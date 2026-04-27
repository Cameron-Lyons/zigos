const std = @import("std");
const principal = @import("../core/principal.zig");

pub const MAX_CAPABILITIES: usize = 128;
pub const CAPABILITY_INDEX_CAPACITY: usize = MAX_CAPABILITIES * 2;
pub const MAX_TARGET_GENERATIONS: usize = 64;
pub const MAX_GRANT_PLAN_ENTRIES: usize = 16;

pub const CapabilityTargetKind = enum(u8) {
    task,
    endpoint,
    service,
    shared_memory,
    object,
    workspace,
    device,
    policy,
    network_policy,
};

pub const CapabilityTarget = struct {
    kind: CapabilityTargetKind,
    id: u64,

    pub fn eql(self: CapabilityTarget, other: CapabilityTarget) bool {
        return self.kind == other.kind and self.id == other.id;
    }
};

pub const CapabilityRights = packed struct(u32) {
    task_create: bool = false,
    task_terminate: bool = false,
    endpoint_create: bool = false,
    endpoint_connect: bool = false,
    endpoint_send: bool = false,
    endpoint_recv: bool = false,
    capability_mint: bool = false,
    capability_derive: bool = false,
    capability_pass: bool = false,
    capability_revoke: bool = false,
    capability_query: bool = false,
    shared_memory_create: bool = false,
    shared_memory_map: bool = false,
    shared_memory_unmap: bool = false,
    shared_memory_revoke: bool = false,
    time_query: bool = false,
    resource_query: bool = false,
    accounting_query: bool = false,
    object_read: bool = false,
    object_write: bool = false,
    device_use: bool = false,
    clipboard_read: bool = false,
    clipboard_write: bool = false,
    sensor_read: bool = false,
    background_run: bool = false,
    network_local: bool = false,
    network_remote: bool = false,
    ipc_peer: bool = false,
    location_read: bool = false,
    contacts_read: bool = false,
    screen_capture: bool = false,
    notification_post: bool = false,

    pub fn containsAll(self: CapabilityRights, requested: CapabilityRights) bool {
        const owned: u32 = @bitCast(self);
        const needed: u32 = @bitCast(requested);
        return (owned & needed) == needed;
    }

    pub fn intersects(self: CapabilityRights, other: CapabilityRights) bool {
        const left: u32 = @bitCast(self);
        const right: u32 = @bitCast(other);
        return (left & right) != 0;
    }

    pub fn unionWith(self: CapabilityRights, other: CapabilityRights) CapabilityRights {
        const left: u32 = @bitCast(self);
        const right: u32 = @bitCast(other);
        return @bitCast(left | right);
    }
};

pub fn rightsAreValidForTarget(target: CapabilityTarget, rights: CapabilityRights) bool {
    return allowedRightsForTarget(target.kind).containsAll(rights);
}

pub const CapabilityScope = struct {
    task_id: ?u64 = null,
    workspace_id: ?u64 = null,
    local_only: bool = false,
    broker_only: bool = false,

    pub fn isSubsetOf(self: CapabilityScope, parent: CapabilityScope) bool {
        if (parent.task_id) |task_id| {
            if (self.task_id == null or self.task_id.? != task_id) return false;
        }
        if (parent.workspace_id) |workspace_id| {
            if (self.workspace_id == null or self.workspace_id.? != workspace_id) return false;
        }
        if (parent.local_only and !self.local_only) return false;
        if (parent.broker_only and !self.broker_only) return false;
        return true;
    }
};

pub const CapabilityLease = struct {
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    renewable: bool = false,

    pub fn isActive(self: CapabilityLease, now_ticks: u64) bool {
        return now_ticks >= self.issued_at_ticks and now_ticks <= self.expires_at_ticks;
    }

    pub fn isSubsetOf(self: CapabilityLease, parent: CapabilityLease) bool {
        return self.issued_at_ticks >= parent.issued_at_ticks and self.expires_at_ticks <= parent.expires_at_ticks;
    }
};

pub const AuditMetadata = struct {
    policy_generation: u32 = 0,
    source_task_id: u64 = 0,
    broker_service_id: u64 = 0,
};

pub const Capability = struct {
    id: u64,
    holder: principal.PrincipalId,
    issuer: principal.PrincipalId,
    target: CapabilityTarget,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    revocation_generation: u32,
    audit: AuditMetadata,
};

pub const MintRequest = struct {
    holder: principal.PrincipalId,
    issuer: principal.PrincipalId,
    target: CapabilityTarget,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    audit: AuditMetadata = .{},
};

pub const GrantPlanEntry = struct {
    task_id: u64,
    request: MintRequest,
};

pub const GrantPlan = struct {
    entry_count: usize = 0,
    entries: [MAX_GRANT_PLAN_ENTRIES]GrantPlanEntry = [_]GrantPlanEntry{emptyGrantPlanEntry()} ** MAX_GRANT_PLAN_ENTRIES,

    pub fn addMint(self: *GrantPlan, task_id: u64, request: MintRequest) Error!void {
        if (self.entry_count >= self.entries.len) return error.GrantPlanFull;
        self.entries[self.entry_count] = .{
            .task_id = task_id,
            .request = request,
        };
        self.entry_count += 1;
    }

    pub fn slice(self: *const GrantPlan) []const GrantPlanEntry {
        return self.entries[0..self.entry_count];
    }
};

pub const DeriveRequest = struct {
    parent_capability_id: u64,
    holder: principal.PrincipalId,
    rights: CapabilityRights,
    scope: CapabilityScope,
    lease: CapabilityLease,
    audit: AuditMetadata = .{},
};

pub const PassRequest = struct {
    capability_id: u64,
    new_holder: principal.PrincipalId,
    now_ticks: u64,
    revoke_source: bool = false,
    allow_task_retarget: bool = false,
    scope: ?CapabilityScope = null,
    audit: AuditMetadata = .{},
};

pub const Error = error{
    CapabilityNotFound,
    CapabilityRevoked,
    InvalidCapabilityRights,
    LeaseEscalation,
    RightsEscalation,
    ScopeEscalation,
    TableFull,
    GrantPlanFull,
    TargetTableFull,
};

const CapabilitySlot = struct {
    in_use: bool = false,
    capability: Capability = zeroCapability(),
    target_generation_index: u8 = 0,
    next_holder_index: ?usize = null,
    next_target_index: ?usize = null,
};

const TargetGeneration = struct {
    in_use: bool = false,
    target: CapabilityTarget = .{ .kind = .task, .id = 0 },
    generation: u32 = 1,
};

const IndexState = enum(u8) {
    empty,
    filled,
    tombstone,
};

const IdIndexSlot = struct {
    state: IndexState = .empty,
    id: u64 = 0,
    slot_index: usize = 0,
};

const GrantReservation = struct {
    entry_count: usize = 0,
    slot_indexes: [MAX_GRANT_PLAN_ENTRIES]usize = [_]usize{0} ** MAX_GRANT_PLAN_ENTRIES,
    target_generation_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
    new_target_count: usize = 0,
    new_target_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
    new_targets: [MAX_GRANT_PLAN_ENTRIES]CapabilityTarget = [_]CapabilityTarget{.{ .kind = .task, .id = 0 }} ** MAX_GRANT_PLAN_ENTRIES,
};

pub const CapabilityTable = struct {
    next_capability_id: u64 = 1,
    slots: [MAX_CAPABILITIES]CapabilitySlot = [_]CapabilitySlot{CapabilitySlot{}} ** MAX_CAPABILITIES,
    capability_index_slots: [CAPABILITY_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(CAPABILITY_INDEX_CAPACITY),
    holder_index_slots: [CAPABILITY_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(CAPABILITY_INDEX_CAPACITY),
    target_index_slots: [CAPABILITY_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(CAPABILITY_INDEX_CAPACITY),
    target_generations: [MAX_TARGET_GENERATIONS]TargetGeneration = [_]TargetGeneration{TargetGeneration{}} ** MAX_TARGET_GENERATIONS,

    pub fn init() CapabilityTable {
        return CapabilityTable{};
    }

    pub fn mintBootRoot(self: *CapabilityTable, request: MintRequest) Error!Capability {
        return self.mintFromGrantPlan(request);
    }

    pub fn applyGrantPlan(self: *CapabilityTable, plan: *const GrantPlan, output: []Capability) Error![]Capability {
        if (output.len < plan.entry_count) return error.TableFull;
        const reservation = try self.reserveGrantPlan(plan);
        self.commitGrantPlan(plan, reservation, output);
        return output[0..plan.entry_count];
    }

    pub fn rollbackGrant(self: *CapabilityTable, capabilities: []const Capability) void {
        for (capabilities) |minted| {
            self.discard(minted.id);
        }
    }

    pub fn queryByHolder(self: *const CapabilityTable, holder: principal.PrincipalId, output: []Capability) []Capability {
        var count: usize = 0;
        var next_index = self.indexedHead(&self.holder_index_slots, holderKey(holder));
        while (next_index) |slot_index| {
            const slot = &self.slots[slot_index];
            if (slot.in_use and slot.capability.holder.eql(holder)) {
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
            }
            next_index = slot.next_holder_index;
        }
        return output[0..count];
    }

    pub fn queryByTarget(self: *const CapabilityTable, target: CapabilityTarget, output: []Capability) []Capability {
        var count: usize = 0;
        var next_index = self.indexedHead(&self.target_index_slots, targetKey(target));
        while (next_index) |slot_index| {
            const slot = &self.slots[slot_index];
            if (slot.in_use and slot.capability.target.eql(target)) {
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
            }
            next_index = slot.next_target_index;
        }
        return output[0..count];
    }

    fn mintFromGrantPlan(self: *CapabilityTable, request: MintRequest) Error!Capability {
        if (!rightsAreValidForTarget(request.target, request.rights)) return error.InvalidCapabilityRights;
        const target_generation_index = try self.ensureTargetGenerationIndex(request.target);
        return self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.holder,
            .issuer = request.issuer,
            .target = request.target,
            .rights = request.rights,
            .scope = request.scope,
            .lease = request.lease,
            .revocation_generation = self.targetGenerationAt(target_generation_index).generation,
            .audit = request.audit,
        }, target_generation_index);
    }

    pub fn derive(self: *CapabilityTable, request: DeriveRequest) Error!Capability {
        const parent_slot = self.findConstSlot(request.parent_capability_id) orelse return error.CapabilityNotFound;
        const parent = &parent_slot.capability;
        if (!self.isUsableSlot(parent_slot, request.lease.issued_at_ticks)) return error.CapabilityRevoked;
        if (!parent.rights.capability_derive) return error.RightsEscalation;
        if (!parent.rights.containsAll(request.rights)) return error.RightsEscalation;
        if (!rightsAreValidForTarget(parent.target, request.rights)) return error.InvalidCapabilityRights;
        if (!request.scope.isSubsetOf(parent.scope)) return error.ScopeEscalation;
        if (!request.lease.isSubsetOf(parent.lease)) return error.LeaseEscalation;

        return self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.holder,
            .issuer = parent.holder,
            .target = parent.target,
            .rights = request.rights,
            .scope = request.scope,
            .lease = request.lease,
            .revocation_generation = parent.revocation_generation,
            .audit = request.audit,
        }, parent_slot.target_generation_index);
    }

    pub fn pass(self: *CapabilityTable, request: PassRequest) Error!Capability {
        const original_slot = self.findConstSlot(request.capability_id) orelse return error.CapabilityNotFound;
        const original = &original_slot.capability;
        if (!self.isUsableSlot(original_slot, request.now_ticks)) return error.CapabilityRevoked;
        if (!original.rights.capability_pass) return error.RightsEscalation;
        const next_scope = request.scope orelse original.scope;
        if (!scopeIsPassCompatible(next_scope, original.scope, request.allow_task_retarget)) return error.ScopeEscalation;

        const passed = try self.insert(.{
            .id = self.allocateCapabilityId(),
            .holder = request.new_holder,
            .issuer = original.issuer,
            .target = original.target,
            .rights = original.rights,
            .scope = next_scope,
            .lease = original.lease,
            .revocation_generation = original.revocation_generation,
            .audit = request.audit,
        }, original_slot.target_generation_index);

        if (request.revoke_source) {
            const source_slot_index = self.findSlotIndex(request.capability_id) orelse return error.CapabilityNotFound;
            self.removeSlot(source_slot_index);
        }

        return passed;
    }

    pub fn revokeGrant(self: *CapabilityTable, capability_id: u64) Error!void {
        _ = self.findConstSlot(capability_id) orelse return error.CapabilityNotFound;
        self.discard(capability_id);
    }

    pub fn revokeTargetAuthority(self: *CapabilityTable, capability_id: u64) Error!void {
        const slot = self.findSlot(capability_id) orelse return error.CapabilityNotFound;
        const target_generation_index = slot.target_generation_index;
        self.discard(capability_id);
        self.targetGenerationAtMut(target_generation_index).generation += 1;
    }

    pub fn query(self: *const CapabilityTable, capability_id: u64) ?Capability {
        const capability_ref = self.queryRef(capability_id) orelse return null;
        return capability_ref.*;
    }

    pub fn queryRef(self: *const CapabilityTable, capability_id: u64) ?*const Capability {
        const slot = self.findConstSlot(capability_id) orelse return null;
        return &slot.capability;
    }

    pub fn isUsable(self: *const CapabilityTable, capability: Capability, now_ticks: u64) bool {
        return self.isUsableRef(&capability, now_ticks);
    }

    pub fn isUsableRef(self: *const CapabilityTable, capability: *const Capability, now_ticks: u64) bool {
        return capability.lease.isActive(now_ticks) and
            self.currentTargetGeneration(capability.target) == capability.revocation_generation;
    }

    pub fn requireUsable(self: *const CapabilityTable, capability_id: u64, now_ticks: u64) Error!*const Capability {
        const slot = self.findConstSlot(capability_id) orelse return error.CapabilityNotFound;
        if (!self.isUsableSlot(slot, now_ticks)) return error.CapabilityRevoked;
        return &slot.capability;
    }

    fn allocateCapabilityId(self: *CapabilityTable) u64 {
        defer self.next_capability_id += 1;
        return self.next_capability_id;
    }

    fn insert(self: *CapabilityTable, capability: Capability, target_generation_index: u8) Error!Capability {
        for (&self.slots, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.capability = capability;
            slot.target_generation_index = target_generation_index;
            self.indexSlot(slot_index);
            return capability;
        }
        return error.TableFull;
    }

    fn findSlot(self: *CapabilityTable, capability_id: u64) ?*CapabilitySlot {
        if (indexLookup(CAPABILITY_INDEX_CAPACITY, &self.capability_index_slots, capability_id)) |slot_index| {
            const slot = &self.slots[slot_index];
            if (slot.in_use and slot.capability.id == capability_id) return slot;
        }
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.capability.id == capability_id) return slot;
        }
        return null;
    }

    fn findConstSlot(self: *const CapabilityTable, capability_id: u64) ?*const CapabilitySlot {
        if (indexLookup(CAPABILITY_INDEX_CAPACITY, &self.capability_index_slots, capability_id)) |slot_index| {
            const slot = &self.slots[slot_index];
            if (slot.in_use and slot.capability.id == capability_id) return slot;
        }
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.capability.id == capability_id) return slot;
        }
        return null;
    }

    fn isUsableSlot(self: *const CapabilityTable, slot: *const CapabilitySlot, now_ticks: u64) bool {
        return slot.capability.lease.isActive(now_ticks) and
            self.targetGenerationAt(slot.target_generation_index).generation == slot.capability.revocation_generation;
    }

    fn ensureTargetGenerationIndex(self: *CapabilityTable, target: CapabilityTarget) Error!u8 {
        for (&self.target_generations, 0..) |*entry, index| {
            if (entry.in_use and entry.target.eql(target)) return @intCast(index);
        }

        for (&self.target_generations, 0..) |*entry, index| {
            if (entry.in_use) continue;
            entry.in_use = true;
            entry.target = target;
            entry.generation = 1;
            return @intCast(index);
        }

        return error.TargetTableFull;
    }

    fn targetGenerationAt(self: *const CapabilityTable, target_generation_index: u8) *const TargetGeneration {
        return &self.target_generations[target_generation_index];
    }

    fn targetGenerationAtMut(self: *CapabilityTable, target_generation_index: u8) *TargetGeneration {
        return &self.target_generations[target_generation_index];
    }

    fn currentTargetGeneration(self: *const CapabilityTable, target: CapabilityTarget) u32 {
        for (self.target_generations) |entry| {
            if (entry.in_use and entry.target.eql(target)) return entry.generation;
        }
        return 1;
    }

    fn reserveGrantPlan(self: *const CapabilityTable, plan: *const GrantPlan) Error!GrantReservation {
        var reservation = GrantReservation{ .entry_count = plan.entry_count };
        for (plan.slice(), 0..) |entry, index| {
            if (!rightsAreValidForTarget(entry.request.target, entry.request.rights)) return error.InvalidCapabilityRights;
            reservation.slot_indexes[index] = try self.reserveCapabilitySlot(&reservation, index);
            reservation.target_generation_indexes[index] = try self.reserveTargetGeneration(entry.request.target, &reservation);
        }
        return reservation;
    }

    fn commitGrantPlan(
        self: *CapabilityTable,
        plan: *const GrantPlan,
        reservation: GrantReservation,
        output: []Capability,
    ) void {
        var new_target_index: usize = 0;
        while (new_target_index < reservation.new_target_count) : (new_target_index += 1) {
            const table_index = reservation.new_target_indexes[new_target_index];
            self.target_generations[table_index] = .{
                .in_use = true,
                .target = reservation.new_targets[new_target_index],
                .generation = 1,
            };
        }

        for (plan.slice(), 0..) |entry, index| {
            const capability = Capability{
                .id = self.allocateCapabilityId(),
                .holder = entry.request.holder,
                .issuer = entry.request.issuer,
                .target = entry.request.target,
                .rights = entry.request.rights,
                .scope = entry.request.scope,
                .lease = entry.request.lease,
                .revocation_generation = self.targetGenerationAt(reservation.target_generation_indexes[index]).generation,
                .audit = entry.request.audit,
            };
            const slot_index = reservation.slot_indexes[index];
            self.slots[slot_index] = .{
                .in_use = true,
                .capability = capability,
                .target_generation_index = reservation.target_generation_indexes[index],
            };
            self.indexSlot(slot_index);
            output[index] = capability;
        }
    }

    fn reserveCapabilitySlot(self: *const CapabilityTable, reservation: *const GrantReservation, used_count: usize) Error!usize {
        for (self.slots, 0..) |slot, slot_index| {
            if (slot.in_use) continue;
            if (reservationContainsSlot(reservation, used_count, slot_index)) continue;
            return slot_index;
        }
        return error.TableFull;
    }

    fn reserveTargetGeneration(self: *const CapabilityTable, target: CapabilityTarget, reservation: *GrantReservation) Error!u8 {
        if (self.findTargetGenerationIndex(target)) |index| return index;

        var reserved_index: usize = 0;
        while (reserved_index < reservation.new_target_count) : (reserved_index += 1) {
            if (reservation.new_targets[reserved_index].eql(target)) {
                return reservation.new_target_indexes[reserved_index];
            }
        }

        for (self.target_generations, 0..) |entry, index| {
            if (entry.in_use) continue;
            if (reservationContainsTargetGeneration(reservation, @intCast(index))) continue;
            if (reservation.new_target_count >= reservation.new_target_indexes.len) return error.TargetTableFull;
            reservation.new_target_indexes[reservation.new_target_count] = @intCast(index);
            reservation.new_targets[reservation.new_target_count] = target;
            reservation.new_target_count += 1;
            return @intCast(index);
        }

        return error.TargetTableFull;
    }

    fn findTargetGenerationIndex(self: *const CapabilityTable, target: CapabilityTarget) ?u8 {
        for (self.target_generations, 0..) |entry, index| {
            if (entry.in_use and entry.target.eql(target)) return @intCast(index);
        }
        return null;
    }

    fn discard(self: *CapabilityTable, capability_id: u64) void {
        const slot_index = self.findSlotIndex(capability_id) orelse return;
        self.removeSlot(slot_index);
    }

    fn findSlotIndex(self: *const CapabilityTable, capability_id: u64) ?usize {
        if (indexLookup(CAPABILITY_INDEX_CAPACITY, &self.capability_index_slots, capability_id)) |slot_index| {
            const slot = &self.slots[slot_index];
            if (slot.in_use and slot.capability.id == capability_id) return slot_index;
        }
        for (self.slots, 0..) |slot, slot_index| {
            if (slot.in_use and slot.capability.id == capability_id) return slot_index;
        }
        return null;
    }

    fn removeSlot(self: *CapabilityTable, slot_index: usize) void {
        if (slot_index >= self.slots.len or !self.slots[slot_index].in_use) return;
        const removed = self.slots[slot_index].capability;
        indexRemove(CAPABILITY_INDEX_CAPACITY, &self.capability_index_slots, removed.id);
        self.unlinkHolder(slot_index, holderKey(removed.holder));
        self.unlinkTarget(slot_index, targetKey(removed.target));
        self.slots[slot_index] = CapabilitySlot{};
    }

    fn indexSlot(self: *CapabilityTable, slot_index: usize) void {
        const cap = self.slots[slot_index].capability;
        indexInsert(CAPABILITY_INDEX_CAPACITY, &self.capability_index_slots, cap.id, slot_index);

        const holder_key = holderKey(cap.holder);
        self.slots[slot_index].next_holder_index = self.indexedHead(&self.holder_index_slots, holder_key);
        indexInsert(CAPABILITY_INDEX_CAPACITY, &self.holder_index_slots, holder_key, slot_index);

        const target_key = targetKey(cap.target);
        self.slots[slot_index].next_target_index = self.indexedHead(&self.target_index_slots, target_key);
        indexInsert(CAPABILITY_INDEX_CAPACITY, &self.target_index_slots, target_key, slot_index);
    }

    fn indexedHead(self: *const CapabilityTable, table: *const [CAPABILITY_INDEX_CAPACITY]IdIndexSlot, key: u64) ?usize {
        _ = self;
        return indexLookup(CAPABILITY_INDEX_CAPACITY, table, key);
    }

    fn unlinkHolder(self: *CapabilityTable, slot_index: usize, key: u64) void {
        self.unlinkChain(slot_index, key, &self.holder_index_slots, true);
    }

    fn unlinkTarget(self: *CapabilityTable, slot_index: usize, key: u64) void {
        self.unlinkChain(slot_index, key, &self.target_index_slots, false);
    }

    fn unlinkChain(
        self: *CapabilityTable,
        slot_index: usize,
        key: u64,
        index_table: *[CAPABILITY_INDEX_CAPACITY]IdIndexSlot,
        comptime holder_chain: bool,
    ) void {
        var previous: ?usize = null;
        var current = indexLookup(CAPABILITY_INDEX_CAPACITY, index_table, key);
        while (current) |current_index| {
            const next = if (holder_chain)
                self.slots[current_index].next_holder_index
            else
                self.slots[current_index].next_target_index;
            if (current_index == slot_index) {
                if (previous) |previous_index| {
                    if (holder_chain) {
                        self.slots[previous_index].next_holder_index = next;
                    } else {
                        self.slots[previous_index].next_target_index = next;
                    }
                } else if (next) |next_index| {
                    indexInsert(CAPABILITY_INDEX_CAPACITY, index_table, key, next_index);
                } else {
                    indexRemove(CAPABILITY_INDEX_CAPACITY, index_table, key);
                }
                return;
            }
            previous = current_index;
            current = next;
        }
    }
};

fn reservationContainsSlot(reservation: *const GrantReservation, used_count: usize, slot_index: usize) bool {
    var index: usize = 0;
    while (index < used_count) : (index += 1) {
        if (reservation.slot_indexes[index] == slot_index) return true;
    }
    return false;
}

fn reservationContainsTargetGeneration(reservation: *const GrantReservation, target_generation_index: u8) bool {
    var index: usize = 0;
    while (index < reservation.new_target_count) : (index += 1) {
        if (reservation.new_target_indexes[index] == target_generation_index) return true;
    }
    return false;
}

fn emptyIndexTable(comptime capacity: usize) [capacity]IdIndexSlot {
    return [_]IdIndexSlot{IdIndexSlot{}} ** capacity;
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    if (id == 0) return null;

    var index = indexHash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        const entry = table[index];
        switch (entry.state) {
            .empty => return null,
            .filled => if (entry.id == id) return entry.slot_index,
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
    return null;
}

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    if (id == 0) unreachable;

    var index = indexHash(id, capacity);
    var first_tombstone: ?usize = null;
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => {
                const insert_index = first_tombstone orelse index;
                table[insert_index] = .{
                    .state = .filled,
                    .id = id,
                    .slot_index = slot_index,
                };
                return;
            },
            .filled => {
                if (table[index].id == id) {
                    table[index].slot_index = slot_index;
                    return;
                }
            },
            .tombstone => {
                if (first_tombstone == null) first_tombstone = index;
            },
        }
        index = (index + 1) % capacity;
    }

    unreachable;
}

fn indexRemove(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64) void {
    if (id == 0) return;

    var index = indexHash(id, capacity);
    var attempts: usize = 0;
    while (attempts < capacity) : (attempts += 1) {
        switch (table[index].state) {
            .empty => return,
            .filled => {
                if (table[index].id == id) {
                    table[index].state = .tombstone;
                    table[index].id = 0;
                    table[index].slot_index = 0;
                    return;
                }
            },
            .tombstone => {},
        }
        index = (index + 1) % capacity;
    }
}

fn indexHash(id: u64, comptime capacity: usize) usize {
    return @as(usize, @intCast((id *% 0x9E37_79B9_7F4A_7C15) % capacity));
}

fn holderKey(holder: principal.PrincipalId) u64 {
    return nonZeroKey((@as(u64, @intFromEnum(holder.kind)) << 56) ^ holder.serial);
}

fn targetKey(target: CapabilityTarget) u64 {
    return nonZeroKey((@as(u64, @intFromEnum(target.kind)) << 56) ^ target.id);
}

fn nonZeroKey(key: u64) u64 {
    return if (key == 0) 0xD1B5_4A32_D192_ED03 else key;
}

fn zeroCapability() Capability {
    return .{
        .id = 0,
        .holder = .{ .kind = .service, .serial = 0 },
        .issuer = .{ .kind = .service, .serial = 0 },
        .target = .{ .kind = .service, .id = 0 },
        .rights = .{},
        .scope = .{},
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 0,
            .renewable = false,
        },
        .revocation_generation = 0,
        .audit = .{},
    };
}

fn emptyGrantPlanEntry() GrantPlanEntry {
    return .{
        .task_id = 0,
        .request = .{
            .holder = .{ .kind = .service, .serial = 0 },
            .issuer = .{ .kind = .service, .serial = 0 },
            .target = .{ .kind = .service, .id = 0 },
            .rights = .{},
            .scope = .{},
            .lease = .{
                .issued_at_ticks = 0,
                .expires_at_ticks = 0,
                .renewable = false,
            },
            .audit = .{},
        },
    };
}

fn scopeIsPassCompatible(next_scope: CapabilityScope, original_scope: CapabilityScope, allow_task_retarget: bool) bool {
    if (original_scope.task_id) |task_id| {
        if (next_scope.task_id == null) return false;
        if (next_scope.task_id.? != task_id and !allow_task_retarget) return false;
    }
    if (original_scope.workspace_id) |workspace_id| {
        if (next_scope.workspace_id == null or next_scope.workspace_id.? != workspace_id) return false;
    }
    if (original_scope.local_only and !next_scope.local_only) return false;
    if (original_scope.broker_only and !next_scope.broker_only) return false;
    return true;
}

fn allowedRightsForTarget(kind: CapabilityTargetKind) CapabilityRights {
    const common = capabilityDelegationRights();
    return switch (kind) {
        .task => common.unionWith(.{
            .task_create = true,
            .task_terminate = true,
            .time_query = true,
            .resource_query = true,
            .accounting_query = true,
            .background_run = true,
            .notification_post = true,
        }),
        .endpoint => common.unionWith(.{
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .ipc_peer = true,
        }),
        .shared_memory => common.unionWith(.{
            .shared_memory_create = true,
            .shared_memory_map = true,
            .shared_memory_unmap = true,
            .shared_memory_revoke = true,
        }),
        .object => common.unionWith(.{
            .object_read = true,
            .object_write = true,
            .contacts_read = true,
        }),
        .device => common.unionWith(.{
            .device_use = true,
            .object_read = true,
            .object_write = true,
            .sensor_read = true,
            .location_read = true,
            .screen_capture = true,
            .network_local = true,
        }),
        .network_policy => common.unionWith(.{
            .network_local = true,
            .network_remote = true,
        }),
        .service, .workspace, .policy => allRights(),
    };
}

fn capabilityDelegationRights() CapabilityRights {
    return .{
        .capability_mint = true,
        .capability_derive = true,
        .capability_pass = true,
        .capability_revoke = true,
        .capability_query = true,
    };
}

fn allRights() CapabilityRights {
    return @bitCast(@as(u32, std.math.maxInt(u32)));
}

fn fullSessionRights() CapabilityRights {
    return .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .endpoint_send = true,
        .endpoint_recv = true,
        .capability_derive = true,
        .capability_pass = true,
        .capability_query = true,
        .time_query = true,
        .resource_query = true,
        .accounting_query = true,
    };
}

test "capabilities derive narrower rights and grant revocation leaves sibling authority usable" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const session = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const task = principal.PrincipalId{ .kind = .user, .serial = 9 };

    const parent = try table.mintBootRoot(.{
        .holder = session,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 42 },
        .rights = fullSessionRights(),
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });

    const derived = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = task,
        .rights = .{
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
        },
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 5, .expires_at_ticks = 500, .renewable = false },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });

    try std.testing.expect(table.isUsable(parent, 10));
    try std.testing.expect(table.isUsable(derived, 10));

    try table.revokeGrant(parent.id);
    try std.testing.expect(table.query(parent.id) == null);
    try std.testing.expect(table.isUsable(derived, 10));
}

test "target authority revocation invalidates sibling and derived capabilities" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const session = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const task = principal.PrincipalId{ .kind = .user, .serial = 9 };

    const parent = try table.mintBootRoot(.{
        .holder = session,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 42 },
        .rights = fullSessionRights(),
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = true },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });
    const sibling = try table.mintBootRoot(.{
        .holder = session,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 42 },
        .rights = .{ .capability_query = true, .time_query = true },
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });
    const derived = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = task,
        .rights = .{
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
        },
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 5, .expires_at_ticks = 500, .renewable = false },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });

    try table.revokeTargetAuthority(parent.id);
    try std.testing.expect(!table.isUsable(sibling, 10));
    try std.testing.expect(!table.isUsable(derived, 10));
}

test "derive rejects rights and scope escalation" {
    var table = CapabilityTable.init();
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 7 };

    const parent = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = issuer,
        .target = .{ .kind = .workspace, .id = 3 },
        .rights = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 50, .renewable = false },
    });

    try std.testing.expectError(error.RightsEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
            .time_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10, .renewable = false },
    }));

    try std.testing.expectError(error.ScopeEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{
            .capability_query = true,
        },
        .scope = .{ .workspace_id = 3, .local_only = false },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10, .renewable = false },
    }));
}

test "mint rejects rights that do not match concrete target kind" {
    var table = CapabilityTable.init();
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 7 };

    try std.testing.expect(rightsAreValidForTarget(
        .{ .kind = .object, .id = 3 },
        .{ .object_read = true, .capability_query = true },
    ));
    try std.testing.expect(!rightsAreValidForTarget(
        .{ .kind = .object, .id = 3 },
        .{ .object_read = true, .network_remote = true },
    ));

    try std.testing.expectError(error.InvalidCapabilityRights, table.mintBootRoot(.{
        .holder = holder,
        .issuer = issuer,
        .target = .{ .kind = .object, .id = 3 },
        .rights = .{
            .object_read = true,
            .network_remote = true,
        },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 50, .renewable = false },
    }));
}

test "passing capabilities duplicates or transfers authority based on request flags" {
    var table = CapabilityTable.init();
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const source = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const target = principal.PrincipalId{ .kind = .app, .serial = 3 };

    const original = try table.mintBootRoot(.{
        .holder = source,
        .issuer = issuer,
        .target = .{ .kind = .endpoint, .id = 99 },
        .rights = .{
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_pass = true,
        },
        .scope = .{ .task_id = 11, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });

    const duplicated = try table.pass(.{
        .capability_id = original.id,
        .new_holder = target,
        .now_ticks = 10,
        .scope = .{ .task_id = 11, .local_only = true },
    });
    try std.testing.expectEqual(target, duplicated.holder);
    try std.testing.expect(table.query(original.id) != null);

    _ = try table.pass(.{
        .capability_id = original.id,
        .new_holder = target,
        .now_ticks = 10,
        .revoke_source = true,
        .scope = .{ .task_id = 11, .local_only = true },
    });
    try std.testing.expect(table.query(original.id) == null);
}

test "expired capabilities are no longer usable" {
    var table = CapabilityTable.init();
    const capability = try table.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .endpoint, .id = 99 },
        .rights = .{ .endpoint_connect = true, .endpoint_recv = true },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 20, .renewable = false },
    });

    try std.testing.expect(!table.isUsable(capability, 9));
    try std.testing.expect(table.isUsable(capability, 15));
    try std.testing.expect(!table.isUsable(capability, 21));
}
