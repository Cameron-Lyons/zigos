const builtin = @import("builtin");
const std = @import("std");
const capability_record = @import("capability/record.zig");
const capability_rights = @import("capability/rights.zig");
const id_index = @import("../core/id_index.zig");
const principal = @import("../core/principal.zig");
const native_util = @import("../core/util.zig");

pub const MAX_CAPABILITIES: usize = 128;
pub const CAPABILITY_INDEX_CAPACITY: usize = MAX_CAPABILITIES * 2;
pub const MAX_TARGET_GENERATIONS: usize = 128;
pub const MAX_GRANT_PLAN_ENTRIES: usize = 16;

pub const TableConfig = struct {
    max_capabilities: usize = MAX_CAPABILITIES,
    capability_index_capacity: usize = CAPABILITY_INDEX_CAPACITY,
    max_target_generations: usize = MAX_TARGET_GENERATIONS,
    debug_index_checks: bool = true,

    pub fn validate(comptime config: TableConfig) void {
        if (config.max_capabilities == 0) @compileError("capability table requires at least one capability slot");
        if (config.capability_index_capacity < config.max_capabilities) @compileError("capability index capacity must cover capability slots");
        if (config.max_target_generations == 0) @compileError("capability table requires at least one target generation slot");
        if (config.max_target_generations > std.math.maxInt(u8) + 1) @compileError("target generation indexes are stored as u8");
    }
};

pub const CapabilityTargetKind = capability_rights.CapabilityTargetKind;
pub const CapabilityTarget = capability_rights.CapabilityTarget;
pub const CapabilityRight = capability_rights.CapabilityRight;
pub const CapabilityRights = capability_rights.CapabilityRights;
pub const CapabilityScope = capability_record.CapabilityScope;
pub const CapabilityLease = capability_record.CapabilityLease;
pub const AuditMetadata = capability_record.AuditMetadata;
pub const Capability = capability_record.Capability;
pub const DEFAULT_MAX_DELEGATION_DEPTH = capability_record.DEFAULT_MAX_DELEGATION_DEPTH;

pub fn rightsAreValidForTarget(target: CapabilityTarget, rights: CapabilityRights) bool {
    return std.meta.activeTag(rights) == target.kind;
}

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
    DelegationDepthExceeded,
    GrantPlanFull,
    TargetTableFull,
};

const CapabilitySlot = struct {
    in_use: bool = false,
    capability: Capability = zeroCapability(),
    target_generation_index: u8 = 0,
    next_holder_index: ?usize = null,
    next_target_index: ?usize = null,
    next_free_index: ?usize = null,
};

const TargetGeneration = struct {
    in_use: bool = false,
    target: CapabilityTarget = .{ .kind = .task, .id = 0 },
    generation: u32 = 1,
    next_free_index: ?usize = null,
};

const IdIndexSlot = id_index.Slot;

const GrantReservation = struct {
    entry_count: usize = 0,
    slot_indexes: [MAX_GRANT_PLAN_ENTRIES]usize = [_]usize{0} ** MAX_GRANT_PLAN_ENTRIES,
    target_generation_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
    new_target_count: usize = 0,
    new_target_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
    new_targets: [MAX_GRANT_PLAN_ENTRIES]CapabilityTarget = [_]CapabilityTarget{.{ .kind = .task, .id = 0 }} ** MAX_GRANT_PLAN_ENTRIES,
};

pub const CapabilityTable = CapabilityTableWith(.{});

pub fn CapabilityTableWith(comptime config: TableConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_TABLE_CAPABILITIES = config.max_capabilities;
        const TABLE_INDEX_CAPACITY = config.capability_index_capacity;
        const MAX_TABLE_TARGET_GENERATIONS = config.max_target_generations;

        next_capability_id: u64 = 1,
        slots: [MAX_TABLE_CAPABILITIES]CapabilitySlot = [_]CapabilitySlot{CapabilitySlot{}} ** MAX_TABLE_CAPABILITIES,
        capability_index_slots: [TABLE_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(TABLE_INDEX_CAPACITY),
        holder_index_slots: [TABLE_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(TABLE_INDEX_CAPACITY),
        target_index_slots: [TABLE_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(TABLE_INDEX_CAPACITY),
        target_generation_index_slots: [TABLE_INDEX_CAPACITY]IdIndexSlot = emptyIndexTable(TABLE_INDEX_CAPACITY),
        target_generations: [MAX_TABLE_TARGET_GENERATIONS]TargetGeneration = [_]TargetGeneration{TargetGeneration{}} ** MAX_TABLE_TARGET_GENERATIONS,
        next_slot_index: usize = 0,
        next_target_generation_index: usize = 0,
        free_slot_head: ?usize = null,
        free_target_generation_head: ?usize = null,

        pub fn init() Self {
            return Self{};
        }

        pub fn mintBootRoot(self: *Self, request: MintRequest) Error!Capability {
            return self.mintFromGrantPlan(request);
        }

        pub fn applyGrantPlan(self: *Self, plan: *const GrantPlan, output: []Capability) Error![]Capability {
            if (output.len < plan.entry_count) return error.TableFull;
            const reservation = try self.reserveGrantPlan(plan);
            self.commitGrantPlan(plan, reservation, output);
            return output[0..plan.entry_count];
        }

        pub fn rollbackGrant(self: *Self, capabilities: []const Capability) void {
            for (capabilities) |minted| {
                self.discard(minted.id);
            }
        }

        pub fn queryByHolder(self: *const Self, holder: principal.PrincipalId, output: []Capability) []Capability {
            var count: usize = 0;
            var next_index = self.indexedHead(&self.holder_index_slots, holderKey(holder));
            if (next_index == null) self.debugAssertHolderIndexMissAbsent(holder);
            while (next_index) |slot_index| {
                if (slot_index >= self.slots.len) native_util.impossibleByInvariant("holder index points outside capability slots");
                const slot = &self.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("holder index points at a free capability slot");
                if (!slot.capability.holder.eql(holder)) native_util.impossibleByInvariant("holder index points at the wrong capability");
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
                next_index = slot.next_holder_index;
            }
            return output[0..count];
        }

        pub fn queryByTarget(self: *const Self, target: CapabilityTarget, output: []Capability) []Capability {
            var count: usize = 0;
            var next_index = self.indexedHead(&self.target_index_slots, targetKey(target));
            if (next_index == null) self.debugAssertTargetIndexMissAbsent(target);
            while (next_index) |slot_index| {
                if (slot_index >= self.slots.len) native_util.impossibleByInvariant("target index points outside capability slots");
                const slot = &self.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("target index points at a free capability slot");
                if (!slot.capability.target.eql(target)) native_util.impossibleByInvariant("target index points at the wrong capability");
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
                next_index = slot.next_target_index;
            }
            return output[0..count];
        }

        fn mintFromGrantPlan(self: *Self, request: MintRequest) Error!Capability {
            if (!rightsAreValidForTarget(request.target, request.rights)) return error.InvalidCapabilityRights;
            if (request.audit.delegation_depth > request.audit.max_delegation_depth) return error.DelegationDepthExceeded;
            const target_generation_index = try self.ensureTargetGenerationIndex(request.target);
            const capability_id = self.nextReservableCapabilityId() orelse return error.TableFull;
            const record = Capability{
                .id = capability_id,
                .holder = request.holder,
                .issuer = request.issuer,
                .target = request.target,
                .rights = request.rights,
                .scope = request.scope,
                .lease = request.lease,
                .revocation_generation = self.targetGenerationAt(target_generation_index).generation,
                .audit = request.audit,
            };
            const inserted = try self.insert(record, target_generation_index);
            self.advanceNextCapabilityIdFrom(capability_id);
            return inserted;
        }

        pub fn derive(self: *Self, request: DeriveRequest) Error!Capability {
            const parent_slot = self.findConstSlot(request.parent_capability_id) orelse return error.CapabilityNotFound;
            const parent = &parent_slot.capability;
            if (!self.isUsableSlot(parent_slot, request.lease.issued_at_ticks)) return error.CapabilityRevoked;
            if (!parent.rights.has(.capability_derive)) return error.RightsEscalation;
            if (!parent.rights.containsAll(request.rights)) return error.RightsEscalation;
            if (!rightsAreValidForTarget(parent.target, request.rights)) return error.InvalidCapabilityRights;
            if (!request.scope.isSubsetOf(parent.scope)) return error.ScopeEscalation;
            if (!request.lease.isSubsetOf(parent.lease)) return error.LeaseEscalation;

            const audit = try delegatedAudit(parent, request.audit);
            const capability_id = self.nextReservableCapabilityId() orelse return error.TableFull;
            const record = Capability{
                .id = capability_id,
                .holder = request.holder,
                .issuer = parent.holder,
                .target = parent.target,
                .rights = request.rights,
                .scope = request.scope,
                .lease = request.lease,
                .revocation_generation = parent.revocation_generation,
                .audit = audit,
            };
            const inserted = try self.insert(record, parent_slot.target_generation_index);
            self.advanceNextCapabilityIdFrom(capability_id);
            return inserted;
        }

        pub fn pass(self: *Self, request: PassRequest) Error!Capability {
            const original_slot = self.findConstSlot(request.capability_id) orelse return error.CapabilityNotFound;
            const original = &original_slot.capability;
            if (!self.isUsableSlot(original_slot, request.now_ticks)) return error.CapabilityRevoked;
            if (!original.rights.has(.capability_pass)) return error.RightsEscalation;
            const next_scope = request.scope orelse original.scope;
            if (!scopeIsPassCompatible(next_scope, original.scope, request.allow_task_retarget)) return error.ScopeEscalation;

            const audit = try delegatedAudit(original, request.audit);
            const capability_id = self.nextReservableCapabilityId() orelse return error.TableFull;
            const record = Capability{
                .id = capability_id,
                .holder = request.new_holder,
                .issuer = original.issuer,
                .target = original.target,
                .rights = original.rights,
                .scope = next_scope,
                .lease = original.lease,
                .revocation_generation = original.revocation_generation,
                .audit = audit,
            };
            const passed = try self.insert(record, original_slot.target_generation_index);
            self.advanceNextCapabilityIdFrom(capability_id);

            if (request.revoke_source) {
                const source_slot_index = self.findSlotIndex(request.capability_id) orelse return error.CapabilityNotFound;
                self.removeSlot(source_slot_index);
            }

            return passed;
        }

        pub fn revokeGrant(self: *Self, capability_id: u64) Error!void {
            _ = self.findConstSlot(capability_id) orelse return error.CapabilityNotFound;
            self.discard(capability_id);
        }

        pub fn revokeTargetAuthority(self: *Self, capability_id: u64) Error!void {
            const slot = self.findSlot(capability_id) orelse return error.CapabilityNotFound;
            const target_generation_index = slot.target_generation_index;
            self.discard(capability_id);
            self.targetGenerationAtMut(target_generation_index).generation += 1;
        }

        pub fn query(self: *const Self, capability_id: u64) ?Capability {
            const capability_ref = self.queryRef(capability_id) orelse return null;
            return capability_ref.*;
        }

        pub fn queryRef(self: *const Self, capability_id: u64) ?*const Capability {
            const slot = self.findConstSlot(capability_id) orelse return null;
            return &slot.capability;
        }

        pub fn isUsable(self: *const Self, capability: Capability, now_ticks: u64) bool {
            return self.isUsableRef(&capability, now_ticks);
        }

        pub fn isUsableRef(self: *const Self, capability: *const Capability, now_ticks: u64) bool {
            return capability.lease.isActive(now_ticks) and
                self.currentTargetGeneration(capability.target) == capability.revocation_generation;
        }

        pub fn requireUsable(self: *const Self, capability_id: u64, now_ticks: u64) Error!*const Capability {
            const slot = self.findConstSlot(capability_id) orelse return error.CapabilityNotFound;
            if (!self.isUsableSlot(slot, now_ticks)) return error.CapabilityRevoked;
            return &slot.capability;
        }

        fn nextReservableCapabilityId(self: *const Self) ?u64 {
            if (self.activeCapabilityCount() >= self.slots.len) return null;

            var capability_id = normalizeCapabilityId(self.next_capability_id);
            var attempts: usize = 0;
            while (attempts <= self.slots.len) : (attempts += 1) {
                if (self.findConstSlot(capability_id) == null) return capability_id;
                capability_id = nextCapabilityIdAfter(capability_id);
            }
            return null;
        }

        fn advanceNextCapabilityIdFrom(self: *Self, capability_id: u64) void {
            self.next_capability_id = nextCapabilityIdAfter(capability_id);
        }

        fn activeCapabilityCount(self: *const Self) usize {
            var count: usize = 0;
            for (self.slots) |slot| {
                if (slot.in_use) count += 1;
            }
            return count;
        }

        fn insert(self: *Self, capability: Capability, target_generation_index: u8) Error!Capability {
            const slot_index = self.popFreeSlot() orelse return error.TableFull;
            self.slots[slot_index] = .{
                .in_use = true,
                .capability = capability,
                .target_generation_index = target_generation_index,
            };
            self.indexSlot(slot_index);
            return capability;
        }

        fn findSlot(self: *Self, capability_id: u64) ?*CapabilitySlot {
            const slot_index = self.findSlotIndex(capability_id) orelse return null;
            return &self.slots[slot_index];
        }

        fn findConstSlot(self: *const Self, capability_id: u64) ?*const CapabilitySlot {
            const slot_index = self.findSlotIndex(capability_id) orelse return null;
            return &self.slots[slot_index];
        }

        fn isUsableSlot(self: *const Self, slot: *const CapabilitySlot, now_ticks: u64) bool {
            return slot.capability.lease.isActive(now_ticks) and
                self.targetGenerationAt(slot.target_generation_index).generation == slot.capability.revocation_generation;
        }

        fn ensureTargetGenerationIndex(self: *Self, target: CapabilityTarget) Error!u8 {
            if (self.findTargetGenerationIndex(target)) |index| return index;

            const index = self.popFreeTargetGeneration() orelse return error.TargetTableFull;
            self.target_generations[index] = .{
                .in_use = true,
                .target = target,
                .generation = 1,
            };
            indexInsert(TABLE_INDEX_CAPACITY, &self.target_generation_index_slots, targetKey(target), index);
            return @intCast(index);
        }

        fn targetGenerationAt(self: *const Self, target_generation_index: u8) *const TargetGeneration {
            return &self.target_generations[target_generation_index];
        }

        fn targetGenerationAtMut(self: *Self, target_generation_index: u8) *TargetGeneration {
            return &self.target_generations[target_generation_index];
        }

        fn currentTargetGeneration(self: *const Self, target: CapabilityTarget) u32 {
            if (self.findTargetGenerationIndex(target)) |index| {
                return self.targetGenerationAt(index).generation;
            }
            return 1;
        }

        fn reserveGrantPlan(self: *const Self, plan: *const GrantPlan) Error!GrantReservation {
            var reservation = GrantReservation{ .entry_count = plan.entry_count };
            for (plan.slice(), 0..) |entry, index| {
                if (!rightsAreValidForTarget(entry.request.target, entry.request.rights)) return error.InvalidCapabilityRights;
                reservation.slot_indexes[index] = try self.reserveCapabilitySlot(&reservation, index);
                reservation.target_generation_indexes[index] = try self.reserveTargetGeneration(entry.request.target, &reservation);
            }
            return reservation;
        }

        fn commitGrantPlan(
            self: *Self,
            plan: *const GrantPlan,
            reservation: GrantReservation,
            output: []Capability,
        ) void {
            var new_target_index: usize = 0;
            while (new_target_index < reservation.new_target_count) : (new_target_index += 1) {
                const table_index = reservation.new_target_indexes[new_target_index];
                self.claimReservedTargetGeneration(table_index);
                self.target_generations[table_index] = .{
                    .in_use = true,
                    .target = reservation.new_targets[new_target_index],
                    .generation = 1,
                };
                indexInsert(TABLE_INDEX_CAPACITY, &self.target_generation_index_slots, targetKey(reservation.new_targets[new_target_index]), table_index);
            }

            for (plan.slice(), 0..) |entry, index| {
                const capability_id = self.nextReservableCapabilityId() orelse {
                    native_util.impossibleByInvariant("grant plan slot reservations cover capability id allocation");
                };
                if (capability_id == 0) native_util.impossibleByInvariant("capability allocator never returns the reserved zero id");
                const granted_capability = Capability{
                    .id = capability_id,
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
                self.claimReservedSlot(slot_index);
                self.slots[slot_index] = .{
                    .in_use = true,
                    .capability = granted_capability,
                    .target_generation_index = reservation.target_generation_indexes[index],
                };
                self.indexSlot(slot_index);
                self.advanceNextCapabilityIdFrom(capability_id);
                output[index] = granted_capability;
            }
        }

        fn reserveCapabilitySlot(self: *const Self, reservation: *const GrantReservation, used_count: usize) Error!usize {
            var next_index = self.free_slot_head;
            while (next_index) |slot_index| {
                if (slot_index >= self.slots.len) return error.TableFull;
                next_index = self.slots[slot_index].next_free_index;
                if (reservationContainsSlot(reservation, used_count, slot_index)) continue;
                return slot_index;
            }
            var slot_index = self.next_slot_index;
            while (slot_index < self.slots.len) : (slot_index += 1) {
                if (reservationContainsSlot(reservation, used_count, slot_index)) continue;
                return slot_index;
            }
            return error.TableFull;
        }

        fn reserveTargetGeneration(self: *const Self, target: CapabilityTarget, reservation: *GrantReservation) Error!u8 {
            if (self.findTargetGenerationIndex(target)) |index| return index;

            var reserved_index: usize = 0;
            while (reserved_index < reservation.new_target_count) : (reserved_index += 1) {
                if (reservation.new_targets[reserved_index].eql(target)) {
                    return reservation.new_target_indexes[reserved_index];
                }
            }

            var next_index = self.free_target_generation_head;
            while (next_index) |index| {
                if (index >= self.target_generations.len) return error.TargetTableFull;
                next_index = self.target_generations[index].next_free_index;
                if (reservationContainsTargetGeneration(reservation, @intCast(index))) continue;
                if (reservation.new_target_count >= reservation.new_target_indexes.len) return error.TargetTableFull;
                reservation.new_target_indexes[reservation.new_target_count] = @intCast(index);
                reservation.new_targets[reservation.new_target_count] = target;
                reservation.new_target_count += 1;
                return @intCast(index);
            }
            var index = self.next_target_generation_index;
            while (index < self.target_generations.len) : (index += 1) {
                const target_generation_index: u8 = @intCast(index);
                if (reservationContainsTargetGeneration(reservation, target_generation_index)) continue;
                if (reservation.new_target_count >= reservation.new_target_indexes.len) return error.TargetTableFull;
                reservation.new_target_indexes[reservation.new_target_count] = target_generation_index;
                reservation.new_targets[reservation.new_target_count] = target;
                reservation.new_target_count += 1;
                return target_generation_index;
            }

            return error.TargetTableFull;
        }

        fn findTargetGenerationIndex(self: *const Self, target: CapabilityTarget) ?u8 {
            if (indexLookup(TABLE_INDEX_CAPACITY, &self.target_generation_index_slots, targetKey(target))) |index| {
                if (index >= self.target_generations.len) native_util.impossibleByInvariant("target generation index points outside slots");
                const entry = &self.target_generations[index];
                if (!entry.in_use) native_util.impossibleByInvariant("target generation index points at a free slot");
                if (!entry.target.eql(target)) native_util.impossibleByInvariant("target generation index points at the wrong target");
                return @intCast(index);
            }
            self.debugAssertTargetGenerationIndexMissAbsent(target);
            return null;
        }

        fn debugAssertTargetGenerationIndexMissAbsent(self: *const Self, target: CapabilityTarget) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.target_generations) |entry| {
                if (entry.in_use and entry.target.eql(target)) {
                    native_util.impossibleByInvariant("target generation index missed a live target");
                }
            }
        }

        fn debugAssertHolderIndexMissAbsent(self: *const Self, holder: principal.PrincipalId) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots) |slot| {
                if (slot.in_use and slot.capability.holder.eql(holder)) {
                    native_util.impossibleByInvariant("holder index missed a live capability");
                }
            }
        }

        fn debugAssertTargetIndexMissAbsent(self: *const Self, target: CapabilityTarget) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots) |slot| {
                if (slot.in_use and slot.capability.target.eql(target)) {
                    native_util.impossibleByInvariant("target index missed a live capability");
                }
            }
        }

        fn discard(self: *Self, capability_id: u64) void {
            const slot_index = self.findSlotIndex(capability_id) orelse return;
            self.removeSlot(slot_index);
        }

        fn findSlotIndex(self: *const Self, capability_id: u64) ?usize {
            const slot_index = indexLookup(TABLE_INDEX_CAPACITY, &self.capability_index_slots, capability_id) orelse {
                self.debugAssertCapabilityIndexMissAbsent(capability_id);
                return null;
            };
            if (slot_index >= self.slots.len) native_util.impossibleByInvariant("capability index points outside slots");
            const slot = &self.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("capability index points at a free slot");
            if (slot.capability.id != capability_id) native_util.impossibleByInvariant("capability index points at the wrong slot");
            return slot_index;
        }

        fn debugAssertCapabilityIndexMissAbsent(self: *const Self, capability_id: u64) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots) |slot| {
                if (slot.in_use and slot.capability.id == capability_id) {
                    native_util.impossibleByInvariant("capability index missed a live capability");
                }
            }
        }

        fn removeSlot(self: *Self, slot_index: usize) void {
            if (slot_index >= self.slots.len or !self.slots[slot_index].in_use) return;
            const removed = self.slots[slot_index].capability;
            indexRemove(TABLE_INDEX_CAPACITY, &self.capability_index_slots, removed.id);
            self.unlinkHolder(slot_index, holderKey(removed.holder));
            self.unlinkTarget(slot_index, targetKey(removed.target));
            self.slots[slot_index] = .{
                .next_free_index = self.free_slot_head,
            };
            self.free_slot_head = slot_index;
        }

        fn popFreeSlot(self: *Self) ?usize {
            if (self.free_slot_head) |slot_index| {
                if (slot_index >= self.slots.len) return null;
                self.free_slot_head = self.slots[slot_index].next_free_index;
                self.slots[slot_index].next_free_index = null;
                return slot_index;
            }
            if (self.next_slot_index >= self.slots.len) return null;
            defer self.next_slot_index += 1;
            return self.next_slot_index;
        }

        fn claimReservedSlot(self: *Self, slot_index: usize) void {
            if (slot_index >= self.next_slot_index) {
                self.next_slot_index = slot_index + 1;
            } else {
                self.unlinkFreeSlot(slot_index);
            }
        }

        fn unlinkFreeSlot(self: *Self, slot_index: usize) void {
            var previous: ?usize = null;
            var current = self.free_slot_head;
            while (current) |current_index| {
                if (current_index == slot_index) {
                    const next = self.slots[current_index].next_free_index;
                    if (previous) |previous_index| {
                        self.slots[previous_index].next_free_index = next;
                    } else {
                        self.free_slot_head = next;
                    }
                    self.slots[current_index].next_free_index = null;
                    return;
                }
                previous = current_index;
                current = self.slots[current_index].next_free_index;
            }
        }

        fn popFreeTargetGeneration(self: *Self) ?usize {
            if (self.free_target_generation_head) |index| {
                if (index >= self.target_generations.len) return null;
                self.free_target_generation_head = self.target_generations[index].next_free_index;
                self.target_generations[index].next_free_index = null;
                return index;
            }
            if (self.next_target_generation_index >= self.target_generations.len) return null;
            defer self.next_target_generation_index += 1;
            return self.next_target_generation_index;
        }

        fn claimReservedTargetGeneration(self: *Self, index: usize) void {
            if (index >= self.next_target_generation_index) {
                self.next_target_generation_index = index + 1;
            } else {
                self.unlinkFreeTargetGeneration(index);
            }
        }

        fn unlinkFreeTargetGeneration(self: *Self, index: usize) void {
            var previous: ?usize = null;
            var current = self.free_target_generation_head;
            while (current) |current_index| {
                if (current_index == index) {
                    const next = self.target_generations[current_index].next_free_index;
                    if (previous) |previous_index| {
                        self.target_generations[previous_index].next_free_index = next;
                    } else {
                        self.free_target_generation_head = next;
                    }
                    self.target_generations[current_index].next_free_index = null;
                    return;
                }
                previous = current_index;
                current = self.target_generations[current_index].next_free_index;
            }
        }

        fn indexSlot(self: *Self, slot_index: usize) void {
            const cap = self.slots[slot_index].capability;
            if (cap.id == 0) native_util.impossibleByInvariant("capability table slots never index the reserved zero capability id");
            indexInsert(TABLE_INDEX_CAPACITY, &self.capability_index_slots, cap.id, slot_index);

            const holder_key = holderKey(cap.holder);
            if (holder_key == 0) native_util.impossibleByInvariant("capability table holder indexes never use the reserved zero key");
            self.slots[slot_index].next_holder_index = self.indexedHead(&self.holder_index_slots, holder_key);
            indexInsert(TABLE_INDEX_CAPACITY, &self.holder_index_slots, holder_key, slot_index);

            const target_key = targetKey(cap.target);
            if (target_key == 0) native_util.impossibleByInvariant("capability table target indexes never use the reserved zero key");
            self.slots[slot_index].next_target_index = self.indexedHead(&self.target_index_slots, target_key);
            indexInsert(TABLE_INDEX_CAPACITY, &self.target_index_slots, target_key, slot_index);
        }

        fn indexedHead(self: *const Self, table: *const [TABLE_INDEX_CAPACITY]IdIndexSlot, key: u64) ?usize {
            _ = self;
            return indexLookup(TABLE_INDEX_CAPACITY, table, key);
        }

        fn unlinkHolder(self: *Self, slot_index: usize, key: u64) void {
            self.unlinkChain(slot_index, key, &self.holder_index_slots, true);
        }

        fn unlinkTarget(self: *Self, slot_index: usize, key: u64) void {
            self.unlinkChain(slot_index, key, &self.target_index_slots, false);
        }

        fn unlinkChain(
            self: *Self,
            slot_index: usize,
            key: u64,
            index_table: *[TABLE_INDEX_CAPACITY]IdIndexSlot,
            comptime holder_chain: bool,
        ) void {
            var previous: ?usize = null;
            var current = indexLookup(TABLE_INDEX_CAPACITY, index_table, key);
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
                        indexInsert(TABLE_INDEX_CAPACITY, index_table, key, next_index);
                    } else {
                        indexRemove(TABLE_INDEX_CAPACITY, index_table, key);
                    }
                    return;
                }
                previous = current_index;
                current = next;
            }
        }

        fn debugIndexChecksEnabledForTable() bool {
            return config.debug_index_checks and debugIndexChecksEnabled();
        }
    };
}

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
    return id_index.emptyTable(capacity);
}

fn indexLookup(comptime capacity: usize, table: *const [capacity]IdIndexSlot, id: u64) ?usize {
    return id_index.lookup(capacity, table, id);
}

fn indexInsert(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64, slot_index: usize) void {
    id_index.insert(capacity, table, id, slot_index, "capability indexes never store the reserved zero id");
}

fn indexRemove(comptime capacity: usize, table: *[capacity]IdIndexSlot, id: u64) void {
    id_index.remove(capacity, table, id);
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

fn normalizeCapabilityId(capability_id: u64) u64 {
    return if (capability_id == 0) 1 else capability_id;
}

fn nextCapabilityIdAfter(capability_id: u64) u64 {
    const next = capability_id +% 1;
    return normalizeCapabilityId(next);
}

fn debugIndexChecksEnabled() bool {
    return builtin.mode == .Debug;
}

fn zeroCapability() Capability {
    return .{
        .id = 0,
        .holder = .{ .kind = .service, .serial = 0 },
        .issuer = .{ .kind = .service, .serial = 0 },
        .target = .{ .kind = .service, .id = 0 },
        .rights = .{ .policy = .{} },
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
            .rights = CapabilityRights.emptyForTarget(.service),
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

fn delegatedAudit(parent: *const Capability, requested: AuditMetadata) Error!AuditMetadata {
    if (parent.audit.delegation_depth >= parent.audit.max_delegation_depth) return error.DelegationDepthExceeded;

    const next_depth = parent.audit.delegation_depth + 1;
    var audit = requested;
    if (audit.parent_trace_id == 0) audit.parent_trace_id = parent.traceId();
    audit.delegation_depth = next_depth;
    audit.max_delegation_depth = @min(parent.audit.max_delegation_depth, requested.max_delegation_depth);
    if (audit.delegation_depth > audit.max_delegation_depth) return error.DelegationDepthExceeded;
    return audit;
}

fn fullSessionRights() CapabilityRights {
    return .{ .service = .{
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
    } };
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
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
        } },
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

test "capability delegation depth budget stops transitive derive and pass chains" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const session = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const first_holder = principal.PrincipalId{ .kind = .app, .serial = 10 };
    const second_holder = principal.PrincipalId{ .kind = .app, .serial = 11 };

    const parent = try table.mintBootRoot(.{
        .holder = session,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 77 },
        .rights = .{ .service = .{
            .capability_derive = true,
            .capability_pass = true,
            .capability_query = true,
            .endpoint_connect = true,
        } },
        .scope = .{ .task_id = 200, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 200,
            .broker_service_id = 77,
            .max_delegation_depth = 1,
        },
    });

    const first = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = first_holder,
        .rights = .{ .service = .{
            .capability_derive = true,
            .capability_pass = true,
            .capability_query = true,
        } },
        .scope = .{ .task_id = 200, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 900, .renewable = false },
    });
    try std.testing.expectEqual(@as(u8, 1), first.audit.delegation_depth);
    try std.testing.expectEqual(@as(u8, 1), first.audit.max_delegation_depth);
    try std.testing.expectEqual(parent.traceId(), first.audit.parent_trace_id);

    try std.testing.expectError(error.DelegationDepthExceeded, table.derive(.{
        .parent_capability_id = first.id,
        .holder = second_holder,
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{ .task_id = 200, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 2, .expires_at_ticks = 800, .renewable = false },
    }));
    try std.testing.expectError(error.DelegationDepthExceeded, table.pass(.{
        .capability_id = first.id,
        .new_holder = second_holder,
        .now_ticks = 2,
        .scope = .{ .task_id = 200, .local_only = true, .broker_only = true },
    }));

    const direct_pass = try table.pass(.{
        .capability_id = parent.id,
        .new_holder = second_holder,
        .now_ticks = 3,
        .scope = .{ .task_id = 200, .local_only = true, .broker_only = true },
    });
    try std.testing.expectEqual(@as(u8, 1), direct_pass.audit.delegation_depth);
    try std.testing.expectEqual(parent.traceId(), direct_pass.audit.parent_trace_id);
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
        .rights = .{ .service = .{ .capability_query = true, .time_query = true } },
        .scope = .{ .task_id = 100, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000, .renewable = false },
        .audit = .{ .policy_generation = 1, .source_task_id = 100, .broker_service_id = 42 },
    });
    const derived = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = task,
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
        } },
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
        .rights = .{ .workspace = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
        } },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 50, .renewable = false },
    });

    try std.testing.expectError(error.RightsEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{ .workspace = .{
            .capability_derive = true,
            .capability_query = true,
            .resource_query = true,
            .time_query = true,
        } },
        .scope = .{ .workspace_id = 3, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 10, .renewable = false },
    }));

    try std.testing.expectError(error.ScopeEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = holder,
        .rights = .{ .workspace = .{
            .capability_query = true,
        } },
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
        .{ .object = .{ .object_read = true, .capability_query = true } },
    ));
    try std.testing.expect(!rightsAreValidForTarget(
        .{ .kind = .object, .id = 3 },
        .{ .network_policy = .{ .network_remote = true } },
    ));

    try std.testing.expectError(error.InvalidCapabilityRights, table.mintBootRoot(.{
        .holder = holder,
        .issuer = issuer,
        .target = .{ .kind = .object, .id = 3 },
        .rights = .{ .network_policy = .{ .network_remote = true } },
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
        .rights = .{ .endpoint = .{
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_pass = true,
        } },
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
        .rights = .{ .endpoint = .{ .endpoint_connect = true, .endpoint_recv = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 20, .renewable = false },
    });

    try std.testing.expect(!table.isUsable(capability, 9));
    try std.testing.expect(table.isUsable(capability, 15));
    try std.testing.expect(!table.isUsable(capability, 21));
}

test "capability table capacity is configurable" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 1,
        .capability_index_capacity = 2,
        .max_target_generations = 1,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };

    _ = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    try std.testing.expectError(error.TableFull, table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    }));
}

test "capability ids wrap without zero and skip active capabilities" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 5,
        .capability_index_capacity = 16,
        .max_target_generations = 1,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };

    table.next_capability_id = std.math.maxInt(u64);
    const max_capability = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(std.math.maxInt(u64), max_capability.id);
    try std.testing.expectEqual(@as(u64, 1), table.next_capability_id);
    try std.testing.expect(table.query(0) == null);

    const wrapped_capability = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(@as(u64, 1), wrapped_capability.id);
    try std.testing.expectEqual(@as(u64, 2), table.next_capability_id);
    try std.testing.expect(table.query(0) == null);

    table.next_capability_id = 1;
    const skipped_capability = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(@as(u64, 2), skipped_capability.id);
    try std.testing.expectEqual(@as(u64, 3), table.next_capability_id);
    try std.testing.expect(table.query(0) == null);

    var plan = GrantPlan{};
    try plan.addMint(1, .{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    var output: [1]Capability = undefined;
    table.next_capability_id = 1;
    _ = try table.applyGrantPlan(&plan, &output);
    try std.testing.expectEqual(@as(u64, 3), output[0].id);
    try std.testing.expectEqual(@as(u64, 4), table.next_capability_id);
    try std.testing.expect(table.query(0) == null);
}

test "capability ids do not advance when the table is full" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 1,
        .capability_index_capacity = 2,
        .max_target_generations = 1,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };

    _ = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    const next_before_full = table.next_capability_id;
    try std.testing.expectError(error.TableFull, table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    }));
    try std.testing.expectEqual(next_before_full, table.next_capability_id);
    try std.testing.expect(table.query(next_before_full) == null);
}

test "capability table reuses revoked slots through a free list" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 3,
        .capability_index_capacity = 8,
        .max_target_generations = 2,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };

    const first = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    const second = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    try table.revokeGrant(first.id);
    const reused = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    try std.testing.expect(table.query(second.id) != null);
    try std.testing.expect(table.query(first.id) == null);
    try std.testing.expect(table.query(reused.id) != null);
    try std.testing.expectEqual(@as(?usize, null), table.free_slot_head);
    try std.testing.expectEqual(@as(usize, 2), table.next_slot_index);

    const third = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expect(table.query(third.id) != null);
    try std.testing.expectEqual(@as(usize, 3), table.next_slot_index);
}

test "grant plan reserves target generation slots from the indexed free chain" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 4,
        .capability_index_capacity = 8,
        .max_target_generations = 2,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };
    var plan = GrantPlan{};

    try plan.addMint(1, .{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try plan.addMint(1, .{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .workspace, .id = 2 },
        .rights = .{ .workspace = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    var output: [2]Capability = undefined;
    _ = try table.applyGrantPlan(&plan, &output);
    try std.testing.expect(table.free_target_generation_head == null);
    try std.testing.expectEqual(@as(usize, 2), table.next_target_generation_index);
    try std.testing.expectEqual(@as(u32, 1), table.currentTargetGeneration(.{ .kind = .workspace, .id = 2 }));

    try std.testing.expectError(error.TargetTableFull, table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .object, .id = 3 },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    }));
}
