const builtin = @import("builtin");
const std = @import("std");
const capability_record = @import("capability/record.zig");
const capability_rights = @import("capability/rights.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
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

pub const LookupError = error{
    CapabilityNotFound,
    CapabilityRevoked,
};

pub const Error = LookupError || error{
    InvalidCapabilityRights,
    LeaseEscalation,
    RightsEscalation,
    ScopeEscalation,
    TableFull,
    DelegationDepthExceeded,
    GrantPlanFull,
    TargetTableFull,
};

pub const Inspection = struct {
    capability: *const Capability,
    usable: bool,
};

const CapabilitySlot = struct {
    in_use: bool = false,
    capability: Capability = zeroCapability(),
    target_generation_index: u8 = 0,
};

fn capabilitySlotId(slot: *const CapabilitySlot) u64 {
    return slot.capability.id;
}

const TargetGeneration = struct {
    in_use: bool = false,
    target: CapabilityTarget = .{ .kind = .task, .id = 0 },
    generation: u32 = 1,
};

fn targetGenerationKey(slot: *const TargetGeneration) u64 {
    return targetKey(slot.target);
}

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
        const CapabilityArena = indexed_arena.IndexedArenaWithKey(u64, CapabilitySlot, MAX_TABLE_CAPABILITIES, TABLE_INDEX_CAPACITY, capabilitySlotId);
        const TargetGenerationArena = indexed_arena.IndexedArenaWithKey(u64, TargetGeneration, MAX_TABLE_TARGET_GENERATIONS, TABLE_INDEX_CAPACITY, targetGenerationKey);
        const HolderIndex = indexed_arena.MultimapIndex(MAX_TABLE_CAPABILITIES, MAX_TABLE_CAPABILITIES, TABLE_INDEX_CAPACITY);
        const TargetIndex = indexed_arena.MultimapIndex(MAX_TABLE_CAPABILITIES, MAX_TABLE_CAPABILITIES, TABLE_INDEX_CAPACITY);
        const InsertedCapabilitySlot = struct {
            capability_id: u64,
            slot_index: usize,
        };

        next_capability_id: u64 = 1,
        slots: CapabilityArena = CapabilityArena.init(),
        holder_index: HolderIndex = HolderIndex.init(),
        target_index: TargetIndex = TargetIndex.init(),
        target_generations: TargetGenerationArena = TargetGenerationArena.init(),
        active_capability_count: usize = 0,
        mutation_generation: u64 = 1,

        pub fn init() Self {
            return Self{};
        }

        pub fn mutationGeneration(self: *const Self) u64 {
            return self.mutation_generation;
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
            var slot_index = self.holder_index.head(holderKey(holder));
            if (slot_index == indexed_arena.no_index) self.debugAssertHolderIndexMissAbsent(holder);
            while (slot_index != indexed_arena.no_index) : (slot_index = self.holder_index.next(slot_index)) {
                if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("holder index points outside capability slots");
                const slot = &self.slots.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("holder index points at a free capability slot");
                if (!slot.capability.holder.eql(holder)) native_util.impossibleByInvariant("holder index points at the wrong capability");
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
            }
            return output[0..count];
        }

        pub fn queryByTarget(self: *const Self, target: CapabilityTarget, output: []Capability) []Capability {
            var count: usize = 0;
            var slot_index = self.target_index.head(targetKey(target));
            if (slot_index == indexed_arena.no_index) self.debugAssertTargetIndexMissAbsent(target);
            while (slot_index != indexed_arena.no_index) : (slot_index = self.target_index.next(slot_index)) {
                if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("target index points outside capability slots");
                const slot = &self.slots.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("target index points at a free capability slot");
                if (!slot.capability.target.eql(target)) native_util.impossibleByInvariant("target index points at the wrong capability");
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
            }
            return output[0..count];
        }

        fn mintFromGrantPlan(self: *Self, request: MintRequest) Error!Capability {
            if (!rightsAreValidForTarget(request.target, request.rights)) return error.InvalidCapabilityRights;
            if (request.audit.delegation_depth > request.audit.max_delegation_depth) return error.DelegationDepthExceeded;
            const target_generation_index = try self.ensureTargetGenerationIndex(request.target);
            const record = Capability{
                .id = 0,
                .holder = request.holder,
                .issuer = request.issuer,
                .target = request.target,
                .rights = request.rights,
                .scope = request.scope,
                .lease = request.lease,
                .revocation_generation = self.targetGenerationAt(target_generation_index).generation,
                .audit = request.audit,
            };
            const inserted = try self.insertWithNextCapabilityId(record, target_generation_index);
            return inserted.*;
        }

        pub fn derive(self: *Self, request: DeriveRequest) Error!*const Capability {
            const parent_slot = self.findConstSlot(request.parent_capability_id) orelse return error.CapabilityNotFound;
            const parent = &parent_slot.capability;
            if (!self.isUsableSlot(parent_slot, request.lease.issued_at_ticks)) return error.CapabilityRevoked;
            if (!parent.rights.has(.capability_derive)) return error.RightsEscalation;
            if (!parent.rights.containsAll(request.rights)) return error.RightsEscalation;
            if (!rightsAreValidForTarget(parent.target, request.rights)) return error.InvalidCapabilityRights;
            if (!request.scope.isSubsetOf(parent.scope)) return error.ScopeEscalation;
            if (!request.lease.isSubsetOf(parent.lease)) return error.LeaseEscalation;

            const audit = try delegatedAudit(parent, request.audit);
            const record = Capability{
                .id = 0,
                .holder = request.holder,
                .issuer = parent.holder,
                .target = parent.target,
                .rights = request.rights,
                .scope = request.scope,
                .lease = request.lease,
                .revocation_generation = parent.revocation_generation,
                .audit = audit,
            };
            return self.insertWithNextCapabilityId(record, parent_slot.target_generation_index);
        }

        pub fn pass(self: *Self, request: PassRequest) Error!Capability {
            const original_slot = self.findConstSlot(request.capability_id) orelse return error.CapabilityNotFound;
            const original = &original_slot.capability;
            if (!self.isUsableSlot(original_slot, request.now_ticks)) return error.CapabilityRevoked;
            if (!original.rights.has(.capability_pass)) return error.RightsEscalation;
            const next_scope = request.scope orelse original.scope;
            if (!scopeIsPassCompatible(next_scope, original.scope, request.allow_task_retarget)) return error.ScopeEscalation;

            const audit = try delegatedAudit(original, request.audit);
            const record = Capability{
                .id = 0,
                .holder = request.new_holder,
                .issuer = original.issuer,
                .target = original.target,
                .rights = original.rights,
                .scope = next_scope,
                .lease = original.lease,
                .revocation_generation = original.revocation_generation,
                .audit = audit,
            };
            const passed = try self.insertWithNextCapabilityId(record, original_slot.target_generation_index);

            if (request.revoke_source) {
                const source_slot_index = self.findSlotIndex(request.capability_id) orelse return error.CapabilityNotFound;
                self.removeSlot(source_slot_index);
            }

            return passed.*;
        }

        pub fn revokeGrant(self: *Self, capability_id: u64) Error!void {
            const slot_index = self.findSlotIndex(capability_id) orelse return error.CapabilityNotFound;
            self.removeSlot(slot_index);
        }

        pub fn revokeTargetAuthority(self: *Self, capability_id: u64) Error!void {
            const slot_index = self.findSlotIndex(capability_id) orelse return error.CapabilityNotFound;
            const target_generation_index = self.slots.slots[slot_index].target_generation_index;
            self.removeSlot(slot_index);
            const target_generation = self.targetGenerationAtMut(target_generation_index);
            target_generation.generation += 1;
        }

        pub fn query(self: *const Self, capability_id: u64) ?Capability {
            const slot = self.findConstSlot(capability_id) orelse return null;
            return slot.capability;
        }

        pub fn inspect(self: *const Self, capability_id: u64, now_ticks: u64) ?Inspection {
            const slot = self.findConstSlot(capability_id) orelse return null;
            return .{
                .capability = &slot.capability,
                .usable = self.isUsableSlot(slot, now_ticks),
            };
        }

        pub fn requireUsable(self: *const Self, capability_id: u64, now_ticks: u64) LookupError!*const Capability {
            const inspected = self.inspect(capability_id, now_ticks) orelse return error.CapabilityNotFound;
            if (!inspected.usable) return error.CapabilityRevoked;
            return inspected.capability;
        }

        fn insertNextCapabilitySlot(
            self: *Self,
            capability_template: Capability,
            target_generation_index: u8,
            requested_slot_index: ?usize,
        ) ?InsertedCapabilitySlot {
            if (self.activeCapabilityCount() >= self.slots.slots.len) return null;

            var capability_id = normalizeCapabilityId(self.next_capability_id);
            var attempts: usize = 0;
            while (attempts <= self.slots.slots.len) : (attempts += 1) {
                var capability = capability_template;
                capability.id = capability_id;
                const slot = CapabilitySlot{
                    .capability = capability,
                    .target_generation_index = target_generation_index,
                };
                const slot_index = if (requested_slot_index) |explicit_index|
                    self.slots.insertIndexAt(capability_id, explicit_index, slot)
                else
                    self.slots.insertIndex(capability_id, slot);
                if (slot_index) |inserted_slot_index| {
                    return .{
                        .capability_id = capability_id,
                        .slot_index = inserted_slot_index,
                    };
                }
                capability_id = nextCapabilityIdAfter(capability_id);
            }
            return null;
        }

        fn advanceNextCapabilityIdFrom(self: *Self, capability_id: u64) void {
            self.next_capability_id = nextCapabilityIdAfter(capability_id);
        }

        fn activeCapabilityCount(self: *const Self) usize {
            return self.active_capability_count;
        }

        fn insertWithNextCapabilityId(self: *Self, capability_template: Capability, target_generation_index: u8) Error!*const Capability {
            const inserted_slot = self.insertNextCapabilitySlot(capability_template, target_generation_index, null) orelse return error.TableFull;
            const inserted = self.commitInsertedSlot(inserted_slot.slot_index);
            self.advanceNextCapabilityIdFrom(inserted_slot.capability_id);
            return inserted;
        }

        fn commitInsertedSlot(self: *Self, slot_index: usize) *const Capability {
            self.indexSlot(slot_index);
            self.active_capability_count += 1;
            self.advanceMutationGeneration();
            return &self.slots.slots[slot_index].capability;
        }

        fn advanceMutationGeneration(self: *Self) void {
            self.mutation_generation +%= 1;
            if (self.mutation_generation == 0) self.mutation_generation = 1;
        }

        fn findConstSlot(self: *const Self, capability_id: u64) ?*const CapabilitySlot {
            return self.slots.getConst(capability_id);
        }

        fn isUsableSlot(self: *const Self, slot: *const CapabilitySlot, now_ticks: u64) bool {
            return slot.capability.lease.isActive(now_ticks) and
                self.targetGenerationAt(slot.target_generation_index).generation == slot.capability.revocation_generation;
        }

        fn ensureTargetGenerationIndex(self: *Self, target: CapabilityTarget) Error!u8 {
            if (self.findTargetGenerationIndex(target)) |index| return index;

            const index = self.target_generations.insertIndex(targetKey(target), .{
                .target = target,
                .generation = 1,
            }) orelse return error.TargetTableFull;
            return @intCast(index);
        }

        fn targetGenerationAt(self: *const Self, target_generation_index: u8) *const TargetGeneration {
            return &self.target_generations.slots[target_generation_index];
        }

        fn targetGenerationAtMut(self: *Self, target_generation_index: u8) *TargetGeneration {
            return &self.target_generations.slots[target_generation_index];
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
                const table_index: usize = reservation.new_target_indexes[new_target_index];
                const target = reservation.new_targets[new_target_index];
                _ = self.target_generations.insertIndexAt(targetKey(target), table_index, .{
                    .target = target,
                    .generation = 1,
                }) orelse {
                    native_util.impossibleByInvariant("grant-plan reserved target-generation slot is still available");
                };
            }

            for (plan.slice(), 0..) |entry, index| {
                const granted_capability = Capability{
                    .id = 0,
                    .holder = entry.request.holder,
                    .issuer = entry.request.issuer,
                    .target = entry.request.target,
                    .rights = entry.request.rights,
                    .scope = entry.request.scope,
                    .lease = entry.request.lease,
                    .revocation_generation = self.targetGenerationAt(reservation.target_generation_indexes[index]).generation,
                    .audit = entry.request.audit,
                };
                const inserted_slot = self.insertNextCapabilitySlot(
                    granted_capability,
                    reservation.target_generation_indexes[index],
                    reservation.slot_indexes[index],
                ) orelse {
                    native_util.impossibleByInvariant("grant plan slot reservations cover capability id allocation");
                };
                if (inserted_slot.capability_id == 0) native_util.impossibleByInvariant("capability allocator never returns the reserved zero id");
                const granted = self.commitInsertedSlot(inserted_slot.slot_index);
                self.advanceNextCapabilityIdFrom(inserted_slot.capability_id);
                output[index] = granted.*;
            }
        }

        fn reserveCapabilitySlot(self: *const Self, reservation: *const GrantReservation, used_count: usize) Error!usize {
            return self.slots.availableIndexExcluding(
                SlotReservationContext{ .reservation = reservation, .used_count = used_count },
                reservationExcludesSlot,
            ) orelse error.TableFull;
        }

        fn reserveTargetGeneration(self: *const Self, target: CapabilityTarget, reservation: *GrantReservation) Error!u8 {
            if (self.findTargetGenerationIndex(target)) |index| return index;

            var reserved_index: usize = 0;
            while (reserved_index < reservation.new_target_count) : (reserved_index += 1) {
                if (reservation.new_targets[reserved_index].eql(target)) {
                    return reservation.new_target_indexes[reserved_index];
                }
            }

            const slot_index = self.target_generations.availableIndexExcluding(
                TargetGenerationReservationContext{ .reservation = reservation },
                reservationExcludesTargetGeneration,
            ) orelse return error.TargetTableFull;
            if (reservation.new_target_count >= reservation.new_target_indexes.len) return error.TargetTableFull;
            const target_generation_index: u8 = @intCast(slot_index);
            reservation.new_target_indexes[reservation.new_target_count] = target_generation_index;
            reservation.new_targets[reservation.new_target_count] = target;
            reservation.new_target_count += 1;
            return target_generation_index;
        }

        fn findTargetGenerationIndex(self: *const Self, target: CapabilityTarget) ?u8 {
            if (self.target_generations.slotIndexOf(targetKey(target))) |index| {
                if (index >= self.target_generations.slots.len) native_util.impossibleByInvariant("target generation index points outside slots");
                const entry = &self.target_generations.slots[index];
                if (!entry.in_use) native_util.impossibleByInvariant("target generation index points at a free slot");
                if (!entry.target.eql(target)) native_util.impossibleByInvariant("target generation index points at the wrong target");
                return @intCast(index);
            }
            self.debugAssertTargetGenerationIndexMissAbsent(target);
            return null;
        }

        fn debugAssertTargetGenerationIndexMissAbsent(self: *const Self, target: CapabilityTarget) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.target_generations.slots) |entry| {
                if (entry.in_use and entry.target.eql(target)) {
                    native_util.impossibleByInvariant("target generation index missed a live target");
                }
            }
        }

        fn debugAssertHolderIndexMissAbsent(self: *const Self, holder: principal.PrincipalId) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots.slots) |slot| {
                if (slot.in_use and slot.capability.holder.eql(holder)) {
                    native_util.impossibleByInvariant("holder index missed a live capability");
                }
            }
        }

        fn debugAssertTargetIndexMissAbsent(self: *const Self, target: CapabilityTarget) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots.slots) |slot| {
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
            const slot_index = self.slots.slotIndexOf(capability_id) orelse {
                self.debugAssertCapabilityIndexMissAbsent(capability_id);
                return null;
            };
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability index points outside slots");
            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("capability index points at a free slot");
            if (slot.capability.id != capability_id) native_util.impossibleByInvariant("capability index points at the wrong slot");
            return slot_index;
        }

        fn debugAssertCapabilityIndexMissAbsent(self: *const Self, capability_id: u64) void {
            if (!debugIndexChecksEnabledForTable()) return;
            for (self.slots.slots) |slot| {
                if (slot.in_use and slot.capability.id == capability_id) {
                    native_util.impossibleByInvariant("capability index missed a live capability");
                }
            }
        }

        fn removeSlot(self: *Self, slot_index: usize) void {
            if (slot_index >= self.slots.slots.len or !self.slots.slots[slot_index].in_use) return;
            const removed = self.slots.slots[slot_index].capability;
            self.unlinkHolder(slot_index, holderKey(removed.holder));
            self.unlinkTarget(slot_index, targetKey(removed.target));
            if (self.slots.removeIndex(slot_index)) {
                self.active_capability_count -= 1;
                self.advanceMutationGeneration();
            }
        }

        fn indexSlot(self: *Self, slot_index: usize) void {
            const cap = self.slots.slots[slot_index].capability;
            if (cap.id == 0) native_util.impossibleByInvariant("capability table slots never index the reserved zero capability id");

            const holder_key = holderKey(cap.holder);
            if (holder_key == 0) native_util.impossibleByInvariant("capability table holder indexes never use the reserved zero key");
            if (!self.holder_index.append(holder_key, slot_index)) {
                native_util.impossibleByInvariant("capability holder index capacity covers capability slots");
            }

            const target_key = targetKey(cap.target);
            if (target_key == 0) native_util.impossibleByInvariant("capability table target indexes never use the reserved zero key");
            if (!self.target_index.append(target_key, slot_index)) {
                native_util.impossibleByInvariant("capability target index capacity covers capability slots");
            }
        }

        fn unlinkHolder(self: *Self, slot_index: usize, key: u64) void {
            _ = self.holder_index.remove(key, slot_index);
        }

        fn unlinkTarget(self: *Self, slot_index: usize, key: u64) void {
            _ = self.target_index.remove(key, slot_index);
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

const SlotReservationContext = struct {
    reservation: *const GrantReservation,
    used_count: usize,
};

fn reservationExcludesSlot(context: SlotReservationContext, slot_index: usize) bool {
    return reservationContainsSlot(context.reservation, context.used_count, slot_index);
}

fn reservationContainsTargetGeneration(reservation: *const GrantReservation, target_generation_index: u8) bool {
    var index: usize = 0;
    while (index < reservation.new_target_count) : (index += 1) {
        if (reservation.new_target_indexes[index] == target_generation_index) return true;
    }
    return false;
}

const TargetGenerationReservationContext = struct {
    reservation: *const GrantReservation,
};

fn reservationExcludesTargetGeneration(context: TargetGenerationReservationContext, slot_index: usize) bool {
    return reservationContainsTargetGeneration(context.reservation, @intCast(slot_index));
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

test "capability table mutation generation tracks insert removal and wrap" {
    var table = CapabilityTable.init();
    const request = MintRequest{
        .holder = .{ .kind = .service, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .target = .{ .kind = .service, .id = 3 },
        .rights = .{ .service = .{ .endpoint_create = true } },
        .scope = .{ .task_id = 4, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    };

    try std.testing.expectEqual(@as(u64, 1), table.mutationGeneration());
    const first = try table.mintBootRoot(request);
    try std.testing.expectEqual(@as(u64, 2), table.mutationGeneration());
    try table.revokeGrant(first.id);
    try std.testing.expectEqual(@as(u64, 3), table.mutationGeneration());

    table.mutation_generation = std.math.maxInt(u64);
    const second = try table.mintBootRoot(request);
    try std.testing.expectEqual(@as(u64, 1), table.mutationGeneration());
    try table.revokeGrant(second.id);
    try std.testing.expectEqual(@as(u64, 2), table.mutationGeneration());
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

    _ = try table.requireUsable(parent.id, 10);
    const stored_derived = try table.requireUsable(derived.id, 10);
    try std.testing.expect(derived == stored_derived);

    try table.revokeGrant(parent.id);
    try std.testing.expect(table.query(parent.id) == null);
    try std.testing.expectError(error.CapabilityNotFound, table.requireUsable(parent.id, 10));
    _ = try table.requireUsable(derived.id, 10);
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
    try std.testing.expect(table.inspect(parent.id, 10) == null);
    const sibling_inspection = table.inspect(sibling.id, 10);
    try std.testing.expect(sibling_inspection != null);
    try std.testing.expect(!sibling_inspection.?.usable);
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(sibling.id, 10));
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(derived.id, 10));
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

    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(capability.id, 9));
    _ = try table.requireUsable(capability.id, 15);
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(capability.id, 21));
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

test "derived capability views are copied before revoked slots are reused" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 3,
        .capability_index_capacity = 8,
        .max_target_generations = 2,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };
    const derived_holder = principal.PrincipalId{ .kind = .app, .serial = 2 };

    const first = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{
            .capability_derive = true,
            .capability_query = true,
        } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    const derived_view = try table.derive(.{
        .parent_capability_id = first.id,
        .holder = derived_holder,
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    const derived: Capability = derived_view.*;
    const derived_slot_index = table.slots.slotIndexOf(derived.id).?;

    try table.revokeGrant(derived.id);
    const reused = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });

    try std.testing.expect(table.query(first.id) != null);
    try std.testing.expect(table.query(derived.id) == null);
    try std.testing.expect(table.query(reused.id) != null);
    try std.testing.expect(table.slots.slotIndexOf(derived.id) == null);
    try std.testing.expectEqual(derived_slot_index, table.slots.slotIndexOf(reused.id).?);
    try std.testing.expect(derived.holder.eql(derived_holder));
    try std.testing.expect(derived.rights.has(.capability_query));
    try std.testing.expectEqual(@as(usize, 2), table.slots.countInUse());

    const third = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expect(table.query(third.id) != null);
    try std.testing.expectEqual(@as(usize, 3), table.slots.countInUse());
}

test "grant plan reserves target generation slots in the arena" {
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
    try std.testing.expectEqual(@as(usize, 2), table.target_generations.countInUse());
    const workspace_generation_index = table.target_generations.slotIndexOf(targetKey(.{ .kind = .workspace, .id = 2 }));
    try std.testing.expect(workspace_generation_index != null);
    try std.testing.expectEqual(@as(u32, 1), table.target_generations.slots[workspace_generation_index.?].generation);

    try std.testing.expectError(error.TargetTableFull, table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .object, .id = 3 },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    }));
}
