const builtin = @import("builtin");
const std = @import("std");
const capability_record = @import("capability/record.zig");
const capability_rights = @import("capability/rights.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const principal = @import("../core/principal.zig");
const native_util = @import("../core/util.zig");

pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_TARGET_GENERATIONS: usize = 128;
pub const TARGET_GENERATION_INDEX_CAPACITY: usize = MAX_TARGET_GENERATIONS * 2;
pub const MAX_GRANT_PLAN_ENTRIES: usize = 16;
pub const CapabilitySlotIndex = indexed_arena.ReusableIndex(MAX_CAPABILITIES);
pub const COMPACT_GRANT_METADATA = true;
pub const TARGET_GENERATION_OWNS_CAPABILITY_CHAINS = true;
pub const CACHES_RECENT_TARGET_GENERATION = true;
pub const OVERWRITES_RESERVED_CAPABILITY_SLOTS = true;
pub const AVOIDS_REDUNDANT_HOLDER_INDEX = true;
pub const ZERO_CAPABILITY_ID_RESERVED = true;
pub const GRANT_RESERVATION_SIZE_CEILING_BYTES: usize = 312;
pub const CAPABILITY_TABLE_SIZE_CEILING_BYTES: usize = 32_040;
pub const CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_QUERY: u8 = 0;
pub const CAPABILITY_ID_COLLISION_PROBES_PER_INSERT: u8 = 0;
pub const PASS_SOURCE_REMOVAL_INDEX_RELOOKUPS: u8 = 0;
pub const DELEGATION_SOURCE_INDEX_RELOOKUPS: u8 = 0;
pub const TARGET_REVOCATION_INDEX_RELOOKUPS: u8 = 0;
pub const RESOLVED_CAPABILITY_SIZE_CEILING_BYTES: usize = 16;

comptime {
    if (MAX_GRANT_PLAN_ENTRIES > std.math.maxInt(u8)) {
        @compileError("capability grant plan count no longer fits in u8");
    }
    if (@sizeOf(CapabilitySlotIndex) != 1) {
        @compileError("capability grant reservation slot indexes no longer fit in u8");
    }
}

pub const TableConfig = struct {
    max_capabilities: usize = MAX_CAPABILITIES,
    max_target_generations: usize = MAX_TARGET_GENERATIONS,
    target_generation_index_capacity: usize = TARGET_GENERATION_INDEX_CAPACITY,
    debug_index_checks: bool = true,

    pub fn validate(comptime config: TableConfig) void {
        if (config.max_capabilities == 0) @compileError("capability table requires at least one capability slot");
        if (config.max_target_generations == 0) @compileError("capability table requires at least one target generation slot");
        if (config.max_target_generations > std.math.maxInt(u8) + 1) @compileError("target generation indexes are stored as u8");
        if (config.target_generation_index_capacity < config.max_target_generations) @compileError("target generation index capacity must cover target generation slots");
    }
};

pub const CapabilityTargetKind = capability_rights.CapabilityTargetKind;
pub const CapabilityTarget = capability_rights.CapabilityTarget;
pub const CapabilityRight = capability_rights.CapabilityRight;
pub const CapabilityRights = capability_rights.CapabilityRights;
pub const DIRECT_RIGHT_MASKS = capability_rights.DIRECT_RIGHT_MASKS;
pub const bitsContainRight = capability_rights.bitsContainRight;
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
    entry_count: u8 = 0,
    entries: [MAX_GRANT_PLAN_ENTRIES]GrantPlanEntry = [_]GrantPlanEntry{emptyGrantPlanEntry()} ** MAX_GRANT_PLAN_ENTRIES,

    pub fn addMint(self: *GrantPlan, task_id: u64, request: MintRequest) Error!void {
        const entry_index: usize = self.entry_count;
        if (entry_index >= self.entries.len) return error.GrantPlanFull;
        self.entries[entry_index] = .{
            .task_id = task_id,
            .request = request,
        };
        self.entry_count += 1;
    }

    pub fn slice(self: *const GrantPlan) []const GrantPlanEntry {
        return self.entries[0..@as(usize, self.entry_count)];
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

pub const ResolvedCapability = struct {
    capability: *const Capability,
    slot_index: usize,
};

comptime {
    if (@sizeOf(ResolvedCapability) > RESOLVED_CAPABILITY_SIZE_CEILING_BYTES) {
        @compileError("resolved capability exceeds its compact size ceiling");
    }
}

pub const RetiredAuthority = struct {
    capability_id: u64,
    scoped_task_id: ?u64,
};

pub fn GrantReservationFor(comptime max_capabilities: usize) type {
    const SlotIndex = indexed_arena.ReusableIndex(max_capabilities);
    return struct {
        slot_indexes: [MAX_GRANT_PLAN_ENTRIES]SlotIndex = [_]SlotIndex{0} ** MAX_GRANT_PLAN_ENTRIES,
        target_generation_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
        new_target_count: u8 = 0,
        new_target_indexes: [MAX_GRANT_PLAN_ENTRIES]u8 = [_]u8{0} ** MAX_GRANT_PLAN_ENTRIES,
        new_targets: [MAX_GRANT_PLAN_ENTRIES]CapabilityTarget = [_]CapabilityTarget{.{ .kind = .task, .id = 0 }} ** MAX_GRANT_PLAN_ENTRIES,

        comptime {
            if (max_capabilities == MAX_CAPABILITIES and @sizeOf(@This()) > GRANT_RESERVATION_SIZE_CEILING_BYTES) {
                @compileError("production capability grant reservation exceeded its stack-size ceiling");
            }
        }
    };
}

pub const GrantReservation = GrantReservationFor(MAX_CAPABILITIES);

pub const CapabilityTable = CapabilityTableWith(.{});

comptime {
    if (@sizeOf(CapabilityTable) > CAPABILITY_TABLE_SIZE_CEILING_BYTES) {
        @compileError("production capability table exceeded its fixed-state size ceiling");
    }
}

pub fn CapabilityTableWith(comptime config: TableConfig) type {
    config.validate();
    return struct {
        const Self = @This();
        const MAX_TABLE_CAPABILITIES = config.max_capabilities;
        const TABLE_TARGET_GENERATION_INDEX_CAPACITY = config.target_generation_index_capacity;
        const MAX_TABLE_TARGET_GENERATIONS = config.max_target_generations;
        const TableCapabilitySlotIndex = indexed_arena.ReusableIndex(MAX_TABLE_CAPABILITIES);
        const table_capability_no_index = indexed_arena.reusableNoIndex(MAX_TABLE_CAPABILITIES);
        const CapabilitySlot = struct {
            in_use: bool = false,
            capability: Capability = zeroCapability(),
            target_generation_index: u8 = 0,
            target_previous: TableCapabilitySlotIndex = table_capability_no_index,
            target_next: TableCapabilitySlotIndex = table_capability_no_index,
        };
        const TargetGeneration = struct {
            in_use: bool = false,
            target: CapabilityTarget = .{ .kind = .task, .id = 0 },
            generation: u32 = 1,
            capability_head: TableCapabilitySlotIndex = table_capability_no_index,
            capability_tail: TableCapabilitySlotIndex = table_capability_no_index,
            capability_count: TableCapabilitySlotIndex = 0,
        };
        const TargetGenerationKey = struct {
            fn key(slot: *const TargetGeneration) u64 {
                return targetKey(slot.target);
            }
        };
        const CapabilityArena = indexed_arena.GenerationalArena("CapabilityId", CapabilitySlot, MAX_TABLE_CAPABILITIES);
        const CapabilityHandle = CapabilityArena.Handle;
        const TargetGenerationArena = indexed_arena.IndexedArenaWithKey(u64, TargetGeneration, MAX_TABLE_TARGET_GENERATIONS, TABLE_TARGET_GENERATION_INDEX_CAPACITY, TargetGenerationKey.key);
        const TableGrantReservation = GrantReservationFor(MAX_TABLE_CAPABILITIES);
        const InsertedCapabilitySlot = struct {
            slot_index: usize,
        };
        const SlotReservationContext = struct {
            reservation: *const TableGrantReservation,
            used_count: usize,
        };
        const TargetGenerationReservationContext = struct {
            reservation: *const TableGrantReservation,
        };

        slots: CapabilityArena = CapabilityArena.init(),
        target_generations: TargetGenerationArena = TargetGenerationArena.init(),
        cached_target_key: u64 = 0,
        cached_target_generation_index: u8 = 0,
        mutation_generation: u64 = 1,

        pub fn init() Self {
            return Self{};
        }

        pub fn initializeAllocated(self: *Self) void {
            @memset(std.mem.asBytes(self), 0);
            self.slots.free_head = indexed_arena.reusableNoIndex(MAX_TABLE_CAPABILITIES);

            self.target_generations.free_head = indexed_arena.reusableNoIndex(MAX_TABLE_TARGET_GENERATIONS);
            self.mutation_generation = 1;
        }

        pub fn mutationGeneration(self: *const Self) u64 {
            return self.mutation_generation;
        }

        pub fn activeCount(self: *const Self) usize {
            return self.slots.countInUse();
        }

        pub fn mintBootRoot(self: *Self, request: MintRequest) Error!Capability {
            return self.mintFromGrantPlan(request);
        }

        pub fn applyGrantPlan(self: *Self, plan: *const GrantPlan, output: []Capability) Error![]Capability {
            const entry_count: usize = plan.entry_count;
            if (output.len < entry_count) return error.TableFull;
            const reservation = try self.reserveGrantPlan(plan);
            self.commitGrantPlan(plan, reservation, output);
            return output[0..entry_count];
        }

        pub fn rollbackGrant(self: *Self, capabilities: []const Capability) void {
            for (capabilities) |minted| {
                self.discard(minted.id);
            }
        }

        pub fn queryByTarget(self: *const Self, target: CapabilityTarget, output: []Capability) []Capability {
            var count: usize = 0;
            const target_generation_index = self.findTargetGenerationIndex(target) orelse return output[0..0];
            var compact_slot_index = self.targetGenerationAt(target_generation_index).capability_head;
            while (compact_slot_index != table_capability_no_index) {
                const slot_index: usize = @intCast(compact_slot_index);
                if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("target index points outside capability slots");
                const slot = &self.slots.slots[slot_index];
                if (!slot.in_use) native_util.impossibleByInvariant("target index points at a free capability slot");
                if (!slot.capability.target.eql(target)) native_util.impossibleByInvariant("target index points at the wrong capability");
                if (count >= output.len) break;
                output[count] = slot.capability;
                count += 1;
                compact_slot_index = slot.target_next;
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
            const inserted = try self.insertWithNewCapabilityId(record, target_generation_index);
            return inserted.*;
        }

        pub fn derive(self: *Self, request: DeriveRequest) Error!Capability {
            const parent = self.resolve(request.parent_capability_id) orelse return error.CapabilityNotFound;
            return self.deriveResolved(request, parent);
        }

        pub fn deriveResolved(self: *Self, request: DeriveRequest, resolved_parent: ResolvedCapability) Error!Capability {
            const parent_slot = self.resolvedSlot(resolved_parent, request.parent_capability_id) orelse return error.CapabilityNotFound;
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
            const inserted = try self.insertWithNewCapabilityId(record, parent_slot.target_generation_index);
            return inserted.*;
        }

        pub fn pass(self: *Self, request: PassRequest) Error!Capability {
            const source = self.resolve(request.capability_id) orelse return error.CapabilityNotFound;
            return self.passResolved(request, source);
        }

        pub fn passResolved(self: *Self, request: PassRequest, source: ResolvedCapability) Error!Capability {
            const original_slot = self.resolvedSlot(source, request.capability_id) orelse return error.CapabilityNotFound;
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
            const passed = try self.insertWithNewCapabilityId(record, original_slot.target_generation_index);

            if (request.revoke_source) {
                self.removeSlot(source.slot_index);
            }

            return passed.*;
        }

        pub fn revokeGrant(self: *Self, capability_id: u64) Error!void {
            const slot_index = self.findSlotIndex(capability_id) orelse return error.CapabilityNotFound;
            self.removeSlot(slot_index);
        }

        pub fn revokeTargetAuthority(self: *Self, capability_id: u64) Error!void {
            const resolved = self.resolve(capability_id) orelse return error.CapabilityNotFound;
            return self.revokeTargetAuthorityResolved(capability_id, resolved);
        }

        pub fn revokeTargetAuthorityResolved(self: *Self, capability_id: u64, resolved: ResolvedCapability) Error!void {
            const slot = self.resolvedSlot(resolved, capability_id) orelse return error.CapabilityNotFound;
            const target_generation_index = slot.target_generation_index;
            self.removeSlot(resolved.slot_index);
            const target_generation = self.targetGenerationAtMut(target_generation_index);
            target_generation.generation += 1;
        }

        pub fn retireTaskAuthority(self: *Self, task_id: u64, held_capability_ids: []const u64) usize {
            if (task_id == 0) return 0;
            return self.retireHeldTaskAuthority(task_id, held_capability_ids) +
                self.retireTargetAuthority(.{ .kind = .task, .id = task_id });
        }

        pub fn retireHeldTaskAuthority(self: *Self, task_id: u64, held_capability_ids: []const u64) usize {
            if (task_id == 0) return 0;
            var retired_count: usize = 0;

            for (held_capability_ids) |capability_id| {
                const slot_index = self.findSlotIndex(capability_id) orelse continue;
                const scoped_task_id = self.slots.slots[slot_index].capability.scope.task_id orelse continue;
                if (scoped_task_id != task_id) continue;
                self.removeSlot(slot_index);
                retired_count += 1;
            }
            return retired_count;
        }

        pub fn retireTargetAuthority(self: *Self, target: CapabilityTarget) usize {
            return self.retireTargetAuthorityInto(target, &[_]RetiredAuthority{});
        }

        pub fn retireTargetAuthorityInto(
            self: *Self,
            target: CapabilityTarget,
            retired_output: []RetiredAuthority,
        ) usize {
            var retired_count: usize = 0;
            const target_generation_index = self.findTargetGenerationIndex(target) orelse return 0;
            while (true) {
                const compact_slot_index = self.targetGenerationAt(target_generation_index).capability_head;
                if (compact_slot_index == table_capability_no_index) break;
                const slot_index: usize = @intCast(compact_slot_index);
                if (slot_index >= self.slots.slots.len) {
                    native_util.impossibleByInvariant("capability target index points outside capability slots");
                }
                const slot = &self.slots.slots[slot_index];
                if (!slot.in_use or !slot.capability.target.eql(target)) {
                    native_util.impossibleByInvariant("capability target index points at the wrong authority");
                }
                if (retired_count < retired_output.len) {
                    retired_output[retired_count] = .{
                        .capability_id = slot.capability.id,
                        .scoped_task_id = slot.capability.scope.task_id,
                    };
                }
                self.removeSlot(slot_index);
                retired_count += 1;
            }
            return retired_count;
        }

        pub fn query(self: *const Self, capability_id: u64) ?Capability {
            return (self.resolve(capability_id) orelse return null).capability.*;
        }

        pub fn inspect(self: *const Self, capability_id: u64, now_ticks: u64) ?Inspection {
            const slot = self.findConstSlot(capability_id) orelse return null;
            return .{
                .capability = &slot.capability,
                .usable = self.isUsableSlot(slot, now_ticks),
            };
        }

        pub fn resolveUsable(self: *const Self, capability_id: u64, now_ticks: u64) LookupError!ResolvedCapability {
            const resolved = self.resolve(capability_id) orelse return error.CapabilityNotFound;
            const slot = self.resolvedSlot(resolved, capability_id) orelse
                native_util.impossibleByInvariant("freshly resolved capability remains in its slot");
            if (!self.isUsableSlot(slot, now_ticks)) return error.CapabilityRevoked;
            return resolved;
        }

        pub fn requireUsable(self: *const Self, capability_id: u64, now_ticks: u64) LookupError!*const Capability {
            return (try self.resolveUsable(capability_id, now_ticks)).capability;
        }

        fn insertCapabilitySlot(
            self: *Self,
            capability_template: Capability,
            target_generation_index: u8,
            requested_slot_index: ?usize,
        ) ?InsertedCapabilitySlot {
            const reserved_handle = if (requested_slot_index) |explicit_index|
                self.slots.reserveHandleAtForOverwrite(explicit_index) orelse return null
            else
                self.slots.reserveHandleForOverwrite() orelse return null;
            const slot = self.slots.getByHandle(reserved_handle) orelse
                native_util.impossibleByInvariant("reserved capability handle is not live");
            slot.* = .{
                .in_use = true,
                .capability = capability_template,
                .target_generation_index = target_generation_index,
                .target_previous = table_capability_no_index,
                .target_next = table_capability_no_index,
            };
            slot.capability.id = reserved_handle.value;
            return .{
                .slot_index = reserved_handle.slotIndex(),
            };
        }

        fn insertWithNewCapabilityId(self: *Self, capability_template: Capability, target_generation_index: u8) Error!*const Capability {
            const inserted_slot = self.insertCapabilitySlot(capability_template, target_generation_index, null) orelse return error.TableFull;
            return self.commitInsertedSlot(inserted_slot.slot_index);
        }

        fn commitInsertedSlot(self: *Self, slot_index: usize) *const Capability {
            self.indexSlot(slot_index);
            self.advanceMutationGeneration();
            return &self.slots.slots[slot_index].capability;
        }

        fn advanceMutationGeneration(self: *Self) void {
            self.mutation_generation +%= 1;
            if (self.mutation_generation == 0) self.mutation_generation = 1;
        }

        fn findConstSlot(self: *const Self, capability_id: u64) ?*const CapabilitySlot {
            return self.slots.getConstByHandle(.{ .value = capability_id });
        }

        pub fn resolve(self: *const Self, capability_id: u64) ?ResolvedCapability {
            const handle = CapabilityHandle{ .value = capability_id };
            const slot = self.slots.getConstByHandle(handle) orelse return null;
            return .{
                .capability = &slot.capability,
                .slot_index = handle.slotIndex(),
            };
        }

        fn resolvedSlot(self: *const Self, resolved: ResolvedCapability, capability_id: u64) ?*const CapabilitySlot {
            if (resolved.slot_index >= self.slots.slots.len) return null;
            const slot = &self.slots.slots[resolved.slot_index];
            if (!slot.in_use or slot.capability.id != capability_id) return null;
            return slot;
        }

        fn isUsableSlot(self: *const Self, slot: *const CapabilitySlot, now_ticks: u64) bool {
            return slot.capability.lease.isActive(now_ticks) and
                self.targetGenerationAt(slot.target_generation_index).generation == slot.capability.revocation_generation;
        }

        fn ensureTargetGenerationIndex(self: *Self, target: CapabilityTarget) Error!u8 {
            const key = targetKey(target);
            if (self.cached_target_key == key) {
                const index = self.cached_target_generation_index;
                const entry = self.targetGenerationAt(index);
                if (!entry.in_use or !entry.target.eql(target)) {
                    native_util.impossibleByInvariant("cached target generation matches its target");
                }
                return index;
            }
            if (self.findTargetGenerationIndex(target)) |index| {
                self.cacheTargetGeneration(key, index);
                return index;
            }

            const index = self.target_generations.insertIndex(key, .{
                .target = target,
                .generation = 1,
            }) orelse return error.TargetTableFull;
            const compact_index: u8 = @intCast(index);
            self.cacheTargetGeneration(key, compact_index);
            return compact_index;
        }

        fn cacheTargetGeneration(self: *Self, key: u64, index: u8) void {
            self.cached_target_key = key;
            self.cached_target_generation_index = index;
        }

        fn targetGenerationAt(self: *const Self, target_generation_index: u8) *const TargetGeneration {
            return &self.target_generations.slots[target_generation_index];
        }

        fn targetGenerationAtMut(self: *Self, target_generation_index: u8) *TargetGeneration {
            return &self.target_generations.slots[target_generation_index];
        }

        fn reserveGrantPlan(self: *const Self, plan: *const GrantPlan) Error!TableGrantReservation {
            var reservation = TableGrantReservation{};
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
            reservation: TableGrantReservation,
            output: []Capability,
        ) void {
            var new_target_index: usize = 0;
            while (new_target_index < @as(usize, reservation.new_target_count)) : (new_target_index += 1) {
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
                const inserted_slot = self.insertCapabilitySlot(
                    granted_capability,
                    reservation.target_generation_indexes[index],
                    @as(usize, reservation.slot_indexes[index]),
                ) orelse {
                    native_util.impossibleByInvariant("grant plan slot reservations cover capability id allocation");
                };
                const granted = self.commitInsertedSlot(inserted_slot.slot_index);
                if (granted.id == 0) native_util.impossibleByInvariant("capability allocator never returns the reserved zero id");
                output[index] = granted.*;
            }
        }

        fn reserveCapabilitySlot(self: *const Self, reservation: *const TableGrantReservation, used_count: usize) Error!TableCapabilitySlotIndex {
            const slot_index = self.slots.availableIndexExcluding(
                SlotReservationContext{ .reservation = reservation, .used_count = used_count },
                reservationExcludesSlot,
            ) orelse return error.TableFull;
            return @intCast(slot_index);
        }

        fn reserveTargetGeneration(self: *const Self, target: CapabilityTarget, reservation: *TableGrantReservation) Error!u8 {
            if (self.findTargetGenerationIndex(target)) |index| return index;

            var reserved_index: usize = 0;
            while (reserved_index < @as(usize, reservation.new_target_count)) : (reserved_index += 1) {
                if (reservation.new_targets[reserved_index].eql(target)) {
                    return reservation.new_target_indexes[reserved_index];
                }
            }

            const slot_index = self.target_generations.availableIndexExcluding(
                TargetGenerationReservationContext{ .reservation = reservation },
                reservationExcludesTargetGeneration,
            ) orelse return error.TargetTableFull;
            const new_target_count: usize = reservation.new_target_count;
            if (new_target_count >= reservation.new_target_indexes.len) return error.TargetTableFull;
            const target_generation_index: u8 = @intCast(slot_index);
            reservation.new_target_indexes[new_target_count] = target_generation_index;
            reservation.new_targets[new_target_count] = target;
            reservation.new_target_count += 1;
            return target_generation_index;
        }

        fn reservationContainsSlot(reservation: *const TableGrantReservation, used_count: usize, slot_index: usize) bool {
            var index: usize = 0;
            while (index < used_count) : (index += 1) {
                if (@as(usize, reservation.slot_indexes[index]) == slot_index) return true;
            }
            return false;
        }

        fn reservationExcludesSlot(context: SlotReservationContext, slot_index: usize) bool {
            return reservationContainsSlot(context.reservation, context.used_count, slot_index);
        }

        fn reservationContainsTargetGeneration(reservation: *const TableGrantReservation, target_generation_index: u8) bool {
            var index: usize = 0;
            while (index < @as(usize, reservation.new_target_count)) : (index += 1) {
                if (reservation.new_target_indexes[index] == target_generation_index) return true;
            }
            return false;
        }

        fn reservationExcludesTargetGeneration(context: TargetGenerationReservationContext, slot_index: usize) bool {
            return reservationContainsTargetGeneration(context.reservation, @intCast(slot_index));
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

        fn discard(self: *Self, capability_id: u64) void {
            const slot_index = self.findSlotIndex(capability_id) orelse return;
            self.removeSlot(slot_index);
        }

        fn findSlotIndex(self: *const Self, capability_id: u64) ?usize {
            const handle = CapabilityHandle{ .value = capability_id };
            const slot = self.slots.getConstByHandle(handle) orelse return null;
            const slot_index = handle.slotIndex();
            if (slot.capability.id != capability_id) native_util.impossibleByInvariant("capability handle points at the wrong slot");
            return slot_index;
        }

        fn removeSlot(self: *Self, slot_index: usize) void {
            if (slot_index >= self.slots.slots.len or !self.slots.slots[slot_index].in_use) return;
            self.unlinkTarget(slot_index);
            if (self.slots.removeIndex(slot_index)) {
                self.advanceMutationGeneration();
            }
        }

        fn indexSlot(self: *Self, slot_index: usize) void {
            if (self.slots.slots[slot_index].capability.id == 0) {
                native_util.impossibleByInvariant("capability table slots never index the reserved zero capability id");
            }
            self.linkTarget(slot_index);
        }

        fn linkTarget(self: *Self, slot_index: usize) void {
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability target link starts inside capability slots");
            const slot = &self.slots.slots[slot_index];
            const target_generation = self.targetGenerationAtMut(slot.target_generation_index);
            if (!target_generation.target.eql(slot.capability.target)) {
                native_util.impossibleByInvariant("capability target generation matches its target");
            }
            if (slot.target_previous != table_capability_no_index or slot.target_next != table_capability_no_index) {
                native_util.impossibleByInvariant("new capability target link starts detached");
            }

            const compact_slot_index: TableCapabilitySlotIndex = @intCast(slot_index);
            slot.target_previous = target_generation.capability_tail;
            if (target_generation.capability_tail == table_capability_no_index) {
                if (target_generation.capability_head != table_capability_no_index or target_generation.capability_count != 0) {
                    native_util.impossibleByInvariant("empty target generation has no capability links");
                }
                target_generation.capability_head = compact_slot_index;
            } else {
                const tail_index: usize = @intCast(target_generation.capability_tail);
                if (tail_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability target tail points inside capability slots");
                const tail = &self.slots.slots[tail_index];
                if (!tail.in_use or tail.target_generation_index != slot.target_generation_index or tail.target_next != table_capability_no_index) {
                    native_util.impossibleByInvariant("capability target tail belongs to its generation");
                }
                tail.target_next = compact_slot_index;
            }
            target_generation.capability_tail = compact_slot_index;
            target_generation.capability_count += 1;
        }

        fn unlinkTarget(self: *Self, slot_index: usize) void {
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability target unlink starts inside capability slots");
            const slot = &self.slots.slots[slot_index];
            const target_generation = self.targetGenerationAtMut(slot.target_generation_index);
            const compact_slot_index: TableCapabilitySlotIndex = @intCast(slot_index);
            if (target_generation.capability_count == 0) native_util.impossibleByInvariant("live capability target generation has links");

            if (slot.target_previous == table_capability_no_index) {
                if (target_generation.capability_head != compact_slot_index) native_util.impossibleByInvariant("capability target head belongs to its generation");
                target_generation.capability_head = slot.target_next;
            } else {
                const previous_index: usize = @intCast(slot.target_previous);
                if (previous_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability target predecessor points inside capability slots");
                const previous = &self.slots.slots[previous_index];
                if (!previous.in_use or previous.target_generation_index != slot.target_generation_index or previous.target_next != compact_slot_index) {
                    native_util.impossibleByInvariant("capability target predecessor points at its successor");
                }
                previous.target_next = slot.target_next;
            }

            if (slot.target_next == table_capability_no_index) {
                if (target_generation.capability_tail != compact_slot_index) native_util.impossibleByInvariant("capability target tail belongs to its generation");
                target_generation.capability_tail = slot.target_previous;
            } else {
                const next_index: usize = @intCast(slot.target_next);
                if (next_index >= self.slots.slots.len) native_util.impossibleByInvariant("capability target successor points inside capability slots");
                const next = &self.slots.slots[next_index];
                if (!next.in_use or next.target_generation_index != slot.target_generation_index or next.target_previous != compact_slot_index) {
                    native_util.impossibleByInvariant("capability target successor points at its predecessor");
                }
                next.target_previous = slot.target_previous;
            }

            slot.target_previous = table_capability_no_index;
            slot.target_next = table_capability_no_index;
            target_generation.capability_count -= 1;
            if (target_generation.capability_count == 0 and
                (target_generation.capability_head != table_capability_no_index or target_generation.capability_tail != table_capability_no_index))
            {
                native_util.impossibleByInvariant("empty target generation has no capability links");
            }
        }

        fn debugIndexChecksEnabledForTable() bool {
            return config.debug_index_checks and debugIndexChecksEnabled();
        }
    };
}

fn targetKey(target: CapabilityTarget) u64 {
    return nonZeroKey((@as(u64, @intFromEnum(target.kind)) << 56) ^ target.id);
}

fn nonZeroKey(key: u64) u64 {
    return if (key == 0) 0xD1B5_4A32_D192_ED03 else key;
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

test "capability grant metadata retains full atomic plan capacity" {
    try std.testing.expect(@FieldType(GrantPlan, "entry_count") == u8);
    try std.testing.expect(@FieldType(GrantReservation, "slot_indexes") == [MAX_GRANT_PLAN_ENTRIES]CapabilitySlotIndex);
    try std.testing.expect(@FieldType(GrantReservation, "new_target_count") == u8);
    try std.testing.expectEqual(@as(usize, GRANT_RESERVATION_SIZE_CEILING_BYTES), @sizeOf(GrantReservation));

    var plan = GrantPlan{};
    const request = emptyGrantPlanEntry().request;
    for (0..MAX_GRANT_PLAN_ENTRIES) |index| {
        try plan.addMint(index, request);
    }
    try std.testing.expectEqual(@as(u8, @intCast(MAX_GRANT_PLAN_ENTRIES)), plan.entry_count);
    try std.testing.expectEqual(@as(usize, MAX_GRANT_PLAN_ENTRIES), plan.slice().len);
    try std.testing.expectError(error.GrantPlanFull, plan.addMint(MAX_GRANT_PLAN_ENTRIES, request));

    var table = CapabilityTable.init();
    var output: [MAX_GRANT_PLAN_ENTRIES]Capability = undefined;
    const granted = try table.applyGrantPlan(&plan, &output);
    try std.testing.expectEqual(@as(usize, MAX_GRANT_PLAN_ENTRIES), granted.len);
    try std.testing.expectEqual(@as(usize, MAX_GRANT_PLAN_ENTRIES), table.activeCount());
}

test "capability table omits redundant holder index state" {
    try std.testing.expect(!@hasField(CapabilityTable, "holder_index"));
    try std.testing.expect(!@hasDecl(CapabilityTable, "queryByHolder"));
    try std.testing.expectEqual(CAPABILITY_TABLE_SIZE_CEILING_BYTES, @sizeOf(CapabilityTable));
}

test "allocated capability table initialization preserves empty table invariants" {
    var table: CapabilityTable = undefined;
    table.initializeAllocated();

    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    try std.testing.expectEqual(@as(u64, 1), table.mutationGeneration());
    const minted = try table.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 1 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 1 },
        .rights = fullSessionRights(),
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    try std.testing.expectEqual(minted.id, table.query(minted.id).?.id);
    var matches: [1]Capability = undefined;
    try std.testing.expectEqual(minted.id, table.queryByTarget(minted.target, &matches)[0].id);
    try table.revokeGrant(minted.id);
    try std.testing.expect(table.query(minted.id) == null);
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
    try std.testing.expect(std.meta.eql(derived, stored_derived.*));

    try table.revokeGrant(parent.id);
    try std.testing.expect(table.query(parent.id) == null);
    try std.testing.expectError(error.CapabilityNotFound, table.requireUsable(parent.id, 10));
    _ = try table.requireUsable(derived.id, 10);
}

test "task authority retirement removes bound and targeting grants but preserves transfers" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const source_holder = principal.PrincipalId{ .kind = .app, .serial = 100 };
    const receiver_holder = principal.PrincipalId{ .kind = .app, .serial = 200 };

    const parent = try table.mintBootRoot(.{
        .holder = source_holder,
        .issuer = policy,
        .target = .{ .kind = .service, .id = 50 },
        .rights = .{ .service = .{
            .capability_derive = true,
            .capability_pass = true,
            .capability_query = true,
        } },
        .scope = .{ .task_id = 100, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const derived = try table.derive(.{
        .parent_capability_id = parent.id,
        .holder = source_holder,
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{ .task_id = 100, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 90 },
    });
    const transferred = try table.pass(.{
        .capability_id = parent.id,
        .new_holder = receiver_holder,
        .now_ticks = 2,
        .allow_task_retarget = true,
        .scope = .{ .task_id = 200, .local_only = true },
    });
    const unscoped = try table.mintBootRoot(.{
        .holder = source_holder,
        .issuer = policy,
        .target = .{ .kind = .object, .id = 60 },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const targeting_task = try table.mintBootRoot(.{
        .holder = receiver_holder,
        .issuer = policy,
        .target = .{ .kind = .task, .id = 100 },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = 200, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const unrelated = try table.mintBootRoot(.{
        .holder = receiver_holder,
        .issuer = policy,
        .target = .{ .kind = .task, .id = 101 },
        .rights = .{ .task = .{ .task_terminate = true } },
        .scope = .{ .task_id = 200, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });

    const mutation_generation = table.mutationGeneration();
    try std.testing.expectEqual(@as(usize, 0), table.retireTaskAuthority(0, &.{parent.id}));
    try std.testing.expectEqual(mutation_generation, table.mutationGeneration());
    try std.testing.expectEqual(@as(usize, 3), table.retireTaskAuthority(100, &.{ 0, parent.id, derived.id, unscoped.id, std.math.maxInt(u64) }));
    try std.testing.expect(table.query(parent.id) == null);
    try std.testing.expect(table.query(derived.id) == null);
    try std.testing.expect(table.query(targeting_task.id) == null);
    try std.testing.expect(table.query(transferred.id) != null);
    _ = try table.requireUsable(transferred.id, 10);
    try std.testing.expect(table.query(unscoped.id) != null);
    try std.testing.expect(table.query(unrelated.id) != null);
    try std.testing.expectEqual(@as(usize, 3), table.activeCount());

    var target_buffer: [2]Capability = undefined;
    try std.testing.expectEqual(@as(usize, 0), table.queryByTarget(.{ .kind = .task, .id = 100 }, &target_buffer).len);
    try std.testing.expectEqual(@as(usize, 1), table.queryByTarget(.{ .kind = .task, .id = 101 }, &target_buffer).len);
}

test "dead target retirement removes every matching grant without scanning unrelated authority" {
    var table = CapabilityTable.init();
    const policy = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const endpoint_target = CapabilityTarget{ .kind = .endpoint, .id = 123 };
    const shared_target = CapabilityTarget{ .kind = .shared_memory, .id = 456 };

    const endpoint_owner = try table.mintBootRoot(.{
        .holder = .{ .kind = .app, .serial = 10 },
        .issuer = policy,
        .target = endpoint_target,
        .rights = .{ .endpoint = .{ .endpoint_connect = true, .endpoint_send = true } },
        .scope = .{ .task_id = 10 },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const endpoint_peer = try table.mintBootRoot(.{
        .holder = .{ .kind = .app, .serial = 11 },
        .issuer = policy,
        .target = endpoint_target,
        .rights = .{ .endpoint = .{ .ipc_peer = true } },
        .scope = .{ .task_id = 11 },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const shared_owner = try table.mintBootRoot(.{
        .holder = .{ .kind = .app, .serial = 12 },
        .issuer = policy,
        .target = shared_target,
        .rights = .{ .shared_memory = .{ .shared_memory_map = true, .shared_memory_revoke = true } },
        .scope = .{ .task_id = 12 },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });
    const unrelated = try table.mintBootRoot(.{
        .holder = .{ .kind = .app, .serial = 13 },
        .issuer = policy,
        .target = .{ .kind = .endpoint, .id = 124 },
        .rights = .{ .endpoint = .{ .endpoint_recv = true } },
        .scope = .{ .task_id = 13 },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    });

    var retired_endpoint_authority: [2]RetiredAuthority = undefined;
    try std.testing.expectEqual(@as(usize, 2), table.retireTargetAuthorityInto(endpoint_target, &retired_endpoint_authority));
    try std.testing.expect(retired_endpoint_authority[0].capability_id == endpoint_owner.id or retired_endpoint_authority[1].capability_id == endpoint_owner.id);
    try std.testing.expect(retired_endpoint_authority[0].capability_id == endpoint_peer.id or retired_endpoint_authority[1].capability_id == endpoint_peer.id);
    try std.testing.expect(retired_endpoint_authority[0].scoped_task_id != null);
    try std.testing.expect(retired_endpoint_authority[1].scoped_task_id != null);
    try std.testing.expect(table.query(endpoint_owner.id) == null);
    try std.testing.expect(table.query(endpoint_peer.id) == null);
    try std.testing.expect(table.query(shared_owner.id) != null);
    try std.testing.expect(table.query(unrelated.id) != null);
    try std.testing.expectEqual(@as(usize, 0), table.retireTargetAuthority(endpoint_target));

    try std.testing.expectEqual(@as(usize, 1), table.retireTargetAuthority(shared_target));
    try std.testing.expect(table.query(shared_owner.id) == null);
    try std.testing.expect(table.query(unrelated.id) != null);
    try std.testing.expectEqual(@as(usize, 1), table.activeCount());
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
        .target_generation_index_capacity = 2,
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

test "capability ids encode slot generations and reject stale reuse" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 1,
        .target_generation_index_capacity = 2,
        .max_target_generations = 1,
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
    const slot_index = table.findSlotIndex(first.id).?;
    const resolved_first = table.resolve(first.id).?;
    try std.testing.expectEqual(@as(u32, 1), @as(u32, @intCast(first.id >> 32)));
    try std.testing.expect(table.query(0) == null);

    try table.revokeGrant(first.id);
    const replacement = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(slot_index, table.findSlotIndex(replacement.id).?);
    try std.testing.expect(first.id != replacement.id);
    try std.testing.expect(table.query(first.id) == null);
    try std.testing.expect(table.query(replacement.id) != null);
    try std.testing.expectError(error.CapabilityNotFound, table.revokeTargetAuthorityResolved(first.id, resolved_first));
    try std.testing.expect(table.query(replacement.id) != null);

    try table.revokeGrant(replacement.id);
    table.slots.slot_generations[slot_index] = std.math.maxInt(u32);
    const last_generation = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(std.math.maxInt(u32), @as(u32, @intCast(last_generation.id >> 32)));
    try table.revokeGrant(last_generation.id);
    const wrapped = try table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    try std.testing.expectEqual(@as(u32, 1), @as(u32, @intCast(wrapped.id >> 32)));
    try std.testing.expect(table.query(last_generation.id) == null);
}

test "capability allocation leaves a full table unchanged" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 1,
        .target_generation_index_capacity = 2,
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

    const count_before_full = table.activeCount();
    const mutation_generation_before_full = table.mutationGeneration();
    try std.testing.expectError(error.TableFull, table.mintBootRoot(.{
        .holder = holder,
        .issuer = holder,
        .target = .{ .kind = .service, .id = 1 },
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    }));
    try std.testing.expectEqual(count_before_full, table.activeCount());
    try std.testing.expectEqual(mutation_generation_before_full, table.mutationGeneration());
}

test "derived capability views are copied before revoked slots are reused" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 3,
        .target_generation_index_capacity = 8,
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
    const derived = try table.derive(.{
        .parent_capability_id = first.id,
        .holder = derived_holder,
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    });
    const derived_slot_index = table.findSlotIndex(derived.id).?;

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
    try std.testing.expect(table.findSlotIndex(derived.id) == null);
    try std.testing.expectEqual(derived_slot_index, table.findSlotIndex(reused.id).?);
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

test "target generation chains preserve middle removal and free-slot reuse" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 4,
        .target_generation_index_capacity = 8,
        .max_target_generations = 2,
    });
    var table = SmallTable.init();
    const holder = principal.PrincipalId{ .kind = .service, .serial = 1 };
    const target = CapabilityTarget{ .kind = .service, .id = 77 };
    const request = MintRequest{
        .holder = holder,
        .issuer = holder,
        .target = target,
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = .{},
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 10 },
    };

    const first = try table.mintBootRoot(request);
    const middle = try table.mintBootRoot(request);
    const last = try table.mintBootRoot(request);
    const middle_slot_index = table.findSlotIndex(middle.id).?;
    var matches: [4]Capability = undefined;
    var found = table.queryByTarget(target, &matches);
    try std.testing.expectEqual(@as(usize, 3), found.len);
    try std.testing.expectEqual(first.id, found[0].id);
    try std.testing.expectEqual(middle.id, found[1].id);
    try std.testing.expectEqual(last.id, found[2].id);

    try table.revokeGrant(middle.id);
    found = table.queryByTarget(target, &matches);
    try std.testing.expectEqual(@as(usize, 2), found.len);
    try std.testing.expectEqual(first.id, found[0].id);
    try std.testing.expectEqual(last.id, found[1].id);

    const replacement = try table.mintBootRoot(request);
    try std.testing.expectEqual(middle_slot_index, table.findSlotIndex(replacement.id).?);
    found = table.queryByTarget(target, &matches);
    try std.testing.expectEqual(@as(usize, 3), found.len);
    try std.testing.expectEqual(first.id, found[0].id);
    try std.testing.expectEqual(last.id, found[1].id);
    try std.testing.expectEqual(replacement.id, found[2].id);

    try table.revokeGrant(first.id);
    try table.revokeGrant(replacement.id);
    found = table.queryByTarget(target, &matches);
    try std.testing.expectEqual(@as(usize, 1), found.len);
    try std.testing.expectEqual(last.id, found[0].id);
    try std.testing.expectEqual(@as(usize, 1), table.retireTargetAuthority(target));
    try std.testing.expectEqual(@as(usize, 0), table.queryByTarget(target, &matches).len);
}

test "grant plan reserves target generation slots in the arena" {
    const SmallTable = CapabilityTableWith(.{
        .max_capabilities = 4,
        .target_generation_index_capacity = 8,
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

    const retired_ids = [_]u64{ output[0].id, output[1].id };
    table.rollbackGrant(&output);
    try std.testing.expectEqual(@as(usize, 0), table.activeCount());
    try std.testing.expect(table.query(retired_ids[0]) == null);
    try std.testing.expect(table.query(retired_ids[1]) == null);

    var replacements: [2]Capability = undefined;
    _ = try table.applyGrantPlan(&plan, &replacements);
    try std.testing.expectEqual(@as(usize, 2), table.activeCount());
    try std.testing.expect(retired_ids[0] != replacements[0].id);
    try std.testing.expect(retired_ids[1] != replacements[1].id);
    try std.testing.expect(table.query(replacements[0].id) != null);
    try std.testing.expect(table.query(replacements[1].id) != null);
}
