// Isolated CPL0 proof of real shared-RAM ownership and user page tables. Fault
// resolution, supervisor copy helpers and endpoint handlers are invoked directly;
// native user fault and syscall trap admission require separate evidence.
const probe = @import("high_half_probe.zig");
const x86 = @import("../x86.zig");
const paging = @import("../../kernel/memory/paging64.zig");
const page_table = @import("../../kernel/memory/page_table64.zig");
const demand = @import("../../kernel/memory/demand_paging.zig");
const shared = @import("../../native/kernel_api/shared_memory.zig");
const executor = @import("../../native/task/userspace_executor.zig");
const ids = @import("../../native/core/ids.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");

const PAGE_BYTES = shared.PAGE_SIZE;
const SHARED_WORD: u64 = 0x7165_7275_6f2d_6465;
const PRIVATE_WORD: u64 = 0x6574_6176_6972_702d;
const SNAPSHOT_ADDRESS: usize = 0x6000_0000;
const COPY_BYTES = 32;
const BATCH_ADDRESS: usize = 0x6100_0000;
const BATCH_PAGES = 5;
const BATCH_CANARY: u8 = 0x6a;

const WriteBatchObservation = struct {
    space: ?*const paging.UserAddressSpace = null,
    writable_mask: u8 = 0,
    barriers: usize = 0,
};

var write_batch_observation: WriteBatchObservation = .{};

const Mapping = struct {
    descriptor: ?shared.FreestandingMappingDescriptor = null,
    retired: bool = false,
};

const Lifetime = struct {
    spaces: [3]paging.UserAddressSpace,
    mappings: [2]Mapping = @splat(.{}),
    expected_allocated: u32 = 0,
    retired_count: u8 = 0,

    fn register(raw: *anyopaque, table: *shared.Table, descriptor: shared.FreestandingMappingDescriptor, writable: bool, copy_on_write: bool) ?u64 {
        const self: *Lifetime = @ptrCast(@alignCast(raw));
        // Membership sealing preserves writable shared RAM, including rings.
        if (!writable or copy_on_write or descriptor.target != null or
            descriptor.page_count != 2 or descriptor.size_bytes != PAGE_BYTES + 37 or
            (table.objectSize(descriptor.object_id) catch return null) != descriptor.size_bytes) return null;
        const index = taskIndex(descriptor.task_id) orelse return null;
        const mapping = &self.mappings[index];
        if (mapping.descriptor != null or leaf(&self.spaces[index], @intCast(descriptor.virtual_base)) != null) return null;
        if (!demand.registerForSpace(&self.spaces[index], .{
            .virt_start = descriptor.virtual_base,
            .virt_end_exclusive = descriptor.virtual_base + descriptor.size_bytes,
            .writable = writable,
            .kind = .shared_ram,
            .physical_base = descriptor.physical_base,
        })) return null;
        mapping.descriptor = descriptor;
        return index + 1;
    }

    fn unregister(raw: *anyopaque, table: *shared.Table, token: u64, descriptor: shared.FreestandingMappingDescriptor) bool {
        const self: *Lifetime = @ptrCast(@alignCast(raw));
        const index = taskIndex(descriptor.task_id) orelse return false;
        const mapping = &self.mappings[index];
        const original = mapping.descriptor orelse return false;
        if (token != index + 1 or mapping.retired or
            original.virtual_base != descriptor.virtual_base or original.physical_base != descriptor.physical_base or
            !original.object_id.eql(descriptor.object_id) or original.size_bytes != descriptor.size_bytes or
            (table.objectSize(descriptor.object_id) catch return false) != descriptor.size_bytes) return false;
        // Both backing pages must still be owned while either alias retires.
        if (paging.frameStats().allocated != self.expected_allocated) probe.fail("shared early release");
        const end = descriptor.virtual_base + descriptor.size_bytes;
        if (!demand.unregisterRegionForSpace(&self.spaces[index], descriptor.virtual_base, end) or
            demand.regionOverlapsSpace(&self.spaces[index], descriptor.virtual_base, end)) return false;
        for (0..descriptor.page_count) |page| {
            if (leaf(&self.spaces[index], @intCast(descriptor.virtual_base + page * PAGE_BYTES)) != null) return false;
        }
        if (demand.resolveFault(&self.spaces[index], descriptor.virtual_base, 0x6) or
            paging.frameStats().allocated != self.expected_allocated) probe.fail("shared borrowed retirement");
        mapping.retired = true;
        self.retired_count += 1;
        return true;
    }
};

pub fn run() void {
    const kernel_cr3 = x86.readCr3();
    if (x86.readMsr(0x277) & 0xff != 6) probe.fail("shared write-back PAT");
    const baseline = paging.frameStats().allocated;
    var lifetime: Lifetime = .{ .spaces = undefined };
    var table = shared.Table.initWithMappingLifetime(.{
        .context = &lifetime,
        .register = Lifetime.register,
        .unregister = Lifetime.unregister,
    });
    const object = table.createWithAccess(ids.task(1), PAGE_BYTES + 37, .{ .ring = true }) catch probe.fail("shared owned allocation");
    const other = table.create(ids.task(3), PAGE_BYTES - 17) catch probe.fail("shared second allocation");
    if (object.page_count != 2 or other.page_count != 1 or object.page_base % PAGE_BYTES != 0 or
        other.page_base % PAGE_BYTES != 0 or overlaps(object, other) or
        paging.frameStats().allocated != baseline + 3) probe.fail("shared frame accounting");
    expectZero(object);
    expectZero(other);
    fill(object, 0x93);
    fill(other, 0x6d);
    expectFilled(object, 0x93);
    expectFilled(other, 0x6d);

    for (&lifetime.spaces) |*space| space.* = paging.createUserAddressSpace() catch probe.fail("shared user root");
    table.map(object.id, ids.task(1)) catch probe.fail("shared owner registration");
    table.map(object.id, ids.task(2)) catch probe.fail("shared peer registration");
    // Sealing closes membership and retains both registered writable aliases.
    table.seal(object.id) catch probe.fail("shared membership seal");
    if (table.map(object.id, ids.task(4))) |_| {
        probe.fail("sealed shared membership");
    } else |err| if (err != error.ObjectSealed) probe.fail("sealed shared error");

    proveCheckedCopies(&table, &lifetime, object, other);
    for (&lifetime.mappings, 0..) |*mapping, index| {
        const descriptor = mapping.descriptor orelse probe.fail("shared registration token");
        for (0..descriptor.page_count) |page| {
            const virtual = descriptor.virtual_base + page * PAGE_BYTES;
            if (leaf(&lifetime.spaces[index], @intCast(virtual)) == null and
                !demand.resolveFault(&lifetime.spaces[index], virtual, 0x6)) probe.fail("shared demand materialization");
            const entry = leaf(&lifetime.spaces[index], @intCast(virtual)) orelse probe.fail("shared materialized leaf");
            expectRamLeaf(entry, true);
            if (page_table.address(entry) != descriptor.physical_base + page * PAGE_BYTES or
                paging.ownedUserPagePermissions(&lifetime.spaces[index], @intCast(virtual)) != null) probe.fail("shared borrowed ownership");
        }
    }
    const owner_virtual: usize = @intCast(lifetime.mappings[0].descriptor.?.virtual_base);
    const peer_virtual: usize = @intCast(lifetime.mappings[1].descriptor.?.virtual_base);
    writeUserWord(&lifetime.spaces[0], owner_virtual, SHARED_WORD);
    if (readUserWord(&lifetime.spaces[1], peer_virtual) != SHARED_WORD or
        physicalWord(object.page_base).* != SHARED_WORD) probe.fail("shared writable coherence");

    // The actual private-page snapshot primitive copies the full source page.
    // Its lifetime belongs to this root, independently of the shared object.
    paging.mapOwnedUserPageFromPhysical(&lifetime.spaces[2], SNAPSHOT_ADDRESS, object.page_base, .{ .writable = false }) catch
        probe.fail("shared private snapshot");
    const snapshot = leaf(&lifetime.spaces[2], SNAPSHOT_ADDRESS) orelse probe.fail("snapshot leaf");
    expectRamLeaf(snapshot, false);
    const snapshot_physical = page_table.address(snapshot);
    if (containsPhysical(object, snapshot_physical) or containsPhysical(other, snapshot_physical) or
        paging.ownedUserPagePermissions(&lifetime.spaces[2], SNAPSHOT_ADDRESS) == null) probe.fail("snapshot ownership");
    const snapshot_bytes = physicalBytes(snapshot_physical);
    const source_bytes = physicalBytes(object.page_base);
    for (0..PAGE_BYTES) |byte| if (snapshot_bytes[byte] != source_bytes[byte]) probe.fail("snapshot full copy");
    if (!(paging.promoteOwnedUserPageForWrite(&lifetime.spaces[2], SNAPSHOT_ADDRESS) catch probe.fail("snapshot write promotion")))
        probe.fail("snapshot write transition");
    expectRamLeaf(leaf(&lifetime.spaces[2], SNAPSHOT_ADDRESS).?, true);
    writeUserWord(&lifetime.spaces[2], SNAPSHOT_ADDRESS, PRIVATE_WORD);
    if (readUserWord(&lifetime.spaces[2], SNAPSHOT_ADDRESS) != PRIVATE_WORD or
        physicalWord(object.page_base).* != SHARED_WORD) probe.fail("snapshot write isolation");

    lifetime.expected_allocated = paging.frameStats().allocated;
    _ = table.revoke(object.id) catch probe.fail("shared revoke");
    if (lifetime.retired_count != 2 or table.hasMapping(object.id, ids.task(1)) or table.hasMapping(object.id, ids.task(2)) or
        paging.frameStats().allocated != lifetime.expected_allocated - 2) probe.fail("shared backing release");
    proveRetiredCopyRejection(&table, &lifetime);
    if (readUserWord(&lifetime.spaces[2], SNAPSHOT_ADDRESS) != PRIVATE_WORD or
        snapshot_bytes[PAGE_BYTES - 1] != 0x93) probe.fail("snapshot independent lifetime");
    const before_second_revoke = paging.frameStats().allocated;
    _ = table.revoke(other.id) catch probe.fail("shared second revoke");
    if (paging.frameStats().allocated != before_second_revoke - 1) probe.fail("shared second release");

    const before_root_retirement = paging.frameStats().allocated;
    for (&lifetime.spaces) |*space| {
        demand.unregisterSpace(space);
        paging.destroyUserAddressSpace(space) catch probe.fail("shared root retirement");
    }
    // Three PML4s, three private intermediate tables each, and one snapshot.
    if (paging.frameStats().allocated != before_root_retirement - 13) probe.fail("shared private frame release");

    const before_fresh = paging.frameStats().allocated;
    const fresh = table.create(ids.task(1), PAGE_BYTES + 37) catch probe.fail("shared fresh allocation");
    if (fresh.id.eql(object.id) or fresh.page_count != 2 or paging.frameStats().allocated != before_fresh + 2)
        probe.fail("shared fresh ownership");
    // Allocation cursors need not immediately choose the previous run. Hosted
    // allocator fixtures cover deterministic reuse; the guest checks ownership
    // and zero publication after returning dirty backing to the real allocator.
    expectZero(fresh);
    _ = table.revoke(fresh.id) catch probe.fail("shared fresh release");
    if (paging.frameStats().allocated != before_fresh or table.activeCount() != 0) probe.fail("shared final accounting");
    table.deinit();
    if (!executor.proveSharedSyscallCopyPath()) probe.fail("shared executor copies and endpoint delivery");
    provePrivateWriteBatch();
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    if (!x86.supervisorAccessPreventionEnabled() or x86.readCr3() != kernel_cr3 or
        flags & ((1 << 18) | (1 << 9)) != 0) probe.fail("shared control continuation");
    probe.pass("SHARED_FRAMES");
}

// Before AP startup, observe the actual pager's synchronous remote callback.
// The resident root exercises the local CR3 barrier on this guest. The callback
// observes publication and counts barriers; it performs no AP shootdown and
// supplies no evidence of an executed PCID/INVPCID instruction path.
fn observeWriteBatchBarrier(identifier: u16) void {
    const space = write_batch_observation.space orelse return;
    requireCopyOwner();
    if (identifier != space.pcid or paging.getCurrentPageDirectory() != space.directory or
        write_batch_observation.barriers != 0) probe.fail("private batch barrier identity or count");
    for (0..BATCH_PAGES) |page| {
        const entry = leaf(space, BATCH_ADDRESS + page * PAGE_BYTES) orelse probe.fail("private batch observed leaf");
        expectRamLeaf(entry, write_batch_observation.writable_mask & (@as(u8, 1) << @intCast(page)) != 0);
        const bytes = physicalBytes(page_table.address(entry));
        for (0..PAGE_BYTES) |byte| if (bytes[byte] != BATCH_CANARY) probe.fail("private batch payload before barrier");
    }
    write_batch_observation.barriers += 1;
}

fn beginWriteBatchObservation(space: *const paging.UserAddressSpace, writable_mask: u8) void {
    write_batch_observation = .{ .space = space, .writable_mask = writable_mask };
}

fn endWriteBatchObservation(expected_barriers: usize) void {
    if (write_batch_observation.barriers != expected_barriers) probe.fail("private batch exact barrier count");
    write_batch_observation.space = null;
}

fn provePrivateWriteBatch() void {
    requireCopyOwner();
    paging.drainFrameCachesForArchitectureProof();
    const baseline = paging.frameStats().allocated;
    const kernel_cr3 = x86.readCr3();
    var space = paging.createUserAddressSpace() catch probe.fail("private batch user root");
    paging.mapOwnedUserRange(&space, BATCH_ADDRESS, BATCH_PAGES * PAGE_BYTES, .{ .writable = false }) catch
        probe.fail("private batch owned pages");
    for ([_]usize{ 0, 3 }) |first_page| {
        const start = BATCH_ADDRESS + first_page * PAGE_BYTES;
        if (!demand.registerForSpace(&space, .{
            .virt_start = start,
            .virt_end_exclusive = start + 2 * PAGE_BYTES,
            .kind = .object_cow,
        })) probe.fail("private batch COW registration");
    }
    for (0..BATCH_PAGES) |page| {
        const entry = leaf(&space, BATCH_ADDRESS + page * PAGE_BYTES) orelse probe.fail("private batch initial leaf");
        expectRamLeaf(entry, false);
        const bytes = physicalBytes(page_table.address(entry));
        for (0..PAGE_BYTES) |byte| bytes[byte] = BATCH_CANARY;
    }
    paging.setRemotePcidShootdown(observeWriteBatchBarrier);
    paging.switchToUserAddressSpace(&space);
    // Warm the hardware translations without leaving the resident root.
    x86.allowSupervisorUserMemory();
    for (0..BATCH_PAGES) |page| {
        if (@as(*volatile u64, @ptrFromInt(BATCH_ADDRESS + page * PAGE_BYTES)).* != 0x6a6a_6a6a_6a6a_6a6a)
            probe.fail("private batch initial payload");
    }
    x86.forbidSupervisorUserMemory();
    beginWriteBatchObservation(&space, 0b11000);
    if (!demand.prepareUserRange(&space, BATCH_ADDRESS + 3 * PAGE_BYTES, 2 * PAGE_BYTES, true))
        probe.fail("private batch complete preparation");
    endWriteBatchObservation(1);
    // A real hardware store succeeds only after the completed barrier. Restore
    // its canary before observing the subsequent rejected preparation.
    x86.allowSupervisorUserMemory();
    @as(*volatile u64, @ptrFromInt(BATCH_ADDRESS + 3 * PAGE_BYTES)).* = PRIVATE_WORD;
    if (@as(*volatile u64, @ptrFromInt(BATCH_ADDRESS + 3 * PAGE_BYTES)).* != PRIVATE_WORD)
        probe.fail("private batch hardware write");
    @as(*volatile u64, @ptrFromInt(BATCH_ADDRESS + 3 * PAGE_BYTES)).* = 0x6a6a_6a6a_6a6a_6a6a;
    x86.forbidSupervisorUserMemory();

    // The third page has no COW registration. The first two promotions still
    // complete their single barrier before failure returns to the copy caller.
    beginWriteBatchObservation(&space, 0b11011);
    if (demand.prepareUserRange(&space, BATCH_ADDRESS, 3 * PAGE_BYTES, true))
        probe.fail("private batch late rejection");
    endWriteBatchObservation(1);
    beginWriteBatchObservation(&space, 0b11011);
    if (!demand.prepareUserRange(&space, BATCH_ADDRESS, 2 * PAGE_BYTES, true))
        probe.fail("private batch unchanged preparation");
    endWriteBatchObservation(0);

    // The single-page hardware-fault primitive retains its immediate barrier.
    beginWriteBatchObservation(&space, 0b11111);
    if (!(paging.promoteOwnedUserPageForWrite(&space, BATCH_ADDRESS + 2 * PAGE_BYTES) catch
        probe.fail("private immediate promotion"))) probe.fail("private immediate transition");
    endWriteBatchObservation(1);
    beginWriteBatchObservation(&space, 0b11111);
    if (paging.promoteOwnedUserPageForWrite(&space, BATCH_ADDRESS + 2 * PAGE_BYTES) catch
        probe.fail("private repeated promotion")) probe.fail("private repeated transition");
    endWriteBatchObservation(0);
    paging.switchToKernelAddressSpace();
    demand.unregisterSpace(&space);
    paging.destroyUserAddressSpace(&space) catch probe.fail("private batch root retirement");
    paging.drainFrameCachesForArchitectureProof();
    if (paging.frameStats().allocated != baseline or x86.readCr3() != kernel_cr3)
        probe.fail("private batch final accounting");
}

fn requireCopyOwner() void {
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    if (cpu_identity.currentIndex() != 0 or flags & ((1 << 18) | (1 << 9)) != 0)
        probe.fail("shared copy owner controls");
}

fn copyAuthority(table: *const shared.Table, task: ids.TaskId, token: u64, address: usize, bytes: usize) ?demand.SharedCopyAuthority {
    requireCopyOwner();
    var span: shared.TaskCopySpan = undefined;
    table.taskCopySpanInto(task, token, address, bytes, &span) catch return null;
    return .{ .virtual_base = span.virtual_base, .physical_base = span.physical_base, .size_bytes = span.size_bytes };
}

// Consume each live Table admission immediately under BSP/IF=0 ownership.
// Copies use the checked supervisor alias and never open SMAP user access.
fn checkedRead(table: *const shared.Table, space: *paging.UserAddressSpace, task: ids.TaskId, token: u64, address: usize, destination: []u8) bool {
    const authority = copyAuthority(table, task, token, address, destination.len) orelse return false;
    const alias = demand.prepareSharedUserRange(space, authority, address, destination.len, false, 0) orelse return false;
    @memcpy(destination, @as([*]const u8, @ptrFromInt(alias))[0..destination.len]);
    return true;
}

fn checkedWrite(table: *const shared.Table, space: *paging.UserAddressSpace, task: ids.TaskId, token: u64, address: usize, source: []const u8) bool {
    const authority = copyAuthority(table, task, token, address, source.len) orelse return false;
    const alias = demand.prepareSharedUserRange(space, authority, address, source.len, true, 0) orelse return false;
    @memcpy(@as([*]u8, @ptrFromInt(alias))[0..source.len], source);
    return true;
}

fn rejectCopy(table: *const shared.Table, space: *paging.UserAddressSpace, task: ids.TaskId, token: u64, address: usize) void {
    var destination: [COPY_BYTES]u8 = @splat(0xa5);
    const source: [COPY_BYTES]u8 = @splat(0x47);
    if (checkedRead(table, space, task, token, address, &destination) or
        checkedWrite(table, space, task, token, address, &source)) probe.fail("shared rejected copy admitted");
    for (destination) |byte| if (byte != 0xa5) probe.fail("shared rejected copy destination");
}

fn proveCheckedCopies(table: *const shared.Table, lifetime: *Lifetime, object: shared.Object, other: shared.Object) void {
    requireCopyOwner();
    const kernel_cr3 = x86.readCr3();
    const owner = lifetime.mappings[0].descriptor.?;
    const peer = lifetime.mappings[1].descriptor.?;
    const owner_base: usize = @intCast(owner.virtual_base);
    const peer_base: usize = @intCast(peer.virtual_base);
    const owner_cross = owner_base + PAGE_BYTES - COPY_BYTES / 2;
    const peer_cross = peer_base + PAGE_BYTES - COPY_BYTES / 2;
    const before = paging.frameStats().allocated;
    for (lifetime.spaces[0..2], [_]usize{ owner_base, peer_base }) |*space, base| {
        if (leaf(space, base) != null or leaf(space, base + PAGE_BYTES) != null) probe.fail("shared copy initially present");
    }
    const authority = copyAuthority(table, ids.task(1), 1, owner_base, object.size_bytes) orelse probe.fail("shared whole logical authority");
    if (authority.virtual_base != owner.virtual_base or authority.physical_base != object.page_base or authority.size_bytes != object.size_bytes or
        !demand.validateSharedUserRangeRegistration(&lifetime.spaces[0], authority, owner_base, object.size_bytes, true, 0) or
        demand.validateSharedUserRangeRegistration(&lifetime.spaces[0], authority, owner_base, object.size_bytes + 1, true, 0) or
        demand.validateSharedUserRangeRegistration(&lifetime.spaces[0], authority, owner_cross, COPY_BYTES, true, 1))
        probe.fail("shared exact registration authority");
    rejectCopy(table, &lifetime.spaces[0], ids.task(2), 1, owner_cross);
    rejectCopy(table, &lifetime.spaces[0], ids.task(3), 1, owner_cross);
    rejectCopy(table, &lifetime.spaces[0], ids.task(1), 0, owner_cross);
    rejectCopy(table, &lifetime.spaces[0], ids.task(1), 2, owner_cross);
    rejectCopy(table, &lifetime.spaces[0], ids.task(1), 1, owner_base + object.size_bytes - COPY_BYTES + 1);
    if (paging.frameStats().allocated != before or leaf(&lifetime.spaces[0], owner_base) != null or
        leaf(&lifetime.spaces[0], owner_base + PAGE_BYTES) != null) probe.fail("shared rejected copy publication");
    expectFilled(object, 0x93);
    expectFilled(other, 0x6d);

    var destination: [COPY_BYTES]u8 = @splat(0xa5);
    if (!checkedRead(table, &lifetime.spaces[0], ids.task(1), 1, owner_cross, &destination)) probe.fail("shared cross-page read");
    for (destination) |byte| if (byte != 0x93) probe.fail("shared cross-page read bytes");
    for (0..2) |page| {
        const entry = leaf(&lifetime.spaces[0], owner_base + page * PAGE_BYTES) orelse probe.fail("shared copy materialization");
        expectRamLeaf(entry, true);
        if (page_table.address(entry) != object.page_base + page * PAGE_BYTES) probe.fail("shared copy backing identity");
    }
    var source: [COPY_BYTES]u8 = undefined;
    for (&source, 0..) |*byte, index| byte.* = @intCast(0x40 + index * 3);
    if (!checkedWrite(table, &lifetime.spaces[0], ids.task(1), 1, owner_cross, &source) or
        !checkedRead(table, &lifetime.spaces[1], ids.task(2), 2, peer_cross, &destination)) probe.fail("shared checked peer copy");
    for (source, destination) |expected, actual| if (expected != actual) probe.fail("shared checked peer visibility");
    const restored: [COPY_BYTES]u8 = @splat(0x93);
    if (!checkedWrite(table, &lifetime.spaces[0], ids.task(1), 1, owner_cross, &restored)) probe.fail("shared copy restore");
    expectFilled(object, 0x93);

    // The address space stays inactive throughout this deliberate PTE forgery;
    // no hardware translation observes it before its exact restoration.
    const before_forgery = paging.frameStats().allocated;
    {
        const late = leafSlot(&lifetime.spaces[0], owner_base + PAGE_BYTES) orelse probe.fail("shared late leaf slot");
        const original = @atomicLoad(page_table.Entry, late, .acquire);
        const forged = (original ^ @as(u64, @intCast(page_table.address(original)))) | other.page_base;
        @atomicStore(page_table.Entry, late, forged, .release);
        defer @atomicStore(page_table.Entry, late, original, .release);
        rejectCopy(table, &lifetime.spaces[0], ids.task(1), 1, owner_cross);
        if (@atomicLoad(page_table.Entry, late, .acquire) != forged or paging.frameStats().allocated != before_forgery)
            probe.fail("shared forged copy mutation");
        expectFilled(object, 0x93);
        expectFilled(other, 0x6d);
    }
    if (!checkedRead(table, &lifetime.spaces[0], ids.task(1), 1, owner_cross, &destination)) probe.fail("shared restored leaf copy");
    for (destination) |byte| if (byte != 0x93) probe.fail("shared restored leaf bytes");
    if (x86.readCr3() != kernel_cr3) probe.fail("shared copy root continuation");
    requireCopyOwner();
}

fn proveRetiredCopyRejection(table: *const shared.Table, lifetime: *Lifetime) void {
    const before = paging.frameStats().allocated;
    for (lifetime.mappings, 0..) |mapping, index| {
        const descriptor = mapping.descriptor.?;
        const address: usize = @intCast(descriptor.virtual_base + PAGE_BYTES - COPY_BYTES / 2);
        rejectCopy(table, &lifetime.spaces[index], descriptor.task_id, index + 1, address);
        const stale = demand.SharedCopyAuthority{
            .virtual_base = descriptor.virtual_base,
            .physical_base = descriptor.physical_base,
            .size_bytes = descriptor.size_bytes,
        };
        if (demand.prepareSharedUserRange(&lifetime.spaces[index], stale, address, COPY_BYTES, false, 0) != null or
            leaf(&lifetime.spaces[index], address) != null) probe.fail("shared retired copy resurrection");
    }
    if (paging.frameStats().allocated != before) probe.fail("shared retired copy allocation");
}

fn taskIndex(task: ids.TaskId) ?usize {
    return switch (task.raw()) {
        1 => 0,
        2 => 1,
        else => null,
    };
}

fn overlaps(left: shared.Object, right: shared.Object) bool {
    return left.page_base < right.page_base + right.page_count * PAGE_BYTES and
        right.page_base < left.page_base + left.page_count * PAGE_BYTES;
}

fn containsPhysical(object: shared.Object, physical: usize) bool {
    return physical >= object.page_base and physical < object.page_base + object.page_count * PAGE_BYTES;
}

fn physicalBytes(physical: u64) [*]volatile u8 {
    return @ptrFromInt(paging.directMapAddress(physical) orelse probe.fail("shared direct alias"));
}

fn physicalWord(physical: u64) *volatile u64 {
    return @ptrFromInt(paging.directMapAddress(physical) orelse probe.fail("shared direct word"));
}

fn expectZero(object: shared.Object) void {
    const bytes = physicalBytes(object.page_base);
    for (0..object.page_count * PAGE_BYTES) |byte| if (bytes[byte] != 0) probe.fail("shared rounded zero");
}

fn fill(object: shared.Object, value: u8) void {
    const bytes = physicalBytes(object.page_base);
    for (0..object.page_count * PAGE_BYTES) |byte| bytes[byte] = value;
}

fn expectFilled(object: shared.Object, value: u8) void {
    const bytes = physicalBytes(object.page_base);
    for (0..object.page_count * PAGE_BYTES) |byte| if (bytes[byte] != value) probe.fail("shared allocation overlap");
}

fn leaf(space: *const paging.UserAddressSpace, virtual: usize) ?page_table.Entry {
    const entry = @atomicLoad(page_table.Entry, leafSlot(space, virtual) orelse return null, .acquire);
    return if (page_table.isPresent(entry)) entry else null;
}

fn leafSlot(space: *const paging.UserAddressSpace, virtual: usize) ?*page_table.Entry {
    var table: *page_table.Table = space.directory;
    for ([_]u6{ page_table.PML4_SHIFT, page_table.PDPT_SHIFT, page_table.PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = @atomicLoad(page_table.Entry, &table[page_table.index(virtual, shift)], .acquire);
        if (!page_table.isPresent(entry)) return null;
        const user_writable = page_table.USER | page_table.WRITABLE;
        if (page_table.isLargePage(entry) or entry & user_writable != user_writable)
            probe.fail("shared private hierarchy");
        table = @ptrFromInt(paging.directMapAddress(@intCast(page_table.address(entry))) orelse probe.fail("shared hierarchy alias"));
    }
    return &table[page_table.index(virtual, page_table.PAGE_TABLE_SHIFT)];
}

fn expectRamLeaf(entry: page_table.Entry, writable: bool) void {
    const required = page_table.PRESENT | page_table.USER | page_table.NO_EXECUTE;
    // Bit 7 is PAT on a 4KiB leaf; default PAT index zero is write-back RAM.
    const forbidden = page_table.WRITE_THROUGH | page_table.CACHE_DISABLE | page_table.LARGE_PAGE | page_table.GLOBAL;
    if (entry & required != required or entry & forbidden != 0 or
        (entry & page_table.WRITABLE != 0) != writable) probe.fail("shared RAM permissions");
}

fn writeUserWord(space: *const paging.UserAddressSpace, virtual: usize, value: u64) void {
    paging.switchToUserAddressSpace(space);
    x86.allowSupervisorUserMemory();
    @as(*volatile u64, @ptrFromInt(virtual)).* = value;
    x86.forbidSupervisorUserMemory();
    paging.switchToKernelAddressSpace();
}

fn readUserWord(space: *const paging.UserAddressSpace, virtual: usize) u64 {
    paging.switchToUserAddressSpace(space);
    x86.allowSupervisorUserMemory();
    const value = @as(*volatile u64, @ptrFromInt(virtual)).*;
    x86.forbidSupervisorUserMemory();
    paging.switchToKernelAddressSpace();
    return value;
}
