const std = @import("std");

pub fn HostAssignment(comptime ProcessClassType: type, comptime NamespaceClassType: type) type {
    return struct {
        process_id: u64,
        address_space_id: u64,
        namespace_id: u64,
        process_class: ProcessClassType,
        namespace_class: NamespaceClassType,
    };
}

pub fn allocateHost(
    ErrorSet: type,
    ProcessClassType: type,
    NamespaceClassType: type,
    runtime: anytype,
    component_class: anytype,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: anytype,
) ErrorSet!HostAssignment(ProcessClassType, NamespaceClassType) {
    return assignHost(
        ErrorSet,
        ProcessClassType,
        NamespaceClassType,
        runtime,
        component_class,
        owner_task_id,
        image_id,
        userspace_image,
        null,
    );
}

pub fn reassignHost(
    ErrorSet: type,
    ProcessClassType: type,
    NamespaceClassType: type,
    runtime: anytype,
    component_class: anytype,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: anytype,
    replace_address_space_id: u64,
) ErrorSet!HostAssignment(ProcessClassType, NamespaceClassType) {
    return assignHost(
        ErrorSet,
        ProcessClassType,
        NamespaceClassType,
        runtime,
        component_class,
        owner_task_id,
        image_id,
        userspace_image,
        replace_address_space_id,
    );
}

pub fn saturatingSub(current: usize, amount: usize) usize {
    return if (amount >= current) 0 else current - amount;
}

pub fn zeroAddressSpaceRegion(RegionType: type) RegionType {
    return .{
        .kind = .load_segment,
        .virtual_address = 0,
        .size_bytes = 0,
        .file_offset = 0,
        .file_size = 0,
        .access = .{},
    };
}

pub fn zeroAddressSpace(AddressSpaceType: type, RegionType: type, comptime region_count: usize) AddressSpaceType {
    const zeroed = std.mem.zeroes(AddressSpaceType);
    return .{
        .id = 0,
        .owner_task_id = 0,
        .process_id = 0,
        .image_id = 0,
        .load_state = .empty,
        .entry_point = 0,
        .instruction_pointer = 0,
        .stack_pointer = 0,
        .stack_top = 0,
        .stack_size_bytes = 0,
        .load_segment_count = 0,
        .region_count = 0,
        .image_sha256 = zeroed.image_sha256,
        .regions = [_]RegionType{zeroAddressSpaceRegion(RegionType)} ** region_count,
    };
}

pub fn findAddressSpaceSlot(runtime: anytype, address_space_id: u64) ?*AddressSpaceSlotType(@TypeOf(runtime)) {
    const RuntimeType = runtimeType(@TypeOf(runtime));
    if (comptime @hasDecl(RuntimeType, "indexedAddressSpaceSlot")) {
        return runtime.indexedAddressSpaceSlot(address_space_id);
    } else {
        for (&runtime.address_spaces) |*slot| {
            if (slot.in_use and slot.address_space.id == address_space_id) return slot;
        }
        return null;
    }
}

pub fn installAddressSpace(
    ErrorSet: type,
    runtime: anytype,
    replace_address_space_id: ?u64,
    address_space: anytype,
) ErrorSet!void {
    const RuntimeType = runtimeType(@TypeOf(runtime));
    if (comptime @hasDecl(RuntimeType, "installAddressSpaceRecord")) {
        if (runtime.installAddressSpaceRecord(replace_address_space_id, address_space)) return;
        return error.AddressSpaceTableFull;
    } else {
        if (replace_address_space_id) |old_id| {
            if (findAddressSpaceSlot(runtime, old_id)) |slot| {
                slot.in_use = true;
                slot.address_space = address_space;
                noteAddressSpaceIndexRemoved(runtime, old_id);
                noteAddressSpaceIndexInstalled(runtime, address_space.id, slotIndexFor(runtime, slot));
                return;
            }
        }

        for (&runtime.address_spaces, 0..) |*slot, slot_index| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.address_space = address_space;
            noteAddressSpaceIndexInstalled(runtime, address_space.id, slot_index);
            return;
        }
        return error.AddressSpaceTableFull;
    }
}

fn noteAddressSpaceIndexInstalled(runtime: anytype, address_space_id: u64, slot_index: usize) void {
    const RuntimeType = runtimeType(@TypeOf(runtime));
    if (@hasDecl(RuntimeType, "noteAddressSpaceInstalled")) {
        runtime.noteAddressSpaceInstalled(address_space_id, slot_index);
    }
}

fn noteAddressSpaceIndexRemoved(runtime: anytype, address_space_id: u64) void {
    const RuntimeType = runtimeType(@TypeOf(runtime));
    if (@hasDecl(RuntimeType, "removeAddressSpaceIndex")) {
        runtime.removeAddressSpaceIndex(address_space_id);
    }
}

fn slotIndexFor(runtime: anytype, slot: anytype) usize {
    return (@intFromPtr(slot) - @intFromPtr(&runtime.address_spaces[0])) / @sizeOf(@TypeOf(runtime.address_spaces[0]));
}

fn assignHost(
    ErrorSet: type,
    ProcessClassType: type,
    NamespaceClassType: type,
    runtime: anytype,
    component_class: anytype,
    owner_task_id: u64,
    image_id: u64,
    userspace_image: anytype,
    replace_address_space_id: ?u64,
) ErrorSet!HostAssignment(ProcessClassType, NamespaceClassType) {
    const process_id = nextReservableProcessId(runtime) orelse return error.AddressSpaceTableFull;
    const address_space_id = nextReservableAddressSpaceId(runtime) orelse return error.AddressSpaceTableFull;
    const namespace_id = nextReservableNamespaceId(runtime) orelse return error.AddressSpaceTableFull;

    const AddressSpaceType = AddressSpaceRecordType(@TypeOf(runtime));
    const RegionType = AddressSpaceRegionType(@TypeOf(runtime));
    try installAddressSpace(
        ErrorSet,
        runtime,
        replace_address_space_id,
        makeAddressSpace(
            AddressSpaceType,
            RegionType,
            addressSpaceRegionCapacity(@TypeOf(runtime)),
            address_space_id,
            owner_task_id,
            process_id,
            image_id,
            userspace_image,
        ),
    );
    runtime.next_process_id = nextHostIdAfter(process_id);
    runtime.next_address_space_id = nextHostIdAfter(address_space_id);
    runtime.next_namespace_id = nextHostIdAfter(namespace_id);

    return .{
        .process_id = process_id,
        .address_space_id = address_space_id,
        .namespace_id = namespace_id,
        .process_class = switch (component_class) {
            .session_manager => ProcessClassType.session_host,
            .app_component => ProcessClassType.app_sandbox,
            .service_component => ProcessClassType.service_sandbox,
        },
        .namespace_class = switch (component_class) {
            .session_manager => NamespaceClassType.session_private,
            .app_component => NamespaceClassType.app_private,
            .service_component => NamespaceClassType.service_private,
        },
    };
}

fn nextReservableProcessId(runtime: anytype) ?u64 {
    var process_id = normalizeHostId(runtime.next_process_id);
    var attempts: usize = 0;
    while (attempts <= taskSlotCapacity(runtime)) : (attempts += 1) {
        if (!processIdInUse(runtime, process_id)) return process_id;
        process_id = nextHostIdAfter(process_id);
    }
    return null;
}

fn nextReservableAddressSpaceId(runtime: anytype) ?u64 {
    var address_space_id = normalizeHostId(runtime.next_address_space_id);
    var attempts: usize = 0;
    while (attempts <= addressSpaceSlotCapacity(runtime)) : (attempts += 1) {
        if (findAddressSpaceSlot(runtime, address_space_id) == null) return address_space_id;
        address_space_id = nextHostIdAfter(address_space_id);
    }
    return null;
}

fn nextReservableNamespaceId(runtime: anytype) ?u64 {
    var namespace_id = normalizeHostId(runtime.next_namespace_id);
    var attempts: usize = 0;
    while (attempts <= taskSlotCapacity(runtime)) : (attempts += 1) {
        if (!namespaceIdInUse(runtime, namespace_id)) return namespace_id;
        namespace_id = nextHostIdAfter(namespace_id);
    }
    return null;
}

fn processIdInUse(runtime: anytype, process_id: u64) bool {
    var slot_index: usize = 0;
    while (slot_index < taskSlotCapacity(runtime)) : (slot_index += 1) {
        const slot = runtime.taskSlotAtConst(slot_index);
        if (slot.in_use and slot.task.process_id == process_id) return true;
    }
    return false;
}

fn namespaceIdInUse(runtime: anytype, namespace_id: u64) bool {
    var slot_index: usize = 0;
    while (slot_index < taskSlotCapacity(runtime)) : (slot_index += 1) {
        const slot = runtime.taskSlotAtConst(slot_index);
        if (slot.in_use and slot.task.namespace_id == namespace_id) return true;
    }
    return false;
}

fn taskSlotCapacity(runtime: anytype) usize {
    return runtime.taskSlotCapacity();
}

fn addressSpaceSlotCapacity(runtime: anytype) usize {
    const AddressSpacesType = @TypeOf(runtime.address_spaces);
    if (comptime @hasField(AddressSpacesType, "slots")) {
        return runtime.address_spaces.slots.len;
    } else {
        return runtime.address_spaces.len;
    }
}

fn normalizeHostId(id: u64) u64 {
    return if (id == 0) 1 else id;
}

fn nextHostIdAfter(id: u64) u64 {
    const next = id +% 1;
    return normalizeHostId(next);
}

fn makeAddressSpace(
    AddressSpaceType: type,
    RegionType: type,
    comptime region_count: usize,
    id: u64,
    owner_task_id: u64,
    process_id: u64,
    image_id: u64,
    userspace_image: anytype,
) AddressSpaceType {
    var record = zeroAddressSpace(AddressSpaceType, RegionType, region_count);
    record.id = id;
    record.owner_task_id = owner_task_id;
    record.process_id = process_id;
    record.image_id = image_id;

    if (!userspace_image.isPresent()) return record;

    record.load_state = .executable_loaded;
    record.entry_point = userspace_image.entry_point;
    record.instruction_pointer = userspace_image.entry_point;
    record.stack_pointer = userspace_image.stack_top;
    record.stack_top = userspace_image.stack_top;
    record.stack_size_bytes = userspace_image.stack_size_bytes;
    record.load_segment_count = userspace_image.segment_count;
    record.image_sha256 = userspace_image.file_sha256;

    var index: usize = 0;
    while (index < userspace_image.segment_count) : (index += 1) {
        const segment = userspace_image.segments[index];
        record.regions[index] = .{
            .kind = .load_segment,
            .virtual_address = segment.virtual_address,
            .size_bytes = segment.memory_size,
            .file_offset = segment.file_offset,
            .file_size = segment.file_size,
            .access = segment.access,
        };
    }

    record.regions[index] = .{
        .kind = .stack,
        .virtual_address = userspace_image.stack_top - userspace_image.stack_size_bytes,
        .size_bytes = userspace_image.stack_size_bytes,
        .file_offset = 0,
        .file_size = 0,
        .access = .{
            .read = true,
            .write = true,
        },
    };
    record.region_count = userspace_image.segment_count + 1;
    return record;
}

fn runtimeType(comptime RuntimePtrType: type) type {
    return switch (@typeInfo(RuntimePtrType)) {
        .pointer => |pointer| pointer.child,
        else => @compileError("task runtime host helpers expect a runtime pointer"),
    };
}

fn AddressSpaceSlotType(comptime RuntimePtrType: type) type {
    const RuntimeType = runtimeType(RuntimePtrType);
    if (@hasDecl(RuntimeType, "AddressSpaceSlotType")) return RuntimeType.AddressSpaceSlotType;
    return switch (@typeInfo(@FieldType(RuntimeType, "address_spaces"))) {
        .array => |array| array.child,
        else => @compileError("legacy runtimes must expose an address_spaces array"),
    };
}

fn AddressSpaceRecordType(comptime RuntimePtrType: type) type {
    const RuntimeType = runtimeType(RuntimePtrType);
    if (@hasDecl(RuntimeType, "AddressSpaceRecordType")) return RuntimeType.AddressSpaceRecordType;
    return @FieldType(AddressSpaceSlotType(RuntimePtrType), "address_space");
}

fn AddressSpaceRegionType(comptime RuntimePtrType: type) type {
    return switch (@typeInfo(@FieldType(AddressSpaceRecordType(RuntimePtrType), "regions"))) {
        .array => |array| array.child,
        else => @compileError("address spaces must expose fixed-size region arrays"),
    };
}

fn addressSpaceRegionCapacity(comptime RuntimePtrType: type) usize {
    return switch (@typeInfo(@FieldType(AddressSpaceRecordType(RuntimePtrType), "regions"))) {
        .array => |array| array.len,
        else => @compileError("address spaces must expose fixed-size region arrays"),
    };
}
