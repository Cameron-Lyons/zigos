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

pub fn findAddressSpaceSlot(runtime: anytype, address_space_id: u64) ?*@TypeOf(runtime.address_spaces[0]) {
    const RuntimeType = @typeInfo(@TypeOf(runtime)).pointer.child;
    if (@hasDecl(RuntimeType, "indexedAddressSpaceSlot")) {
        return runtime.indexedAddressSpaceSlot(address_space_id);
    }

    for (&runtime.address_spaces) |*slot| {
        if (slot.in_use and slot.address_space.id == address_space_id) return slot;
    }
    return null;
}

pub fn installAddressSpace(
    ErrorSet: type,
    runtime: anytype,
    replace_address_space_id: ?u64,
    address_space: anytype,
) ErrorSet!void {
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

fn noteAddressSpaceIndexInstalled(runtime: anytype, address_space_id: u64, slot_index: usize) void {
    const RuntimeType = @typeInfo(@TypeOf(runtime)).pointer.child;
    if (@hasDecl(RuntimeType, "noteAddressSpaceInstalled")) {
        runtime.noteAddressSpaceInstalled(address_space_id, slot_index);
    }
}

fn noteAddressSpaceIndexRemoved(runtime: anytype, address_space_id: u64) void {
    const RuntimeType = @typeInfo(@TypeOf(runtime)).pointer.child;
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
    const process_id = runtime.next_process_id;
    runtime.next_process_id += 1;
    const address_space_id = runtime.next_address_space_id;
    runtime.next_address_space_id += 1;
    const namespace_id = runtime.next_namespace_id;
    runtime.next_namespace_id += 1;

    const AddressSpaceType = @TypeOf(runtime.address_spaces[0].address_space);
    const RegionType = @TypeOf(runtime.address_spaces[0].address_space.regions[0]);
    try installAddressSpace(
        ErrorSet,
        runtime,
        replace_address_space_id,
        makeAddressSpace(
            AddressSpaceType,
            RegionType,
            runtime.address_spaces[0].address_space.regions.len,
            address_space_id,
            owner_task_id,
            process_id,
            image_id,
            userspace_image,
        ),
    );

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
