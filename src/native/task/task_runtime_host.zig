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
    source_address_space: anytype,
    replace_address_space_id: u64,
) ErrorSet!HostAssignment(ProcessClassType, NamespaceClassType) {
    var address_space = source_address_space;
    address_space.instruction_pointer = address_space.entry_point;
    address_space.stack_pointer = address_space.stack_top;
    return assignAddressSpaceHost(
        ErrorSet,
        ProcessClassType,
        NamespaceClassType,
        runtime,
        component_class,
        owner_task_id,
        address_space,
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
    return runtime.indexedAddressSpaceSlot(address_space_id);
}

pub fn installAddressSpace(
    ErrorSet: type,
    runtime: anytype,
    replace_address_space_id: ?u64,
    address_space: anytype,
) ErrorSet!void {
    if (runtime.installAddressSpaceRecord(replace_address_space_id, address_space)) return;
    return error.AddressSpaceTableFull;
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
    const AddressSpaceType = AddressSpaceRecordType(@TypeOf(runtime));
    const RegionType = AddressSpaceRegionType(@TypeOf(runtime));
    return assignAddressSpaceHost(
        ErrorSet,
        ProcessClassType,
        NamespaceClassType,
        runtime,
        component_class,
        owner_task_id,
        makeAddressSpace(
            AddressSpaceType,
            RegionType,
            addressSpaceRegionCapacity(@TypeOf(runtime)),
            0,
            owner_task_id,
            0,
            image_id,
            userspace_image,
        ),
        replace_address_space_id,
    );
}

fn assignAddressSpaceHost(
    ErrorSet: type,
    ProcessClassType: type,
    NamespaceClassType: type,
    runtime: anytype,
    component_class: anytype,
    owner_task_id: u64,
    address_space_template: anytype,
    replace_address_space_id: ?u64,
) ErrorSet!HostAssignment(ProcessClassType, NamespaceClassType) {
    const process_id = runtime.next_process_id;
    const address_space_id = runtime.next_address_space_id;
    const namespace_id = runtime.next_namespace_id;
    if (process_id == 0 or address_space_id == 0 or namespace_id == 0) {
        return error.AddressSpaceTableFull;
    }

    var address_space = address_space_template;
    address_space.id = address_space_id;
    address_space.owner_task_id = owner_task_id;
    address_space.process_id = process_id;
    try installAddressSpace(ErrorSet, runtime, replace_address_space_id, address_space);
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

fn nextHostIdAfter(id: u64) u64 {
    return id +% 1;
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
    return runtimeType(RuntimePtrType).AddressSpaceSlotType;
}

fn AddressSpaceRecordType(comptime RuntimePtrType: type) type {
    return runtimeType(RuntimePtrType).AddressSpaceRecordType;
}

fn AddressSpaceRegionType(comptime RuntimePtrType: type) type {
    return runtimeType(RuntimePtrType).AddressSpaceRegionType;
}

fn addressSpaceRegionCapacity(comptime RuntimePtrType: type) usize {
    return switch (@typeInfo(@FieldType(AddressSpaceRecordType(RuntimePtrType), "regions"))) {
        .array => |array| array.len,
        else => @compileError("address spaces must expose fixed-size region arrays"),
    };
}
