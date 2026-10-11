const std = @import("std");
const abi = @import("../core/abi.zig");
const wire_types = @import("../core/task_create_wire.zig");
const principal = @import("../core/principal.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_model = @import("../task/task_runtime_model.zig");
const accelerator = @import("../task/accelerator_scheduler.zig");

pub const StagedStrings = struct {
    bundle_id: []const u8,
    source_identity: []const u8,
    component_label: []const u8,
    component_entry: []const u8,
};

// This scalar admission runs before any nested user address is followed.
pub inline fn taskCreateWireValid(wire: *const abi.TaskCreateWireRequest) bool {
    if (wire.header.operation != abi.opcode(.task_create) or wire.header.flags != 0 or
        wire.header.reserved != 0 or
        wire.flags & ~wire_types.KNOWN_FLAGS != 0 or !std.mem.allEqual(u8, &wire.reserved, 0)) return false;
    if (std.enums.fromInt(principal.PrincipalKind, wire.owner_kind) == null or
        std.enums.fromInt(task_runtime.ComponentClass, wire.component_class) == null or
        std.enums.fromInt(task_runtime.ExecutionSubstrate, wire.substrate) == null or
        std.enums.fromInt(task_runtime.LaunchBoundary, wire.launch_boundary) == null) return false;
    if (wire.flags & wire_types.RESOURCE_CLASS_PRESENT != 0) {
        if (std.enums.fromInt(accelerator.ResourceClass, wire.resource_class) == null) return false;
    } else if (wire.resource_class != 0) return false;
    if (wire.flags & wire_types.UI_SURFACE_PRESENT == 0 and wire.ui_surface_id != 0) return false;
    if (std.math.cast(usize, wire.memory_bytes) == null or std.math.cast(usize, wire.shared_memory_bytes) == null) return false;
    return wire.bundle_id_bytes <= task_runtime.MAX_TASK_BUNDLE_ID_BYTES and
        wire.source_identity_bytes <= task_runtime.MAX_TASK_SOURCE_IDENTITY_BYTES and
        wire.component_label_bytes <= task_runtime.MAX_COMPONENT_LABEL_BYTES and
        wire.component_entry_bytes <= task_runtime.MAX_COMPONENT_ENTRY_BYTES;
}

pub inline fn taskCreateFromWireInto(
    wire: *const abi.TaskCreateWireRequest,
    staged: StagedStrings,
    image: ?*const task_runtime.ExecutableImageSpec,
    out: *task_runtime.TaskCreateRequest,
) bool {
    if (!taskCreateWireValid(wire)) return false;
    if (staged.bundle_id.len != wire.bundle_id_bytes or staged.source_identity.len != wire.source_identity_bytes or
        staged.component_label.len != wire.component_label_bytes or staged.component_entry.len != wire.component_entry_bytes or
        (wire.userspace_image_address == 0) != (image == null)) return false;
    const boundary = std.enums.fromInt(task_runtime.LaunchBoundary, wire.launch_boundary).?;
    if (boundary == .userspace_process and (image == null or !image.?.isPresent())) return false;
    const decoded = task_runtime.TaskCreateRequest{
        .owner = .{ .kind = std.enums.fromInt(principal.PrincipalKind, wire.owner_kind).?, .serial = wire.owner_serial },
        .component_class = std.enums.fromInt(task_runtime.ComponentClass, wire.component_class).?,
        .budget = .{
            .cpu_time_ticks = wire.cpu_time_ticks,
            .memory_bytes = std.math.cast(usize, wire.memory_bytes).?,
            .endpoint_slots = wire.endpoint_slots,
            .shared_memory_bytes = std.math.cast(usize, wire.shared_memory_bytes).?,
            .resource_class = if (wire.flags & wire_types.RESOURCE_CLASS_PRESENT != 0) std.enums.fromInt(accelerator.ResourceClass, wire.resource_class).? else null,
            .background_allowed = wire.flags & wire_types.BACKGROUND_ALLOWED != 0,
        },
        .ui_surface_id = if (wire.flags & wire_types.UI_SURFACE_PRESENT != 0) wire.ui_surface_id else null,
        .local_only = wire.flags & wire_types.LOCAL_ONLY != 0,
        .initial_component = .{
            .substrate = std.enums.fromInt(task_runtime.ExecutionSubstrate, wire.substrate).?,
            .label = staged.component_label,
            .entry = staged.component_entry,
        },
        .launch = .{
            .boundary = boundary,
            .image_id = wire.image_id,
            .component_abi_version = wire.component_abi_version,
            .signed = wire.flags & wire_types.SIGNED != 0,
            .bundle_id = staged.bundle_id,
            .source_identity = staged.source_identity,
            .release_transparency_sequence = wire.release_transparency_sequence,
            .release_transparency_root = wire.release_transparency_root,
            .release_transparency_log_head = wire.release_transparency_log_head,
        },
        .userspace_image = image,
    };
    out.* = decoded;
    return true;
}

pub inline fn executableImageFromWireInto(wire: *const abi.ExecutableImageWireSpec, out: *task_runtime.ExecutableImageSpec) bool {
    if (wire.segment_count > task_runtime.MAX_EXECUTABLE_SEGMENTS or wire.reserved_tail != 0 or !std.mem.allEqual(u8, &wire.reserved, 0)) return false;
    var decoded = task_runtime.ExecutableImageSpec{
        .entry_point = wire.entry_point,
        .bootstrap_mailbox_address = wire.bootstrap_mailbox_address,
        .stack_top = wire.stack_top,
        .stack_size_bytes = wire.stack_size_bytes,
        .file_size_bytes = wire.file_size_bytes,
        .file_sha256 = wire.file_sha256,
        .segment_count = wire.segment_count,
    };
    for (wire.segments, &decoded.segments) |segment, *destination| {
        if (segment.reserved != 0 or segment.access_bits & ~wire_types.SEGMENT_KNOWN_ACCESS != 0 or
            segment.access_bits & (wire_types.SEGMENT_WRITE | wire_types.SEGMENT_EXECUTE) ==
                (wire_types.SEGMENT_WRITE | wire_types.SEGMENT_EXECUTE)) return false;
        destination.* = .{
            .virtual_address = segment.virtual_address,
            .file_offset = segment.file_offset,
            .file_size = segment.file_size,
            .memory_size = segment.memory_size,
            .alignment = segment.alignment,
            .access = .{
                .read = segment.access_bits & wire_types.SEGMENT_READ != 0,
                .write = segment.access_bits & wire_types.SEGMENT_WRITE != 0,
                .execute = segment.access_bits & wire_types.SEGMENT_EXECUTE != 0,
            },
        };
    }
    // A direct request may carry an empty image, which the Runtime ignores.
    // Every present executable retains the normal complete layout admission.
    if (decoded.isPresent()) _ = task_model.validateUserspaceImage(decoded) catch return false;
    out.* = decoded;
    return true;
}

pub fn taskCreateToWireInto(header: abi.RequestHeader, authority_capability_id: u64, request: *const task_runtime.TaskCreateRequest, image_address: u64, out: *abi.TaskCreateWireRequest) void {
    out.* = .{
        .header = header,
        .authority_capability_id = authority_capability_id,
        .owner_serial = request.owner.serial,
        .cpu_time_ticks = request.budget.cpu_time_ticks,
        .memory_bytes = request.budget.memory_bytes,
        .shared_memory_bytes = request.budget.shared_memory_bytes,
        .ui_surface_id = request.ui_surface_id orelse 0,
        .userspace_image_address = image_address,
        .image_id = request.launch.image_id,
        .release_transparency_sequence = request.launch.release_transparency_sequence,
        .release_transparency_root = request.launch.release_transparency_root,
        .release_transparency_log_head = request.launch.release_transparency_log_head,
        .bundle_id_address = if (request.launch.bundle_id.len == 0) 0 else @intFromPtr(request.launch.bundle_id.ptr),
        .source_identity_address = if (request.launch.source_identity.len == 0) 0 else @intFromPtr(request.launch.source_identity.ptr),
        .component_label_address = if (request.initial_component.label.len == 0) 0 else @intFromPtr(request.initial_component.label.ptr),
        .component_entry_address = if (request.initial_component.entry.len == 0) 0 else @intFromPtr(request.initial_component.entry.ptr),
        .bundle_id_bytes = std.math.cast(u32, request.launch.bundle_id.len) orelse std.math.maxInt(u32),
        .source_identity_bytes = std.math.cast(u32, request.launch.source_identity.len) orelse std.math.maxInt(u32),
        .component_label_bytes = std.math.cast(u32, request.initial_component.label.len) orelse std.math.maxInt(u32),
        .component_entry_bytes = std.math.cast(u32, request.initial_component.entry.len) orelse std.math.maxInt(u32),
        .endpoint_slots = request.budget.endpoint_slots,
        .component_abi_version = request.launch.component_abi_version,
        .owner_kind = @backingInt(request.owner.kind),
        .component_class = @backingInt(request.component_class),
        .substrate = @backingInt(request.initial_component.substrate),
        .launch_boundary = @backingInt(request.launch.boundary),
        .flags = (if (request.budget.background_allowed) wire_types.BACKGROUND_ALLOWED else 0) |
            (if (request.local_only) wire_types.LOCAL_ONLY else 0) |
            (if (request.launch.signed) wire_types.SIGNED else 0) |
            (if (request.ui_surface_id != null) wire_types.UI_SURFACE_PRESENT else 0) |
            (if (request.budget.resource_class != null) wire_types.RESOURCE_CLASS_PRESENT else 0),
        .resource_class = if (request.budget.resource_class) |value| @backingInt(value) else 0,
    };
}

pub fn taskCreateToWire(header: abi.RequestHeader, authority_capability_id: u64, request: task_runtime.TaskCreateRequest, image_address: u64) abi.TaskCreateWireRequest {
    var wire: abi.TaskCreateWireRequest = undefined;
    taskCreateToWireInto(header, authority_capability_id, &request, image_address, &wire);
    return wire;
}

pub fn executableImageToWireInto(image: *const task_runtime.ExecutableImageSpec, out: *abi.ExecutableImageWireSpec) void {
    out.* = .{
        .entry_point = image.entry_point,
        .bootstrap_mailbox_address = image.bootstrap_mailbox_address,
        .stack_top = image.stack_top,
        .stack_size_bytes = image.stack_size_bytes,
        .file_size_bytes = image.file_size_bytes,
        .file_sha256 = image.file_sha256,
        .segment_count = image.segment_count,
    };
    for (image.segments, &out.segments) |segment, *destination| {
        destination.* = .{
            .virtual_address = segment.virtual_address,
            .file_offset = segment.file_offset,
            .file_size = segment.file_size,
            .memory_size = segment.memory_size,
            .alignment = segment.alignment,
            .access_bits = (if (segment.access.read) wire_types.SEGMENT_READ else 0) |
                (if (segment.access.write) wire_types.SEGMENT_WRITE else 0) |
                (if (segment.access.execute) wire_types.SEGMENT_EXECUTE else 0) |
                (@as(u32, segment.access._reserved) << 3),
        };
    }
}

pub fn executableImageToWire(image: task_runtime.ExecutableImageSpec) abi.ExecutableImageWireSpec {
    var wire: abi.ExecutableImageWireSpec = undefined;
    executableImageToWireInto(&image, &wire);
    return wire;
}

const Testing = if (@import("builtin").is_test) struct {
    const request = task_runtime.TaskCreateRequest{
        .owner = .{ .kind = .service, .serial = 37 },
        .component_class = .service_component,
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 8192, .endpoint_slots = 3, .shared_memory_bytes = 4096 },
        .initial_component = .{ .label = "service", .entry = "service.run" },
        .launch = .{ .bundle_id = "bundle", .source_identity = "publisher" },
    };
    const staged = StagedStrings{
        .bundle_id = request.launch.bundle_id,
        .source_identity = request.launch.source_identity,
        .component_label = request.initial_component.label,
        .component_entry = request.initial_component.entry,
    };
    fn wire() abi.TaskCreateWireRequest {
        return taskCreateToWire(.{ .operation = abi.opcode(.task_create), .subject_task_id = 11 }, 13, request, 0);
    }
    fn reject(value: abi.TaskCreateWireRequest) !void {
        var out = request;
        try std.testing.expect(!taskCreateFromWireInto(&value, staged, null, &out));
        try std.testing.expectEqualDeep(request, out);
    }
    fn rejectImage(value: abi.ExecutableImageWireSpec, canary: task_runtime.ExecutableImageSpec) !void {
        var out = canary;
        try std.testing.expect(!executableImageFromWireInto(&value, &out));
        try std.testing.expectEqualDeep(canary, out);
    }
} else struct {};

test "task create wire decodes only staged storage and preserves optional zero values" {
    const T = Testing;
    var original = T.request;
    original.ui_surface_id = 0;
    original.budget.resource_class = .foreground_interactive;
    original.budget.background_allowed = true;
    original.local_only = true;
    original.launch.signed = true;
    original.launch.release_transparency_sequence = 17;
    original.launch.release_transparency_root = @splat(0xa5);
    original.launch.release_transparency_log_head = @splat(0x5a);
    var wire = taskCreateToWire(.{ .operation = abi.opcode(.task_create) }, 19, original, 0);
    // Header subjects retain ordinary authenticated-caller override semantics.
    var out = T.request;
    try std.testing.expect(taskCreateFromWireInto(&wire, T.staged, null, &out));
    try std.testing.expectEqualDeep(original, out);
    wire.header.subject_task_id = 999;
    try std.testing.expect(taskCreateFromWireInto(&wire, T.staged, null, &out));
    try std.testing.expectEqualDeep(original, out);
    // Addresses never become decoded slices or an optional image pointer.
    wire.bundle_id_address = std.math.maxInt(u64);
    wire.source_identity_address = 1;
    try std.testing.expect(taskCreateFromWireInto(&wire, T.staged, null, &out));
    try std.testing.expectEqual(@intFromPtr(T.staged.bundle_id.ptr), @intFromPtr(out.launch.bundle_id.ptr));
    try std.testing.expectEqual(@intFromPtr(T.staged.component_entry.ptr), @intFromPtr(out.initial_component.entry.ptr));
    var mismatch = T.staged;
    mismatch.bundle_id = "short";
    out = T.request;
    try std.testing.expect(!taskCreateFromWireInto(&wire, mismatch, null, &out));
    try std.testing.expectEqualDeep(T.request, out);
    wire.userspace_image_address = 0x1000;
    try T.reject(wire);
    original.userspace_image = @ptrFromInt(0x1234_5000);
    // The encoder receives the image descriptor explicitly and never reads
    // the trusted request's optional image pointer.
    wire = taskCreateToWire(wire.header, 19, original, 0);
    try std.testing.expectEqual(@as(u64, 0), wire.userspace_image_address);
}

test "task create wire rejects every invalid scalar tag flag and reserved byte atomically" {
    const T = Testing;
    inline for (.{ "owner_kind", "component_class", "substrate", "launch_boundary", "resource_class" }) |field| {
        const valid_count: usize = if (std.mem.eql(u8, field, "owner_kind")) 6 else if (std.mem.eql(u8, field, "component_class")) 3 else if (std.mem.eql(u8, field, "resource_class")) 5 else 2;
        for (0..256) |tag| {
            var wire = T.wire();
            if (comptime std.mem.eql(u8, field, "resource_class")) wire.flags |= wire_types.RESOURCE_CLASS_PRESENT;
            @field(wire, field) = @intCast(tag);
            if (tag >= valid_count) {
                try T.reject(wire);
            } else {
                try std.testing.expect(taskCreateWireValid(&wire));
            }
        }
    }
    for (5..16) |bit| {
        var wire = T.wire();
        wire.flags = @as(u16, 1) << @intCast(bit);
        try T.reject(wire);
    }
    for (0..32) |flags| {
        var wire = T.wire();
        wire.flags = @intCast(flags);
        var out = T.request;
        try std.testing.expect(taskCreateFromWireInto(&wire, T.staged, null, &out));
        try std.testing.expectEqual(flags & 1 != 0, out.budget.background_allowed);
        try std.testing.expectEqual(flags & 2 != 0, out.local_only);
        try std.testing.expectEqual(flags & 4 != 0, out.launch.signed);
        try std.testing.expectEqual(if (flags & 8 != 0) @as(?u64, 0) else null, out.ui_surface_id);
        try std.testing.expectEqual(if (flags & 16 != 0) @as(?accelerator.ResourceClass, .foreground_interactive) else null, out.budget.resource_class);
    }
    for (0..5) |index| {
        var wire = T.wire();
        wire.reserved[index] = 1;
        try T.reject(wire);
    }
    inline for (.{ "flags", "reserved", "operation" }) |field| {
        var wire = T.wire();
        @field(wire.header, field) = if (comptime std.mem.eql(u8, field, "operation")) abi.opcode(.task_terminate) else 1;
        try T.reject(wire);
    }
    var wire = T.wire();
    wire.resource_class = 1;
    try T.reject(wire);
    wire = T.wire();
    wire.ui_surface_id = 1;
    try T.reject(wire);
    inline for (.{ "bundle_id_bytes", "source_identity_bytes", "component_label_bytes", "component_entry_bytes" }) |field| {
        wire = T.wire();
        @field(wire, field) = std.math.maxInt(u32);
        try T.reject(wire);
    }
}

test "executable image wire admits complete layouts and checks all eight segment representations" {
    const T = Testing;
    const image = task_runtime.syntheticUserspaceImage("wire", "wire.run");
    const wire = executableImageToWire(image);
    var out = task_runtime.ExecutableImageSpec{};
    try std.testing.expect(executableImageFromWireInto(&wire, &out));
    try std.testing.expectEqualDeep(image, out);
    var empty = abi.ExecutableImageWireSpec{};
    for (0..8) |index| {
        for (3..32) |bit| {
            var invalid = empty;
            invalid.segments[index].access_bits = @as(u32, 1) << @intCast(bit);
            try T.rejectImage(invalid, image);
        }
        var invalid = wire;
        invalid.segments[index].reserved = 1;
        try T.rejectImage(invalid, image);
        invalid = empty;
        invalid.segments[index].access_bits = 6;
        try T.rejectImage(invalid, image);
        for ([_]u32{ 0, 1, 2, 3, 4, 5 }) |access| {
            empty.segments[index].access_bits = access;
            try std.testing.expect(executableImageFromWireInto(&empty, &out));
        }
        empty.segments[index].access_bits = 0;
    }
    for (0..3) |index| {
        var invalid = wire;
        invalid.reserved[index] = 1;
        try T.rejectImage(invalid, image);
    }
    var invalid = wire;
    invalid.reserved_tail = 1;
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.segment_count = 9;
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.entry_point = std.math.maxInt(u64);
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.bootstrap_mailbox_address += 1;
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.segments[1].virtual_address = invalid.segments[0].virtual_address;
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.segments[0].file_size = std.math.maxInt(u32);
    try T.rejectImage(invalid, image);
    invalid = wire;
    invalid.stack_size_bytes = std.math.maxInt(u64);
    try T.rejectImage(invalid, image);
    var task_wire = T.wire();
    task_wire.userspace_image_address = 0x1000;
    task_wire.launch_boundary = @backingInt(task_runtime.LaunchBoundary.userspace_process);
    var task = T.request;
    try std.testing.expect(taskCreateFromWireInto(&task_wire, T.staged, &image, &task));
    try std.testing.expect(task.userspace_image.? == &image);
    const absent = task_runtime.ExecutableImageSpec{};
    task = T.request;
    try std.testing.expect(!taskCreateFromWireInto(&task_wire, T.staged, &absent, &task));
    try std.testing.expectEqualDeep(T.request, task);
}
