const std = @import("std");
const Header = @import("request_header_wire.zig").RequestHeader;

pub const TaskTerminateWireRequest = extern struct { header: Header, task_capability_id: u64 };
pub const EndpointCreateWireRequest = extern struct {
    header: Header,
    authority_capability_id: u64,
    owner_task_id: u64,
    label_address: u64,
    label_bytes: u32,
    flags: u16 = 0,
    reserved: u16 = 0,
};
pub const EndpointConnectWireRequest = extern struct {
    header: Header,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
};
pub const EndpointCloseWireRequest = extern struct { header: Header, endpoint_capability_id: u64 };
pub const CapabilityRevokeWireRequest = extern struct { header: Header, authority_capability_id: u64, capability_id: u64 };
pub const CapabilityQueryWireRequest = extern struct { header: Header, authority_capability_id: u64, capability_id: u64 };
pub const SharedMemoryCreateWireRequest = extern struct { header: Header, authority_capability_id: u64, owner_task_id: u64, size_bytes: u64 };
pub const SharedMemoryMapWireRequest = extern struct { header: Header, shared_memory_capability_id: u64, task_id: u64 };
pub const SharedMemoryUnmapWireRequest = extern struct { header: Header, shared_memory_capability_id: u64, task_id: u64 };
pub const SharedMemoryRevokeWireRequest = extern struct { header: Header, shared_memory_capability_id: u64 };
pub const TimeQueryWireRequest = extern struct { header: Header, authority_capability_id: u64 };
pub const ResourceQueryWireRequest = extern struct { header: Header, authority_capability_id: u64, task_id: u64 };
pub const AccountingQueryWireRequest = extern struct { header: Header, authority_capability_id: u64, task_id: u64 };
pub const InputRecvWireRequest = extern struct { header: Header, input_capability_id: u64, receiver_task_id: u64 };
pub const SurfacePresentWireRequest = extern struct {
    header: Header,
    presentation_capability_id: u64,
    presenter_task_id: u64,
    surface_id: u64,
    fence: u64,
    buffer_object_id: u64,
    buffer_offset: u32,
    buffer_bytes: u32,
    text_address: u64 = 0,
};
pub const DeviceDescribeWireRequest = extern struct { header: Header, device_capability_id: u64 };
pub const DeviceMmioWindowWireRequest = extern struct {
    header: Header,
    device_capability_id: u64,
    window_index: u8,
    reserved: [7]u8 = @splat(0),
};
pub const SurfaceTextWire = extern struct {
    window_id: u64 = 0,
    text_length: u16 = 0,
    cursor: u16 = 0,
    state: u32 = 0,
    text: [512]u8 = @splat(0),
};

// All byte patterns of an admitted wire type are legal Zig values. Explicit
// padding makes every byte part of the schema and subject to canonical checks.
pub fn isScalarWire(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .int => |info| info.signedness == .unsigned and
            (info.bits == 8 or info.bits == 16 or info.bits == 32 or info.bits == 64) and
            !std.mem.eql(u8, @typeName(T), "usize"),
        .array => |info| info.sentinel_ptr == null and isScalarWire(info.child),
        .@"struct" => |info| blk: {
            if (info.layout != .@"extern") break :blk false;
            var end: usize = 0;
            inline for (info.field_names, info.field_types) |name, Field| {
                if (!isScalarWire(Field) or @offsetOf(T, name) != end) break :blk false;
                end += @sizeOf(Field);
            }
            break :blk end == @sizeOf(T);
        },
        else => false,
    };
}

pub fn requireScalarWire(comptime T: type) void {
    // A complete syscall descriptor table validates every nested wire shape
    // in one comptime evaluation, including all executable-image segments.
    @setEvalBranchQuota(20_000);
    if (!isScalarWire(T)) @compileError("user-memory ingress requires an explicit integer-only wire type: " ++ @typeName(T));
}

test "scalar wire gate rejects unsafe representations and implicit padding" {
    try std.testing.expect(isScalarWire(Header));
    try std.testing.expect(isScalarWire(SurfacePresentWireRequest));
    try std.testing.expect(isScalarWire(SurfaceTextWire));
    inline for (.{
        bool,                     usize,                  ?u64,                                   *const u8,                              []const u8, enum(u8) { one },
        union(enum) { one: u64 }, struct { number: u64 }, extern struct { tag: u8, number: u64 }, extern struct { number: u64, tag: u8 },
    }) |T| try std.testing.expect(!isScalarWire(T));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Header, "reserved"));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Header));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(EndpointCreateWireRequest));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(DeviceMmioWindowWireRequest));
    try std.testing.expectEqual(@as(usize, 72), @sizeOf(SurfacePresentWireRequest));
    try std.testing.expectEqual(@as(usize, 528), @sizeOf(SurfaceTextWire));
}
