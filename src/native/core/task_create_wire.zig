const std = @import("std");
const header_wire = @import("request_header_wire.zig");

pub const MAX_EXECUTABLE_SEGMENTS = 8;
pub const BACKGROUND_ALLOWED: u16 = 1 << 0;
pub const LOCAL_ONLY: u16 = 1 << 1;
pub const SIGNED: u16 = 1 << 2;
pub const UI_SURFACE_PRESENT: u16 = 1 << 3;
pub const RESOURCE_CLASS_PRESENT: u16 = 1 << 4;
pub const KNOWN_FLAGS: u16 = BACKGROUND_ALLOWED | LOCAL_ONLY | SIGNED | UI_SURFACE_PRESENT | RESOURCE_CLASS_PRESENT;
pub const SEGMENT_READ: u32 = 1 << 0;
pub const SEGMENT_WRITE: u32 = 1 << 1;
pub const SEGMENT_EXECUTE: u32 = 1 << 2;
pub const SEGMENT_KNOWN_ACCESS: u32 = SEGMENT_READ | SEGMENT_WRITE | SEGMENT_EXECUTE;

pub const ExecutableSegmentWireSpec = extern struct {
    virtual_address: u64 = 0,
    file_offset: u32 = 0,
    file_size: u32 = 0,
    memory_size: u32 = 0,
    alignment: u32 = 0,
    access_bits: u32 = 0,
    reserved: u32 = 0,
};

pub const ExecutableImageWireSpec = extern struct {
    entry_point: u64 = 0,
    bootstrap_mailbox_address: u64 = 0,
    stack_top: u64 = 0,
    stack_size_bytes: u64 = 0,
    file_size_bytes: u32 = 0,
    segment_count: u8 = 0,
    reserved: [3]u8 = @splat(0),
    file_sha256: [32]u8 = @splat(0),
    segments: [MAX_EXECUTABLE_SEGMENTS]ExecutableSegmentWireSpec = @splat(.{}),
    reserved_tail: u64 = 0,
};

pub const TaskCreateWireRequest = extern struct {
    header: header_wire.RequestHeader,
    authority_capability_id: u64 = 0,
    owner_serial: u64 = 0,
    cpu_time_ticks: u64 = 0,
    memory_bytes: u64 = 0,
    shared_memory_bytes: u64 = 0,
    ui_surface_id: u64 = 0,
    userspace_image_address: u64 = 0,
    image_id: u64 = 0,
    release_transparency_sequence: u64 = 0,
    release_transparency_root: [32]u8 = @splat(0),
    release_transparency_log_head: [32]u8 = @splat(0),
    bundle_id_address: u64 = 0,
    source_identity_address: u64 = 0,
    component_label_address: u64 = 0,
    component_entry_address: u64 = 0,
    bundle_id_bytes: u32 = 0,
    source_identity_bytes: u32 = 0,
    component_label_bytes: u32 = 0,
    component_entry_bytes: u32 = 0,
    endpoint_slots: u16 = 0,
    component_abi_version: u16 = 0,
    owner_kind: u8 = 0,
    component_class: u8 = 0,
    substrate: u8 = 0,
    launch_boundary: u8 = 0,
    flags: u16 = 0,
    resource_class: u8 = 0,
    reserved: [5]u8 = @splat(0),
};

test "task create scalar wires have exact contiguous fixed-width geometry" {
    @setEvalBranchQuota(4000);
    inline for (.{ ExecutableSegmentWireSpec, ExecutableImageWireSpec, TaskCreateWireRequest }) |T| {
        var end: usize = 0;
        inline for (@typeInfo(T).@"struct".field_names, @typeInfo(T).@"struct".field_types) |name, Field| {
            try std.testing.expectEqual(end, @offsetOf(T, name));
            end += @sizeOf(Field);
        }
        try std.testing.expectEqual(end, @sizeOf(T));
        try std.testing.expectEqual(@as(usize, 8), @alignOf(T));
    }
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(ExecutableSegmentWireSpec));
    try std.testing.expectEqual(@as(usize, 336), @sizeOf(ExecutableImageWireSpec));
    try std.testing.expectEqual(@as(usize, 216), @sizeOf(TaskCreateWireRequest));
    try std.testing.expectEqual(@as(usize, 72), @offsetOf(ExecutableImageWireSpec, "segments"));
    try std.testing.expectEqual(@as(usize, 184), @offsetOf(TaskCreateWireRequest, "bundle_id_bytes"));
    try std.testing.expectEqual(@as(usize, 208), @offsetOf(TaskCreateWireRequest, "flags"));
}
