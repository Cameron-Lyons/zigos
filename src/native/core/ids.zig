const std = @import("std");

pub fn Id(comptime display_name: []const u8) type {
    return extern struct {
        const Self = @This();
        pub const is_typed_id = true;
        pub const name = display_name;
        pub const zero = Self{ .value = 0 };

        value: u64 = 0,

        pub fn from(raw_value: u64) Self {
            return .{ .value = raw_value };
        }

        pub fn raw(self: Self) u64 {
            return self.value;
        }

        pub fn isZero(self: Self) bool {
            return self.value == 0;
        }

        pub fn eql(self: Self, other: Self) bool {
            return self.value == other.value;
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{s}({d})", .{ display_name, self.value });
        }

        pub fn formatNumber(self: Self, writer: *std.Io.Writer, number: std.fmt.Number) std.Io.Writer.Error!void {
            return writer.printInt(self.value, number.mode.base() orelse 10, number.case, .{
                .precision = number.precision,
                .width = number.width,
                .alignment = number.alignment,
                .fill = number.fill,
            });
        }
    };
}

pub const TaskId = Id("TaskId");
pub const ObjectId = Id("ObjectId");
pub const WorkspaceId = Id("WorkspaceId");
pub const EndpointId = Id("EndpointId");
pub const ServiceId = Id("ServiceId");
pub const PolicyId = Id("PolicyId");
pub const DeviceId = Id("DeviceId");
pub const CapabilityId = Id("CapabilityId");
pub const SharedMemoryId = Id("SharedMemoryId");
pub const VersionId = Id("VersionId");
pub const SnapshotId = Id("SnapshotId");

pub fn task(raw_value: u64) TaskId {
    return TaskId.from(raw_value);
}

pub fn object(raw_value: u64) ObjectId {
    return ObjectId.from(raw_value);
}

pub fn workspace(raw_value: u64) WorkspaceId {
    return WorkspaceId.from(raw_value);
}

pub fn endpoint(raw_value: u64) EndpointId {
    return EndpointId.from(raw_value);
}

pub fn service(raw_value: u64) ServiceId {
    return ServiceId.from(raw_value);
}

pub fn policy(raw_value: u64) PolicyId {
    return PolicyId.from(raw_value);
}

pub fn device(raw_value: u64) DeviceId {
    return DeviceId.from(raw_value);
}

pub fn capability(raw_value: u64) CapabilityId {
    return CapabilityId.from(raw_value);
}

pub fn sharedMemory(raw_value: u64) SharedMemoryId {
    return SharedMemoryId.from(raw_value);
}

pub fn version(raw_value: u64) VersionId {
    return VersionId.from(raw_value);
}

pub fn snapshot(raw_value: u64) SnapshotId {
    return SnapshotId.from(raw_value);
}

pub fn raw(value: anytype) u64 {
    const Value = @TypeOf(value);
    if (comptime isTypedId(Value)) return value.raw();
    if (comptime Value == comptime_int) return value;
    switch (@typeInfo(Value)) {
        .int, .comptime_int => return value,
        else => @compileError("expected typed id or integer, got " ++ @typeName(Value)),
    }
}

pub fn zero(comptime T: type) T {
    if (comptime isTypedId(T)) return T.zero;
    switch (@typeInfo(T)) {
        .int, .comptime_int => return 0,
        else => @compileError("expected typed id or integer, got " ++ @typeName(T)),
    }
}

pub fn coerce(comptime Target: type, value: anytype) Target {
    if (comptime !isTypedId(Target)) @compileError("target must be a typed id, got " ++ @typeName(Target));
    const Value = @TypeOf(value);
    if (comptime isTypedId(Value)) {
        if (comptime Value != Target) @compileError("cannot coerce " ++ @typeName(Value) ++ " to " ++ @typeName(Target));
        return value;
    }
    return Target.from(raw(value));
}

pub fn isZero(value: anytype) bool {
    return raw(value) == 0;
}

pub fn isTypedId(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => @hasDecl(T, "is_typed_id") and T.is_typed_id,
        else => false,
    };
}

test "typed IDs preserve raw ABI values but stay nominally distinct" {
    const task_id = TaskId.from(7);
    const endpoint_id = EndpointId.from(7);
    try std.testing.expectEqual(@as(u64, 7), task_id.raw());
    try std.testing.expectEqual(@as(u64, 7), endpoint_id.raw());
    try std.testing.expectEqual(@as(usize, @sizeOf(u64)), @sizeOf(TaskId));
    try std.testing.expectEqual(@as(usize, @sizeOf(u64)), @sizeOf(EndpointId));
    try std.testing.expect(!TaskId.zero.eql(task_id));
}
