const std = @import("std");
const userspace_wire = @import("userspace_wire");

pub const MAGIC: u32 = 0x5356_4331;
pub const WIRE_VERSION: u16 = 1;
pub const MAX_OPERATIONS: usize = 4;
pub const MAX_OPERATION_NAME_BYTES: usize = 32;
pub const OperationCount = u8;
pub const PLAN_SIZE_BYTES: usize = 120;
pub const COMPACT_PLAN_METADATA = true;

comptime {
    if (MAX_OPERATIONS > std.math.maxInt(OperationCount)) {
        @compileError("userspace service plan count cannot represent the operation capacity");
    }
}

const REQUEST_FIXED_BYTES: usize = @sizeOf(u32) + @sizeOf(u16) + @sizeOf(u8) + @sizeOf(u8) + @sizeOf(u16) + @sizeOf(u16) + @sizeOf(u32);
const RESPONSE_FIXED_BYTES: usize = REQUEST_FIXED_BYTES + @sizeOf(u64);
const STATE_HASH_NAMESPACE = "zigos-userspace-service";

pub const MAX_REQUEST_BYTES: usize = REQUEST_FIXED_BYTES + MAX_OPERATION_NAME_BYTES;
pub const MAX_RESPONSE_BYTES: usize = RESPONSE_FIXED_BYTES + MAX_OPERATION_NAME_BYTES;

pub const ServiceKind = enum(u8) {
    generic = 0,
    storage = 1,
    sync = 2,
    network = 3,
    package = 4,
    compositor = 5,
};

pub const Operation = struct {
    code: u16,
    name: []const u8,
    value: u32,
};

pub const Plan = struct {
    kind: ServiceKind,
    endpoint_label: []const u8,
    operation_count: OperationCount,
    operations: [MAX_OPERATIONS]Operation,

    pub fn slice(self: *const Plan) []const Operation {
        return self.operations[0..@as(usize, self.operation_count)];
    }

    comptime {
        if (@sizeOf(@This()) != PLAN_SIZE_BYTES) {
            @compileError("userspace service plan no longer matches its compact layout");
        }
    }
};

pub const Message = struct {
    kind: ServiceKind,
    ordinal: u8,
    code: u16,
    value: u32,
    name: []const u8,
    state_hash: u64 = 0,
};

pub const Error = error{
    InvalidKind,
    MalformedMessage,
    NoSpaceLeft,
    OperationNameTooLong,
};

const Writer = userspace_wire.Writer(Error, error.NoSpaceLeft);
const Reader = userspace_wire.Reader(Error, error.MalformedMessage);

pub fn planFor(comptime kind: anytype) Plan {
    const service_kind = coerceKind(kind);
    return switch (service_kind) {
        .storage => plan(.storage, "zigos.object.workspace.selftest", &.{
            .{ .code = 0x0101, .name = "workspace-open", .value = 11 },
            .{ .code = 0x0102, .name = "object-put", .value = 17 },
            .{ .code = 0x0103, .name = "snapshot", .value = 23 },
            .{ .code = 0x0104, .name = "file-bridge", .value = 29 },
        }),
        .sync => plan(.sync, "zigos.sync.replication.selftest", &.{
            .{ .code = 0x0201, .name = "device-graph", .value = 31 },
            .{ .code = 0x0202, .name = "vector-clock", .value = 37 },
            .{ .code = 0x0203, .name = "delta-queue", .value = 41 },
            .{ .code = 0x0204, .name = "conflict-record", .value = 43 },
        }),
        .network => plan(.network, "zigos.service.network.selftest", &.{
            .{ .code = 0x0301, .name = "route-table", .value = 47 },
            .{ .code = 0x0302, .name = "egress-policy", .value = 53 },
            .{ .code = 0x0303, .name = "device-queue", .value = 59 },
        }),
        .package => plan(.package, "zigos.package.install.selftest", &.{
            .{ .code = 0x0401, .name = "manifest-verify", .value = 61 },
            .{ .code = 0x0402, .name = "bundle-stage", .value = 67 },
            .{ .code = 0x0403, .name = "rollback-journal", .value = 71 },
            .{ .code = 0x0404, .name = "update-channel", .value = 73 },
        }),
        .compositor => plan(.compositor, "zigos.ui.session.selftest", &.{
            .{ .code = 0x0501, .name = "surface-create", .value = 79 },
            .{ .code = 0x0502, .name = "input-route", .value = 83 },
            .{ .code = 0x0503, .name = "frame-commit", .value = 89 },
            .{ .code = 0x0504, .name = "session-focus", .value = 97 },
        }),
        .generic => plan(.generic, "zigos.service.generic.selftest", &.{}),
    };
}

pub fn initialStateHash(kind: anytype) u64 {
    const service_kind = coerceKind(kind);
    var hash = userspace_wire.fnv1a64(STATE_HASH_NAMESPACE);
    hash = userspace_wire.fnv1a64AppendByte(hash, @intFromEnum(service_kind));
    return hash;
}

pub fn foldOperation(hash: u64, op: Operation, ordinal: usize) u64 {
    var next = userspace_wire.fnv1a64AppendU16LittleEndian(hash, op.code);
    next = userspace_wire.fnv1a64AppendByte(next, @intCast(ordinal));
    next = userspace_wire.fnv1a64AppendU32LittleEndian(next, op.value);
    return userspace_wire.fnv1a64WithSeed(next, op.name);
}

pub fn encodeRequest(buffer: []u8, kind: anytype, op: Operation, ordinal: usize) Error![]const u8 {
    const service_kind = coerceKind(kind);
    if (op.name.len > MAX_OPERATION_NAME_BYTES) return error.OperationNameTooLong;
    if (ordinal > std.math.maxInt(u8)) return error.NoSpaceLeft;
    var writer = Writer{ .buffer = buffer };
    try writer.writeU32(MAGIC);
    try writer.writeU16(WIRE_VERSION);
    try writer.writeByte(@intFromEnum(service_kind));
    try writer.writeByte(@intCast(ordinal));
    try writer.writeU16(op.code);
    try writer.writeU16(@intCast(op.name.len));
    try writer.writeU32(op.value);
    try writer.writeBytes(op.name);
    return buffer[0..writer.offset];
}

pub fn decodeRequest(payload: []const u8) Error!Message {
    var reader = Reader{ .buffer = payload };
    const magic = try reader.readU32();
    if (magic != MAGIC) return error.MalformedMessage;
    const version = try reader.readU16();
    if (version != WIRE_VERSION) return error.MalformedMessage;
    const kind = std.enums.fromInt(ServiceKind, try reader.readByte()) orelse return error.InvalidKind;
    const ordinal = try reader.readByte();
    const code = try reader.readU16();
    const name_len = try reader.readU16();
    if (name_len > MAX_OPERATION_NAME_BYTES) return error.MalformedMessage;
    const value = try reader.readU32();
    const name = try reader.readSlice(name_len);
    if (reader.offset != payload.len) return error.MalformedMessage;
    return .{
        .kind = kind,
        .ordinal = ordinal,
        .code = code,
        .value = value,
        .name = name,
    };
}

pub fn encodeResponse(buffer: []u8, request: Message, state_hash: u64) Error![]const u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.writeU32(MAGIC);
    try writer.writeU16(WIRE_VERSION);
    try writer.writeByte(@intFromEnum(request.kind));
    try writer.writeByte(request.ordinal);
    try writer.writeU16(request.code);
    try writer.writeU16(@intCast(request.name.len));
    try writer.writeU32(request.value);
    try writer.writeU64(state_hash);
    try writer.writeBytes(request.name);
    return buffer[0..writer.offset];
}

pub fn decodeResponse(payload: []const u8) Error!Message {
    var reader = Reader{ .buffer = payload };
    const magic = try reader.readU32();
    if (magic != MAGIC) return error.MalformedMessage;
    const version = try reader.readU16();
    if (version != WIRE_VERSION) return error.MalformedMessage;
    const kind = std.enums.fromInt(ServiceKind, try reader.readByte()) orelse return error.InvalidKind;
    const ordinal = try reader.readByte();
    const code = try reader.readU16();
    const name_len = try reader.readU16();
    if (name_len > MAX_OPERATION_NAME_BYTES) return error.MalformedMessage;
    const value = try reader.readU32();
    const state_hash = try reader.readU64();
    const name = try reader.readSlice(name_len);
    if (reader.offset != payload.len) return error.MalformedMessage;
    return .{
        .kind = kind,
        .ordinal = ordinal,
        .code = code,
        .value = value,
        .name = name,
        .state_hash = state_hash,
    };
}

pub fn requestMatchesOperation(request: Message, kind: anytype, op: Operation, ordinal: usize) bool {
    const service_kind = coerceKind(kind);
    return request.kind == service_kind and
        request.ordinal == ordinal and
        request.code == op.code and
        request.value == op.value and
        std.mem.eql(u8, request.name, op.name);
}

fn coerceKind(kind: anytype) ServiceKind {
    return switch (@typeInfo(@TypeOf(kind))) {
        .enum_literal => @as(ServiceKind, kind),
        .@"enum" => @enumFromInt(@intFromEnum(kind)),
        else => @compileError("service kind must be an enum or enum literal"),
    };
}

fn plan(comptime kind: ServiceKind, comptime endpoint_label: []const u8, comptime ops: []const Operation) Plan {
    if (ops.len > MAX_OPERATIONS) @compileError("too many userspace service startup operations");
    var out = Plan{
        .kind = kind,
        .endpoint_label = endpoint_label,
        .operation_count = @intCast(ops.len),
        .operations = [_]Operation{.{ .code = 0, .name = "", .value = 0 }} ** MAX_OPERATIONS,
    };
    inline for (ops, 0..) |op, index| {
        if (op.name.len > MAX_OPERATION_NAME_BYTES) @compileError("userspace service operation name too long");
        out.operations[index] = op;
    }
    return out;
}

test "userspace service protocol round-trips every concrete service plan" {
    inline for (.{ ServiceKind.storage, .sync, .network, .package, .compositor }) |kind| {
        const service_plan = planFor(kind);
        var state_hash = initialStateHash(kind);
        for (service_plan.slice(), 0..) |op, index| {
            var request_buffer: [MAX_REQUEST_BYTES]u8 = undefined;
            const request_payload = try encodeRequest(&request_buffer, kind, op, index);
            const request = try decodeRequest(request_payload);
            try std.testing.expect(requestMatchesOperation(request, kind, op, index));

            state_hash = foldOperation(state_hash, op, index);
            var response_buffer: [MAX_RESPONSE_BYTES]u8 = undefined;
            const response_payload = try encodeResponse(&response_buffer, request, state_hash);
            const response = try decodeResponse(response_payload);
            try std.testing.expect(requestMatchesOperation(response, kind, op, index));
            try std.testing.expectEqual(state_hash, response.state_hash);
            try std.testing.expect(request_payload.len <= MAX_REQUEST_BYTES);
            try std.testing.expect(response_payload.len <= MAX_RESPONSE_BYTES);
        }
    }
}

test "userspace service plan metadata stays compact" {
    try std.testing.expect(COMPACT_PLAN_METADATA);
    try std.testing.expectEqual(OperationCount, @FieldType(Plan, "operation_count"));
    try std.testing.expectEqual(@as(usize, 120), @sizeOf(Plan));
}
