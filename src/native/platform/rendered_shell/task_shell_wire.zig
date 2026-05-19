const std = @import("std");
const model = @import("model.zig");

pub const TaskShellOperation = enum(u8) {
    click = 1,
    recover_state = 2,
};

pub const TaskShellStatus = enum(u8) {
    ok = 0,
    invalid_order = 1,
    not_found = 2,
    compositor_rejected = 3,
    recovery_missing = 4,
    invalid_request = 5,
    malformed_request = 6,
    request_too_large = 7,
    response_too_large = 8,
};

pub const TaskShellRequest = struct {
    operation: TaskShellOperation,
    control: model.Control = .start_task,
    tick: u64 = 0,
};

pub const TaskShellResponse = struct {
    operation: TaskShellOperation,
    control: model.Control,
    status: TaskShellStatus = .ok,
    recovered: bool = false,
    task_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    task_flow_events: u16 = 0,
};

const TASK_SHELL_MAGIC_REQUEST = [_]u8{ 'Z', 'S', 'H', '1' };
const TASK_SHELL_MAGIC_RESPONSE = [_]u8{ 'Z', 'S', 'R', '1' };

pub fn encodeRequest(buffer: []u8, request: TaskShellRequest) ![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &TASK_SHELL_MAGIC_REQUEST);
    try writeByte(buffer, &used, @intFromEnum(request.operation));
    try writeByte(buffer, &used, @intFromEnum(request.control));
    try writeU64(buffer, &used, request.tick);
    return buffer[0..used];
}

pub fn decodeRequest(payload: []const u8) !TaskShellRequest {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &TASK_SHELL_MAGIC_REQUEST)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(model.Control, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const tick = try readU64(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .tick = tick,
    };
}

pub fn encodeResponse(buffer: []u8, response: TaskShellResponse) ![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &TASK_SHELL_MAGIC_RESPONSE);
    try writeByte(buffer, &used, @intFromEnum(response.operation));
    try writeByte(buffer, &used, @intFromEnum(response.control));
    try writeByte(buffer, &used, @intFromEnum(response.status));
    try writeByte(buffer, &used, if (response.recovered) 1 else 0);
    try writeU64(buffer, &used, response.task_id);
    try writeU64(buffer, &used, response.active_window_id);
    try writeU16(buffer, &used, response.visible_window_count);
    try writeU16(buffer, &used, response.task_flow_events);
    return buffer[0..used];
}

pub fn decodeResponse(payload: []const u8) !TaskShellResponse {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &TASK_SHELL_MAGIC_RESPONSE)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(model.Control, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(TaskShellStatus, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const recovered = (try readByte(payload, &cursor)) != 0;
    const task_id = try readU64(payload, &cursor);
    const active_window_id = try readU64(payload, &cursor);
    const visible_window_count = try readU16(payload, &cursor);
    const task_flow_events = try readU16(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .status = status,
        .recovered = recovered,
        .task_id = task_id,
        .active_window_id = active_window_id,
        .visible_window_count = visible_window_count,
        .task_flow_events = task_flow_events,
    };
}

pub fn statusForError(err: anyerror) TaskShellStatus {
    return switch (err) {
        error.TaskRequired,
        error.TaskAlreadyStarted,
        error.WorkspaceRequired,
        error.DocumentRequired,
        error.AppPanelRequired,
        => .invalid_order,
        error.EntryNotFound,
        error.TaskNotFound,
        => .not_found,
        error.CompositorRejected => .compositor_rejected,
        error.RecoveryStateMissing => .recovery_missing,
        error.MalformedRequest => .malformed_request,
        error.RequestTooLarge => .request_too_large,
        error.ResponseTooLarge => .response_too_large,
        else => .invalid_request,
    };
}

fn writeByte(buffer: []u8, used: *usize, value: u8) !void {
    if (used.* + 1 > buffer.len) return error.RequestTooLarge;
    buffer[used.*] = value;
    used.* += 1;
}

fn writeBytes(buffer: []u8, used: *usize, bytes: []const u8) !void {
    if (used.* + bytes.len > buffer.len) return error.RequestTooLarge;
    @memcpy(buffer[used.* .. used.* + bytes.len], bytes);
    used.* += bytes.len;
}

fn writeU16(buffer: []u8, used: *usize, value: u16) !void {
    if (used.* + 2 > buffer.len) return error.ResponseTooLarge;
    std.mem.writeInt(u16, buffer[used.*..][0..2], value, .little);
    used.* += 2;
}

fn writeU64(buffer: []u8, used: *usize, value: u64) !void {
    if (used.* + 8 > buffer.len) return error.RequestTooLarge;
    std.mem.writeInt(u64, buffer[used.*..][0..8], value, .little);
    used.* += 8;
}

fn readByte(buffer: []const u8, cursor: *usize) !u8 {
    if (cursor.* + 1 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 1;
    return buffer[cursor.*];
}

fn readBytes(buffer: []const u8, cursor: *usize, len: usize) ![]const u8 {
    if (cursor.* + len > buffer.len) return error.MalformedRequest;
    defer cursor.* += len;
    return buffer[cursor.* .. cursor.* + len];
}

fn readU16(buffer: []const u8, cursor: *usize) !u16 {
    if (cursor.* + 2 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 2;
    return std.mem.readInt(u16, buffer[cursor.*..][0..2], .little);
}

fn readU64(buffer: []const u8, cursor: *usize) !u64 {
    if (cursor.* + 8 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 8;
    return std.mem.readInt(u64, buffer[cursor.*..][0..8], .little);
}
