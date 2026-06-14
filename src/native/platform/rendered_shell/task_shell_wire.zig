const std = @import("std");
const binary_cursor = @import("binary_cursor");
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
const RequestWriter = binary_cursor.Writer(anyerror, error.RequestTooLarge);
const ResponseWriter = binary_cursor.Writer(anyerror, error.ResponseTooLarge);
const RequestReader = binary_cursor.Reader(anyerror, error.MalformedRequest);

pub fn encodeRequest(buffer: []u8, request: TaskShellRequest) ![]const u8 {
    var writer = RequestWriter{ .buffer = buffer };
    try writer.writeBytes(&TASK_SHELL_MAGIC_REQUEST);
    try writer.writeByte(@intFromEnum(request.operation));
    try writer.writeByte(@intFromEnum(request.control));
    try writer.writeU64(request.tick);
    return buffer[0..writer.offset];
}

pub fn decodeRequest(payload: []const u8) !TaskShellRequest {
    var reader = RequestReader{ .buffer = payload };
    if (!std.mem.eql(u8, try reader.readSlice(TASK_SHELL_MAGIC_REQUEST.len), &TASK_SHELL_MAGIC_REQUEST)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try reader.readByte()) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(model.Control, try reader.readByte()) orelse return error.MalformedRequest;
    const tick = try reader.readU64();
    if (!reader.eof()) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .tick = tick,
    };
}

pub fn encodeResponse(buffer: []u8, response: TaskShellResponse) ![]const u8 {
    var writer = ResponseWriter{ .buffer = buffer };
    try writer.writeBytes(&TASK_SHELL_MAGIC_RESPONSE);
    try writer.writeByte(@intFromEnum(response.operation));
    try writer.writeByte(@intFromEnum(response.control));
    try writer.writeByte(@intFromEnum(response.status));
    try writer.writeByte(if (response.recovered) 1 else 0);
    try writer.writeU64(response.task_id);
    try writer.writeU64(response.active_window_id);
    try writer.writeU16(response.visible_window_count);
    try writer.writeU16(response.task_flow_events);
    return buffer[0..writer.offset];
}

pub fn decodeResponse(payload: []const u8) !TaskShellResponse {
    var reader = RequestReader{ .buffer = payload };
    if (!std.mem.eql(u8, try reader.readSlice(TASK_SHELL_MAGIC_RESPONSE.len), &TASK_SHELL_MAGIC_RESPONSE)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try reader.readByte()) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(model.Control, try reader.readByte()) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(TaskShellStatus, try reader.readByte()) orelse return error.MalformedRequest;
    const recovered = (try reader.readByte()) != 0;
    const task_id = try reader.readU64();
    const active_window_id = try reader.readU64();
    const visible_window_count = try reader.readU16();
    const task_flow_events = try reader.readU16();
    if (!reader.eof()) return error.MalformedRequest;
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
