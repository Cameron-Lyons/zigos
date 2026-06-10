const std = @import("std");
const humane_shell = @import("humane_shell.zig");

pub const Error = error{
    MalformedRequest,
    RequestTooLarge,
    ResponseTooLarge,
};

const REQUEST_MAGIC = [_]u8{ 'Z', 'H', 'S', '1' };
const RESPONSE_MAGIC = [_]u8{ 'Z', 'H', 'R', '1' };

const response_flag_permission_reviewed: u16 = 0x01;
const response_flag_permission_denied: u16 = 0x02;
const response_flag_recovered: u16 = 0x04;
const response_flag_object_shared: u16 = 0x08;
const response_flag_object_conflict_reviewed: u16 = 0x10;
const response_flag_object_conflict_resolved: u16 = 0x20;
const response_flag_document_edited: u16 = 0x40;
const response_flag_document_synced: u16 = 0x80;
const response_flag_package_removed: u16 = 0x0100;

pub fn encodeRequest(buffer: []u8, request: humane_shell.HumaneShellRequest) Error![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &REQUEST_MAGIC, error.RequestTooLarge);
    try writeByte(buffer, &used, @intFromEnum(request.operation), error.RequestTooLarge);
    try writeByte(buffer, &used, @intFromEnum(request.control), error.RequestTooLarge);
    try writeByte(buffer, &used, @intFromEnum(request.keyboard), error.RequestTooLarge);
    try writeU64(buffer, &used, request.tick, error.RequestTooLarge);
    try writeText(buffer, &used, request.text, error.RequestTooLarge);
    return buffer[0..used];
}

pub fn decodeRequest(payload: []const u8) Error!humane_shell.HumaneShellRequest {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &REQUEST_MAGIC)) return error.MalformedRequest;
    const operation = std.enums.fromInt(humane_shell.HumaneShellOperation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(humane_shell.HumaneShellControl, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const keyboard = std.enums.fromInt(humane_shell.KeyboardIntent, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const tick = try readU64(payload, &cursor);
    const text = if (cursor == payload.len) "" else try readText(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .keyboard = keyboard,
        .tick = tick,
        .text = text,
    };
}

pub fn encodeResponse(buffer: []u8, response: humane_shell.HumaneShellResponse) Error![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &RESPONSE_MAGIC, error.ResponseTooLarge);
    try writeByte(buffer, &used, @intFromEnum(response.operation), error.ResponseTooLarge);
    try writeByte(buffer, &used, @intFromEnum(response.control), error.ResponseTooLarge);
    try writeByte(buffer, &used, @intFromEnum(response.status), error.ResponseTooLarge);
    try writeU16(buffer, &used, responseFlags(response), error.ResponseTooLarge);
    try writeByte(buffer, &used, @intFromEnum(response.focused_control), error.ResponseTooLarge);
    try writeU64(buffer, &used, response.task_id, error.ResponseTooLarge);
    try writeU64(buffer, &used, response.active_window_id, error.ResponseTooLarge);
    try writeU64(buffer, &used, response.snapshot_id, error.ResponseTooLarge);
    try writeU64(buffer, &used, response.document_version_id, error.ResponseTooLarge);
    try writeU64(buffer, &used, response.selected_object_id, error.ResponseTooLarge);
    try writeU64(buffer, &used, response.object_capability_id, error.ResponseTooLarge);
    try writeU16(buffer, &used, response.visible_window_count, error.ResponseTooLarge);
    try writeU16(buffer, &used, response.task_flow_events, error.ResponseTooLarge);
    try writeU16(buffer, &used, response.notification_events, error.ResponseTooLarge);
    try writeU16(buffer, &used, response.object_query_count, error.ResponseTooLarge);
    try writeU16(buffer, &used, response.object_history_count, error.ResponseTooLarge);
    return buffer[0..used];
}

pub fn decodeResponse(payload: []const u8) Error!humane_shell.HumaneShellResponse {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &RESPONSE_MAGIC)) return error.MalformedRequest;
    const operation = std.enums.fromInt(humane_shell.HumaneShellOperation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(humane_shell.HumaneShellControl, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(humane_shell.HumaneShellStatus, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const flags = try readU16(payload, &cursor);
    const focused_control = std.enums.fromInt(humane_shell.HumaneShellControl, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const task_id = try readU64(payload, &cursor);
    const active_window_id = try readU64(payload, &cursor);
    const snapshot_id = try readU64(payload, &cursor);
    const document_version_id = try readU64(payload, &cursor);
    const selected_object_id = try readU64(payload, &cursor);
    const object_capability_id = try readU64(payload, &cursor);
    const visible_window_count = try readU16(payload, &cursor);
    const task_flow_events = try readU16(payload, &cursor);
    const notification_events = try readU16(payload, &cursor);
    const object_query_count = try readU16(payload, &cursor);
    const object_history_count = try readU16(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .status = status,
        .task_id = task_id,
        .active_window_id = active_window_id,
        .visible_window_count = visible_window_count,
        .task_flow_events = task_flow_events,
        .notification_events = notification_events,
        .focused_control = focused_control,
        .permission_reviewed = (flags & response_flag_permission_reviewed) != 0,
        .permission_denied = (flags & response_flag_permission_denied) != 0,
        .snapshot_id = snapshot_id,
        .recovered = (flags & response_flag_recovered) != 0,
        .document_version_id = document_version_id,
        .document_edited = (flags & response_flag_document_edited) != 0,
        .document_synced = (flags & response_flag_document_synced) != 0,
        .selected_object_id = selected_object_id,
        .object_query_count = object_query_count,
        .object_history_count = object_history_count,
        .object_capability_id = object_capability_id,
        .object_shared = (flags & response_flag_object_shared) != 0,
        .object_conflict_reviewed = (flags & response_flag_object_conflict_reviewed) != 0,
        .object_conflict_resolved = (flags & response_flag_object_conflict_resolved) != 0,
        .package_removed = (flags & response_flag_package_removed) != 0,
    };
}

pub fn dispatchPayload(
    shell: *humane_shell.HumaneShell,
    payload: []const u8,
    out: []u8,
) Error![]const u8 {
    const request = try decodeRequest(payload);
    const response = shell.dispatch(request);
    return encodeResponse(out, response);
}

fn responseFlags(response: humane_shell.HumaneShellResponse) u16 {
    var flags: u16 = 0;
    if (response.permission_reviewed) flags |= response_flag_permission_reviewed;
    if (response.permission_denied) flags |= response_flag_permission_denied;
    if (response.recovered) flags |= response_flag_recovered;
    if (response.object_shared) flags |= response_flag_object_shared;
    if (response.object_conflict_reviewed) flags |= response_flag_object_conflict_reviewed;
    if (response.object_conflict_resolved) flags |= response_flag_object_conflict_resolved;
    if (response.document_edited) flags |= response_flag_document_edited;
    if (response.document_synced) flags |= response_flag_document_synced;
    if (response.package_removed) flags |= response_flag_package_removed;
    return flags;
}

fn writeByte(buffer: []u8, used: *usize, value: u8, comptime overflow_error: Error) Error!void {
    if (used.* + 1 > buffer.len) return overflow_error;
    buffer[used.*] = value;
    used.* += 1;
}

fn writeBytes(buffer: []u8, used: *usize, bytes: []const u8, comptime overflow_error: Error) Error!void {
    if (used.* + bytes.len > buffer.len) return overflow_error;
    @memcpy(buffer[used.* .. used.* + bytes.len], bytes);
    used.* += bytes.len;
}

fn writeU16(buffer: []u8, used: *usize, value: u16, comptime overflow_error: Error) Error!void {
    if (used.* + 2 > buffer.len) return overflow_error;
    std.mem.writeInt(u16, buffer[used.*..][0..2], value, .little);
    used.* += 2;
}

fn writeText(buffer: []u8, used: *usize, text: []const u8, comptime overflow_error: Error) Error!void {
    if (text.len > humane_shell.MAX_SHELL_TEXT_INPUT_BYTES) return overflow_error;
    try writeU16(buffer, used, @intCast(text.len), overflow_error);
    try writeBytes(buffer, used, text, overflow_error);
}

fn writeU64(buffer: []u8, used: *usize, value: u64, comptime overflow_error: Error) Error!void {
    if (used.* + 8 > buffer.len) return overflow_error;
    std.mem.writeInt(u64, buffer[used.*..][0..8], value, .little);
    used.* += 8;
}

fn readByte(buffer: []const u8, cursor: *usize) Error!u8 {
    if (cursor.* + 1 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 1;
    return buffer[cursor.*];
}

fn readBytes(buffer: []const u8, cursor: *usize, len: usize) Error![]const u8 {
    if (cursor.* + len > buffer.len) return error.MalformedRequest;
    defer cursor.* += len;
    return buffer[cursor.* .. cursor.* + len];
}

fn readU16(buffer: []const u8, cursor: *usize) Error!u16 {
    if (cursor.* + 2 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 2;
    return std.mem.readInt(u16, buffer[cursor.*..][0..2], .little);
}

fn readText(buffer: []const u8, cursor: *usize) Error![]const u8 {
    const len = try readU16(buffer, cursor);
    if (len > humane_shell.MAX_SHELL_TEXT_INPUT_BYTES) return error.MalformedRequest;
    return readBytes(buffer, cursor, len);
}

fn readU64(buffer: []const u8, cursor: *usize) Error!u64 {
    if (cursor.* + 8 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 8;
    return std.mem.readInt(u64, buffer[cursor.*..][0..8], .little);
}
