const std = @import("std");
const binary_cursor = @import("binary_cursor");
const humane_shell = @import("humane_shell.zig");

pub const Error = error{
    MalformedRequest,
    RequestTooLarge,
    ResponseTooLarge,
};

const REQUEST_MAGIC = [_]u8{ 'Z', 'H', 'S', '1' };
const RESPONSE_MAGIC = [_]u8{ 'Z', 'H', 'R', '1' };
const RequestWriter = binary_cursor.Writer(Error, error.RequestTooLarge);
const ResponseWriter = binary_cursor.Writer(Error, error.ResponseTooLarge);
const WireReader = binary_cursor.Reader(Error, error.MalformedRequest);

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
    var writer = RequestWriter{ .buffer = buffer };
    try writer.writeBytes(&REQUEST_MAGIC);
    try writer.writeByte(@intFromEnum(request.operation));
    try writer.writeByte(@intFromEnum(request.control));
    try writer.writeByte(@intFromEnum(request.keyboard));
    try writer.writeU64(request.tick);
    try writeText(&writer, request.text);
    return buffer[0..writer.offset];
}

pub fn decodeRequest(payload: []const u8) Error!humane_shell.HumaneShellRequest {
    var reader = WireReader{ .buffer = payload };
    if (!std.mem.eql(u8, try reader.readSlice(REQUEST_MAGIC.len), &REQUEST_MAGIC)) return error.MalformedRequest;
    const operation = std.enums.fromInt(humane_shell.HumaneShellOperation, try reader.readByte()) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(humane_shell.HumaneShellControl, try reader.readByte()) orelse return error.MalformedRequest;
    const keyboard = std.enums.fromInt(humane_shell.KeyboardIntent, try reader.readByte()) orelse return error.MalformedRequest;
    const tick = try reader.readU64();
    const text = if (reader.eof()) "" else try readText(&reader);
    if (!reader.eof()) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .keyboard = keyboard,
        .tick = tick,
        .text = text,
    };
}

pub fn encodeResponse(buffer: []u8, response: humane_shell.HumaneShellResponse) Error![]const u8 {
    var writer = ResponseWriter{ .buffer = buffer };
    try writer.writeBytes(&RESPONSE_MAGIC);
    try writer.writeByte(@intFromEnum(response.operation));
    try writer.writeByte(@intFromEnum(response.control));
    try writer.writeByte(@intFromEnum(response.status));
    try writer.writeU16(responseFlags(response));
    try writer.writeByte(@intFromEnum(response.focused_control));
    try writer.writeU64(response.task_id);
    try writer.writeU64(response.active_window_id);
    try writer.writeU64(response.snapshot_id);
    try writer.writeU64(response.document_version_id);
    try writer.writeU64(response.selected_object_id);
    try writer.writeU64(response.object_capability_id);
    try writer.writeU16(response.visible_window_count);
    try writer.writeU16(response.task_flow_events);
    try writer.writeU16(response.notification_events);
    try writer.writeU16(response.object_query_count);
    try writer.writeU16(response.object_history_count);
    return buffer[0..writer.offset];
}

pub fn decodeResponse(payload: []const u8) Error!humane_shell.HumaneShellResponse {
    var reader = WireReader{ .buffer = payload };
    if (!std.mem.eql(u8, try reader.readSlice(RESPONSE_MAGIC.len), &RESPONSE_MAGIC)) return error.MalformedRequest;
    const operation = std.enums.fromInt(humane_shell.HumaneShellOperation, try reader.readByte()) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(humane_shell.HumaneShellControl, try reader.readByte()) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(humane_shell.HumaneShellStatus, try reader.readByte()) orelse return error.MalformedRequest;
    const flags = try reader.readU16();
    const focused_control = std.enums.fromInt(humane_shell.HumaneShellControl, try reader.readByte()) orelse return error.MalformedRequest;
    const task_id = try reader.readU64();
    const active_window_id = try reader.readU64();
    const snapshot_id = try reader.readU64();
    const document_version_id = try reader.readU64();
    const selected_object_id = try reader.readU64();
    const object_capability_id = try reader.readU64();
    const visible_window_count = try reader.readU16();
    const task_flow_events = try reader.readU16();
    const notification_events = try reader.readU16();
    const object_query_count = try reader.readU16();
    const object_history_count = try reader.readU16();
    if (!reader.eof()) return error.MalformedRequest;
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

fn writeText(writer: anytype, text: []const u8) Error!void {
    if (text.len > humane_shell.MAX_SHELL_TEXT_INPUT_BYTES) return error.RequestTooLarge;
    try writer.writeU16(@intCast(text.len));
    try writer.writeBytes(text);
}

fn readText(reader: *WireReader) Error![]const u8 {
    const len = try reader.readU16();
    if (len > humane_shell.MAX_SHELL_TEXT_INPUT_BYTES) return error.MalformedRequest;
    return reader.readSlice(len);
}
