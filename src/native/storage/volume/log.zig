const std = @import("std");
const volume_errors = @import("errors.zig");
const volume_hashing = @import("hashing.zig");
const volume_layout = @import("layout.zig");

pub const Error = volume_errors.Error;

pub const RecordKind = enum(u8) {
    checkpoint = 1,
    object_state = 2,
    version_state = 3,
    workspace_state = 4,
    snapshot_state = 5,
    blob_state = 6,
    chunk_state = 7,
    segment_boundary = 8,
    workspace_delta = 9,
};

pub const RecordHeader = struct {
    kind: RecordKind,
    payload_len: u32,
    checksum: u64,
};

pub const BuiltLog = struct {
    bytes_len: usize = 0,
    record_count: u16 = 0,
    segment_count: u16 = 0,
};

pub fn appendRecordPayload(writer: anytype, kind: RecordKind, payload: []const u8) Error!void {
    const header_offset = try beginRecord(writer, kind);
    try writer.writeBytes(payload);
    try finishRecord(writer, header_offset);
}

pub fn beginRecord(writer: anytype, kind: RecordKind) Error!usize {
    const header_offset = writer.offset;
    try writer.writeByte(@backingInt(kind));
    try writer.writeU32(0);
    try writer.writeU64(0);
    return header_offset;
}

pub fn finishRecord(writer: anytype, header_offset: usize) Error!void {
    const payload_offset = header_offset + recordHeaderLen();
    const payload_len = writer.offset - payload_offset;
    const checksum = volume_hashing.checksumBytes(writer.buffer[payload_offset..writer.offset]);
    const payload_len_offset = header_offset + volume_layout.log_record_payload_len_offset;
    const checksum_offset = header_offset + volume_layout.log_record_checksum_offset;
    writeU32At(writer.buffer[payload_len_offset..checksum_offset], @intCast(payload_len));
    writeU64At(writer.buffer[checksum_offset .. header_offset + recordHeaderLen()], checksum);
}

pub fn recordHeaderLen() usize {
    return volume_layout.log_record_header_len;
}

pub fn readRecordHeader(reader: anytype) Error!RecordHeader {
    return .{
        .kind = try reader.readEnum(RecordKind),
        .payload_len = try reader.readU32(),
        .checksum = try reader.readU64(),
    };
}

fn writeU32At(buffer: []u8, value: u32) void {
    writeIntAt(u32, buffer, value);
}

fn writeU64At(buffer: []u8, value: u64) void {
    writeIntAt(u64, buffer, value);
}

fn writeIntAt(comptime T: type, buffer: []u8, value: T) void {
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
}
