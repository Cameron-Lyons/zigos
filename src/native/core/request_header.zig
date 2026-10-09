const std = @import("std");
const abi = @import("abi.zig");

pub const HeaderError = error{
    UnexpectedOperation,
    UnsupportedAbiVersion,
    InvalidRequestFlags,
};

pub const SubjectTaskError = error{
    SubjectTaskRequired,
    SubjectTaskMismatch,
};

pub fn makeHeader(operation: u16, subject_task_id: u64) abi.RequestHeader {
    return .{
        .operation = operation,
        .subject_task_id = subject_task_id,
    };
}

pub fn validateHeader(header: abi.RequestHeader, expected_operation: u16) HeaderError!void {
    if (header.operation != expected_operation) return error.UnexpectedOperation;
    if (header.flags != 0) return error.InvalidRequestFlags;
    if (header.reserved != 0) return error.InvalidRequestFlags;
}

pub fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) SubjectTaskError!void {
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
    if (header.subject_task_id != task_id) {
        return error.SubjectTaskMismatch;
    }
}

test "request header helper validates operation and subject task" {
    const header = makeHeader(abi.opcode(.task_create), 9);

    try validateHeader(header, abi.opcode(.task_create));
    try validateSubjectTask(header, 9);

    try std.testing.expectError(error.UnexpectedOperation, validateHeader(header, abi.opcode(.endpoint_create)));
    try std.testing.expectError(error.SubjectTaskRequired, validateSubjectTask(makeHeader(abi.opcode(.task_create), 0), 9));
    try std.testing.expectError(error.SubjectTaskMismatch, validateSubjectTask(header, 10));
}

test "request header rejects reserved flags after opcode admission" {
    const valid = makeHeader(abi.opcode(.endpoint_close), 9);
    try std.testing.expectEqual(@as(u16, 0), valid.flags);
    for ([_]u16{ 1, 0x8000, 0xffff }) |flags| {
        var malformed = valid;
        malformed.flags = flags;
        try std.testing.expectError(error.InvalidRequestFlags, validateHeader(malformed, valid.operation));
        try std.testing.expectError(error.UnexpectedOperation, validateHeader(malformed, abi.opcode(.endpoint_send)));
    }
    try validateHeader(valid, valid.operation);
}

test "request header explicitly rejects every nonzero reserved-word bit" {
    const valid = makeHeader(abi.opcode(.task_create), 9);
    for (0..32) |bit| {
        var malformed = valid;
        malformed.reserved = @as(u32, 1) << @intCast(bit);
        try std.testing.expectError(error.InvalidRequestFlags, validateHeader(malformed, valid.operation));
        try std.testing.expectError(error.UnexpectedOperation, validateHeader(malformed, abi.opcode(.endpoint_create)));
    }
    try validateHeader(valid, valid.operation);
}
