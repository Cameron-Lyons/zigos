const std = @import("std");
const abi = @import("abi.zig");

pub const HeaderError = error{
    UnexpectedOperation,
    UnsupportedAbiVersion,
};

pub const SubjectTaskError = error{
    SubjectTaskRequired,
    SubjectTaskMismatch,
};

pub fn makeHeader(operation: u16, correlation_id: u64, subject_task_id: u64) abi.RequestHeader {
    return .{
        .operation = operation,
        .correlation_id = correlation_id,
        .subject_task_id = subject_task_id,
    };
}

pub fn validateHeader(header: abi.RequestHeader, expected_operation: u16) HeaderError!void {
    if (header.version != abi.ABI_VERSION) return error.UnsupportedAbiVersion;
    if (header.operation != expected_operation) return error.UnexpectedOperation;
}

pub fn validateSubjectTask(header: abi.RequestHeader, task_id: u64) SubjectTaskError!void {
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
    if (header.subject_task_id != task_id) {
        return error.SubjectTaskMismatch;
    }
}

test "request header helper validates version operation and subject task" {
    const header = makeHeader(abi.opcode(.task_create), 7, 9);

    try validateHeader(header, abi.opcode(.task_create));
    try validateSubjectTask(header, 9);

    try std.testing.expectError(error.UnexpectedOperation, validateHeader(header, abi.opcode(.endpoint_create)));
    try std.testing.expectError(error.SubjectTaskRequired, validateSubjectTask(makeHeader(abi.opcode(.task_create), 7, 0), 9));
    try std.testing.expectError(error.SubjectTaskMismatch, validateSubjectTask(header, 10));
    try std.testing.expectError(error.UnsupportedAbiVersion, validateHeader(.{
        .version = abi.ABI_VERSION + 1,
        .operation = header.operation,
        .correlation_id = header.correlation_id,
        .subject_task_id = header.subject_task_id,
    }, header.operation));
}
