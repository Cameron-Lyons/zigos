const std = @import("std");
const impl = @import("proofs/runtime_negative_proofs.zig");

pub const runAndPrint = impl.runAndPrint;
pub const runFreestandingAndPrint = impl.runFreestandingAndPrint;
pub const processIsolationBlocksForeignSharedMemory = impl.processIsolationBlocksForeignSharedMemory;
pub const syscallSubjectSpoofingIsRejected = impl.syscallSubjectSpoofingIsRejected;
pub const rawNetworkSendBypassIsDenied = impl.rawNetworkSendBypassIsDenied;
pub const driverAuthorityEscapeIsRejected = impl.driverAuthorityEscapeIsRejected;
pub const rebootGrantAndRevocationStatePersists = impl.rebootGrantAndRevocationStatePersists;

test "runtime negative proofs reject modeled bypasses" {
    try std.testing.expect(processIsolationBlocksForeignSharedMemory());
    try std.testing.expect(syscallSubjectSpoofingIsRejected());
    try std.testing.expect(rawNetworkSendBypassIsDenied());
    try std.testing.expect(driverAuthorityEscapeIsRejected());
    try std.testing.expect(rebootGrantAndRevocationStatePersists());
}
