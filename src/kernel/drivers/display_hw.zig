const std = @import("std");

pub const PROGRAMS_SCANOUT_HANDLE = true;
pub const PREFERS_ARC_ENGINE = true;
pub const COPIES_GOP_PIXELS = false;

var programmed_object_id: u64 = 0;
var programmed_bytes: u32 = 0;
var programmed_offset: u32 = 0;
var programmed_revision: u64 = 0;

pub fn programScanout(object_id: u64, offset: u32, bytes: u32) bool {
    return programScanoutRevision(object_id, offset, bytes, 1);
}

pub fn programScanoutRevision(object_id: u64, offset: u32, bytes: u32, revision: u64) bool {
    if (object_id == 0 or bytes == 0 or revision == 0) return false;
    programmed_object_id = object_id;
    programmed_offset = offset;
    programmed_bytes = bytes;
    programmed_revision = revision;
    return true;
}

pub fn programmedObjectId() u64 {
    return programmed_object_id;
}

pub fn programmedOffset() u32 {
    return programmed_offset;
}

pub fn programmedRevision() u64 {
    return programmed_revision;
}

pub fn gopPixelsWritten() u32 {
    return 0;
}

test "display hardware records a scanout handle" {
    try std.testing.expect(programScanoutRevision(7, 64, 8192, 3));
    try std.testing.expectEqual(@as(u64, 7), programmedObjectId());
    try std.testing.expectEqual(@as(u32, 64), programmedOffset());
    try std.testing.expectEqual(@as(u64, 3), programmedRevision());
    try std.testing.expectEqual(@as(u32, 0), gopPixelsWritten());
    try std.testing.expect(!COPIES_GOP_PIXELS);
}
