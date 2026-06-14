const std = @import("std");
const ascii = @import("../utils/ascii.zig");

pub const MAGIC: u32 = 0x5A43_5248;
pub const VERSION: u16 = 1;
pub const REDACTION_POLICY_VERSION: u16 = 1;
pub const MAX_REASON_BYTES: usize = 64;
pub const REDACTED_REPORT_BUFFER_BYTES: usize = 256;
const REDACTED_SUMMARY_BUFFER_BYTES: usize = 160;
const REDACTED_SUMMARY_TEST_BUFFER_BYTES: usize = 128;

pub const Error = error{
    BadMagic,
    BadVersion,
    BadChecksum,
    ReasonTooLong,
};

pub const CrashKind = enum(u8) {
    panic = 1,
    page_fault = 2,
    double_fault = 3,
    watchdog = 4,
    unknown = 255,
};

const SENSITIVE_MARKERS = [_][]const u8{
    "secret",
    "token",
    "capability",
    "private",
    "raw-memory",
    "raw memory",
    "object:",
    "workspace:",
};

pub const RedactionMetadata = struct {
    policy_version: u16 = REDACTION_POLICY_VERSION,
    redacted: bool = false,
    marker_mask: u32 = 0,
    reason_fingerprint: u64 = 0,
};

pub const Record = extern struct {
    magic: u32 = MAGIC,
    version: u16 = VERSION,
    kind: u8 = @intFromEnum(CrashKind.unknown),
    reason_len: u8 = 0,
    boot_id: u64 = 0,
    tick: u64 = 0,
    instruction_pointer: u64 = 0,
    stack_pointer: u64 = 0,
    reason: [MAX_REASON_BYTES]u8 = [_]u8{0} ** MAX_REASON_BYTES,
    checksum: u32 = 0,
};

pub fn init(
    kind: CrashKind,
    boot_id: u64,
    tick: u64,
    instruction_pointer: u64,
    stack_pointer: u64,
    reason: []const u8,
) Error!Record {
    if (reason.len > MAX_REASON_BYTES) return error.ReasonTooLong;
    var record = Record{
        .kind = @intFromEnum(kind),
        .reason_len = @intCast(reason.len),
        .boot_id = boot_id,
        .tick = tick,
        .instruction_pointer = instruction_pointer,
        .stack_pointer = stack_pointer,
    };
    @memcpy(record.reason[0..reason.len], reason);
    record.checksum = checksum(record);
    return record;
}

pub fn validate(record: Record) Error!void {
    if (record.magic != MAGIC) return error.BadMagic;
    if (record.version != VERSION) return error.BadVersion;
    const expected = checksum(.{
        .magic = record.magic,
        .version = record.version,
        .kind = record.kind,
        .reason_len = record.reason_len,
        .boot_id = record.boot_id,
        .tick = record.tick,
        .instruction_pointer = record.instruction_pointer,
        .stack_pointer = record.stack_pointer,
        .reason = record.reason,
        .checksum = 0,
    });
    if (record.checksum != expected) return error.BadChecksum;
}

pub fn redactedSummary(record: Record, buffer: []u8) []const u8 {
    const reason = record.reason[0..@min(record.reason_len, MAX_REASON_BYTES)];
    const reason_summary = if (reasonContainsSensitiveData(reason)) "[redacted]" else reason;
    return std.fmt.bufPrint(
        buffer,
        "kind={d} boot={d} tick={d} ip=0x{x} sp=0x{x} reason={s}",
        .{ record.kind, record.boot_id, record.tick, record.instruction_pointer, record.stack_pointer, reason_summary },
    ) catch "";
}

pub fn redactionMetadata(record: Record) RedactionMetadata {
    const reason = record.reason[0..@min(record.reason_len, MAX_REASON_BYTES)];
    const marker_mask = redactionMarkerMask(reason);
    return .{
        .redacted = marker_mask != 0,
        .marker_mask = marker_mask,
        .reason_fingerprint = fingerprintReason(reason),
    };
}

pub fn redactedReport(record: Record, buffer: []u8) []const u8 {
    var summary_buffer: [REDACTED_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const summary = redactedSummary(record, &summary_buffer);
    const metadata = redactionMetadata(record);
    return std.fmt.bufPrint(
        buffer,
        "{s} redaction_policy={d} redacted={s} marker_mask=0x{x} reason_fingerprint=0x{x}",
        .{
            summary,
            metadata.policy_version,
            if (metadata.redacted) "yes" else "no",
            metadata.marker_mask,
            metadata.reason_fingerprint,
        },
    ) catch "";
}

fn reasonContainsSensitiveData(reason: []const u8) bool {
    return redactionMarkerMask(reason) != 0;
}

fn redactionMarkerMask(reason: []const u8) u32 {
    var mask: u32 = 0;
    for (SENSITIVE_MARKERS, 0..) |marker, index| {
        if (ascii.containsIgnoreCase(reason, marker)) {
            mask |= @as(u32, 1) << @intCast(index);
        }
    }
    return mask;
}

fn fingerprintReason(reason: []const u8) u64 {
    var hash: u64 = 0xCBF2_9CE4_8422_2325;
    for (reason) |byte| {
        hash ^= @as(u64, byte);
        hash *%= 0x0000_0100_0000_01B3;
    }
    return hash;
}

fn checksum(record: Record) u32 {
    const bytes = std.mem.asBytes(&record);
    var value: u32 = 0x811C_9DC5;
    for (bytes[0 .. bytes.len - @sizeOf(u32)]) |byte| {
        value ^= byte;
        value *%= 0x0100_0193;
    }
    return value;
}

test "crash record validates and redacts to summary metadata" {
    const record = try init(.panic, 42, 100, 0x1234, 0x5678, "panic before ready");
    try validate(record);

    var buffer: [REDACTED_SUMMARY_TEST_BUFFER_BYTES]u8 = undefined;
    const summary = redactedSummary(record, buffer[0..]);
    try std.testing.expect(std.mem.indexOf(u8, summary, "boot=42") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "panic before ready") != null);
}

test "crash record redacts sensitive reason text by default" {
    const record = try init(.panic, 42, 100, 0x1234, 0x5678, "capability token secret=abc");

    var buffer: [REDACTED_SUMMARY_TEST_BUFFER_BYTES]u8 = undefined;
    const summary = redactedSummary(record, buffer[0..]);
    try std.testing.expect(std.mem.indexOf(u8, summary, "[redacted]") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "secret=abc") == null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "capability token") == null);

    const metadata = redactionMetadata(record);
    try std.testing.expect(metadata.redacted);
    try std.testing.expect(metadata.marker_mask != 0);
    try std.testing.expectEqual(metadata.reason_fingerprint, redactionMetadata(record).reason_fingerprint);

    var report_buffer: [REDACTED_REPORT_BUFFER_BYTES]u8 = undefined;
    const report = redactedReport(record, &report_buffer);
    try std.testing.expect(std.mem.indexOf(u8, report, "redacted=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "reason_fingerprint=0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "secret=abc") == null);
}

test "crash record rejects tampering" {
    var record = try init(.watchdog, 7, 11, 0x1234, 0x5678, "watchdog");
    record.tick += 1;
    try std.testing.expectError(error.BadChecksum, validate(record));
}

test "crash record bounds reason text" {
    const long_reason = [_]u8{'x'} ** (MAX_REASON_BYTES + 1);
    try std.testing.expectError(error.ReasonTooLong, init(.panic, 1, 2, 3, 4, long_reason[0..]));
}
