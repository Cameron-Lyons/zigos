const std = @import("std");

pub fn contains(log: []const u8, marker: []const u8) bool {
    return std.mem.indexOf(u8, log, marker) != null;
}

pub fn containsInsensitive(log: []const u8, marker: []const u8) bool {
    if (marker.len > log.len) return false;
    for (0..log.len - marker.len + 1) |offset| {
        if (std.ascii.eqlIgnoreCase(log[offset..][0..marker.len], marker)) return true;
    }
    return false;
}

pub fn exact(log: []const u8, marker: []const u8) bool {
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| if (std.mem.eql(u8, line, marker)) return true;
    return false;
}

pub fn countPrefix(log: []const u8, prefix: []const u8) usize {
    var result: usize = 0;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| if (std.mem.startsWith(u8, line, prefix)) {
        result += 1;
    };
    return result;
}

pub fn countContaining(log: []const u8, marker: []const u8) usize {
    var result: usize = 0;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| if (contains(line, marker)) {
        result += 1;
    };
    return result;
}

pub fn field(log: []const u8, prefix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) {
            var words = std.mem.tokenizeAny(u8, line[prefix.len..], " \t\r");
            return words.next();
        }
    }
    return null;
}

pub fn healthy(log: []const u8, failure: []const u8) bool {
    return log.len != 0 and !containsInsensitive(log, "panic") and
        !containsInsensitive(log, "System Halted") and !containsInsensitive(log, failure);
}

pub fn stackHeadroom(log: []const u8, marker: []const u8) !void {
    var used: ?u64 = null;
    var capacity: ?u64 = null;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (!contains(line, marker)) continue;
        used = null;
        capacity = null;
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        while (words.next()) |word| {
            if (std.mem.startsWith(u8, word, "used_bytes=")) used = try std.fmt.parseInt(u64, word[11..], 10);
            if (std.mem.startsWith(u8, word, "capacity_bytes=")) capacity = try std.fmt.parseInt(u64, word[15..], 10);
        }
    }
    const u = used orelse return error.MissingStackWatermark;
    const c = capacity orelse return error.MissingStackWatermark;
    if (@as(u128, u) * 4 > @as(u128, c) * 3) return error.InsufficientStackHeadroom;
}

pub fn bootInstance(log: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "ZIGOS:BOOT:INSTANCE")) continue;
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next().?, "ZIGOS:BOOT:INSTANCE")) return error.InvalidBootInstance;
        const instance = words.next() orelse return error.InvalidBootInstance;
        if (found != null or words.next() != null or instance.len != 32 or
            std.mem.indexOfNone(u8, instance, "0123456789abcdef") != null or
            std.mem.indexOfNone(u8, instance, "0") == null) return error.InvalidBootInstance;
        found = instance;
    }
    return found orelse error.MissingBootInstance;
}

pub fn ordered(log: []const u8, group: []const []const u8) !void {
    var previous: ?usize = null;
    for (group) |marker| {
        const position = std.mem.indexOf(u8, log, marker) orelse return error.MissingMarker;
        if (previous) |last| {
            // Distinct markers on one line must not count as ordered proofs.
            if (position <= last or std.mem.indexOfScalar(u8, log[last..position], '\n') == null)
                return error.MarkersOutOfOrder;
        }
        previous = position;
    }
}

test "exact and prefix proof checks distinguish forged suffixes and duplicates" {
    const bytes = "PROOF:VERIFIED forged\nPROOF:VERIFIED\nPROOF:FAILED\n";
    try std.testing.expect(exact(bytes, "PROOF:VERIFIED"));
    try std.testing.expect(!exact("PROOF:VERIFIED forged\n", "PROOF:VERIFIED"));
    try std.testing.expectEqual(@as(usize, 3), countPrefix(bytes, "PROOF:"));
}

test "boot instance rejects missing, repeated, zero, and malformed ids" {
    const valid = "ZIGOS:BOOT:INSTANCE 0123456789abcdef0123456789abcdef\n";
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", try bootInstance(valid));
    try std.testing.expectError(error.InvalidBootInstance, bootInstance(valid ++ valid));
    try std.testing.expectError(error.InvalidBootInstance, bootInstance("ZIGOS:BOOT:INSTANCE 00000000000000000000000000000000\n"));
    try std.testing.expectError(error.InvalidBootInstance, bootInstance("ZIGOS:BOOT:INSTANCEBAD 0123456789abcdef0123456789abcdef\n"));
}

test "stack headroom gate handles boundary and overflowing metrics" {
    try stackHeadroom("PEAK used_bytes=75 capacity_bytes=100", "PEAK");
    try std.testing.expectError(error.InsufficientStackHeadroom, stackHeadroom("PEAK used_bytes=76 capacity_bytes=100", "PEAK"));
    try std.testing.expectError(error.InsufficientStackHeadroom, stackHeadroom("PEAK used_bytes=18446744073709551615 capacity_bytes=100", "PEAK"));
}

test "ordered proof rejects reversed or same-line evidence" {
    try ordered("START\nBEFORE\nAFTER\n", &.{ "START", "BEFORE", "AFTER" });
    try std.testing.expectError(error.MarkersOutOfOrder, ordered("AFTER\nBEFORE\n", &.{ "BEFORE", "AFTER" }));
    try std.testing.expectError(error.MarkersOutOfOrder, ordered("BEFORE AFTER\n", &.{ "BEFORE", "AFTER" }));
}
