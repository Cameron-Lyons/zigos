const std = @import("std");
const parser = @import("parser.zig");

pub const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;

pub const Error = error{
    ArgumentTooLong,
};

pub fn containsWildcardChars(text: []const u8) bool {
    for (text) |char| {
        if (char == '*' or char == '?') return true;
    }
    return false;
}

pub fn wildcardMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_idx: usize = 0;
    var text_idx: usize = 0;
    var star_idx: ?usize = null;
    var match_after_star: usize = 0;

    while (text_idx < text.len) {
        if (pattern_idx < pattern.len and (pattern[pattern_idx] == '?' or pattern[pattern_idx] == text[text_idx])) {
            pattern_idx += 1;
            text_idx += 1;
        } else if (pattern_idx < pattern.len and pattern[pattern_idx] == '*') {
            star_idx = pattern_idx;
            pattern_idx += 1;
            match_after_star = text_idx;
        } else if (star_idx) |star| {
            pattern_idx = star + 1;
            match_after_star += 1;
            text_idx = match_after_star;
        } else {
            return false;
        }
    }

    while (pattern_idx < pattern.len and pattern[pattern_idx] == '*') : (pattern_idx += 1) {}
    return pattern_idx == pattern.len;
}

pub fn joinPath(base: []const u8, component: []const u8, out: *[MAX_COMMAND_LENGTH]u8) Error![]const u8 {
    @memset(out, 0);
    if (base.len == 1 and base[0] == '/') {
        if (component.len + 1 >= out.len) return error.ArgumentTooLong;
        out[0] = '/';
        @memcpy(out[1 .. 1 + component.len], component);
        return out[0 .. 1 + component.len];
    }

    if (base.len + 1 + component.len >= out.len) return error.ArgumentTooLong;
    @memcpy(out[0..base.len], base);
    out[base.len] = '/';
    @memcpy(out[base.len + 1 .. base.len + 1 + component.len], component);
    return out[0 .. base.len + 1 + component.len];
}

const TestRng = struct {
    state: u64,

    fn next(self: *TestRng) u64 {
        self.state = self.state *% 2862933555777941757 +% 3037000493;
        return self.state;
    }

    fn choose(self: *TestRng, limit: usize) usize {
        if (limit == 0) return 0;
        return @intCast(self.next() % limit);
    }
};

fn randomGlobText(rng: *TestRng, buffer: []u8, allow_wildcards: bool) []const u8 {
    const alphabet = if (allow_wildcards)
        "abcdefghijklmnopqrstuvwxyz0123456789*?.-_/"
    else
        "abcdefghijklmnopqrstuvwxyz0123456789.-_/";
    const len = rng.choose(buffer.len + 1);
    for (buffer[0..len]) |*byte| {
        byte.* = alphabet[rng.choose(alphabet.len)];
    }
    return buffer[0..len];
}

fn referenceWildcardMatch(pattern: []const u8, text: []const u8) bool {
    var dp: [17][17]bool = [_][17]bool{[_]bool{false} ** 17} ** 17;
    dp[0][0] = true;

    var pattern_idx: usize = 1;
    while (pattern_idx <= pattern.len) : (pattern_idx += 1) {
        if (pattern[pattern_idx - 1] == '*') {
            dp[pattern_idx][0] = dp[pattern_idx - 1][0];
        }
    }

    pattern_idx = 1;
    while (pattern_idx <= pattern.len) : (pattern_idx += 1) {
        var text_idx: usize = 1;
        while (text_idx <= text.len) : (text_idx += 1) {
            const token = pattern[pattern_idx - 1];
            if (token == '*') {
                dp[pattern_idx][text_idx] = dp[pattern_idx - 1][text_idx] or dp[pattern_idx][text_idx - 1];
            } else if (token == '?' or token == text[text_idx - 1]) {
                dp[pattern_idx][text_idx] = dp[pattern_idx - 1][text_idx - 1];
            }
        }
    }

    return dp[pattern.len][text.len];
}

test "containsWildcardChars spots glob tokens" {
    try std.testing.expect(!containsWildcardChars("plain"));
    try std.testing.expect(containsWildcardChars("*.zig"));
    try std.testing.expect(containsWildcardChars("file?"));
}

test "wildcardMatch handles exact star and question patterns" {
    try std.testing.expect(wildcardMatch("file.txt", "file.txt"));
    try std.testing.expect(wildcardMatch("*.zig", "shell.zig"));
    try std.testing.expect(wildcardMatch("f?le.*", "file.txt"));
    try std.testing.expect(!wildcardMatch("*.zig", "shell.c"));
    try std.testing.expect(!wildcardMatch("ab?d", "abd"));
}

test "joinPath preserves root and nested paths" {
    var buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
    try std.testing.expectEqualStrings("/tmp", try joinPath("/", "tmp", &buffer));
    try std.testing.expectEqualStrings("/usr/bin", try joinPath("/usr", "bin", &buffer));
}

test "joinPath rejects oversized output" {
    var buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
    var component = [_]u8{'x'} ** (MAX_COMMAND_LENGTH - 1);
    try std.testing.expectError(error.ArgumentTooLong, joinPath("/", component[0..], &buffer));
}

test "wildcardMatch agrees with reference matcher on randomized corpus" {
    var rng = TestRng{ .state = 0xCAFEBABE12345678 };
    var pattern_buf: [16]u8 = undefined;
    var text_buf: [16]u8 = undefined;

    for (0..2048) |_| {
        const pattern = randomGlobText(&rng, &pattern_buf, true);
        const text = randomGlobText(&rng, &text_buf, false);
        try std.testing.expectEqual(referenceWildcardMatch(pattern, text), wildcardMatch(pattern, text));
    }
}
