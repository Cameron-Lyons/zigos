const std = @import("std");
const parser = @import("parser/pipeline.zig");

pub const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;

pub const Error = error{
    ArgumentTooLong,
};

pub const CompiledPattern = struct {
    storage: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
    len: usize = 0,
    literal_prefix_len: usize = 0,
    literal_suffix_len: usize = 0,
    has_wildcards: bool = false,

    pub fn init(pattern: []const u8) Error!CompiledPattern {
        if (pattern.len >= MAX_COMMAND_LENGTH) return error.ArgumentTooLong;

        var compiled = CompiledPattern{};
        var out_len: usize = 0;
        var previous_was_star = false;

        for (pattern) |char| {
            if (char == '*') {
                if (previous_was_star) continue;
                previous_was_star = true;
            } else {
                previous_was_star = false;
            }

            compiled.storage[out_len] = char;
            compiled.has_wildcards = compiled.has_wildcards or char == '*' or char == '?';
            out_len += 1;
        }

        compiled.len = out_len;
        compiled.literal_prefix_len = literalPrefixLen(compiled.slice());
        compiled.literal_suffix_len = literalSuffixLen(compiled.slice(), compiled.literal_prefix_len);
        return compiled;
    }

    pub fn slice(self: *const CompiledPattern) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn matches(self: *const CompiledPattern, text: []const u8) bool {
        const pattern = self.slice();
        if (!self.has_wildcards) {
            return std.mem.eql(u8, pattern, text);
        }

        if (text.len < self.literal_prefix_len + self.literal_suffix_len) return false;
        if (self.literal_prefix_len > 0 and !std.mem.eql(u8, pattern[0..self.literal_prefix_len], text[0..self.literal_prefix_len])) {
            return false;
        }

        if (self.literal_suffix_len > 0) {
            const pattern_suffix_start = pattern.len - self.literal_suffix_len;
            const text_suffix_start = text.len - self.literal_suffix_len;
            if (!std.mem.eql(u8, pattern[pattern_suffix_start..], text[text_suffix_start..])) {
                return false;
            }
        }

        const pattern_end = pattern.len - self.literal_suffix_len;
        const text_end = text.len - self.literal_suffix_len;
        return wildcardMatchSlice(pattern[self.literal_prefix_len..pattern_end], text[self.literal_prefix_len..text_end]);
    }
};

pub fn PatternCache(comptime capacity: usize) type {
    comptime {
        if (capacity == 0) {
            @compileError("PatternCache capacity must be non-zero");
        }
    }

    return struct {
        const Self = @This();

        const Entry = struct {
            valid: bool = false,
            source_len: usize = 0,
            source: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
            compiled: CompiledPattern = .{},
        };

        entries: [capacity]Entry = [_]Entry{Entry{}} ** capacity,
        next: usize = 0,

        pub fn getOrCompile(self: *Self, pattern: []const u8) Error!*const CompiledPattern {
            for (&self.entries) |*entry| {
                if (!entry.valid) continue;
                if (std.mem.eql(u8, entry.source[0..entry.source_len], pattern)) {
                    return &entry.compiled;
                }
            }

            const entry = &self.entries[self.next % capacity];
            entry.compiled = try CompiledPattern.init(pattern);
            @memset(&entry.source, 0);
            @memcpy(entry.source[0..pattern.len], pattern);
            entry.source_len = pattern.len;
            entry.valid = true;
            self.next += 1;
            return &entry.compiled;
        }
    };
}

pub fn containsWildcardChars(text: []const u8) bool {
    for (text) |char| {
        if (char == '*' or char == '?') return true;
    }
    return false;
}

pub fn wildcardMatch(pattern: []const u8, text: []const u8) bool {
    var compiled = CompiledPattern.init(pattern) catch return false;
    return compiled.matches(text);
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

fn literalPrefixLen(pattern: []const u8) usize {
    var idx: usize = 0;
    while (idx < pattern.len) : (idx += 1) {
        if (pattern[idx] == '*' or pattern[idx] == '?') break;
    }
    return idx;
}

fn literalSuffixLen(pattern: []const u8, prefix_len: usize) usize {
    var len: usize = 0;
    var idx = pattern.len;
    while (idx > prefix_len) {
        const char = pattern[idx - 1];
        if (char == '*' or char == '?') break;
        len += 1;
        idx -= 1;
    }
    return len;
}

fn wildcardMatchSlice(pattern: []const u8, text: []const u8) bool {
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

test "compiled patterns normalize repeated stars and preserve matches" {
    var compiled = try CompiledPattern.init("src//**/*.zig");
    try std.testing.expectEqualStrings("src//*/*.zig", compiled.slice());
    try std.testing.expect(compiled.matches("src//shell/main.zig"));
    try std.testing.expect(!compiled.matches("src//shell/main.c"));
}

test "pattern cache reuses compiled entries" {
    var cache = PatternCache(2){};
    const first = try cache.getOrCompile("*.zig");
    const second = try cache.getOrCompile("*.zig");
    try std.testing.expect(first == second);
    try std.testing.expect(first.matches("shell.zig"));
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
