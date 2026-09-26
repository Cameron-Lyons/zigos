const std = @import("std");

// The pinned Zig CSPRNG erases consumed bytes and rekeys on every refill.
const Csprng = std.Random.DefaultCsprng;
pub const Seed = [Csprng.secret_seed_length]u8;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const RESEED_BYTES: usize = 1024 * 1024;
pub const MAX_WORD_ATTEMPTS: usize = 64;
pub const Error = error{ Unsupported, EntropyUnavailable, RepeatedEntropy, NotInitialized, AlreadyInitialized, RequestTooLarge };

// This is a bounded stuck-source check, not a substitute for the hardware's
// entropy-source health tests. Successful zero-valued words remain valid.
pub const SeedCollector = struct {
    previous_word: ?u64 = null,

    pub fn collect(self: *SeedCollector, source: anytype, out: *Seed) Error!void {
        errdefer std.crypto.secureZero(u8, out);
        for (0..@sizeOf(Seed) / @sizeOf(u64)) |index| {
            var word: u64 = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&word));
            var attempt: usize = 0;
            while (attempt < MAX_WORD_ATTEMPTS) : (attempt += 1) {
                if (source.readWord()) |value| {
                    word = value;
                    break;
                }
                source.pause();
            } else return error.EntropyUnavailable;
            if (self.previous_word == word) return error.RepeatedEntropy;
            self.previous_word = word;
            std.mem.writeInt(u64, out[index * 8 ..][0..8], word, .little);
        }
    }
};

// The caller serializes access. No clock, task identifier, saved checkpoint,
// or deterministic fixture is accepted as a production entropy source.
pub const Generator = struct {
    csprng: Csprng = undefined,
    remaining_bytes: usize = 0,
    initialized: bool = false,

    comptime {
        if (@sizeOf(@This()) > 544) @compileError("kernel random generator exceeds its bounded state budget");
        if (@sizeOf(Seed) != 32) @compileError("kernel randomness requires a 256-bit seed");
    }

    pub fn initialize(self: *Generator, source: anytype) Error!void {
        if (self.initialized) return error.AlreadyInitialized;
        try self.reseed(source);
    }

    pub fn fill(self: *Generator, source: anytype, out: []u8) Error!void {
        // Oversized requests are rejected without touching unbounded memory.
        if (out.len > MAX_REQUEST_BYTES) return error.RequestTooLarge;
        errdefer std.crypto.secureZero(u8, out);
        if (!self.initialized) return error.NotInitialized;
        if (out.len == 0) return;
        if (out.len > self.remaining_bytes) try self.reseed(source);
        self.csprng.fill(out);
        self.remaining_bytes -= out.len;
    }

    fn reseed(self: *Generator, source: anytype) Error!void {
        self.remaining_bytes = 0;
        var seed: Seed = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try source.readSeed(&seed);
        if (self.initialized) {
            self.csprng.addEntropy(&seed);
        } else {
            self.csprng = Csprng.init(seed);
            self.initialized = true;
        }
        self.remaining_bytes = RESEED_BYTES;
    }

    pub fn deinit(self: *Generator) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

const TestWords = struct {
    words: []const ?u64,
    reads: usize = 0,
    pauses: usize = 0,

    fn readWord(self: *TestWords) ?u64 {
        const index = self.reads;
        self.reads += 1;
        return if (index < self.words.len) self.words[index] else null;
    }
    fn pause(self: *TestWords) void {
        self.pauses += 1;
    }
};

const TestSeedSource = struct {
    collector: SeedCollector = .{},
    word: u64 = 1,
    seed_reads: usize = 0,
    failing: bool = false,

    fn readWord(self: *TestSeedSource) ?u64 {
        defer self.word += 1;
        return self.word;
    }
    fn pause(_: *TestSeedSource) void {}
    fn readSeed(self: *TestSeedSource, out: *Seed) Error!void {
        self.seed_reads += 1;
        if (self.failing) {
            @memset(out, 0xa5);
            return error.EntropyUnavailable;
        }
        try self.collector.collect(self, out);
    }
};

test "entropy collection honors availability and accepts successful zero words" {
    var source = TestWords{ .words = &.{ null, 0, null, 1, 2, 3 } };
    var collector = SeedCollector{};
    var seed: Seed = undefined;
    try collector.collect(&source, &seed);
    for (0..4) |index| try std.testing.expectEqual(@as(u64, index), std.mem.readInt(u64, seed[index * 8 ..][0..8], .little));
    try std.testing.expectEqual(@as(usize, 6), source.reads);
    try std.testing.expectEqual(@as(usize, 2), source.pauses);

    var delayed: [MAX_WORD_ATTEMPTS + 3]?u64 = @splat(null);
    for (0..4) |index| delayed[MAX_WORD_ATTEMPTS - 1 + index] = index;
    source = .{ .words = &delayed };
    collector = .{};
    try collector.collect(&source, &seed);
    try std.testing.expectEqual(@as(usize, MAX_WORD_ATTEMPTS + 3), source.reads);
    try std.testing.expectEqual(@as(usize, MAX_WORD_ATTEMPTS - 1), source.pauses);
}

test "entropy exhaustion is bounded and erases a partial seed" {
    var source = TestWords{ .words = &.{7} };
    var collector = SeedCollector{};
    var seed: Seed = @splat(0xa5);
    try std.testing.expectError(error.EntropyUnavailable, collector.collect(&source, &seed));
    try std.testing.expectEqual(@as(usize, MAX_WORD_ATTEMPTS + 1), source.reads);
    try std.testing.expectEqual(@as(usize, MAX_WORD_ATTEMPTS), source.pauses);
    try std.testing.expectEqualSlices(u8, &@as(Seed, @splat(0)), &seed);
}

test "entropy stuck-source rejection spans separate seeds" {
    var source = TestWords{ .words = &.{ 1, 2, 3, 4, 4, 5, 6, 7 } };
    var collector = SeedCollector{};
    var seed: Seed = undefined;
    try collector.collect(&source, &seed);
    try std.testing.expectError(error.RepeatedEntropy, collector.collect(&source, &seed));
    try std.testing.expectEqual(@as(usize, 5), source.reads);
    try std.testing.expectEqualSlices(u8, &@as(Seed, @splat(0)), &seed);
}

test "randomness requires seeding and bounds requests before touching memory" {
    var source = TestSeedSource{};
    var generator = Generator{};
    var out: [MAX_REQUEST_BYTES + 1]u8 = @splat(0xa5);
    try std.testing.expectError(error.NotInitialized, generator.fill(&source, out[0..32]));
    try std.testing.expect(std.mem.allEqual(u8, out[0..32], 0));
    source.failing = true;
    try std.testing.expectError(error.EntropyUnavailable, generator.initialize(&source));
    try std.testing.expect(!generator.initialized);
    source.failing = false;
    try generator.initialize(&source);
    try std.testing.expectError(error.AlreadyInitialized, generator.initialize(&source));
    try std.testing.expectError(error.RequestTooLarge, generator.fill(&source, &out));
    try std.testing.expectEqual(@as(u8, 0xa5), out[MAX_REQUEST_BYTES]);
    try std.testing.expectEqual(@as(usize, 2), source.seed_reads);
    generator.deinit();
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&generator), 0));
}

test "random output matches the pinned CSPRNG across bounded requests" {
    var source = TestSeedSource{};
    var generator = Generator{};
    defer generator.deinit();
    try generator.initialize(&source);
    var seed: Seed = undefined;
    for (0..4) |index| std.mem.writeInt(u64, seed[index * 8 ..][0..8], index + 1, .little);
    var reference = Csprng.init(seed);
    var actual: [997]u8 = undefined;
    var expected: [997]u8 = undefined;
    for (0..3) |_| {
        try generator.fill(&source, &actual);
        reference.fill(&expected);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
    try std.testing.expectEqual(@as(usize, 1), source.seed_reads);
}

test "mandatory reseeding fails closed and can recover without replaying output" {
    var source = TestSeedSource{};
    var generator = Generator{};
    defer generator.deinit();
    try generator.initialize(&source);
    var out: [MAX_REQUEST_BYTES]u8 = undefined;
    for (0..RESEED_BYTES / MAX_REQUEST_BYTES) |_| try generator.fill(&source, &out);
    try std.testing.expectEqual(@as(usize, 1), source.seed_reads);
    const previous = out;
    source.failing = true;
    try std.testing.expectError(error.EntropyUnavailable, generator.fill(&source, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
    try std.testing.expectEqual(@as(usize, 0), generator.remaining_bytes);
    try std.testing.expectError(error.EntropyUnavailable, generator.fill(&source, out[0..1]));
    source.failing = false;
    try generator.fill(&source, &out);
    try std.testing.expect(!std.mem.eql(u8, &previous, &out));
    try std.testing.expectEqual(@as(usize, 4), source.seed_reads);
}
