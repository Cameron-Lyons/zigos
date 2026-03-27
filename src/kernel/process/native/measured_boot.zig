const std = @import("std");

pub const MAX_RECORDS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;

pub const MeasurementKind = enum(u8) {
    kernel,
    base_image,
    critical_service,
    policy,
    driver_set,
};

pub const MeasurementRecord = struct {
    kind: MeasurementKind,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    digest: [32]u8,

    pub fn labelSlice(self: *const MeasurementRecord) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const BootRecord = struct {
    generation: u64,
    record_count: usize,
    records: [MAX_RECORDS]MeasurementRecord,
    root_digest: [32]u8,

    pub fn countKind(self: *const BootRecord, kind: MeasurementKind) usize {
        var count: usize = 0;
        for (self.records[0..self.record_count]) |record| {
            if (record.kind == kind) count += 1;
        }
        return count;
    }
};

pub const Error = error{
    RecordTableFull,
};

pub const Recorder = struct {
    generation: u64 = 0,
    records: [MAX_RECORDS]MeasurementRecord = [_]MeasurementRecord{zeroRecord()} ** MAX_RECORDS,
    record_count: usize = 0,

    pub fn init() Recorder {
        return .{};
    }

    pub fn begin(self: *Recorder, generation: u64) void {
        self.generation = generation;
        self.record_count = 0;
        self.records = [_]MeasurementRecord{zeroRecord()} ** MAX_RECORDS;
    }

    pub fn add(self: *Recorder, kind: MeasurementKind, label: []const u8, payload: []const u8) Error!void {
        if (self.record_count >= MAX_RECORDS) return error.RecordTableFull;
        self.records[self.record_count] = .{
            .kind = kind,
            .label_len = 0,
            .label = [_]u8{0} ** MAX_LABEL_BYTES,
            .digest = hashMeasurement(kind, label, payload),
        };
        self.records[self.record_count].label_len = copyText(&self.records[self.record_count].label, label);
        self.record_count += 1;
    }

    pub fn finalize(self: *const Recorder) BootRecord {
        var root = [_]u8{0} ** 32;
        for (self.records[0..self.record_count], 0..) |record, index| {
            root = hashDigest(root, record, index);
        }
        return .{
            .generation = self.generation,
            .record_count = self.record_count,
            .records = self.records,
            .root_digest = root,
        };
    }
};

fn zeroRecord() MeasurementRecord {
    return .{
        .kind = .kernel,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .digest = [_]u8{0} ** 32,
    };
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

fn hashMeasurement(kind: MeasurementKind, label: []const u8, payload: []const u8) [32]u8 {
    var digest = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0x6A09E667F3BCC909,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    };
    for (seeds, 0..) |seed, index| {
        var hash = seed;
        hash = hashByte(hash, @intFromEnum(kind));
        hash = hashBytes(hash, label);
        hash = hashBytes(hash, payload);
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn hashDigest(root: [32]u8, record: MeasurementRecord, index: usize) [32]u8 {
    var next = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    };
    for (seeds, 0..) |seed, word| {
        var hash = seed;
        hash = hashBytes(hash, &root);
        hash = hashBytes(hash, record.labelSlice());
        hash = hashBytes(hash, &record.digest);
        hash = hashByte(hash, @intCast(index));
        std.mem.writeInt(u64, next[word * 8 ..][0..8], hash, .little);
    }
    return next;
}

fn hashBytes(start: u64, bytes: []const u8) u64 {
    var hash = start;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
}

fn hashByte(start: u64, byte: u8) u64 {
    return hashBytes(start, &.{byte});
}

test "measured boot records kernel base image services policies and drivers" {
    var recorder = Recorder.init();
    recorder.begin(7);
    try recorder.add(.kernel, "kernel-zigos-native", "kernel.elf");
    try recorder.add(.base_image, "stable-b", "image:v2");
    try recorder.add(.critical_service, "storage_object", "healthy");
    try recorder.add(.policy, "notes-sync", "offline-first");
    try recorder.add(.driver_set, "storage+network+graphics", "driver-set");

    const boot = recorder.finalize();
    try std.testing.expectEqual(@as(u64, 7), boot.generation);
    try std.testing.expectEqual(@as(usize, 5), boot.record_count);
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.kernel));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.base_image));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.critical_service));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.policy));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.driver_set));
    try std.testing.expect(!std.mem.allEqual(u8, &boot.root_digest, 0));
}
