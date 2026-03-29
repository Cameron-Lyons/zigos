const std = @import("std");
const crypto_hash = @import("crypto_hash.zig");
const native_util = @import("util.zig");
const copyText = native_util.copyText;

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


fn hashMeasurement(kind: MeasurementKind, label: []const u8, payload: []const u8) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "measurement-kind", kind);
    crypto_hash.updateBytes(&hasher, "label", label);
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn hashDigest(root: [32]u8, record: MeasurementRecord, index: usize) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "root", &root);
    crypto_hash.updateEnum(&hasher, "record-kind", record.kind);
    crypto_hash.updateBytes(&hasher, "record-label", record.labelSlice());
    crypto_hash.updateBytes(&hasher, "record-digest", &record.digest);
    crypto_hash.updateInt(&hasher, "record-index", index);
    return crypto_hash.finalize(&hasher);
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
