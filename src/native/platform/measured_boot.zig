const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_util = @import("../core/util.zig");
const supervisor_mod = @import("../session/supervisor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
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

    pub fn addCriticalServiceImage(
        self: *Recorder,
        service: *const supervisor_mod.ServiceRecord,
        image: *const userspace_loader.ImageRecord,
    ) Error!void {
        var payload = [_]u8{0} ** 72;
        @memcpy(payload[0..32], &image.file_sha256);
        std.mem.writeInt(u64, payload[32..40], image.id, .little);
        std.mem.writeInt(u64, payload[40..48], image.entry_point, .little);
        std.mem.writeInt(u64, payload[48..56], @intCast(image.byte_len), .little);
        std.mem.writeInt(u16, payload[56..58], @intFromEnum(service.class), .little);
        std.mem.writeInt(u16, payload[58..60], @intFromEnum(service.state), .little);
        std.mem.writeInt(u16, payload[60..62], service.restart_count, .little);
        std.mem.writeInt(u32, payload[62..66], image.contract_flags, .little);
        std.mem.writeInt(u16, payload[66..68], image.component_abi_version, .little);
        return self.add(.critical_service, image.bundleIdSlice(), payload[0..68]);
    }

    pub fn addDriverSet(
        self: *Recorder,
        label: []const u8,
        directory: *const driver_service.Directory,
    ) Error!void {
        var hasher = crypto_hash.init();
        var driver_count: usize = 0;
        for (directory.slots) |slot| {
            if (!slot.in_use) continue;
            driver_count += 1;
            const driver = &slot.driver;
            crypto_hash.updateInt(&hasher, "service-id", driver.service_id);
            crypto_hash.updateInt(&hasher, "owner-task-id", driver.owner_task_id);
            crypto_hash.updateInt(&hasher, "device-id", driver.device_id);
            crypto_hash.updateEnum(&hasher, "device-class", driver.device_class);
            crypto_hash.updateInt(&hasher, "authority-capability-id", driver.authority_capability_id);
            crypto_hash.updateInt(&hasher, "restart-generation", driver.restart_generation);
            crypto_hash.updateEnum(&hasher, "bootstrap-transport", driver.bootstrap_transport);
            crypto_hash.updateInt(&hasher, "dma-domain-id", driver.dma_domain_id);
            crypto_hash.updateEnum(&hasher, "dma-protection", driver.dma_protection);
            crypto_hash.updateBytes(&hasher, "signer", driver.signerSlice());
            crypto_hash.updateInt(&hasher, "dma-range-count", driver.dma_range_count);
            for (driver.dma_ranges[0..driver.dma_range_count]) |range| {
                crypto_hash.updateInt(&hasher, "dma-range-base", range.base);
                crypto_hash.updateInt(&hasher, "dma-range-length", range.length);
            }
        }
        crypto_hash.updateInt(&hasher, "driver-count", driver_count);
        const digest = crypto_hash.finalize(&hasher);
        return self.add(.driver_set, label, &digest);
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

test "critical service measurements bind launched userspace image artifacts" {
    const manifest = @import("../policy/manifest.zig");
    const principal = @import("../core/principal.zig");
    const userspace_manifest_signing = @import("../task/userspace_manifest_signing.zig");

    var catalog = userspace_loader.Catalog.init();
    var bundle = manifest.BundleManifest{
        .bundle_id = "zigos.system.storage-object",
        .display_name = "Storage Object Service",
        .publisher = "zigos.system",
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "workspace-storage", .entry = "zigos.object.workspace" },
        },
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);
    const image = try catalog.register(.{
        .bundle = bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
        },
        .role_tag = 0xA10C,
        .heartbeat_increment = 12,
        .contract_flags = 0x11,
    });

    var supervisor = supervisor_mod.Supervisor.init();
    const service = try supervisor.register(.storage_object, principal.PrincipalId{ .kind = .service, .serial = 40 });
    try std.testing.expect(supervisor.markHealthy(service.id, 3));

    var recorder = Recorder.init();
    recorder.begin(8);
    try recorder.addCriticalServiceImage(service, image);
    const boot = recorder.finalize();

    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.critical_service));
    try std.testing.expectEqualStrings("zigos.system.storage-object", boot.records[0].labelSlice());
    try std.testing.expect(!std.mem.allEqual(u8, &boot.records[0].digest, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &boot.root_digest, 0));
}

test "driver set measurements bind signed driver records and restart generation" {
    const capability = @import("../kernel_api/capability.zig");
    const manifest = @import("../policy/manifest.zig");

    var capabilities = capability.CapabilityTable.init();
    var directory = driver_service.Directory.init();
    const authority = try capabilities.mint(.{
        .holder = .{ .kind = .service, .serial = 2 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = driver_service.authorityTarget(100),
        .rights = driver_service.allowedRightsFor(.network_adapter),
        .scope = .{
            .task_id = 7,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.net.driver",
        .display_name = "Network Driver",
        .publisher = "zigos.dev",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-driver-key",
        },
    };
    _ = try directory.register(.{
        .service_id = 44,
        .owner_task_id = 7,
        .device_id = 100,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });

    var first_recorder = Recorder.init();
    first_recorder.begin(1);
    try first_recorder.addDriverSet("core-driver-set", &directory);
    const first = first_recorder.finalize();

    try std.testing.expect(directory.markRestarted(44));
    var second_recorder = Recorder.init();
    second_recorder.begin(1);
    try second_recorder.addDriverSet("core-driver-set", &directory);
    const second = second_recorder.finalize();

    try std.testing.expectEqual(@as(usize, 1), first.countKind(.driver_set));
    try std.testing.expectEqualStrings("core-driver-set", first.records[0].labelSlice());
    try std.testing.expect(!std.mem.eql(u8, &first.records[0].digest, &second.records[0].digest));
}
