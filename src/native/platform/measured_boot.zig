const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const policy_manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const supervisor_mod = @import("../session/supervisor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const copyText = native_util.copyText;

pub const MAX_RECORDS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MEASUREMENT_KIND_COUNT: usize = 5;
pub const MAX_MANIFEST_ENTRIES: usize = MAX_RECORDS;
pub const state_workspace_label = "system-measured-boot";

const state_entry_path = "state/latest";
const state_magic = "ZMB1";
const state_version: u16 = 1;

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

pub const ArtifactManifestEntry = MeasurementRecord;

pub const ArtifactManifest = struct {
    generation: u64,
    entry_count: usize,
    entries: [MAX_MANIFEST_ENTRIES]ArtifactManifestEntry,

    pub fn init(generation: u64) ArtifactManifest {
        return .{
            .generation = generation,
            .entry_count = 0,
            .entries = [_]ArtifactManifestEntry{zeroRecord()} ** MAX_MANIFEST_ENTRIES,
        };
    }

    pub fn add(self: *ArtifactManifest, kind: MeasurementKind, label: []const u8, payload: []const u8) Error!void {
        if (self.entry_count >= MAX_MANIFEST_ENTRIES) return error.RecordTableFull;
        self.entries[self.entry_count] = .{
            .kind = kind,
            .label_len = 0,
            .label = [_]u8{0} ** MAX_LABEL_BYTES,
            .digest = hashMeasurement(kind, label, payload),
        };
        self.entries[self.entry_count].label_len = copyText(&self.entries[self.entry_count].label, label);
        self.entry_count += 1;
    }

    pub fn addUserspaceServiceImage(
        self: *ArtifactManifest,
        image: *const userspace_loader.ImageRecord,
    ) Error!void {
        var payload = [_]u8{0} ** 64;
        @memcpy(payload[0..32], &image.file_sha256);
        std.mem.writeInt(u64, payload[32..40], image.id, .little);
        std.mem.writeInt(u64, payload[40..48], image.entry_point, .little);
        std.mem.writeInt(u64, payload[48..56], @intCast(image.byte_len), .little);
        std.mem.writeInt(u32, payload[56..60], image.contract_flags, .little);
        std.mem.writeInt(u16, payload[60..62], image.component_abi_version, .little);
        return self.add(.critical_service, image.bundleIdSlice(), payload[0..62]);
    }

    pub fn countKind(self: *const ArtifactManifest, kind: MeasurementKind) usize {
        var count: usize = 0;
        for (self.entries[0..self.entry_count]) |entry| {
            if (entry.kind == kind) count += 1;
        }
        return count;
    }
};

pub const SignedArtifactManifest = struct {
    manifest: ArtifactManifest,
    signature: policy_manifest.Signature,

    pub fn verify(self: *const SignedArtifactManifest) bool {
        var payload_buffer: [2048]u8 = undefined;
        const payload = encodeArtifactManifest(self.manifest, &payload_buffer) catch return false;
        return signing.verify(self.signature, payload) and requiredArtifactShape(&self.manifest);
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

pub const BootSummary = struct {
    generation: u64,
    record_count: u16,
    kind_counts: [MEASUREMENT_KIND_COUNT]u16,
    root_digest: [32]u8,

    pub fn fromRecord(boot: *const BootRecord) BootSummary {
        var summary = BootSummary{
            .generation = boot.generation,
            .record_count = @intCast(boot.record_count),
            .kind_counts = [_]u16{0} ** MEASUREMENT_KIND_COUNT,
            .root_digest = boot.root_digest,
        };
        for (boot.records[0..boot.record_count]) |record| {
            summary.kind_counts[@intFromEnum(record.kind)] += 1;
        }
        return summary;
    }

    pub fn countKind(self: *const BootSummary, kind: MeasurementKind) u16 {
        return self.kind_counts[@intFromEnum(kind)];
    }

    pub fn matchesRecord(self: *const BootSummary, boot: *const BootRecord) bool {
        const other = BootSummary.fromRecord(boot);
        return self.eql(other);
    }

    pub fn eql(self: *const BootSummary, other: BootSummary) bool {
        return self.generation == other.generation and
            self.record_count == other.record_count and
            std.mem.eql(u16, &self.kind_counts, &other.kind_counts) and
            std.mem.eql(u8, &self.root_digest, &other.root_digest);
    }
};

pub const BootComparison = struct {
    previous: ?BootSummary,
    current: BootSummary,
    same_root_digest: bool,
    same_generation: bool,
    same_record_shape: bool,

    pub fn changed(self: *const BootComparison) bool {
        return self.previous != null and
            (!self.same_root_digest or !self.same_generation or !self.same_record_shape);
    }
};

pub const Error = error{
    RecordTableFull,
    CorruptState,
    StateTooLarge,
    UnsupportedStateVersion,
    ManifestTooLarge,
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

pub fn signArtifactManifest(
    artifact_manifest: ArtifactManifest,
    identity: signing.SignerIdentity,
) anyerror!SignedArtifactManifest {
    var payload_buffer: [2048]u8 = undefined;
    const payload = try encodeArtifactManifest(artifact_manifest, &payload_buffer);
    return .{
        .manifest = artifact_manifest,
        .signature = try signing.sign(identity, payload),
    };
}

pub fn verifySignedArtifactManifest(signed_manifest: *const SignedArtifactManifest) bool {
    return signed_manifest.verify();
}

pub fn bootRecordMatchesManifest(boot: *const BootRecord, artifact_manifest: *const ArtifactManifest) bool {
    if (boot.generation != artifact_manifest.generation) return false;
    if (boot.record_count != artifact_manifest.entry_count) return false;
    var matched = [_]bool{false} ** MAX_MANIFEST_ENTRIES;
    for (boot.records[0..boot.record_count]) |record| {
        var found = false;
        for (artifact_manifest.entries[0..artifact_manifest.entry_count], 0..) |entry, index| {
            if (matched[index]) continue;
            if (record.kind != entry.kind) continue;
            if (!std.mem.eql(u8, record.labelSlice(), entry.labelSlice())) continue;
            if (!std.mem.eql(u8, &record.digest, &entry.digest)) continue;
            matched[index] = true;
            found = true;
            break;
        }
        if (!found) return false;
    }
    return true;
}

pub const MeasurementJournal = struct {
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    state_signer: signing.SignerIdentity,
    workspace_id: u64,
    loaded_existing_state: bool = false,
    latest_version_id: u64 = 0,
    previous_summary: ?BootSummary = null,
    latest_summary: ?BootSummary = null,

    pub fn init(
        storage: *storage_service.Service,
        owner: principal.PrincipalId,
        state_signer: signing.SignerIdentity,
    ) anyerror!MeasurementJournal {
        const workspace_record = storage.findWorkspace(owner, state_workspace_label) orelse
            try storage.createWorkspace(.{
                .owner = owner,
                .label = state_workspace_label,
            });

        var journal = MeasurementJournal{
            .storage = storage,
            .owner = owner,
            .state_signer = state_signer,
            .workspace_id = workspace_record.id,
        };

        if (storage.resolve(workspace_record.id, state_entry_path)) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            journal.latest_summary = try decodeSummary(try storage.versionPayload(version));
            journal.loaded_existing_state = true;
            journal.latest_version_id = entry.version_id;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        }

        return journal;
    }

    pub fn record(self: *MeasurementJournal, boot: BootRecord, tick: u64) anyerror!BootComparison {
        const previous = self.latest_summary;
        const current = BootSummary.fromRecord(&boot);
        var comparison = compareSummaries(previous, current);
        try self.persist(current, tick);
        self.previous_summary = previous;
        self.latest_summary = current;
        comparison.previous = previous;
        comparison.current = current;
        return comparison;
    }

    pub fn hasPreviousMeasurement(self: *const MeasurementJournal) bool {
        return self.latest_summary != null;
    }

    pub fn latestMatches(self: *const MeasurementJournal, boot: *const BootRecord) bool {
        const latest = self.latest_summary orelse return false;
        return latest.matchesRecord(boot);
    }

    fn persist(self: *MeasurementJournal, summary: BootSummary, tick: u64) anyerror!void {
        var payload_buffer: [128]u8 = undefined;
        const payload = try encodeSummary(summary, &payload_buffer);
        const existing_entry = self.storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const result = try self.storage.putVersion(.{
            .preferred_object_id = stateObjectId(),
            .object_type = .document,
            .payload = payload,
            .metadata = try object_store.signMetadata(
                self.state_signer,
                "measured-boot-state",
                "application/zigos-measured-boot",
                .document,
                payload,
                tick,
            ),
            .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
        });
        try self.storage.beginTransaction(self.workspace_id);
        try self.storage.stagePut(self.workspace_id, state_entry_path, result.object_id, result.version_id, .document);
        _ = try self.storage.commit(self.workspace_id, tick);
        self.latest_version_id = result.version_id;
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

fn compareSummaries(previous: ?BootSummary, current: BootSummary) BootComparison {
    const same_root_digest = if (previous) |summary|
        std.mem.eql(u8, &summary.root_digest, &current.root_digest)
    else
        false;
    const same_generation = if (previous) |summary|
        summary.generation == current.generation
    else
        false;
    const same_record_shape = if (previous) |summary|
        summary.record_count == current.record_count and std.mem.eql(u16, &summary.kind_counts, &current.kind_counts)
    else
        false;
    return .{
        .previous = previous,
        .current = current,
        .same_root_digest = same_root_digest,
        .same_generation = same_generation,
        .same_record_shape = same_record_shape,
    };
}

fn requiredArtifactShape(artifact_manifest: *const ArtifactManifest) bool {
    return artifact_manifest.countKind(.kernel) == 1 and
        artifact_manifest.countKind(.base_image) == 1 and
        artifact_manifest.countKind(.critical_service) >= 4 and
        artifact_manifest.countKind(.policy) == 1 and
        artifact_manifest.countKind(.driver_set) == 1;
}

fn encodeArtifactManifest(artifact_manifest: ArtifactManifest, buffer: []u8) Error![]const u8 {
    var offset: usize = 0;
    offset = appendManifestFormat(buffer, offset, "ZAM1|g={d}|n={d}", .{
        artifact_manifest.generation,
        artifact_manifest.entry_count,
    }) catch return error.ManifestTooLarge;
    for (artifact_manifest.entries[0..artifact_manifest.entry_count]) |entry| {
        offset = appendManifestFormat(buffer, offset, "|{s}:{s}:", .{
            @tagName(entry.kind),
            entry.labelSlice(),
        }) catch return error.ManifestTooLarge;
        offset = appendHexDigest(buffer, offset, &entry.digest) catch return error.ManifestTooLarge;
    }
    return buffer[0..offset];
}

fn appendManifestFormat(buffer: []u8, offset: usize, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!usize {
    const text = std.fmt.bufPrint(buffer[offset..], fmt, args) catch return error.NoSpaceLeft;
    return offset + text.len;
}

fn appendHexDigest(buffer: []u8, offset: usize, digest: *const [32]u8) error{NoSpaceLeft}!usize {
    const hex = "0123456789abcdef";
    if (offset + 64 > buffer.len) return error.NoSpaceLeft;
    var cursor = offset;
    for (digest.*) |byte| {
        buffer[cursor] = hex[byte >> 4];
        buffer[cursor + 1] = hex[byte & 0x0f];
        cursor += 2;
    }
    return cursor;
}

fn encodeSummary(summary: BootSummary, buffer: []u8) Error![]const u8 {
    var writer = CursorWriter{ .buffer = buffer };
    try writer.writeBytes(state_magic);
    try writer.writeU16(state_version);
    try writer.writeU64(summary.generation);
    try writer.writeU16(summary.record_count);
    try writer.writeBytes(&summary.root_digest);
    for (summary.kind_counts) |count| {
        try writer.writeU16(count);
    }
    return buffer[0..writer.offset];
}

fn decodeSummary(payload: []const u8) Error!BootSummary {
    var reader = CursorReader{ .buffer = payload };
    var magic_buffer: [state_magic.len]u8 = undefined;
    try reader.readBytes(&magic_buffer);
    if (!std.mem.eql(u8, &magic_buffer, state_magic)) return error.CorruptState;
    if ((try reader.readU16()) != state_version) return error.UnsupportedStateVersion;

    var summary = BootSummary{
        .generation = try reader.readU64(),
        .record_count = try reader.readU16(),
        .kind_counts = [_]u16{0} ** MEASUREMENT_KIND_COUNT,
        .root_digest = [_]u8{0} ** 32,
    };
    if (summary.record_count > MAX_RECORDS) return error.CorruptState;
    try reader.readBytes(&summary.root_digest);
    var total_count: u16 = 0;
    for (&summary.kind_counts) |*count| {
        count.* = try reader.readU16();
        total_count += count.*;
    }
    if (total_count != summary.record_count) return error.CorruptState;
    if (!reader.eof()) return error.CorruptState;
    return summary;
}

const CursorWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn writeBytes(self: *CursorWriter, bytes: []const u8) Error!void {
        if (self.offset + bytes.len > self.buffer.len) return error.StateTooLarge;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeU16(self: *CursorWriter, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }

    fn writeU64(self: *CursorWriter, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.writeBytes(&bytes);
    }
};

const CursorReader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn readBytes(self: *CursorReader, dest: []u8) Error!void {
        if (self.offset + dest.len > self.buffer.len) return error.CorruptState;
        @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
        self.offset += dest.len;
    }

    fn readU16(self: *CursorReader) Error!u16 {
        var bytes: [2]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u16, &bytes, .little);
    }

    fn readU64(self: *CursorReader) Error!u64 {
        var bytes: [8]u8 = undefined;
        try self.readBytes(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    fn eof(self: *const CursorReader) bool {
        return self.offset == self.buffer.len;
    }
};

fn stateObjectId() u64 {
    return native_util.fnv1a64WithSeed(0xB0075A7E600D0001, "platform:measured-boot:latest");
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

    const summary = BootSummary.fromRecord(&boot);
    try std.testing.expect(summary.matchesRecord(&boot));
    try std.testing.expectEqual(@as(u16, 1), summary.countKind(.kernel));
}

test "critical service measurements bind launched userspace image artifacts" {
    const manifest = @import("../policy/manifest.zig");
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
    const authority = try capabilities.mintBootRoot(.{
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

test "measured boot journal persists and compares latest boot summary across restart" {
    var checkpoint_store = storage_service.CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 160 };
    const state_signer = signing.SignerIdentity{
        .label = "measured-boot-state",
        .seed = [_]u8{0xA1} ** 32,
    };

    var first_storage = storage_service.Service.initWithStore(1_600, 160, owner, &checkpoint_store);
    var first_journal = try MeasurementJournal.init(&first_storage, owner, state_signer);
    try std.testing.expect(!first_journal.loaded_existing_state);

    var recorder = Recorder.init();
    recorder.begin(44);
    try recorder.add(.kernel, "kernel-zigos-native", "kernel=v1");
    try recorder.add(.base_image, "stable-a", "image=v1");
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "workspace-policy", "strict");
    try recorder.add(.driver_set, "core-driver-set", "drivers=v1");
    const first_boot = recorder.finalize();
    const first_comparison = try first_journal.record(first_boot, 10);
    try std.testing.expect(first_comparison.previous == null);
    try std.testing.expect(!first_comparison.changed());

    var restarted_storage = storage_service.Service.initWithStore(1_600, 161, owner, &checkpoint_store);
    var restarted_journal = try MeasurementJournal.init(&restarted_storage, owner, state_signer);
    try std.testing.expect(restarted_journal.loaded_existing_state);
    try std.testing.expect(restarted_journal.latestMatches(&first_boot));

    var second_recorder = Recorder.init();
    second_recorder.begin(45);
    try second_recorder.add(.kernel, "kernel-zigos-native", "kernel=v2");
    try second_recorder.add(.base_image, "stable-b", "image=v2");
    try second_recorder.add(.critical_service, "storage", "healthy");
    try second_recorder.add(.policy, "workspace-policy", "strict");
    try second_recorder.add(.driver_set, "core-driver-set", "drivers=v1");
    const second_boot = second_recorder.finalize();
    const second_comparison = try restarted_journal.record(second_boot, 11);
    try std.testing.expect(second_comparison.previous != null);
    try std.testing.expect(second_comparison.changed());
    try std.testing.expect(!second_comparison.same_root_digest);
    try std.testing.expect(!second_comparison.same_generation);
    try std.testing.expect(second_comparison.same_record_shape);

    var second_restart_storage = storage_service.Service.initWithStore(1_600, 162, owner, &checkpoint_store);
    var second_restart = try MeasurementJournal.init(&second_restart_storage, owner, state_signer);
    try std.testing.expect(second_restart.loaded_existing_state);
    try std.testing.expect(second_restart.latestMatches(&second_boot));
    try std.testing.expect(!second_restart.latestMatches(&first_boot));
}

test "signed artifact manifests bind required boot artifact classes before activation" {
    var artifact_manifest = ArtifactManifest.init(7);
    try artifact_manifest.add(.kernel, "kernel-zigos-native", "kernel-bytes-v1");
    try artifact_manifest.add(.base_image, "stable-a", "base-image-v1");
    try artifact_manifest.add(.critical_service, "zigos.system.policy", "policy-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.storage", "storage-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.compositor", "compositor-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.network", "network-service-elf");
    try artifact_manifest.add(.policy, "production-policy-set", "policy-v1");
    try artifact_manifest.add(.driver_set, "production-driver-set", "drivers-v1");

    const signer = signing.SignerIdentity{
        .label = "artifact-manifest-test",
        .seed = [_]u8{0xB7} ** 32,
    };
    const signed_manifest = try signArtifactManifest(artifact_manifest, signer);
    try std.testing.expect(verifySignedArtifactManifest(&signed_manifest));

    var tampered = signed_manifest;
    tampered.manifest.entries[0].digest[0] ^= 0xFF;
    try std.testing.expect(!verifySignedArtifactManifest(&tampered));

    var boot = BootRecord{
        .generation = artifact_manifest.generation,
        .record_count = artifact_manifest.entry_count,
        .records = [_]MeasurementRecord{zeroRecord()} ** MAX_RECORDS,
        .root_digest = [_]u8{0} ** 32,
    };
    @memcpy(boot.records[0..artifact_manifest.entry_count], artifact_manifest.entries[0..artifact_manifest.entry_count]);
    try std.testing.expect(bootRecordMatchesManifest(&boot, &artifact_manifest));
    boot.records[1].digest[0] ^= 0xAA;
    try std.testing.expect(!bootRecordMatchesManifest(&boot, &artifact_manifest));
}
