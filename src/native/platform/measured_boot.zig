const std = @import("std");
const binary_cursor = @import("binary_cursor");
const crypto_hash = @import("../core/crypto_hash.zig");
const driver_service = @import("../drivers/driver_service.zig");
const hex = @import("../core/hex.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const policy_manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const supervisor_mod = @import("../session/supervisor.zig");
const units = @import("../core/units.zig");
const elf_image_inspector = @import("../task/elf_image_inspector.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const copyText = native_util.copyText;

pub const production_artifact_manifest_signer = signing.SignerIdentity{
    .label = "zigos-artifact-manifest",
    .seed = signing.seedFromByte(0xB7),
};

pub const build_artifact_manifest_signer = signing.SignerIdentity{
    .label = "zigos-build-artifact-manifest",
    .seed = signing.seedFromByte(0xC7),
};

pub const MAX_RECORDS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MEASUREMENT_KIND_COUNT: usize = 5;
pub const MAX_MANIFEST_ENTRIES: usize = MAX_RECORDS;
pub const MAX_BUILD_ARTIFACTS: usize = 32;
pub const state_workspace_label = "system-measured-boot";

const state_entry_path = "state/latest";
const state_magic = "ZMB1";
const state_version: u16 = 1;
const ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES: usize = units.kibibytes(2);
const BUILD_ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES: usize = units.kibibytes(4);
const BOOT_SUMMARY_PAYLOAD_BUFFER_BYTES: usize = 128;
const BUILD_ARTIFACT_LABEL_BUFFER_BYTES: usize = 32;
const UserspaceServiceMeasurementPayload = [62]u8;
const CursorWriter = binary_cursor.Writer(Error, error.StateTooLarge);
const CursorReader = binary_cursor.Reader(Error, error.CorruptState);

pub const MeasurementKind = enum(u8) {
    kernel,
    base_image,
    critical_service,
    policy,
    driver_set,
};

pub const RootProvenance = enum(u8) {
    synthetic_host,
    bootloader_provided,
    emulator_provided,
};

pub const MeasurementRecord = struct {
    kind: MeasurementKind,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    digest: crypto_hash.Digest,

    pub fn labelSlice(self: *const MeasurementRecord) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const ArtifactManifestEntry = MeasurementRecord;

pub const BuildArtifactKind = enum(u8) {
    bootloader_source,
    bootloader_measurement,
    userspace_image,
};

pub const BuildArtifactEntry = struct {
    kind: BuildArtifactKind,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    digest: crypto_hash.Digest,

    pub fn labelSlice(self: *const BuildArtifactEntry) []const u8 {
        return self.label[0..self.label_len];
    }
};

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
        return self.addDigest(kind, label, hashMeasurement(kind, label, payload));
    }

    pub fn addDigest(self: *ArtifactManifest, kind: MeasurementKind, label: []const u8, digest: crypto_hash.Digest) Error!void {
        if (self.entry_count >= MAX_MANIFEST_ENTRIES) return error.RecordTableFull;
        self.entries[self.entry_count] = .{
            .kind = kind,
            .label_len = 0,
            .label = [_]u8{0} ** MAX_LABEL_BYTES,
            .digest = digest,
        };
        self.entries[self.entry_count].label_len = copyText(&self.entries[self.entry_count].label, label);
        self.entry_count += 1;
    }

    pub fn addUserspaceServiceImage(
        self: *ArtifactManifest,
        image: *const userspace_loader.ImageRecord,
    ) Error!void {
        var payload = std.mem.zeroes(UserspaceServiceMeasurementPayload);
        @memcpy(payload[0..32], &image.file_sha256);
        std.mem.writeInt(u64, payload[32..40], image.id, .little);
        std.mem.writeInt(u64, payload[40..48], image.entry_point, .little);
        std.mem.writeInt(u64, payload[48..56], @intCast(image.byte_len), .little);
        std.mem.writeInt(u32, payload[56..60], image.contract_flags, .little);
        std.mem.writeInt(u16, payload[60..62], image.component_abi_version, .little);
        return self.add(.critical_service, image.bundleIdSlice(), payload[0..]);
    }

    pub fn addCriticalServiceImage(
        self: *ArtifactManifest,
        service: *const supervisor_mod.ServiceRecord,
        image: *const userspace_loader.ImageRecord,
    ) Error!void {
        var payload: CriticalServiceMeasurementPayload = undefined;
        const bytes = criticalServiceMeasurementPayload(&payload, service, image);
        return self.add(.critical_service, image.bundleIdSlice(), bytes);
    }

    pub fn addDriverSet(
        self: *ArtifactManifest,
        label: []const u8,
        directory: *const driver_service.Directory,
    ) Error!void {
        const digest = driverSetDigest(directory);
        return self.add(.driver_set, label, &digest);
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

    pub fn verify(self: *const SignedArtifactManifest, expected_signer: signing.SignerIdentity) bool {
        var payload_buffer: [ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = encodeArtifactManifest(self.manifest, &payload_buffer) catch return false;
        return signing.verifyTrusted(self.signature, payload, expected_signer) and requiredArtifactShape(&self.manifest);
    }
};

pub const BuildArtifactManifest = struct {
    generation: u64,
    entry_count: usize,
    entries: [MAX_BUILD_ARTIFACTS]BuildArtifactEntry,
    signature: policy_manifest.Signature,

    pub fn init(generation: u64) BuildArtifactManifest {
        return .{
            .generation = generation,
            .entry_count = 0,
            .entries = [_]BuildArtifactEntry{zeroBuildArtifactEntry()} ** MAX_BUILD_ARTIFACTS,
            .signature = .{},
        };
    }

    pub fn addDigest(self: *BuildArtifactManifest, kind: BuildArtifactKind, label: []const u8, digest: crypto_hash.Digest) Error!void {
        if (self.entry_count >= MAX_BUILD_ARTIFACTS) return error.RecordTableFull;
        self.entries[self.entry_count] = try buildArtifactEntry(kind, label, digest);
        self.entry_count += 1;
    }

    pub fn countKind(self: *const BuildArtifactManifest, kind: BuildArtifactKind) usize {
        var count: usize = 0;
        for (self.entries[0..self.entry_count]) |entry| {
            if (entry.kind == kind) count += 1;
        }
        return count;
    }

    pub fn find(self: *const BuildArtifactManifest, kind: BuildArtifactKind, label: []const u8) ?BuildArtifactEntry {
        for (self.entries[0..self.entry_count]) |entry| {
            if (entry.kind == kind and std.mem.eql(u8, entry.labelSlice(), label)) return entry;
        }
        return null;
    }

    pub fn verify(self: *const BuildArtifactManifest) bool {
        var payload_buffer: [BUILD_ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = encodeBuildArtifactManifest(self.generation, self.entries[0..self.entry_count], &payload_buffer) catch return false;
        return signing.verifyTrusted(self.signature, payload, build_artifact_manifest_signer) and
            requiredBuildArtifactShape(self);
    }
};

pub const BootRecord = struct {
    generation: u64,
    record_count: usize,
    records: [MAX_RECORDS]MeasurementRecord,
    root_digest: crypto_hash.Digest,
    root_provenance: RootProvenance = .synthetic_host,
    artifact_manifest_verified: bool = false,

    pub fn countKind(self: *const BootRecord, kind: MeasurementKind) usize {
        var count: usize = 0;
        for (self.records[0..self.record_count]) |record| {
            if (record.kind == kind) count += 1;
        }
        return count;
    }

    pub fn hasVerifiedRoot(self: *const BootRecord) bool {
        return self.artifact_manifest_verified and !std.mem.allEqual(u8, &self.root_digest, 0);
    }

    pub fn isRemoteAttestable(self: *const BootRecord) bool {
        return self.hasVerifiedRoot() and self.root_provenance == .bootloader_provided;
    }

    pub fn computedRootDigest(self: *const BootRecord) ?crypto_hash.Digest {
        if (self.record_count > MAX_RECORDS) return null;
        var root = crypto_hash.zero_digest;
        for (self.records[0..self.record_count], 0..) |record, index| {
            root = hashDigest(root, record, index);
        }
        return root;
    }

    pub fn isInternallyConsistent(self: *const BootRecord) bool {
        const computed = self.computedRootDigest() orelse return false;
        return std.mem.eql(u8, &self.root_digest, &computed);
    }
};

pub const BootloaderMeasurementHandoff = struct {
    generation: u64,
    record_count: usize,
    records: [MAX_RECORDS]MeasurementRecord,
    root_digest: crypto_hash.Digest,

    pub fn fromBootRecord(boot: *const BootRecord) Error!BootloaderMeasurementHandoff {
        if (boot.record_count > MAX_RECORDS) return error.ManifestMismatch;
        var handoff = BootloaderMeasurementHandoff{
            .generation = boot.generation,
            .record_count = boot.record_count,
            .records = [_]MeasurementRecord{zeroRecord()} ** MAX_RECORDS,
            .root_digest = boot.root_digest,
        };
        @memcpy(handoff.records[0..boot.record_count], boot.records[0..boot.record_count]);
        return handoff;
    }
};

pub const BootSummary = struct {
    generation: u64,
    record_count: u16,
    kind_counts: [MEASUREMENT_KIND_COUNT]u16,
    root_digest: crypto_hash.Digest,

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
    InvalidBuildArtifactKind,
    ManifestMismatch,
    UntrustedArtifactManifest,
    UntrustedRootProvenance,
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
        return self.addDigest(kind, label, hashMeasurement(kind, label, payload));
    }

    pub fn addDigest(self: *Recorder, kind: MeasurementKind, label: []const u8, digest: crypto_hash.Digest) Error!void {
        if (self.record_count >= MAX_RECORDS) return error.RecordTableFull;
        self.records[self.record_count] = .{
            .kind = kind,
            .label_len = 0,
            .label = [_]u8{0} ** MAX_LABEL_BYTES,
            .digest = digest,
        };
        self.records[self.record_count].label_len = copyText(&self.records[self.record_count].label, label);
        self.record_count += 1;
    }

    pub fn addCriticalServiceImage(
        self: *Recorder,
        service: *const supervisor_mod.ServiceRecord,
        image: *const userspace_loader.ImageRecord,
    ) Error!void {
        var payload: CriticalServiceMeasurementPayload = undefined;
        const bytes = criticalServiceMeasurementPayload(&payload, service, image);
        return self.add(.critical_service, image.bundleIdSlice(), bytes);
    }

    pub fn addDriverSet(
        self: *Recorder,
        label: []const u8,
        directory: *const driver_service.Directory,
    ) Error!void {
        const digest = driverSetDigest(directory);
        return self.add(.driver_set, label, &digest);
    }

    pub fn finalize(self: *const Recorder) BootRecord {
        var root = crypto_hash.zero_digest;
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

pub fn addMeasuredArtifact(
    recorder: *Recorder,
    artifact_manifest: *ArtifactManifest,
    kind: MeasurementKind,
    label: []const u8,
    payload: []const u8,
) Error!void {
    try recorder.add(kind, label, payload);
    try artifact_manifest.add(kind, label, payload);
}

pub fn signArtifactManifest(
    artifact_manifest: ArtifactManifest,
    identity: signing.SignerIdentity,
) anyerror!SignedArtifactManifest {
    var payload_buffer: [ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
    const payload = try encodeArtifactManifest(artifact_manifest, &payload_buffer);
    return .{
        .manifest = artifact_manifest,
        .signature = try signing.signWithDefaultRegistry(.ed25519, identity, payload),
    };
}

pub fn signArtifactManifestWithProvider(
    artifact_manifest: ArtifactManifest,
    identity: signing.SignerIdentity,
    provider: signing.SignatureProvider,
) anyerror!SignedArtifactManifest {
    if (!provider.releaseEligible()) return error.ReleaseProviderNotEligible;
    var payload_buffer: [ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
    const payload = try encodeArtifactManifest(artifact_manifest, &payload_buffer);
    return .{
        .manifest = artifact_manifest,
        .signature = try provider.sign(identity, payload),
    };
}

pub fn verifySignedArtifactManifest(
    signed_manifest: *const SignedArtifactManifest,
    expected_signer: signing.SignerIdentity,
) bool {
    return signed_manifest.verify(expected_signer);
}

pub fn verifyBuildArtifactManifest(manifest: *const BuildArtifactManifest) bool {
    return manifest.verify();
}

pub fn buildArtifactDigestMatches(
    manifest: *const BuildArtifactManifest,
    kind: BuildArtifactKind,
    label: []const u8,
    digest: *const crypto_hash.Digest,
) bool {
    const entry = manifest.find(kind, label) orelse return false;
    return std.mem.eql(u8, &entry.digest, digest);
}

pub fn generatedUserspaceArchiveMatchesManifest(manifest: *const BuildArtifactManifest) bool {
    if (!@import("builtin").is_test) return false;
    const generated_archive = @import("userspace_archive");

    if (manifest.countKind(.userspace_image) != generated_archive.artifacts.len) return false;
    for (generated_archive.artifacts) |artifact| {
        if (!generatedArtifactMatchesManifest(manifest, artifact)) return false;
    }

    return true;
}

fn generatedArtifactMatchesManifest(manifest: *const BuildArtifactManifest, artifact: anytype) bool {
    const spec = userspace_boot_registry.find(artifact.bundle_id) orelse return false;
    userspace_boot_registry.validateGeneratedArtifactMatchesSpec(spec, artifact) catch return false;
    if (artifact.data.len == 0) return false;
    if (!artifact.signed) return false;
    if (artifact.file_size_bytes != artifact.data.len) return false;

    const digest = rawSha256(artifact.data);
    if (!std.mem.eql(u8, &digest, &artifact.file_sha256)) return false;
    if (!buildArtifactDigestMatches(manifest, .userspace_image, artifact.bundle_id, &digest)) return false;

    const inspection = elf_image_inspector.inspect(artifact.data) catch return false;
    if (artifact.entry_point != inspection.entry_point) return false;
    if (artifact.bootstrap_mailbox_address != inspection.bootstrap_mailbox_address) return false;
    if (artifact.segment_count != inspection.executable_image.segment_count) return false;
    return true;
}

pub fn generatedProductionArtifactManifestMatchesUserspaceArchive() !void {
    if (!@import("builtin").is_test) return;
    const generated_manifest = @import("production_artifact_manifest");
    const generated_archive = @import("userspace_archive");

    var manifest = try buildArtifactManifestFromGenerated(generated_manifest);
    try std.testing.expect(verifyBuildArtifactManifest(&manifest));
    try std.testing.expectEqual(generated_archive.artifacts.len, manifest.countKind(.userspace_image));
    try std.testing.expect(generatedUserspaceArchiveMatchesManifest(&manifest));

    var stale_digest = manifest;
    const stale_index = firstBuildArtifactIndex(&stale_digest, .userspace_image) orelse return error.ManifestMismatch;
    stale_digest.entries[stale_index].digest[0] ^= 0x33;
    try signBuildArtifactManifestForTest(&stale_digest);
    try std.testing.expect(verifyBuildArtifactManifest(&stale_digest));
    try std.testing.expect(!generatedUserspaceArchiveMatchesManifest(&stale_digest));

    var missing_entry = manifest;
    try removeBuildArtifactEntry(&missing_entry, stale_index);
    try signBuildArtifactManifestForTest(&missing_entry);
    try std.testing.expect(!generatedUserspaceArchiveMatchesManifest(&missing_entry));

    var stale_metadata = generated_archive.artifacts[0];
    stale_metadata.entry_point +%= 0x1000;
    try std.testing.expect(!generatedArtifactMatchesManifest(&manifest, stale_metadata));

    var stale_registry_identity = generated_archive.artifacts[0];
    stale_registry_identity.publisher = "stale.publisher";
    try std.testing.expect(!generatedArtifactMatchesManifest(&manifest, stale_registry_identity));
}

pub fn buildArtifactEntry(kind: BuildArtifactKind, label: []const u8, digest: crypto_hash.Digest) Error!BuildArtifactEntry {
    var entry = zeroBuildArtifactEntry();
    entry.kind = kind;
    entry.label_len = copyText(&entry.label, label);
    entry.digest = digest;
    return entry;
}

pub fn buildArtifactManifestFromGenerated(comptime generated: anytype) Error!BuildArtifactManifest {
    var manifest = BuildArtifactManifest.init(generated.generation);
    inline for (generated.entries) |entry| {
        const kind = std.enums.fromInt(BuildArtifactKind, entry.kind) orelse return error.InvalidBuildArtifactKind;
        try manifest.addDigest(kind, entry.label, entry.digest);
    }
    var signature = policy_manifest.Signature{
        .format = generated.signature_format,
        .signer = generated.signature_signer,
        .public_key_len = generated.signature_public_key.len,
        .value_len = generated.signature_value.len,
    };
    @memcpy(signature.public_key[0..generated.signature_public_key.len], generated.signature_public_key[0..]);
    @memcpy(signature.value[0..generated.signature_value.len], generated.signature_value[0..]);
    manifest.signature = signature;
    return manifest;
}

fn signBuildArtifactManifestForTest(manifest: *BuildArtifactManifest) !void {
    var payload_buffer: [BUILD_ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
    const payload = try encodeBuildArtifactManifest(manifest.generation, manifest.entries[0..manifest.entry_count], &payload_buffer);
    manifest.signature = try signing.signWithDefaultRegistry(.ed25519, build_artifact_manifest_signer, payload);
}

pub fn encodeBuildArtifactManifest(generation: u64, entries: []const BuildArtifactEntry, buffer: []u8) Error![]const u8 {
    var offset: usize = 0;
    offset = appendManifestFormat(buffer, offset, "ZBAM1|g={d}|n={d}", .{
        generation,
        entries.len,
    }) catch return error.ManifestTooLarge;
    for (entries) |entry| {
        offset = appendManifestFormat(buffer, offset, "|{s}:{s}:", .{
            @tagName(entry.kind),
            entry.labelSlice(),
        }) catch return error.ManifestTooLarge;
        offset = appendHexDigest(buffer, offset, &entry.digest) catch return error.ManifestTooLarge;
    }
    return buffer[0..offset];
}

pub fn bootRecordMatchesManifest(boot: *const BootRecord, artifact_manifest: *const ArtifactManifest) bool {
    if (boot.record_count > MAX_RECORDS) return false;
    if (artifact_manifest.entry_count > MAX_MANIFEST_ENTRIES) return false;
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

pub fn verifyBootRecordAgainstManifest(
    boot: *BootRecord,
    artifact_manifest: *const ArtifactManifest,
    root_provenance: RootProvenance,
) Error!void {
    if (!requiredArtifactShape(artifact_manifest)) return error.ManifestMismatch;
    if (!bootRecordMatchesManifest(boot, artifact_manifest)) return error.ManifestMismatch;
    if (std.mem.allEqual(u8, &boot.root_digest, 0)) return error.ManifestMismatch;
    if (!boot.isInternallyConsistent()) return error.ManifestMismatch;
    if (root_provenance == .synthetic_host) return error.UntrustedRootProvenance;
    boot.root_provenance = root_provenance;
    boot.artifact_manifest_verified = true;
}

pub fn verifyBootloaderMeasurementHandoff(
    handoff: *const BootloaderMeasurementHandoff,
    signed_manifest: *const SignedArtifactManifest,
    expected_signer: signing.SignerIdentity,
) Error!BootRecord {
    if (!verifySignedArtifactManifest(signed_manifest, expected_signer)) {
        return error.UntrustedArtifactManifest;
    }
    if (handoff.record_count > MAX_RECORDS) return error.ManifestMismatch;
    var boot = BootRecord{
        .generation = handoff.generation,
        .record_count = handoff.record_count,
        .records = handoff.records,
        .root_digest = handoff.root_digest,
    };
    try verifyBootRecordAgainstManifest(&boot, &signed_manifest.manifest, .bootloader_provided);
    return boot;
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
            .workspace_id = workspace_record.id.raw(),
        };

        if (storage.resolve(workspace_record.id, state_entry_path)) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            journal.latest_summary = try decodeSummary(try storage.versionPayload(version));
            journal.loaded_existing_state = true;
            journal.latest_version_id = entry.version_id.raw();
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
        var payload_buffer: [BOOT_SUMMARY_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const payload = try encodeSummary(summary, &payload_buffer);
        const existing_entry = self.storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
            error.EntryNotFound => null,
            else => return err,
        };
        const result = try self.storage.putVersion(.{
            .preferred_object_id = object_store.ids.object(stateObjectId()),
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
        self.latest_version_id = result.version_id.raw();
    }
};

fn zeroRecord() MeasurementRecord {
    return .{
        .kind = .kernel,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .digest = crypto_hash.zero_digest,
    };
}

fn zeroBuildArtifactEntry() BuildArtifactEntry {
    return .{
        .kind = .bootloader_source,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .digest = crypto_hash.zero_digest,
    };
}

fn hashMeasurement(kind: MeasurementKind, label: []const u8, payload: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "measurement-kind", kind);
    crypto_hash.updateBytes(&hasher, "label", label);
    crypto_hash.updateBytes(&hasher, "payload", payload);
    return crypto_hash.finalize(&hasher);
}

fn rawSha256(bytes: []const u8) crypto_hash.Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var digest: crypto_hash.Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn firstBuildArtifactIndex(manifest: *const BuildArtifactManifest, kind: BuildArtifactKind) ?usize {
    for (manifest.entries[0..manifest.entry_count], 0..) |entry, index| {
        if (entry.kind == kind) return index;
    }
    return null;
}

fn removeBuildArtifactEntry(manifest: *BuildArtifactManifest, index: usize) Error!void {
    if (index >= manifest.entry_count) return error.ManifestMismatch;
    var cursor = index;
    while (cursor + 1 < manifest.entry_count) : (cursor += 1) {
        manifest.entries[cursor] = manifest.entries[cursor + 1];
    }
    manifest.entry_count -= 1;
    manifest.entries[manifest.entry_count] = zeroBuildArtifactEntry();
}

const CRITICAL_SERVICE_MEASUREMENT_PAYLOAD_BYTES: usize = 64;
const CriticalServiceMeasurementPayload = [CRITICAL_SERVICE_MEASUREMENT_PAYLOAD_BYTES]u8;

fn criticalServiceMeasurementPayload(
    payload: *CriticalServiceMeasurementPayload,
    service: *const supervisor_mod.ServiceRecord,
    image: *const userspace_loader.ImageRecord,
) []const u8 {
    @memcpy(payload[0..32], &image.file_sha256);
    std.mem.writeInt(u64, payload[32..40], image.id, .little);
    std.mem.writeInt(u64, payload[40..48], image.entry_point, .little);
    std.mem.writeInt(u64, payload[48..56], @intCast(image.byte_len), .little);
    std.mem.writeInt(u16, payload[56..58], @intFromEnum(service.class), .little);
    std.mem.writeInt(u32, payload[58..62], image.contract_flags, .little);
    std.mem.writeInt(u16, payload[62..64], image.component_abi_version, .little);
    return payload[0..];
}

fn driverSetDigest(directory: *const driver_service.Directory) crypto_hash.Digest {
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
    return crypto_hash.finalize(&hasher);
}

fn hashDigest(root: crypto_hash.Digest, record: MeasurementRecord, index: usize) crypto_hash.Digest {
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

fn requiredBuildArtifactShape(manifest: *const BuildArtifactManifest) bool {
    return manifest.countKind(.bootloader_source) == 1 and
        manifest.countKind(.bootloader_measurement) == 1 and
        manifest.countKind(.userspace_image) >= 10;
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

fn appendHexDigest(buffer: []u8, offset: usize, digest: *const crypto_hash.Digest) error{NoSpaceLeft}!usize {
    const encoded = hex.encodeLower(digest.*[0..], buffer[offset..]) catch return error.NoSpaceLeft;
    return offset + encoded.len;
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
        .root_digest = crypto_hash.zero_digest,
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
            .format = manifest.SIGNATURE_FORMAT_ED25519,
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
        .seed = signing.seedFromByte(0xA1),
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

    const signed_manifest = try signArtifactManifest(artifact_manifest, production_artifact_manifest_signer);
    try std.testing.expect(verifySignedArtifactManifest(
        &signed_manifest,
        production_artifact_manifest_signer,
    ));

    var tampered = signed_manifest;
    tampered.manifest.entries[0].digest[0] ^= 0xFF;
    try std.testing.expect(!verifySignedArtifactManifest(
        &tampered,
        production_artifact_manifest_signer,
    ));

    const wrong_signer = signing.SignerIdentity{
        .label = "untrusted-artifact-manifest",
        .seed = signing.seedFromByte(0xB8),
    };
    const wrong_authority = try signArtifactManifest(artifact_manifest, wrong_signer);
    try std.testing.expect(!verifySignedArtifactManifest(
        &wrong_authority,
        production_artifact_manifest_signer,
    ));

    var boot = BootRecord{
        .generation = artifact_manifest.generation,
        .record_count = artifact_manifest.entry_count,
        .records = [_]MeasurementRecord{zeroRecord()} ** MAX_RECORDS,
        .root_digest = crypto_hash.zero_digest,
    };
    @memcpy(boot.records[0..artifact_manifest.entry_count], artifact_manifest.entries[0..artifact_manifest.entry_count]);
    try std.testing.expect(bootRecordMatchesManifest(&boot, &artifact_manifest));
    boot.records[1].digest[0] ^= 0xAA;
    try std.testing.expect(!bootRecordMatchesManifest(&boot, &artifact_manifest));
}

test "artifact manifests can be signed through release provider boundaries" {
    const SigningBackend = struct {
        seed: signing.Seed,

        fn sign(context: *anyopaque, key: signing.ReleaseRootKeyHandle, message: []const u8) ![signing.SIGNATURE_BYTES]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seed);
            try std.testing.expectEqualSlices(u8, &key.public_key, &key_pair.public_key.toBytes());
            return (try key_pair.sign(message, null)).toBytes();
        }
    };

    var artifact_manifest = ArtifactManifest.init(8);
    try artifact_manifest.add(.kernel, "kernel-zigos-native", "kernel-bytes-v2");
    try artifact_manifest.add(.base_image, "stable-a", "base-image-v2");
    try artifact_manifest.add(.critical_service, "zigos.system.policy", "policy-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.storage", "storage-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.compositor", "compositor-service-elf");
    try artifact_manifest.add(.critical_service, "zigos.system.network", "network-service-elf");
    try artifact_manifest.add(.policy, "production-policy-set", "policy-v2");
    try artifact_manifest.add(.driver_set, "production-driver-set", "drivers-v2");

    const root_identity = production_artifact_manifest_signer;
    var backend = SigningBackend{ .seed = root_identity.seed };
    var provider_impl = try signing.ExternalReleaseProvider.init(
        .{
            .name = "release-kms-artifact-manifest",
            .profile = .ed25519,
            .role = .production,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
            .hardware_backed = true,
            .rotation_supported = true,
            .revocation_supported = true,
            .customer_verifiable = true,
            .verifier_protocol = .dsse_in_toto_slsa,
        },
        .{
            .key_id = "kms://zigos/release/artifact-manifest/1",
            .label = root_identity.label,
            .public_key = try signing.publicKey(root_identity),
            .generation = 1,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
        },
        &backend,
        SigningBackend.sign,
    );
    const provider = provider_impl.provider();
    const signed_manifest = try signArtifactManifestWithProvider(artifact_manifest, root_identity, provider);
    try std.testing.expect(verifySignedArtifactManifest(&signed_manifest, root_identity));

    var software_provider_impl = signing.SoftwareEd25519Provider{};
    try std.testing.expectError(
        error.ReleaseProviderNotEligible,
        signArtifactManifestWithProvider(artifact_manifest, root_identity, software_provider_impl.provider()),
    );
}

test "build-generated artifact manifests reject tampered bootloader source measurement and authority" {
    var manifest = BuildArtifactManifest.init(1);
    const bootloader_source_digest = crypto_hash.digestFromByte(0x10);
    const bootloader_measurement_digest = crypto_hash.digestFromByte(0x11);
    const unexpected_bootloader_digest = crypto_hash.digestFromByte(0x12);

    try manifest.addDigest(.bootloader_source, "src/boot/boot64.S", bootloader_source_digest);
    try manifest.addDigest(.bootloader_measurement, "multiboot-v1:zigos_native", bootloader_measurement_digest);
    inline for (0..10) |index| {
        const digest = crypto_hash.digestFromByte(@intCast(0x20 + index));
        var label_buffer: [BUILD_ARTIFACT_LABEL_BUFFER_BYTES]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buffer, "zigos.system.test-{d}", .{index});
        try manifest.addDigest(.userspace_image, label, digest);
    }

    var payload_buffer: [BUILD_ARTIFACT_MANIFEST_PAYLOAD_BUFFER_BYTES]u8 = undefined;
    const payload = try encodeBuildArtifactManifest(manifest.generation, manifest.entries[0..manifest.entry_count], &payload_buffer);
    manifest.signature = try signing.signWithDefaultRegistry(.ed25519, build_artifact_manifest_signer, payload);

    try std.testing.expect(verifyBuildArtifactManifest(&manifest));
    try std.testing.expect(manifest.find(.bootloader_measurement, "multiboot-v1:zigos_native") != null);
    try std.testing.expect(buildArtifactDigestMatches(
        &manifest,
        .bootloader_source,
        "src/boot/boot64.S",
        &bootloader_source_digest,
    ));
    try std.testing.expect(buildArtifactDigestMatches(
        &manifest,
        .bootloader_measurement,
        "multiboot-v1:zigos_native",
        &bootloader_measurement_digest,
    ));
    try std.testing.expect(!buildArtifactDigestMatches(
        &manifest,
        .bootloader_source,
        "src/boot/boot64.S",
        &unexpected_bootloader_digest,
    ));
    try std.testing.expect(!buildArtifactDigestMatches(
        &manifest,
        .bootloader_measurement,
        "multiboot-v1:zigos_native",
        &unexpected_bootloader_digest,
    ));

    for (0..manifest.entry_count) |entry_index| {
        var tampered = manifest;
        tampered.entries[entry_index].digest[0] ^= 0xFF;
        try std.testing.expect(!verifyBuildArtifactManifest(&tampered));
    }

    var wrong_authority = manifest;
    const wrong_signer = signing.SignerIdentity{
        .label = "untrusted-build-artifact-manifest",
        .seed = signing.seedFromByte(0xC8),
    };
    wrong_authority.signature = try signing.signWithDefaultRegistry(.ed25519, wrong_signer, payload);
    try std.testing.expect(!verifyBuildArtifactManifest(&wrong_authority));
}

test "build-generated production artifact manifest matches embedded userspace archive" {
    try generatedProductionArtifactManifestMatchesUserspaceArchive();
}

test "bootloader measurement handoff rejects unsigned manifests and tampered startup artifacts" {
    var artifact_manifest = ArtifactManifest.init(33);
    var recorder = Recorder.init();
    recorder.begin(33);

    try addMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos-native", "kernel=v7");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-f", "image=v7");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "compositor", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .policy, "production-policy-set", "strict");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "production-driver-set", "drivers=v7");

    const signed_manifest = try signArtifactManifest(artifact_manifest, production_artifact_manifest_signer);
    const boot = recorder.finalize();
    const handoff = try BootloaderMeasurementHandoff.fromBootRecord(&boot);
    const verified = try verifyBootloaderMeasurementHandoff(
        &handoff,
        &signed_manifest,
        production_artifact_manifest_signer,
    );
    try std.testing.expect(verified.hasVerifiedRoot());
    try std.testing.expect(verified.isRemoteAttestable());
    try std.testing.expectEqual(RootProvenance.bootloader_provided, verified.root_provenance);

    var unsigned_manifest = signed_manifest;
    unsigned_manifest.manifest.entries[0].digest[0] ^= 0x40;
    try std.testing.expectError(
        error.UntrustedArtifactManifest,
        verifyBootloaderMeasurementHandoff(&handoff, &unsigned_manifest, production_artifact_manifest_signer),
    );

    var wrong_root = handoff;
    wrong_root.root_digest[31] ^= 0x20;
    try std.testing.expectError(
        error.ManifestMismatch,
        verifyBootloaderMeasurementHandoff(&wrong_root, &signed_manifest, production_artifact_manifest_signer),
    );

    for (0..artifact_manifest.entry_count) |entry_index| {
        var tampered_handoff = handoff;
        tampered_handoff.records[entry_index].digest[0] ^= 0x11;
        try std.testing.expectError(
            error.ManifestMismatch,
            verifyBootloaderMeasurementHandoff(&tampered_handoff, &signed_manifest, production_artifact_manifest_signer),
        );

        var tampered_manifest = artifact_manifest;
        tampered_manifest.entries[entry_index].digest[0] ^= 0x22;
        const trusted_tampered_manifest = try signArtifactManifest(tampered_manifest, production_artifact_manifest_signer);
        try std.testing.expectError(
            error.ManifestMismatch,
            verifyBootloaderMeasurementHandoff(&handoff, &trusted_tampered_manifest, production_artifact_manifest_signer),
        );
    }
}

test "verified boot chain rejects synthetic provenance and every mismatched artifact class" {
    var artifact_manifest = ArtifactManifest.init(22);
    var recorder = Recorder.init();
    recorder.begin(22);

    try addMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos-native", "kernel=v6");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-e", "image=v6");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "compositor", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .policy, "production-policy-set", "strict");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "production-driver-set", "drivers=v6");

    var boot = recorder.finalize();
    try verifyBootRecordAgainstManifest(&boot, &artifact_manifest, .bootloader_provided);
    try std.testing.expect(boot.hasVerifiedRoot());
    try std.testing.expect(boot.isRemoteAttestable());
    try std.testing.expectEqual(RootProvenance.bootloader_provided, boot.root_provenance);

    var emulator_boot = recorder.finalize();
    try verifyBootRecordAgainstManifest(&emulator_boot, &artifact_manifest, .emulator_provided);
    try std.testing.expect(emulator_boot.hasVerifiedRoot());
    try std.testing.expect(!emulator_boot.isRemoteAttestable());
    try std.testing.expectEqual(RootProvenance.emulator_provided, emulator_boot.root_provenance);

    var synthetic_boot = recorder.finalize();
    try std.testing.expectError(
        error.UntrustedRootProvenance,
        verifyBootRecordAgainstManifest(&synthetic_boot, &artifact_manifest, .synthetic_host),
    );
    try std.testing.expect(!synthetic_boot.hasVerifiedRoot());

    var wrong_root_boot = recorder.finalize();
    wrong_root_boot.root_digest[0] ^= 0xFF;
    try std.testing.expectError(
        error.ManifestMismatch,
        verifyBootRecordAgainstManifest(&wrong_root_boot, &artifact_manifest, .bootloader_provided),
    );
    try std.testing.expect(!wrong_root_boot.hasVerifiedRoot());

    for (0..artifact_manifest.entry_count) |entry_index| {
        var tampered_manifest = artifact_manifest;
        tampered_manifest.entries[entry_index].digest[0] ^= 0xFF;
        var rejected_boot = recorder.finalize();
        try std.testing.expectError(
            error.ManifestMismatch,
            verifyBootRecordAgainstManifest(&rejected_boot, &tampered_manifest, .bootloader_provided),
        );
        try std.testing.expect(!rejected_boot.hasVerifiedRoot());

        var tampered_boot = recorder.finalize();
        tampered_boot.records[entry_index].digest[0] ^= 0xAA;
        try std.testing.expectError(
            error.ManifestMismatch,
            verifyBootRecordAgainstManifest(&tampered_boot, &artifact_manifest, .bootloader_provided),
        );
        try std.testing.expect(!tampered_boot.hasVerifiedRoot());
    }
}
