const std = @import("std");

pub const production_base_target_paths = [_][]const u8{
    "build/os.iso",
    "spec/production_readiness.json",
    "spec/release_security/crash_dump_redaction.json",
    "spec/release_security/fuzz_corpus.json",
    "spec/release_security/memory_safety_inventory.json",
    "spec/release_security/release_artifacts.json",
    "spec/release_security/threat_model.json",
    "spec/release_security/vulnerability_disclosure.json",
    "zig-out/bin/kernel-zigos-native.elf",
};

pub const production_userspace_target_paths = [_][]const u8{
    "zig-out/bin/userspace-attention-broker.elf",
    "zig-out/bin/userspace-capture.elf",
    "zig-out/bin/userspace-compositor.elf",
    "zig-out/bin/userspace-indexing-search.elf",
    "zig-out/bin/userspace-media-print.elf",
    "zig-out/bin/userspace-network-stack.elf",
    "zig-out/bin/userspace-notes.elf",
    "zig-out/bin/userspace-object-resilience.elf",
    "zig-out/bin/userspace-package-service.elf",
    "zig-out/bin/userspace-permission-review.elf",
    "zig-out/bin/userspace-personal-context.elf",
    "zig-out/bin/userspace-policy-mediation.elf",
    "zig-out/bin/userspace-secret-vault.elf",
    "zig-out/bin/userspace-secure-pasteboard.elf",
    "zig-out/bin/userspace-sensitive-capture.elf",
    "zig-out/bin/userspace-service-registry.elf",
    "zig-out/bin/userspace-session-manager.elf",
    "zig-out/bin/userspace-storage-driver.elf",
    "zig-out/bin/userspace-storage-object.elf",
    "zig-out/bin/userspace-sync-service.elf",
    "zig-out/bin/userspace-sync.elf",
    "zig-out/bin/userspace-task-lifecycle.elf",
    "zig-out/bin/userspace-viewer.elf",
    "zig-out/bin/userspace-workspace-storage.elf",
};

pub const production_target_paths = sortedConcatenation(
    production_base_target_paths,
    production_userspace_target_paths,
);

pub const root_metadata_evidence_name = "root-metadata.json";

pub const release_evidence_names = [_][]const u8{
    "artifact-digests.sha256",
    "artifact-measurements.json",
    "customer-verification-policy.json",
    "provenance.dsse.intoto.jsonl",
    "provenance.intoto.jsonl",
    "release-trust-policy.dsse.json",
    "reproducible-artifact-digests.sha256",
    "reproducible-build.json",
    root_metadata_evidence_name,
    "sbom.spdx.json",
};

pub const forbidden_verification_paths = [_][]const u8{
    "build/os-verification.iso",
    "zig-out/bin/kernel-benchmark.elf",
    "zig-out/bin/kernel-recovery.elf",
    "zig-out/bin/kernel-zigos-native-rollback-slot-failure.elf",
    "zig-out/bin/kernel-zigos-native-storage-durability.elf",
    "zig-out/bin/kernel-zigos-native-tampered-artifact-manifest.elf",
    "zig-out/bin/kernel-zigos-native-tampered-bootloader-measurement.elf",
    "zig-out/bin/kernel-zigos-native-tampered-driver-set.elf",
    "zig-out/bin/kernel-zigos-native-tampered-kernel.elf",
    "zig-out/bin/kernel-zigos-native-tampered-policy.elf",
    "zig-out/bin/kernel-zigos-native-tampered-userspace-image.elf",
    "zig-out/bin/kernel-zigos-native-verification.elf",
    "zig-out/bin/userspace-mmu-isolation-proof.elf",
    "zig-out/bin/userspace-notes-daily.elf",
    "zig-out/bin/userspace-service-client.elf",
    "zig-out/bin/userspace-termination-probe.elf",
    "zig-out/bin/userspace-transport-probe.elf",
};

pub const ExactSetError = error{
    UnsafeEntry,
    DuplicateEntry,
    UnexpectedEntry,
    MissingEntry,
};

pub fn productionTargetPaths() []const []const u8 {
    return &production_target_paths;
}

pub fn releaseEvidenceNames() []const []const u8 {
    return &release_evidence_names;
}

pub fn forbiddenVerificationPaths() []const []const u8 {
    return &forbidden_verification_paths;
}

pub fn requireExactProductionTargets(actual: []const []const u8) ExactSetError!void {
    try requireExactSet(actual, productionTargetPaths(), .path);
}

pub fn requireExactReleaseEvidenceNames(actual: []const []const u8) ExactSetError!void {
    try requireExactSet(actual, releaseEvidenceNames(), .name);
}

pub fn requireExactForbiddenVerificationPaths(actual: []const []const u8) ExactSetError!void {
    try requireExactSet(actual, forbiddenVerificationPaths(), .path);
}

pub fn isProductionTarget(path: []const u8) bool {
    return contains(productionTargetPaths(), path);
}

pub fn isReleaseEvidenceName(name: []const u8) bool {
    return contains(releaseEvidenceNames(), name);
}

pub fn isForbiddenVerificationPath(path: []const u8) bool {
    return contains(forbiddenVerificationPaths(), path);
}

pub fn isSafeRelativePath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return false;

    var segment_start: usize = 0;
    for (path, 0..) |byte, index| {
        if (byte == '/') {
            if (!isSafeSegment(path[segment_start..index])) return false;
            segment_start = index + 1;
            continue;
        }
        if (!isSafePathByte(byte)) return false;
    }
    return isSafeSegment(path[segment_start..]);
}

pub fn isSafeEvidenceName(name: []const u8) bool {
    return std.mem.indexOfScalar(u8, name, '/') == null and isSafeRelativePath(name);
}

const EntryKind = enum {
    path,
    name,
};

fn requireExactSet(
    actual: []const []const u8,
    expected: []const []const u8,
    kind: EntryKind,
) ExactSetError!void {
    for (actual) |entry| {
        const safe = switch (kind) {
            .path => isSafeRelativePath(entry),
            .name => isSafeEvidenceName(entry),
        };
        if (!safe) return error.UnsafeEntry;
    }

    for (actual, 0..) |entry, index| {
        if (contains(actual[0..index], entry)) return error.DuplicateEntry;
    }

    for (actual) |entry| {
        if (!contains(expected, entry)) return error.UnexpectedEntry;
    }

    for (expected) |entry| {
        if (!contains(actual, entry)) return error.MissingEntry;
    }
}

fn contains(entries: []const []const u8, needle: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry, needle)) return true;
    }
    return false;
}

fn isSafePathByte(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => true,
        else => false,
    };
}

fn isSafeSegment(segment: []const u8) bool {
    if (segment.len == 0) return false;
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    return true;
}

fn sortedConcatenation(comptime left: anytype, comptime right: anytype) [left.len + right.len][]const u8 {
    @setEvalBranchQuota(100_000);
    var result: [left.len + right.len][]const u8 = undefined;
    for (left, 0..) |entry, index| result[index] = entry;
    for (right, 0..) |entry, index| result[left.len + index] = entry;

    var index: usize = 1;
    while (index < result.len) : (index += 1) {
        const entry = result[index];
        var insertion_index = index;
        while (insertion_index > 0 and
            std.mem.order(u8, entry, result[insertion_index - 1]) == .lt)
        {
            result[insertion_index] = result[insertion_index - 1];
            insertion_index -= 1;
        }
        result[insertion_index] = entry;
    }
    return result;
}

fn assertSafeSortedUnique(comptime label: []const u8, comptime entries: anytype, comptime kind: EntryKind) void {
    for (entries, 0..) |entry, index| {
        const safe = switch (kind) {
            .path => isSafeRelativePath(entry),
            .name => isSafeEvidenceName(entry),
        };
        if (!safe) @compileError(label ++ " contains an unsafe entry");
        if (index > 0 and std.mem.order(u8, entries[index - 1], entry) != .lt) {
            @compileError(label ++ " must be strictly sorted and unique");
        }
    }
}

comptime {
    @setEvalBranchQuota(100_000);
    if (production_base_target_paths.len != 9) {
        @compileError("production release catalog must contain exactly nine fixed targets");
    }
    if (production_userspace_target_paths.len != 24) {
        @compileError("production release catalog must contain exactly 24 userspace targets");
    }
    if (production_target_paths.len != 33) {
        @compileError("production release catalog must contain exactly 33 targets");
    }
    if (release_evidence_names.len != 10) {
        @compileError("release evidence catalog must contain exactly ten files");
    }
    if (forbidden_verification_paths.len != 17) {
        @compileError("forbidden verification catalog must contain exactly 17 artifacts");
    }

    assertSafeSortedUnique("production base target catalog", production_base_target_paths, .path);
    assertSafeSortedUnique("production userspace target catalog", production_userspace_target_paths, .path);
    assertSafeSortedUnique("production target catalog", production_target_paths, .path);
    assertSafeSortedUnique("release evidence catalog", release_evidence_names, .name);
    assertSafeSortedUnique("forbidden verification catalog", forbidden_verification_paths, .path);

    for (production_target_paths) |path| {
        if (contains(&forbidden_verification_paths, path)) {
            @compileError("production and forbidden verification catalogs must be disjoint");
        }
    }
}

test "production targets are an exact order-independent set" {
    try requireExactProductionTargets(&production_target_paths);

    var permuted = production_target_paths;
    std.mem.swap([]const u8, &permuted[0], &permuted[permuted.len - 1]);
    try requireExactProductionTargets(&permuted);
    try std.testing.expectEqual(@as(usize, 33), productionTargetPaths().len);
    try std.testing.expect(!isProductionTarget("zig-out/bin/zigos-sign"));
    try std.testing.expect(!isProductionTarget("spec/release_security/release_keyring.json"));
    try std.testing.expect(!isProductionTarget("spec/release_security/revoked_release_keys.json"));
}

test "production target validation rejects duplicate missing unexpected and unsafe entries" {
    var duplicate = production_target_paths;
    duplicate[duplicate.len - 1] = duplicate[0];
    try std.testing.expectError(error.DuplicateEntry, requireExactProductionTargets(&duplicate));

    try std.testing.expectError(
        error.MissingEntry,
        requireExactProductionTargets(production_target_paths[0 .. production_target_paths.len - 1]),
    );

    var unexpected = production_target_paths;
    unexpected[0] = "build/unlisted.iso";
    try std.testing.expectError(error.UnexpectedEntry, requireExactProductionTargets(&unexpected));

    var unsafe = production_target_paths;
    unsafe[0] = "../build/os.iso";
    try std.testing.expectError(error.UnsafeEntry, requireExactProductionTargets(&unsafe));

    var duplicate_unexpected = production_target_paths;
    duplicate_unexpected[0] = "build/unlisted.iso";
    duplicate_unexpected[1] = "build/unlisted.iso";
    try std.testing.expectError(
        error.DuplicateEntry,
        requireExactProductionTargets(&duplicate_unexpected),
    );
}

test "release evidence is exact and root metadata is not an implicit trust anchor" {
    try requireExactReleaseEvidenceNames(&release_evidence_names);
    try std.testing.expect(isReleaseEvidenceName(root_metadata_evidence_name));
    try std.testing.expect(!isReleaseEvidenceName("release-keyring.json"));
    try std.testing.expect(!isReleaseEvidenceName("revoked-release-keys.json"));

    var duplicate = release_evidence_names;
    duplicate[duplicate.len - 1] = duplicate[0];
    try std.testing.expectError(error.DuplicateEntry, requireExactReleaseEvidenceNames(&duplicate));

    var nested = release_evidence_names;
    nested[0] = "nested/artifact-digests.sha256";
    try std.testing.expectError(error.UnsafeEntry, requireExactReleaseEvidenceNames(&nested));
}

test "forbidden verification artifacts are explicit and disjoint" {
    try requireExactForbiddenVerificationPaths(&forbidden_verification_paths);
    try std.testing.expect(isForbiddenVerificationPath("build/os-verification.iso"));
    try std.testing.expect(isForbiddenVerificationPath(
        "zig-out/bin/kernel-zigos-native-tampered-kernel.elf",
    ));
    try std.testing.expect(!isForbiddenVerificationPath("zig-out/bin/kernel-zigos-native.elf"));
}

test "relative path validation rejects traversal aliases and metacharacters" {
    const safe = [_][]const u8{
        "build/os.iso",
        "spec/release_security/release_artifacts.json",
        "zig-out/bin/userspace-sync.elf",
    };
    for (safe) |path| try std.testing.expect(isSafeRelativePath(path));

    const unsafe = [_][]const u8{
        "",
        "/build/os.iso",
        "build/os.iso/",
        "build//os.iso",
        "./build/os.iso",
        "build/../os.iso",
        "build\\os.iso",
        "build/os*.iso",
        "build/os iso",
    };
    for (unsafe) |path| try std.testing.expect(!isSafeRelativePath(path));
}
