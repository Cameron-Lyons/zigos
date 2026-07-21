const std = @import("std");
const common = @import("check_common");

const abi = @import("native/core/abi.zig");
const binary_cursor = @import("binary_cursor");
const capability = @import("native/kernel_api/capability.zig");
const crash_record = @import("kernel/platform/crash_record.zig");
const elf_image_inspector = @import("native/task/elf_image_inspector.zig");
const manifest = @import("native/policy/manifest.zig");
const object_store = @import("native/storage/object_store.zig");
const release_catalog = @import("tools/release_catalog.zig");
const request_header = @import("native/core/request_header.zig");
const storage_volume = @import("native/storage/storage_volume.zig");
const sync_state_store = @import("native/sync/sync_state_store.zig");
const syscall_dispatch = @import("native/kernel_api/syscall_dispatch.zig");
const userspace_descriptor = @import("native/task/userspace_descriptor.zig");
const workspace = @import("native/storage/workspace.zig");

const FUZZ_CORPUS_PATH = "spec/release_security/fuzz_corpus.json";
const RELEASE_ARTIFACTS_PATH = "spec/release_security/release_artifacts.json";
const THREAT_MODEL_PATH = "spec/release_security/threat_model.json";
const MEMORY_SAFETY_INVENTORY_PATH = "spec/release_security/memory_safety_inventory.json";
const CRASH_DUMP_REDACTION_PATH = "spec/release_security/crash_dump_redaction.json";
const VULNERABILITY_DISCLOSURE_PATH = "spec/release_security/vulnerability_disclosure.json";
const SECURITY_POLICY_PATH = "SECURITY.md";

const REQUIRED_RELEASE_BASE_TARGET_PATHS = release_catalog.production_base_target_paths;
const REQUIRED_PRODUCTION_USERSPACE_PATHS = release_catalog.production_userspace_target_paths;
const REQUIRED_RELEASE_TARGET_PATHS = release_catalog.production_target_paths;
const REQUIRED_RELEASE_EVIDENCE_NAMES = release_catalog.release_evidence_names;

const REQUIRED_HARNESS_IDS = [_][]const u8{
    "binary-cursor",
    "userspace-descriptor",
    "elf-image-metadata",
    "storage-volume-image",
    "sync-record",
    "capability-message",
    "syscall-abi",
    "manifest-permissions",
};

const REQUIRED_THREAT_DOMAINS = [_][]const u8{
    "explicit-authority",
    "privilege-boundaries",
    "boot-trust",
    "recovery",
    "policy-mediation",
    "storage-integrity",
    "sync-trust",
    "diagnostics-privacy",
    "driver-isolation",
};

const UNSAFE_SCAN_PATTERNS = [_][]const u8{
    "@ptrFromInt",
    "@intFromPtr",
    "@ptrCast",
    "@alignCast",
    "asm",
    "extern struct",
    "packed struct",
    "volatile",
    "allowzero",
    "@fieldParentPtr",
    "@atomic",
};

const REDACTION_MARKERS = [_][]const u8{
    "secret",
    "token",
    "capability",
    "private",
    "raw-memory",
    "raw memory",
    "object:",
    "workspace:",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    var summary = GateSummary{};

    try validateFuzzCorpus(allocator, io, &errors, &summary);
    try validateReleaseArtifacts(allocator, io, &errors);
    try validateThreatModel(allocator, io, &errors);
    try validateMemorySafetyInventory(allocator, gpa, io, &errors, &summary);
    try validateCrashDumpRedaction(allocator, io, &errors);
    try validateVulnerabilityDisclosure(allocator, io, &errors);

    if (errors.items.len > 0) {
        common.printErrors(errors.items);
        std.process.exit(1);
    }

    try common.printStdout(
        io,
        "Release security gate OK: {d} fuzz cases, {d} unsafe source files audited\n",
        .{ summary.fuzz_cases, summary.unsafe_paths },
    );
}

const GateSummary = struct {
    fuzz_cases: usize = 0,
    unsafe_paths: usize = 0,
};

fn validateFuzzCorpus(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    summary: *GateSummary,
) !void {
    const root = try parseJsonFile(allocator, io, errors, FUZZ_CORPUS_PATH) orelse return;
    const min_mutations = try expectPositiveIntegerField(
        allocator,
        errors,
        root,
        "fuzz corpus",
        "minimum_mutations_per_seed",
    ) orelse 0;
    if (min_mutations < 64) {
        try common.addError(errors, allocator, "fuzz corpus minimum_mutations_per_seed must be at least 64", .{});
    }

    const harnesses_value = common.field(root, "harnesses") orelse {
        try common.addError(errors, allocator, "fuzz corpus must include harnesses", .{});
        return;
    };
    const harnesses = switch (harnesses_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "fuzz corpus harnesses must be an array", .{});
            return;
        },
    };

    var seen = std.StringHashMap(void).init(allocator);
    for (harnesses, 0..) |harness, index| {
        if (harness != .object) {
            try common.addError(errors, allocator, "fuzz harness at index {d} must be an object", .{index});
            continue;
        }
        const id = try common.expectStringField(allocator, errors, harness, "fuzz harness", "id") orelse continue;
        const gop = try seen.getOrPut(id);
        if (gop.found_existing) {
            try common.addError(errors, allocator, "duplicate fuzz harness id: {s}", .{id});
        }
        if (!isOneOf(id, &REQUIRED_HARNESS_IDS)) {
            try common.addError(errors, allocator, "unsupported fuzz harness id: {s}", .{id});
        }

        const target_anchor = try common.expectStringField(allocator, errors, harness, id, "target_anchor") orelse "";
        if (target_anchor.len > 0 and !common.pathExists(io, target_anchor)) {
            try common.addError(errors, allocator, "fuzz harness {s} target_anchor is missing: {s}", .{ id, target_anchor });
        }
        _ = try common.expectStringField(allocator, errors, harness, id, "scope");

        const seeds = try common.collectStringArray(
            allocator,
            errors,
            common.field(harness, "seeds"),
            try std.fmt.allocPrint(allocator, "fuzz harness {s} seeds", .{id}),
            true,
        );
        if (seeds.len < 3) {
            try common.addError(errors, allocator, "fuzz harness {s} must include at least three seeds", .{id});
        }
        for (seeds) |seed_hex| {
            const seed = try decodeHex(allocator, errors, id, seed_hex);
            if (seed.len == 0) continue;
            try runHarnessMutations(id, seed, min_mutations, summary);
        }
    }

    for (REQUIRED_HARNESS_IDS) |required| {
        if (!seen.contains(required)) {
            try common.addError(errors, allocator, "fuzz corpus missing harness: {s}", .{required});
        }
    }
}

fn runHarnessMutations(
    id: []const u8,
    seed: []const u8,
    min_mutations: u64,
    summary: *GateSummary,
) !void {
    var mutated: [8192]u8 = undefined;

    runFuzzHarness(id, seed);
    summary.fuzz_cases += 1;

    var mutation_index: u64 = 0;
    while (mutation_index < min_mutations) : (mutation_index += 1) {
        var len = @min(seed.len, mutated.len);
        @memcpy(mutated[0..len], seed[0..len]);
        if (len == 0) {
            mutated[0] = @intCast(mutation_index & 0xff);
            len = 1;
        }

        const position: usize = @intCast(mutation_index % len);
        switch (mutation_index % 6) {
            0 => mutated[position] ^= @as(u8, 1) << @as(u3, @intCast(mutation_index & 7)),
            1 => mutated[position] = @intCast((mutation_index *% 37) & 0xff),
            2 => if (len < mutated.len) {
                mutated[len] = @intCast((mutation_index *% 131) & 0xff);
                len += 1;
            },
            3 => len = @max(@as(usize, 1), len / 2),
            4 => @memset(mutated[0..len], @intCast((mutation_index *% 17) & 0xff)),
            else => {
                var byte_index: usize = 0;
                while (byte_index < len) : (byte_index += 1) {
                    mutated[byte_index] +%= @intCast((mutation_index + byte_index) & 0xff);
                }
            },
        }
        runFuzzHarness(id, mutated[0..len]);
        summary.fuzz_cases += 1;
    }
}

fn runFuzzHarness(id: []const u8, input: []const u8) void {
    if (std.mem.eql(u8, id, "binary-cursor")) return fuzzBinaryCursor(input);
    if (std.mem.eql(u8, id, "userspace-descriptor")) return fuzzUserspaceDescriptor(input);
    if (std.mem.eql(u8, id, "elf-image-metadata")) return fuzzElfImageMetadata(input);
    if (std.mem.eql(u8, id, "storage-volume-image")) return fuzzStorageVolumeImage(input);
    if (std.mem.eql(u8, id, "sync-record")) return fuzzSyncRecord(input);
    if (std.mem.eql(u8, id, "capability-message")) return fuzzCapabilityMessage(input);
    if (std.mem.eql(u8, id, "syscall-abi")) return fuzzSyscallAbi(input);
    if (std.mem.eql(u8, id, "manifest-permissions")) return fuzzManifestPermissions(input);
}

fn fuzzBinaryCursor(input: []const u8) void {
    const Error = error{Corrupt};
    const Reader = binary_cursor.Reader(Error, error.Corrupt);
    var reader = Reader{ .buffer = input };
    _ = reader.readByte() catch {};
    _ = reader.readU16() catch {};
    _ = reader.readU32() catch {};
    _ = reader.readU64() catch {};
    _ = reader.readSlice(@min(@as(usize, 3), input.len)) catch {};
}

fn fuzzUserspaceDescriptor(input: []const u8) void {
    var descriptor = std.mem.zeroes(userspace_descriptor.Descriptor);
    const bytes = std.mem.asBytes(&descriptor);
    @memcpy(bytes[0..@min(bytes.len, input.len)], input[0..@min(bytes.len, input.len)]);
    userspace_descriptor.validate(&descriptor) catch {};
}

fn fuzzElfImageMetadata(input: []const u8) void {
    _ = elf_image_inspector.inspect(input) catch {};
}

fn fuzzStorageVolumeImage(input: []const u8) void {
    var image = [_]u8{0} ** storage_volume.image_bytes;
    @memcpy(image[0..@min(image.len, input.len)], input[0..@min(image.len, input.len)]);
    var volume = storage_volume.Volume.init();
    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    _ = volume.loadFromImage(image[0..], &store, &workspaces) catch {};
}

fn fuzzSyncRecord(input: []const u8) void {
    sync_state_store.validateRecordPayloadForReleaseGate(input) catch {};
}

fn fuzzCapabilityMessage(input: []const u8) void {
    const kind_fields = std.meta.fields(capability.CapabilityTargetKind);
    const right_fields = std.meta.fields(capability.CapabilityRight);
    const kind_value: u8 = if (input.len > 0) input[0] else 0;
    const right_value: u8 = if (input.len > 1) input[1] else 0;
    const kind: capability.CapabilityTargetKind = @enumFromInt(kind_value % kind_fields.len);
    const right: capability.CapabilityRight = @enumFromInt(right_value % right_fields.len);
    const rights = capability.CapabilityRights.single(right).retarget(kind);
    _ = rights.has(right);
    _ = rights.containsAll(rights);
    _ = rights.intersects(capability.CapabilityRights.single(right).retarget(kind));
}

fn fuzzSyscallAbi(input: []const u8) void {
    var header = abi.RequestHeader{
        .operation = abi.opcode(.task_create),
        .correlation_id = 0,
        .subject_task_id = 0,
    };
    const header_bytes = std.mem.asBytes(&header);
    @memcpy(header_bytes[0..@min(header_bytes.len, input.len)], input[0..@min(header_bytes.len, input.len)]);
    request_header.validateHeader(header, abi.opcode(.task_create)) catch {};
    request_header.validateSubjectTask(header, 1) catch {};

    const Error = error{Corrupt};
    const Reader = binary_cursor.Reader(Error, error.Corrupt);
    var reader = Reader{ .buffer = input };
    const raw_addr = reader.readU64() catch 0;
    const raw_len = reader.readU64() catch 0;
    const raw_alignment = reader.readU16() catch 1;
    const alignment: usize = @max(@as(usize, 1), @as(usize, raw_alignment % 64));
    const memory = syscall_dispatch.UserMemoryContext{ .address_space = null };
    _ = syscall_dispatch.validateUserRange(memory, @intCast(raw_addr), @intCast(raw_len), alignment, .read);
    _ = syscall_dispatch.validateUserRange(memory, @intCast(raw_addr), @intCast(raw_len), alignment, .write);
    _ = syscall_dispatch.mapError(error.PermissionDenied);
}

fn fuzzManifestPermissions(input: []const u8) void {
    const remote_network = input.len > 0 and (input[0] & 1) != 0;
    const local_only = input.len > 1 and (input[1] & 1) != 0;
    const duplicate = input.len > 2 and (input[2] & 1) != 0;
    const include_second = input.len <= 3 or (input[3] & 1) != 0;

    const network_permission = manifest.PermissionRequest{
        .kind = .network_egress,
        .resource = "sync.example",
        .rights = .{ .network_policy = .{
            .network_local = !remote_network,
            .network_remote = remote_network,
        } },
        .required = false,
        .local_only = local_only,
        .egress_intent = .{
            .kind = .call_service,
            .service = "sync.example",
        },
    };
    const object_permission = manifest.PermissionRequest{
        .kind = .object_access,
        .resource = "workspace:notes",
        .rights = .{ .object = .{ .object_read = true } },
        .required = false,
        .local_only = true,
    };
    const permissions = [_]manifest.PermissionRequest{
        network_permission,
        if (duplicate) network_permission else object_permission,
    };

    _ = manifest.validate(.{
        .bundle_id = "app.fuzz.permissions",
        .display_name = "Fuzz Permissions",
        .publisher = "zigos.release",
        .requested_permissions = permissions[0..if (include_second) 2 else 1],
    }) catch {};
}

const ReleaseArtifactSelection = struct {
    exact_paths: []const []const u8,
    forbidden_paths: []const []const u8,
};

fn validateReleaseArtifactSelectionPolicy(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    root: std.json.Value,
) !?ReleaseArtifactSelection {
    const policy = try common.expectObjectField(
        allocator,
        errors,
        root,
        "release artifacts",
        "release_artifact_selection",
    ) orelse return null;
    try expectFalseBoolField(allocator, errors, policy, "release artifact selection", "directory_sweeps_allowed");
    try expectTrueBoolField(allocator, errors, policy, "release artifact selection", "reject_unlisted_artifacts");
    try expectTrueBoolField(allocator, errors, policy, "release artifact selection", "verification_artifacts_forbidden");

    const exact_paths = try common.collectStringArray(
        allocator,
        errors,
        common.field(policy, "exact_paths"),
        "release artifact selection exact_paths",
        true,
    );
    release_catalog.requireExactProductionTargets(exact_paths) catch |err| {
        try common.addError(
            errors,
            allocator,
            "release artifact selection exact_paths must equal the exact 33-target production catalog: {s}",
            .{@errorName(err)},
        );
    };

    const forbidden_paths = try common.collectStringArray(
        allocator,
        errors,
        common.field(policy, "forbidden_paths"),
        "release artifact selection forbidden_paths",
        true,
    );
    release_catalog.requireExactForbiddenVerificationPaths(forbidden_paths) catch |err| {
        try common.addError(
            errors,
            allocator,
            "release artifact selection forbidden_paths must equal the exact verification-artifact denylist: {s}",
            .{@errorName(err)},
        );
    };

    return .{
        .exact_paths = exact_paths,
        .forbidden_paths = forbidden_paths,
    };
}

fn releaseArtifactPathAllowed(selection: ReleaseArtifactSelection, path: []const u8) bool {
    _ = selection;
    return release_catalog.isProductionTarget(path);
}

fn validateShellReleaseArtifactArray(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    source: []const u8,
    variable_name: []const u8,
    expected_paths: []const []const u8,
) !void {
    const marker = try std.fmt.allocPrint(allocator, "{s}=(", .{variable_name});
    const marker_offset = std.mem.indexOf(u8, source, marker) orelse {
        try common.addError(errors, allocator, "release script must declare {s} as a literal path array", .{variable_name});
        return;
    };
    const body_start = marker_offset + marker.len;
    const body_end_offset = std.mem.indexOf(u8, source[body_start..], "\n)") orelse {
        try common.addError(errors, allocator, "release script {s} array must have a closing parenthesis", .{variable_name});
        return;
    };
    const body = source[body_start .. body_start + body_end_offset];

    var declared_paths = std.ArrayList([]const u8).empty;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line.len < 2 or line[0] != '"' or line[line.len - 1] != '"') {
            try common.addError(errors, allocator, "release script {s} entries must be literal quoted paths: {s}", .{ variable_name, line });
            continue;
        }
        try declared_paths.append(allocator, line[1 .. line.len - 1]);
    }

    var declared_set = try common.collectUniqueStrings(
        allocator,
        errors,
        declared_paths.items,
        try std.fmt.allocPrint(allocator, "release script {s} path", .{variable_name}),
    );
    for (expected_paths) |path| {
        if (!declared_set.contains(path)) {
            try common.addError(errors, allocator, "release script {s} must include {s}", .{ variable_name, path });
        }
    }
    for (declared_paths.items) |path| {
        if (!isOneOf(path, expected_paths)) {
            try common.addError(errors, allocator, "release script {s} contains an unapproved path: {s}", .{ variable_name, path });
        }
    }
}

fn validateReleaseArtifacts(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const root = try parseJsonFile(allocator, io, errors, RELEASE_ARTIFACTS_PATH) orelse return;
    const generator = try common.expectStringField(allocator, errors, root, "release artifacts", "generator") orelse "";
    if (generator.len > 0 and !common.pathExists(io, generator)) {
        try common.addError(errors, allocator, "release artifact generator is missing: {s}", .{generator});
    }
    if (generator.len > 0 and common.pathExists(io, generator)) {
        const generator_source = try common.readFileAlloc(allocator, io, generator, common.source_file_max_bytes);
        const required_generator_snippets = [_][]const u8{
            "command -v jj",
            "repo_vcs=\"jj\"",
            "jj -R \"$ROOT_DIR\" git remote list",
            "repo_change_id=\"$(jj -R \"$ROOT_DIR\" log -r @ --no-graph",
            "commit_sha=\"$(jj -R \"$ROOT_DIR\" log -r @ --no-graph",
            "dirty_count=\"$(jj -R \"$ROOT_DIR\" diff -r @ --name-only",
            "sourceControl",
            "changeId",
            "RELEASE_OPTIMIZE_MODE",
            "optimizeMode",
            "buildType",
            "https://github.com/Cameron-Lyons/zigos/release-security-gate",
            "zigos-local-release-security-gate",
            "require_artifact_path",
            "missing_required_artifacts",
            "missing required release artifact",
            "REQUIRED_RELEASE_ARTIFACTS",
            "PRODUCTION_USERSPACE_ARTIFACTS",
            "is_forbidden_release_artifact",
            "is_allowed_release_artifact",
            "collect_production_userspace_artifacts",
            "artifact is outside the production release allowlist",
            "ZIGOS_RELEASE_TRUST_ROOT",
            "ZIGOS_RELEASE_TRUST_ROOT_SHA256",
            "ZIGOS_RELEASE_TRUST_POLICY",
            "ZIGOS_RELEASE_VERIFIER",
            "ZIGOS_RELEASE_VERIFIER_SHA256",
            "ZIGOS_RELEASE_DSSE_SIGN_COMMAND",
            "ZIGOS_RELEASE_SIGNING_KEY_ID",
            "ZIGOS_RELEASE_HARDWARE_BACKED",
            "trust-info",
            "--trusted-root",
            "--trusted-root-sha256",
            "--release-key-id",
            "root-metadata.json",
            "release-trust-policy.dsse.json",
            "verifier_bootstrap",
            "minimumPolicyVersion",
            "minimumReleaseSequence",
            "produced malformed DSSE signature; expected non-empty standard base64",
        };
        for (required_generator_snippets) |snippet| {
            if (std.mem.indexOf(u8, generator_source, snippet) == null) {
                try common.addError(errors, allocator, "release artifact generator must enforce Jujutsu provenance snippet: {s}", .{snippet});
            }
        }
        try validateShellReleaseArtifactArray(allocator, errors, generator_source, "REQUIRED_RELEASE_ARTIFACTS", &REQUIRED_RELEASE_BASE_TARGET_PATHS);
        try validateShellReleaseArtifactArray(allocator, errors, generator_source, "PRODUCTION_USERSPACE_ARTIFACTS", &REQUIRED_PRODUCTION_USERSPACE_PATHS);
        for (REQUIRED_RELEASE_BASE_TARGET_PATHS) |path| {
            if (std.mem.indexOf(u8, generator_source, path) == null) {
                try common.addError(errors, allocator, "release artifact generator production allowlist must include {s}", .{path});
            }
        }
        for (REQUIRED_PRODUCTION_USERSPACE_PATHS) |path| {
            if (std.mem.indexOf(u8, generator_source, path) == null) {
                try common.addError(errors, allocator, "release artifact generator production userspace allowlist must include {s}", .{path});
            }
        }
        if (std.mem.indexOf(u8, generator_source, "git -C \"$ROOT_DIR\"") != null) {
            try common.addError(errors, allocator, "release artifact generator must use Jujutsu metadata instead of raw git -C provenance lookups", .{});
        }
        if (std.mem.indexOf(u8, generator_source, "require_artifact_path \"zig-out/bin\"") != null or
            std.mem.indexOf(u8, generator_source, "find \"$absolute_path\" -type f") != null or
            std.mem.indexOf(u8, generator_source, "find \"$userspace_dir\"") != null)
        {
            try common.addError(errors, allocator, "release artifact generator must not sweep an output directory into the production release", .{});
        }
    }
    const repro_checker = try common.expectStringField(allocator, errors, root, "release artifacts", "reproducible_build_checker") orelse "";
    if (repro_checker.len > 0 and !common.pathExists(io, repro_checker)) {
        try common.addError(errors, allocator, "reproducible build checker is missing: {s}", .{repro_checker});
    }
    if (repro_checker.len > 0 and common.pathExists(io, repro_checker)) {
        const repro_source = try common.readFileAlloc(allocator, io, repro_checker, common.source_file_max_bytes);
        const required_repro_snippets = [_][]const u8{
            "command -v jj",
            "jj -R \"$ROOT_DIR\" file list -r @",
            "repo_vcs=\"jj\"",
            "jj -R \"$ROOT_DIR\" git remote list",
            "repo_change_id=\"$(jj -R \"$ROOT_DIR\" log -r @ --no-graph",
            "commit_sha=\"$(jj -R \"$ROOT_DIR\" log -r @ --no-graph",
            "dirty_count=\"$(jj -R \"$ROOT_DIR\" diff -r @ --name-only",
            "\"repo_vcs\": \"$repo_vcs\"",
            "\"repository\":",
            "\"repo_change_id\":",
            "\"dirty_workspace_file_count\":",
            "\"optimize_mode\": \"ReleaseFast\"",
            "-Doptimize=ReleaseFast",
            "REQUIRED_RELEASE_ARTIFACTS",
            "PRODUCTION_USERSPACE_ARTIFACTS",
            "is_forbidden_release_artifact",
            "is_allowed_release_artifact",
            "outside the production release allowlist",
        };
        for (required_repro_snippets) |snippet| {
            if (std.mem.indexOf(u8, repro_source, snippet) == null) {
                try common.addError(errors, allocator, "reproducible build checker must enforce Jujutsu provenance snippet: {s}", .{snippet});
            }
        }
        try validateShellReleaseArtifactArray(allocator, errors, repro_source, "REQUIRED_RELEASE_ARTIFACTS", &REQUIRED_RELEASE_BASE_TARGET_PATHS);
        try validateShellReleaseArtifactArray(allocator, errors, repro_source, "PRODUCTION_USERSPACE_ARTIFACTS", &REQUIRED_PRODUCTION_USERSPACE_PATHS);
        for (REQUIRED_RELEASE_BASE_TARGET_PATHS) |path| {
            if (std.mem.indexOf(u8, repro_source, path) == null) {
                try common.addError(errors, allocator, "reproducible build production allowlist must include {s}", .{path});
            }
        }
        for (REQUIRED_PRODUCTION_USERSPACE_PATHS) |path| {
            if (std.mem.indexOf(u8, repro_source, path) == null) {
                try common.addError(errors, allocator, "reproducible build production userspace allowlist must include {s}", .{path});
            }
        }
        if (std.mem.indexOf(u8, repro_source, "git -C \"$ROOT_DIR\"") != null) {
            try common.addError(errors, allocator, "reproducible build checker must use Jujutsu metadata instead of raw git -C provenance lookups", .{});
        }
        if (std.mem.indexOf(u8, repro_source, "find \"$tree/zig-out/bin\"") != null) {
            try common.addError(errors, allocator, "reproducible build checker must not sweep the binary output directory into the production manifest", .{});
        }
    }
    const finalizer = try common.expectStringField(allocator, errors, root, "release artifacts", "release_manifest_finalizer") orelse "";
    if (finalizer.len > 0 and !common.pathExists(io, finalizer)) {
        try common.addError(errors, allocator, "release manifest finalizer is missing: {s}", .{finalizer});
    }
    if (finalizer.len > 0 and common.pathExists(io, finalizer)) {
        const finalizer_source = try common.readFileAlloc(allocator, io, finalizer, common.source_file_max_bytes);
        const required_finalizer_snippets = [_][]const u8{
            "ZIGOS_RELEASE_TRUST_ROOT",
            "ZIGOS_RELEASE_TRUST_ROOT_SHA256",
            "ZIGOS_RELEASE_TRUST_POLICY",
            "ZIGOS_RELEASE_TRUST_STATE",
            "ZIGOS_RELEASE_VERIFIER",
            "ZIGOS_RELEASE_VERIFIER_SHA256",
            "ZIGOS_RELEASE_DSSE_SIGN_COMMAND",
            "ZIGOS_RELEASE_SIGNING_KEY_ID",
            "ZIGOS_RELEASE_SEQUENCE",
            "ZIGOS_RELEASE_EXPIRES_AT",
            "release-manifest.dsse.json",
            "application/vnd.zigos.release-manifest.v1+json",
            "trust-info",
            "verify-candidate",
            ".finalize.lock",
            "mkdir -m 0700",
            "--trusted-root",
            "--trusted-root-sha256",
            "--release-key-id",
        };
        for (required_finalizer_snippets) |snippet| {
            if (std.mem.indexOf(u8, finalizer_source, snippet) == null) {
                try common.addError(errors, allocator, "release manifest finalizer must enforce authenticated publication snippet: {s}", .{snippet});
            }
        }
    }
    const pinned_verifier_runner = try common.expectStringField(allocator, errors, root, "release artifacts", "pinned_verifier_runner") orelse "";
    if (pinned_verifier_runner.len > 0 and !common.pathExists(io, pinned_verifier_runner)) {
        try common.addError(errors, allocator, "pinned release verifier runner is missing: {s}", .{pinned_verifier_runner});
    }
    if (pinned_verifier_runner.len > 0 and common.pathExists(io, pinned_verifier_runner)) {
        const runner_source = try common.readFileAlloc(allocator, io, pinned_verifier_runner, common.source_file_max_bytes);
        const required_runner_snippets = [_][]const u8{
            "VERIFIER_SHA256",
            "mktemp -d",
            "cp \"$VERIFIER\"",
            "sha256_file \"$pinned_verifier\"",
            "--trusted-root-sha256",
            "--trust-state",
        };
        for (required_runner_snippets) |snippet| {
            if (std.mem.indexOf(u8, runner_source, snippet) == null) {
                try common.addError(errors, allocator, "pinned release verifier runner must enforce exact-copy execution snippet: {s}", .{snippet});
            }
        }
    }
    const customer_verifier_source = try common.expectStringField(allocator, errors, root, "release artifacts", "customer_verifier_source") orelse "";
    if (customer_verifier_source.len > 0 and !common.pathExists(io, customer_verifier_source)) {
        try common.addError(errors, allocator, "customer verifier source is missing: {s}", .{customer_verifier_source});
    }
    if (customer_verifier_source.len > 0 and common.pathExists(io, customer_verifier_source)) {
        const customer_verifier = try common.readFileAlloc(allocator, io, customer_verifier_source, common.source_file_max_bytes);
        const required_customer_verifier_snippets = [_][]const u8{
            "trust-info",
            "verify",
            "verify-candidate",
            "--bundle",
            "--artifacts",
            "--trusted-root",
            "--trusted-root-sha256",
            "--trust-state",
            "release-manifest.dsse.json",
            "release-trust-policy.dsse.json",
            "root-metadata.json",
            "release_catalog",
            "release_trust",
            "verifySlsaSourceParameters",
            "release_slsa_build_type",
            "release_slsa_builder_id",
            "\"buildType\"",
            "\"builder\"",
            "\"sourceControl\"",
            "\"changeId\"",
            "\"repo_vcs\"",
            "\"repository\"",
            "\"repo_change_id\"",
            "\"dirty_workspace_file_count\"",
            "\"dirtyWorkspaceFileCount\"",
            "\"optimizeMode\"",
            "\"optimize_mode\"",
            "release_optimize_mode",
            "InvalidSlsaSourceControl",
            "InvalidSlsaBuildType",
            "InvalidSlsaBuilderId",
            "SlsaStatementSubjectCardinalityInvalid",
            "InvalidSlsaChangeId",
            "InvalidSlsaCommitId",
            "InvalidSlsaRepository",
            "InvalidSlsaZigVersion",
            "InvalidSlsaOptimizeMode",
            "SlsaDirtyWorkspaceEvidence",
            "SlsaSourceIdentityMismatch",
            "ReproducibleBuildSourceControlMismatch",
            "ReproducibleBuildDirtyWorkspace",
            "ReproducibleBuildSourceIdentityMismatch",
            "ReproducibleDigestCoverageMismatch",
            "DuplicateArtifactMeasurement",
            "summary.measurements",
            "summary.reproducible_digests",
            "sourceIdentitiesEqual",
            "looksLikeJjChangeId",
            "looksLikeGitCommitId",
            "verifySlsaRunMetadata",
            "\"startedOn\"",
            "\"invocationId\"",
            "TrustStateTransaction",
            "policyPayloadSha256",
            "manifestPayloadSha256",
            "acl_get_fd_np",
            "TrustStateAclCheckFailed",
        };
        for (required_customer_verifier_snippets) |snippet| {
            if (std.mem.indexOf(u8, customer_verifier, snippet) == null) {
                try common.addError(errors, allocator, "customer release verifier must enforce Jujutsu source identity snippet: {s}", .{snippet});
            }
        }
    }
    const customer_verifier_command = try common.expectStringField(allocator, errors, root, "release artifacts", "customer_verifier_command") orelse "";
    const required_customer_command_terms = [_][]const u8{
        "zigos-verify-release verify",
        "--bundle",
        "--artifacts",
        "--trusted-root",
        "--trusted-root-sha256",
        "--trust-state",
    };
    for (required_customer_command_terms) |term| {
        if (std.mem.indexOf(u8, customer_verifier_command, term) == null) {
            try common.addError(errors, allocator, "release artifacts customer_verifier_command must include {s}", .{term});
        }
    }
    if (customer_verifier_command.len == 0 or customer_verifier_command[0] != '/') {
        try common.addError(errors, allocator, "release artifacts customer_verifier_command must use an absolute independently provisioned verifier", .{});
    }
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "customer_verifier_sha256_required");
    const artifact_measurements = try common.expectStringField(allocator, errors, root, "release artifacts", "artifact_measurements") orelse "";
    if (std.mem.indexOf(u8, artifact_measurements, "artifact-measurements.json") == null) {
        try common.addError(errors, allocator, "release artifacts must declare artifact-measurements.json output", .{});
    }
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "generator_requires_all_release_artifacts");
    const artifact_selection = try validateReleaseArtifactSelectionPolicy(allocator, errors, root) orelse return;
    const required_generator_inputs = try common.collectStringArray(
        allocator,
        errors,
        common.field(root, "required_generator_inputs"),
        "release artifacts required_generator_inputs",
        true,
    );
    release_catalog.requireExactProductionTargets(required_generator_inputs) catch |err| {
        try common.addError(
            errors,
            allocator,
            "release artifacts required_generator_inputs must equal the exact 33-target production catalog: {s}",
            .{@errorName(err)},
        );
    };
    const sbom_format = try common.expectStringField(allocator, errors, root, "release artifacts", "sbom_format") orelse "";
    if (!std.mem.eql(u8, sbom_format, "SPDX-2.3")) {
        try common.addError(errors, allocator, "release artifacts must require SPDX-2.3 SBOM output", .{});
    }
    const provenance_format = try common.expectStringField(allocator, errors, root, "release artifacts", "provenance_format") orelse "";
    if (std.mem.indexOf(u8, provenance_format, "in-toto") == null or std.mem.indexOf(u8, provenance_format, "SLSA") == null) {
        try common.addError(errors, allocator, "release artifacts must require in-toto/SLSA provenance output", .{});
    }
    try expectStringValue(allocator, errors, root, "release artifacts", "provenance_predicate_type", "https://slsa.dev/provenance/v1");
    try expectStringValue(allocator, errors, root, "release artifacts", "source_vcs", "jj");
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "source_change_id_required");
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "source_commit_id_required");
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "customer_verifier_requires_slsa_source_identity");
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "customer_verifier_requires_reproducible_source_identity");
    try expectTrueBoolField(allocator, errors, root, "release artifacts", "customer_verifier_requires_source_identity_consistency");
    const envelope_format = try common.expectStringField(allocator, errors, root, "release artifacts", "attestation_envelope_format") orelse "";
    if (std.mem.indexOf(u8, envelope_format, "DSSE") == null) {
        try common.addError(errors, allocator, "release artifacts must require DSSE attestation envelopes", .{});
    }
    try expectStringValue(allocator, errors, root, "release artifacts", "attestation_payload_type", "application/vnd.in-toto+json");

    const release_bundle = try common.expectObjectField(allocator, errors, root, "release artifacts", "release_bundle") orelse return;
    try expectStringValue(allocator, errors, release_bundle, "release bundle", "directory", "build/release-security");
    try expectStringValue(
        allocator,
        errors,
        release_bundle,
        "release bundle",
        "publication_marker",
        "build/release-security/release-manifest.dsse.json",
    );
    try expectStringValue(
        allocator,
        errors,
        release_bundle,
        "release bundle",
        "manifest_payload_type",
        "application/vnd.zigos.release-manifest.v1+json",
    );
    try expectStringValue(
        allocator,
        errors,
        release_bundle,
        "release bundle",
        "trust_policy_payload_type",
        "application/vnd.zigos.release-trust-policy.v1+json",
    );
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "signed_manifest_is_sole_digest_authority");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "signature_verified_before_payload_parsing");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "candidate_verified_before_publication");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "publication_withdrawn_on_final_verification_failure");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "finalization_lock_required");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "quiescent_authenticated_inputs_required");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "exact_target_set_required");
    try expectTrueBoolField(allocator, errors, release_bundle, "release bundle", "exact_evidence_set_required");
    const release_evidence_names = try common.collectStringArray(
        allocator,
        errors,
        common.field(release_bundle, "evidence_names"),
        "release bundle evidence_names",
        true,
    );
    release_catalog.requireExactReleaseEvidenceNames(release_evidence_names) catch |err| {
        try common.addError(
            errors,
            allocator,
            "release bundle evidence_names must equal the exact ten-file evidence catalog: {s}",
            .{@errorName(err)},
        );
    };

    const release_trust = try common.expectObjectField(allocator, errors, root, "release artifacts", "release_trust") orelse return;
    try expectStringValue(allocator, errors, release_trust, "release trust", "root_metadata_source", "out-of-band");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "root_digest_pin_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "root_threshold_signatures_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "root_minimum_policy_checkpoint_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "policy_minimum_release_checkpoint_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "release_policy_root_threshold_signed");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "release_manifest_release_key_signed");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "revocations_in_signed_policy");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "persistent_rollback_state_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_state_external_to_bundle");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_state_external_to_artifacts");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_state_transaction_lock_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_state_authenticated_payload_digests");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_state_darwin_acl_free_storage_required");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "rollback_and_equivocation_rejected");
    try expectTrueBoolField(allocator, errors, release_trust, "release trust", "independently_pinned_verifier_required");
    const rollback_claim_scope = try common.expectStringField(allocator, errors, release_trust, "release trust", "rollback_claim_scope") orelse "";
    if (std.mem.indexOf(u8, rollback_claim_scope, "minimum checkpoints") == null or
        std.mem.indexOf(u8, rollback_claim_scope, "persistent state") == null)
    {
        try common.addError(errors, allocator, "release trust rollback_claim_scope must cover external checkpoints and local persistent state", .{});
    }
    try expectFalseBoolField(allocator, errors, release_trust, "release trust", "automatic_root_rotation");
    try expectStringValue(
        allocator,
        errors,
        release_trust,
        "release trust",
        "root_rotation_policy",
        "manual out-of-band re-pin and state migration only",
    );

    const release_signing = try common.expectObjectField(allocator, errors, root, "release artifacts", "release_signing") orelse return;
    const provider_boundary = try common.expectStringField(allocator, errors, release_signing, "release signing", "provider_boundary") orelse "";
    if (!containsHardwareReleaseBoundary(provider_boundary)) {
        try common.addError(errors, allocator, "release signing provider_boundary must name a TPM, secure enclave, HSM, or KMS provider boundary", .{});
    }
    if (!common.containsAsciiIgnoreCase(provider_boundary, "key handle") or
        !common.containsAsciiIgnoreCase(provider_boundary, "never seed material"))
    {
        try common.addError(errors, allocator, "release signing provider_boundary must describe key-handle-only access and no seed material in release code", .{});
    }
    try expectTrueBoolField(allocator, errors, release_signing, "release signing", "hardware_backed_required");
    try expectTrueBoolField(allocator, errors, release_signing, "release signing", "revocation_required");
    try expectTrueBoolField(allocator, errors, release_signing, "release signing", "customer_verifiable_required");
    try expectTrueBoolField(allocator, errors, release_signing, "release signing", "external_signer_required");
    try expectTrueBoolField(allocator, errors, release_signing, "release signing", "dsse_signature_output_base64_required");
    const post_quantum_policy = try common.expectObjectField(allocator, errors, release_signing, "release signing", "post_quantum_policy") orelse return;
    try validatePostQuantumReleasePolicy(allocator, errors, post_quantum_policy);
    const verifier_protocols = try common.collectStringArray(
        allocator,
        errors,
        common.field(release_signing, "verifier_protocols"),
        "release signing verifier_protocols",
        true,
    );
    const required_verifier_protocol_terms = [_][]const u8{
        "out-of-band",
        "root metadata",
        "root threshold",
        "release-trust-policy.dsse.json",
        "release-manifest.dsse.json",
        "sole digest authority",
        "before parsing",
        "exact 33",
        "exact ten",
        "persistent rollback state",
        "external to the bundle",
        "equivocation",
        "manual root rotation",
        "minimumPolicyVersion",
        "minimumReleaseSequence",
        "descriptor-relative",
        "authenticated decoded",
        "extended ACL",
        "quiescent",
        "DSSE",
        "SLSA",
        "Jujutsu",
        "changeId",
        "post_quantum_policy",
        "FIPS 203",
        "ML-KEM",
        "FIPS 204",
        "ML-DSA",
        "FIPS 205",
        "SLH-DSA",
        "revoked",
        "required ML-DSA",
        "artifact-measurements",
        "reproducible-build",
        "zigos-verify-release",
    };
    for (required_verifier_protocol_terms) |term| {
        if (!stringArrayContainsSubstring(verifier_protocols, term)) {
            try common.addError(errors, allocator, "release signing verifier_protocols must cover {s}", .{term});
        }
    }
    const generator_required_environment = try common.collectStringArray(
        allocator,
        errors,
        common.field(release_signing, "generator_required_environment"),
        "release signing generator_required_environment",
        true,
    );
    const required_signing_environment = [_][]const u8{
        "ZIGOS_RELEASE_TRUST_ROOT",
        "ZIGOS_RELEASE_TRUST_ROOT_SHA256",
        "ZIGOS_RELEASE_TRUST_POLICY",
        "ZIGOS_RELEASE_VERIFIER",
        "ZIGOS_RELEASE_VERIFIER_SHA256",
        "ZIGOS_RELEASE_DSSE_SIGN_COMMAND",
        "ZIGOS_RELEASE_SIGNING_KEY_ID",
        "ZIGOS_RELEASE_HARDWARE_BACKED",
    };
    if (generator_required_environment.len != required_signing_environment.len) {
        try common.addError(errors, allocator, "release signing generator_required_environment must equal the exact required environment set", .{});
    }
    for (required_signing_environment) |name| {
        if (!stringArrayContains(generator_required_environment, name)) {
            try common.addError(errors, allocator, "release signing generator_required_environment must include {s}", .{name});
        }
    }
    const finalizer_additional_environment = try common.collectStringArray(
        allocator,
        errors,
        common.field(release_signing, "finalizer_additional_environment"),
        "release signing finalizer_additional_environment",
        true,
    );
    const required_finalizer_environment = [_][]const u8{
        "ZIGOS_RELEASE_TRUST_STATE",
        "ZIGOS_RELEASE_SEQUENCE",
        "ZIGOS_RELEASE_EXPIRES_AT",
    };
    if (finalizer_additional_environment.len != required_finalizer_environment.len) {
        try common.addError(errors, allocator, "release signing finalizer_additional_environment must equal the exact required environment set", .{});
    }
    for (required_finalizer_environment) |name| {
        if (!stringArrayContains(finalizer_additional_environment, name)) {
            try common.addError(errors, allocator, "release signing finalizer_additional_environment must include {s}", .{name});
        }
    }

    const artifacts_value = common.field(root, "release_artifacts") orelse {
        try common.addError(errors, allocator, "release_artifacts must be present", .{});
        return;
    };
    const artifacts = switch (artifacts_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "release_artifacts must be an array", .{});
            return;
        },
    };
    if (artifacts.len < 4) {
        try common.addError(errors, allocator, "release_artifacts must cover kernel, userspace, ISO, and policy artifacts", .{});
    }
    var has_production_userspace_set = false;
    var declared_target_paths = std.ArrayList([]const u8).empty;
    for (artifacts, 0..) |artifact, index| {
        if (artifact != .object) {
            try common.addError(errors, allocator, "release artifact at index {d} must be an object", .{index});
            continue;
        }
        const id = try common.expectStringField(allocator, errors, artifact, "release artifact", "id") orelse "<unknown>";
        const has_path = common.field(artifact, "path") != null;
        const has_paths = common.field(artifact, "paths") != null;
        if (has_path == has_paths) {
            try common.addError(errors, allocator, "release artifact {s} must include exactly one of path or paths", .{id});
        } else if (has_path) {
            const path = try common.expectStringField(allocator, errors, artifact, id, "path") orelse "";
            if (path.len > 0) try declared_target_paths.append(allocator, path);
            if (path.len > 0 and !releaseArtifactPathAllowed(artifact_selection, path)) {
                try common.addError(errors, allocator, "release artifact {s} path is outside the production release allowlist: {s}", .{ id, path });
            }
        } else {
            const paths = try common.collectStringArray(
                allocator,
                errors,
                common.field(artifact, "paths"),
                try std.fmt.allocPrint(allocator, "release artifact {s} paths", .{id}),
                true,
            );
            try declared_target_paths.appendSlice(allocator, paths);
            if (!std.mem.eql(u8, id, "production-userspace-images")) {
                try common.addError(errors, allocator, "only production-userspace-images may declare a release artifact path set", .{});
            } else {
                has_production_userspace_set = true;
            }
            var path_set = try common.collectUniqueStrings(allocator, errors, paths, "release artifact path");
            for (REQUIRED_PRODUCTION_USERSPACE_PATHS) |required_path| {
                if (!path_set.contains(required_path)) {
                    try common.addError(errors, allocator, "production-userspace-images paths must include {s}", .{required_path});
                }
            }
            for (paths) |path| {
                if (!isOneOf(path, &REQUIRED_PRODUCTION_USERSPACE_PATHS)) {
                    try common.addError(errors, allocator, "production-userspace-images contains an unapproved path: {s}", .{path});
                }
            }
        }
        _ = try common.expectStringField(allocator, errors, artifact, id, "kind");
        try expectTrueBoolField(allocator, errors, artifact, id, "digest_required");
        try expectTrueBoolField(allocator, errors, artifact, id, "sbom_required");
        try expectTrueBoolField(allocator, errors, artifact, id, "provenance_required");
        try expectTrueBoolField(allocator, errors, artifact, id, "dsse_required");
        try expectTrueBoolField(allocator, errors, artifact, id, "reproducible_required");
        try expectTrueBoolField(allocator, errors, artifact, id, "customer_verifiable");
    }
    if (!has_production_userspace_set) {
        try common.addError(errors, allocator, "release_artifacts must declare the production-userspace-images path set", .{});
    }
    release_catalog.requireExactProductionTargets(declared_target_paths.items) catch |err| {
        try common.addError(
            errors,
            allocator,
            "release_artifacts must cover the exact 33-target production catalog once: {s}",
            .{@errorName(err)},
        );
    };
}

test "release policy uses the exact authenticated production catalogs" {
    try std.testing.expectEqual(@as(usize, 33), REQUIRED_RELEASE_TARGET_PATHS.len);
    try std.testing.expectEqual(@as(usize, 10), REQUIRED_RELEASE_EVIDENCE_NAMES.len);
    try std.testing.expect(release_catalog.isProductionTarget("build/os.iso"));
    try std.testing.expect(!release_catalog.isProductionTarget("zig-out/bin/zigos-verify-release"));
    try std.testing.expect(!release_catalog.isProductionTarget("zig-out/bin/zigos-sign"));
    try std.testing.expect(!release_catalog.isProductionTarget("build/os-verification.iso"));
    try std.testing.expect(!release_catalog.isProductionTarget("spec/release_security/release_keyring.json"));
    try std.testing.expect(!release_catalog.isProductionTarget("spec/release_security/revoked_release_keys.json"));
}

test "release evidence excludes bundle-controlled trust authorities" {
    try std.testing.expect(release_catalog.isReleaseEvidenceName("root-metadata.json"));
    try std.testing.expect(release_catalog.isReleaseEvidenceName("release-trust-policy.dsse.json"));
    try std.testing.expect(!release_catalog.isReleaseEvidenceName("release-manifest.dsse.json"));
    try std.testing.expect(!release_catalog.isReleaseEvidenceName("release-keyring.json"));
    try std.testing.expect(!release_catalog.isReleaseEvidenceName("revoked-release-keys.json"));
}

fn validateThreatModel(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const root = try parseJsonFile(allocator, io, errors, THREAT_MODEL_PATH) orelse return;
    const required_domains = try common.collectStringArray(
        allocator,
        errors,
        common.field(root, "required_domains"),
        "threat model required_domains",
        true,
    );
    var required_domain_set = try common.collectUniqueStrings(allocator, errors, required_domains, "threat model required domain");
    for (REQUIRED_THREAT_DOMAINS) |domain| {
        if (!required_domain_set.contains(domain)) {
            try common.addError(errors, allocator, "threat model missing required domain: {s}", .{domain});
        }
    }

    const threats_value = common.field(root, "threats") orelse {
        try common.addError(errors, allocator, "threat model must include threats", .{});
        return;
    };
    const threats = switch (threats_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "threat model threats must be an array", .{});
            return;
        },
    };
    var covered_domains = std.StringHashMap(void).init(allocator);
    for (threats, 0..) |threat, index| {
        if (threat != .object) {
            try common.addError(errors, allocator, "threat at index {d} must be an object", .{index});
            continue;
        }
        const id = try common.expectStringField(allocator, errors, threat, "threat", "id") orelse "<unknown>";
        const domain = try common.expectStringField(allocator, errors, threat, id, "domain") orelse "";
        if (domain.len > 0) {
            if (!required_domain_set.contains(domain)) {
                try common.addError(errors, allocator, "threat {s} references unsupported domain: {s}", .{ id, domain });
            }
            try covered_domains.put(domain, {});
        }
        _ = try common.expectStringField(allocator, errors, threat, id, "abuse_case");
        _ = try common.expectStringField(allocator, errors, threat, id, "mitigation");
        _ = try common.expectStringField(allocator, errors, threat, id, "residual_risk_owner");
        _ = try common.expectStringField(allocator, errors, threat, id, "residual_risk_decision");
        const tests = try common.collectStringArray(
            allocator,
            errors,
            common.field(threat, "negative_tests"),
            try std.fmt.allocPrint(allocator, "threat {s} negative_tests", .{id}),
            true,
        );
        for (tests) |test_path| {
            if (!common.pathExists(io, test_path)) {
                try common.addError(errors, allocator, "threat {s} references missing negative test artifact: {s}", .{ id, test_path });
            }
        }
    }
    for (REQUIRED_THREAT_DOMAINS) |domain| {
        if (!covered_domains.contains(domain)) {
            try common.addError(errors, allocator, "threat model has no threat covering required domain: {s}", .{domain});
        }
    }
}

fn validateMemorySafetyInventory(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    summary: *GateSummary,
) !void {
    const root = try parseJsonFile(allocator, io, errors, MEMORY_SAFETY_INVENTORY_PATH) orelse return;
    const scan_patterns = try common.collectStringArray(
        allocator,
        errors,
        common.field(root, "scan_patterns"),
        "memory safety inventory scan_patterns",
        true,
    );
    var scan_pattern_set = try common.collectUniqueStrings(allocator, errors, scan_patterns, "memory safety scan pattern");
    for (UNSAFE_SCAN_PATTERNS) |pattern| {
        if (!scan_pattern_set.contains(pattern)) {
            try common.addError(errors, allocator, "memory safety inventory missing scan pattern: {s}", .{pattern});
        }
    }

    const required_review_state = try common.expectStringField(allocator, errors, root, "memory safety inventory", "required_review_state") orelse "";
    const entries_value = common.field(root, "unsafe_surface_inventory") orelse {
        try common.addError(errors, allocator, "memory safety inventory must include unsafe_surface_inventory", .{});
        return;
    };
    const entries = switch (entries_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "memory safety inventory unsafe_surface_inventory must be an array", .{});
            return;
        },
    };

    var covered_paths = std.StringHashMap(void).init(allocator);
    for (entries, 0..) |entry, index| {
        if (entry != .object) {
            try common.addError(errors, allocator, "memory safety inventory entry at index {d} must be an object", .{index});
            continue;
        }
        const path = try common.expectStringField(allocator, errors, entry, "memory safety inventory entry", "path") orelse continue;
        if (!common.pathExists(io, path)) {
            try common.addError(errors, allocator, "memory safety inventory references missing path: {s}", .{path});
        }
        const gop = try covered_paths.getOrPut(path);
        if (gop.found_existing) {
            try common.addError(errors, allocator, "duplicate memory safety inventory path: {s}", .{path});
        }
        const review_state = try common.expectStringField(allocator, errors, entry, path, "review_state") orelse "";
        if (required_review_state.len > 0 and !std.mem.eql(u8, review_state, required_review_state)) {
            try common.addError(errors, allocator, "memory safety inventory path {s} review_state must be {s}", .{ path, required_review_state });
        }
        _ = try common.expectStringField(allocator, errors, entry, path, "owner");
        _ = try common.collectStringArray(allocator, errors, common.field(entry, "categories"), path, true);
        _ = try common.collectStringArray(allocator, errors, common.field(entry, "mitigations"), path, true);
        _ = try common.collectStringArray(allocator, errors, common.field(entry, "tests"), path, true);
    }

    const unsafe_paths = try collectUnsafeSourcePaths(allocator, gpa, io);
    var it = unsafe_paths.iterator();
    while (it.next()) |entry| {
        summary.unsafe_paths += 1;
        const path = entry.key_ptr.*;
        if (!covered_paths.contains(path)) {
            try common.addError(errors, allocator, "unsafe source path lacks memory safety inventory coverage: {s}", .{path});
        }
    }
}

fn collectUnsafeSourcePaths(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
) !std.StringHashMap(void) {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "jj", "file", "list", "-T", "path ++ \"\\0\"", "src", "tools", "build_support" },
        .stdout_limit = .limited(common.child_stdout_max_bytes),
        .stderr_limit = .limited(common.child_stderr_max_bytes),
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("{s}", .{result.stderr});
            return error.JjFileListFailed;
        },
        else => return error.JjFileListFailed,
    }

    var unsafe_paths = std.StringHashMap(void).init(allocator);
    var parts = std.mem.splitScalar(u8, result.stdout, 0);
    while (parts.next()) |path| {
        if (path.len == 0 or !std.mem.endsWith(u8, path, ".zig")) continue;
        if (!common.pathExists(io, path)) continue;
        const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
        for (UNSAFE_SCAN_PATTERNS) |pattern| {
            if (std.mem.indexOf(u8, source, pattern) != null) {
                try unsafe_paths.put(try allocator.dupe(u8, path), {});
                break;
            }
        }
    }
    return unsafe_paths;
}

fn validateCrashDumpRedaction(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const root = try parseJsonFile(allocator, io, errors, CRASH_DUMP_REDACTION_PATH) orelse return;
    const default_policy = try common.expectObjectField(allocator, errors, root, "crash dump redaction", "default_policy") orelse return;
    try expectStringValue(allocator, errors, default_policy, "default_policy", "raw_memory_capture", "deny");
    try expectStringValue(allocator, errors, default_policy, "default_policy", "capability_token_export", "deny");
    try expectStringValue(allocator, errors, default_policy, "default_policy", "private_object_name_export", "deny");
    try expectStringValue(allocator, errors, default_policy, "default_policy", "personal_content_export", "deny");
    try expectStringValue(allocator, errors, default_policy, "default_policy", "support_bundle_review", "required");
    try expectStringValue(allocator, errors, default_policy, "default_policy", "scoped_diagnostics_opt_in", "required");

    const markers = try common.collectStringArray(
        allocator,
        errors,
        common.field(root, "redaction_markers"),
        "crash dump redaction markers",
        true,
    );
    var marker_set = try common.collectUniqueStrings(allocator, errors, markers, "crash dump redaction marker");
    for (REDACTION_MARKERS) |marker| {
        if (!marker_set.contains(marker)) {
            try common.addError(errors, allocator, "crash dump redaction policy missing marker: {s}", .{marker});
        }
    }

    const fixtures_value = common.field(root, "fixtures") orelse {
        try common.addError(errors, allocator, "crash dump redaction policy must include fixtures", .{});
        return;
    };
    const fixtures = switch (fixtures_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "crash dump redaction fixtures must be an array", .{});
            return;
        },
    };
    for (fixtures, 0..) |fixture, index| {
        if (fixture != .object) {
            try common.addError(errors, allocator, "crash dump redaction fixture at index {d} must be an object", .{index});
            continue;
        }
        const input_reason = try common.expectStringField(allocator, errors, fixture, "crash dump redaction fixture", "input_reason") orelse continue;
        const record = crash_record.init(.panic, 7, 11, 0x1234, 0x5678, input_reason) catch {
            try common.addError(errors, allocator, "crash dump redaction fixture reason is too long: {s}", .{input_reason});
            continue;
        };
        var buffer: [256]u8 = undefined;
        const summary = crash_record.redactedSummary(record, buffer[0..]);
        const must_contain = try common.collectStringArray(
            allocator,
            errors,
            common.field(fixture, "must_contain"),
            "crash dump redaction fixture must_contain",
            true,
        );
        for (must_contain) |needle| {
            if (std.mem.indexOf(u8, summary, needle) == null) {
                try common.addError(errors, allocator, "crash redaction summary for '{s}' must contain '{s}'", .{ input_reason, needle });
            }
        }
        const must_not_contain = try common.collectStringArray(
            allocator,
            errors,
            common.field(fixture, "must_not_contain"),
            "crash dump redaction fixture must_not_contain",
            false,
        );
        for (must_not_contain) |needle| {
            if (std.mem.indexOf(u8, summary, needle) != null) {
                try common.addError(errors, allocator, "crash redaction summary for '{s}' must not contain '{s}'", .{ input_reason, needle });
            }
        }
    }
}

fn validateVulnerabilityDisclosure(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    const root = try parseJsonFile(allocator, io, errors, VULNERABILITY_DISCLOSURE_PATH) orelse return;
    const policy_artifact = try common.expectStringField(allocator, errors, root, "vulnerability disclosure", "policy_artifact") orelse "";
    if (!std.mem.eql(u8, policy_artifact, SECURITY_POLICY_PATH)) {
        try common.addError(errors, allocator, "vulnerability disclosure policy_artifact must be SECURITY.md", .{});
    }
    if (!common.pathExists(io, SECURITY_POLICY_PATH)) {
        try common.addError(errors, allocator, "SECURITY.md is missing", .{});
        return;
    }
    const security_policy = try common.readFileAlloc(allocator, io, SECURITY_POLICY_PATH, common.source_file_max_bytes);

    const primary = try common.expectObjectField(allocator, errors, root, "vulnerability disclosure", "primary_private_intake") orelse return;
    const primary_url = try common.expectStringField(allocator, errors, primary, "primary private intake", "url") orelse "";
    if (primary_url.len > 0 and std.mem.indexOf(u8, security_policy, primary_url) == null) {
        try common.addError(errors, allocator, "SECURITY.md must publish primary private intake URL: {s}", .{primary_url});
    }
    _ = try common.collectStringArray(allocator, errors, common.field(primary, "monitored_by"), "primary private intake monitored_by", true);
    const ack_sla = try expectPositiveIntegerField(allocator, errors, primary, "primary private intake", "acknowledgement_sla_business_days") orelse 0;
    const triage_sla = try expectPositiveIntegerField(allocator, errors, primary, "primary private intake", "triage_sla_business_days") orelse 0;
    if (ack_sla > 3 or triage_sla > 10) {
        try common.addError(errors, allocator, "vulnerability disclosure SLA must acknowledge within 3 business days and triage within 10", .{});
    }

    const backup = try common.expectObjectField(allocator, errors, root, "vulnerability disclosure", "backup_private_intake") orelse return;
    const backup_address = try common.expectStringField(allocator, errors, backup, "backup private intake", "address") orelse "";
    if (backup_address.len > 0 and std.mem.indexOf(u8, security_policy, backup_address) == null) {
        try common.addError(errors, allocator, "SECURITY.md must publish backup private intake address: {s}", .{backup_address});
    }

    const cve = try common.expectObjectField(allocator, errors, root, "vulnerability disclosure", "cve_cwe_handling") orelse return;
    _ = try common.expectStringField(allocator, errors, cve, "cve_cwe_handling", "owner");
    _ = try common.expectStringField(allocator, errors, cve, "cve_cwe_handling", "cve_issuance_path");
    try expectTrueBoolField(allocator, errors, cve, "cve_cwe_handling", "cwe_required");
    try expectTrueBoolField(allocator, errors, cve, "cve_cwe_handling", "coordinated_disclosure_required");
    _ = try common.expectStringField(allocator, errors, cve, "cve_cwe_handling", "security_update_commitment");

    const workflow_test = try common.expectObjectField(allocator, errors, root, "vulnerability disclosure", "workflow_test") orelse return;
    try expectTrueBoolField(allocator, errors, workflow_test, "workflow_test", "dry_run_required");
    _ = try common.expectStringField(allocator, errors, workflow_test, "workflow_test", "dry_run_artifact");
    const required_steps = try common.collectStringArray(allocator, errors, common.field(workflow_test, "required_steps"), "workflow_test required_steps", true);
    if (required_steps.len < 6) {
        try common.addError(errors, allocator, "vulnerability disclosure workflow_test must cover report, ack, triage, CWE, advisory, and fix decision", .{});
    }

    const required_policy_text = [_][]const u8{
        "3 business days",
        "10 business days",
        "CVE",
        "CWE",
        "coordinated disclosure",
    };
    for (required_policy_text) |needle| {
        if (std.mem.indexOf(u8, security_policy, needle) == null) {
            try common.addError(errors, allocator, "SECURITY.md must include vulnerability disclosure text: {s}", .{needle});
        }
    }
}

fn validatePostQuantumReleasePolicy(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    policy: std.json.Value,
) !void {
    const mode = try common.expectStringField(allocator, errors, policy, "release signing post_quantum_policy", "mode") orelse "";
    const allowed_modes = [_][]const u8{ "shadow", "canary", "required" };
    if (mode.len > 0 and !isOneOf(mode, &allowed_modes)) {
        try common.addError(errors, allocator, "release signing post_quantum_policy mode must be shadow, canary, or required", .{});
    }
    try expectTrueBoolField(allocator, errors, policy, "release signing post_quantum_policy", "fips_validated_required");
    try expectTrueBoolField(allocator, errors, policy, "release signing post_quantum_policy", "fips_140_validation_required");

    const production_signature = try common.expectStringField(allocator, errors, policy, "release signing post_quantum_policy", "production_signature_algorithm") orelse "";
    if (!common.containsAsciiIgnoreCase(production_signature, "ml-dsa")) {
        try common.addError(errors, allocator, "release signing post_quantum_policy production_signature_algorithm must name ML-DSA", .{});
    }
    const key_establishment = try common.expectStringField(allocator, errors, policy, "release signing post_quantum_policy", "key_establishment_algorithm") orelse "";
    if (!common.containsAsciiIgnoreCase(key_establishment, "ml-kem")) {
        try common.addError(errors, allocator, "release signing post_quantum_policy key_establishment_algorithm must name ML-KEM", .{});
    }
    const backup_signature = try common.expectStringField(allocator, errors, policy, "release signing post_quantum_policy", "backup_signature_algorithm") orelse "";
    if (!common.containsAsciiIgnoreCase(backup_signature, "slh-dsa")) {
        try common.addError(errors, allocator, "release signing post_quantum_policy backup_signature_algorithm must name SLH-DSA", .{});
    }
    const classical_baseline = try common.expectStringField(allocator, errors, policy, "release signing post_quantum_policy", "classical_baseline") orelse "";
    if (!common.containsAsciiIgnoreCase(classical_baseline, "ed25519") or
        !common.containsAsciiIgnoreCase(classical_baseline, "validated") or
        !common.containsAsciiIgnoreCase(classical_baseline, "FIPS 204"))
    {
        try common.addError(errors, allocator, "release signing post_quantum_policy classical_baseline must keep ed25519 as the classical baseline and require a validated FIPS 204 ML-DSA provider for production", .{});
    }

    const standards_value = common.field(policy, "standards") orelse {
        try common.addError(errors, allocator, "release signing post_quantum_policy must include standards", .{});
        return;
    };
    const standards = switch (standards_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "release signing post_quantum_policy standards must be an array", .{});
            return;
        },
    };
    var has_fips_203 = false;
    var has_fips_204 = false;
    var has_fips_205 = false;
    for (standards, 0..) |standard, index| {
        if (standard != .object) {
            try common.addError(errors, allocator, "release signing post_quantum_policy standard at index {d} must be an object", .{index});
            continue;
        }
        const fips = try common.expectStringField(allocator, errors, standard, "release signing post_quantum_policy standard", "fips") orelse "";
        const algorithm = try common.expectStringField(allocator, errors, standard, "release signing post_quantum_policy standard", "algorithm") orelse "";
        if (std.mem.eql(u8, fips, "FIPS 203") and common.containsAsciiIgnoreCase(algorithm, "ML-KEM")) has_fips_203 = true;
        if (std.mem.eql(u8, fips, "FIPS 204") and common.containsAsciiIgnoreCase(algorithm, "ML-DSA")) has_fips_204 = true;
        if (std.mem.eql(u8, fips, "FIPS 205") and common.containsAsciiIgnoreCase(algorithm, "SLH-DSA")) has_fips_205 = true;
    }
    if (!has_fips_203 or !has_fips_204 or !has_fips_205) {
        try common.addError(errors, allocator, "release signing post_quantum_policy standards must cover FIPS 203 ML-KEM, FIPS 204 ML-DSA, and FIPS 205 SLH-DSA", .{});
    }

    const rollout = try common.collectStringArray(
        allocator,
        errors,
        common.field(policy, "rollout"),
        "release signing post_quantum_policy rollout",
        true,
    );
    if (rollout.len < 3 or
        !stringArrayContainsSubstring(rollout, "shadow") or
        !stringArrayContainsSubstring(rollout, "canary") or
        !stringArrayContainsSubstring(rollout, "required"))
    {
        try common.addError(errors, allocator, "release signing post_quantum_policy rollout must include shadow, canary, and required phases", .{});
    }
}

fn parseJsonFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    path: []const u8,
) !?std.json.Value {
    if (!common.pathExists(io, path)) {
        try common.addError(errors, allocator, "release security artifact is missing: {s}", .{path});
        return null;
    }
    const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, source, .{}) catch |err| {
        try common.addError(errors, allocator, "release security artifact is not valid JSON: {s}: {s}", .{ path, @errorName(err) });
        return null;
    };
    return parsed.value;
}

fn decodeHex(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    context: []const u8,
    hex: []const u8,
) ![]const u8 {
    if (hex.len % 2 != 0) {
        try common.addError(errors, allocator, "hex seed for {s} must have even length: {s}", .{ context, hex });
        return &.{};
    }
    var bytes = try allocator.alloc(u8, hex.len / 2);
    var index: usize = 0;
    while (index < bytes.len) : (index += 1) {
        const high = hexValue(hex[index * 2]) orelse {
            try common.addError(errors, allocator, "hex seed for {s} has invalid digit: {s}", .{ context, hex });
            return &.{};
        };
        const low = hexValue(hex[index * 2 + 1]) orelse {
            try common.addError(errors, allocator, "hex seed for {s} has invalid digit: {s}", .{ context, hex });
            return &.{};
        };
        bytes[index] = (high << 4) | low;
    }
    return bytes;
}

fn hexValue(byte: u8) ?u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'a' and byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' and byte <= 'F') return byte - 'A' + 10;
    return null;
}

fn expectPositiveIntegerField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !?u64 {
    const value = common.field(object, name) orelse {
        try common.addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return null;
    };
    return switch (value) {
        .integer => |number| if (number > 0) @intCast(number) else blk: {
            try common.addError(errors, allocator, "{s} {s} must be positive", .{ context, name });
            break :blk null;
        },
        else => {
            try common.addError(errors, allocator, "{s} {s} must be an integer", .{ context, name });
            return null;
        },
    };
}

fn expectBoolField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !?bool {
    const value = common.field(object, name) orelse {
        try common.addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return null;
    };
    return switch (value) {
        .bool => |flag| flag,
        else => {
            try common.addError(errors, allocator, "{s} {s} must be a bool", .{ context, name });
            return null;
        },
    };
}

fn expectTrueBoolField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !void {
    const value = common.field(object, name) orelse {
        try common.addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return;
    };
    switch (value) {
        .bool => |flag| if (!flag) {
            try common.addError(errors, allocator, "{s} {s} must be true", .{ context, name });
        },
        else => try common.addError(errors, allocator, "{s} {s} must be a bool", .{ context, name }),
    }
}

fn expectFalseBoolField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !void {
    const value = common.field(object, name) orelse {
        try common.addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return;
    };
    switch (value) {
        .bool => |flag| if (flag) {
            try common.addError(errors, allocator, "{s} {s} must be false", .{ context, name });
        },
        else => try common.addError(errors, allocator, "{s} {s} must be a bool", .{ context, name }),
    }
}

fn expectStringValue(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
    expected: []const u8,
) !void {
    const actual = try common.expectStringField(allocator, errors, object, context, name) orelse return;
    if (!std.mem.eql(u8, actual, expected)) {
        try common.addError(errors, allocator, "{s} {s} must be {s}", .{ context, name, expected });
    }
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

fn stringArrayContains(values: []const []const u8, expected: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, expected)) return true;
    }
    return false;
}

fn stringArrayContainsSubstring(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| {
        if (std.mem.indexOf(u8, value, needle) != null) return true;
    }
    return false;
}

fn containsHardwareReleaseBoundary(value: []const u8) bool {
    return common.containsAsciiIgnoreCase(value, "tpm") or
        common.containsAsciiIgnoreCase(value, "secure enclave") or
        common.containsAsciiIgnoreCase(value, "hardware_security_module") or
        common.containsAsciiIgnoreCase(value, "hardware security module") or
        common.containsAsciiIgnoreCase(value, "hsm") or
        common.containsAsciiIgnoreCase(value, "kms");
}
