const std = @import("std");
const common = @import("check_common.zig");

const MANIFEST_PATH = "spec/coverage.json";
const SUMMARY_REQUIREMENT_ID = "REQ-ONE-SENTENCE-SUMMARY";

const EVIDENCE_STATUSES = [_][]const u8{ "enforced", "modeled", "scenario", "deferred" };
const ROADMAP_PRIORITIES = [_][]const u8{ "P0", "P1", "P2" };
const ROADMAP_TEXT_FIELDS = [_][]const u8{ "focus", "graduation_proof" };

const SummaryClauseDependency = struct {
    clause: []const u8,
    dependencies: []const []const u8,
};

const SUMMARY_CLAUSE_DEPENDENCIES = [_]SummaryClauseDependency{
    .{
        .clause = "capability-based",
        .dependencies = &.{ "REQ-ZERO-AMBIENT-AUTHORITY", "REQ-CAPABILITY-MODEL", "REQ-CAPABILITY-BASED-ACCESS-CONTROL" },
    },
    .{
        .clause = "local-first",
        .dependencies = &.{ "REQ-LOCAL-FIRST-REPLICATION", "REQ-SYNC-SEMANTICS" },
    },
    .{
        .clause = "multi-device",
        .dependencies = &.{ "REQ-DEVICE-GRAPH", "REQ-SHARING" },
    },
    .{
        .clause = "immutable core",
        .dependencies = &.{ "REQ-IMMUTABLE-BASE-SYSTEM", "REQ-BASE-OS-UPDATES" },
    },
    .{
        .clause = "versioned object storage",
        .dependencies = &.{ "REQ-DATA-IS-VERSIONED", "REQ-OBJECT-STORE", "REQ-MUTABLE-STATE" },
    },
    .{
        .clause = "strong sandboxing",
        .dependencies = &.{ "REQ-PROCESS-ISOLATION", "REQ-SECRETS" },
    },
    .{
        .clause = "explicit identity",
        .dependencies = &.{ "REQ-PRINCIPAL-MODEL", "REQ-IDENTITY-FIRST-NETWORKING" },
    },
    .{
        .clause = "first-class support for modern accelerators",
        .dependencies = &.{ "REQ-UNIFIED-RESOURCE-SCHEDULER", "REQ-SHARED-MEMORY-OBJECTS", "REQ-THERMAL-AND-POWER-POLICY" },
    },
};

const TestRef = struct {
    file: []const u8,
    name: []const u8,
};

const TestCounters = struct {
    referenced_test_count: usize = 0,
    enforced_count: usize = 0,
    scenario_count: usize = 0,
    negative_test_count: usize = 0,
    roadmap_count: usize = 0,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try runSelfTests(allocator, &errors);

    const manifest_source = try common.readFileAlloc(allocator, io, MANIFEST_PATH, common.coverage_manifest_max_bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, manifest_source, .{});
    defer parsed.deinit();

    const manifest = parsed.value;
    if (manifest != .object) {
        try common.addError(&errors, allocator, "{s} must contain a JSON object", .{MANIFEST_PATH});
    }

    const required_headings = try common.collectStringArray(
        allocator,
        &errors,
        common.field(manifest, "required_headings"),
        "coverage manifest required_headings",
        true,
    );
    var required_heading_set = try common.collectUniqueStrings(allocator, &errors, required_headings, "required heading");

    const required_requirements = try common.collectStringArray(
        allocator,
        &errors,
        common.field(manifest, "required_requirements"),
        "coverage manifest required_requirements",
        true,
    );
    var required_requirement_set = try common.collectUniqueStrings(allocator, &errors, required_requirements, "required requirement");

    const summary_text = try common.expectStringField(
        allocator,
        &errors,
        manifest,
        "coverage manifest",
        "one_sentence_summary",
    ) orelse "";

    var seen_sections = std.StringHashMap(void).init(allocator);
    var seen_requirements = std.StringHashMap([]const u8).init(allocator);
    var test_cache = std.StringHashMap(std.StringHashMap(void)).init(allocator);
    var counters: TestCounters = .{};

    try validateSections(
        allocator,
        io,
        &errors,
        manifest,
        &required_heading_set,
        &seen_sections,
        &seen_requirements,
        &test_cache,
        &counters,
    );

    for (required_requirements) |requirement_id| {
        if (!seen_requirements.contains(requirement_id)) {
            try common.addError(&errors, allocator, "Required spec requirement is not covered: {s}", .{requirement_id});
        }
    }
    var covered_it = seen_requirements.iterator();
    while (covered_it.next()) |entry| {
        if (!required_requirement_set.contains(entry.key_ptr.*)) {
            try common.addError(&errors, allocator, "Unexpected spec requirement in coverage manifest: {s}", .{entry.key_ptr.*});
        }
    }

    var status_by_requirement = std.StringHashMap([]const u8).init(allocator);
    try validateRequirementEvidence(
        allocator,
        io,
        &errors,
        manifest,
        required_requirements,
        &required_requirement_set,
        &test_cache,
        &status_by_requirement,
        &counters,
    );

    try validateSummaryClauseDependencies(
        allocator,
        &errors,
        &status_by_requirement,
        summary_text,
    );

    if (errors.items.len > 0) {
        common.printErrors(errors.items);
        std.process.exit(1);
    }

    try common.printStdout(
        io,
        "Spec coverage OK: {d} headings, {d} requirements, {d} section groups, {d} test references, {d} enforced requirements, {d} scenario-only requirements, {d} negative test references, {d} roadmap requirements\n",
        .{
            required_headings.len,
            required_requirements.len,
            seen_sections.count(),
            counters.referenced_test_count,
            counters.enforced_count,
            counters.scenario_count,
            counters.negative_test_count,
            counters.roadmap_count,
        },
    );
}

fn validateSections(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    manifest: std.json.Value,
    required_heading_set: *const std.StringHashMap(void),
    seen_sections: *std.StringHashMap(void),
    seen_requirements: *std.StringHashMap([]const u8),
    test_cache: *std.StringHashMap(std.StringHashMap(void)),
    counters: *TestCounters,
) !void {
    const sections_value = common.field(manifest, "sections") orelse {
        try common.addError(errors, allocator, "coverage manifest must include sections", .{});
        return;
    };
    const sections = switch (sections_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "coverage manifest sections must be an array", .{});
            return;
        },
    };

    for (sections, 0..) |section, index| {
        if (section != .object) {
            try common.addError(errors, allocator, "Coverage section at index {d} must be an object", .{index});
            continue;
        }

        const section_id = try common.expectStringField(allocator, errors, section, "coverage section", "id") orelse continue;
        const section_gop = try seen_sections.getOrPut(section_id);
        if (section_gop.found_existing) {
            try common.addError(errors, allocator, "Duplicate section entry in coverage manifest: {s}", .{section_id});
        }

        const heading = try common.expectStringField(allocator, errors, section, "coverage section", "heading") orelse "";
        if (heading.len > 0 and !required_heading_set.contains(heading)) {
            try common.addError(
                errors,
                allocator,
                "Coverage section {s} uses heading not listed in required_headings: {s}",
                .{ section_id, heading },
            );
        }

        const tests = try collectTestRefs(
            allocator,
            errors,
            common.field(section, "tests"),
            try std.fmt.allocPrint(allocator, "Coverage section {s} tests", .{section_id}),
            true,
        );
        for (tests) |test_ref| {
            try validateTestRef(allocator, io, errors, test_cache, "Coverage section", section_id, test_ref);
            counters.referenced_test_count += 1;
        }

        const requirements = try common.collectStringArray(
            allocator,
            errors,
            common.field(section, "requirements"),
            try std.fmt.allocPrint(allocator, "Coverage section {s} requirements", .{section_id}),
            false,
        );
        for (requirements) |requirement_id| {
            const requirement_gop = try seen_requirements.getOrPut(requirement_id);
            if (requirement_gop.found_existing) {
                try common.addError(
                    errors,
                    allocator,
                    "Requirement {s} is mapped more than once in coverage manifest: {s} and {s}",
                    .{ requirement_id, requirement_gop.value_ptr.*, section_id },
                );
            } else {
                requirement_gop.value_ptr.* = section_id;
            }
        }
    }
}

fn validateRequirementEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    manifest: std.json.Value,
    required_requirements: []const []const u8,
    required_requirement_set: *const std.StringHashMap(void),
    test_cache: *std.StringHashMap(std.StringHashMap(void)),
    status_by_requirement: *std.StringHashMap([]const u8),
    counters: *TestCounters,
) !void {
    const evidence_value = common.field(manifest, "requirement_evidence") orelse {
        try common.addError(errors, allocator, "coverage manifest requirement_evidence must be an object", .{});
        return;
    };
    const evidence = switch (evidence_value) {
        .object => |object| object,
        else => {
            try common.addError(errors, allocator, "coverage manifest requirement_evidence must be an object", .{});
            return;
        },
    };

    for (required_requirements) |requirement_id| {
        if (evidence.get(requirement_id) == null) {
            try common.addError(errors, allocator, "Required spec requirement is missing requirement_evidence: {s}", .{requirement_id});
        }
    }
    var evidence_it = evidence.iterator();
    while (evidence_it.next()) |entry| {
        if (!required_requirement_set.contains(entry.key_ptr.*)) {
            try common.addError(errors, allocator, "Unexpected requirement_evidence entry: {s}", .{entry.key_ptr.*});
        }
    }

    for (required_requirements) |requirement_id| {
        const requirement_evidence = evidence.get(requirement_id) orelse continue;
        if (requirement_evidence != .object) {
            try common.addError(errors, allocator, "Requirement evidence for {s} must be an object", .{requirement_id});
            continue;
        }

        const status = try common.expectStringField(
            allocator,
            errors,
            requirement_evidence,
            try std.fmt.allocPrint(allocator, "Requirement evidence for {s}", .{requirement_id}),
            "status",
        ) orelse continue;
        try status_by_requirement.put(requirement_id, status);

        if (!isOneOf(status, &EVIDENCE_STATUSES)) {
            try common.addError(
                errors,
                allocator,
                "Requirement evidence for {s} has invalid status: {s}",
                .{ requirement_id, status },
            );
            continue;
        }

        if (std.mem.eql(u8, status, "scenario")) counters.scenario_count += 1;
        if (std.mem.eql(u8, status, "enforced")) {
            counters.enforced_count += 1;
            try validateEnforcedEvidence(
                allocator,
                io,
                errors,
                requirement_id,
                requirement_evidence,
                test_cache,
                counters,
            );
        } else {
            try validateRoadmapEvidence(allocator, errors, requirement_id, requirement_evidence, status, counters);
        }
    }
}

fn validateEnforcedEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    requirement_id: []const u8,
    requirement_evidence: std.json.Value,
    test_cache: *std.StringHashMap(std.StringHashMap(void)),
    counters: *TestCounters,
) !void {
    if (common.field(requirement_evidence, "roadmap") != null) {
        try common.addError(errors, allocator, "Enforced requirement {s} should not keep roadmap metadata", .{requirement_id});
    }

    const enforcement_modules = try common.collectStringArray(
        allocator,
        errors,
        common.field(requirement_evidence, "enforcement_modules"),
        try std.fmt.allocPrint(allocator, "Enforced requirement {s} enforcement_modules", .{requirement_id}),
        true,
    );
    for (enforcement_modules) |module| {
        if (!common.pathExists(io, module)) {
            try common.addError(
                errors,
                allocator,
                "Enforced requirement {s} references missing enforcement module: {s}",
                .{ requirement_id, module },
            );
        } else if (std.mem.startsWith(u8, module, "src/tests/spec/")) {
            try common.addError(
                errors,
                allocator,
                "Enforced requirement {s} uses a spec test as an enforcement module: {s}",
                .{ requirement_id, module },
            );
        }
    }

    const negative_tests = try collectTestRefs(
        allocator,
        errors,
        common.field(requirement_evidence, "negative_tests"),
        try std.fmt.allocPrint(allocator, "Enforced requirement {s} negative_tests", .{requirement_id}),
        true,
    );
    for (negative_tests) |test_ref| {
        try validateTestRef(allocator, io, errors, test_cache, "Enforced requirement", requirement_id, test_ref);
        counters.negative_test_count += 1;
    }
}

fn validateRoadmapEvidence(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    requirement_id: []const u8,
    requirement_evidence: std.json.Value,
    status: []const u8,
    counters: *TestCounters,
) !void {
    if (common.field(requirement_evidence, "negative_tests") != null) {
        try common.addError(
            errors,
            allocator,
            "Requirement {s} is {s} but lists negative_tests; mark it enforced or remove the enforced evidence",
            .{ requirement_id, status },
        );
    }
    const coverage_note = common.field(requirement_evidence, "coverage_note");
    if (coverage_note == null or coverage_note.? != .string or coverage_note.?.string.len == 0) {
        try common.addError(
            errors,
            allocator,
            "Requirement {s} is {s} and must include coverage_note explaining why it is not enforced",
            .{ requirement_id, status },
        );
    }

    const roadmap = common.field(requirement_evidence, "roadmap") orelse {
        try common.addError(errors, allocator, "Requirement {s} is {s} and must include roadmap metadata", .{ requirement_id, status });
        return;
    };
    if (roadmap != .object) {
        try common.addError(errors, allocator, "Requirement {s} roadmap must be an object", .{requirement_id});
        return;
    }

    const priority = try common.expectStringField(
        allocator,
        errors,
        roadmap,
        try std.fmt.allocPrint(allocator, "Requirement {s} roadmap", .{requirement_id}),
        "priority",
    ) orelse "";
    var valid = priority.len > 0 and isOneOf(priority, &ROADMAP_PRIORITIES);
    if (priority.len > 0 and !valid) {
        try common.addError(
            errors,
            allocator,
            "Requirement {s} roadmap priority must be one of [P0, P1, P2]",
            .{requirement_id},
        );
    }
    for (ROADMAP_TEXT_FIELDS) |field_name| {
        const value = try common.expectStringField(
            allocator,
            errors,
            roadmap,
            try std.fmt.allocPrint(allocator, "Requirement {s} roadmap", .{requirement_id}),
            field_name,
        );
        if (value == null or value.?.len == 0) {
            valid = false;
            try common.addError(errors, allocator, "Requirement {s} roadmap must include non-empty {s}", .{ requirement_id, field_name });
        }
    }
    if (valid) counters.roadmap_count += 1;
}

fn validateSummaryClauseDependencies(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    status_by_requirement: *const std.StringHashMap([]const u8),
    summary_text: []const u8,
) !void {
    const summary_status = status_by_requirement.get(SUMMARY_REQUIREMENT_ID) orelse return;
    if (!std.mem.eql(u8, summary_status, "enforced") and !std.mem.eql(u8, summary_status, "modeled")) return;

    for (SUMMARY_CLAUSE_DEPENDENCIES) |dependency_group| {
        if (!common.containsAsciiIgnoreCase(summary_text, dependency_group.clause)) {
            try common.addError(
                errors,
                allocator,
                "One-sentence summary clause '{s}' is not present in coverage manifest one_sentence_summary",
                .{dependency_group.clause},
            );
        }
        if (dependency_group.dependencies.len == 0) {
            try common.addError(errors, allocator, "One-sentence summary clause '{s}' has no dependency mapping", .{dependency_group.clause});
            continue;
        }
        for (dependency_group.dependencies) |dependency_id| {
            const dependency_status = status_by_requirement.get(dependency_id) orelse {
                try common.addError(
                    errors,
                    allocator,
                    "One-sentence summary clause '{s}' depends on missing requirement evidence: {s}",
                    .{ dependency_group.clause, dependency_id },
                );
                continue;
            };
            if (!std.mem.eql(u8, dependency_status, "enforced")) {
                try common.addError(
                    errors,
                    allocator,
                    "One-sentence summary clause '{s}' depends on {s}, which is '{s}'; expected enforced",
                    .{ dependency_group.clause, dependency_id, dependency_status },
                );
            }
        }
    }
}

fn collectTestRefs(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    maybe_value: ?std.json.Value,
    context: []const u8,
    required_non_empty: bool,
) ![]const TestRef {
    var refs = std.ArrayList(TestRef).empty;
    const value = maybe_value orelse {
        try common.addError(errors, allocator, "{s} must be an array", .{context});
        return refs.toOwnedSlice(allocator);
    };

    switch (value) {
        .array => |array| {
            for (array.items, 0..) |item, index| {
                if (item != .object) {
                    try common.addError(errors, allocator, "{s} entry at index {d} must be an object", .{ context, index });
                    continue;
                }
                const file = try common.expectStringField(allocator, errors, item, context, "file") orelse continue;
                const name = try common.expectStringField(allocator, errors, item, context, "name") orelse continue;
                try refs.append(allocator, .{ .file = file, .name = name });
            }
        },
        else => try common.addError(errors, allocator, "{s} must be an array", .{context}),
    }

    if (required_non_empty and refs.items.len == 0) {
        try common.addError(errors, allocator, "{s} must be non-empty", .{context});
    }

    return refs.toOwnedSlice(allocator);
}

fn validateTestRef(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    test_cache: *std.StringHashMap(std.StringHashMap(void)),
    owner_kind: []const u8,
    owner_id: []const u8,
    test_ref: TestRef,
) !void {
    if (!common.pathExists(io, test_ref.file)) {
        try common.addError(errors, allocator, "{s} {s} references missing file: {s}", .{ owner_kind, owner_id, test_ref.file });
        return;
    }

    const test_names = try loadTestNames(allocator, io, test_cache, test_ref.file);
    if (!test_names.contains(test_ref.name)) {
        try common.addError(
            errors,
            allocator,
            "{s} {s} references missing test in {s}: {s}",
            .{ owner_kind, owner_id, test_ref.file, test_ref.name },
        );
    }
}

fn loadTestNames(
    allocator: std.mem.Allocator,
    io: std.Io,
    test_cache: *std.StringHashMap(std.StringHashMap(void)),
    path: []const u8,
) !*std.StringHashMap(void) {
    if (test_cache.getPtr(path)) |cached| return cached;

    var names = std.StringHashMap(void).init(allocator);
    const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "test \"")) continue;
        const name_start = "test \"".len;
        const name_end = std.mem.indexOfScalarPos(u8, trimmed, name_start, '"') orelse continue;
        try names.put(trimmed[name_start..name_end], {});
    }

    try test_cache.put(try allocator.dupe(u8, path), names);
    return test_cache.getPtr(path).?;
}

fn runSelfTests(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8)) !void {
    try selfTestSummaryClauseGateRejectsMissingOrModeledDependencies(allocator, errors);
    try selfTestSummaryClauseGateRequiresCurrentSummaryPhrases(allocator, errors);
}

fn selfTestSummaryClauseGateRejectsMissingOrModeledDependencies(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
) !void {
    var evidence = try summaryEvidenceFixture(allocator);
    try evidence.put("REQ-LOCAL-FIRST-REPLICATION", "modeled");
    _ = evidence.remove("REQ-SHARED-MEMORY-OBJECTS");

    var self_errors = std.ArrayList([]const u8).empty;
    try validateSummaryClauseDependencies(allocator, &self_errors, &evidence, completeSummaryText());

    if (!common.errorContains(self_errors.items, "REQ-LOCAL-FIRST-REPLICATION") or
        !common.errorContains(self_errors.items, "expected enforced"))
    {
        try common.addError(errors, allocator, "Spec coverage checker self-test failed: test_summary_clause_gate_rejects_missing_or_modeled_dependencies: modeled dependency was accepted", .{});
    }
    if (!common.errorContains(self_errors.items, "REQ-SHARED-MEMORY-OBJECTS") or
        !common.errorContains(self_errors.items, "missing requirement evidence"))
    {
        try common.addError(errors, allocator, "Spec coverage checker self-test failed: test_summary_clause_gate_rejects_missing_or_modeled_dependencies: missing dependency was accepted", .{});
    }
}

fn selfTestSummaryClauseGateRequiresCurrentSummaryPhrases(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
) !void {
    var evidence = try summaryEvidenceFixture(allocator);
    var self_errors = std.ArrayList([]const u8).empty;
    try validateSummaryClauseDependencies(allocator, &self_errors, &evidence, "Zigos is an operating system.");

    if (!common.errorContains(self_errors.items, "capability-based") or
        !common.errorContains(self_errors.items, "not present"))
    {
        try common.addError(errors, allocator, "Spec coverage checker self-test failed: test_summary_clause_gate_requires_current_summary_phrases: missing summary phrase was accepted", .{});
    }
}

fn summaryEvidenceFixture(allocator: std.mem.Allocator) !std.StringHashMap([]const u8) {
    var evidence = std.StringHashMap([]const u8).init(allocator);
    try evidence.put(SUMMARY_REQUIREMENT_ID, "enforced");
    for (SUMMARY_CLAUSE_DEPENDENCIES) |dependency_group| {
        for (dependency_group.dependencies) |dependency_id| {
            try evidence.put(dependency_id, "enforced");
        }
    }
    return evidence;
}

fn completeSummaryText() []const u8 {
    return "Zigos is a capability-based, local-first, multi-device operating system with an immutable core, versioned object storage, strong sandboxing, explicit identity, and first-class support for modern accelerators.";
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

test "test_summary_clause_gate_rejects_missing_or_modeled_dependencies" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try selfTestSummaryClauseGateRejectsMissingOrModeledDependencies(allocator, &errors);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}

test "test_summary_clause_gate_requires_current_summary_phrases" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try selfTestSummaryClauseGateRequiresCurrentSummaryPhrases(allocator, &errors);
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}
