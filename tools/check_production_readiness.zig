const std = @import("std");
const common = @import("check_common.zig");

const COVERAGE_MANIFEST_PATH = "spec/coverage.json";
const PROD_READINESS_MANIFEST_PATH = "spec/production_readiness.json";

const STATUS_LABELS = [_][]const u8{ "prod_ready", "prod_candidate", "prototype", "blocked" };
const PRIORITIES = [_][]const u8{ "P0", "P1", "P2" };
const LIST_FIELDS = [_][]const u8{
    "requirements",
    "implementation_anchors",
    "current_evidence",
    "production_gaps",
    "graduation_criteria",
    "next_actions",
    "verification_commands",
};
const OPTIONAL_LIST_FIELDS = [_][]const u8{"capacity_envelope"};
const MODEL_ONLY_SYNTHETIC_IMAGE_MARKER = "prod-readiness: model-only synthetic-userspace-image";
const CRITICAL_SYNTHETIC_IMAGE_PATHS = [_][]const u8{
    "src/native/kernel_api/component_port.zig",
    "src/native/kernel_api/native_kernel.zig",
    "src/native/kernel_api/syscall_surface.zig",
    "src/native/services/userspace_service_ipc.zig",
    "src/native/session/service_path_proofs.zig",
    "src/native/storage/storage_service_ipc.zig",
    "src/native/sync/sync_service_test.zig",
    "src/native/task/process_isolation.zig",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try runSelfTests(allocator, &errors);

    const prod_source = try common.readFileAlloc(allocator, io, PROD_READINESS_MANIFEST_PATH, common.production_readiness_manifest_max_bytes);
    var parsed_prod = try std.json.parseFromSlice(std.json.Value, allocator, prod_source, .{});
    defer parsed_prod.deinit();

    const coverage_source = try common.readFileAlloc(allocator, io, COVERAGE_MANIFEST_PATH, common.coverage_manifest_max_bytes);
    var parsed_coverage = try std.json.parseFromSlice(std.json.Value, allocator, coverage_source, .{});
    defer parsed_coverage.deinit();

    try validateProdReadinessManifest(allocator, io, &errors, parsed_prod.value, parsed_coverage.value);
    try validateSyntheticUserspaceImageMarkers(allocator, io, &errors);

    if (errors.items.len > 0) {
        common.printErrors(errors.items);
        std.process.exit(1);
    }

    const tracks = common.field(parsed_prod.value, "tracks").?.array.items;
    var requirement_refs: usize = 0;
    for (tracks) |track| {
        if (common.field(track, "requirements")) |requirements| {
            if (requirements == .array) requirement_refs += requirements.array.items.len;
        }
    }
    try common.printStdout(
        io,
        "Production readiness OK: {d} tracks, {d} requirement references\n",
        .{ tracks.len, requirement_refs },
    );
}

fn validateProdReadinessManifest(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    prod_manifest: std.json.Value,
    coverage_manifest: std.json.Value,
) !void {
    if (prod_manifest != .object) {
        try common.addError(errors, allocator, "production_readiness.json must contain a JSON object", .{});
        return;
    }
    if (coverage_manifest != .object) {
        try common.addError(errors, allocator, "coverage.json must contain a JSON object", .{});
        return;
    }

    const schema_version = common.field(prod_manifest, "schema_version");
    if (schema_version == null or schema_version.? != .integer or schema_version.?.integer != 1) {
        try common.addError(errors, allocator, "production_readiness.json schema_version must be 1", .{});
    }

    const source_coverage_manifest = try common.expectStringField(
        allocator,
        errors,
        prod_manifest,
        "production_readiness.json",
        "source_coverage_manifest",
    ) orelse "";
    if (source_coverage_manifest.len > 0 and !std.mem.eql(u8, source_coverage_manifest, COVERAGE_MANIFEST_PATH)) {
        try common.addError(errors, allocator, "production_readiness.json source_coverage_manifest must be spec/coverage.json", .{});
    }

    const required_requirements = try common.collectStringArray(
        allocator,
        errors,
        common.field(coverage_manifest, "required_requirements"),
        "coverage manifest required_requirements",
        true,
    );
    var required_requirement_set = try common.collectUniqueStrings(allocator, errors, required_requirements, "required requirement");

    const requirement_evidence = try common.expectObjectField(
        allocator,
        errors,
        coverage_manifest,
        "coverage manifest",
        "requirement_evidence",
    ) orelse return;

    const tracks_value = common.field(prod_manifest, "tracks") orelse {
        try common.addError(errors, allocator, "production_readiness.json must include at least one track", .{});
        return;
    };
    const tracks = switch (tracks_value) {
        .array => |array| array.items,
        else => {
            try common.addError(errors, allocator, "production_readiness.json tracks must be an array", .{});
            return;
        },
    };
    if (tracks.len == 0) {
        try common.addError(errors, allocator, "production_readiness.json must include at least one track", .{});
        return;
    }

    var seen_track_ids = std.StringHashMap(void).init(allocator);
    for (tracks, 0..) |track, index| {
        try validateTrack(
            allocator,
            io,
            errors,
            track,
            index,
            &seen_track_ids,
            &required_requirement_set,
            requirement_evidence,
        );
    }
}

fn validateTrack(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
    track: std.json.Value,
    index: usize,
    seen_track_ids: *std.StringHashMap(void),
    required_requirement_set: *const std.StringHashMap(void),
    requirement_evidence: std.json.Value,
) !void {
    if (track != .object) {
        try common.addError(errors, allocator, "Production readiness track at index {d} must be an object", .{index});
        return;
    }

    const fallback_track_id = try std.fmt.allocPrint(allocator, "<track-{d}>", .{index});
    const track_id = try common.expectStringField(allocator, errors, track, "Production readiness track", "id") orelse fallback_track_id;
    if (std.mem.eql(u8, track_id, fallback_track_id)) {
        try common.addError(errors, allocator, "Production readiness track at index {d} must include id", .{index});
    } else {
        const gop = try seen_track_ids.getOrPut(track_id);
        if (gop.found_existing) {
            try common.addError(errors, allocator, "Duplicate production readiness track id: {s}", .{track_id});
        }
    }

    const title = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "title");
    if (title != null and title.?.len == 0) {
        try common.addError(errors, allocator, "Production readiness track {s} must include title", .{track_id});
    }

    const priority = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "priority") orelse "";
    if (priority.len > 0 and !isOneOf(priority, &PRIORITIES)) {
        try common.addError(errors, allocator, "Production readiness track {s} priority must be one of [P0, P1, P2]", .{track_id});
    }

    const status = try common.expectStringField(allocator, errors, track, try std.fmt.allocPrint(allocator, "Production readiness track {s}", .{track_id}), "status") orelse "";
    if (status.len > 0 and !isOneOf(status, &STATUS_LABELS)) {
        try common.addError(errors, allocator, "Production readiness track {s} status must be one of [blocked, prod_candidate, prod_ready, prototype]", .{track_id});
    }

    for (LIST_FIELDS) |field_name| {
        const required_non_empty = !std.mem.eql(u8, field_name, "production_gaps") or !std.mem.eql(u8, status, "prod_ready");
        _ = try common.collectStringArray(
            allocator,
            errors,
            common.field(track, field_name),
            try std.fmt.allocPrint(allocator, "Production readiness track {s} {s}", .{ track_id, field_name }),
            required_non_empty,
        );
    }

    for (OPTIONAL_LIST_FIELDS) |field_name| {
        const value = common.field(track, field_name) orelse continue;
        if (value == .null) continue;
        _ = try common.collectStringArray(
            allocator,
            errors,
            value,
            try std.fmt.allocPrint(allocator, "Production readiness track {s} optional {s}", .{ track_id, field_name }),
            false,
        );
    }

    const requirements = try common.collectStringArray(
        allocator,
        errors,
        common.field(track, "requirements"),
        try std.fmt.allocPrint(allocator, "Production readiness track {s} requirements", .{track_id}),
        true,
    );
    for (requirements) |requirement_id| {
        if (!required_requirement_set.contains(requirement_id)) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references unknown requirement: {s}",
                .{ track_id, requirement_id },
            );
            continue;
        }
        const evidence = common.field(requirement_evidence, requirement_id) orelse continue;
        const evidence_status = common.field(evidence, "status");
        if (evidence_status == null or evidence_status.? != .string or !std.mem.eql(u8, evidence_status.?.string, "enforced")) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references {s}, which is '{s}'; production tracks require spec-enforced requirements",
                .{ track_id, requirement_id, if (evidence_status != null and evidence_status.? == .string) evidence_status.?.string else "<missing>" },
            );
        }
    }

    const anchors = try common.collectStringArray(
        allocator,
        errors,
        common.field(track, "implementation_anchors"),
        try std.fmt.allocPrint(allocator, "Production readiness track {s} implementation_anchors", .{track_id}),
        true,
    );
    for (anchors) |anchor| {
        if (!common.pathExists(io, anchor)) {
            try common.addError(
                errors,
                allocator,
                "Production readiness track {s} references missing implementation anchor: {s}",
                .{ track_id, anchor },
            );
        }
    }

    const production_gaps = common.field(track, "production_gaps");
    if (std.mem.eql(u8, status, "prod_ready") and production_gaps != null and production_gaps.? == .array and production_gaps.?.array.items.len > 0) {
        try common.addError(errors, allocator, "Production readiness track {s} is prod_ready but still lists production_gaps", .{track_id});
    }
}

fn validateSyntheticUserspaceImageMarkers(
    allocator: std.mem.Allocator,
    io: std.Io,
    errors: *std.ArrayList([]const u8),
) !void {
    for (CRITICAL_SYNTHETIC_IMAGE_PATHS) |relative_path| {
        if (!common.pathExists(io, relative_path)) {
            try common.addError(errors, allocator, "Critical synthetic userspace image path is missing: {s}", .{relative_path});
            continue;
        }
        const source = try common.readFileAlloc(allocator, io, relative_path, common.source_file_max_bytes);
        try validateSyntheticUserspaceImageMarkersForSource(allocator, errors, relative_path, source);
    }
}

fn validateSyntheticUserspaceImageMarkersForSource(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    relative_path: []const u8,
    source: []const u8,
) !void {
    var previous_line: []const u8 = "";
    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 1;
    while (lines.next()) |line| : (line_number += 1) {
        if (lineCallsSyntheticUserspaceImage(line) and
            std.mem.indexOf(u8, line, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER) == null and
            std.mem.indexOf(u8, previous_line, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER) == null)
        {
            try common.addError(
                errors,
                allocator,
                "{s}:{d} calls syntheticUserspaceImage in a critical service launch path without the '{s}' marker",
                .{ relative_path, line_number, MODEL_ONLY_SYNTHETIC_IMAGE_MARKER },
            );
        }
        previous_line = line;
    }
}

fn lineCallsSyntheticUserspaceImage(line: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, line, offset, "syntheticUserspaceImage")) |start| {
        const after_name = start + "syntheticUserspaceImage".len;
        var cursor = after_name;
        while (cursor < line.len and (line[cursor] == ' ' or line[cursor] == '\t')) : (cursor += 1) {}
        if (cursor < line.len and line[cursor] == '(') return true;
        offset = after_name;
    }
    return false;
}

fn runSelfTests(allocator: std.mem.Allocator, errors: *std.ArrayList([]const u8)) !void {
    var unmarked_errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &unmarked_errors,
        "src/native/kernel_api/native_kernel.zig",
        "const image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    if (unmarked_errors.items.len == 0) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: synthetic userspace image gate accepted unmarked critical fixture", .{});
    }

    var marked_errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &marked_errors,
        "src/native/kernel_api/native_kernel.zig",
        "// " ++ MODEL_ONLY_SYNTHETIC_IMAGE_MARKER ++ "\nconst image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    if (marked_errors.items.len != 0) {
        try common.addError(errors, allocator, "Production readiness checker self-test failed: synthetic userspace image gate rejected marked model-only fixture", .{});
    }
}

fn isOneOf(value: []const u8, allowed: []const []const u8) bool {
    for (allowed) |candidate| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

test "synthetic userspace marker gate rejects unmarked fixture" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &errors,
        "src/native/kernel_api/native_kernel.zig",
        "const image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    try std.testing.expect(errors.items.len > 0);
}

test "synthetic userspace marker gate accepts model-only marker" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    try validateSyntheticUserspaceImageMarkersForSource(
        allocator,
        &errors,
        "src/native/kernel_api/native_kernel.zig",
        "// " ++ MODEL_ONLY_SYNTHETIC_IMAGE_MARKER ++ "\nconst image = task_runtime.syntheticUserspaceImage(\"label\", \"entry\");\n",
    );
    try std.testing.expectEqual(@as(usize, 0), errors.items.len);
}
