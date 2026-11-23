const std = @import("std");
const common = @import("check_common.zig");

const TEST_ROOTS = [_][]const u8{
    "tools/host/main.zig",
    "tools/check_kernel_benchmarks.zig",
    "tools/check_kernel_roles.zig",
    "tools/check_production_readiness.zig",
    "tools/check_spec_coverage.zig",
    "src/check_release_security_gate.zig",
    "src/native_host_test.zig",
    "src/zigos_spec_test.zig",
    "src/userspace/runtime.zig",
};

const SOURCE_DIRS = [_][]const u8{ "src", "tools" };
const IGNORED_DIRS = [_][]const u8{ ".zig-cache", "zig-cache", "zig-out", "build" };

const NamedImport = struct {
    name: []const u8,
    path: []const u8,
};

const NAMED_IMPORTS = [_]NamedImport{
    .{ .name = "native_smoke_markers", .path = "src/native_smoke_markers.zig" },
    .{ .name = "release_catalog", .path = "src/tools/release_catalog.zig" },
    .{ .name = "binary_cursor", .path = "src/native/core/binary_cursor.zig" },
    .{ .name = "userspace_wire", .path = "src/native/task/userspace_wire.zig" },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var errors = std.ArrayList([]const u8).empty;
    var sources = std.StringHashMap(void).init(allocator);
    for (SOURCE_DIRS) |dir| try collectZigSources(allocator, io, dir, &sources);
    var test_files = std.StringHashMap(void).init(allocator);

    var source_it = sources.iterator();
    while (source_it.next()) |entry| {
        if (try hasTests(allocator, io, entry.key_ptr.*)) {
            try test_files.put(entry.key_ptr.*, {});
        }
    }

    for (TEST_ROOTS) |root| {
        if (!sources.contains(root)) {
            try common.addError(&errors, allocator, "Configured Zig test root is missing: {s}", .{root});
        }
    }

    var reachable = std.StringHashMap(void).init(allocator);
    if (errors.items.len == 0) {
        for (TEST_ROOTS) |root| {
            try collectReachableSources(allocator, io, sources, &reachable, root);
        }
    }

    var missing = std.ArrayList([]const u8).empty;
    var test_it = test_files.iterator();
    while (test_it.next()) |entry| {
        if (!reachable.contains(entry.key_ptr.*)) {
            try missing.append(allocator, entry.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, missing.items, {}, stringLessThan);

    if (missing.items.len > 0) {
        try common.addError(
            &errors,
            allocator,
            "Zig test root coverage failed: these files contain tests but are not reachable from the configured test roots.",
            .{},
        );
        for (missing.items) |path| {
            try common.addError(&errors, allocator, "  {s}", .{path});
        }
        try common.addError(
            &errors,
            allocator,
            "Import the file from a test root or add a dedicated test root in tools/check_zig_test_roots.zig and build.zig.",
            .{},
        );
    }

    if (errors.items.len > 0) {
        common.printErrors(errors.items);
        std.process.exit(1);
    }

    try common.printStdout(
        io,
        "Zig test roots OK: {d} test-bearing source files reachable from {d} test roots\n",
        .{ test_files.count(), TEST_ROOTS.len },
    );
}

fn collectZigSources(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    sources: *std.StringHashMap(void),
) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);

    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, entry.name });
        switch (entry.kind) {
            .directory => if (!isIgnoredDir(entry.name)) try collectZigSources(allocator, io, child, sources),
            .file => if (std.mem.endsWith(u8, entry.name, ".zig")) try sources.put(child, {}),
            else => {},
        }
    }
}

fn isIgnoredDir(name: []const u8) bool {
    for (IGNORED_DIRS) |ignored| {
        if (std.mem.eql(u8, name, ignored)) return true;
    }
    return false;
}

fn hasTests(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !bool {
    const source = try common.readFileAlloc(allocator, io, path, common.source_file_max_bytes);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "test \"")) return true;
    }
    return false;
}

fn collectReachableSources(
    allocator: std.mem.Allocator,
    io: std.Io,
    sources: std.StringHashMap(void),
    reachable: *std.StringHashMap(void),
    root: []const u8,
) !void {
    var pending = std.ArrayList([]const u8).empty;
    try pending.append(allocator, root);

    while (pending.items.len > 0) {
        const current = pending.pop().?;
        const current_gop = try reachable.getOrPut(current);
        if (current_gop.found_existing) continue;

        if (!common.pathExists(io, current)) continue;
        const source = try common.readFileAlloc(allocator, io, current, common.source_file_max_bytes);

        var offset: usize = 0;
        while (std.mem.indexOfPos(u8, source, offset, "@import(\"")) |start| {
            const import_start = start + "@import(\"".len;
            const import_end = std.mem.indexOfScalarPos(u8, source, import_start, '"') orelse break;
            const import_path = source[import_start..import_end];
            offset = import_end + 1;

            const resolved = try resolveImport(allocator, io, current, import_path) orelse continue;
            if (sources.contains(resolved) and !reachable.contains(resolved)) {
                try pending.append(allocator, resolved);
            }
        }
    }
}

fn resolveImport(
    allocator: std.mem.Allocator,
    io: std.Io,
    owner: []const u8,
    import_path: []const u8,
) !?[]const u8 {
    if (!std.mem.endsWith(u8, import_path, ".zig")) {
        for (NAMED_IMPORTS) |named_import| {
            if (std.mem.eql(u8, named_import.name, import_path)) return named_import.path;
        }
        return null;
    }

    const owner_dir = std.fs.path.dirname(owner) orelse "";
    const normalized = try normalizeRelativePath(allocator, owner_dir, import_path);
    if (!std.mem.startsWith(u8, normalized, "src/") and !std.mem.startsWith(u8, normalized, "tools/")) return null;
    if (!common.pathExists(io, normalized)) return null;
    return normalized;
}

fn normalizeRelativePath(
    allocator: std.mem.Allocator,
    owner_dir: []const u8,
    import_path: []const u8,
) ![]const u8 {
    var parts = std.ArrayList([]const u8).empty;
    try appendPathParts(allocator, &parts, owner_dir);
    try appendPathParts(allocator, &parts, import_path);

    if (parts.items.len == 0) return try allocator.dupe(u8, "");
    return std.mem.join(allocator, "/", parts.items);
}

fn appendPathParts(
    allocator: std.mem.Allocator,
    parts: *std.ArrayList([]const u8),
    path: []const u8,
) !void {
    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) {
            if (parts.items.len > 0) _ = parts.pop();
            continue;
        }
        try parts.append(allocator, segment);
    }
}

fn stringLessThan(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}
