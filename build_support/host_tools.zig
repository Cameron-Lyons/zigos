const std = @import("std");

var executable: ?*std.Build.Step.Compile = null;
var relay_tests: ?*std.Build.Step.Run = null;

pub fn module(b: *std.Build) *std.Build.Module {
    const root = b.createModule(.{
        .root_source_file = b.path("tools/host/main.zig"),
        .target = b.graph.host,
        .optimize = .fast,
        .link_libc = true,
    });
    root.addImport("native_smoke_markers", b.createModule(.{ .root_source_file = b.path("src/native_smoke_markers.zig") }));
    root.addImport("release_catalog", b.createModule(.{ .root_source_file = b.path("src/tools/release_catalog.zig") }));
    return root;
}

pub fn tool(b: *std.Build) *std.Build.Step.Compile {
    if (executable) |value| return value;
    const value = b.addExecutable(.{ .name = "zigos-tool", .root_module = module(b) });
    executable = value;
    return value;
}

pub fn addInvocation(b: *std.Build) *std.Build.Step.Run {
    const run = b.addRunArtifact(tool(b));
    run.setCwd(b.path("."));
    addCompilerArgument(run);
    return run;
}

pub fn addRun(b: *std.Build, command: []const u8) *std.Build.Step.Run {
    const run = addInvocation(b);
    run.addArg(command);
    return run;
}

fn addCompilerArgument(run: *std.Build.Step.Run) void {
    // Resolve the current installation during make, including restored configure
    // caches. Setting Run.environ_map would freeze the entire inherited env.
    run.addArg("--build-zig");
    run.addFileArg(std.Build.LazyPath.zig_exe);
}

pub fn addEnvironmentOverride(run: *std.Build.Step.Run, name: []const u8, value: []const u8) void {
    const graph = run.step.owner.graph;
    // Keep build options before the command and its unmodified arguments.
    run.argv.insertSlice(graph.arena, 1, &.{
        .{ .bytes = "--build-env" },
        .{ .bytes = graph.dupeString(name) },
        .{ .bytes = graph.dupeString(value) },
    }) catch @panic("OOM");
}

pub fn addTests(b: *std.Build) *std.Build.Step.Run {
    const tests = b.addTest(.{ .name = "host-tool-tests", .root_module = module(b) });
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
    return run;
}

pub fn addRelayTests(b: *std.Build) *std.Build.Step.Run {
    if (relay_tests) |value| return value;
    const tests = b.addTest(.{
        .name = "qemu-peer-relay-tests",
        .root_module = module(b),
        .filters = &.{"QEMU relay"},
    });
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
    relay_tests = run;
    return run;
}

/// The fixture is a separate executable, so deterministic software signing keys
/// cannot become an available signing provider in the production host tool.
pub fn addReleaseFixture(b: *std.Build, verifier: *std.Build.Step.Compile) *std.Build.Step.Run {
    const root = b.createModule(.{
        .root_source_file = b.path("tools/host/release/fixture.zig"),
        .target = b.graph.host,
        .optimize = .fast,
        .link_libc = true,
    });
    root.addImport("common", b.createModule(.{ .root_source_file = b.path("tools/host/common.zig") }));
    root.addImport("release_catalog", b.createModule(.{ .root_source_file = b.path("src/tools/release_catalog.zig") }));
    const fixture = b.addExecutable(.{ .name = "release-command-fixture", .root_module = root });
    const run = b.addRunArtifact(fixture);
    addCompilerArgument(run);
    run.addArg("scenario");
    run.addArtifactArg(tool(b));
    run.addArtifactArg(verifier);
    run.setCwd(b.path("."));
    return run;
}
