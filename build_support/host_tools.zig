const std = @import("std");

var executable: ?*std.Build.Step.Compile = null;

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

pub fn addRun(b: *std.Build, command: []const u8) *std.Build.Step.Run {
    const run = b.addRunArtifact(tool(b));
    run.addArg(command);
    run.setCwd(b.path("."));
    run.setEnvironmentVariable("ZIG_BIN", b.graph.zig_exe);
    return run;
}

pub fn addTests(b: *std.Build) *std.Build.Step.Run {
    const tests = b.addTest(.{ .name = "host-tool-tests", .root_module = module(b) });
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
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
    run.addArg("scenario");
    run.addArtifactArg(tool(b));
    run.addArtifactArg(verifier);
    run.setCwd(b.path("."));
    run.setEnvironmentVariable("ZIG_BIN", b.graph.zig_exe);
    return run;
}
