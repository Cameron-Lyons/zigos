const std = @import("std");
const contract_registry = @import("../src/native/task/userspace_contract_registry.zig");
const registry = @import("../src/native/task/userspace_registry.zig");

pub const ArtifactSet = struct {
    step: *std.Build.Step,
    count: usize,
    archive_module: *std.Build.Module,
};

pub fn addUserspaceArtifacts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ArtifactSet {
    const step = b.step("userspace-images", "Build userspace image artifacts");
    var count: usize = 0;
    const descriptor_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_descriptor.zig"),
    });
    const runtime_module = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = target,
        .optimize = optimize,
    });
    runtime_module.addImport("userspace_descriptor", descriptor_module);
    const archive_generator = b.addExecutable(.{
        .name = "userspace-archive-generator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/generate_userspace_archive.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    archive_generator.root_module.addImport("userspace_descriptor", descriptor_module);
    const archive_run = b.addRunArtifact(archive_generator);
    const archive_dir = archive_run.addOutputDirectoryArg("userspace-archive");
    const archive_source = archive_dir.path(b, "userspace_archive.zig");

    for (registry.boot_image_specs) |spec| {
        const contract = contract_registry.find(spec.bundle_id) orelse unreachable;
        const options = b.addOptions();
        options.addOption([]const u8, "bundle_id", spec.bundle_id);
        options.addOption([]const u8, "display_name", spec.display_name);
        options.addOption([]const u8, "label", spec.label);
        options.addOption([]const u8, "entry", spec.entry);
        options.addOption([]const u8, "publisher", spec.publisher);
        options.addOption(u8, "component_class", @intFromEnum(spec.component_class));
        options.addOption(bool, "signed", spec.signed);
        options.addOption(u32, "role_tag", contract.role_tag);
        options.addOption(u32, "heartbeat_increment", contract.heartbeat_increment);
        options.addOption(u32, "contract_flags", contract.contract_flags);

        const module = b.addModule(spec.artifact_name, .{
            .root_source_file = b.path(sourcePathFor(spec.bundle_id)),
            .target = target,
            .optimize = optimize,
        });
        module.addOptions("build_options", options);
        module.addImport("userspace_descriptor", descriptor_module);
        module.addImport("userspace_runtime", runtime_module);

        const artifact = b.addExecutable(.{
            .name = spec.artifact_name,
            .root_module = module,
        });
        artifact.setLinkerScript(b.path("src/userspace/linker.ld"));
        const install = b.addInstallArtifact(artifact, .{});
        archive_run.addArtifactArg(artifact);
        step.dependOn(&install.step);
        count += 1;
    }
    step.dependOn(&archive_run.step);

    return .{
        .step = step,
        .count = count,
        .archive_module = b.createModule(.{
            .root_source_file = archive_source,
        }),
    };
}

fn sourcePathFor(bundle_id: []const u8) []const u8 {
    if (std.mem.eql(u8, bundle_id, "zigos.system.session-manager")) return "src/userspace/entries/session_manager.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.permission-review")) return "src/userspace/entries/permission_review.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.workspace-storage")) return "src/userspace/entries/workspace_storage.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.phase1-client")) return "src/userspace/entries/phase1_client.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.phase1-temp")) return "src/userspace/entries/phase1_temp.zig";
    if (std.mem.eql(u8, bundle_id, "app.viewer")) return "src/userspace/entries/viewer.zig";
    if (std.mem.eql(u8, bundle_id, "app.notes")) return "src/userspace/entries/notes.zig";
    if (std.mem.eql(u8, bundle_id, "app.sync")) return "src/userspace/entries/sync.zig";
    if (std.mem.eql(u8, bundle_id, "app.capture")) return "src/userspace/entries/capture.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.policy-mediation")) return "src/userspace/entries/policy_mediation.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.network-stack")) return "src/userspace/entries/network_stack.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.storage-object")) return "src/userspace/entries/storage_object.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.storage-driver")) return "src/userspace/entries/storage_driver.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.package-service")) return "src/userspace/entries/package_service.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.compositor")) return "src/userspace/entries/compositor.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.indexing-search")) return "src/userspace/entries/indexing_search.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.sync-service")) return "src/userspace/entries/sync_service.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.media-print")) return "src/userspace/entries/media_print.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.compatibility-portal")) return "src/userspace/entries/compatibility_portal.zig";
    if (std.mem.eql(u8, bundle_id, "zigos.system.phase3-client")) return "src/userspace/entries/phase3_client.zig";
    return "src/userspace/component_main.zig";
}
