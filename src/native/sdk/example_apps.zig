const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const signing = @import("../core/signing.zig");

pub const ExampleKind = enum(u8) {
    writer,
    viewer,
    first_party_writer,
    first_party_workbench,
    first_party_studio,
    legacy_editor,
};

pub const ExamplePackage = struct {
    kind: ExampleKind,
    bundle: manifest.BundleManifest,
    signer: signing.SignerIdentity,
    data_schema_version: u32 = 1,
    idl_source: []const u8 = "",
};

pub const writer_signer = signing.SignerIdentity{
    .label = "example.writer.bundle",
    .seed = [_]u8{0xA1} ** signing.SEED_BYTES,
};

pub const viewer_signer = signing.SignerIdentity{
    .label = "example.viewer.bundle",
    .seed = [_]u8{0xA2} ** signing.SEED_BYTES,
};

pub const legacy_editor_signer = signing.SignerIdentity{
    .label = "example.legacy.bundle",
    .seed = [_]u8{0xA3} ** signing.SEED_BYTES,
};

pub const first_party_writer_signer = signing.SignerIdentity{
    .label = "zigos.writer.bundle",
    .seed = [_]u8{0xB1} ** signing.SEED_BYTES,
};

pub const first_party_workbench_signer = signing.SignerIdentity{
    .label = "zigos.workbench.bundle",
    .seed = [_]u8{0xB2} ** signing.SEED_BYTES,
};

pub const first_party_studio_signer = signing.SignerIdentity{
    .label = "zigos.studio.bundle",
    .seed = [_]u8{0xB3} ** signing.SEED_BYTES,
};

pub const writer_idl =
    \\interface writer.edit 1.0
    \\operation open 32 8
    \\operation save 64 8
    \\operation export_pdf 48 8
;

pub const viewer_idl =
    \\interface viewer.document 1.0
    \\operation open 24 8
    \\operation annotate 48 8
;

pub const legacy_editor_idl =
    \\interface compat.portal 1.0
    \\operation open_uri 32 8
    \\operation file_import 40 8
;

pub const first_party_writer_idl =
    \\interface zigos.writer.document 1.0
    \\operation open_workspace_document 64 16
    \\operation apply_structured_edit 128 24
    \\operation render_page_preview 96 32
    \\operation export_versioned_pdf 80 16
    \\operation schedule_local_autosave 40 8
;

pub const first_party_workbench_idl =
    \\interface zigos.workbench.developer 1.0
    \\operation compile_idl 96 32
    \\operation sign_package 128 64
    \\operation run_simulator 80 24
    \\operation inspect_debug_trace 64 48
;

pub const first_party_studio_idl =
    \\interface zigos.studio.capture 1.0
    \\operation start_capture_session 80 24
    \\operation attach_media_track 96 16
    \\operation export_timeline 128 24
    \\operation publish_local_archive 72 16
;

const first_party_writer_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "writer-ui", .entry = "app.zigos.writer.ui" },
    .{ .id = "writer-indexer", .entry = "app.zigos.writer.indexer", .abi = .native_sandbox },
    .{ .id = "writer-export", .entry = "app.zigos.writer.export" },
};

const first_party_writer_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.writer.document", .version_major = 1, .version_minor = 0 },
};

const first_party_writer_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.object.workspace" },
    .{ .name = "zigos.media.print" },
    .{ .name = "zigos.notification.center" },
};

const first_party_writer_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/writer/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/writer/editor.css", .content_type = "text/css" },
};

const first_party_writer_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://documents",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 8_000,
    },
    .{
        .kind = .clipboard,
        .resource = "clipboard",
        .rights = .{ .workspace = .{ .clipboard_read = true, .clipboard_write = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 600,
    },
    .{
        .kind = .network_egress,
        .resource = "local-sync",
        .rights = .{ .network_policy = .{ .network_local = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 1_200,
    },
    .{
        .kind = .background_execution,
        .resource = "writer-autosave",
        .rights = .{ .task = .{ .background_run = true } },
        .required = false,
        .local_only = true,
    },
    .{
        .kind = .notification_post,
        .resource = "writer-export-status",
        .rights = .{ .workspace = .{ .notification_post = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 2_000,
    },
};

const first_party_writer_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "writer-autosave",
        .trigger = .local_object_change,
        .expected_duration_seconds = 20,
        .budget = .{
            .cpu_time_ticks = 700,
            .memory_bytes = 96 * 1024,
            .shared_memory_bytes = 12 * 1024,
        },
        .network = .local_network_only,
        .visibility = .status_only,
    },
};

const first_party_workbench_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "workbench-ui", .entry = "app.zigos.workbench.ui" },
    .{ .id = "idl-compiler", .entry = "app.zigos.workbench.idl", .abi = .native_sandbox },
    .{ .id = "sim-runner", .entry = "app.zigos.workbench.simulator", .abi = .native_sandbox },
    .{ .id = "debug-inspector", .entry = "app.zigos.workbench.debug" },
};

const first_party_workbench_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.workbench.developer", .version_major = 1, .version_minor = 0 },
};

const first_party_workbench_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.package.install" },
    .{ .name = "zigos.debug.trace" },
    .{ .name = "zigos.simulator.control" },
    .{ .name = "zigos.object.workspace" },
};

const first_party_workbench_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/workbench/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/workbench/debug.css", .content_type = "text/css" },
};

const first_party_workbench_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://projects",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 6_000,
    },
    .{
        .kind = .peer_ipc,
        .resource = "zigos.debug.trace",
        .rights = .{ .endpoint = .{ .ipc_peer = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 900,
    },
    .{
        .kind = .background_execution,
        .resource = "simulator-run",
        .rights = .{ .task = .{ .background_run = true } },
        .required = false,
        .local_only = true,
    },
    .{
        .kind = .notification_post,
        .resource = "build-status",
        .rights = .{ .workspace = .{ .notification_post = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 1_000,
    },
};

const first_party_workbench_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "simulator-run",
        .trigger = .user_approved_scheduled_job,
        .expected_duration_seconds = 45,
        .budget = .{
            .cpu_time_ticks = 2_400,
            .memory_bytes = 384 * 1024,
            .shared_memory_bytes = 32 * 1024,
        },
        .network = .none,
        .visibility = .user_visible,
    },
};

const first_party_studio_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "studio-ui", .entry = "app.zigos.studio.ui" },
    .{ .id = "capture-engine", .entry = "app.zigos.studio.capture", .abi = .native_sandbox },
    .{ .id = "media-export", .entry = "app.zigos.studio.export", .abi = .native_sandbox },
};

const first_party_studio_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.studio.capture", .version_major = 1, .version_minor = 0 },
};

const first_party_studio_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.object.workspace" },
    .{ .name = "zigos.media.print" },
    .{ .name = "zigos.notification.center" },
};

const first_party_studio_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/studio/icon.svg", .content_type = "image/svg+xml" },
    .{ .path = "assets/studio/timeline.css", .content_type = "text/css" },
};

const first_party_studio_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://media",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 4_000,
    },
    .{
        .kind = .camera,
        .resource = "camera.front",
        .rights = .{ .device = .{ .device_use = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 300,
        .target_id = 701,
    },
    .{
        .kind = .mic,
        .resource = "mic.array",
        .rights = .{ .device = .{ .device_use = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 300,
        .target_id = 702,
    },
    .{
        .kind = .screen_capture,
        .resource = "display.main",
        .rights = .{ .workspace = .{ .screen_capture = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 300,
    },
    .{
        .kind = .background_execution,
        .resource = "studio-export",
        .rights = .{ .task = .{ .background_run = true } },
        .required = false,
        .local_only = true,
    },
    .{
        .kind = .notification_post,
        .resource = "studio-export-status",
        .rights = .{ .workspace = .{ .notification_post = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 1_500,
    },
};

const first_party_studio_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "studio-export",
        .trigger = .media_export_completion,
        .expected_duration_seconds = 60,
        .budget = .{
            .cpu_time_ticks = 3_000,
            .memory_bytes = 512 * 1024,
            .shared_memory_bytes = 64 * 1024,
        },
        .network = .none,
        .visibility = .user_visible,
    },
};

const viewer_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "viewer-ui", .entry = "com.example.viewer.ui" },
};

const viewer_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "viewer.document", .version_major = 1, .version_minor = 0 },
};

const viewer_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.object.workspace" },
    .{ .name = "zigos.media.print" },
};

const viewer_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/viewer/icon.svg", .content_type = "image/svg+xml" },
};

const viewer_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://documents",
        .rights = .{ .object = .{ .object_read = true } },
        .local_only = true,
    },
    .{
        .kind = .clipboard,
        .resource = "clipboard",
        .rights = .{ .workspace = .{ .clipboard_read = true } },
        .required = false,
        .local_only = true,
    },
};

const legacy_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "legacy-editor", .entry = "compat.portal.launcher" },
};

const legacy_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.compat.portal" },
};

const legacy_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/legacy-editor/icon.svg", .content_type = "image/svg+xml" },
};

pub fn writer() ExamplePackage {
    return .{
        .kind = .writer,
        .bundle = manifest_fixtures.exampleWriterBundle(),
        .signer = writer_signer,
        .data_schema_version = 1,
        .idl_source = writer_idl,
    };
}

pub fn viewer() ExamplePackage {
    return .{
        .kind = .viewer,
        .bundle = .{
            .bundle_id = "com.example.viewer",
            .display_name = "Viewer",
            .publisher = "Example Software",
            .provided_interfaces = &viewer_provided_interfaces,
            .consumed_interfaces = &viewer_consumed_interfaces,
            .components = &viewer_components,
            .assets = &viewer_assets,
            .requested_permissions = &viewer_permissions,
            .update_channel = .stable,
        },
        .signer = viewer_signer,
        .data_schema_version = 1,
        .idl_source = viewer_idl,
    };
}

pub fn firstPartyWriter() ExamplePackage {
    return .{
        .kind = .first_party_writer,
        .bundle = .{
            .bundle_id = "app.zigos.writer",
            .display_name = "Zigos Writer",
            .publisher = "Zigos",
            .provided_interfaces = &first_party_writer_provided_interfaces,
            .consumed_interfaces = &first_party_writer_consumed_interfaces,
            .components = &first_party_writer_components,
            .assets = &first_party_writer_assets,
            .requested_permissions = &first_party_writer_permissions,
            .background_tasks = &first_party_writer_background_tasks,
            .ai_metadata = .{
                .model_family = "zigos-local-writing",
                .locality = .local_only,
                .offline_required = true,
            },
            .update_channel = .stable,
        },
        .signer = first_party_writer_signer,
        .data_schema_version = 2,
        .idl_source = first_party_writer_idl,
    };
}

pub fn firstPartyWorkbench() ExamplePackage {
    return .{
        .kind = .first_party_workbench,
        .bundle = .{
            .bundle_id = "app.zigos.workbench",
            .display_name = "Zigos Workbench",
            .publisher = "Zigos",
            .provided_interfaces = &first_party_workbench_provided_interfaces,
            .consumed_interfaces = &first_party_workbench_consumed_interfaces,
            .components = &first_party_workbench_components,
            .assets = &first_party_workbench_assets,
            .requested_permissions = &first_party_workbench_permissions,
            .background_tasks = &first_party_workbench_background_tasks,
            .update_channel = .dev,
        },
        .signer = first_party_workbench_signer,
        .data_schema_version = 1,
        .idl_source = first_party_workbench_idl,
    };
}

pub fn firstPartyStudio() ExamplePackage {
    return .{
        .kind = .first_party_studio,
        .bundle = .{
            .bundle_id = "app.zigos.studio",
            .display_name = "Zigos Studio",
            .publisher = "Zigos",
            .provided_interfaces = &first_party_studio_provided_interfaces,
            .consumed_interfaces = &first_party_studio_consumed_interfaces,
            .components = &first_party_studio_components,
            .assets = &first_party_studio_assets,
            .requested_permissions = &first_party_studio_permissions,
            .background_tasks = &first_party_studio_background_tasks,
            .update_channel = .beta,
        },
        .signer = first_party_studio_signer,
        .data_schema_version = 1,
        .idl_source = first_party_studio_idl,
    };
}

pub fn firstPartySuite() [3]ExamplePackage {
    return .{
        firstPartyWriter(),
        firstPartyWorkbench(),
        firstPartyStudio(),
    };
}

pub fn legacyEditor() ExamplePackage {
    return .{
        .kind = .legacy_editor,
        .bundle = .{
            .bundle_id = "compat.example.legacy-editor",
            .display_name = "Legacy Editor",
            .publisher = "Example Software",
            .provided_interfaces = &.{},
            .consumed_interfaces = &legacy_consumed_interfaces,
            .components = &legacy_components,
            .assets = &legacy_assets,
            .requested_permissions = &.{},
            .update_channel = .pinned,
        },
        .signer = legacy_editor_signer,
        .data_schema_version = 1,
        .idl_source = legacy_editor_idl,
    };
}

pub fn byName(name: []const u8) ?ExamplePackage {
    if (std.mem.eql(u8, name, "writer")) return writer();
    if (std.mem.eql(u8, name, "viewer")) return viewer();
    if (std.mem.eql(u8, name, "zigos-writer") or std.mem.eql(u8, name, "first-party-writer")) return firstPartyWriter();
    if (std.mem.eql(u8, name, "zigos-workbench") or std.mem.eql(u8, name, "workbench")) return firstPartyWorkbench();
    if (std.mem.eql(u8, name, "zigos-studio") or std.mem.eql(u8, name, "studio")) return firstPartyStudio();
    if (std.mem.eql(u8, name, "legacy") or std.mem.eql(u8, name, "legacy-editor")) return legacyEditor();
    return null;
}

test "example apps are complete app or compatibility manifests" {
    const first_party = firstPartySuite();
    const packages = [_]ExamplePackage{
        writer(),
        viewer(),
        first_party[0],
        first_party[1],
        first_party[2],
        legacyEditor(),
    };
    for (packages) |package| {
        try manifest.validate(package.bundle);
        try manifest.validateApplicationPackaging(package.bundle);
        try std.testing.expect(package.idl_source.len != 0);
    }
}

test "first party apps prove native app platform surfaces without compatibility portals" {
    for (firstPartySuite()) |package| {
        try std.testing.expect(!std.mem.startsWith(u8, package.bundle.bundle_id, "compat."));
        try std.testing.expect(package.bundle.components.len >= 3);
        try std.testing.expect(package.bundle.provided_interfaces.len >= 1);
        try std.testing.expect(package.bundle.requested_permissions.len >= 4);
        try std.testing.expect(package.bundle.background_tasks.len >= 1);
    }
}
