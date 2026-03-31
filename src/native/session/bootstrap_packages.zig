const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const signing = @import("../core/signing.zig");

const store_source = "store:zigos";

const viewer_signer = signing.SignerIdentity{
    .label = "zigos.viewer.bundle",
    .seed = [_]u8{0x41} ** 32,
};
const notes_signer = signing.SignerIdentity{
    .label = "zigos.notes.bundle",
    .seed = [_]u8{0x42} ** 32,
};
const sync_signer = signing.SignerIdentity{
    .label = "zigos.sync.bundle",
    .seed = [_]u8{0x43} ** 32,
};
const capture_signer = signing.SignerIdentity{
    .label = "zigos.capture.bundle",
    .seed = [_]u8{0x44} ** 32,
};

pub fn seed(packages: *package_service.Service) void {
    installViewer(packages);
    installNotes(packages);
    installSync(packages);
    installCapture(packages);
}

fn installViewer(packages: *package_service.Service) void {
    if (packages.find("app.viewer") != null) return;

    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "viewer", .entry = "app.viewer" },
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.viewer.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/viewer/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.viewer",
        .display_name = "Viewer",
        .publisher = "zigos.dev",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
    };
    bundle.signature = signing.sign(viewer_signer, &package_service.digestBundle(bundle)) catch unreachable;
    _ = packages.install(.{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installNotes(packages: *package_service.Service) void {
    if (packages.find("app.notes") != null) return;

    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes", .entry = "app.notes" },
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
    };
    bundle.signature = signing.sign(notes_signer, &package_service.digestBundle(bundle)) catch unreachable;
    _ = packages.install(.{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installSync(packages: *package_service.Service) void {
    if (packages.find("app.sync") != null) return;

    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "sync", .entry = "app.sync" },
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.sync.replication" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/sync/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
        },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 2_000,
                .memory_bytes = 128 * 1024,
                .shared_memory_bytes = 8 * 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
        .background_tasks = &background_tasks,
    };
    bundle.signature = signing.sign(sync_signer, &package_service.digestBundle(bundle)) catch unreachable;
    _ = packages.install(.{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installCapture(packages: *package_service.Service) void {
    if (packages.find("app.capture") != null) return;

    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "capture", .entry = "app.capture" },
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.capture.session" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.media.print" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/capture/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .device_access,
            .resource = "capture.card0",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .sensor_read = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .ipc_peer = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 15,
        },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.capture",
        .display_name = "Capture",
        .publisher = "zigos.dev",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
    };
    bundle.signature = signing.sign(capture_signer, &package_service.digestBundle(bundle)) catch unreachable;
    _ = packages.install(.{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}
