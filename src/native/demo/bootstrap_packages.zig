const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const package_service = @import("../services/package_service.zig");
const principal = @import("../core/principal.zig");
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
    trustDemoPublishers(packages);
    installViewer(packages);
    installNotes(packages);
    installSync(packages);
    installCapture(packages);
}

fn trustDemoPublishers(packages: *package_service.Service) void {
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    _ = packages.trustPolicyAuthorityRoot(issuer, [_]u8{0x5A} ** 32) catch unreachable;
    _ = packages.trustPublisher(.{ .kind = .app, .serial = 41 }, issuer, "zigos.dev", signing.publicKey(viewer_signer) catch unreachable) catch unreachable;
    _ = packages.trustPublisher(.{ .kind = .app, .serial = 42 }, issuer, "zigos.dev", signing.publicKey(notes_signer) catch unreachable) catch unreachable;
    _ = packages.trustPublisher(.{ .kind = .app, .serial = 43 }, issuer, "zigos.dev", signing.publicKey(sync_signer) catch unreachable) catch unreachable;
    _ = packages.trustPublisher(.{ .kind = .app, .serial = 44 }, issuer, "zigos.dev", signing.publicKey(capture_signer) catch unreachable) catch unreachable;
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
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true, .clipboard_write = true } },
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

    var bundle = manifest_fixtures.notesBundle();
    bundle.signature = signing.sign(notes_signer, &package_service.digestBundle(bundle)) catch unreachable;
    _ = packages.install(.{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installSync(packages: *package_service.Service) void {
    if (packages.find("app.sync") != null) return;

    var bundle = manifest_fixtures.syncBundle();
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
            .rights = .{ .device = .{ .device_use = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{ .device_use = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device = .{ .device_use = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .device = .{ .sensor_read = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .endpoint = .{ .ipc_peer = true } },
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
