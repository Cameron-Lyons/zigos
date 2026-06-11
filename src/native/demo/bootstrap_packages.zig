const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const capability = @import("../kernel_api/capability.zig");
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

fn signDemoReleaseBundle(identity: signing.SignerIdentity, bundle: manifest.BundleManifest) manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &package_service.digestBundle(bundle),
    ) catch unreachable;
}

pub fn seed(
    packages: *package_service.Service,
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    service_principal: principal.PrincipalId,
    task_id: u64,
    authority_principal: principal.PrincipalId,
    policy_authority: principal.PrincipalId,
) void {
    packages.bind(service_id, service_principal);
    const package_authority = capability_table.mintBootRoot(.{
        .holder = authority_principal,
        .issuer = policy_authority,
        .target = .{ .kind = .service, .id = service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .capability_mint = true,
            .capability_revoke = true,
        } },
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 1_000,
        },
        .audit = .{},
    }) catch unreachable;
    var port = package_service.PackagePort.init(packages, capability_table);
    const authority = package_service.AuthorityContext{
        .task_id = task_id,
        .principal = authority_principal,
        .capability_id = package_authority.id,
        .now_ticks = 1,
    };
    trustDemoPublishers(&port, authority);
    installViewer(&port, authority, packages);
    installNotes(&port, authority, packages);
    installSync(&port, authority, packages);
    installCapture(&port, authority, packages);
    capability_table.revokeGrant(package_authority.id) catch unreachable;
}

fn trustDemoPublishers(port: *package_service.PackagePort, authority: package_service.AuthorityContext) void {
    const issuer = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    _ = port.trustPolicyAuthorityRoot(authority, issuer, [_]u8{0x5A} ** 32) catch unreachable;
    _ = port.trustPublisher(authority, .{ .kind = .app, .serial = 41 }, issuer, "zigos.dev", signing.publicKey(viewer_signer) catch unreachable) catch unreachable;
    _ = port.trustPublisher(authority, .{ .kind = .app, .serial = 42 }, issuer, "zigos.dev", signing.publicKey(notes_signer) catch unreachable) catch unreachable;
    _ = port.trustPublisher(authority, .{ .kind = .app, .serial = 43 }, issuer, "zigos.dev", signing.publicKey(sync_signer) catch unreachable) catch unreachable;
    _ = port.trustPublisher(authority, .{ .kind = .app, .serial = 44 }, issuer, "zigos.dev", signing.publicKey(capture_signer) catch unreachable) catch unreachable;
}

fn installViewer(port: *package_service.PackagePort, authority: package_service.AuthorityContext, packages: *package_service.Service) void {
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
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace://viewer",
                .principal = "trusted-devices",
            },
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
    bundle.signature = signDemoReleaseBundle(viewer_signer, bundle);
    _ = port.install(authority, .{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installNotes(port: *package_service.PackagePort, authority: package_service.AuthorityContext, packages: *package_service.Service) void {
    if (packages.find("app.notes") != null) return;

    var bundle = manifest_fixtures.notesBundle();
    bundle.signature = signDemoReleaseBundle(notes_signer, bundle);
    _ = port.install(authority, .{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installSync(port: *package_service.PackagePort, authority: package_service.AuthorityContext, packages: *package_service.Service) void {
    if (packages.find("app.sync") != null) return;

    var bundle = manifest_fixtures.syncBundle();
    bundle.signature = signDemoReleaseBundle(sync_signer, bundle);
    _ = port.install(authority, .{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}

fn installCapture(port: *package_service.PackagePort, authority: package_service.AuthorityContext, packages: *package_service.Service) void {
    if (packages.find("app.capture") != null) return;

    var bundle = manifest_fixtures.captureBundle();
    bundle.signature = signDemoReleaseBundle(capture_signer, bundle);
    _ = port.install(authority, .{
        .bundle = bundle,
        .source_identity = store_source,
        .data_schema_version = 1,
    }, null) catch unreachable;
}
