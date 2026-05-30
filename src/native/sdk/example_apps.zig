const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const signing = @import("../core/signing.zig");

pub const ExampleKind = enum(u8) {
    writer,
    viewer,
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
    if (std.mem.eql(u8, name, "legacy") or std.mem.eql(u8, name, "legacy-editor")) return legacyEditor();
    return null;
}

test "example apps are complete app or compatibility manifests" {
    const packages = [_]ExamplePackage{ writer(), viewer(), legacyEditor() };
    for (packages) |package| {
        try manifest.validate(package.bundle);
        try manifest.validateApplicationPackaging(package.bundle);
        try std.testing.expect(package.idl_source.len != 0);
    }
}
