const std = @import("std");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");
const units = @import("../core/units.zig");

pub const MAX_ISSUES: usize = 24;
const BACKGROUND_BUDGET_INFO_MEMORY_BYTES: usize = units.kibibytes(256);

pub const Severity = enum(u8) {
    info,
    warning,
    err,
};

pub const Code = enum(u8) {
    manifest_validation,
    application_packaging,
    unsigned_manifest,
    unversioned_interface,
    broad_network,
    data_egress_intent,
    optional_permission,
    background_budget,
    local_first,
    sensitive_permission_reason,
    sensitive_remote_egress,
    sensitive_permission_purpose,
    sensitive_permission_retention,
    sensitive_permission_lease,
    idl_parse,
    idl_untyped_operation,
    idl_interface_missing_manifest,
    idl_native_declarations_missing,
    idl_object_permission_missing,
    idl_sync_permission_missing,
    posix_dependency,
    compat_dependency,
};

pub const Issue = struct {
    severity: Severity,
    code: Code,
    detail: []const u8,
};

pub const Report = struct {
    issue_count: usize = 0,
    issues: [MAX_ISSUES]Issue = undefined,

    pub fn hasErrors(self: *const Report) bool {
        for (self.issues[0..self.issue_count]) |issue| {
            if (issue.severity == .err) return true;
        }
        return false;
    }

    pub fn count(self: *const Report, severity: Severity) usize {
        var total: usize = 0;
        for (self.issues[0..self.issue_count]) |issue| {
            if (issue.severity == severity) total += 1;
        }
        return total;
    }

    pub fn add(self: *Report, severity: Severity, code: Code, detail: []const u8) void {
        if (self.issue_count >= self.issues.len) return;
        self.issues[self.issue_count] = .{
            .severity = severity,
            .code = code,
            .detail = detail,
        };
        self.issue_count += 1;
    }
};

pub fn lint(bundle: manifest.BundleManifest) Report {
    var report = Report{};

    manifest.validate(bundle) catch |err| {
        report.add(.err, .manifest_validation, @errorName(err));
    };
    manifest.validateApplicationPackaging(bundle) catch |err| {
        report.add(.err, .application_packaging, @errorName(err));
    };

    if (!bundle.signature.isPresent()) {
        report.add(.warning, .unsigned_manifest, "package signing flow has not attached a manifest signature");
    }

    for (bundle.provided_interfaces) |interface| {
        if (interface.version_major == 0) {
            report.add(.warning, .unversioned_interface, interface.name);
        }
    }
    for (bundle.consumed_interfaces) |interface| {
        if (interface.version_major == 0) {
            report.add(.warning, .unversioned_interface, interface.name);
        }
    }

    var local_permission_count: usize = 0;
    for (bundle.requested_permissions) |request| {
        if (!request.required) {
            report.add(.info, .optional_permission, "optional permission will be presented as skippable in review");
        }
        if (request.local_only) local_permission_count += 1;
        if (manifest.dangerousPermissionKind(request.kind) and request.user_visible_reason.len == 0) {
            report.add(.warning, .sensitive_permission_reason, "dangerous permissions should include user-visible reason text");
        }
        if (manifest.isSensitive(request.sensitivity) and request.purpose == .unspecified) {
            report.add(.warning, .sensitive_permission_purpose, "sensitive permissions should declare a specific purpose");
        }
        if (manifest.isSensitive(request.sensitivity) and request.retention_days == 0) {
            report.add(.warning, .sensitive_permission_retention, "sensitive permissions should declare retention days");
        }
        if (manifest.isSensitive(request.sensitivity) and manifest.dangerousPermissionKind(request.kind) and request.max_lease_ticks == 0) {
            report.add(.warning, .sensitive_permission_lease, "sensitive device permissions should be lease bounded");
        }
        if (request.kind == .network_egress) {
            if (!request.egress_intent.declared() or !request.egress_intent.complete()) {
                report.add(.err, .data_egress_intent, "network_egress must declare sync_object, call_service, or publish_event intent");
            }
            if (manifest.isSensitive(request.sensitivity) and request.rights.has(.network_remote)) {
                report.add(.warning, .sensitive_remote_egress, request.resource);
            }
            if (request.rights.has(.network_remote)) {
                report.add(.warning, .broad_network, request.resource);
            }
        }
    }

    for (bundle.background_tasks) |task| {
        if (task.budget.cpu_time_ticks > 2_000 or task.budget.memory_bytes > BACKGROUND_BUDGET_INFO_MEMORY_BYTES) {
            report.add(.info, .background_budget, task.id);
        }
    }

    if (bundle.requested_permissions.len != 0 and local_permission_count == bundle.requested_permissions.len) {
        report.add(.info, .local_first, "all requested permissions are local-only");
    }

    return report;
}

pub fn lintWithIdl(bundle: manifest.BundleManifest, idl_source: []const u8) Report {
    var report = lint(bundle);

    if (std.mem.trim(u8, idl_source, " \t\r\n").len == 0) {
        report.add(.err, .idl_parse, "package does not include a native IDL contract");
        return report;
    }

    const document = idl.parse(idl_source) catch |err| {
        report.add(.err, .idl_parse, @errorName(err));
        return report;
    };

    if (!document.allOperationsTyped()) {
        report.add(.err, .idl_untyped_operation, "every app operation must name request and response records");
    }
    if (document.nativeDeclarationCount() == 0) {
        report.add(.err, .idl_native_declarations_missing, "IDL must declare permissions objects or sync behavior");
    }

    for (document.interfaces[0..document.interface_count]) |*interface| {
        if (!bundleDeclaresInterface(bundle, interface.manifestDecl())) {
            report.add(.err, .idl_interface_missing_manifest, interface.nameSlice());
        }
    }

    for (document.objects[0..document.object_count]) |*object| {
        if (!bundleRequestsResource(bundle, .object_access, object.pathSlice())) {
            report.add(.warning, .idl_object_permission_missing, object.pathSlice());
        }
    }

    for (document.syncs[0..document.sync_count]) |*sync| {
        if (!bundleRequestsPermission(bundle, .network_egress)) {
            report.add(.info, .idl_sync_permission_missing, sync.prefixSlice());
        }
    }

    if (mentionsPosix(bundle) or std.mem.indexOf(u8, idl_source, "posix") != null or std.mem.indexOf(u8, idl_source, "POSIX") != null) {
        report.add(.err, .posix_dependency, "native apps must use declared services instead of POSIX escape hatches");
    }
    if (mentionsCompat(bundle) or std.mem.indexOf(u8, idl_source, "compat.") != null) {
        report.add(.err, .compat_dependency, "compatibility wrappers must be replaced with native typed components");
    }

    return report;
}

pub fn expectClean(bundle: manifest.BundleManifest) !void {
    const report = lint(bundle);
    if (report.hasErrors()) return error.ManifestLintFailed;
}

pub fn expectNativeClean(bundle: manifest.BundleManifest, idl_source: []const u8) !void {
    const report = lintWithIdl(bundle, idl_source);
    if (report.hasErrors()) return error.ManifestLintFailed;
}

fn bundleDeclaresInterface(bundle: manifest.BundleManifest, expected: manifest.InterfaceDecl) bool {
    return interfaceListDeclares(bundle.provided_interfaces, expected) or
        interfaceListDeclares(bundle.consumed_interfaces, expected);
}

fn interfaceListDeclares(interfaces: []const manifest.InterfaceDecl, expected: manifest.InterfaceDecl) bool {
    for (interfaces) |candidate| {
        if (!std.mem.eql(u8, candidate.name, expected.name)) continue;
        if (candidate.version_major != expected.version_major) continue;
        if (candidate.version_minor != expected.version_minor) continue;
        return true;
    }
    return false;
}

fn bundleRequestsPermission(bundle: manifest.BundleManifest, kind: manifest.PermissionKind) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind == kind) return true;
    }
    return false;
}

fn bundleRequestsResource(bundle: manifest.BundleManifest, kind: manifest.PermissionKind, resource: []const u8) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind != kind) continue;
        if (std.mem.eql(u8, request.resource, resource)) return true;
    }
    return false;
}

fn mentionsPosix(bundle: manifest.BundleManifest) bool {
    if (std.mem.indexOf(u8, bundle.bundle_id, "posix") != null or std.mem.indexOf(u8, bundle.bundle_id, "POSIX") != null) return true;
    for (bundle.components) |component| {
        if (std.mem.indexOf(u8, component.entry, "posix") != null or std.mem.indexOf(u8, component.entry, "POSIX") != null) return true;
    }
    return false;
}

fn mentionsCompat(bundle: manifest.BundleManifest) bool {
    if (std.mem.startsWith(u8, bundle.bundle_id, "compat.") or std.mem.indexOf(u8, bundle.bundle_id, ".compat.") != null) return true;
    for (bundle.components) |component| {
        if (std.mem.startsWith(u8, component.entry, "compat.") or std.mem.indexOf(u8, component.entry, ".compat.") != null) return true;
    }
    return false;
}

test "manifest linter explains SDK packaging problems without stopping at the first issue" {
    const report = lint(.{
        .bundle_id = "app.empty",
        .display_name = "Empty",
        .publisher = "Zigos",
    });
    try std.testing.expect(report.hasErrors());
    try std.testing.expect(report.count(.err) >= 1);
    try std.testing.expect(report.count(.warning) >= 1);
}

test "manifest linter validates typed native IDL package contracts" {
    const examples = @import("example_apps.zig");
    const package = examples.firstPartyWriter();
    const report = lintWithIdl(package.bundle, package.idl_source);
    try std.testing.expect(!report.hasErrors());

    const untyped = lintWithIdl(package.bundle,
        \\interface zigos.writer.document 1.0
        \\operation open 8 8
    );
    try std.testing.expect(untyped.hasErrors());
    try std.testing.expect(untyped.count(.err) >= 1);
}

test "manifest linter rejects compatibility wrapper packages" {
    const compat_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "main", .entry = "compat.posix.main" },
    };
    const compat_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const compat_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const report = lintWithIdl(.{
        .bundle_id = "compat.posix",
        .display_name = "Compat POSIX",
        .publisher = "zigos.dev",
        .components = &compat_components,
        .provided_interfaces = &compat_interfaces,
        .assets = &compat_assets,
    },
        \\interface zigos.object.workspace 1.0
        \\native object workspace:notes
    );

    try std.testing.expect(report.hasErrors());
    try std.testing.expect(report.count(.err) >= 1);
}

test "manifest linter highlights sensitive permission explanations and remote egress" {
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .egress_intent = .{
                .kind = .call_service,
                .service = "private.relay",
            },
        },
    };
    const report = lint(.{
        .bundle_id = "app.private-tools",
        .display_name = "Private Tools",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    });

    try std.testing.expect(report.hasErrors());
    try std.testing.expect(report.count(.warning) >= 2);
}
