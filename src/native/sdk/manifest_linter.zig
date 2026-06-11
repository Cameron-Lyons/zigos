const std = @import("std");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");

pub const MAX_ISSUES: usize = 24;

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
    idl_parse,
    idl_untyped_operation,
    idl_interface_missing_manifest,
    idl_native_declarations_missing,
    idl_object_permission_missing,
    idl_sync_permission_missing,
    posix_dependency,
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
        if (request.kind == .network_egress) {
            if (!request.egress_intent.declared() or !request.egress_intent.complete()) {
                report.add(.err, .data_egress_intent, "network_egress must declare sync_object, call_service, or publish_event intent");
            }
            if (request.rights.has(.network_remote)) {
                report.add(.warning, .broad_network, request.resource);
            }
        }
    }

    for (bundle.background_tasks) |task| {
        if (task.budget.cpu_time_ticks > 2_000 or task.budget.memory_bytes > 256 * 1024) {
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
