const std = @import("std");
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
    optional_permission,
    background_budget,
    local_first,
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
        if (request.kind == .network_egress and request.rights.has(.network_remote)) {
            report.add(.warning, .broad_network, request.resource);
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

pub fn expectClean(bundle: manifest.BundleManifest) !void {
    const report = lint(bundle);
    if (report.hasErrors()) return error.ManifestLintFailed;
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
