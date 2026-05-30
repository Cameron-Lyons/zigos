const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const compatibility_environment = @import("../services/compatibility_environment.zig");
const debugger = @import("debugger.zig");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const SDK_PACKAGE_SERVICE_ID: u64 = 60_001;
pub const SDK_TASK_ID: u64 = 60_002;
pub const SDK_ACTOR = principal.PrincipalId{ .kind = .service, .serial = 60_003 };
pub const SDK_POLICY_AUTHORITY = principal.PrincipalId{ .kind = .policy_authority, .serial = 60_004 };
pub const SDK_PACKAGE_OWNER = principal.PrincipalId{ .kind = .service, .serial = 60_005 };

pub const DevPackage = struct {
    bundle: manifest.BundleManifest,
    signer: signing.SignerIdentity,
    source_identity: []const u8 = "sdk:local",
    data_schema_version: u32 = 1,
    migration_manifest: []const u8 = "",
    declared_permission_change: bool = false,
    retains_data_compatibility: bool = false,
    migration_applier: ?package_service.MigrationApplier = null,
};

pub const CompatibilityLaunch = struct {
    bundle: manifest.BundleManifest,
    signer: signing.SignerIdentity,
    label: []const u8,
    kind: compatibility_environment.EnvironmentKind = .emulation_layer,
    network_class: compatibility_environment.NetworkClass = .none,
};

fn signSdkReleaseBundle(identity: signing.SignerIdentity, bundle: manifest.BundleManifest) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &package_service.digestBundle(bundle),
    );
}

pub const Simulator = struct {
    packages: package_service.Service = package_service.Service.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    compatibility: compatibility_environment.Manager = compatibility_environment.Manager.init(),
    debug: debugger.Session = debugger.Session.init(),
    authority_capability_id: u64 = 0,
    now_ticks: u64 = 1,
    bootstrapped: bool = false,

    pub fn init() Simulator {
        return .{};
    }

    pub fn bootstrap(self: *Simulator) !void {
        if (self.bootstrapped) return;
        self.packages.bind(SDK_PACKAGE_SERVICE_ID, SDK_PACKAGE_OWNER);
        const package_authority = try self.capabilities.mintBootRoot(.{
            .holder = SDK_ACTOR,
            .issuer = SDK_POLICY_AUTHORITY,
            .target = .{ .kind = .service, .id = SDK_PACKAGE_SERVICE_ID },
            .rights = .{ .service = .{
                .endpoint_connect = true,
                .capability_mint = true,
                .capability_revoke = true,
            } },
            .scope = .{
                .task_id = SDK_TASK_ID,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 0,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = true,
            },
            .audit = .{},
        });
        self.authority_capability_id = package_authority.id;

        var port = self.packagePort();
        _ = try port.trustPolicyAuthorityRoot(self.authority(), SDK_POLICY_AUTHORITY, [_]u8{0xC1} ** 32);
        self.bootstrapped = true;
    }

    pub fn parseAndGenerate(self: *Simulator, source: []const u8) !idl.GeneratedSource {
        const document = try idl.parse(source);
        try self.debug.record(.idl_parsed, self.advanceClock(), "idl", "parsed", true);
        const generated = try idl.generate(&document);
        try self.debug.record(.codegen_emitted, self.advanceClock(), "idl", "zig-bindings", true);
        return generated;
    }

    pub fn install(self: *Simulator, package: DevPackage) !package_service.InstallResult {
        try self.bootstrap();
        var signed_bundle = package.bundle;
        signed_bundle.signature = try signSdkReleaseBundle(package.signer, signed_bundle);
        try self.trustPublisher(package.signer, signed_bundle.publisher);

        var port = self.packagePort();
        const result = try port.install(self.authority(), .{
            .bundle = signed_bundle,
            .source_identity = package.source_identity,
            .data_schema_version = package.data_schema_version,
            .migration_manifest = package.migration_manifest,
            .declared_permission_change = package.declared_permission_change,
            .retains_data_compatibility = package.retains_data_compatibility,
            .migration_applier = package.migration_applier,
        }, null);
        try self.debug.record(
            if (result.installed_new) .package_installed else .package_updated,
            self.advanceClock(),
            signed_bundle.bundle_id,
            signed_bundle.display_name,
            true,
        );
        return result;
    }

    pub fn rollback(self: *Simulator, bundle_id: []const u8) !package_service.InstallResult {
        try self.bootstrap();
        var port = self.packagePort();
        const result = try port.rollback(self.authority(), bundle_id);
        try self.debug.record(.package_rolled_back, self.advanceClock(), bundle_id, "rollback", true);
        return result;
    }

    pub fn remove(self: *Simulator, bundle_id: []const u8) !package_service.RemoveResult {
        try self.bootstrap();
        var port = self.packagePort();
        const result = try port.remove(self.authority(), bundle_id);
        try self.debug.record(.package_removed, self.advanceClock(), bundle_id, "remove", true);
        return result;
    }

    pub fn launchCompatibility(
        self: *Simulator,
        request: CompatibilityLaunch,
    ) !*compatibility_environment.EnvironmentRecord {
        var signed_bundle = request.bundle;
        signed_bundle.signature = try signSdkReleaseBundle(request.signer, signed_bundle);
        const environment = try self.compatibility.launch(.{
            .service_id = SDK_PACKAGE_SERVICE_ID,
            .owner = SDK_ACTOR,
            .kind = request.kind,
            .label = request.label,
            .bundle = signed_bundle,
            .network_class = request.network_class,
        });
        try self.debug.record(.compatibility_launched, self.advanceClock(), signed_bundle.bundle_id, request.label, true);
        return environment;
    }

    pub fn resolveCurrentManifest(
        self: *const Simulator,
        bundle_id: []const u8,
        resolved: *package_service.ResolvedManifest,
    ) !manifest.BundleManifest {
        return self.packages.resolveCurrentManifest(bundle_id, resolved);
    }

    fn packagePort(self: *Simulator) package_service.PackagePort {
        return package_service.PackagePort.init(&self.packages, &self.capabilities);
    }

    fn authority(self: *const Simulator) package_service.AuthorityContext {
        return .{
            .task_id = SDK_TASK_ID,
            .principal = SDK_ACTOR,
            .capability_id = self.authority_capability_id,
            .now_ticks = self.now_ticks,
        };
    }

    fn trustPublisher(self: *Simulator, signer: signing.SignerIdentity, publisher: []const u8) !void {
        var port = self.packagePort();
        _ = try port.trustPublisher(
            self.authority(),
            .{ .kind = .app, .serial = std.hash.Wyhash.hash(0x5A47_5344_4B50, publisher) },
            SDK_POLICY_AUTHORITY,
            publisher,
            try signing.publicKey(signer),
        );
    }

    fn advanceClock(self: *Simulator) u64 {
        defer self.now_ticks += 1;
        return self.now_ticks;
    }
};

test "SDK simulator installs updates rolls back and debugs example packages" {
    const examples = @import("example_apps.zig");

    var sim = Simulator.init();
    const generated = try sim.parseAndGenerate(examples.writer_idl);
    try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "writer_edit") != null);

    const writer = examples.writer();
    const first = try sim.install(.{
        .bundle = writer.bundle,
        .signer = writer.signer,
        .data_schema_version = writer.data_schema_version,
    });
    try std.testing.expect(first.installed_new);

    var updated_bundle = writer.bundle;
    updated_bundle.version_minor += 1;
    const updated = try sim.install(.{
        .bundle = updated_bundle,
        .signer = writer.signer,
        .data_schema_version = writer.data_schema_version,
        .retains_data_compatibility = true,
    });
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.rollback_available);

    const rolled_back = try sim.rollback(writer.bundle.bundle_id);
    try std.testing.expect(rolled_back.updated_existing);
    var resolved = package_service.ResolvedManifest{
        .provided_interfaces = undefined,
        .consumed_interfaces = undefined,
        .components = undefined,
        .assets = undefined,
        .requested_permissions = undefined,
        .background_tasks = undefined,
        .ai_metadata = .{},
        .signature = .{},
    };
    const current = try sim.resolveCurrentManifest(writer.bundle.bundle_id, &resolved);
    try std.testing.expectEqual(writer.bundle.version_minor, current.version_minor);

    const legacy = examples.legacyEditor();
    const environment = try sim.launchCompatibility(.{
        .bundle = legacy.bundle,
        .signer = legacy.signer,
        .label = "Legacy Editor",
    });
    try std.testing.expect(environment.isolated);
    try std.testing.expect(environment.portal_only_host_access);

    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_installed));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_updated));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_rolled_back));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.compatibility_launched));
}
