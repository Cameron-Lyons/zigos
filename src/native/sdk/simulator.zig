const std = @import("std");
const app_platform = @import("app_platform.zig");
const capability = @import("../kernel_api/capability.zig");
const debugger = @import("debugger.zig");
const example_apps = @import("example_apps.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const idl = @import("idl.zig");
const manifest_linter = @import("manifest_linter.zig");
const manifest = @import("../policy/manifest.zig");
const object_store_api = @import("object_store_api.zig");
const package_service = @import("../services/package_service.zig");
const permissions = @import("permissions.zig");
const permission_review = @import("../policy/permission_review.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const sync_api = @import("sync_api.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const ui = @import("ui.zig");

pub const SDK_PACKAGE_SERVICE_ID: u64 = 60_001;
pub const SDK_TASK_ID: u64 = 60_002;
pub const SDK_ACTOR = principal.PrincipalId{ .kind = .service, .serial = 60_003 };
pub const SDK_POLICY_AUTHORITY = principal.PrincipalId{ .kind = .policy_authority, .serial = 60_004 };
pub const SDK_PACKAGE_OWNER = principal.PrincipalId{ .kind = .service, .serial = 60_005 };
pub const SDK_FIRST_APP_SURFACE_ID: u64 = 61_000;
pub const MAX_PERMISSION_REVIEW_TEXT: usize = permissions.MAX_REVIEW_TEXT_BYTES;

pub const DevPackage = struct {
    bundle: manifest.BundleManifest,
    signer: signing.SignerIdentity,
    source_identity: []const u8 = "sdk:local",
    data_schema_version: u32 = 1,
    declared_permission_change: bool = false,
};

pub const PermissionReviewResult = struct {
    request_count: usize = 0,
    grant_count: usize = 0,
    review_len: usize = 0,
    review_text: [MAX_PERMISSION_REVIEW_TEXT]u8 = [_]u8{0} ** MAX_PERMISSION_REVIEW_TEXT,
    grants: [permission_review.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant =
        [_]policy_mediation.UserGrant{.{ .kind = .object_access }} ** permission_review.MAX_REVIEW_DECISIONS,

    pub fn textSlice(self: *const PermissionReviewResult) []const u8 {
        return self.review_text[0..self.review_len];
    }

    pub fn grantSlice(self: *const PermissionReviewResult) []const policy_mediation.UserGrant {
        return self.grants[0..self.grant_count];
    }
};

pub const LaunchResult = struct {
    task_id: u64,
    component_count: usize,
    asset_count: usize,
    permission_count: usize,
    signed_provenance: bool,
    background_allowed: bool,
    local_only: bool,
    state: task_runtime.TaskState,
};

pub const NativeAppHarnessResult = struct {
    interface_count: usize = 0,
    operation_count: usize = 0,
    record_count: usize = 0,
    native_declaration_count: usize = 0,
    lint_issue_count: usize = 0,
    permission_grant_count: usize = 0,
    task_id: u64 = 0,
    object_id: u64 = 0,
    version_id: u64 = 0,
    synced_version: ?u64 = null,
    accessibility_issue_count: usize = 0,
    signed_provenance: bool = false,
    local_first: bool = false,

    pub fn completedNativeLoop(self: *const NativeAppHarnessResult) bool {
        return self.interface_count != 0 and
            self.operation_count != 0 and
            self.record_count != 0 and
            self.native_declaration_count != 0 and
            self.signed_provenance and
            self.local_first and
            self.synced_version != null and
            self.accessibility_issue_count == 0;
    }
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
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    debug: debugger.Session = debugger.Session.init(),
    authority_capability_id: u64 = 0,
    now_ticks: u64 = 1,
    next_ui_surface_id: u64 = SDK_FIRST_APP_SURFACE_ID,
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
        _ = try port.trustPolicyAuthorityRoot(self.authority(), SDK_POLICY_AUTHORITY, signing.publicKeyFromByte(0xC1));
        self.bootstrapped = true;
    }

    pub fn parseAndGenerate(self: *Simulator, source: []const u8) !idl.GeneratedSource {
        const document = try idl.parse(source);
        try self.debug.record(.idl_parsed, self.advanceClock(), "idl", "parsed", true);
        const generated = try idl.generate(&document);
        try self.debug.record(.codegen_emitted, self.advanceClock(), "idl", "zig-bindings", true);
        return generated;
    }

    pub fn runNativeAppHarness(self: *Simulator, package: example_apps.ExamplePackage) !NativeAppHarnessResult {
        const compiled = try app_platform.compile(package);
        const lint = manifest_linter.lintWithIdl(package.bundle, package.idl_source);
        if (lint.hasErrors()) return error.ManifestLintFailed;

        var permission_harness = permissions.Harness.init(SDK_TASK_ID, &package.bundle);
        const permission_result = try permission_harness.run();
        if (!permission_result.allRequiredGranted()) return error.PermissionHarnessDeniedRequired;

        _ = try self.install(.{
            .bundle = package.bundle,
            .signer = package.signer,
            .data_schema_version = package.data_schema_version,
        });
        const launched = try self.launchNativeApp(package.bundle.bundle_id);

        var objects = object_store_api.Client.init(package.signer);
        const object = try objects.putDocumentObject("simulator-native-object.md", "text/markdown", "# Native SDK");
        const updated = try objects.compareAndUpdate(object, "# Native SDK\n\nLocal-first state");

        var sync = sync_api.DevNode.init();
        const workspace = try sync.openLocalFirstWorkspace(launched.task_id, &.{"documents/"});
        try sync.publishObject(workspace, "documents/simulator-native-object.md", updated);

        const title = ui.heading(1, package.bundle.display_name, 1);
        var save = ui.iconButton(2, "Save", "save", .primary);
        save.hint = "Save local object state";
        const sync_status = ui.status(3, "Sync status", "Local first");
        const tools = ui.toolbar(4, &.{&save});
        const root_stack = ui.stack(5, &.{ &tools, &title, &sync_status });
        const root = ui.window(6, "Native App Harness", &.{&root_stack});
        const accessibility = ui.audit(&root);

        return .{
            .interface_count = compiled.interfaceCount(),
            .operation_count = compiled.operationCount(),
            .record_count = compiled.document.record_count,
            .native_declaration_count = compiled.document.nativeDeclarationCount(),
            .lint_issue_count = lint.issue_count,
            .permission_grant_count = permission_result.plan.grantSlice().len,
            .task_id = launched.task_id,
            .object_id = updated.object_id.raw(),
            .version_id = updated.version_id.raw(),
            .synced_version = sync.replicaVersionFor(workspace, "documents/simulator-native-object.md"),
            .accessibility_issue_count = accessibility.issue_count,
            .signed_provenance = launched.signed_provenance,
            .local_first = launched.local_only and workspace.offline_first,
        };
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
            .declared_permission_change = package.declared_permission_change,
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

    pub fn reviewPermissions(
        self: *Simulator,
        package: DevPackage,
        commands: []const permission_review.ReviewCommand,
    ) !PermissionReviewResult {
        try manifest.validate(package.bundle);
        var decisions = [_]permission_review.ReviewDecision{.{
            .kind = .object_access,
            .resource = "",
            .allow = false,
        }} ** permission_review.MAX_REVIEW_DECISIONS;
        var decision_count: usize = 0;
        for (package.bundle.requested_permissions, 0..) |request, index| {
            if (decision_count >= decisions.len) return error.TooManyPermissions;
            const command = if (index < commands.len)
                commands[index]
            else
                defaultReviewCommand(request);
            decisions[decision_count] = permission_review.decisionFromCommand(request, command);
            decision_count += 1;
        }

        const session = permission_review.initSession(
            SDK_TASK_ID,
            &package.bundle,
            decisions[0..decision_count],
        );
        var result = PermissionReviewResult{
            .request_count = package.bundle.requested_permissions.len,
        };
        const rendered = try permission_review.renderToBuffer(
            &result.review_text,
            &session,
            &package.bundle,
        );
        result.review_len = rendered.len;
        const grants = permission_review.decisionsToGrants(
            &package.bundle,
            session.decisions[0..session.decision_count],
            self.now_ticks,
            &result.grants,
        );
        result.grant_count = grants.len;
        try self.debug.record(
            .permission_review_rendered,
            self.advanceClock(),
            package.bundle.bundle_id,
            package.bundle.display_name,
            true,
        );
        return result;
    }

    pub fn launchNativeApp(self: *Simulator, bundle_id: []const u8) !LaunchResult {
        try self.bootstrap();
        const launch_plan = try self.packages.buildLaunchPlan(bundle_id);
        if (launch_plan.component_count == 0) return error.MissingExecutableComponent;

        var resolved = emptyResolvedManifest();
        const bundle = try self.packages.resolveCurrentManifest(bundle_id, &resolved);
        const first_component = launch_plan.components[0];
        const task = try self.runtime.createTask(.{
            .owner = appPrincipal(bundle.bundle_id),
            .component_class = .app_component,
            .budget = budgetForBundle(bundle),
            .ui_surface_id = self.nextSurfaceId(),
            .local_only = bundleIsLocalOnly(bundle),
            .initial_component = componentSpec(first_component),
            .launch = .{
                .boundary = .direct_request,
                .image_id = appImageId(bundle),
                .component_abi_version = 1,
                .signed = bundle.signature.isComplete(),
                .bundle_id = bundle.bundle_id,
            },
        });

        var component_index: usize = 1;
        while (component_index < launch_plan.component_count) : (component_index += 1) {
            _ = try self.runtime.attachComponent(
                task.id,
                componentSpec(launch_plan.components[component_index]),
                self.advanceClock(),
            );
        }

        try self.debug.record(
            .native_app_launched,
            self.advanceClock(),
            bundle.bundle_id,
            bundle.display_name,
            true,
        );
        return .{
            .task_id = task.id,
            .component_count = launch_plan.component_count,
            .asset_count = launch_plan.asset_count,
            .permission_count = bundle.requested_permissions.len,
            .signed_provenance = task.launch.signed,
            .background_allowed = task.background_allowed,
            .local_only = task.local_only,
            .state = task.state,
        };
    }

    pub fn suspendNativeApp(self: *Simulator, task_id: u64) !bool {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        if (task.state != .active) return false;
        task.state = .suspended;
        try self.debug.record(.native_app_suspended, self.advanceClock(), task.launchBundleIdSlice(), "suspend", true);
        return true;
    }

    pub fn resumeNativeApp(self: *Simulator, task_id: u64) !bool {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        if (task.state != .suspended) return false;
        task.state = .active;
        try self.debug.record(.native_app_resumed, self.advanceClock(), task.launchBundleIdSlice(), "resume", true);
        return true;
    }

    pub fn stopNativeApp(self: *Simulator, task_id: u64) !bool {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const bundle_id = task.launchBundleIdSlice();
        const stopped = try self.runtime.terminateTask(task_id, self.advanceClock());
        try self.debug.record(.native_app_stopped, self.advanceClock(), bundle_id, "stop", stopped);
        return stopped;
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
            .{ .kind = .app, .serial = std.hash.Wyhash.hash(hash_seeds.package_sdk_publisher, publisher) },
            SDK_POLICY_AUTHORITY,
            publisher,
            try signing.publicKey(signer),
        );
    }

    fn advanceClock(self: *Simulator) u64 {
        defer self.now_ticks += 1;
        return self.now_ticks;
    }

    fn nextSurfaceId(self: *Simulator) u64 {
        defer self.next_ui_surface_id += 1;
        return self.next_ui_surface_id;
    }
};

fn defaultReviewCommand(request: manifest.PermissionRequest) permission_review.ReviewCommand {
    return .{
        .allow = true,
        .local_only = request.local_only,
        .lease_ticks = if (request.max_lease_ticks == 0) null else request.max_lease_ticks,
    };
}

fn emptyResolvedManifest() package_service.ResolvedManifest {
    return .{
        .provided_interfaces = undefined,
        .consumed_interfaces = undefined,
        .components = undefined,
        .assets = undefined,
        .requested_permissions = undefined,
        .background_tasks = undefined,
        .ai_metadata = .{},
        .data_rights = .{},
        .supply_chain = .{},
        .agent_delegation = .{},
        .accessibility = .{},
        .signature = .{},
    };
}

fn appPrincipal(bundle_id: []const u8) principal.PrincipalId {
    return .{
        .kind = .app,
        .serial = std.hash.Wyhash.hash(hash_seeds.sdk_app_principal, bundle_id),
    };
}

fn appImageId(bundle: manifest.BundleManifest) u64 {
    var hasher = std.hash.Wyhash.init(hash_seeds.sdk_app_image);
    hasher.update(bundle.bundle_id);
    hasher.update(bundle.display_name);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u16, version_bytes[0..2], bundle.version_major, .little);
    std.mem.writeInt(u16, version_bytes[2..4], bundle.version_minor, .little);
    hasher.update(&version_bytes);
    const image_id = hasher.final();
    return if (image_id == 0) 1 else image_id;
}

fn componentSpec(component: package_service.StoredComponent) task_runtime.ExecutionComponentSpec {
    return .{
        .substrate = switch (component.abi) {
            .typed_component_v1 => .typed_component_abi,
            .native_sandbox => .early_elf_runner,
        },
        .label = component.idSlice(),
        .entry = component.entrySlice(),
    };
}

fn budgetForBundle(bundle: manifest.BundleManifest) task_runtime.ResourceBudget {
    var cpu_time_ticks: u64 = 12_000;
    var memory_bytes: usize = units.mebibytes(2) + bundle.components.len * units.kibibytes(128);
    var shared_memory_bytes: usize = units.kibibytes(256);
    for (bundle.background_tasks) |task| {
        cpu_time_ticks += task.budget.cpu_time_ticks;
        memory_bytes += task.budget.memory_bytes;
        shared_memory_bytes += task.budget.shared_memory_bytes;
    }

    return .{
        .cpu_time_ticks = cpu_time_ticks,
        .memory_bytes = memory_bytes,
        .endpoint_slots = @intCast(8 + bundle.components.len + bundle.consumed_interfaces.len + bundle.provided_interfaces.len),
        .shared_memory_bytes = shared_memory_bytes,
        .background_allowed = bundle.background_tasks.len != 0,
    };
}

fn bundleIsLocalOnly(bundle: manifest.BundleManifest) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind == .network_egress and request.rights.has(.network_remote)) return false;
    }
    return true;
}

test "SDK simulator installs updates rolls back launches and debugs native first party apps" {
    const examples = @import("example_apps.zig");

    var sim = Simulator.init();
    const suite = examples.firstPartySuite();
    var launched_task_ids = [_]u64{0} ** suite.len;

    for (suite, 0..) |package, index| {
        const compiled = try app_platform.compile(package);
        try std.testing.expect(compiled.operationCount() >= 4);

        const generated = try sim.parseAndGenerate(package.idl_source);
        try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "OperationDescriptor") != null);

        const review = try sim.reviewPermissions(.{
            .bundle = package.bundle,
            .signer = package.signer,
        }, &.{});
        try std.testing.expectEqual(package.bundle.requested_permissions.len, review.request_count);
        try std.testing.expect(review.grant_count >= manifest.requiredPermissionCount(package.bundle));
        try std.testing.expect(std.mem.indexOf(u8, review.textSlice(), package.bundle.display_name) != null);

        const installed = try sim.install(.{
            .bundle = package.bundle,
            .signer = package.signer,
            .data_schema_version = package.data_schema_version,
        });
        try std.testing.expect(installed.installed_new);

        const launched = try sim.launchNativeApp(package.bundle.bundle_id);
        launched_task_ids[index] = launched.task_id;
        try std.testing.expectEqual(package.bundle.components.len, launched.component_count);
        try std.testing.expectEqual(package.bundle.assets.len, launched.asset_count);
        try std.testing.expect(launched.signed_provenance);
        try std.testing.expect(launched.background_allowed);
        try std.testing.expect(launched.local_only);
        try std.testing.expectEqual(task_runtime.TaskState.active, launched.state);

        try std.testing.expect(try sim.suspendNativeApp(launched.task_id));
        try std.testing.expectEqual(task_runtime.TaskState.suspended, sim.runtime.find(launched.task_id).?.state);
        try std.testing.expect(try sim.resumeNativeApp(launched.task_id));
        try std.testing.expectEqual(task_runtime.TaskState.active, sim.runtime.find(launched.task_id).?.state);
    }

    var updated_bundle = suite[0].bundle;
    updated_bundle.version_minor += 1;
    const updated = try sim.install(.{
        .bundle = updated_bundle,
        .signer = suite[0].signer,
        .data_schema_version = suite[0].data_schema_version,
    });
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.rollback_available);

    const rolled_back = try sim.rollback(suite[0].bundle.bundle_id);
    try std.testing.expect(rolled_back.updated_existing);
    var resolved = emptyResolvedManifest();
    const current = try sim.resolveCurrentManifest(suite[0].bundle.bundle_id, &resolved);
    try std.testing.expectEqual(suite[0].bundle.version_minor, current.version_minor);

    for (launched_task_ids) |task_id| {
        try std.testing.expect(try sim.stopNativeApp(task_id));
        try std.testing.expectEqual(task_runtime.TaskState.terminated, sim.runtime.find(task_id).?.state);
    }

    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.package_installed));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_updated));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_rolled_back));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.permission_review_rendered));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.native_app_launched));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.native_app_suspended));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.native_app_resumed));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.native_app_stopped));
}

test "SDK simulator runs a radically native app harness without POSIX" {
    const examples = @import("example_apps.zig");

    var sim = Simulator.init();
    const result = try sim.runNativeAppHarness(examples.firstPartyWriter());
    try std.testing.expect(result.completedNativeLoop());
    try std.testing.expect(result.lint_issue_count >= 1);
    try std.testing.expect(result.permission_grant_count >= 1);
    try std.testing.expect(result.object_id != 0);
    try std.testing.expectEqual(result.version_id, result.synced_version.?);
}
