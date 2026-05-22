const abi = @import("../../core/abi.zig");
const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const ids = @import("../../core/ids.zig");
const manifest = @import("../../policy/manifest.zig");
const native_ux = @import("../native_ux.zig");
const package_service = @import("../../services/package_service.zig");
const policy_object = @import("../../policy/policy_object.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const rendering = @import("rendering.zig");

const appendFmt = rendering.appendFmt;
const renderControl = rendering.renderControl;

pub const ProductionJourneyControl = enum {
    apply_policy,
    trust_device,
    install_app,
    start_task,
    open_workspace,
    open_document,
    review_permission,
    sync_workspace,
    update_app,
    rollback_update,
    recover_system,
    remove_app,
    revoke_device,
    revoke_policy,
};

pub const ProductionJourneyStatus = enum(u8) {
    ok = 0,
    invalid_order = 1,
    policy_rejected = 2,
    package_rejected = 3,
    sync_rejected = 4,
    compositor_rejected = 5,
    recovery_missing = 6,
    invalid_request = 7,
};

pub const ProductionJourneyConfig = struct {
    user: principal.PrincipalId,
    admin: principal.PrincipalId,
    app_owner: principal.PrincipalId,
    organization_id: u64,
    reviewer_task_id: u64,
    workspace_id: u64,
    workspace_label: []const u8,
    document_path: []const u8,
    task_label: []const u8,
    task_entry: []const u8,
    task_title: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    source_identity: []const u8,
    sync_destination: []const u8,
    device_label: []const u8,
    policy_label: []const u8,
    install_bundle: manifest.BundleManifest,
    update_bundle: manifest.BundleManifest,
    ui_surface_id: u64,
    image_id: u64,
    sync_from_device: principal.PrincipalId,
    sync_to_device: principal.PrincipalId,
    policy_signer: signing.SignerIdentity,
    user_signer: signing.SignerIdentity,
    primary_device_signer: signing.SignerIdentity,
    paired_device_signer: signing.SignerIdentity,
};

pub const ProductionJourneyRequest = struct {
    control: ProductionJourneyControl,
    tick: u64 = 0,
};

pub const ProductionJourneyResponse = struct {
    control: ProductionJourneyControl,
    status: ProductionJourneyStatus = .ok,
    task_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    task_flow_events: u16 = 0,
    policy_events: u16 = 0,
    device_trust_events: u16 = 0,
};

pub const ProductionJourneyService = struct {
    runtime_service: *task_runtime_service.Service,
    ux: *native_ux.Controller,
    compositor_service: *compositor_session.Service,
    storage: *storage_service.Service,
    packages: *package_service.PackagePort,
    package_authority: package_service.AuthorityContext,
    sync: *sync_service.SyncPort,
    sync_authority: sync_service.AuthorityContext,
    policies: *policy_object.Directory,
    ledger: *event_ledger.Ledger,
    config: ProductionJourneyConfig,
    task_id: u64 = 0,
    app_panel_window_id: u64 = 0,
    policy_id: u64 = 0,
    installed: bool = false,
    workspace_opened: bool = false,
    document_opened: bool = false,
    permission_reviewed: bool = false,
    device_trusted: bool = false,
    sync_configured: bool = false,
    synced: bool = false,
    updated: bool = false,
    rolled_back: bool = false,
    recovered: bool = false,
    removed: bool = false,
    device_revoked: bool = false,
    policy_revoked: bool = false,
    next_ledger_flow_order: usize = 0,

    pub fn init(
        runtime_service: *task_runtime_service.Service,
        ux: *native_ux.Controller,
        compositor_service: *compositor_session.Service,
        storage: *storage_service.Service,
        packages: *package_service.PackagePort,
        package_authority: package_service.AuthorityContext,
        sync: *sync_service.SyncPort,
        sync_authority: sync_service.AuthorityContext,
        policies: *policy_object.Directory,
        ledger: *event_ledger.Ledger,
        config: ProductionJourneyConfig,
    ) ProductionJourneyService {
        return .{
            .runtime_service = runtime_service,
            .ux = ux,
            .compositor_service = compositor_service,
            .storage = storage,
            .packages = packages,
            .package_authority = package_authority,
            .sync = sync,
            .sync_authority = sync_authority,
            .policies = policies,
            .ledger = ledger,
            .config = config,
            .next_ledger_flow_order = ux.flow_count,
        };
    }

    pub fn dispatch(self: *ProductionJourneyService, request: ProductionJourneyRequest) ProductionJourneyResponse {
        var response = ProductionJourneyResponse{ .control = request.control };
        self.click(request.control, request.tick) catch |err| {
            response.status = statusForProductionJourneyError(err);
        };
        if (response.status == .ok and request.control != .recover_system) {
            self.runtime_service.checkpoint(request.tick);
        }
        self.refreshResponse(&response);
        return response;
    }

    pub fn render(self: *const ProductionJourneyService, buffer: []u8) ![]const u8 {
        const session = self.compositor_service.session;
        var used: usize = 0;
        try appendFmt(buffer, &used, "Zigos production journey service\n", .{});
        try renderControl(buffer, &used, "apply-policy", self.policy_id != 0);
        try renderControl(buffer, &used, "trust-device", self.device_trusted);
        try renderControl(buffer, &used, "install-app", self.installed);
        try renderControl(buffer, &used, "start-task", self.task_id != 0);
        try renderControl(buffer, &used, "open-workspace", self.workspace_opened);
        try renderControl(buffer, &used, "open-document", self.document_opened);
        try renderControl(buffer, &used, "review-permission", self.permission_reviewed);
        try renderControl(buffer, &used, "sync-workspace", self.synced);
        try renderControl(buffer, &used, "update-app", self.updated);
        try renderControl(buffer, &used, "rollback-update", self.rolled_back);
        try renderControl(buffer, &used, "recover-system", self.recovered);
        try renderControl(buffer, &used, "remove-app", self.removed);
        try renderControl(buffer, &used, "revoke-device", self.device_revoked);
        try renderControl(buffer, &used, "revoke-policy", self.policy_revoked);
        try appendFmt(buffer, &used, "task={d} bundle={s} workspace={d} policy={d}\n", .{
            self.task_id,
            self.config.bundle_id,
            self.config.workspace_id,
            self.policy_id,
        });
        try appendFmt(buffer, &used, "visible_windows={d} task_flow_events={d} policy_events={d} device_trust_events={d}\n", .{
            session.visibleWindowCount(),
            self.ledger.countMatching(.{ .kind = .task_flow }),
            self.ledger.countMatching(.{ .kind = .policy_change }),
            self.ledger.countMatching(.{ .kind = .device_trust_change }),
        });
        return buffer[0..used];
    }

    fn click(self: *ProductionJourneyService, control: ProductionJourneyControl, tick: u64) !void {
        switch (control) {
            .apply_policy => try self.applyPolicy(tick),
            .trust_device => try self.trustDevice(tick),
            .install_app => try self.installApp(tick),
            .start_task => try self.startTask(tick),
            .open_workspace => try self.openWorkspace(tick),
            .open_document => try self.openDocument(tick),
            .review_permission => try self.reviewPermission(tick),
            .sync_workspace => try self.syncWorkspace(tick),
            .update_app => try self.updateApp(tick),
            .rollback_update => try self.rollbackUpdate(tick),
            .recover_system => try self.recoverSystem(tick),
            .remove_app => try self.removeApp(tick),
            .revoke_device => try self.revokeDevice(tick),
            .revoke_policy => try self.revokePolicy(tick),
        }
    }

    fn applyPolicy(self: *ProductionJourneyService, tick: u64) !void {
        if (self.policy_id != 0 and !self.policy_revoked) return error.PolicyAlreadyApplied;
        const allowed_install_sources = [_][]const u8{self.config.source_identity};
        const allowed_sync_destinations = [_][]const u8{self.config.sync_destination};
        const policy = try self.policies.create(.{
            .scope = .organization,
            .subject_id = self.config.organization_id,
            .issuer = self.config.admin,
            .label = self.config.policy_label,
            .install_source_mode = .trusted_sources,
            .allowed_install_sources = &allowed_install_sources,
            .network_egress_mode = .allow_list,
            .allowed_sync_destinations = &allowed_sync_destinations,
            .retention_days = 180,
            .audit_export_required = true,
        }, self.config.policy_signer);
        self.policy_id = policy.id;
        self.policy_revoked = false;
        try self.ledger.recordPolicyChange(self.config.admin, policy.id, .applied, tick, policy.labelSlice());
    }

    fn trustDevice(self: *ProductionJourneyService, tick: u64) !void {
        _ = try self.requireActivePolicy();
        _ = try self.sync.ensureUserRoot(
            self.sync_authority,
            self.config.user,
            "owner",
            self.config.user_signer,
        );
        if (!self.sync.service.isTrustedDevice(self.config.sync_from_device)) {
            _ = try self.sync.enrollTrustedDevice(
                self.sync_authority,
                self.config.user,
                self.config.sync_from_device,
                "primary",
                self.config.user_signer,
                self.config.primary_device_signer,
                tick,
            );
            try self.ledger.recordDeviceTrustChange(
                self.config.admin,
                self.config.sync_from_device,
                true,
                tick,
                "primary trusted for sync",
            );
        }
        if (!self.sync.service.isTrustedDevice(self.config.sync_to_device)) {
            _ = try self.sync.enrollTrustedDevice(
                self.sync_authority,
                self.config.user,
                self.config.sync_to_device,
                self.config.device_label,
                self.config.user_signer,
                self.config.paired_device_signer,
                tick,
            );
            try self.ledger.recordDeviceTrustChange(
                self.config.admin,
                self.config.sync_to_device,
                true,
                tick,
                self.config.device_label,
            );
        }
        self.device_trusted = self.sync.service.isTrustedDevice(self.config.sync_to_device);
    }

    fn installApp(self: *ProductionJourneyService, tick: u64) !void {
        if (self.installed and !self.removed) return error.AppAlreadyInstalled;
        const policy = try self.requireActivePolicy();
        const installed_result = try self.packages.install(self.package_authority, .{
            .bundle = self.config.install_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
        }, policy);
        if (!installed_result.installed_new) return error.AppAlreadyInstalled;
        _ = try self.ux.installApp(self.config.user, self.config.bundle_id);
        self.installed = true;
        self.removed = false;
        try self.recordPendingTaskFlows(tick);
    }

    fn startTask(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.installed or self.removed) return error.AppNotInstalled;
        if (self.task_id != 0) return error.TaskAlreadyStarted;
        const image = task_runtime.syntheticUserspaceImage(self.config.task_label, self.config.task_entry);
        const task = try self.ux.startTask(self.runtime_service.runtimePtr(), .{
            .owner = self.config.app_owner,
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = 64 * 1024,
                .endpoint_slots = 2,
                .shared_memory_bytes = 4096,
            },
            .ui_surface_id = self.config.ui_surface_id,
            .local_only = true,
            .initial_component = .{
                .label = self.config.task_label,
                .entry = self.config.task_entry,
            },
            .launch = .{
                .boundary = .userspace_process,
                .image_id = self.config.image_id,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = self.config.bundle_id,
            },
            .userspace_image = &image,
        });
        self.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *ProductionJourneyService, tick: u64) !void {
        const task = try self.requireTask();
        _ = try self.ux.openWorkspace(
            self.storage,
            ids.workspace(self.config.workspace_id),
            self.config.document_path,
            self.config.user,
        );
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .workspace_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = self.config.workspace_label,
        });
        self.workspace_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openDocument(self: *ProductionJourneyService, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.workspace_opened) return error.WorkspaceRequired;
        _ = try self.ux.openDocument(
            self.storage,
            ids.workspace(self.config.workspace_id),
            self.config.document_path,
            task.id,
            self.config.user,
        );
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .document_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = self.config.document_path,
        });
        self.document_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn reviewPermission(self: *ProductionJourneyService, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.document_opened) return error.DocumentRequired;
        const permission = self.permissionRequest();
        const review_response = try self.dispatchCompositor(.{
            .operation = .review_permission,
            .subject_task_id = task.id,
            .reviewer_task_id = self.config.reviewer_task_id,
            .permission_kind = permission.kind,
            .required = permission.required,
            .local_only = permission.local_only,
            .max_lease_ticks = permission.max_lease_ticks,
            .bundle_id = self.config.bundle_id,
            .display_name = self.config.display_name,
            .resource = permission.resource,
        });
        _ = try self.ux.openAppPanel(task.id, self.config.workspace_id, self.config.user, self.config.bundle_id);
        _ = try self.dispatchCompositor(.{
            .operation = .record_decision,
            .window_id = review_response.window_id,
            .permission_kind = permission.kind,
            .allow = true,
            .local_only = true,
            .required = permission.required,
            .has_lease = permission.max_lease_ticks != 0,
            .lease_ticks = permission.max_lease_ticks,
            .max_lease_ticks = permission.max_lease_ticks,
            .resource = permission.resource,
        });
        _ = try self.ux.reviewPermissionDecision(
            task.id,
            self.config.user,
            self.config.bundle_id,
            permission,
            true,
            true,
            permission.max_lease_ticks,
        );
        self.app_panel_window_id = review_response.window_id;
        self.permission_reviewed = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn syncWorkspace(self: *ProductionJourneyService, tick: u64) !void {
        _ = try self.requireActivePolicy();
        if (!self.device_trusted or !self.sync.service.isTrustedDevice(self.config.sync_to_device)) {
            return error.DeviceTrustRequired;
        }
        const decision = self.policies.syncDestinationDecision(.{
            .user_id = self.config.user.serial,
            .device_id = self.config.sync_to_device.serial,
            .workspace_id = self.config.workspace_id,
            .organization_id = self.config.organization_id,
        }, self.config.sync_destination);
        if (!decision.allowed) return error.PolicyDenied;
        try self.ensureSyncPolicy();
        const summary = try self.sync.replicateWorkspace(
            self.sync_authority,
            self.storage,
            self.config.workspace_id,
            self.config.sync_from_device,
            self.config.sync_to_device,
            .device_to_device,
        );
        if (!summary.offline_first or !summary.personal_e2ee or !summary.used_device_to_device) {
            return error.SyncPolicyMissing;
        }
        _ = try self.ux.syncWorkspace(self.config.workspace_id, self.config.user, "device-to-device");
        self.synced = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn updateApp(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.installed or self.removed) return error.AppNotInstalled;
        const policy = try self.requireActivePolicy();
        const updated_result = try self.packages.install(self.package_authority, .{
            .bundle = self.config.update_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
            .retains_data_compatibility = true,
        }, policy);
        if (!updated_result.updated_existing or !updated_result.rollback_available) return error.AppNotInstalled;
        _ = try self.ux.updateApp(self.task_id, self.config.user, self.config.bundle_id);
        self.updated = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn rollbackUpdate(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.updated) return error.NoRollbackVersion;
        const rolled_back_result = try self.packages.rollback(self.package_authority, self.config.bundle_id);
        if (!rolled_back_result.updated_existing) return error.NoRollbackVersion;
        _ = try self.ux.rollbackAppUpdate(self.task_id, self.config.user, self.config.bundle_id);
        self.rolled_back = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn recoverSystem(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.runtime_service.restartFromCheckpoint(tick)) return error.RecoveryStateMissing;
        const recovered_response = self.compositor_service.dispatch(.{ .operation = .recover_state });
        if (recovered_response.status != .ok or !recovered_response.recovered) {
            return error.RecoveryStateMissing;
        }
        try self.ux.recoverSystem(self.task_id, self.config.user, "restored previous app and shell state");
        self.recovered = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn removeApp(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.installed or self.removed) return error.AppNotInstalled;
        const removed_result = try self.packages.remove(self.package_authority, self.config.bundle_id);
        if (!removed_result.removed_existing) return error.AppNotInstalled;
        if (self.task_id != 0) {
            const removed_task_id = self.task_id;
            _ = try self.runtime_service.runtimePtr().terminateTask(removed_task_id, tick);
            _ = try self.dispatchCompositor(.{
                .operation = .close_task_windows,
                .subject_task_id = removed_task_id,
            });
            self.task_id = 0;
            self.app_panel_window_id = 0;
            self.workspace_opened = false;
            self.document_opened = false;
            self.permission_reviewed = false;
            self.synced = false;
        }
        _ = try self.ux.removeApp(self.config.user, self.config.bundle_id);
        self.removed = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn revokeDevice(self: *ProductionJourneyService, tick: u64) !void {
        if (!self.device_trusted) return error.DeviceTrustRequired;
        try self.sync.revokeTrustedDevice(
            self.sync_authority,
            self.config.user,
            self.config.sync_to_device,
            self.config.user_signer,
            tick,
        );
        try self.ledger.recordDeviceTrustChange(
            self.config.admin,
            self.config.sync_to_device,
            false,
            tick,
            "device trust revoked",
        );
        self.device_revoked = true;
        self.device_trusted = false;
    }

    fn revokePolicy(self: *ProductionJourneyService, tick: u64) !void {
        if (self.policy_id == 0 or self.policy_revoked) return error.PolicyRequired;
        try self.policies.revokePolicy(self.policy_id);
        try self.ledger.recordPolicyChange(self.config.admin, self.policy_id, .revoked, tick, self.config.policy_label);
        self.policy_revoked = true;
    }

    fn requireTask(self: *ProductionJourneyService) !*task_runtime.TaskRecord {
        if (self.task_id == 0) return error.TaskRequired;
        return self.runtime_service.runtimePtr().find(self.task_id) orelse error.TaskRequired;
    }

    fn requireActivePolicy(self: *ProductionJourneyService) !*const policy_object.PolicyObject {
        if (self.policy_id == 0 or self.policy_revoked) return error.PolicyRequired;
        const active = self.policies.activeForScope(.organization, self.config.organization_id) orelse return error.PolicyRequired;
        if (active.id != self.policy_id or !self.policies.verify(active.id)) return error.PolicyDenied;
        return active;
    }

    fn permissionRequest(self: *const ProductionJourneyService) manifest.PermissionRequest {
        if (self.config.install_bundle.requested_permissions.len != 0) {
            return self.config.install_bundle.requested_permissions[0];
        }
        return .{
            .kind = .object_access,
            .resource = self.config.document_path,
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        };
    }

    fn dispatchCompositor(
        self: *ProductionJourneyService,
        request: compositor_session.ServiceRequest,
    ) !compositor_session.ServiceResponse {
        const response = self.compositor_service.dispatch(request);
        if (response.status != .ok) return error.CompositorRejected;
        return response;
    }

    fn ensureSyncPolicy(self: *ProductionJourneyService) !void {
        if (self.sync_configured) return;
        const local_policy = try self.sync.createNetworkPolicy(self.sync_authority, .{
            .owner = self.sync.service.owner,
            .workspace_id = self.config.workspace_id,
            .label = "production-journey-local",
            .mode = .local_network,
        });
        _ = try self.sync.configureWorkspacePolicy(self.sync_authority, .{
            .workspace_id = self.config.workspace_id,
            .owner = self.config.user,
            .offline_first = true,
            .personal_e2ee = true,
            .selective_prefixes = &.{"documents/"},
            .device_to_device_policy_id = local_policy.id,
        });
        self.sync_configured = true;
    }

    fn recordPendingTaskFlows(self: *ProductionJourneyService, tick: u64) !void {
        while (self.next_ledger_flow_order < self.ux.flow_count) : (self.next_ledger_flow_order += 1) {
            const flow = self.ux.flowAtOrder(self.next_ledger_flow_order) orelse return error.MissingTaskFlow;
            try self.ledger.recordTaskFlow(flow.*, tick);
        }
    }

    fn refreshResponse(self: *const ProductionJourneyService, response: *ProductionJourneyResponse) void {
        const session = self.compositor_service.session;
        response.task_id = self.task_id;
        response.active_window_id = session.active_window_id;
        response.visible_window_count = @intCast(session.visibleWindowCount());
        response.task_flow_events = @intCast(self.ledger.countMatching(.{ .kind = .task_flow }));
        response.policy_events = @intCast(self.ledger.countMatching(.{ .kind = .policy_change }));
        response.device_trust_events = @intCast(self.ledger.countMatching(.{ .kind = .device_trust_change }));
    }
};

fn statusForProductionJourneyError(err: anyerror) ProductionJourneyStatus {
    return switch (err) {
        error.PolicyRequired,
        error.PolicyAlreadyApplied,
        error.PolicyDenied,
        => .policy_rejected,
        error.AppAlreadyInstalled,
        error.AppNotInstalled,
        error.BundleNotFound,
        error.InstallSourceDenied,
        error.InvalidManifestSignature,
        error.UntrustedManifestSigner,
        error.PublisherKeyRevoked,
        error.NoRollbackVersion,
        error.PermissionChangeUndeclared,
        => .package_rejected,
        error.DeviceTrustRequired,
        error.SyncPolicyMissing,
        error.DeviceNotTrusted,
        error.WorkspacePolicyMissing,
        error.NetworkPolicyMissing,
        error.ReplicaTableFull,
        => .sync_rejected,
        error.TaskRequired,
        error.TaskAlreadyStarted,
        error.WorkspaceRequired,
        error.DocumentRequired,
        => .invalid_order,
        error.CompositorRejected => .compositor_rejected,
        error.RecoveryStateMissing => .recovery_missing,
        else => .invalid_request,
    };
}
