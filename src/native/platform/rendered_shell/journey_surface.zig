const std = @import("std");
const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const ids = @import("../../core/ids.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const native_ux = @import("../native_ux.zig");
const package_service = @import("../../services/package_service.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const model = @import("model.zig");
const rendering = @import("rendering.zig");
const task_launch = @import("task_launch.zig");

const appendFmt = rendering.appendFmt;
const renderControl = rendering.renderControl;
const yesNo = native_util.yesNo;
const JourneyConfig = model.JourneyConfig;
const JourneyControl = model.JourneyControl;

pub const JourneySurface = struct {
    runtime: *task_runtime.Runtime,
    ux: *native_ux.Controller,
    compositor: *compositor_session.Session,
    storage: *storage_service.Service,
    packages: *package_service.PackagePort,
    package_authority: package_service.AuthorityContext,
    sync: *sync_service.SyncPort,
    sync_authority: sync_service.AuthorityContext,
    ledger: *event_ledger.Ledger,
    config: JourneyConfig,
    task_id: u64 = 0,
    app_panel_window_id: u64 = 0,
    installed: bool = false,
    workspace_opened: bool = false,
    document_opened: bool = false,
    permission_reviewed: bool = false,
    synced: bool = false,
    updated: bool = false,
    rolled_back: bool = false,
    containment_blocked: bool = false,
    recovered: bool = false,
    removed: bool = false,
    next_ledger_flow_order: usize = 0,
    permission_request: manifest.PermissionRequest = .{
        .kind = .object_access,
        .resource = "",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 240,
    },

    pub fn init(
        runtime: *task_runtime.Runtime,
        ux: *native_ux.Controller,
        compositor: *compositor_session.Session,
        storage: *storage_service.Service,
        packages: *package_service.PackagePort,
        package_authority: package_service.AuthorityContext,
        sync: *sync_service.SyncPort,
        sync_authority: sync_service.AuthorityContext,
        ledger: *event_ledger.Ledger,
        config: JourneyConfig,
    ) JourneySurface {
        var surface = JourneySurface{
            .runtime = runtime,
            .ux = ux,
            .compositor = compositor,
            .storage = storage,
            .packages = packages,
            .package_authority = package_authority,
            .sync = sync,
            .sync_authority = sync_authority,
            .ledger = ledger,
            .config = config,
            .next_ledger_flow_order = ux.flow_count,
        };
        surface.permission_request.resource = config.document_path;
        return surface;
    }

    pub fn click(self: *JourneySurface, control: JourneyControl, tick: u64) !void {
        switch (control) {
            .install_app => try self.installApp(tick),
            .start_task => try self.startTask(tick),
            .open_workspace => try self.openWorkspace(tick),
            .open_document => try self.openDocument(tick),
            .open_app_panel => try self.openAppPanel(tick),
            .review_permission => try self.reviewPermission(tick),
            .sync_workspace => try self.syncWorkspace(tick),
            .update_app => try self.updateApp(tick),
            .rollback_update => try self.rollbackUpdate(tick),
            .containment_denial => try self.containmentDenial(tick),
            .recover_system => try self.recoverSystem(tick),
            .remove_app => try self.removeApp(tick),
        }
    }

    pub fn render(self: *const JourneySurface, buffer: []u8) ![]const u8 {
        var used: usize = 0;
        try appendFmt(buffer, &used, "Zigos rendered demo journey\n", .{});
        try renderControl(buffer, &used, "install-app", self.installed);
        try renderControl(buffer, &used, "start-task", self.task_id != 0);
        try renderControl(buffer, &used, "open-workspace", self.workspace_opened);
        try renderControl(buffer, &used, "open-document", self.document_opened);
        try renderControl(buffer, &used, "open-app-panel", self.app_panel_window_id != 0);
        try renderControl(buffer, &used, "review-permission", self.permission_reviewed);
        try renderControl(buffer, &used, "sync-workspace", self.synced);
        try renderControl(buffer, &used, "update-app", self.updated);
        try renderControl(buffer, &used, "rollback-update", self.rolled_back);
        try renderControl(buffer, &used, "containment-denial", self.containment_blocked);
        try renderControl(buffer, &used, "recover-system", self.recovered);
        try renderControl(buffer, &used, "remove-app", self.removed);
        try appendFmt(buffer, &used, "task={d} bundle={s} workspace={d} document={s}\n", .{
            self.task_id,
            self.config.bundle_id,
            self.config.workspace_id,
            self.config.document_path,
        });
        try appendFmt(buffer, &used, "visible_windows={d} task_flow_events={d}\n", .{
            self.compositor.visibleWindowCount(),
            self.ledger.countMatching(.{ .kind = .task_flow }),
        });
        try appendFmt(buffer, &used, "package installed={s} updated={s} rolled_back={s} removed={s}\n", .{
            yesNo(self.installed),
            yesNo(self.updated),
            yesNo(self.rolled_back),
            yesNo(self.removed),
        });
        return buffer[0..used];
    }

    fn installApp(self: *JourneySurface, tick: u64) !void {
        if (self.installed) return error.AppAlreadyInstalled;
        const installed = try self.packages.install(self.package_authority, .{
            .bundle = self.config.install_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
        }, null);
        if (!installed.installed_new) return error.AppAlreadyInstalled;
        _ = try self.ux.installApp(self.config.user, self.config.bundle_id);
        self.installed = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn startTask(self: *JourneySurface, tick: u64) !void {
        if (!self.installed or self.removed) return error.AppNotInstalled;
        if (self.task_id != 0) return error.TaskAlreadyStarted;
        const task = try task_launch.startConfiguredTask(self.ux, self.runtime, self.config);
        self.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *JourneySurface, tick: u64) !void {
        const task = try self.requireTask();
        _ = try self.ux.openWorkspace(
            self.storage,
            ids.workspace(self.config.workspace_id),
            self.config.document_path,
            self.config.user,
        );
        _ = try self.compositor.openWorkspaceView(task, self.config.workspace_id, self.config.workspace_label);
        self.workspace_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openDocument(self: *JourneySurface, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.workspace_opened) return error.WorkspaceRequired;
        _ = try self.ux.openDocument(
            self.storage,
            ids.workspace(self.config.workspace_id),
            self.config.document_path,
            task.id,
            self.config.user,
        );
        _ = try self.compositor.openDocumentView(task, self.config.workspace_id, self.config.document_path);
        self.document_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openAppPanel(self: *JourneySurface, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.document_opened) return error.DocumentRequired;
        const window = try self.compositor.beginPermissionReview(
            self.config.reviewer_task_id,
            task,
            self.config.install_bundle,
        );
        _ = try self.compositor.ensureReviewItem(window.id, self.config.install_bundle, self.permission_request);
        _ = try self.ux.openAppPanel(task.id, self.config.workspace_id, self.config.user, self.config.bundle_id);
        self.app_panel_window_id = window.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn reviewPermission(self: *JourneySurface, tick: u64) !void {
        const task = try self.requireTask();
        if (self.app_panel_window_id == 0) return error.AppPanelRequired;
        _ = try self.compositor.recordDecision(
            self.app_panel_window_id,
            self.permission_request,
            true,
            true,
            self.permission_request.max_lease_ticks,
        );
        _ = try self.ux.reviewPermissionDecision(
            task.id,
            self.config.user,
            self.config.bundle_id,
            self.permission_request,
            true,
            true,
            self.permission_request.max_lease_ticks,
        );
        self.permission_reviewed = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn syncWorkspace(self: *JourneySurface, tick: u64) !void {
        const task = try self.requireTask();
        const summary = try self.sync.replicateWorkspace(
            self.sync_authority,
            self.storage,
            self.config.workspace_id,
            self.config.sync_from_device,
            self.config.sync_to_device,
            .device_to_device,
        );
        if (!summary.offline_first or !summary.personal_e2ee or !summary.used_device_to_device) return error.SyncPolicyMissing;
        _ = try self.ux.syncWorkspace(self.config.workspace_id, self.config.user, "device-to-device");
        if (summary.conflict_count != 0) {
            var detail_buffer: [compositor_session.MAX_WINDOW_DETAIL_BYTES]u8 = undefined;
            const detail = std.fmt.bufPrint(&detail_buffer, "sync conflicts: {d}", .{summary.conflict_count}) catch "sync conflicts";
            _ = try self.compositor.openSyncConflictReview(task, self.config.workspace_id, detail);
            _ = try self.ux.syncConflictReview(self.config.workspace_id, self.config.user, detail);
        }
        self.synced = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn updateApp(self: *JourneySurface, tick: u64) !void {
        const updated = try self.packages.install(self.package_authority, .{
            .bundle = self.config.update_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
        }, null);
        if (!updated.updated_existing or !updated.rollback_available) return error.AppNotInstalled;
        _ = try self.ux.updateApp(self.task_id, self.config.user, self.config.bundle_id);
        self.updated = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn rollbackUpdate(self: *JourneySurface, tick: u64) !void {
        const bundle = self.packages.service.find(self.config.bundle_id) orelse return error.AppNotInstalled;
        const rolled_back = try self.packages.rollback(
            self.package_authority,
            package_service.rollbackRequestForActive(bundle),
        );
        if (!rolled_back.updated_existing) return error.NoRollbackVersion;
        _ = try self.ux.rollbackAppUpdate(self.task_id, self.config.user, self.config.bundle_id);
        self.rolled_back = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn containmentDenial(self: *JourneySurface, tick: u64) !void {
        const untyped_components = [_]manifest.ExecutionComponentDecl{
            .{ .id = "trip-importer", .entry = "app.trip.importer", .abi = .native_sandbox },
        };
        var denied_bundle = self.config.install_bundle;
        denied_bundle.bundle_id = "app.trip.importer";
        denied_bundle.display_name = "Trip Importer";
        denied_bundle.components = &untyped_components;
        denied_bundle.signature = .{};
        if (self.packages.install(self.package_authority, .{
            .bundle = denied_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
        }, null)) |_| {
            return error.ContainmentBypassAccepted;
        } else |err| switch (err) {
            error.UntypedApplicationComponent => {},
            else => return err,
        }
        _ = try self.ux.containmentDenial(self.task_id, self.config.user, "untyped native component blocked");
        self.containment_blocked = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn recoverSystem(self: *JourneySurface, tick: u64) !void {
        try self.ux.recoverSystem(self.task_id, self.config.user, "restored previous trip planner version");
        self.recovered = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn removeApp(self: *JourneySurface, tick: u64) !void {
        if (!self.installed or self.removed) return error.AppNotInstalled;
        const bundle = self.packages.service.find(self.config.bundle_id) orelse return error.AppNotInstalled;
        const removed = try self.packages.remove(
            self.package_authority,
            package_service.removeRequestForActive(bundle),
        );
        if (!removed.removed_existing) return error.AppNotInstalled;
        _ = try self.ux.removeApp(self.config.user, self.config.bundle_id);
        self.removed = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn requireTask(self: *JourneySurface) !*task_runtime.TaskRecord {
        if (self.task_id == 0) return error.TaskRequired;
        return self.runtime.find(self.task_id) orelse error.TaskRequired;
    }

    fn recordPendingTaskFlows(self: *JourneySurface, tick: u64) !void {
        while (self.next_ledger_flow_order < self.ux.flow_count) : (self.next_ledger_flow_order += 1) {
            const flow = self.ux.flowAtOrder(self.next_ledger_flow_order) orelse return error.MissingTaskFlow;
            try self.ledger.recordTaskFlow(flow.*, tick);
        }
    }
};
