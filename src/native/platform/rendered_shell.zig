const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const compatibility_environment = @import("../services/compatibility_environment.zig");
const compositor_session = @import("compositor_session.zig");
const event_ledger = @import("event_ledger.zig");
const ids = @import("../core/ids.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const native_ux = @import("native_ux.zig");
const object_store = @import("../storage/object_store.zig");
const package_service = @import("../services/package_service.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const yesNo = native_util.yesNo;

pub const Control = enum {
    start_task,
    open_workspace,
    open_document,
    open_app_panel,
    focus_full_screen,
};

pub const JourneyControl = enum {
    install_app,
    start_task,
    open_workspace,
    open_document,
    open_app_panel,
    review_permission,
    sync_workspace,
    update_app,
    rollback_update,
    containment_denial,
    recover_system,
    remove_app,
};

pub const Config = struct {
    user: principal.PrincipalId,
    app_owner: principal.PrincipalId,
    reviewer_task_id: u64 = 0,
    workspace_id: u64,
    workspace_label: []const u8,
    document_path: []const u8,
    task_label: []const u8,
    task_entry: []const u8,
    task_title: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    ui_surface_id: u64,
    image_id: u64,
};

pub const JourneyConfig = struct {
    user: principal.PrincipalId,
    app_owner: principal.PrincipalId,
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
    install_bundle: manifest.BundleManifest,
    update_bundle: manifest.BundleManifest,
    ui_surface_id: u64,
    image_id: u64,
    sync_from_device: principal.PrincipalId,
    sync_to_device: principal.PrincipalId,
};

pub const Shell = struct {
    runtime: *task_runtime.Runtime,
    ux: *native_ux.Controller,
    compositor: *compositor_session.Session,
    storage: *storage_service.Service,
    ledger: *event_ledger.Ledger,
    config: Config,
    task_id: u64 = 0,
    workspace_opened: bool = false,
    document_opened: bool = false,
    app_panel_window_id: u64 = 0,
    full_screen_window_id: u64 = 0,
    next_ledger_flow_order: usize = 0,

    pub fn init(
        runtime: *task_runtime.Runtime,
        ux: *native_ux.Controller,
        compositor: *compositor_session.Session,
        storage: *storage_service.Service,
        ledger: *event_ledger.Ledger,
        config: Config,
    ) Shell {
        return .{
            .runtime = runtime,
            .ux = ux,
            .compositor = compositor,
            .storage = storage,
            .ledger = ledger,
            .config = config,
            .next_ledger_flow_order = ux.flow_count,
        };
    }

    pub fn click(self: *Shell, control: Control, tick: u64) !void {
        switch (control) {
            .start_task => try self.startTask(tick),
            .open_workspace => try self.openWorkspace(tick),
            .open_document => try self.openDocument(tick),
            .open_app_panel => try self.openAppPanel(tick),
            .focus_full_screen => try self.focusFullScreen(tick),
        }
    }

    pub fn render(self: *const Shell, buffer: []u8) ![]const u8 {
        var used: usize = 0;
        const active = if (self.compositor.active_window_id == 0)
            null
        else
            self.compositor.findWindowConst(self.compositor.active_window_id);
        const active_title = if (active) |window| window.titleSlice() else "none";
        const active_type = if (active) |window| @tagName(window.view_type) else "none";

        try appendFmt(buffer, &used, "Zigos rendered task shell\n", .{});
        try appendFmt(buffer, &used, "control=start-task state={s}\n", .{if (self.task_id == 0) "ready" else "done"});
        try appendFmt(buffer, &used, "control=open-workspace state={s}\n", .{if (self.workspace_opened) "done" else "ready"});
        try appendFmt(buffer, &used, "control=open-document state={s}\n", .{if (self.document_opened) "done" else "ready"});
        try appendFmt(buffer, &used, "control=open-app-panel state={s}\n", .{if (self.app_panel_window_id != 0) "done" else "ready"});
        try appendFmt(buffer, &used, "control=focus-full-screen state={s}\n", .{if (self.full_screen_window_id != 0) "done" else "ready"});
        try appendFmt(buffer, &used, "task={d} workspace={d} document={s}\n", .{
            self.task_id,
            self.config.workspace_id,
            self.config.document_path,
        });
        try appendFmt(buffer, &used, "active_window={d} active_type={s} active_title={s}\n", .{
            self.compositor.active_window_id,
            active_type,
            active_title,
        });
        try appendFmt(buffer, &used, "visible_windows={d} task_flow_events={d}\n", .{
            self.compositor.visibleWindowCount(),
            self.ledger.countMatching(.{ .kind = .task_flow }),
        });
        return buffer[0..used];
    }

    pub fn taskId(self: *const Shell) u64 {
        return self.task_id;
    }

    fn startTask(self: *Shell, tick: u64) !void {
        if (self.task_id != 0) return error.TaskAlreadyStarted;

        const image = task_runtime.syntheticUserspaceImage(self.config.task_label, self.config.task_entry);
        const task = try self.ux.startTask(self.runtime, .{
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

    fn openWorkspace(self: *Shell, tick: u64) !void {
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

    fn openDocument(self: *Shell, tick: u64) !void {
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

    fn openAppPanel(self: *Shell, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.workspace_opened) return error.WorkspaceRequired;
        if (!self.document_opened) return error.DocumentRequired;

        const bundle = manifest.BundleManifest{
            .bundle_id = self.config.bundle_id,
            .display_name = self.config.display_name,
            .publisher = "zigos.local",
        };
        const window = try self.compositor.beginPermissionReview(self.config.reviewer_task_id, task, bundle);
        _ = try self.compositor.ensureReviewItem(window.id, bundle, .{
            .kind = .object_access,
            .resource = self.config.document_path,
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        });
        _ = try self.ux.openAppPanel(task.id, self.config.workspace_id, self.config.user, self.config.bundle_id);
        self.app_panel_window_id = window.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn focusFullScreen(self: *Shell, tick: u64) !void {
        const task = try self.requireTask();
        if (self.app_panel_window_id == 0) return error.AppPanelRequired;

        const window = try self.compositor.openTaskView(task, self.config.task_title);
        _ = try self.compositor.switchView(window.id);
        _ = try self.ux.focusTask(task.id, self.config.user, self.config.task_title);
        self.full_screen_window_id = window.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn requireTask(self: *Shell) !*task_runtime.TaskRecord {
        if (self.task_id == 0) return error.TaskRequired;
        return self.runtime.find(self.task_id) orelse error.TaskRequired;
    }

    fn recordPendingTaskFlows(self: *Shell, tick: u64) !void {
        while (self.next_ledger_flow_order < self.ux.flow_count) : (self.next_ledger_flow_order += 1) {
            const flow = self.ux.flowAtOrder(self.next_ledger_flow_order) orelse return error.MissingTaskFlow;
            try self.ledger.recordTaskFlow(flow.*, tick);
        }
    }
};

pub const JourneySurface = struct {
    runtime: *task_runtime.Runtime,
    ux: *native_ux.Controller,
    compositor: *compositor_session.Session,
    storage: *storage_service.Service,
    packages: *package_service.PackagePort,
    package_authority: package_service.AuthorityContext,
    sync: *sync_service.SyncPort,
    sync_authority: sync_service.AuthorityContext,
    compatibility: *compatibility_environment.Manager,
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
        compatibility: *compatibility_environment.Manager,
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
            .compatibility = compatibility,
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
        const image = task_runtime.syntheticUserspaceImage(self.config.task_label, self.config.task_entry);
        const task = try self.ux.startTask(self.runtime, .{
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
        self.synced = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn updateApp(self: *JourneySurface, tick: u64) !void {
        const updated = try self.packages.install(self.package_authority, .{
            .bundle = self.config.update_bundle,
            .source_identity = self.config.source_identity,
            .data_schema_version = 1,
            .retains_data_compatibility = true,
        }, null);
        if (!updated.updated_existing or !updated.rollback_available) return error.AppNotInstalled;
        _ = try self.ux.updateApp(self.task_id, self.config.user, self.config.bundle_id);
        self.updated = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn rollbackUpdate(self: *JourneySurface, tick: u64) !void {
        const rolled_back = try self.packages.rollback(self.package_authority, self.config.bundle_id);
        if (!rolled_back.updated_existing) return error.NoRollbackVersion;
        _ = try self.ux.rollbackAppUpdate(self.task_id, self.config.user, self.config.bundle_id);
        self.rolled_back = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn containmentDenial(self: *JourneySurface, tick: u64) !void {
        if (self.compatibility.launch(.{
            .service_id = 900,
            .owner = self.config.user,
            .kind = .container,
            .label = "Legacy Trip Importer",
            .bundle = self.config.install_bundle,
            .portal_only_host_access = false,
        })) |_| {
            return error.ContainmentBypassAccepted;
        } else |err| switch (err) {
            error.DirectHostAccessForbidden => {},
            else => return err,
        }
        _ = try self.ux.containmentDenial(self.task_id, self.config.user, "direct host access blocked");
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
        const removed = try self.packages.remove(self.package_authority, self.config.bundle_id);
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

fn renderControl(buffer: []u8, used: *usize, name: []const u8, done: bool) !void {
    try appendFmt(buffer, used, "control={s} state={s}\n", .{ name, if (done) "done" else "ready" });
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return error.ExpectedSubstringMissing;
}

fn seedShellWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId, path: []const u8) !u64 {
    const signer_identity = signing.SignerIdentity{
        .label = "rendered-shell-object",
        .seed = [_]u8{0x9a} ** 32,
    };
    const document = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(92_001),
        .object_type = .document,
        .payload = "rendered shell document",
        .metadata = try object_store.signMetadata(
            signer_identity,
            "rendered shell document",
            "text/markdown",
            .document,
            "rendered shell document",
            10,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "rendered-shell",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, path, document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);
    return workspace_record.id.raw();
}

fn mintRenderedShellServiceAuthority(
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
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
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
}

fn shellConfig(user: principal.PrincipalId, workspace_id: u64, document_path: []const u8) Config {
    return .{
        .user = user,
        .app_owner = user,
        .reviewer_task_id = 71,
        .workspace_id = workspace_id,
        .workspace_label = "Rendered Shell Workspace",
        .document_path = document_path,
        .task_label = "trip-planner",
        .task_entry = "app.trip.ui",
        .task_title = "Plan Trip",
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .ui_surface_id = 88,
        .image_id = 92_001,
    };
}

test "rendered demo journey drives install sync permission update recovery and removal controls" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 94 };
    const package_owner = principal.PrincipalId{ .kind = .service, .serial = 95 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 96 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 94 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 941 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 942 };
    const document_path = "documents/plan.md";
    const bundle_signer = signing.SignerIdentity{
        .label = "rendered-journey-bundle",
        .seed = [_]u8{0x9c} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "rendered-journey-user",
        .seed = [_]u8{0x9d} ** 32,
    };
    const primary_signer = signing.SignerIdentity{
        .label = "rendered-journey-primary",
        .seed = [_]u8{0x9e} ** 32,
    };
    const paired_signer = signing.SignerIdentity{
        .label = "rendered-journey-paired",
        .seed = [_]u8{0x9f} ** 32,
    };

    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "trip-ui", .entry = "app.trip.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/theme.css", .content_type = "text/css" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "documents/plan.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 240,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v1_assets,
        .requested_permissions = &permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &v2_assets,
        .requested_permissions = &permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    var package_capabilities = capability.CapabilityTable.init();
    var packages_service = package_service.Service.init();
    packages_service.bind(9_500, package_owner);
    var package_port = package_service.PackagePort.init(&packages_service, &package_capabilities);
    const package_capability = try mintRenderedShellServiceAuthority(&package_capabilities, packages_service.service_id, package_owner, 9_501);
    const package_authority = package_service.AuthorityContext{
        .task_id = 9_501,
        .principal = package_owner,
        .capability_id = package_capability.id,
        .now_ticks = 10,
    };
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, [_]u8{0x5A} ** 32);
    _ = try package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 9_502 },
        .{ .kind = .policy_authority, .serial = 1 },
        "Example Software",
        try signing.publicKey(bundle_signer),
    );

    var storage = storage_service.Service.initWithStore(940, 941, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_510, 9_511, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintRenderedShellServiceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_capability.id,
        .now_ticks = 12,
    };
    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, primary_device, "laptop", user_signer, primary_signer, 12);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, paired_device, "tablet", user_signer, paired_signer, 13);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "trip-local",
        .mode = .local_network,
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{"documents/"},
        .device_to_device_policy_id = local_policy.id,
    });

    var runtime = task_runtime.Runtime.init();
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compatibility = compatibility_environment.Manager.init();
    var ledger = event_ledger.Ledger.init();
    var journey = JourneySurface.init(
        &runtime,
        &ux,
        &compositor,
        &storage,
        &package_port,
        package_authority,
        &sync_port,
        sync_authority,
        &compatibility,
        &ledger,
        .{
            .user = user,
            .app_owner = user,
            .reviewer_task_id = 77,
            .workspace_id = workspace_id,
            .workspace_label = "Trip Workspace",
            .document_path = document_path,
            .task_label = "trip-planner",
            .task_entry = "app.trip.ui",
            .task_title = "Plan Trip",
            .bundle_id = "app.trip",
            .display_name = "Trip Planner",
            .source_identity = "store:zigos",
            .install_bundle = v1,
            .update_bundle = v2,
            .ui_surface_id = 94,
            .image_id = 94_001,
            .sync_from_device = primary_device,
            .sync_to_device = paired_device,
        },
    );

    var render_buffer: [2048]u8 = undefined;
    const initial = try journey.render(&render_buffer);
    try expectContains(initial, "control=install-app state=ready");
    try expectContains(initial, "control=remove-app state=ready");

    try journey.click(.install_app, 20);
    try journey.click(.start_task, 21);
    try journey.click(.open_workspace, 22);
    try journey.click(.open_document, 23);
    try journey.click(.open_app_panel, 24);
    try journey.click(.review_permission, 25);
    try journey.click(.sync_workspace, 26);
    try journey.click(.update_app, 27);
    try journey.click(.rollback_update, 28);
    try journey.click(.containment_denial, 29);
    try journey.click(.recover_system, 30);
    try journey.click(.remove_app, 31);

    try std.testing.expect(packages_service.find("app.trip") == null);
    try std.testing.expectError(error.AppNotInstalled, journey.click(.start_task, 32));
    try std.testing.expectEqual(@as(usize, 12), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 3), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);

    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "package installed=yes updated=yes rolled_back=yes removed=yes");
    try expectContains(rendered, "task_flow_events=12");

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=install_app");
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=sync_workspace");
    try expectContains(exported, "flow_kind=update_app");
    try expectContains(exported, "flow_kind=rollback_app_update");
    try expectContains(exported, "flow_kind=containment_denial");
    try expectContains(exported, "flow_kind=recover_system");
    try expectContains(exported, "flow_kind=remove_app");
}

test "rendered task shell drives task workspace document panel and focus controls" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 92 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 92 };
    const document_path = "documents/plan.md";

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(920, 921, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var ledger = event_ledger.Ledger.init();
    var shell = Shell.init(&runtime, &ux, &compositor, &storage, &ledger, shellConfig(user, workspace_id, document_path));

    var render_buffer: [768]u8 = undefined;
    const initial = try shell.render(&render_buffer);
    try expectContains(initial, "control=start-task");
    try expectContains(initial, "task=0");

    try shell.click(.start_task, 20);
    try shell.click(.open_workspace, 21);
    try shell.click(.open_document, 22);
    try shell.click(.open_app_panel, 23);
    try shell.click(.focus_full_screen, 24);

    const task = runtime.find(shell.taskId()) orelse return error.TaskMissing;
    try std.testing.expect(task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 88), task.ui_surface_id);
    try std.testing.expectEqual(@as(usize, 4), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), compositor.item_count);
    try std.testing.expectEqual(compositor_session.ViewType.workspace_view, compositor.windowAtOrder(0).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.document_view, compositor.windowAtOrder(1).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, compositor.windowAtOrder(3).?.view_type);
    try std.testing.expectEqual(compositor.windowAtOrder(3).?.id, compositor.active_window_id);

    try std.testing.expectEqual(@as(usize, 5), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .task_flow, .task_id = task.id }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .task_flow, .workspace_id = workspace_id }));

    var export_buffer: [1024]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "flow_kind=start_task");
    try expectContains(exported, "flow_kind=open_workspace");
    try expectContains(exported, "flow_kind=open_document");
    try expectContains(exported, "flow_kind=open_app_panel");
    try expectContains(exported, "flow_kind=focus_task");

    const rendered = try shell.render(&render_buffer);
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Plan Trip");
    try expectContains(rendered, "task_flow_events=5");
}

test "rendered task shell rejects out-of-order or missing workspace interactions" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 93 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 93 };

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(930, 931, storage_owner, &storage_checkpoint_store);
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "empty-rendered-shell",
    });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var ledger = event_ledger.Ledger.init();
    var shell = Shell.init(&runtime, &ux, &compositor, &storage, &ledger, shellConfig(user, workspace_record.id.raw(), "documents/missing.md"));

    try std.testing.expectError(error.TaskRequired, shell.click(.open_workspace, 30));
    try std.testing.expectError(error.TaskRequired, shell.click(.focus_full_screen, 31));

    try shell.click(.start_task, 32);
    try std.testing.expectError(error.WorkspaceRequired, shell.click(.open_document, 33));
    try std.testing.expectError(error.EntryNotFound, shell.click(.open_workspace, 34));
    try std.testing.expectError(error.WorkspaceRequired, shell.click(.open_app_panel, 35));

    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .task_flow }));
}
