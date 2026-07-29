const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const manifest = @import("../../policy/manifest.zig");
const native_ux = @import("../native_ux.zig");
const storage_service = @import("../../storage/storage_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const model = @import("model.zig");
const rendering = @import("rendering.zig");
const task_launch = @import("task_launch.zig");

const appendFmt = rendering.appendFmt;
const Config = model.Config;
const Control = model.Control;

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

        const task = try task_launch.startConfiguredTask(self.ux, self.runtime, self.config);
        self.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *Shell, tick: u64) !void {
        const task = try self.requireTask();
        _ = try task_launch.openConfiguredWorkspace(self.ux, self.storage, self.config);
        _ = try self.compositor.openWorkspaceView(task, self.config.workspace_id, self.config.workspace_label);
        self.workspace_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openDocument(self: *Shell, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.workspace_opened) return error.WorkspaceRequired;
        _ = try task_launch.openConfiguredDocument(self.ux, self.storage, self.config, task.id);
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

    inline fn requireTask(self: *Shell) !*task_runtime.TaskRecord {
        return task_launch.requireTask(self.runtime, self.task_id);
    }

    inline fn recordPendingTaskFlows(self: *Shell, tick: u64) !void {
        return task_launch.recordPendingTaskFlows(self.ux, self.ledger, &self.next_ledger_flow_order, tick);
    }
};
