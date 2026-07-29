const compositor_session = @import("../compositor_session.zig");
const event_ledger = @import("../event_ledger.zig");
const native_ux = @import("../native_ux.zig");
const storage_service = @import("../../storage/storage_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const model = @import("model.zig");
const rendering = @import("rendering.zig");
const task_launch = @import("task_launch.zig");
const task_shell_wire = @import("task_shell_wire.zig");

const appendFmt = rendering.appendFmt;
const Config = model.Config;
const Control = model.Control;
const TaskShellRequest = task_shell_wire.TaskShellRequest;
const TaskShellResponse = task_shell_wire.TaskShellResponse;
const decodeTaskShellRequest = task_shell_wire.decodeRequest;
const encodeTaskShellResponse = task_shell_wire.encodeResponse;

pub const TaskShellState = struct {
    task_id: u64 = 0,
    workspace_opened: bool = false,
    document_opened: bool = false,
    app_panel_window_id: u64 = 0,
    full_screen_window_id: u64 = 0,
    next_ledger_flow_order: usize = 0,
};

pub const TaskShellCheckpointStore = struct {
    valid: bool = false,
    state: TaskShellState = .{},

    pub fn reset(self: *TaskShellCheckpointStore) void {
        self.* = .{};
    }
};

pub const TaskShellService = struct {
    runtime_service: *task_runtime_service.Service,
    ux: *native_ux.Controller,
    compositor_service: *compositor_session.Service,
    storage: *storage_service.Service,
    ledger: *event_ledger.Ledger,
    config: Config,
    checkpoint_store: *TaskShellCheckpointStore,
    state: TaskShellState = .{},

    pub fn init(
        runtime_service: *task_runtime_service.Service,
        ux: *native_ux.Controller,
        compositor_service: *compositor_session.Service,
        storage: *storage_service.Service,
        ledger: *event_ledger.Ledger,
        config: Config,
        checkpoint_store: *TaskShellCheckpointStore,
    ) TaskShellService {
        return .{
            .runtime_service = runtime_service,
            .ux = ux,
            .compositor_service = compositor_service,
            .storage = storage,
            .ledger = ledger,
            .config = config,
            .checkpoint_store = checkpoint_store,
            .state = .{ .next_ledger_flow_order = ux.flow_count },
        };
    }

    pub fn dispatch(self: *TaskShellService, request: TaskShellRequest) TaskShellResponse {
        var response = self.responseFor(request);
        self.apply(request, &response) catch |err| {
            response.status = task_shell_wire.statusForError(err);
        };
        self.refreshResponse(&response);
        return response;
    }

    pub fn dispatchPayload(self: *TaskShellService, payload: []const u8, out: []u8) ![]const u8 {
        const request = try decodeTaskShellRequest(payload);
        const response = self.dispatch(request);
        return encodeTaskShellResponse(out, response);
    }

    pub fn render(self: *const TaskShellService, buffer: []u8) ![]const u8 {
        const session = self.compositor_service.session;
        var used: usize = 0;
        const active = if (session.active_window_id == 0)
            null
        else
            session.findWindowConst(session.active_window_id);
        const active_title = if (active) |window| window.titleSlice() else "none";
        const active_type = if (active) |window| @tagName(window.view_type) else "none";

        try appendFmt(buffer, &used, "Zigos task shell service\n", .{});
        try appendFmt(buffer, &used, "control=start-task state={s}\n", .{if (self.state.task_id == 0) "ready" else "done"});
        try appendFmt(buffer, &used, "control=open-workspace state={s}\n", .{if (self.state.workspace_opened) "done" else "ready"});
        try appendFmt(buffer, &used, "control=open-document state={s}\n", .{if (self.state.document_opened) "done" else "ready"});
        try appendFmt(buffer, &used, "control=open-app-panel state={s}\n", .{if (self.state.app_panel_window_id != 0) "done" else "ready"});
        try appendFmt(buffer, &used, "control=focus-full-screen state={s}\n", .{if (self.state.full_screen_window_id != 0) "done" else "ready"});
        try appendFmt(buffer, &used, "task={d} workspace={d} document={s}\n", .{
            self.state.task_id,
            self.config.workspace_id,
            self.config.document_path,
        });
        try appendFmt(buffer, &used, "active_window={d} active_type={s} active_title={s}\n", .{
            session.active_window_id,
            active_type,
            active_title,
        });
        try appendFmt(buffer, &used, "visible_windows={d} task_flow_events={d}\n", .{
            session.visibleWindowCount(),
            self.ledger.countMatching(.{ .kind = .task_flow }),
        });
        return buffer[0..used];
    }

    fn apply(self: *TaskShellService, request: TaskShellRequest, response: *TaskShellResponse) !void {
        switch (request.operation) {
            .click => {
                try self.click(request.control, request.tick);
                self.runtime_service.checkpoint(request.tick);
                self.checkpoint();
            },
            .recover_state => try self.recover(request.tick, response),
        }
    }

    fn click(self: *TaskShellService, control: Control, tick: u64) !void {
        switch (control) {
            .start_task => try self.startTask(tick),
            .open_workspace => try self.openWorkspace(tick),
            .open_document => try self.openDocument(tick),
            .open_app_panel => try self.openAppPanel(tick),
            .focus_full_screen => try self.focusFullScreen(tick),
        }
    }

    fn startTask(self: *TaskShellService, tick: u64) !void {
        if (self.state.task_id != 0) return error.TaskAlreadyStarted;

        const task = try task_launch.startConfiguredTask(self.ux, self.runtime_service.runtimePtr(), self.config);
        self.state.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *TaskShellService, tick: u64) !void {
        const task = try self.requireTask();
        _ = try task_launch.openConfiguredWorkspace(self.ux, self.storage, self.config);
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .workspace_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = self.config.workspace_label,
        });
        self.state.workspace_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openDocument(self: *TaskShellService, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.state.workspace_opened) return error.WorkspaceRequired;
        _ = try task_launch.openConfiguredDocument(self.ux, self.storage, self.config, task.id);
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .document_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = self.config.document_path,
        });
        self.state.document_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openAppPanel(self: *TaskShellService, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.state.workspace_opened) return error.WorkspaceRequired;
        if (!self.state.document_opened) return error.DocumentRequired;

        const response = try self.dispatchCompositor(.{
            .operation = .review_permission,
            .subject_task_id = task.id,
            .reviewer_task_id = self.config.reviewer_task_id,
            .permission_kind = .object_access,
            .required = true,
            .local_only = true,
            .max_lease_ticks = 240,
            .bundle_id = self.config.bundle_id,
            .display_name = self.config.display_name,
            .resource = self.config.document_path,
        });
        _ = try self.ux.openAppPanel(task.id, self.config.workspace_id, self.config.user, self.config.bundle_id);
        self.state.app_panel_window_id = response.window_id;
        try self.recordPendingTaskFlows(tick);
    }

    fn focusFullScreen(self: *TaskShellService, tick: u64) !void {
        const task = try self.requireTask();
        if (self.state.app_panel_window_id == 0) return error.AppPanelRequired;

        const response = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .full_screen_task_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = self.config.task_title,
        });
        _ = try self.dispatchCompositor(.{
            .operation = .switch_view,
            .window_id = response.window_id,
        });
        _ = try self.ux.focusTask(task.id, self.config.user, self.config.task_title);
        self.state.full_screen_window_id = response.window_id;
        try self.recordPendingTaskFlows(tick);
    }

    inline fn requireTask(self: *TaskShellService) !*task_runtime.TaskRecord {
        return task_launch.requireTask(self.runtime_service.runtimePtr(), self.state.task_id);
    }

    fn dispatchCompositor(
        self: *TaskShellService,
        request: compositor_session.ServiceRequest,
    ) !compositor_session.ServiceResponse {
        const response = self.compositor_service.dispatch(request);
        if (response.status != .ok) return error.CompositorRejected;
        return response;
    }

    inline fn recordPendingTaskFlows(self: *TaskShellService, tick: u64) !void {
        return task_launch.recordPendingTaskFlows(self.ux, self.ledger, &self.state.next_ledger_flow_order, tick);
    }

    fn recover(self: *TaskShellService, tick: u64, response: *TaskShellResponse) !void {
        try task_launch.recoverCheckpointedTaskState(
            self.runtime_service,
            self.compositor_service,
            self.checkpoint_store,
            &self.state,
            tick,
        );
        response.recovered = true;
    }

    fn checkpoint(self: *TaskShellService) void {
        self.checkpoint_store.state = self.state;
        self.checkpoint_store.valid = true;
    }

    fn responseFor(self: *const TaskShellService, request: TaskShellRequest) TaskShellResponse {
        var response = TaskShellResponse{
            .operation = request.operation,
            .control = request.control,
        };
        self.refreshResponse(&response);
        return response;
    }

    fn refreshResponse(self: *const TaskShellService, response: *TaskShellResponse) void {
        const session = self.compositor_service.session;
        response.task_id = self.state.task_id;
        response.active_window_id = session.active_window_id;
        response.visible_window_count = @intCast(session.visibleWindowCount());
        response.task_flow_events = @intCast(self.ledger.countMatching(.{ .kind = .task_flow }));
    }
};
