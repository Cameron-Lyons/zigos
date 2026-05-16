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
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
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

pub const TaskShellOperation = enum(u8) {
    click = 1,
    recover_state = 2,
};

pub const TaskShellStatus = enum(u8) {
    ok = 0,
    invalid_order = 1,
    not_found = 2,
    compositor_rejected = 3,
    recovery_missing = 4,
    invalid_request = 5,
    malformed_request = 6,
    request_too_large = 7,
    response_too_large = 8,
};

pub const TaskShellRequest = struct {
    operation: TaskShellOperation,
    control: Control = .start_task,
    tick: u64 = 0,
};

pub const TaskShellResponse = struct {
    operation: TaskShellOperation,
    control: Control,
    status: TaskShellStatus = .ok,
    recovered: bool = false,
    task_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    task_flow_events: u16 = 0,
};

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
            response.status = statusForTaskShellError(err);
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
        self.state.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *TaskShellService, tick: u64) !void {
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
        self.state.workspace_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn openDocument(self: *TaskShellService, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.state.workspace_opened) return error.WorkspaceRequired;
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

    fn requireTask(self: *TaskShellService) !*task_runtime.TaskRecord {
        if (self.state.task_id == 0) return error.TaskRequired;
        return self.runtime_service.runtimePtr().find(self.state.task_id) orelse error.TaskRequired;
    }

    fn dispatchCompositor(
        self: *TaskShellService,
        request: compositor_session.ServiceRequest,
    ) !compositor_session.ServiceResponse {
        const response = self.compositor_service.dispatch(request);
        if (response.status != .ok) return error.CompositorRejected;
        return response;
    }

    fn recordPendingTaskFlows(self: *TaskShellService, tick: u64) !void {
        while (self.state.next_ledger_flow_order < self.ux.flow_count) : (self.state.next_ledger_flow_order += 1) {
            const flow = self.ux.flowAtOrder(self.state.next_ledger_flow_order) orelse return error.MissingTaskFlow;
            try self.ledger.recordTaskFlow(flow.*, tick);
        }
    }

    fn recover(self: *TaskShellService, tick: u64, response: *TaskShellResponse) !void {
        if (!self.checkpoint_store.valid) return error.RecoveryStateMissing;
        if (!self.runtime_service.restartFromCheckpoint(tick)) return error.RecoveryStateMissing;
        const compositor_recovered = self.compositor_service.dispatch(.{ .operation = .recover_state });
        if (compositor_recovered.status != .ok or !compositor_recovered.recovered) return error.RecoveryStateMissing;
        self.state = self.checkpoint_store.state;
        if (self.state.task_id != 0 and self.runtime_service.runtimePtr().find(self.state.task_id) == null) {
            return error.RecoveryStateMissing;
        }
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

const TASK_SHELL_MAGIC_REQUEST = [_]u8{ 'Z', 'S', 'H', '1' };
const TASK_SHELL_MAGIC_RESPONSE = [_]u8{ 'Z', 'S', 'R', '1' };

pub fn encodeTaskShellRequest(buffer: []u8, request: TaskShellRequest) ![]const u8 {
    var used: usize = 0;
    try shellWriteBytes(buffer, &used, &TASK_SHELL_MAGIC_REQUEST);
    try shellWriteByte(buffer, &used, @intFromEnum(request.operation));
    try shellWriteByte(buffer, &used, @intFromEnum(request.control));
    try shellWriteU64(buffer, &used, request.tick);
    return buffer[0..used];
}

pub fn decodeTaskShellRequest(payload: []const u8) !TaskShellRequest {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try shellReadBytes(payload, &cursor, 4), &TASK_SHELL_MAGIC_REQUEST)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try shellReadByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(Control, try shellReadByte(payload, &cursor)) orelse return error.MalformedRequest;
    const tick = try shellReadU64(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .tick = tick,
    };
}

pub fn encodeTaskShellResponse(buffer: []u8, response: TaskShellResponse) ![]const u8 {
    var used: usize = 0;
    try shellWriteBytes(buffer, &used, &TASK_SHELL_MAGIC_RESPONSE);
    try shellWriteByte(buffer, &used, @intFromEnum(response.operation));
    try shellWriteByte(buffer, &used, @intFromEnum(response.control));
    try shellWriteByte(buffer, &used, @intFromEnum(response.status));
    try shellWriteByte(buffer, &used, if (response.recovered) 1 else 0);
    try shellWriteU64(buffer, &used, response.task_id);
    try shellWriteU64(buffer, &used, response.active_window_id);
    try shellWriteU16(buffer, &used, response.visible_window_count);
    try shellWriteU16(buffer, &used, response.task_flow_events);
    return buffer[0..used];
}

pub fn decodeTaskShellResponse(payload: []const u8) !TaskShellResponse {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try shellReadBytes(payload, &cursor, 4), &TASK_SHELL_MAGIC_RESPONSE)) return error.MalformedRequest;
    const operation = std.enums.fromInt(TaskShellOperation, try shellReadByte(payload, &cursor)) orelse return error.MalformedRequest;
    const control = std.enums.fromInt(Control, try shellReadByte(payload, &cursor)) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(TaskShellStatus, try shellReadByte(payload, &cursor)) orelse return error.MalformedRequest;
    const recovered = (try shellReadByte(payload, &cursor)) != 0;
    const task_id = try shellReadU64(payload, &cursor);
    const active_window_id = try shellReadU64(payload, &cursor);
    const visible_window_count = try shellReadU16(payload, &cursor);
    const task_flow_events = try shellReadU16(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .control = control,
        .status = status,
        .recovered = recovered,
        .task_id = task_id,
        .active_window_id = active_window_id,
        .visible_window_count = visible_window_count,
        .task_flow_events = task_flow_events,
    };
}

fn statusForTaskShellError(err: anyerror) TaskShellStatus {
    return switch (err) {
        error.TaskRequired,
        error.TaskAlreadyStarted,
        error.WorkspaceRequired,
        error.DocumentRequired,
        error.AppPanelRequired,
        => .invalid_order,
        error.EntryNotFound,
        error.TaskNotFound,
        => .not_found,
        error.CompositorRejected => .compositor_rejected,
        error.RecoveryStateMissing => .recovery_missing,
        error.MalformedRequest => .malformed_request,
        error.RequestTooLarge => .request_too_large,
        error.ResponseTooLarge => .response_too_large,
        else => .invalid_request,
    };
}

fn shellWriteByte(buffer: []u8, used: *usize, value: u8) !void {
    if (used.* + 1 > buffer.len) return error.RequestTooLarge;
    buffer[used.*] = value;
    used.* += 1;
}

fn shellWriteBytes(buffer: []u8, used: *usize, bytes: []const u8) !void {
    if (used.* + bytes.len > buffer.len) return error.RequestTooLarge;
    @memcpy(buffer[used.* .. used.* + bytes.len], bytes);
    used.* += bytes.len;
}

fn shellWriteU16(buffer: []u8, used: *usize, value: u16) !void {
    if (used.* + 2 > buffer.len) return error.ResponseTooLarge;
    std.mem.writeInt(u16, buffer[used.*..][0..2], value, .little);
    used.* += 2;
}

fn shellWriteU64(buffer: []u8, used: *usize, value: u64) !void {
    if (used.* + 8 > buffer.len) return error.RequestTooLarge;
    std.mem.writeInt(u64, buffer[used.*..][0..8], value, .little);
    used.* += 8;
}

fn shellReadByte(buffer: []const u8, cursor: *usize) !u8 {
    if (cursor.* + 1 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 1;
    return buffer[cursor.*];
}

fn shellReadBytes(buffer: []const u8, cursor: *usize, len: usize) ![]const u8 {
    if (cursor.* + len > buffer.len) return error.MalformedRequest;
    defer cursor.* += len;
    return buffer[cursor.* .. cursor.* + len];
}

fn shellReadU16(buffer: []const u8, cursor: *usize) !u16 {
    if (cursor.* + 2 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 2;
    return std.mem.readInt(u16, buffer[cursor.*..][0..2], .little);
}

fn shellReadU64(buffer: []const u8, cursor: *usize) !u64 {
    if (cursor.* + 8 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 8;
    return std.mem.readInt(u64, buffer[cursor.*..][0..8], .little);
}

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

fn dispatchTaskShellForTest(
    service: *TaskShellService,
    operation: TaskShellOperation,
    control: Control,
    tick: u64,
) !TaskShellResponse {
    var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const payload = try encodeTaskShellRequest(&request_buffer, .{
        .operation = operation,
        .control = control,
        .tick = tick,
    });
    return decodeTaskShellResponse(try service.dispatchPayload(payload, &response_buffer));
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

test "production journey service rejects premature controls then routes lifecycle policy device trust and recovery through service ports" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 97 };
    const package_owner = principal.PrincipalId{ .kind = .service, .serial = 98 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 99 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 97 };
    const admin = principal.PrincipalId{ .kind = .policy_authority, .serial = 97 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 971 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 972 };
    const document_path = "documents/plan.md";
    const bundle_signer = signing.SignerIdentity{
        .label = "production-journey-bundle",
        .seed = [_]u8{0xa1} ** 32,
    };
    const policy_signer = signing.SignerIdentity{
        .label = "production-journey-policy",
        .seed = [_]u8{0xa2} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "production-journey-user",
        .seed = [_]u8{0xa3} ** 32,
    };
    const primary_signer = signing.SignerIdentity{
        .label = "production-journey-primary",
        .seed = [_]u8{0xa4} ** 32,
    };
    const paired_signer = signing.SignerIdentity{
        .label = "production-journey-paired",
        .seed = [_]u8{0xa5} ** 32,
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
        .bundle_id = "app.trip.production",
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
        .bundle_id = "app.trip.production",
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
    packages_service.bind(9_700, package_owner);
    var package_port = package_service.PackagePort.init(&packages_service, &package_capabilities);
    const package_capability = try mintRenderedShellServiceAuthority(&package_capabilities, packages_service.service_id, package_owner, 9_701);
    const package_authority = package_service.AuthorityContext{
        .task_id = 9_701,
        .principal = package_owner,
        .capability_id = package_capability.id,
        .now_ticks = 10,
    };
    _ = try package_port.trustPolicyAuthorityRoot(package_authority, .{ .kind = .policy_authority, .serial = 1 }, [_]u8{0x5A} ** 32);
    _ = try package_port.trustPublisher(
        package_authority,
        .{ .kind = .app, .serial = 9_702 },
        .{ .kind = .policy_authority, .serial = 1 },
        "Example Software",
        try signing.publicKey(bundle_signer),
    );

    var storage = storage_service.Service.initWithStore(970, 971, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);

    var sync = sync_service.Service.init(9_710, 9_711, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_capability = try mintRenderedShellServiceAuthority(&sync_capabilities, sync.service_id, sync_owner, sync.task_id);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_capability.id,
        .now_ticks = 12,
    };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_720, .{ .kind = .service, .serial = 9_720 });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        9_721,
        9_722,
        &runtime,
        &compositor,
        &compositor_checkpoint_store,
    );
    var policies = policy_object.Directory.init();
    var ledger = event_ledger.Ledger.init();
    var journey = ProductionJourneyService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &package_port,
        package_authority,
        &sync_port,
        sync_authority,
        &policies,
        &ledger,
        .{
            .user = user,
            .admin = admin,
            .app_owner = user,
            .organization_id = 97,
            .reviewer_task_id = 78,
            .workspace_id = workspace_id,
            .workspace_label = "Trip Workspace",
            .document_path = document_path,
            .task_label = "trip-planner",
            .task_entry = "app.trip.ui",
            .task_title = "Plan Trip",
            .bundle_id = "app.trip.production",
            .display_name = "Trip Planner",
            .source_identity = "store:zigos",
            .sync_destination = "relay.production.zigos",
            .device_label = "tablet",
            .policy_label = "production-journey-defaults",
            .install_bundle = v1,
            .update_bundle = v2,
            .ui_surface_id = 97,
            .image_id = 97_001,
            .sync_from_device = primary_device,
            .sync_to_device = paired_device,
            .policy_signer = policy_signer,
            .user_signer = user_signer,
            .primary_device_signer = primary_signer,
            .paired_device_signer = paired_signer,
        },
    );

    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .install_app, .tick = 19 }).status,
    );
    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .sync_workspace, .tick = 19 }).status,
    );

    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .apply_policy, .tick = 20 }).status);
    try std.testing.expect(policies.activeForScope(.organization, 97) != null);
    try std.testing.expectEqual(ProductionJourneyStatus.package_rejected, journey.dispatch(.{ .control = .start_task, .tick = 20 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.sync_rejected, journey.dispatch(.{ .control = .sync_workspace, .tick = 20 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .trust_device, .tick = 21 }).status);
    try std.testing.expect(sync.isTrustedDevice(primary_device));
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .install_app, .tick = 22 }).status);
    const start_response = journey.dispatch(.{ .control = .start_task, .tick = 23 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, start_response.status);
    const started_task_id = start_response.task_id;
    try std.testing.expect(started_task_id != 0);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_workspace, .tick = 24 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .open_document, .tick = 25 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .review_permission, .tick = 26 }).status);
    try std.testing.expectEqual(@as(usize, 3), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, compositor.windowAtOrder(2).?.view_type);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .sync_workspace, .tick = 27 }).status);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .update_app, .tick = 28 }).status);
    try std.testing.expectEqual(@as(u16, 1), packages_service.find("app.trip.production").?.versionMinor());
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .rollback_update, .tick = 29 }).status);
    try std.testing.expectEqual(@as(u16, 0), packages_service.find("app.trip.production").?.versionMinor());
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .recover_system, .tick = 30 }).status);
    const remove_response = journey.dispatch(.{ .control = .remove_app, .tick = 31 });
    try std.testing.expectEqual(ProductionJourneyStatus.ok, remove_response.status);
    try std.testing.expectEqual(@as(u64, 0), remove_response.task_id);
    try std.testing.expectEqual(@as(u16, 0), remove_response.visible_window_count);
    try std.testing.expect(packages_service.find("app.trip.production") == null);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, runtime.find(started_task_id).?.state);
    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 0), compositor.item_count);
    try std.testing.expectEqual(@as(u64, 0), compositor.active_window_id);
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_device, .tick = 32 }).status);
    try std.testing.expect(!sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(ProductionJourneyStatus.ok, journey.dispatch(.{ .control = .revoke_policy, .tick = 33 }).status);
    try std.testing.expectEqual(
        ProductionJourneyStatus.policy_rejected,
        journey.dispatch(.{ .control = .install_app, .tick = 34 }).status,
    );

    try std.testing.expectEqual(@as(usize, 11), ledger.countMatching(.{ .kind = .task_flow }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .policy_change }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .kind = .device_trust_change }));
    try std.testing.expect(runtime_checkpoint_store.has_checkpoint);
    try std.testing.expect(compositor_checkpoint_store.valid);

    var render_buffer: [2048]u8 = undefined;
    const rendered = try journey.render(&render_buffer);
    try expectContains(rendered, "control=apply-policy state=done");
    try expectContains(rendered, "control=remove-app state=done");
    try expectContains(rendered, "control=revoke-policy state=done");
    try expectContains(rendered, "task=0 bundle=app.trip.production");
    try expectContains(rendered, "visible_windows=0");
    try expectContains(rendered, "task_flow_events=11");

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try expectContains(exported, "kind=policy_change");
    try expectContains(exported, "kind=device_trust_change");
    try expectContains(exported, "flow_kind=review_permission_request");
    try expectContains(exported, "flow_kind=recover_system");
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

test "task shell service routes controls through compositor service and recovers persistent task state" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 95 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 95 };
    const document_path = "documents/plan.md";

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_600, .{ .kind = .service, .serial = 9_600 });

    var storage = storage_service.Service.initWithStore(950, 951, storage_owner, &storage_checkpoint_store);
    const workspace_id = try seedShellWorkspace(&storage, user, document_path);
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(9_601, 9_602, &runtime, &compositor, &compositor_checkpoint_store);
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = TaskShellCheckpointStore{};
    const config = shellConfig(user, workspace_id, document_path);
    var shell_service = TaskShellService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &ledger,
        config,
        &shell_checkpoint_store,
    );

    const start = try dispatchTaskShellForTest(&shell_service, .click, .start_task, 40);
    try std.testing.expectEqual(TaskShellStatus.ok, start.status);
    const workspace_response = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 41);
    try std.testing.expectEqual(TaskShellStatus.ok, workspace_response.status);
    const document_response = try dispatchTaskShellForTest(&shell_service, .click, .open_document, 42);
    try std.testing.expectEqual(TaskShellStatus.ok, document_response.status);
    const panel_response = try dispatchTaskShellForTest(&shell_service, .click, .open_app_panel, 43);
    try std.testing.expectEqual(TaskShellStatus.ok, panel_response.status);
    const focus_response = try dispatchTaskShellForTest(&shell_service, .click, .focus_full_screen, 44);
    try std.testing.expectEqual(TaskShellStatus.ok, focus_response.status);

    const task_id = focus_response.task_id;
    try std.testing.expect(task_id != 0);
    try std.testing.expect(runtime_checkpoint_store.has_checkpoint);
    try std.testing.expect(compositor_checkpoint_store.valid);
    try std.testing.expect(shell_checkpoint_store.valid);
    try std.testing.expectEqual(@as(u16, 4), focus_response.visible_window_count);
    try std.testing.expectEqual(@as(u16, 5), focus_response.task_flow_events);
    try std.testing.expectEqual(@as(usize, 4), compositor.window_count);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, compositor.windowAtOrder(3).?.view_type);
    try std.testing.expectEqual(compositor.windowAtOrder(3).?.id, compositor.active_window_id);

    var restarted_runtime = task_runtime.Runtime.init();
    var restarted_runtime_service = task_runtime_service.Service.initWithStore(&restarted_runtime, &runtime_checkpoint_store);
    restarted_runtime_service.bind(9_600, .{ .kind = .service, .serial = 9_600 });
    var restarted_compositor = compositor_session.Session.init();
    var restarted_compositor_service = compositor_session.Service.initWithCheckpoint(
        9_601,
        9_602,
        &restarted_runtime,
        &restarted_compositor,
        &compositor_checkpoint_store,
    );
    var restarted_shell_service = TaskShellService.init(
        &restarted_runtime_service,
        &ux,
        &restarted_compositor_service,
        &storage,
        &ledger,
        config,
        &shell_checkpoint_store,
    );
    const recovered = try dispatchTaskShellForTest(&restarted_shell_service, .recover_state, .start_task, 50);
    try std.testing.expectEqual(TaskShellStatus.ok, recovered.status);
    try std.testing.expect(recovered.recovered);
    try std.testing.expectEqual(task_id, recovered.task_id);
    try std.testing.expect(restarted_runtime.find(task_id) != null);
    try std.testing.expectEqual(@as(usize, 4), restarted_compositor.window_count);
    try std.testing.expectEqual(restarted_compositor.windowAtOrder(3).?.id, restarted_compositor.active_window_id);

    var render_buffer: [768]u8 = undefined;
    const rendered = try restarted_shell_service.render(&render_buffer);
    try expectContains(rendered, "control=focus-full-screen state=done");
    try expectContains(rendered, "active_type=full_screen_task_view");
    try expectContains(rendered, "active_title=Task: Plan Trip");
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

test "task shell service rejects out-of-order controls before creating compositor state" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 96 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 96 };

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(9_700, .{ .kind = .service, .serial = 9_700 });

    var storage = storage_service.Service.initWithStore(960, 961, storage_owner, &storage_checkpoint_store);
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "empty-service-shell",
    });
    var ux = native_ux.Controller.init();
    var compositor = compositor_session.Session.init();
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(9_701, 9_702, &runtime, &compositor, &compositor_checkpoint_store);
    var ledger = event_ledger.Ledger.init();
    var shell_checkpoint_store = TaskShellCheckpointStore{};
    var shell_service = TaskShellService.init(
        &runtime_service,
        &ux,
        &compositor_service,
        &storage,
        &ledger,
        shellConfig(user, workspace_record.id.raw(), "documents/missing.md"),
        &shell_checkpoint_store,
    );

    const missing_task = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 60);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, missing_task.status);
    try std.testing.expect(!shell_checkpoint_store.valid);

    const start = try dispatchTaskShellForTest(&shell_service, .click, .start_task, 61);
    try std.testing.expectEqual(TaskShellStatus.ok, start.status);
    const document_before_workspace = try dispatchTaskShellForTest(&shell_service, .click, .open_document, 62);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, document_before_workspace.status);
    const missing_workspace_entry = try dispatchTaskShellForTest(&shell_service, .click, .open_workspace, 63);
    try std.testing.expectEqual(TaskShellStatus.not_found, missing_workspace_entry.status);
    const panel_before_document = try dispatchTaskShellForTest(&shell_service, .click, .open_app_panel, 64);
    try std.testing.expectEqual(TaskShellStatus.invalid_order, panel_before_document.status);

    try std.testing.expectEqual(@as(usize, 0), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .task_flow }));
}
