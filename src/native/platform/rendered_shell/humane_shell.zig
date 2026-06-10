const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const compositor_session = @import("../compositor_session.zig");
const denial_explanation = @import("../../policy/denial_explanation.zig");
const event_ledger = @import("../event_ledger.zig");
const ids = @import("../../core/ids.zig");
const manifest = @import("../../policy/manifest.zig");
const native_util = @import("../../core/util.zig");
const native_ux = @import("../native_ux.zig");
const notification_center = @import("../../services/notification_center.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const storage_service = @import("../../storage/storage_service.zig");
const sync_service = @import("../../sync/sync_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const workspace = @import("../../storage/workspace.zig");
const rendering = @import("rendering.zig");
const task_launch = @import("task_launch.zig");

const appendFmt = rendering.appendFmt;
const yesNo = native_util.yesNo;

pub const MAX_SHELL_OBJECT_RESULTS: usize = 4;
pub const MAX_SHELL_OBJECT_HISTORY: usize = 4;

pub const HumaneShellControl = enum(u8) {
    start_task,
    open_workspace,
    open_document,
    query_objects,
    open_object,
    show_object_history,
    mint_object_capability,
    share_object,
    review_object_conflict,
    review_permission,
    allow_permission,
    deny_permission,
    pair_device,
    create_snapshot,
    rollback_snapshot,
    run_diagnostics,
    post_notification,
    recover_state,
    focus_next,
    focus_previous,
};

pub const KeyboardIntent = enum(u8) {
    next,
    previous,
    activate,
};

pub const HumaneShellOperation = enum(u8) {
    click,
    keyboard,
};

pub const ControlState = enum(u8) {
    ready,
    done,
    blocked,
};

pub const ControlGuidance = struct {
    control: HumaneShellControl,
    state: ControlState,
    label: []const u8,
    shortcut: []const u8,
    blocked_reason: []const u8 = "none",
    next_action: []const u8 = "none",
};

pub const HumaneShellStatus = enum(u8) {
    ok,
    invalid_order,
    not_found,
    permission_rejected,
    sync_rejected,
    compositor_rejected,
    diagnostics_rejected,
    recovery_missing,
    invalid_request,
};

pub const HumaneShellRequest = struct {
    operation: HumaneShellOperation = .click,
    control: HumaneShellControl = .start_task,
    keyboard: KeyboardIntent = .activate,
    tick: u64 = 0,
};

pub const HumaneShellResponse = struct {
    operation: HumaneShellOperation,
    control: HumaneShellControl,
    status: HumaneShellStatus = .ok,
    task_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    task_flow_events: u16 = 0,
    notification_events: u16 = 0,
    focused_control: HumaneShellControl = .start_task,
    permission_reviewed: bool = false,
    permission_denied: bool = false,
    snapshot_id: u64 = 0,
    recovered: bool = false,
    selected_object_id: u64 = 0,
    object_query_count: u16 = 0,
    object_history_count: u16 = 0,
    object_capability_id: u64 = 0,
    object_shared: bool = false,
    object_conflict_reviewed: bool = false,
    object_conflict_resolved: bool = false,
};

pub const AccessibilityProfile = struct {
    keyboard_navigation: bool = true,
    screen_reader_labels: bool = true,
    visible_focus: bool = true,
    reduce_motion: bool = true,
    high_contrast: bool = false,
};

pub const HumaneShellConfig = struct {
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
    object_query_label: []const u8 = "",
    object_share_principal: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    object_conflict_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    object_capability_table: ?*capability.CapabilityTable = null,
    permission_request: manifest.PermissionRequest = .{
        .kind = .object_access,
        .resource = "",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 240,
    },
    paired_device: principal.PrincipalId,
    device_label: []const u8,
    user_signer: signing.SignerIdentity,
    device_signer: signing.SignerIdentity,
    snapshot_label: []const u8 = "humane-shell-snapshot",
    snapshot_signer: signing.SignerIdentity,
};

pub const HumaneShellState = struct {
    task_id: u64 = 0,
    workspace_opened: bool = false,
    document_opened: bool = false,
    review_window_id: u64 = 0,
    permission_reviewed: bool = false,
    permission_denied: bool = false,
    device_paired: bool = false,
    snapshot_id: u64 = 0,
    snapshot_restored: bool = false,
    diagnostics_ran: bool = false,
    diagnostics_event_count: usize = 0,
    notification_id: u64 = 0,
    recovered: bool = false,
    object_query_count: u16 = 0,
    object_query_ids: [MAX_SHELL_OBJECT_RESULTS]u64 = [_]u64{0} ** MAX_SHELL_OBJECT_RESULTS,
    selected_object_id: u64 = 0,
    selected_version_id: u64 = 0,
    object_opened: bool = false,
    object_history_count: u16 = 0,
    object_history_versions: [MAX_SHELL_OBJECT_HISTORY]u64 = [_]u64{0} ** MAX_SHELL_OBJECT_HISTORY,
    object_capability_id: u64 = 0,
    object_shared: bool = false,
    object_conflict_reviewed: bool = false,
    object_conflict_resolved: bool = false,
    object_conflict_local_version_id: u64 = 0,
    object_conflict_remote_version_id: u64 = 0,
    remote_diagnostics_require_opt_in: bool = true,
    focus_index: usize = 0,
    last_tick: u64 = 0,
    next_ledger_flow_order: usize = 0,
    last_denial: denial_explanation.Explanation = .{},
};

pub const HumaneShellCheckpointStore = struct {
    valid: bool = false,
    state: HumaneShellState = .{},

    pub fn reset(self: *HumaneShellCheckpointStore) void {
        self.* = .{};
    }
};

pub const control_order = [_]HumaneShellControl{
    .start_task,
    .open_workspace,
    .open_document,
    .query_objects,
    .open_object,
    .show_object_history,
    .mint_object_capability,
    .share_object,
    .review_object_conflict,
    .review_permission,
    .allow_permission,
    .deny_permission,
    .pair_device,
    .create_snapshot,
    .rollback_snapshot,
    .run_diagnostics,
    .post_notification,
    .recover_state,
};

pub const HumaneShell = struct {
    runtime_service: *task_runtime_service.Service,
    ux: *native_ux.Controller,
    compositor_service: *compositor_session.Service,
    storage: *storage_service.Service,
    sync: *sync_service.SyncPort,
    sync_authority: sync_service.AuthorityContext,
    notifications: *notification_center.Center,
    ledger: *event_ledger.Ledger,
    config: HumaneShellConfig,
    accessibility: AccessibilityProfile,
    checkpoint_store: *HumaneShellCheckpointStore,
    state: HumaneShellState = .{},

    pub fn init(
        runtime_service: *task_runtime_service.Service,
        ux: *native_ux.Controller,
        compositor_service: *compositor_session.Service,
        storage: *storage_service.Service,
        sync: *sync_service.SyncPort,
        sync_authority: sync_service.AuthorityContext,
        notifications: *notification_center.Center,
        ledger: *event_ledger.Ledger,
        config: HumaneShellConfig,
        accessibility: AccessibilityProfile,
        checkpoint_store: *HumaneShellCheckpointStore,
    ) HumaneShell {
        return .{
            .runtime_service = runtime_service,
            .ux = ux,
            .compositor_service = compositor_service,
            .storage = storage,
            .sync = sync,
            .sync_authority = sync_authority,
            .notifications = notifications,
            .ledger = ledger,
            .config = config,
            .accessibility = accessibility,
            .checkpoint_store = checkpoint_store,
            .state = .{ .next_ledger_flow_order = ux.flow_count },
        };
    }

    pub fn dispatch(self: *HumaneShell, request: HumaneShellRequest) HumaneShellResponse {
        var response = HumaneShellResponse{
            .operation = request.operation,
            .control = request.control,
        };
        switch (request.operation) {
            .click => self.click(request.control, request.tick) catch |err| {
                response.status = statusForError(err);
            },
            .keyboard => self.handleKeyboard(request.keyboard, request.tick) catch |err| {
                response.status = statusForError(err);
            },
        }
        self.refreshResponse(&response);
        return response;
    }

    pub fn click(self: *HumaneShell, control: HumaneShellControl, tick: u64) !void {
        self.state.last_tick = tick;
        switch (control) {
            .start_task => try self.startTask(tick),
            .open_workspace => try self.openWorkspace(tick),
            .open_document => try self.openDocument(tick),
            .query_objects => try self.queryObjects(),
            .open_object => try self.openObject(tick),
            .show_object_history => try self.showObjectHistory(),
            .mint_object_capability => try self.mintObjectCapability(tick),
            .share_object => try self.shareObject(),
            .review_object_conflict => try self.reviewObjectConflict(tick),
            .review_permission => try self.reviewPermission(tick),
            .allow_permission => try self.decidePermission(true, tick),
            .deny_permission => try self.decidePermission(false, tick),
            .pair_device => try self.pairDevice(tick),
            .create_snapshot => try self.createSnapshot(),
            .rollback_snapshot => try self.rollbackSnapshot(tick),
            .run_diagnostics => try self.runDiagnostics(tick),
            .post_notification => try self.postShellNotification(tick, "shell status available"),
            .recover_state => try self.recoverState(tick),
            .focus_next => self.focusNext(),
            .focus_previous => self.focusPrevious(),
        }
        self.runtime_service.checkpoint(tick);
        self.checkpoint();
    }

    pub fn handleKeyboard(self: *HumaneShell, intent: KeyboardIntent, tick: u64) !void {
        switch (intent) {
            .next => try self.click(.focus_next, tick),
            .previous => try self.click(.focus_previous, tick),
            .activate => try self.click(self.focusedControl(), tick),
        }
    }

    pub fn focusedControl(self: *const HumaneShell) HumaneShellControl {
        return control_order[self.state.focus_index % control_order.len];
    }

    pub fn controlGuidance(self: *const HumaneShell, control: HumaneShellControl) ControlGuidance {
        const state = self.controlState(control);
        return .{
            .control = control,
            .state = state,
            .label = accessibleLabel(control),
            .shortcut = shortcutForControl(control),
            .blocked_reason = blockedReason(self, control, state),
            .next_action = nextAction(self, control, state),
        };
    }

    pub fn render(self: *const HumaneShell, buffer: []u8) ![]const u8 {
        const session = self.compositor_service.session;
        var used: usize = 0;
        const active = if (session.active_window_id == 0)
            null
        else
            session.findWindowConst(session.active_window_id);
        const active_title = if (active) |window| window.titleSlice() else "none";
        const active_type = if (active) |window| @tagName(window.view_type) else "none";

        try appendFmt(buffer, &used, "Zigos humane task shell\n", .{});
        try appendFmt(buffer, &used, "task_first=yes focus_index={d} focus_control={s}\n", .{
            self.state.focus_index,
            controlName(self.focusedControl()),
        });
        try appendFmt(buffer, &used, "accessibility keyboard={s} screen_reader={s} visible_focus={s} reduce_motion={s} high_contrast={s}\n", .{
            yesNo(self.accessibility.keyboard_navigation),
            yesNo(self.accessibility.screen_reader_labels),
            yesNo(self.accessibility.visible_focus),
            yesNo(self.accessibility.reduce_motion),
            yesNo(self.accessibility.high_contrast),
        });
        try appendFmt(buffer, &used, "keyboard next=Tab previous=Shift+Tab activate=Enter\n", .{});

        for (control_order, 0..) |control, index| {
            const guidance = self.controlGuidance(control);
            try appendFmt(buffer, &used, "control={s} state={s} focus={s} shortcut={s} label={s} reason={s} next={s}\n", .{
                controlName(control),
                @tagName(guidance.state),
                yesNo(index == self.state.focus_index),
                guidance.shortcut,
                guidance.label,
                guidance.blocked_reason,
                guidance.next_action,
            });
        }

        try appendFmt(buffer, &used, "task={d} workspace={d} document={s}\n", .{
            self.state.task_id,
            self.config.workspace_id,
            self.config.document_path,
        });
        try appendFmt(buffer, &used, "object_model first_class=yes file_bridge=export-import-only\n", .{});
        try appendFmt(buffer, &used, "object_query count={d} selected={d} opened={s} capability={d} shared={s}\n", .{
            self.state.object_query_count,
            self.state.selected_object_id,
            yesNo(self.state.object_opened),
            self.state.object_capability_id,
            yesNo(self.state.object_shared),
        });
        var object_index: usize = 0;
        while (object_index < @as(usize, @intCast(self.state.object_query_count)) and object_index < MAX_SHELL_OBJECT_RESULTS) : (object_index += 1) {
            const object_id = self.state.object_query_ids[object_index];
            const latest = self.storage.latestVersion(object_id);
            const version_id = if (latest) |version| version.id.raw() else 0;
            const label = if (latest) |version| version.metadata.labelSlice() else "missing";
            try appendFmt(buffer, &used, "object[{d}] id={d} version={d} label={s}\n", .{
                object_index,
                object_id,
                version_id,
                label,
            });
        }
        try appendFmt(buffer, &used, "object_history count={d}", .{self.state.object_history_count});
        var history_index: usize = 0;
        while (history_index < @as(usize, @intCast(self.state.object_history_count)) and history_index < MAX_SHELL_OBJECT_HISTORY) : (history_index += 1) {
            try appendFmt(buffer, &used, " v{d}={d}", .{
                history_index,
                self.state.object_history_versions[history_index],
            });
        }
        try appendFmt(buffer, &used, "\n", .{});
        try appendFmt(buffer, &used, "object_conflict reviewed={s} resolved={s} local={d} remote={d}\n", .{
            yesNo(self.state.object_conflict_reviewed),
            yesNo(self.state.object_conflict_resolved),
            self.state.object_conflict_local_version_id,
            self.state.object_conflict_remote_version_id,
        });
        try appendFmt(buffer, &used, "active_window={d} active_type={s} active_title={s} visible_windows={d}\n", .{
            session.active_window_id,
            active_type,
            active_title,
            session.visibleWindowCount(),
        });
        try appendFmt(buffer, &used, "permission reviewed={s} denied={s} window={d}\n", .{
            yesNo(self.state.permission_reviewed),
            yesNo(self.state.permission_denied),
            self.state.review_window_id,
        });
        if (self.state.permission_denied) {
            try appendFmt(buffer, &used, "denial reason={s} policy={s} missing={s} approval={s} retry_safe={s}\n", .{
                @tagName(self.state.last_denial.reason),
                self.state.last_denial.policySlice(),
                self.state.last_denial.missingCapabilitySlice(),
                yesNo(self.state.last_denial.user_approval_can_resolve),
                yesNo(self.state.last_denial.retry_safe),
            });
        }
        try appendFmt(buffer, &used, "device paired={s} trusted={s} label={s}\n", .{
            yesNo(self.state.device_paired),
            yesNo(self.sync.service.isTrustedDevice(self.config.paired_device)),
            self.config.device_label,
        });
        try appendFmt(buffer, &used, "snapshot id={d} label={s} restored={s}\n", .{
            self.state.snapshot_id,
            self.config.snapshot_label,
            yesNo(self.state.snapshot_restored),
        });
        try appendFmt(buffer, &used, "diagnostics ran={s} events={d} remote_share_requires_opt_in={s}\n", .{
            yesNo(self.state.diagnostics_ran),
            self.state.diagnostics_event_count,
            yesNo(self.state.remote_diagnostics_require_opt_in),
        });
        const latest = self.notifications.latestVisible(self.state.last_tick);
        if (latest) |notification| {
            try appendFmt(buffer, &used, "notification id={d} reason={s} detail={s}\n", .{
                notification.id,
                @tagName(notification.reason),
                notification.detailSlice(),
            });
        } else {
            try appendFmt(buffer, &used, "notification id=0 reason=none detail=none\n", .{});
        }
        try appendFmt(buffer, &used, "recovery checkpoint={s} recovered={s} task_flow_events={d} notifications={d}\n", .{
            yesNo(self.checkpoint_store.valid),
            yesNo(self.state.recovered),
            self.ledger.countMatching(.{ .kind = .task_flow }),
            self.ledger.countMatching(.{ .kind = .notification }),
        });
        return buffer[0..used];
    }

    pub fn controlState(self: *const HumaneShell, control: HumaneShellControl) ControlState {
        return switch (control) {
            .start_task => if (self.state.task_id == 0) .ready else .done,
            .open_workspace => if (self.state.workspace_opened) .done else if (self.state.task_id == 0) .blocked else .ready,
            .open_document => if (self.state.document_opened) .done else if (!self.state.workspace_opened) .blocked else .ready,
            .query_objects => if (self.state.object_query_count != 0) .done else .ready,
            .open_object => if (self.state.object_opened) .done else if (self.state.selected_object_id == 0 and self.state.object_query_count == 0) .ready else .ready,
            .show_object_history => if (self.state.object_history_count != 0) .done else if (self.state.selected_object_id == 0) .blocked else .ready,
            .mint_object_capability => if (self.state.object_capability_id != 0) .done else if (self.state.selected_object_id == 0) .blocked else .ready,
            .share_object => if (self.state.object_shared) .done else if (self.state.selected_object_id == 0) .blocked else .ready,
            .review_object_conflict => if (self.state.object_conflict_reviewed) .done else if (self.state.selected_object_id == 0) .blocked else .ready,
            .review_permission => if (self.state.review_window_id != 0) .done else if (!self.state.document_opened) .blocked else .ready,
            .allow_permission => if (self.state.permission_reviewed and !self.state.permission_denied)
                .done
            else if (self.state.permission_reviewed or self.state.review_window_id == 0)
                .blocked
            else
                .ready,
            .deny_permission => if (self.state.permission_denied)
                .done
            else if (self.state.permission_reviewed or self.state.review_window_id == 0)
                .blocked
            else
                .ready,
            .pair_device => if (self.state.device_paired) .done else .ready,
            .create_snapshot => if (self.state.snapshot_id != 0) .done else .ready,
            .rollback_snapshot => if (self.state.snapshot_restored) .done else if (self.state.snapshot_id == 0) .blocked else .ready,
            .run_diagnostics => if (self.state.diagnostics_ran) .done else .ready,
            .post_notification => if (self.state.notification_id != 0) .done else .ready,
            .recover_state => if (self.state.recovered) .done else if (!self.checkpoint_store.valid) .blocked else .ready,
            .focus_next, .focus_previous => .ready,
        };
    }

    fn startTask(self: *HumaneShell, tick: u64) !void {
        if (self.state.task_id != 0) return error.TaskAlreadyStarted;
        const task = try task_launch.startConfiguredTask(self.ux, self.runtime_service.runtimePtr(), self.config);
        self.state.task_id = task.id;
        try self.recordPendingTaskFlows(tick);
    }

    fn openWorkspace(self: *HumaneShell, tick: u64) !void {
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

    fn openDocument(self: *HumaneShell, tick: u64) !void {
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

    fn queryObjects(self: *HumaneShell) !void {
        var results_buffer: [MAX_SHELL_OBJECT_RESULTS]object_store.ObjectQueryResult = undefined;
        const results = self.storage.queryObjects(.{
            .object_type = .document,
            .label_contains = self.config.object_query_label,
        }, &results_buffer);
        self.clearObjectQueryState();
        if (results.len == 0) return error.ObjectMissing;
        self.state.object_query_count = @intCast(results.len);
        for (results, 0..) |result, index| {
            self.state.object_query_ids[index] = result.object_id.raw();
        }
        self.state.selected_object_id = results[0].object_id.raw();
        self.state.selected_version_id = results[0].latest_version_id.raw();
    }

    fn openObject(self: *HumaneShell, tick: u64) !void {
        const task = try self.requireTask();
        if (self.state.selected_object_id == 0) try self.queryObjects();
        const latest = self.storage.latestVersion(self.state.selected_object_id) orelse return error.ObjectMissing;
        var detail_buffer: [64]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buffer, "object:{d}", .{self.state.selected_object_id}) catch "object";
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .document_view,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = detail,
        });
        self.state.selected_version_id = latest.id.raw();
        self.state.object_opened = true;
        self.state.document_opened = true;
        try self.recordPendingTaskFlows(tick);
    }

    fn showObjectHistory(self: *HumaneShell) !void {
        if (self.state.selected_object_id == 0) return error.ObjectMissing;
        var history_buffer: [MAX_SHELL_OBJECT_HISTORY]object_store.ObjectHistoryEntry = undefined;
        const history = try self.storage.objectHistory(self.state.selected_object_id, &history_buffer);
        if (history.len == 0) return error.ObjectMissing;
        self.state.object_history_count = @intCast(history.len);
        @memset(self.state.object_history_versions[0..], 0);
        for (history, 0..) |entry, index| {
            self.state.object_history_versions[index] = entry.version_id.raw();
        }
    }

    fn mintObjectCapability(self: *HumaneShell, tick: u64) !void {
        if (self.state.selected_object_id == 0) return error.ObjectMissing;
        const table = self.config.object_capability_table orelse return error.CapabilityRequired;
        const minted = try table.mintBootRoot(.{
            .holder = self.config.user,
            .issuer = .{ .kind = .policy_authority, .serial = 1 },
            .target = .{ .kind = .object, .id = self.state.selected_object_id },
            .rights = .{ .object = .{
                .object_read = true,
                .object_write = true,
                .capability_query = true,
                .capability_pass = true,
            } },
            .scope = .{
                .task_id = self.state.task_id,
                .workspace_id = self.config.workspace_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = tick,
                .expires_at_ticks = tick + self.permissionRequest().max_lease_ticks,
            },
            .audit = .{
                .source_task_id = self.state.task_id,
                .broker_service_id = self.storage.service_id,
                .user_visible_entitlement = true,
            },
        });
        self.state.object_capability_id = minted.id;
    }

    fn shareObject(self: *HumaneShell) !void {
        if (self.state.selected_object_id == 0) return error.ObjectMissing;
        const grantee = self.objectSharePrincipal();
        const entry = try self.storage.findEntryForObject(ids.workspace(self.config.workspace_id), ids.object(self.state.selected_object_id));
        const grant = try (workspace.ShareGrant{
            .principal_id = grantee,
            .can_read = true,
            .can_write = false,
            .can_admin = false,
            .can_export = false,
            .network_scope = .local_only,
            .audit_visibility = .shared_participants,
        }).withObjectScope(entry.object_id, entry.pathSlice());
        try self.storage.shareWorkspace(ids.workspace(self.config.workspace_id), grant);
        self.state.object_shared = true;
    }

    fn reviewObjectConflict(self: *HumaneShell, tick: u64) !void {
        const task = try self.requireTask();
        if (self.state.selected_object_id == 0) return error.ObjectMissing;
        const review = try self.sync.reviewConflictForObject(
            self.sync_authority,
            self.config.workspace_id,
            self.objectConflictDevice(),
            self.state.selected_object_id,
        );
        var detail_buffer: [96]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buffer, "object conflict: {d}", .{review.object_id}) catch "object conflict";
        _ = try self.dispatchCompositor(.{
            .operation = .open_view,
            .view_type = .sync_conflict_review,
            .subject_task_id = task.id,
            .workspace_id = self.config.workspace_id,
            .detail = detail,
        });
        _ = try self.ux.syncConflictReview(self.config.workspace_id, self.config.user, detail);
        const resolved = try self.sync.resolveConflictForObject(
            self.sync_authority,
            self.config.workspace_id,
            self.objectConflictDevice(),
            self.state.selected_object_id,
            .keep_local,
        );
        self.state.object_conflict_reviewed = true;
        self.state.object_conflict_resolved = resolved.resolved;
        self.state.object_conflict_local_version_id = review.local_version_id;
        self.state.object_conflict_remote_version_id = review.remote_version_id;
        try self.recordPendingTaskFlows(tick);
    }

    fn reviewPermission(self: *HumaneShell, tick: u64) !void {
        const task = try self.requireTask();
        if (!self.state.document_opened) return error.DocumentRequired;
        const permission = self.permissionRequest();
        const response = try self.dispatchCompositor(.{
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
        self.state.review_window_id = response.window_id;
        try self.postNotification(tick, .permission_request, .high, "permission review waiting");
        try self.recordPendingTaskFlows(tick);
    }

    fn decidePermission(self: *HumaneShell, allow: bool, tick: u64) !void {
        const task = try self.requireTask();
        if (self.state.review_window_id == 0) return error.PermissionReviewRequired;
        const permission = self.permissionRequest();
        _ = try self.dispatchCompositor(.{
            .operation = .record_decision,
            .window_id = self.state.review_window_id,
            .permission_kind = permission.kind,
            .allow = allow,
            .local_only = allow and permission.local_only,
            .required = permission.required,
            .has_lease = allow and permission.max_lease_ticks != 0,
            .lease_ticks = permission.max_lease_ticks,
            .max_lease_ticks = permission.max_lease_ticks,
            .resource = permission.resource,
        });
        _ = try self.ux.reviewPermissionDecision(
            task.id,
            self.config.user,
            self.config.bundle_id,
            permission,
            allow,
            allow and permission.local_only,
            if (allow and permission.max_lease_ticks != 0) permission.max_lease_ticks else null,
        );
        try self.ledger.recordPermissionReview(
            self.config.user,
            task.id,
            permission.kind,
            allow,
            tick,
            permission.resource,
            false,
        );
        try self.ledger.recordPermissionDecision(
            self.config.user,
            task.id,
            permission.kind,
            allow,
            if (allow) .none else .policy_denied,
            tick,
            permission.resource,
            false,
        );
        self.state.permission_reviewed = true;
        self.state.permission_denied = !allow;
        self.state.last_denial = if (allow)
            denial_explanation.none()
        else
            denial_explanation.forPermissionDecision(permission.kind, .policy_denied);
        try self.recordPendingTaskFlows(tick);
    }

    fn pairDevice(self: *HumaneShell, tick: u64) !void {
        if (self.state.device_paired) return error.DeviceAlreadyPaired;
        try self.ux.pairDevice(
            self.sync,
            self.sync_authority,
            self.config.user,
            self.config.paired_device,
            self.config.device_label,
            self.config.user_signer,
            self.config.device_signer,
            tick,
        );
        self.state.device_paired = self.sync.service.isTrustedDevice(self.config.paired_device);
        if (!self.state.device_paired) return error.DevicePairingFailed;
        try self.ledger.recordDeviceTrustChange(self.config.user, self.config.paired_device, true, tick, self.config.device_label);
        try self.recordPendingTaskFlows(tick);
    }

    fn createSnapshot(self: *HumaneShell) !void {
        if (self.state.snapshot_id != 0) return error.SnapshotAlreadyCreated;
        const snapshot = try self.storage.snapshot(
            ids.workspace(self.config.workspace_id),
            self.config.snapshot_label,
            self.config.snapshot_signer,
        );
        self.state.snapshot_id = snapshot.id.raw();
    }

    fn rollbackSnapshot(self: *HumaneShell, tick: u64) !void {
        if (self.state.snapshot_id == 0) return error.SnapshotRequired;
        _ = try self.storage.restore(
            ids.workspace(self.config.workspace_id),
            ids.snapshot(self.state.snapshot_id),
            tick,
        );
        self.state.snapshot_restored = true;
        try self.postNotification(tick, .policy_notice, .normal, "workspace restored from snapshot");
    }

    fn runDiagnostics(self: *HumaneShell, tick: u64) !void {
        var probe_buffer: [1]u8 = undefined;
        if (self.ledger.exportRemoteShare(&probe_buffer, .{})) |_| {
            return error.DiagnosticsConsentBypass;
        } else |err| switch (err) {
            error.ConsentRequired => {},
            else => return err,
        }
        self.state.remote_diagnostics_require_opt_in = true;
        self.state.diagnostics_event_count = self.ledger.countMatching(.{});
        self.state.diagnostics_ran = true;
        try self.postNotification(tick, .policy_notice, .passive, "local diagnostics ready");
    }

    fn postShellNotification(self: *HumaneShell, tick: u64, detail: []const u8) !void {
        try self.postNotification(tick, .policy_notice, .normal, detail);
    }

    fn postNotification(
        self: *HumaneShell,
        tick: u64,
        reason: notification_center.Reason,
        urgency: notification_center.Urgency,
        detail: []const u8,
    ) !void {
        const notification = try self.notifications.post(.{
            .source = self.config.app_owner,
            .reason = reason,
            .urgency = urgency,
            .task_id = if (self.state.task_id == 0) null else self.state.task_id,
            .detail = detail,
            .expires_at_ticks = tick + 100,
            .suppression_policy = .replace_same_source_reason_task,
        });
        self.state.notification_id = notification.id;
        try self.ledger.recordNotification(notification.*, tick);
    }

    fn recoverState(self: *HumaneShell, tick: u64) !void {
        if (!self.checkpoint_store.valid) return error.RecoveryStateMissing;
        if (!self.runtime_service.restartFromCheckpoint(tick)) return error.RecoveryStateMissing;
        const compositor_recovered = self.compositor_service.dispatch(.{ .operation = .recover_state });
        if (compositor_recovered.status != .ok or !compositor_recovered.recovered) return error.RecoveryStateMissing;
        self.state = self.checkpoint_store.state;
        if (self.state.task_id != 0 and self.runtime_service.runtimePtr().find(self.state.task_id) == null) {
            return error.RecoveryStateMissing;
        }
        try self.ux.recoverSystem(self.state.task_id, self.config.user, "restored shell checkpoint");
        self.state.recovered = true;
        self.state.last_tick = tick;
        try self.recordPendingTaskFlows(tick);
    }

    fn requireTask(self: *HumaneShell) !*task_runtime.TaskRecord {
        if (self.state.task_id == 0) return error.TaskRequired;
        return self.runtime_service.runtimePtr().find(self.state.task_id) orelse error.TaskRequired;
    }

    fn dispatchCompositor(
        self: *HumaneShell,
        request: compositor_session.ServiceRequest,
    ) !compositor_session.ServiceResponse {
        const response = self.compositor_service.dispatch(request);
        if (response.status != .ok) return error.CompositorRejected;
        return response;
    }

    fn permissionRequest(self: *const HumaneShell) manifest.PermissionRequest {
        var request = self.config.permission_request;
        if (request.resource.len == 0) {
            request.resource = self.config.document_path;
        }
        return request;
    }

    fn recordPendingTaskFlows(self: *HumaneShell, tick: u64) !void {
        while (self.state.next_ledger_flow_order < self.ux.flow_count) : (self.state.next_ledger_flow_order += 1) {
            const flow = self.ux.flowAtOrder(self.state.next_ledger_flow_order) orelse return error.MissingTaskFlow;
            try self.ledger.recordTaskFlow(flow.*, tick);
        }
    }

    fn checkpoint(self: *HumaneShell) void {
        self.checkpoint_store.state = self.state;
        self.checkpoint_store.valid = true;
    }

    fn refreshResponse(self: *const HumaneShell, response: *HumaneShellResponse) void {
        const session = self.compositor_service.session;
        response.task_id = self.state.task_id;
        response.active_window_id = session.active_window_id;
        response.visible_window_count = @intCast(session.visibleWindowCount());
        response.task_flow_events = @intCast(self.ledger.countMatching(.{ .kind = .task_flow }));
        response.notification_events = @intCast(self.ledger.countMatching(.{ .kind = .notification }));
        response.focused_control = self.focusedControl();
        response.permission_reviewed = self.state.permission_reviewed;
        response.permission_denied = self.state.permission_denied;
        response.snapshot_id = self.state.snapshot_id;
        response.recovered = self.state.recovered;
        response.selected_object_id = self.state.selected_object_id;
        response.object_query_count = self.state.object_query_count;
        response.object_history_count = self.state.object_history_count;
        response.object_capability_id = self.state.object_capability_id;
        response.object_shared = self.state.object_shared;
        response.object_conflict_reviewed = self.state.object_conflict_reviewed;
        response.object_conflict_resolved = self.state.object_conflict_resolved;
    }

    fn focusNext(self: *HumaneShell) void {
        self.state.focus_index = (self.state.focus_index + 1) % control_order.len;
    }

    fn focusPrevious(self: *HumaneShell) void {
        self.state.focus_index = (self.state.focus_index + control_order.len - 1) % control_order.len;
    }

    fn clearObjectQueryState(self: *HumaneShell) void {
        self.state.object_query_count = 0;
        self.state.selected_object_id = 0;
        self.state.selected_version_id = 0;
        self.state.object_opened = false;
        self.state.object_history_count = 0;
        self.state.object_capability_id = 0;
        self.state.object_shared = false;
        self.state.object_conflict_reviewed = false;
        self.state.object_conflict_resolved = false;
        self.state.object_conflict_local_version_id = 0;
        self.state.object_conflict_remote_version_id = 0;
        @memset(self.state.object_query_ids[0..], 0);
        @memset(self.state.object_history_versions[0..], 0);
    }

    fn objectSharePrincipal(self: *const HumaneShell) principal.PrincipalId {
        if (self.config.object_share_principal.serial != 0) return self.config.object_share_principal;
        return self.config.paired_device;
    }

    fn objectConflictDevice(self: *const HumaneShell) principal.PrincipalId {
        if (self.config.object_conflict_device.serial != 0) return self.config.object_conflict_device;
        return self.config.paired_device;
    }
};

pub fn controlName(control: HumaneShellControl) []const u8 {
    return switch (control) {
        .start_task => "start-task",
        .open_workspace => "open-workspace",
        .open_document => "open-document",
        .query_objects => "query-objects",
        .open_object => "open-object",
        .show_object_history => "show-object-history",
        .mint_object_capability => "mint-object-capability",
        .share_object => "share-object",
        .review_object_conflict => "review-object-conflict",
        .review_permission => "review-permission",
        .allow_permission => "allow-permission",
        .deny_permission => "deny-permission",
        .pair_device => "pair-device",
        .create_snapshot => "create-snapshot",
        .rollback_snapshot => "rollback-snapshot",
        .run_diagnostics => "run-diagnostics",
        .post_notification => "post-notification",
        .recover_state => "recover-state",
        .focus_next => "focus-next",
        .focus_previous => "focus-previous",
    };
}

pub fn statusForError(err: anyerror) HumaneShellStatus {
    return switch (err) {
        error.TaskRequired,
        error.TaskAlreadyStarted,
        error.WorkspaceRequired,
        error.DocumentRequired,
        error.PermissionReviewRequired,
        error.DeviceAlreadyPaired,
        error.SnapshotAlreadyCreated,
        error.SnapshotRequired,
        => .invalid_order,
        error.EntryNotFound,
        error.WorkspaceNotFound,
        error.SnapshotNotFound,
        error.TaskNotFound,
        error.ObjectMissing,
        error.ConflictNotFound,
        => .not_found,
        error.PermissionDenied,
        error.CapabilityRequired,
        error.CapabilityNotFound,
        error.CapabilityRevoked,
        error.WorkspaceScopeViolation,
        => .permission_rejected,
        error.DevicePairingFailed,
        error.DeviceNotTrusted,
        error.UserRootNotFound,
        error.AuthorityRequired,
        error.AuthorityScopeViolation,
        => .sync_rejected,
        error.CompositorRejected => .compositor_rejected,
        error.ConsentRequired,
        error.DiagnosticsConsentBypass,
        => .diagnostics_rejected,
        error.RecoveryStateMissing => .recovery_missing,
        else => .invalid_request,
    };
}

fn shortcutForControl(control: HumaneShellControl) []const u8 {
    return switch (control) {
        .start_task => "Enter",
        .open_workspace => "W",
        .open_document => "D",
        .query_objects => "Q",
        .open_object => "O",
        .show_object_history => "H",
        .mint_object_capability => "C",
        .share_object => "X",
        .review_object_conflict => "V",
        .review_permission => "R",
        .allow_permission => "A",
        .deny_permission => "N",
        .pair_device => "P",
        .create_snapshot => "S",
        .rollback_snapshot => "B",
        .run_diagnostics => "G",
        .post_notification => "O",
        .recover_state => "Ctrl+R",
        .focus_next => "Tab",
        .focus_previous => "Shift+Tab",
    };
}

fn blockedReason(shell: *const HumaneShell, control: HumaneShellControl, state: ControlState) []const u8 {
    if (state != .blocked) return "none";
    return switch (control) {
        .open_workspace => "task required",
        .open_document => "workspace required",
        .show_object_history,
        .mint_object_capability,
        .share_object,
        .review_object_conflict,
        => "object required",
        .review_permission => "document required",
        .allow_permission, .deny_permission => if (shell.state.permission_reviewed)
            "permission already decided"
        else
            "permission review required",
        .rollback_snapshot => "snapshot required",
        .recover_state => "checkpoint required",
        else => "control unavailable",
    };
}

fn nextAction(shell: *const HumaneShell, control: HumaneShellControl, state: ControlState) []const u8 {
    if (state == .done) return "completed";
    if (state == .blocked) {
        return switch (control) {
            .open_workspace => "start task",
            .open_document => "open workspace",
            .show_object_history,
            .mint_object_capability,
            .share_object,
            .review_object_conflict,
            => "query objects",
            .review_permission => "open document",
            .allow_permission, .deny_permission => if (shell.state.permission_reviewed)
                "continue"
            else
                "review permission",
            .rollback_snapshot => "create snapshot",
            .recover_state => "complete a checkpointed action",
            else => "resolve prerequisite",
        };
    }
    return switch (control) {
        .start_task => "launch task",
        .open_workspace => "show workspace",
        .open_document => "show document",
        .query_objects => "query object store",
        .open_object => "open object",
        .show_object_history => "show object history",
        .mint_object_capability => "mint object capability",
        .share_object => "share selected object",
        .review_object_conflict => "review object conflict",
        .review_permission => "open review",
        .allow_permission => "allow request",
        .deny_permission => "deny with explanation",
        .pair_device => "pair trusted device",
        .create_snapshot => "create signed snapshot",
        .rollback_snapshot => "restore snapshot",
        .run_diagnostics => "run local diagnostics",
        .post_notification => "post notification",
        .recover_state => "restore checkpoint",
        .focus_next => "move focus forward",
        .focus_previous => "move focus backward",
    };
}

fn accessibleLabel(control: HumaneShellControl) []const u8 {
    return switch (control) {
        .start_task => "Start task",
        .open_workspace => "Open workspace",
        .open_document => "Open document",
        .query_objects => "Query object store",
        .open_object => "Open selected object",
        .show_object_history => "Show object history",
        .mint_object_capability => "Mint object capability",
        .share_object => "Share selected object",
        .review_object_conflict => "Review object conflict",
        .review_permission => "Review permission request",
        .allow_permission => "Allow requested permission",
        .deny_permission => "Deny requested permission and explain why",
        .pair_device => "Pair trusted device",
        .create_snapshot => "Create workspace snapshot",
        .rollback_snapshot => "Rollback workspace to snapshot",
        .run_diagnostics => "Run local diagnostics",
        .post_notification => "Post shell notification",
        .recover_state => "Recover shell state",
        .focus_next => "Move focus to next control",
        .focus_previous => "Move focus to previous control",
    };
}
