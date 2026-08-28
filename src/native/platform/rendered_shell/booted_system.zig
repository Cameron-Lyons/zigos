const std = @import("std");
const compositor_session = @import("../compositor_session.zig");
const input_driver_task = @import("../../drivers/input_driver_task.zig");
const native_util = @import("../../core/util.zig");
const humane_shell = @import("humane_shell.zig");
const rendering = @import("rendering.zig");

const HumaneShell = humane_shell.HumaneShell;
const HumaneShellControl = humane_shell.HumaneShellControl;
const HumaneShellRequest = humane_shell.HumaneShellRequest;
const HumaneShellResponse = humane_shell.HumaneShellResponse;
const HumaneShellStatus = humane_shell.HumaneShellStatus;
const appendFmt = rendering.appendFmt;
const USER_DIAGNOSTICS_BUFFER_BYTES = rendering.USER_DIAGNOSTICS_BUFFER_BYTES;
const yesNo = native_util.yesNo;

pub const BootPhase = enum(u8) {
    cold,
    booting,
    running,
    recovery,
};

pub const PermissionPromptState = enum(u8) {
    hidden,
    pending,
    allowed,
    denied,
};

pub const InputKind = enum(u8) {
    boot,
    tick,
    key_next,
    key_previous,
    key_activate,
    start_task,
    open_workspace,
    open_document,
    text_input,
    edit_document,
    sync_document,
    query_objects,
    open_object,
    show_object_history,
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
    remove_package,
    task_switch_next,
    task_switch_previous,
    show_recovery,
    dismiss_recovery,
};

pub const ShellInput = struct {
    kind: InputKind,
    tick: u64 = 0,
    text: []const u8 = "",
};

pub const InputResult = struct {
    kind: InputKind,
    accepted: bool = false,
    phase: BootPhase = .cold,
    status: HumaneShellStatus = .ok,
    task_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    focused_control: HumaneShellControl = .start_task,
    error_visible: bool = false,
};

pub const BootedSystem = struct {
    shell: *HumaneShell,
    phase: BootPhase = .cold,
    input_loop_running: bool = false,
    recovery_visible: bool = false,
    task_switcher_visible: bool = false,
    task_switcher_index: usize = 0,
    input_event_count: usize = 0,
    last_input: InputKind = .boot,
    last_control: HumaneShellControl = .start_task,
    last_status: HumaneShellStatus = .ok,
    last_tick: u64 = 0,
    error_visible: bool = false,
    hardware_text_initialized: bool = false,
    hardware_text_dirty: bool = false,
    hardware_text_len: usize = 0,
    hardware_text: [humane_shell.MAX_SHELL_TEXT_INPUT_BYTES]u8 =
        [_]u8{0} ** humane_shell.MAX_SHELL_TEXT_INPUT_BYTES,

    pub fn init(shell: *HumaneShell) BootedSystem {
        return .{ .shell = shell };
    }

    pub fn boot(self: *BootedSystem, tick: u64) InputResult {
        self.phase = .booting;
        self.last_tick = tick;
        self.input_loop_running = true;
        self.hardware_text_initialized = false;
        self.hardware_text_dirty = false;
        self.hardware_text_len = 0;
        @memset(self.hardware_text[0..], 0);
        self.phase = .running;
        self.clearError();
        self.last_input = .boot;
        return self.result(.boot, true);
    }

    pub fn dispatchInput(self: *BootedSystem, input: ShellInput) InputResult {
        self.last_input = input.kind;
        self.last_tick = input.tick;

        if (input.kind == .boot) {
            return self.boot(input.tick);
        }

        if (!self.input_loop_running or self.phase == .cold) {
            self.setError(.invalid_order, .start_task);
            return self.result(input.kind, false);
        }

        self.input_event_count += 1;

        switch (input.kind) {
            .boot => unreachable,
            .tick => {
                self.clearError();
                return self.result(input.kind, true);
            },
            .key_next => return self.dispatchHumaneInput(input, .{
                .operation = .keyboard,
                .keyboard = .next,
                .tick = input.tick,
            }, .focus_next),
            .key_previous => return self.dispatchHumaneInput(input, .{
                .operation = .keyboard,
                .keyboard = .previous,
                .tick = input.tick,
            }, .focus_previous),
            .key_activate => {
                const control = self.shell.focusedControl();
                return self.dispatchHumaneInput(input, .{
                    .operation = .keyboard,
                    .keyboard = .activate,
                    .tick = input.tick,
                }, control);
            },
            .text_input,
            .edit_document,
            => {
                const response = self.dispatchHumaneInput(input, .{
                    .operation = .click,
                    .control = .edit_document,
                    .tick = input.tick,
                    .text = input.text,
                }, .edit_document);
                if (response.accepted) self.invalidateHardwareText();
                return response;
            },
            .task_switch_next => {
                self.switchActiveWindow(.next) catch |err| {
                    self.setError(statusForBootError(err), .start_task);
                    return self.result(input.kind, false);
                };
                self.clearError();
                return self.result(input.kind, true);
            },
            .task_switch_previous => {
                self.switchActiveWindow(.previous) catch |err| {
                    self.setError(statusForBootError(err), .start_task);
                    return self.result(input.kind, false);
                };
                self.clearError();
                return self.result(input.kind, true);
            },
            .show_recovery => {
                self.recovery_visible = true;
                self.phase = .recovery;
                self.clearError();
                return self.result(input.kind, true);
            },
            .dismiss_recovery => {
                self.recovery_visible = false;
                self.phase = .running;
                self.clearError();
                return self.result(input.kind, true);
            },
            else => {
                const control = controlForInput(input.kind).?;
                const response = self.dispatchHumaneInput(input, .{
                    .operation = .click,
                    .control = control,
                    .tick = input.tick,
                }, control);
                if (response.accepted and inputInvalidatesHardwareText(input.kind)) {
                    self.invalidateHardwareText();
                }
                return response;
            },
        }
    }

    pub fn runInputLoop(self: *BootedSystem, inputs: []const ShellInput) InputResult {
        var response = self.result(.tick, true);
        for (inputs) |input| {
            response = self.dispatchInput(input);
        }
        return response;
    }

    pub fn dispatchKeyboardEvent(
        self: *BootedSystem,
        event: input_driver_task.KeyboardEvent,
        tick: u64,
    ) InputResult {
        return switch (event.kind) {
            .focus_next => self.dispatchInput(.{ .kind = .key_next, .tick = tick }),
            .focus_previous => self.dispatchInput(.{ .kind = .key_previous, .tick = tick }),
            .activate => self.dispatchInput(.{ .kind = .key_activate, .tick = tick }),
            .task_switch_next => self.dispatchInput(.{ .kind = .task_switch_next, .tick = tick }),
            .task_switch_previous => self.dispatchInput(.{ .kind = .task_switch_previous, .tick = tick }),
            .show_recovery => self.dispatchInput(.{ .kind = .show_recovery, .tick = tick }),
            .dismiss_recovery => self.dispatchInput(.{ .kind = .dismiss_recovery, .tick = tick }),
            .text => self.stageHardwareText(event.text, tick),
            .backspace => self.backspaceHardwareText(tick),
            .commit_text => self.commitHardwareText(tick),
        };
    }

    pub fn render(self: *const BootedSystem, buffer: []u8) ![]const u8 {
        const session = self.shell.compositor_service.session;
        const active = self.activeWindow();
        const active_title = if (active) |window| window.titleSlice() else "none";
        const active_type = if (active) |window| @tagName(window.view_type) else "none";
        const active_task_id = if (active) |window| window.subject_task_id else 0;
        const latest = self.shell.notifications.latestVisible(self.last_tick);
        const prompt = self.permissionPrompt();
        const review_item = self.permissionReviewItem();
        const review_resource = if (review_item) |item| item.resourceSlice() else "none";
        const review_decision = if (review_item) |item| @tagName(item.decision) else "none";
        const review_local_only = if (review_item) |item| item.decision_local_only or item.requested_local_only else false;
        const review_lease_ticks = if (review_item) |item| if (item.decision_has_lease) item.decision_lease_ticks else item.requested_lease_ticks else 0;

        var used: usize = 0;
        try appendFmt(buffer, &used, "Zigos booted rendered system\n", .{});
        try appendFmt(buffer, &used, "boot_phase={s} input_loop={s} events={d} last_input={s} last_status={s}\n", .{
            @tagName(self.phase),
            if (self.input_loop_running) "running" else "stopped",
            self.input_event_count,
            @tagName(self.last_input),
            @tagName(self.last_status),
        });
        try appendFmt(buffer, &used, "input bindings next=Tab previous=Shift+Tab activate=Enter task_switch=Alt+Tab recovery=Ctrl+R\n", .{});
        try appendFmt(buffer, &used, "hardware_text staged_bytes={d} dirty={s} commit=Ctrl+Enter\n", .{
            self.hardware_text_len,
            yesNo(self.hardware_text_dirty),
        });
        try appendFmt(buffer, &used, "accessibility keyboard={s} screen_reader={s} visible_focus={s} reduce_motion={s} high_contrast={s}\n", .{
            yesNo(self.shell.accessibility.keyboard_navigation),
            yesNo(self.shell.accessibility.screen_reader_labels),
            yesNo(self.shell.accessibility.visible_focus),
            yesNo(self.shell.accessibility.reduce_motion),
            yesNo(self.shell.accessibility.high_contrast),
        });
        try appendFmt(buffer, &used, "compositor active_window={d} active_type={s} active_title={s} active_task={d} visible_windows={d} total_windows={d}\n", .{
            session.active_window_id,
            active_type,
            active_title,
            active_task_id,
            session.visibleWindowCount(),
            session.window_count,
        });

        var index: usize = 0;
        while (index < session.window_count) : (index += 1) {
            const window = session.windowAtOrder(index) orelse continue;
            try appendFmt(buffer, &used, "window[{d}] id={d} type={s} active={s} modal={s} task={d} title={s} detail={s}\n", .{
                index,
                window.id,
                @tagName(window.view_type),
                yesNo(window.id == session.active_window_id),
                yesNo(window.modal),
                window.subject_task_id,
                window.titleSlice(),
                window.detailSlice(),
            });
        }

        try appendFmt(buffer, &used, "task_switcher visible={s} index={d} active_window={d} active_task={d}\n", .{
            yesNo(self.task_switcher_visible),
            self.task_switcher_index,
            session.active_window_id,
            active_task_id,
        });
        try appendFmt(buffer, &used, "permission_prompt state={s} window={d} decision={s} resource={s} local_only={s} lease_ticks={d}\n", .{
            @tagName(prompt),
            self.shell.state.review_window_id,
            review_decision,
            review_resource,
            yesNo(review_local_only),
            review_lease_ticks,
        });
        try appendFmt(buffer, &used, "document_loop opened={s} edited={s} version={d} bytes={d} synced={s} sync_selected={d} frames={d} conflicts={d} object_shared={s} conflict_reviewed={s} package_removed={s}\n", .{
            yesNo(self.shell.state.document_opened),
            yesNo(self.shell.state.document_edited),
            self.shell.state.document_version_id,
            self.shell.state.document_text_len,
            yesNo(self.shell.state.document_synced),
            self.shell.state.sync_selected_entries,
            self.shell.state.sync_transport_frames,
            self.shell.state.sync_conflicts,
            yesNo(self.shell.state.object_shared),
            yesNo(self.shell.state.object_conflict_reviewed),
            yesNo(self.shell.state.package_removed),
        });
        if (self.shell.state.document_text_len != 0) {
            try appendFmt(buffer, &used, "document_text={s}\n", .{self.shell.documentTextSlice()});
        }
        if (self.shell.state.permission_denied) {
            try appendFmt(buffer, &used, "permission_error reason={s} policy={s} missing={s} approval={s} retry_safe={s}\n", .{
                @tagName(self.shell.state.last_denial.reason),
                self.shell.state.last_denial.policySlice(),
                self.shell.state.last_denial.missingCapabilitySlice(),
                yesNo(self.shell.state.last_denial.userApprovalCanResolve()),
                yesNo(self.shell.state.last_denial.retryIsSafe()),
            });
        }
        if (latest) |notification| {
            try appendFmt(buffer, &used, "notifications active={d} latest_id={d} urgency={s} reason={s} detail={s}\n", .{
                self.shell.notifications.activeCount(self.last_tick),
                notification.id,
                @tagName(notification.urgency),
                @tagName(notification.reason),
                notification.detailSlice(),
            });
        } else {
            try appendFmt(buffer, &used, "notifications active={d} latest_id=0 urgency=none reason=none detail=none\n", .{
                self.shell.notifications.activeCount(self.last_tick),
            });
        }
        if (self.shell.state.diagnostics_ran) {
            var diagnostics_buffer: [USER_DIAGNOSTICS_BUFFER_BYTES]u8 = undefined;
            const diagnostics = try self.shell.ledger.renderUserVisibleDiagnosticsToBuffer(&diagnostics_buffer);
            try appendFmt(buffer, &used, "{s}\n", .{diagnostics});
        }
        try appendFmt(buffer, &used, "recovery_ui visible={s} checkpoint={s} recovered={s} runtime_checkpoint={s} restart_generation={d}\n", .{
            yesNo(self.recovery_visible),
            yesNo(self.shell.checkpoint_store.valid),
            yesNo(self.shell.state.recovered),
            yesNo(self.shell.runtime_service.has_checkpoint),
            self.shell.runtime_service.restart_generation,
        });
        try appendFmt(buffer, &used, "error_surface visible={s} status={s} summary={s} cause={s} next={s}\n", .{
            yesNo(self.error_visible),
            @tagName(self.last_status),
            self.errorSummary(),
            self.errorCause(),
            self.errorNextAction(),
        });
        return buffer[0..used];
    }

    fn dispatchHumaneInput(
        self: *BootedSystem,
        input: ShellInput,
        request: HumaneShellRequest,
        control: HumaneShellControl,
    ) InputResult {
        self.last_control = control;
        const response = self.shell.dispatch(request);
        if (response.status != .ok) {
            self.setError(response.status, control);
            return self.result(input.kind, false);
        }

        if (control == .recover_state) {
            self.recovery_visible = true;
            self.phase = .recovery;
        } else if (self.phase != .recovery) {
            self.phase = .running;
        }
        self.clearError();
        return self.result(input.kind, true);
    }

    fn stageHardwareText(self: *BootedSystem, text: u8, tick: u64) InputResult {
        if (self.hardwareTextInputBlocked(tick)) |blocked| return blocked;
        self.ensureHardwareTextBuffer();
        if (text == 0 or self.hardware_text_len == self.hardware_text.len) {
            self.setError(.invalid_request, .edit_document);
            return self.result(.text_input, false);
        }
        self.hardware_text[self.hardware_text_len] = text;
        self.hardware_text_len += 1;
        self.hardware_text_dirty = true;
        self.clearError();
        return self.result(.text_input, true);
    }

    fn backspaceHardwareText(self: *BootedSystem, tick: u64) InputResult {
        if (self.hardwareTextInputBlocked(tick)) |blocked| return blocked;
        self.ensureHardwareTextBuffer();
        if (self.hardware_text_len != 0) {
            self.hardware_text_len -= 1;
            self.hardware_text[self.hardware_text_len] = 0;
            self.hardware_text_dirty = true;
        }
        self.clearError();
        return self.result(.text_input, true);
    }

    fn commitHardwareText(self: *BootedSystem, tick: u64) InputResult {
        self.last_input = .text_input;
        self.last_tick = tick;
        self.last_control = .edit_document;
        if (!self.input_loop_running or self.phase == .cold) {
            self.setError(.invalid_order, .edit_document);
            return self.result(.text_input, false);
        }
        if (!self.shell.state.document_opened) {
            self.setError(.invalid_order, .edit_document);
            return self.result(.text_input, false);
        }
        self.ensureHardwareTextBuffer();
        if (!self.hardware_text_dirty) {
            self.input_event_count += 1;
            self.clearError();
            return self.result(.text_input, true);
        }
        const response = self.dispatchInput(.{
            .kind = .text_input,
            .tick = tick,
            .text = self.hardware_text[0..self.hardware_text_len],
        });
        if (response.accepted) {
            self.hardware_text_initialized = false;
            self.hardware_text_dirty = false;
        } else {
            self.hardware_text_initialized = true;
            self.hardware_text_dirty = true;
        }
        return response;
    }

    fn hardwareTextInputBlocked(self: *BootedSystem, tick: u64) ?InputResult {
        self.last_input = .text_input;
        self.last_tick = tick;
        self.last_control = .edit_document;
        if (!self.input_loop_running or self.phase == .cold) {
            self.setError(.invalid_order, .edit_document);
            return self.result(.text_input, false);
        }
        if (!self.shell.state.document_opened) {
            self.setError(.invalid_order, .edit_document);
            return self.result(.text_input, false);
        }
        self.input_event_count += 1;
        return null;
    }

    fn ensureHardwareTextBuffer(self: *BootedSystem) void {
        if (self.hardware_text_initialized) return;
        const current = self.shell.documentTextSlice();
        self.hardware_text_len = @min(current.len, self.hardware_text.len);
        @memcpy(self.hardware_text[0..self.hardware_text_len], current[0..self.hardware_text_len]);
        if (self.hardware_text_len < self.hardware_text.len) {
            @memset(self.hardware_text[self.hardware_text_len..], 0);
        }
        self.hardware_text_initialized = true;
        self.hardware_text_dirty = false;
    }

    fn invalidateHardwareText(self: *BootedSystem) void {
        self.hardware_text_initialized = false;
        self.hardware_text_dirty = false;
    }

    fn switchActiveWindow(self: *BootedSystem, direction: compositor_session.SwitchDirection) !void {
        const switched = try self.shell.compositor_service.switchVisible(direction);
        self.task_switcher_visible = true;
        self.task_switcher_index = switched.visible_index;
    }

    fn result(self: *const BootedSystem, kind: InputKind, accepted: bool) InputResult {
        const session = self.shell.compositor_service.session;
        return .{
            .kind = kind,
            .accepted = accepted,
            .phase = self.phase,
            .status = self.last_status,
            .task_id = self.shell.state.task_id,
            .active_window_id = session.active_window_id,
            .visible_window_count = @intCast(session.visibleWindowCount()),
            .focused_control = self.shell.focusedControl(),
            .error_visible = self.error_visible,
        };
    }

    fn clearError(self: *BootedSystem) void {
        self.last_status = .ok;
        self.error_visible = false;
    }

    fn setError(self: *BootedSystem, status: HumaneShellStatus, control: HumaneShellControl) void {
        self.last_status = status;
        self.last_control = control;
        self.error_visible = true;
    }

    fn activeWindow(self: *const BootedSystem) ?*const compositor_session.WindowRecord {
        const session = self.shell.compositor_service.session;
        if (session.active_window_id == 0) return null;
        return session.findWindowConst(session.active_window_id);
    }

    fn permissionPrompt(self: *const BootedSystem) PermissionPromptState {
        if (self.shell.state.review_window_id == 0) return .hidden;
        if (!self.shell.state.permission_reviewed) return .pending;
        return if (self.shell.state.permission_denied) .denied else .allowed;
    }

    fn permissionReviewItem(self: *const BootedSystem) ?*const compositor_session.ReviewItemRecord {
        const session = self.shell.compositor_service.session;
        if (self.shell.state.review_window_id == 0) return null;
        var index: usize = 0;
        while (index < session.item_count) : (index += 1) {
            const item = session.itemAtOrder(index) orelse continue;
            if (item.window_id == self.shell.state.review_window_id) return item;
        }
        return null;
    }

    fn errorSummary(self: *const BootedSystem) []const u8 {
        if (!self.error_visible) return "none";
        return switch (self.last_status) {
            .ok => "none",
            .invalid_order => "action blocked by current shell state",
            .not_found => "requested task workspace or object was not found",
            .permission_rejected => "permission policy rejected the action",
            .sync_rejected => "device or sync trust rejected the action",
            .compositor_rejected => "compositor could not present the requested surface",
            .diagnostics_rejected => "diagnostics require explicit local consent",
            .recovery_missing => "no recoverable checkpoint is available",
            .invalid_request => "input could not be handled",
        };
    }

    fn errorCause(self: *const BootedSystem) []const u8 {
        if (!self.error_visible) return "none";
        const guidance = self.shell.controlGuidance(self.last_control);
        if (guidance.state == .blocked) return guidance.blocked_reason;
        return switch (self.last_status) {
            .ok => "none",
            .invalid_order => "control already completed or prerequisite missing",
            .not_found => "the referenced resource is absent",
            .permission_rejected => "capability or user grant is missing",
            .sync_rejected => "device trust or user root is missing",
            .compositor_rejected => "active surface could not be found",
            .diagnostics_rejected => "remote diagnostics export is blocked without consent",
            .recovery_missing => "runtime or compositor checkpoint is missing",
            .invalid_request => "input mapping is invalid for this shell",
        };
    }

    fn errorNextAction(self: *const BootedSystem) []const u8 {
        if (!self.error_visible) return "none";
        const guidance = self.shell.controlGuidance(self.last_control);
        if (guidance.state == .blocked) return guidance.next_action;
        return switch (self.last_status) {
            .ok => "none",
            .invalid_order => "choose an available control",
            .not_found => "open an existing workspace object",
            .permission_rejected => "review or request a narrower permission",
            .sync_rejected => "pair or trust the device first",
            .compositor_rejected => "return to a visible window",
            .diagnostics_rejected => "keep diagnostics local or opt in",
            .recovery_missing => "complete a checkpointed action first",
            .invalid_request => "send a supported input event",
        };
    }
};

fn inputInvalidatesHardwareText(kind: InputKind) bool {
    return kind == .open_document or kind == .rollback_snapshot or kind == .recover_state;
}

fn controlForInput(kind: InputKind) ?HumaneShellControl {
    return switch (kind) {
        .start_task => .start_task,
        .open_workspace => .open_workspace,
        .open_document => .open_document,
        .edit_document, .text_input => .edit_document,
        .sync_document => .sync_document,
        .query_objects => .query_objects,
        .open_object => .open_object,
        .show_object_history => .show_object_history,
        .share_object => .share_object,
        .review_object_conflict => .review_object_conflict,
        .review_permission => .review_permission,
        .allow_permission => .allow_permission,
        .deny_permission => .deny_permission,
        .pair_device => .pair_device,
        .create_snapshot => .create_snapshot,
        .rollback_snapshot => .rollback_snapshot,
        .run_diagnostics => .run_diagnostics,
        .post_notification => .post_notification,
        .recover_state => .recover_state,
        .remove_package => .remove_package,
        else => null,
    };
}

fn statusForBootError(err: anyerror) HumaneShellStatus {
    return switch (err) {
        error.NoVisibleWindows => .not_found,
        error.CompositorRejected => .compositor_rejected,
        else => .invalid_request,
    };
}
