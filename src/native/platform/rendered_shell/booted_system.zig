const std = @import("std");
const compositor_session = @import("../compositor_session.zig");
const native_util = @import("../../core/util.zig");
const humane_shell = @import("humane_shell.zig");
const rendering = @import("rendering.zig");

const HumaneShell = humane_shell.HumaneShell;
const HumaneShellControl = humane_shell.HumaneShellControl;
const HumaneShellRequest = humane_shell.HumaneShellRequest;
const HumaneShellResponse = humane_shell.HumaneShellResponse;
const HumaneShellStatus = humane_shell.HumaneShellStatus;
const appendFmt = rendering.appendFmt;
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
    review_permission,
    allow_permission,
    deny_permission,
    pair_device,
    create_snapshot,
    rollback_snapshot,
    run_diagnostics,
    post_notification,
    recover_state,
    task_switch_next,
    task_switch_previous,
    show_recovery,
    dismiss_recovery,
};

pub const ShellInput = struct {
    kind: InputKind,
    tick: u64 = 0,
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

    pub fn init(shell: *HumaneShell) BootedSystem {
        return .{ .shell = shell };
    }

    pub fn boot(self: *BootedSystem, tick: u64) InputResult {
        self.phase = .booting;
        self.last_tick = tick;
        self.input_loop_running = true;
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
                return self.dispatchHumaneInput(input, .{
                    .operation = .click,
                    .control = control,
                    .tick = input.tick,
                }, control);
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
        if (self.shell.state.permission_denied) {
            try appendFmt(buffer, &used, "permission_error reason={s} policy={s} missing={s} approval={s} retry_safe={s}\n", .{
                @tagName(self.shell.state.last_denial.reason),
                self.shell.state.last_denial.policySlice(),
                self.shell.state.last_denial.missingCapabilitySlice(),
                yesNo(self.shell.state.last_denial.user_approval_can_resolve),
                yesNo(self.shell.state.last_denial.retry_safe),
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

    fn switchActiveWindow(self: *BootedSystem, direction: SwitchDirection) !void {
        const session = self.shell.compositor_service.session;
        const visible_count = session.visibleWindowCount();
        if (visible_count == 0) return error.NoVisibleWindows;

        const current = activeVisibleIndex(session) orelse 0;
        const target_index = switch (direction) {
            .next => (current + 1) % visible_count,
            .previous => (current + visible_count - 1) % visible_count,
        };
        const window_id = visibleWindowIdAt(session, target_index) orelse return error.NoVisibleWindows;
        const switched = self.shell.compositor_service.dispatch(.{
            .operation = .switch_view,
            .window_id = window_id,
        });
        if (switched.status != .ok) return error.CompositorRejected;
        self.task_switcher_visible = true;
        self.task_switcher_index = target_index;
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

const SwitchDirection = enum {
    next,
    previous,
};

fn controlForInput(kind: InputKind) ?HumaneShellControl {
    return switch (kind) {
        .start_task => .start_task,
        .open_workspace => .open_workspace,
        .open_document => .open_document,
        .review_permission => .review_permission,
        .allow_permission => .allow_permission,
        .deny_permission => .deny_permission,
        .pair_device => .pair_device,
        .create_snapshot => .create_snapshot,
        .rollback_snapshot => .rollback_snapshot,
        .run_diagnostics => .run_diagnostics,
        .post_notification => .post_notification,
        .recover_state => .recover_state,
        else => null,
    };
}

fn activeVisibleIndex(session: *const compositor_session.Session) ?usize {
    var visible_index: usize = 0;
    var order_index: usize = 0;
    while (order_index < session.window_count) : (order_index += 1) {
        const window = session.windowAtOrder(order_index) orelse continue;
        if (!window.visible) continue;
        if (window.id == session.active_window_id) return visible_index;
        visible_index += 1;
    }
    return null;
}

fn visibleWindowIdAt(session: *const compositor_session.Session, target_index: usize) ?u64 {
    var visible_index: usize = 0;
    var order_index: usize = 0;
    while (order_index < session.window_count) : (order_index += 1) {
        const window = session.windowAtOrder(order_index) orelse continue;
        if (!window.visible) continue;
        if (visible_index == target_index) return window.id;
        visible_index += 1;
    }
    return null;
}

fn statusForBootError(err: anyerror) HumaneShellStatus {
    return switch (err) {
        error.NoVisibleWindows => .not_found,
        error.CompositorRejected => .compositor_rejected,
        else => .invalid_request,
    };
}
