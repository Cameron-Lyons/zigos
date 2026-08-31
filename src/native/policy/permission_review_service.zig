const std = @import("std");
const abi = @import("../core/abi.zig");
const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const compositor_display = @import("../platform/compositor_display.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const input_driver_task = @import("../drivers/input_driver_task.zig");
const input_router = @import("../platform/input_router.zig");
const native_ux = @import("../platform/native_ux.zig");
const permission_review = @import("permission_review.zig");
const policy_mediation = @import("policy_mediation.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const xhci = @import("../../kernel/drivers/xhci.zig");

const REVIEW_RENDER_BUFFER_BYTES: usize = units.kibibytes(4);
const REVIEW_CARD_BUFFER_BYTES: usize = 512;
const REVIEW_DECISION_BUFFER_BYTES: usize = 320;
const REVIEW_PROMPT_BUFFER_BYTES: usize = 512;
const REVIEW_FLOW_BUFFER_BYTES: usize = 320;
const REVIEW_WINDOW_BUFFER_BYTES: usize = 320;

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn hlt() void {}
    };
const serial = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/serial.zig")
else
    struct {
        pub fn hasChar() bool {
            return false;
        }

        pub fn getchar() ?u8 {
            return null;
        }
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const MAX_REVIEW_DECISIONS: usize = permission_review.MAX_REVIEW_DECISIONS;
pub const MAX_INPUT_LINE: usize = 96;
pub const MAX_PHYSICAL_INPUT_COMMANDS: usize = MAX_REVIEW_DECISIONS;
pub const MAX_SCRIPTED_PLAN_ENTRIES: usize = 16;
pub const COMPACT_COMMAND_QUEUE_METADATA = true;
pub const COMPACT_REVIEW_PROGRESS_METADATA = true;
pub const IN_PLACE_MODELED_INPUT_INITIALIZATION = true;
pub const RENDERED_BEGIN_AUDIT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const BATCH_REVIEW_AUDIT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const COMMAND_INPUT_SIZE_CEILING_BYTES: usize = 1_664;
pub const RENDERED_REVIEW_SURFACE_SIZE_CEILING_BYTES: usize = 1_144;

comptime {
    if (MAX_INPUT_LINE > std.math.maxInt(u8) or
        MAX_PHYSICAL_INPUT_COMMANDS > std.math.maxInt(u8))
    {
        @compileError("permission review command queue no longer fits compact metadata");
    }
    if (MAX_REVIEW_DECISIONS > std.math.maxInt(u8)) {
        @compileError("rendered permission review progress no longer fits compact metadata");
    }
}

pub const InputError = xhci.Error || input_driver_task.Error || error{ UnsupportedTextInput, InputCommandQueueFull };
pub const Error = task_runtime.Error || manifest.ValidationError || compositor_display.Error || event_ledger.Error || permission_review.SessionError || error{
    ReviewCommandTooLong,
    ReviewComplete,
    ReviewIncomplete,
    ReviewRenderTooLarge,
    ReviewTickRequired,
    ReviewWindowMissing,
};

pub const ScriptedPlanEntry = struct {
    bundle_id: []const u8,
    kind: manifest.PermissionKind,
    resource: []const u8,
    command: []const u8,
};

pub const CommandInput = struct {
    pending_line: [MAX_INPUT_LINE]u8 = [_]u8{0} ** MAX_INPUT_LINE,
    pending_line_len: u8 = 0,
    pending_commands: [MAX_PHYSICAL_INPUT_COMMANDS][MAX_INPUT_LINE]u8 =
        [_][MAX_INPUT_LINE]u8{[_]u8{0} ** MAX_INPUT_LINE} ** MAX_PHYSICAL_INPUT_COMMANDS,
    pending_command_lens: [MAX_PHYSICAL_INPUT_COMMANDS]u8 = [_]u8{0} ** MAX_PHYSICAL_INPUT_COMMANDS,
    pending_command_head: u8 = 0,
    pending_command_tail: u8 = 0,
    pending_command_count: u8 = 0,
    commands_completed: usize = 0,

    pub fn initializeAllocated(self: *CommandInput) void {
        @memset(self.pending_line[0..], 0);
        self.pending_line_len = 0;
        for (&self.pending_commands) |*command| @memset(command[0..], 0);
        @memset(self.pending_command_lens[0..], 0);
        self.pending_command_head = 0;
        self.pending_command_tail = 0;
        self.pending_command_count = 0;
        self.commands_completed = 0;
    }

    pub fn submit(self: *CommandInput, event: input_driver_task.KeyboardEvent) InputError!bool {
        switch (event.kind) {
            .text => {
                if (self.pending_line_len >= self.pending_line.len) return error.ReportTooLarge;
                self.pending_line[self.pending_line_len] = event.text;
                self.pending_line_len += 1;
            },
            .backspace => {
                if (self.pending_line_len != 0) {
                    self.pending_line_len -= 1;
                    self.pending_line[self.pending_line_len] = 0;
                }
            },
            .activate, .commit_text => {
                if (self.pending_line_len == 0) return false;
                if (self.pending_command_count == self.pending_commands.len) {
                    return error.InputCommandQueueFull;
                }
                const index = self.pending_command_tail;
                @memcpy(
                    self.pending_commands[index][0..self.pending_line_len],
                    self.pending_line[0..self.pending_line_len],
                );
                self.pending_command_lens[index] = self.pending_line_len;
                self.pending_command_tail = @intCast((@as(usize, self.pending_command_tail) + 1) % self.pending_commands.len);
                self.pending_command_count += 1;
                self.commands_completed += 1;
                self.pending_line_len = 0;
                @memset(self.pending_line[0..], 0);
                return true;
            },
            .focus_next,
            .focus_previous,
            .task_switch_next,
            .task_switch_previous,
            .show_recovery,
            .dismiss_recovery,
            => {},
        }
        return false;
    }

    pub fn take(self: *CommandInput, buffer: *[MAX_INPUT_LINE]u8) ?[]const u8 {
        if (self.pending_command_count == 0) return null;
        const index = self.pending_command_head;
        const len = self.pending_command_lens[index];
        @memcpy(buffer[0..len], self.pending_commands[index][0..len]);
        @memset(self.pending_commands[index][0..], 0);
        self.pending_command_lens[index] = 0;
        self.pending_command_head = @intCast((@as(usize, self.pending_command_head) + 1) % self.pending_commands.len);
        self.pending_command_count -= 1;
        return buffer[0..len];
    }

    comptime {
        if (@sizeOf(@This()) > COMMAND_INPUT_SIZE_CEILING_BYTES) {
            @compileError("permission review command input exceeds its compact size ceiling");
        }
    }
};

pub const ModeledInputSource = struct {
    controller: xhci.HidController,
    commands: CommandInput = .{},
    decoder: input_driver_task.Decoder = .{},
    reports_consumed: usize = 0,

    pub fn initInto(self: *ModeledInputSource, plan: xhci.RingPlan) xhci.Error!void {
        try self.controller.initInto(plan);
        self.commands.initializeAllocated();
        self.decoder = .{};
        self.reports_consumed = 0;
    }

    pub fn init(plan: xhci.RingPlan) xhci.Error!ModeledInputSource {
        var source: ModeledInputSource = undefined;
        try source.initInto(plan);
        return source;
    }

    pub fn initDefaultInto(self: *ModeledInputSource) xhci.Error!void {
        try self.controller.initWithMmioInto(
            xhci.defaultCapabilityRegisters(),
            .{
                .command_ring_trbs = 64,
                .event_ring_trbs = 64,
                .command_ring_address = 0x1000,
                .event_ring_address = 0x2000,
            },
        );
        self.commands.initializeAllocated();
        self.decoder = .{};
        self.reports_consumed = 0;
        const descriptor = xhci.bootKeyboardConfigurationDescriptor(xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
        _ = try self.controller.attachBootKeyboard(
            xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID,
            descriptor[0..],
        );
    }

    pub fn initDefault() xhci.Error!ModeledInputSource {
        var source: ModeledInputSource = undefined;
        try source.initDefaultInto();
        return source;
    }

    pub fn enqueueTextCommand(
        self: *ModeledInputSource,
        device_id: u64,
        endpoint_id: u8,
        command: []const u8,
    ) InputError!void {
        try self.drainReports();
        if (self.commands.pending_command_count == self.commands.pending_commands.len) return error.InputCommandQueueFull;
        for (command) |ch| {
            try self.enqueueAsciiKey(device_id, endpoint_id, ch);
            try self.drainReports();
        }
        try self.enqueueAsciiKey(device_id, endpoint_id, '\n');
        try self.drainReports();
    }

    pub fn takeCommand(self: *ModeledInputSource, buffer: *[MAX_INPUT_LINE]u8) ?[]const u8 {
        self.drainReports() catch return null;
        return self.commands.take(buffer);
    }

    pub fn reportCount(self: *const ModeledInputSource) usize {
        return self.reports_consumed;
    }

    pub fn commandCount(self: *const ModeledInputSource) usize {
        return self.commands.commands_completed;
    }

    pub fn queuedCommandCount(self: *const ModeledInputSource) usize {
        return @intCast(self.commands.pending_command_count);
    }

    pub fn inputProof(self: *const ModeledInputSource) ?xhci.InputProof {
        return self.controller.inputProof();
    }

    fn enqueueAsciiKey(
        self: *ModeledInputSource,
        device_id: u64,
        endpoint_id: u8,
        ch: u8,
    ) InputError!void {
        const key = hidKeyForAscii(ch) orelse return error.UnsupportedTextInput;
        try self.submitKeyboardReport(device_id, endpoint_id, try xhci.bootKeyboardReport(device_id, endpoint_id, key.modifiers, &.{key.usage}));
        try self.submitKeyboardReport(device_id, endpoint_id, try xhci.bootKeyboardReport(device_id, endpoint_id, 0, &.{}));
    }

    fn submitKeyboardReport(
        self: *ModeledInputSource,
        device_id: u64,
        endpoint_id: u8,
        report: xhci.HidReport,
    ) InputError!void {
        const boot_keyboard = self.controller.configuredBootKeyboard() orelse return error.MissingBootKeyboardInterface;
        if (boot_keyboard.device_id != device_id) return error.UnknownHidDevice;
        try self.controller.submitKeyboardInterruptEvent(boot_keyboard.slot_id, endpoint_id, report.reportSlice());
    }

    fn drainReports(self: *ModeledInputSource) InputError!void {
        while (true) {
            const report = try self.pollReport() orelse return;
            self.reports_consumed += 1;
            const decoded = try self.decoder.decode(report.report);
            var command_completed = false;
            for (decoded.slice()) |event| {
                command_completed = (try self.commands.submit(event)) or command_completed;
            }
            if (command_completed) return;
        }
    }

    fn pollReport(self: *ModeledInputSource) InputError!?xhci.HidReport {
        return self.controller.pollHidReport() catch |err| switch (err) {
            error.EventRingEmpty => null,
            else => return err,
        };
    }
};

var system_input_router: ?*input_router.Router = null;

pub fn bindSystemInputRouter(router: *input_router.Router) void {
    system_input_router = router;
}

pub fn clearSystemInputRouter() void {
    system_input_router = null;
}

const TestHardwareReportFeed = struct {
    reports: [3]xhci.HardwareBootKeyboardReport = [_]xhci.HardwareBootKeyboardReport{.{}} ** 3,
    cursor: usize = 0,
};

var test_hardware_report_feed = TestHardwareReportFeed{};

fn pollTestHardwareReport() ?xhci.HardwareBootKeyboardReport {
    if (test_hardware_report_feed.cursor == test_hardware_report_feed.reports.len) return null;
    defer test_hardware_report_feed.cursor += 1;
    return test_hardware_report_feed.reports[test_hardware_report_feed.cursor];
}

fn noTestHardwareInputProof() ?xhci.InputProof {
    return null;
}

fn testHardwareKeyboardReport(sequence: u64, usage: u8) xhci.HardwareBootKeyboardReport {
    return .{
        .sequence = sequence,
        .port_id = 2,
        .slot_id = 3,
        .interface_number = 1,
        .endpoint_id = 3,
        .vendor_id = 0x046D,
        .product_id = 0xC31C,
        .bytes = .{ 0, 0, usage, 0, 0, 0, 0, 0 },
    };
}

const HidKey = struct {
    usage: u8,
    modifiers: u8 = 0,
};

const HID_LEFT_SHIFT: u8 = 1 << 1;

fn hidKeyForAscii(ch: u8) ?HidKey {
    return switch (ch) {
        'a'...'z' => .{ .usage = 0x04 + (ch - 'a') },
        'A'...'Z' => .{ .usage = 0x04 + (ch - 'A'), .modifiers = HID_LEFT_SHIFT },
        '1'...'9' => .{ .usage = 0x1e + (ch - '1') },
        '0' => .{ .usage = 0x27 },
        '\n' => .{ .usage = 0x28 },
        8, 127 => .{ .usage = 0x2a },
        '\t' => .{ .usage = 0x2b },
        ' ' => .{ .usage = 0x2c },
        '-' => .{ .usage = 0x2d },
        '=' => .{ .usage = 0x2e },
        '[', ']', '\\', ';', '\'', '`', ',', '.', '/' => .{ .usage = switch (ch) {
            '[' => 0x2f,
            ']' => 0x30,
            '\\' => 0x31,
            ';' => 0x33,
            '\'' => 0x34,
            '`' => 0x35,
            ',' => 0x36,
            '.' => 0x37,
            '/' => 0x38,
            else => unreachable,
        } },
        '!', '@', '#', '$', '%', '^', '&', '*', '(', ')' => .{
            .usage = switch (ch) {
                '!' => 0x1e,
                '@' => 0x1f,
                '#' => 0x20,
                '$' => 0x21,
                '%' => 0x22,
                '^' => 0x23,
                '&' => 0x24,
                '*' => 0x25,
                '(' => 0x26,
                ')' => 0x27,
                else => unreachable,
            },
            .modifiers = HID_LEFT_SHIFT,
        },
        '_', '+', '{', '}', '|', ':', '"', '~', '<', '>', '?' => .{
            .usage = switch (ch) {
                '_' => 0x2d,
                '+' => 0x2e,
                '{' => 0x2f,
                '}' => 0x30,
                '|' => 0x31,
                ':' => 0x33,
                '"' => 0x34,
                '~' => 0x35,
                '<' => 0x36,
                '>' => 0x37,
                '?' => 0x38,
                else => unreachable,
            },
            .modifiers = HID_LEFT_SHIFT,
        },
        else => null,
    };
}

pub const ProfileLeaseMode = enum(u8) {
    none,
    requested,
    fixed,
};

pub const ProfileRule = struct {
    bundle_id: []const u8,
    kind: manifest.PermissionKind,
    resource: []const u8,
    allow: bool,
    local_only: bool = false,
    lease_mode: ProfileLeaseMode = .none,
    fixed_lease_ticks: manifest.LeaseTicks = 0,
};

pub const SurfaceControl = enum {
    allow,
    allow_local,
    allow_requested_lease,
    allow_local_requested_lease,
    deny,
};

pub const RenderedReviewSurface = struct {
    service: *Service,
    app_task_id: u64,
    bundle: manifest.BundleManifest,
    now_ticks: u64,
    display: *compositor_display.Framebuffer,
    ledger: ?*event_ledger.Ledger = null,
    review_window_id: ?u64 = null,
    active_index: u8 = 0,
    decision_count: u8 = 0,
    decisions: [MAX_REVIEW_DECISIONS]permission_review.ReviewDecision = [_]permission_review.ReviewDecision{.{
        .kind = .object_access,
        .resource = "",
        .allow = false,
    }} ** MAX_REVIEW_DECISIONS,

    pub fn init(
        service: *Service,
        app_task_id: u64,
        bundle: manifest.BundleManifest,
        now_ticks: u64,
        display: *compositor_display.Framebuffer,
    ) RenderedReviewSurface {
        return .{
            .service = service,
            .app_task_id = app_task_id,
            .bundle = bundle,
            .now_ticks = now_ticks,
            .display = display,
        };
    }

    pub fn bindLedger(self: *RenderedReviewSurface, ledger: *event_ledger.Ledger) void {
        self.ledger = ledger;
    }

    pub fn begin(self: *RenderedReviewSurface) Error!void {
        if (self.now_ticks == 0) return error.ReviewTickRequired;
        try manifest.validate(self.bundle);
        if (self.bundle.requested_permissions.len > self.decisions.len) return error.TooManyPermissions;
        const app_task = self.service.runtime.find(self.app_task_id) orelse return error.TaskNotFound;
        self.review_window_id = self.service.ensureReviewWindow(app_task, self.bundle) orelse return error.ReviewWindowMissing;
        app_task.appendAudit(.{
            .kind = .permission_prompted,
            .detail = @intCast(self.bundle.requested_permissions.len),
            .tick = self.now_ticks,
        });
        common.printBootMarker("ZIGOS:PERMISSION:UI:REVIEW_READY");
        common.printBootMarker("ZIGOS:PERMISSION:UI:INPUT_LOOP");
        try self.presentCurrentRequest();
        try self.render();
    }

    pub fn click(self: *RenderedReviewSurface, control: SurfaceControl) Error!void {
        if (self.review_window_id == null) return error.ReviewWindowMissing;
        const active_index: usize = self.active_index;
        const decision_count: usize = self.decision_count;
        if (active_index >= self.bundle.requested_permissions.len) return error.ReviewComplete;
        if (decision_count >= self.decisions.len) return error.ReviewComplete;

        const request = self.bundle.requested_permissions[active_index];
        const command = commandForControl(control, request);
        const decision = permission_review.decisionFromCommand(request, command);
        self.service.recordDecision(self.app_task_id, self.review_window_id, self.bundle, request, decision);
        try self.recordLedgerDecision(request, decision);
        self.decisions[decision_count] = decision;
        self.decision_count += 1;
        self.active_index += 1;
        if (@as(usize, self.active_index) < self.bundle.requested_permissions.len) {
            try self.presentCurrentRequest();
        }
        try self.render();
    }

    pub fn finish(
        self: *RenderedReviewSurface,
        output: *[MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
    ) Error![]const policy_mediation.UserGrant {
        if (self.review_window_id == null) return error.ReviewWindowMissing;
        if (@as(usize, self.active_index) < self.bundle.requested_permissions.len) return error.ReviewIncomplete;
        const reviewed_session = try permission_review.initSession(
            self.app_task_id,
            &self.bundle,
            self.decisions[0..@as(usize, self.decision_count)],
        );
        var review_buffer: [REVIEW_RENDER_BUFFER_BYTES]u8 = undefined;
        const rendered = permission_review.renderToBuffer(&review_buffer, &reviewed_session) catch return error.ReviewRenderTooLarge;
        console.print(rendered);
        common.printBootMarker(boot_markers.permission_ui_review_rendered);

        const grants = permission_review.decisionsToGrants(
            &reviewed_session,
            self.now_ticks,
            output,
        );
        try self.service.runtime.audit(self.app_task_id, .{
            .kind = .permission_reviewed,
            .detail = @intCast(grants.len),
            .tick = self.now_ticks,
        });
        try self.render();
        return grants;
    }

    pub fn render(self: *RenderedReviewSurface) Error!void {
        const compositor = self.service.compositor orelse return error.ReviewWindowMissing;
        try self.display.renderSession(compositor);
    }

    fn presentCurrentRequest(self: *RenderedReviewSurface) Error!void {
        const active_index: usize = self.active_index;
        if (active_index >= self.bundle.requested_permissions.len) return;
        self.service.presentReviewRequest(
            self.review_window_id,
            self.bundle,
            self.bundle.requested_permissions[active_index],
        );
    }

    fn recordLedgerDecision(
        self: *RenderedReviewSurface,
        request: manifest.PermissionRequest,
        decision: permission_review.ReviewDecision,
    ) Error!void {
        const ledger = self.ledger orelse return;
        const task = self.service.runtime.find(self.app_task_id) orelse return error.TaskNotFound;
        const window_id = self.review_window_id orelse return error.ReviewWindowMissing;
        const compositor = self.service.compositor orelse return error.ReviewWindowMissing;
        const item = compositor.findReviewItemConst(window_id, request.kind, request.resource) orelse return error.ReviewWindowMissing;

        var item_buffer: [REVIEW_CARD_BUFFER_BYTES]u8 = undefined;
        const rendered_item = compositor_session.renderReviewItemToBuffer(&item_buffer, window_id, item) catch return;
        try ledger.recordPermissionReview(
            task.owner,
            task.id,
            request.kind,
            decision.allow,
            self.now_ticks + @as(u64, self.decision_count) * 2,
            rendered_item,
            false,
        );

        var decision_buffer: [REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
        const rendered_decision = compositor_session.renderDecisionToBuffer(&decision_buffer, window_id, item) catch return;
        try ledger.recordPermissionDecision(
            task.owner,
            task.id,
            request.kind,
            decision.allow,
            if (decision.allow) abi.DenialReason.none else abi.DenialReason.policy_denied,
            self.now_ticks + @as(u64, self.decision_count) * 2 + 1,
            rendered_decision,
            false,
        );
    }

    comptime {
        if (@sizeOf(@This()) > RENDERED_REVIEW_SURFACE_SIZE_CEILING_BYTES) {
            @compileError("rendered permission review surface exceeds its compact size ceiling");
        }
    }
};

fn commandForControl(control: SurfaceControl, request: manifest.PermissionRequest) permission_review.ReviewCommand {
    const requested_lease = if (request.max_lease_ticks == 0) null else request.max_lease_ticks;
    return switch (control) {
        .allow => .{ .allow = true },
        .allow_local => .{ .allow = true, .local_only = true },
        .allow_requested_lease => .{
            .allow = true,
            .local_only = request.local_only,
            .lease_ticks = requested_lease,
        },
        .allow_local_requested_lease => .{
            .allow = true,
            .local_only = true,
            .lease_ticks = requested_lease,
        },
        .deny => .{ .allow = false },
    };
}

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    runtime: *task_runtime.Runtime,
    scripted_inputs: []const []const u8,
    scripted_plan: []const ScriptedPlanEntry = &.{},
    scripted_plan_used: [MAX_SCRIPTED_PLAN_ENTRIES]bool = [_]bool{false} ** MAX_SCRIPTED_PLAN_ENTRIES,
    scripted_cursor: usize = 0,
    decision_profile: []const ProfileRule = &.{},
    compositor: ?*compositor_session.Session = null,
    compositor_service: ?*compositor_session.Service = null,
    ux: ?*native_ux.Controller = null,
    modeled_input: ?*ModeledInputSource = null,
    focused_input: ?*input_router.Router = null,
    focused_commands: CommandInput = .{},

    pub fn init(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        scripted_inputs: []const []const u8,
    ) Service {
        var service = Service{
            .service_id = service_id,
            .task_id = task_id,
            .runtime = runtime,
            .scripted_inputs = scripted_inputs,
        };
        service.focused_input = system_input_router;
        return service;
    }

    pub fn initConfigured(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        scripted_inputs: []const []const u8,
        scripted_plan: []const ScriptedPlanEntry,
        compositor: ?*compositor_session.Session,
        ux: ?*native_ux.Controller,
    ) Service {
        var service = init(service_id, task_id, runtime, scripted_inputs);
        service.scripted_plan = scripted_plan[0..@min(scripted_plan.len, MAX_SCRIPTED_PLAN_ENTRIES)];
        service.compositor = compositor;
        service.ux = ux;
        return service;
    }

    pub fn bindCompositorService(self: *Service, service: *compositor_session.Service) void {
        self.compositor_service = service;
        self.compositor = service.session;
    }

    pub fn bindModeledInput(self: *Service, source: *ModeledInputSource) void {
        self.modeled_input = source;
    }

    pub fn bindFocusedInput(self: *Service, router: *input_router.Router) void {
        self.focused_input = router;
    }

    pub fn physicalInputReportCount(self: *const Service) usize {
        const focused_count = if (self.focused_input) |router| router.reports_accepted else 0;
        const modeled_count = if (self.modeled_input) |source| source.reportCount() else 0;
        return focused_count +| modeled_count;
    }

    pub fn physicalInputCommandCount(self: *const Service) usize {
        const focused_count = self.focused_commands.commands_completed;
        return focused_count + if (self.modeled_input) |source| source.commandCount() else 0;
    }

    pub fn physicalInputEventCount(self: *const Service) usize {
        const focused_count = if (self.focused_input) |router|
            if (router.inputProof()) |proof| proof.event_count else 0
        else
            0;
        const modeled_count = if (self.modeled_input) |source|
            if (source.inputProof()) |proof| proof.event_count else 0
        else
            0;
        return focused_count +| modeled_count;
    }

    pub fn initProfiled(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        scripted_inputs: []const []const u8,
        decision_profile: []const ProfileRule,
        compositor: ?*compositor_session.Session,
        ux: ?*native_ux.Controller,
    ) Service {
        var service = init(service_id, task_id, runtime, scripted_inputs);
        service.decision_profile = decision_profile;
        service.compositor = compositor;
        service.ux = ux;
        return service;
    }

    pub fn reviewBundle(
        self: *Service,
        app_task_id: u64,
        bundle: manifest.BundleManifest,
        now_ticks: u64,
        output: *[MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
    ) Error![]const policy_mediation.UserGrant {
        if (now_ticks == 0) return error.ReviewTickRequired;
        try manifest.validate(bundle);
        if (bundle.requested_permissions.len > MAX_REVIEW_DECISIONS) return error.TooManyPermissions;
        const app_task = self.runtime.find(app_task_id) orelse return error.TaskNotFound;
        const review_window_id = self.ensureReviewWindow(app_task, bundle);
        var decisions: [MAX_REVIEW_DECISIONS]permission_review.ReviewDecision = undefined;
        var decision_count: usize = 0;

        app_task.appendAudit(.{
            .kind = .permission_prompted,
            .detail = @intCast(bundle.requested_permissions.len),
            .tick = now_ticks,
        });
        common.printBootMarker("ZIGOS:PERMISSION:UI:REVIEW_READY");
        common.printBootMarker("ZIGOS:PERMISSION:UI:INPUT_LOOP");

        for (bundle.requested_permissions, 0..) |request, index| {
            if (decision_count >= decisions.len) return error.TooManyPermissions;

            self.presentReviewRequest(review_window_id, bundle, request);
            const session = try permission_review.initSession(app_task_id, &bundle, decisions[0..decision_count]);
            var prompt_buffer: [REVIEW_PROMPT_BUFFER_BYTES]u8 = undefined;
            const prompt = permission_review.renderRequestToBuffer(&prompt_buffer, &session, index) catch return error.ReviewRenderTooLarge;
            console.print(prompt);
            console.print("    command: allow [local] [lease=<ticks>] | deny (revokable later)\n");

            while (true) {
                var input_buffer: [MAX_INPUT_LINE]u8 = undefined;
                const line = self.readCommandLine(&input_buffer, bundle, request, now_ticks);
                if (line.len > MAX_INPUT_LINE) return error.ReviewCommandTooLong;
                const command = permission_review.parseCommand(line) catch {
                    console.print("    invalid command; expected allow [local] [lease=<ticks>] or deny\n");
                    continue;
                };

                decisions[decision_count] = permission_review.decisionFromCommand(request, command);
                self.recordDecision(app_task_id, review_window_id, bundle, request, decisions[decision_count]);
                decision_count += 1;
                break;
            }
        }

        const reviewed_session = try permission_review.initSession(app_task_id, &bundle, decisions[0..decision_count]);
        var review_buffer: [REVIEW_RENDER_BUFFER_BYTES]u8 = undefined;
        const rendered = permission_review.renderToBuffer(&review_buffer, &reviewed_session) catch return error.ReviewRenderTooLarge;
        console.print(rendered);
        common.printBootMarker(boot_markers.permission_ui_review_rendered);

        const grants = permission_review.decisionsToGrants(
            &reviewed_session,
            now_ticks,
            output,
        );
        app_task.appendAudit(.{
            .kind = .permission_reviewed,
            .detail = @intCast(grants.len),
            .tick = now_ticks,
        });
        return grants;
    }

    fn readCommandLine(
        self: *Service,
        buffer: *[MAX_INPUT_LINE]u8,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
        now_ticks: u64,
    ) []const u8 {
        if (self.focused_input) |router| {
            _ = router.service(now_ticks, input_router.DEFAULT_REPORT_BUDGET);
            while (router.pollForTask(self.task_id)) |routed| {
                _ = self.focused_commands.submit(routed.event) catch continue;
            }
            if (self.focused_commands.take(buffer)) |line| {
                console.print("    input> ");
                console.print(line);
                console.print("\n");
                return line;
            }
        }

        if (self.modeled_input) |source| {
            if (source.takeCommand(buffer)) |line| {
                console.print("    input> ");
                console.print(line);
                console.print("\n");
                return line;
            }
        }

        if (self.renderProfileCommand(buffer, bundle, request)) |line| {
            console.print("    input> ");
            console.print(line);
            console.print("\n");
            return line;
        }

        if (self.findPlannedCommand(bundle, request)) |line| {
            console.print("    input> ");
            console.print(line);
            console.print("\n");
            return line;
        }

        if (self.scripted_cursor < self.scripted_inputs.len) {
            const line = self.scripted_inputs[self.scripted_cursor];
            self.scripted_cursor += 1;
            console.print("    input> ");
            console.print(line);
            console.print("\n");
            return line;
        }

        console.print("    input> ");
        var length: usize = 0;
        while (true) {
            if (self.tryReadChar()) |ch| {
                switch (ch) {
                    '\r' => {},
                    '\n' => {
                        console.print("\n");
                        return buffer[0..length];
                    },
                    8, 127 => {
                        if (length > 0) {
                            length -= 1;
                        }
                    },
                    else => {
                        if (length < buffer.len) {
                            buffer[length] = ch;
                            length += 1;
                        }
                    },
                }
                continue;
            }

            x86.hlt();
        }
    }

    fn findPlannedCommand(
        self: *Service,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
    ) ?[]const u8 {
        for (self.scripted_plan, 0..) |entry, index| {
            if (index >= self.scripted_plan_used.len or self.scripted_plan_used[index]) continue;
            if (!std.mem.eql(u8, entry.bundle_id, bundle.bundle_id)) continue;
            if (entry.kind != request.kind) continue;
            if (!std.mem.eql(u8, entry.resource, request.resource)) continue;
            self.scripted_plan_used[index] = true;
            return entry.command;
        }
        return null;
    }

    fn renderProfileCommand(
        self: *const Service,
        buffer: *[MAX_INPUT_LINE]u8,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
    ) ?[]const u8 {
        for (self.decision_profile) |rule| {
            if (!std.mem.eql(u8, rule.bundle_id, bundle.bundle_id)) continue;
            if (rule.kind != request.kind) continue;
            if (!std.mem.eql(u8, rule.resource, request.resource)) continue;
            if (!rule.allow) {
                @memcpy(buffer[0..4], "deny");
                return buffer[0..4];
            }

            const lease_ticks = switch (rule.lease_mode) {
                .none => null,
                .requested => if (request.max_lease_ticks != 0) request.max_lease_ticks else null,
                .fixed => rule.fixed_lease_ticks,
            };
            if (lease_ticks) |ticks| {
                return std.fmt.bufPrint(
                    buffer,
                    "allow{s} lease={d}",
                    .{
                        if (rule.local_only) " local" else "",
                        ticks,
                    },
                ) catch null;
            }
            return std.fmt.bufPrint(
                buffer,
                "allow{s}",
                .{if (rule.local_only) " local" else ""},
            ) catch null;
        }
        return null;
    }

    fn recordDecision(
        self: *Service,
        app_task_id: u64,
        review_window_id: ?u64,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
        decision: permission_review.ReviewDecision,
    ) void {
        if (review_window_id) |window_id| {
            self.updateReviewWindow(window_id, request, decision);
        }
        if (self.compositor_service != null) return;
        const ux = self.ux orelse return;
        const task = self.runtime.find(app_task_id) orelse return;
        const flow = ux.reviewPermissionDecision(
            app_task_id,
            task.owner,
            bundle.bundle_id,
            request,
            decision.allow,
            decision.local_only,
            decision.lease_ticks,
        ) catch return;
        var buffer: [REVIEW_FLOW_BUFFER_BYTES]u8 = undefined;
        const rendered = native_ux.renderReviewFlowToBuffer(&buffer, flow) catch return;
        console.print(rendered);
        console.print("\n");
    }

    fn ensureReviewWindow(self: *Service, app_task: *const task_runtime.TaskRecord, bundle: manifest.BundleManifest) ?u64 {
        if (self.compositor_service) |service| {
            const existed = service.session.findWindowForTaskBundleConst(app_task.id, bundle.bundle_id) != null;
            const response = service.dispatch(.{
                .operation = .review_permission,
                .subject_task_id = app_task.id,
                .reviewer_task_id = self.task_id,
                .bundle_id = bundle.bundle_id,
                .display_name = bundle.display_name,
            });
            if (response.status != .ok) return null;
            const window = service.session.findWindowConst(response.window_id) orelse return response.window_id;
            if (!existed) {
                var buffer: [REVIEW_WINDOW_BUFFER_BYTES]u8 = undefined;
                const rendered = compositor_session.renderWindowToBuffer(&buffer, window) catch return window.id;
                console.print(rendered);
                console.print("\n");
            }
            return response.window_id;
        }

        const compositor = self.compositor orelse return null;
        const existed = compositor.findWindowForTaskBundleConst(app_task.id, bundle.bundle_id) != null;
        const window = compositor.beginPermissionReview(self.task_id, app_task, bundle) catch return null;
        if (!existed) {
            var buffer: [REVIEW_WINDOW_BUFFER_BYTES]u8 = undefined;
            const rendered = compositor_session.renderWindowToBuffer(&buffer, window) catch return window.id;
            console.print(rendered);
            console.print("\n");
        }
        return window.id;
    }

    fn presentReviewRequest(
        self: *Service,
        review_window_id: ?u64,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
    ) void {
        const window_id = review_window_id orelse return;
        if (self.compositor_service) |service| {
            const window = service.session.findWindowConst(window_id) orelse return;
            const response = service.dispatch(.{
                .operation = .review_permission,
                .subject_task_id = window.subject_task_id,
                .reviewer_task_id = if (window.reviewer_task_id != 0) window.reviewer_task_id else self.task_id,
                .window_id = window_id,
                .permission_kind = request.kind,
                .local_only = request.local_only,
                .required = request.required,
                .max_lease_ticks = request.max_lease_ticks,
                .bundle_id = bundle.bundle_id,
                .display_name = bundle.display_name,
                .resource = request.resource,
            });
            if (response.status != .ok) return;
            const item = service.session.findReviewItemConst(window_id, request.kind, request.resource) orelse return;
            var buffer: [REVIEW_CARD_BUFFER_BYTES]u8 = undefined;
            const rendered = compositor_session.renderReviewItemToBuffer(&buffer, window_id, item) catch return;
            console.print(rendered);
            console.print("\n");
            return;
        }

        const compositor = self.compositor orelse return;
        const item = compositor.ensureReviewItem(window_id, bundle, request) catch return;
        var buffer: [REVIEW_CARD_BUFFER_BYTES]u8 = undefined;
        const rendered = compositor_session.renderReviewItemToBuffer(&buffer, window_id, item) catch return;
        console.print(rendered);
        console.print("\n");
    }

    fn updateReviewWindow(
        self: *Service,
        window_id: u64,
        request: manifest.PermissionRequest,
        decision: permission_review.ReviewDecision,
    ) void {
        if (self.compositor_service) |service| {
            const response = service.dispatch(.{
                .operation = .record_decision,
                .window_id = window_id,
                .permission_kind = request.kind,
                .resource = request.resource,
                .allow = decision.allow,
                .local_only = decision.local_only,
                .has_lease = decision.lease_ticks != null,
                .lease_ticks = decision.lease_ticks orelse 0,
            });
            if (response.status != .ok) return;
            const item = service.session.findReviewItemConst(window_id, request.kind, request.resource) orelse return;
            var buffer: [REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
            const rendered = compositor_session.renderDecisionToBuffer(&buffer, window_id, item) catch return;
            console.print(rendered);
            console.print("\n");
            return;
        }

        const compositor = self.compositor orelse return;
        const item = compositor.recordDecision(
            window_id,
            request,
            decision.allow,
            decision.local_only,
            decision.lease_ticks,
        ) catch return;
        var buffer: [REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
        const rendered = compositor_session.renderDecisionToBuffer(&buffer, window_id, item) catch return;
        console.print(rendered);
        console.print("\n");
    }

    fn tryReadChar(self: *const Service) ?u8 {
        _ = self;
        if (serial.hasChar()) {
            return serial.getchar();
        }
        return null;
    }
};

fn createReviewTestTask(
    runtime: *task_runtime.Runtime,
    owner_serial: u64,
    ui_surface_id: ?u64,
) !*task_runtime.TaskRecord {
    return runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = owner_serial },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .ui_surface_id = ui_surface_id,
        .local_only = true,
    });
}

test "permission command queue retains its full compact capacity" {
    var input = CommandInput{};
    for (0..MAX_PHYSICAL_INPUT_COMMANDS) |_| {
        try std.testing.expect(!try input.submit(.{ .kind = .text, .text = 'a' }));
        try std.testing.expect(try input.submit(.{ .kind = .activate }));
    }

    try std.testing.expectEqual(@as(u8, MAX_PHYSICAL_INPUT_COMMANDS), input.pending_command_count);
    try std.testing.expect(!try input.submit(.{ .kind = .text, .text = 'b' }));
    try std.testing.expectError(error.InputCommandQueueFull, input.submit(.{ .kind = .activate }));

    var buffer: [MAX_INPUT_LINE]u8 = undefined;
    for (0..MAX_PHYSICAL_INPUT_COMMANDS) |_| {
        try std.testing.expectEqualStrings("a", input.take(&buffer).?);
    }
    try std.testing.expect(input.take(&buffer) == null);
    try std.testing.expectEqual(input.pending_command_head, input.pending_command_tail);
    try std.testing.expectEqual(@as(usize, COMMAND_INPUT_SIZE_CEILING_BYTES), @sizeOf(CommandInput));
}

test "review service retries invalid commands clamps leases and records audits" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 1, null);
    const scripted_inputs = [_][]const u8{
        "wat",
        "allow local lease=60",
        "deny",
    };
    var service = Service.init(9, 10, &runtime, &scripted_inputs);
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes/documents/notes.md",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 30,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.zigos.dev",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
            .egress_intent = .{
                .kind = .call_service,
                .service = "relay.zigos.dev",
            },
        },
    };
    var bundle = manifest_fixtures.basicNotesBundle(&permissions);
    bundle.signature = .{
        .format = .ed25519,
        .signer = "zigos-dev-key",
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 40, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 70), grants[0].expires_at_ticks);
    try std.testing.expectEqual(@as(usize, 2), task.audit_count);
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_prompted, task.auditEventAt(0).?.kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_reviewed, task.auditEventAt(1).?.kind);
    try std.testing.expectEqual(@as(u32, 2), task.auditEventAt(0).?.detail);
    try std.testing.expectEqual(@as(u32, 1), task.auditEventAt(1).?.detail);
}

test "review service rejects invalid manifests before auditing" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 2, null);
    const scripted_inputs = [_][]const u8{"allow"};
    var service = Service.init(11, 12, &runtime, &scripted_inputs);
    var bundle = manifest_fixtures.syncPushBundle();
    bundle.requested_permissions = &.{};
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.MissingBackgroundPermission, service.reviewBundle(task.id, bundle, 10, &grants_buffer));
    try std.testing.expectEqual(@as(usize, 0), task.audit_count);
}

test "review service rejects zero audit ticks before prompting" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 3, null);
    const scripted_inputs = [_][]const u8{"allow"};
    var service = Service.init(13, 14, &runtime, &scripted_inputs);
    const bundle = manifest_fixtures.notesBundle();
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.ReviewTickRequired, service.reviewBundle(task.id, bundle, 0, &grants_buffer));
    try std.testing.expectEqual(@as(usize, 0), task.audit_count);
}

test "review service rejects oversized scripted commands" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 4, null);
    const oversized = [_]u8{'a'} ** (MAX_INPUT_LINE + 1);
    const scripted_inputs = [_][]const u8{oversized[0..]};
    var service = Service.init(15, 16, &runtime, &scripted_inputs);
    const bundle = manifest_fixtures.notesBundle();
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.ReviewCommandTooLong, service.reviewBundle(task.id, bundle, 10, &grants_buffer));
}

test "review service refuses partial grants when visible decisions exceed capacity" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 46, null);
    var permissions: [MAX_REVIEW_DECISIONS + 1]manifest.PermissionRequest = undefined;
    const resources = [_][]const u8{
        "workspace:too-many-00",
        "workspace:too-many-01",
        "workspace:too-many-02",
        "workspace:too-many-03",
        "workspace:too-many-04",
        "workspace:too-many-05",
        "workspace:too-many-06",
        "workspace:too-many-07",
        "workspace:too-many-08",
        "workspace:too-many-09",
        "workspace:too-many-10",
        "workspace:too-many-11",
        "workspace:too-many-12",
        "workspace:too-many-13",
        "workspace:too-many-14",
        "workspace:too-many-15",
        "workspace:too-many-16",
    };
    for (&permissions, 0..) |*request, index| {
        request.* = .{
            .kind = .object_access,
            .resource = resources[index],
            .rights = .{ .object = .{ .object_read = true } },
            .local_only = true,
        };
    }
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.too-many",
        .display_name = "Too Many",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    var display_storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try compositor_display.Framebuffer.init(
        &display_storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    );
    var service = Service.init(49, 50, &runtime, &[_][]const u8{});
    var surface = RenderedReviewSurface.init(&service, task.id, bundle, 70, &display);

    try std.testing.expectError(error.TooManyPermissions, service.reviewBundle(task.id, bundle, 70, &grants_buffer));
    try std.testing.expectError(error.TooManyPermissions, surface.begin());
    try std.testing.expectEqual(@as(usize, 0), task.audit_count);
}

test "review service uses manifest-aware scripted plans through compositor service path" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 3, 33);
    const fallback_inputs = [_][]const u8{"deny"};
    const scripted_plan = [_]ScriptedPlanEntry{
        .{
            .bundle_id = "app.notes",
            .kind = .network_egress,
            .resource = "lan.sync",
            .command = "allow local lease=50",
        },
        .{
            .bundle_id = "app.notes",
            .kind = .object_access,
            .resource = "workspace:notes",
            .command = "allow local lease=400",
        },
    };
    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(13, 14, &runtime, &compositor, &checkpoint_store);
    var service = Service.initConfigured(13, 14, &runtime, &fallback_inputs, &scripted_plan, &compositor, null);
    service.bindCompositorService(&compositor_service);
    var bundle = manifest_fixtures.notesBundle();
    bundle.requested_permissions = manifest_fixtures.notes_permissions[0..2];
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 20, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 2), grants.len);
    try std.testing.expectEqual(@as(usize, 1), compositor.window_count);
    try std.testing.expectEqual(@as(usize, 2), compositor.item_count);
    const window = compositor.windowAtOrder(0).?;
    try std.testing.expectEqualStrings("Notes permission review", window.titleSlice());
    try std.testing.expectEqual(compositor_session.DecisionState.allow, compositor.findReviewItemConst(window.id, .object_access, "workspace:notes").?.decision);
    try std.testing.expectEqualStrings("lan.sync", compositor.findReviewItemConst(window.id, .network_egress, "lan.sync").?.networkPathSlice());
    try std.testing.expect(checkpoint_store.valid);
}

test "review service renders commands from a typed decision profile" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 4, 34);
    const profile = [_]ProfileRule{
        .{
            .bundle_id = "app.notes",
            .kind = .object_access,
            .resource = "workspace:notes",
            .allow = true,
            .local_only = true,
            .lease_mode = .requested,
        },
        .{
            .bundle_id = "app.notes",
            .kind = .clipboard,
            .resource = "clipboard",
            .allow = false,
        },
    };
    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(15, 16, &runtime, &compositor, &checkpoint_store);
    var service = Service.initProfiled(15, 16, &runtime, &[_][]const u8{}, profile[0..], &compositor, null);
    service.bindCompositorService(&compositor_service);
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    var bundle = manifest_fixtures.basicNotesBundle(&permissions);
    bundle.signature = .{
        .format = .ed25519,
        .signer = "zigos-dev-key",
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 25, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(@as(?u64, 425), grants[0].expires_at_ticks);
    const window = compositor.windowAtOrder(0).?;
    try std.testing.expectEqual(compositor_session.DecisionState.deny, compositor.findReviewItemConst(window.id, .clipboard, "clipboard").?.decision);
}

test "review service consumes xHCI keyboard reports for physical permission commands" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 14, 37);
    var modeled_input = try ModeledInputSource.initDefault();
    try modeled_input.enqueueTextCommand(xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, "allow local lease=25");
    try modeled_input.enqueueTextCommand(xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, "deny");

    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(17, 18, &runtime, &compositor, &checkpoint_store);
    var service = Service.init(17, 18, &runtime, &[_][]const u8{});
    service.bindCompositorService(&compositor_service);
    service.bindModeledInput(&modeled_input);

    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    var bundle = manifest_fixtures.basicNotesBundle(&permissions);
    bundle.signature = .{
        .format = .ed25519,
        .signer = "zigos-dev-key",
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 30, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 55), grants[0].expires_at_ticks);
    try std.testing.expectEqual(@as(usize, 2), service.physicalInputCommandCount());
    try std.testing.expect(service.physicalInputReportCount() >= "allow local lease=25".len + "deny".len + 2);
    try std.testing.expect(service.modeled_input.?.inputProof().?.event_count >= service.physicalInputReportCount());
    const window = compositor.windowAtOrder(0).?;
    try std.testing.expectEqual(compositor_session.DecisionState.allow, compositor.findReviewItemConst(window.id, .object_access, "workspace:notes").?.decision);
    try std.testing.expectEqual(compositor_session.DecisionState.deny, compositor.findReviewItemConst(window.id, .clipboard, "clipboard").?.decision);
}

test "permission input consumes only centrally routed events for its focused task" {
    test_hardware_report_feed = .{
        .reports = .{
            testHardwareKeyboardReport(1, 0x12),
            testHardwareKeyboardReport(2, 0x0E),
            testHardwareKeyboardReport(3, 0x28),
        },
    };
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 44, 71);
    var compositor = compositor_session.Session.init();
    const review_window = try compositor.openDocumentView(task, 1, "notes.md");
    _ = try compositor.setModalReviewer(review_window.id, 2);
    var router = input_router.Router{};
    router.bindHardwareSource(.{
        .poll_report = pollTestHardwareReport,
        .input_proof = noTestHardwareInputProof,
    });
    router.bindCompositor(&compositor, 3);
    bindSystemInputRouter(&router);
    defer clearSystemInputRouter();
    var service = Service.init(1, 2, &runtime, &.{});
    var modeled_input = try ModeledInputSource.initDefault();
    try modeled_input.enqueueTextCommand(
        xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID,
        xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID,
        "deny",
    );
    service.bindModeledInput(&modeled_input);
    try std.testing.expect(service.focused_input != null);
    var command_buffer: [MAX_INPUT_LINE]u8 = undefined;
    var bundle = manifest_fixtures.notesBundle();
    bundle.requested_permissions = manifest_fixtures.notes_permissions[0..1];
    try std.testing.expectEqualStrings(
        "ok",
        service.readCommandLine(&command_buffer, bundle, bundle.requested_permissions[0], 1),
    );
    try std.testing.expectEqual(router.reports_accepted + modeled_input.reportCount(), service.physicalInputReportCount());
    try std.testing.expectEqual(modeled_input.inputProof().?.event_count, service.physicalInputEventCount());
}

test "hosted modeled xHCI reports still count when a focused router is bound" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 14, 37);
    var modeled_input = try ModeledInputSource.initDefault();
    try modeled_input.enqueueTextCommand(xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, "allow local lease=25");
    try modeled_input.enqueueTextCommand(xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, "deny");

    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(17, 18, &runtime, &compositor, &checkpoint_store);
    var router = input_router.Router{};
    router.bindCompositor(&compositor, compositor_service.task_id);
    bindSystemInputRouter(&router);
    defer clearSystemInputRouter();

    var service = Service.init(17, 18, &runtime, &[_][]const u8{});
    service.bindCompositorService(&compositor_service);
    service.bindModeledInput(&modeled_input);
    try std.testing.expect(service.focused_input != null);

    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    var bundle = manifest_fixtures.basicNotesBundle(&permissions);
    bundle.signature = .{
        .format = .ed25519,
        .signer = "zigos-dev-key",
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 30, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(@as(usize, 2), service.physicalInputCommandCount());
    try std.testing.expect(service.physicalInputReportCount() >= "allow local lease=25".len + "deny".len + 2);
    try std.testing.expect(service.physicalInputEventCount() >= service.physicalInputReportCount());
}

test "physical input command editing honors shift punctuation and backspace" {
    var source: ModeledInputSource = undefined;
    @memset(std.mem.asBytes(&source), 0xaa);
    try source.initDefaultInto();
    try std.testing.expectEqual(@as(usize, 0), source.reports_consumed);
    try std.testing.expectEqual(@as(u8, 0), source.commands.pending_command_count);
    try std.testing.expectEqual(@as(usize, 0), source.commands.commands_completed);
    try source.enqueueTextCommand(
        xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID,
        xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID,
        "Allow_Local+1?",
    );
    try source.enqueueTextCommand(
        xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID,
        xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID,
        "denyx\x08",
    );
    var command_buffer: [MAX_INPUT_LINE]u8 = undefined;
    try std.testing.expectEqualStrings("Allow_Local+1?", source.takeCommand(&command_buffer).?);
    try std.testing.expectEqualStrings("deny", source.takeCommand(&command_buffer).?);
}

test "rendered permission review surface drives allow deny controls through compositor display and policy grants" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 44, 71);
    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(45, 46, &runtime, &compositor, &checkpoint_store);
    var service = Service.init(45, 46, &runtime, &[_][]const u8{});
    service.bindCompositorService(&compositor_service);
    var ledger = event_ledger.Ledger.init();
    var display_storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try compositor_display.Framebuffer.init(
        &display_storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    );
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:trip",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "net:trip",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
            .max_lease_ticks = 80,
            .egress_intent = .{
                .kind = .call_service,
                .service = "trip.remote",
            },
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
        .signature = .{
            .format = .ed25519,
            .signer = "zigos-dev-key",
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    var zero_tick_surface = RenderedReviewSurface.init(&service, task.id, bundle, 0, &display);
    try std.testing.expectError(error.ReviewTickRequired, zero_tick_surface.begin());
    var surface = RenderedReviewSurface.init(&service, task.id, bundle, 50, &display);
    surface.bindLedger(&ledger);
    try std.testing.expectError(error.ReviewWindowMissing, surface.click(.allow));
    try std.testing.expectError(error.ReviewWindowMissing, surface.finish(&grants_buffer));

    try surface.begin();
    try std.testing.expectEqual(@as(u8, 0), surface.active_index);
    try std.testing.expectEqual(@as(u8, 0), surface.decision_count);
    try std.testing.expect(display.containsText("active_type=app_panel"));
    try std.testing.expect(display.containsText("permission kind=object_access resource=workspace:trip"));
    try std.testing.expect(display.containsText("permission_scope object=workspace:trip network=none local=yes lease=400"));
    try std.testing.expect(display.containsText("control=allow_local_requested_lease window=1 kind=object_access resource=workspace:trip lease=400"));

    try surface.click(.allow_local_requested_lease);
    try std.testing.expectEqual(@as(u8, 1), surface.active_index);
    try std.testing.expectEqual(@as(u8, 1), surface.decision_count);
    try std.testing.expect(display.containsText("permission_decision kind=object_access resource=workspace:trip decision=allow"));
    try std.testing.expect(display.containsText("permission kind=network_egress resource=net:trip"));
    try std.testing.expect(display.containsText("permission_scope object=none network=net:trip local=no lease=80"));
    try std.testing.expect(display.containsText("control=deny window=1 kind=network_egress resource=net:trip"));

    try surface.click(.deny);
    try std.testing.expectEqual(@as(u8, 2), surface.active_index);
    try std.testing.expectEqual(@as(u8, 2), surface.decision_count);
    try std.testing.expectEqual(@as(usize, RENDERED_REVIEW_SURFACE_SIZE_CEILING_BYTES), @sizeOf(RenderedReviewSurface));
    const grants = try surface.finish(&grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 450), grants[0].expires_at_ticks);
    try std.testing.expect(display.containsText("permission_decision kind=network_egress resource=net:trip decision=deny"));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .permission_review, .task_id = task.id }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .kind = .permission_decision, .task_id = task.id }));

    var capability_table = capability.CapabilityTable.init();
    var mediator = policy_mediation.PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 45 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 45_001,
            .compositor_service_id = compositor_service.service_id,
            .policy_service_id = 45_002,
            .service_registry_id = 45_003,
        },
    );
    mediator.attachLedger(&ledger);
    const summary = try mediator.applyManifest(task.id, bundle, grants, 55);

    try std.testing.expectEqual(@as(u8, 1), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 1), summary.denied_count);
    try std.testing.expectEqual(@as(u8, 0), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    const object_decision = summary.decisionForKind(.object_access).?;
    try std.testing.expect(object_decision.allowed);
    try std.testing.expect(object_decision.local_only);
    try std.testing.expectEqual(@as(u64, 450), object_decision.expires_at_ticks);
    const object_capability = capability_table.query(object_decision.capabilityId().?).?;
    try std.testing.expect(runtime.hasCapability(task.id, object_capability.id));
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, object_capability.target.kind);
    try std.testing.expect(object_capability.rights.has(.object_read));
    try std.testing.expect(object_capability.rights.has(.object_write));
    try std.testing.expectEqual(@as(?u64, task.id), object_capability.scope.task_id);
    try std.testing.expect(object_capability.scope.local_only);
    try std.testing.expect(object_capability.scope.broker_only);
    try std.testing.expectEqual(@as(u64, 450), object_capability.lease.expires_at_ticks);
    const network_decision = summary.decisionForKind(.network_egress).?;
    try std.testing.expect(!network_decision.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, network_decision.reason);
    try std.testing.expect(network_decision.capabilityId() == null);
    try std.testing.expectEqual(@as(usize, 4), ledger.countMatching(.{ .kind = .permission_decision, .task_id = task.id }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .capability_grant, .task_id = task.id }));
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_prompted, task.auditEventAt(0).?.kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_reviewed, task.auditEventAt(1).?.kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_allowed, task.auditEventAt(2).?.kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_denied, task.auditEventAt(3).?.kind);
    try std.testing.expect(checkpoint_store.valid);
}

test "rendered permission review surface requires every visible decision before grants" {
    var runtime = task_runtime.Runtime.init();
    const task = try createReviewTestTask(&runtime, 45, 74);
    var compositor = compositor_session.Session.init();
    var checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(47, 48, &runtime, &compositor, &checkpoint_store);
    var service = Service.init(47, 48, &runtime, &[_][]const u8{});
    service.bindCompositorService(&compositor_service);
    var display_storage: [compositor_display.DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try compositor_display.Framebuffer.init(
        &display_storage,
        compositor_display.DEFAULT_WIDTH,
        compositor_display.DEFAULT_HEIGHT,
    );
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.clip",
        .display_name = "Clip",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
        .signature = .{
            .format = .ed25519,
            .signer = "zigos-dev-key",
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    var surface = RenderedReviewSurface.init(&service, task.id, bundle, 60, &display);

    try surface.begin();
    try std.testing.expect(display.containsText("control=deny window=1 kind=clipboard resource=clipboard"));
    try std.testing.expectError(error.ReviewIncomplete, surface.finish(&grants_buffer));
    try surface.click(.deny);
    const grants = try surface.finish(&grants_buffer);
    try std.testing.expectEqual(@as(usize, 0), grants.len);
    try std.testing.expectError(error.ReviewComplete, surface.click(.allow));
}
