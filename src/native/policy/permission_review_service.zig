const std = @import("std");
const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const native_ux = @import("../platform/native_ux.zig");
const permission_review = @import("permission_review.zig");
const policy_mediation = @import("policy_mediation.zig");
const task_runtime = @import("../task/task_runtime.zig");

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
const keyboard = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/keyboard.zig")
else
    struct {
        pub fn has_char() bool {
            return false;
        }

        pub fn getchar() u8 {
            return 0;
        }
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
pub const MAX_SCRIPTED_PLAN_ENTRIES: usize = 16;
pub const Error = task_runtime.Error || manifest.ValidationError;

pub const ScriptedPlanEntry = struct {
    bundle_id: []const u8,
    kind: manifest.PermissionKind,
    resource: []const u8,
    command: []const u8,
};

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
    fixed_lease_ticks: u64 = 0,
};

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

    pub fn init(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        scripted_inputs: []const []const u8,
    ) Service {
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .runtime = runtime,
            .scripted_inputs = scripted_inputs,
        };
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
        try manifest.validate(bundle);
        const app_task = self.runtime.find(app_task_id) orelse return error.TaskNotFound;
        const review_window_id = self.ensureReviewWindow(app_task, bundle);
        var decisions: [MAX_REVIEW_DECISIONS]permission_review.ReviewDecision = undefined;
        var decision_count: usize = 0;

        try self.runtime.audit(app_task_id, .{
            .kind = .permission_prompted,
            .detail = @intCast(bundle.requested_permissions.len),
            .tick = now_ticks,
        });
        common.printBootMarker("ZIGOS:PERMISSION:UI:REVIEW_READY");
        common.printBootMarker("ZIGOS:PERMISSION:UI:INPUT_LOOP");

        for (bundle.requested_permissions, 0..) |request, index| {
            if (decision_count >= decisions.len) break;

            self.presentReviewRequest(review_window_id, bundle, request);
            const session = permission_review.initSession(app_task_id, &bundle, decisions[0..decision_count]);
            var prompt_buffer: [512]u8 = undefined;
            const prompt = permission_review.renderRequestToBuffer(&prompt_buffer, &session, &bundle, index) catch unreachable;
            console.print(prompt);
            console.print("    command: allow [local] [lease=<ticks>] | deny\n");

            while (true) {
                var input_buffer: [MAX_INPUT_LINE]u8 = undefined;
                const line = self.readCommandLine(&input_buffer, bundle, request);
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

        const reviewed_session = permission_review.initSession(app_task_id, &bundle, decisions[0..decision_count]);
        var review_buffer: [2048]u8 = undefined;
        const rendered = permission_review.renderToBuffer(&review_buffer, &reviewed_session, &bundle) catch unreachable;
        console.print(rendered);
        common.printBootMarker(boot_markers.permission_ui_review_rendered);

        const grants = permission_review.decisionsToGrants(
            &bundle,
            reviewed_session.decisions[0..reviewed_session.decision_count],
            now_ticks,
            output,
        );
        try self.runtime.audit(app_task_id, .{
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
    ) []const u8 {
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
        var buffer: [320]u8 = undefined;
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
                var buffer: [320]u8 = undefined;
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
            var buffer: [320]u8 = undefined;
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
            var buffer: [512]u8 = undefined;
            const rendered = compositor_session.renderReviewItemToBuffer(&buffer, window_id, item) catch return;
            console.print(rendered);
            console.print("\n");
            return;
        }

        const compositor = self.compositor orelse return;
        const item = compositor.ensureReviewItem(window_id, bundle, request) catch return;
        var buffer: [512]u8 = undefined;
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
            var buffer: [320]u8 = undefined;
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
        var buffer: [320]u8 = undefined;
        const rendered = compositor_session.renderDecisionToBuffer(&buffer, window_id, item) catch return;
        console.print(rendered);
        console.print("\n");
    }

    fn tryReadChar(self: *const Service) ?u8 {
        _ = self;
        if (serial.hasChar()) {
            return serial.getchar();
        }
        if (keyboard.has_char()) {
            return keyboard.getchar();
        }
        return null;
    }
};

test "review service retries invalid commands clamps leases and records audits" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
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
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-dev-key",
        },
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
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    const scripted_inputs = [_][]const u8{"allow"};
    var service = Service.init(11, 12, &runtime, &scripted_inputs);
    var bundle = manifest_fixtures.syncPushBundle();
    bundle.requested_permissions = &.{};
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.MissingBackgroundPermission, service.reviewBundle(task.id, bundle, 10, &grants_buffer));
    try std.testing.expectEqual(@as(usize, 0), task.audit_count);
}

test "review service uses manifest-aware scripted plans through compositor service path" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
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
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
    };
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
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
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
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-dev-key",
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 25, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(@as(?u64, 425), grants[0].expires_at_ticks);
    const window = compositor.windowAtOrder(0).?;
    try std.testing.expectEqual(compositor_session.DecisionState.deny, compositor.findReviewItemConst(window.id, .clipboard, "clipboard").?.decision);
}
