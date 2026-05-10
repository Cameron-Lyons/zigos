const std = @import("std");
const compositor_session = @import("compositor_session.zig");
const principal = @import("../core/principal.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const DEFAULT_WIDTH: usize = 160;
pub const DEFAULT_HEIGHT: usize = 72;
pub const DEFAULT_STORAGE_BYTES: usize = DEFAULT_WIDTH * DEFAULT_HEIGHT;
pub const MIN_WIDTH: usize = 64;
pub const MIN_HEIGHT: usize = 16;

pub const Error = error{
    ActiveWindowMissing,
    DisplayTooSmall,
    NoSpaceLeft,
};

pub const Framebuffer = struct {
    width: usize,
    height: usize,
    cells: []u8,

    pub fn init(storage: []u8, width: usize, height: usize) Error!Framebuffer {
        if (width < MIN_WIDTH or height < MIN_HEIGHT) return error.DisplayTooSmall;
        if (storage.len < width * height) return error.DisplayTooSmall;
        var framebuffer = Framebuffer{
            .width = width,
            .height = height,
            .cells = storage[0 .. width * height],
        };
        framebuffer.clear();
        return framebuffer;
    }

    pub fn clear(self: *Framebuffer) void {
        @memset(self.cells, ' ');
    }

    pub fn renderSession(self: *Framebuffer, session: *const compositor_session.Session) Error!void {
        self.clear();

        var cursor: usize = 0;
        try self.drawFmt(&cursor, "ZIGOS DISPLAY width={d} height={d} visible={d} active={d}", .{
            self.width,
            self.height,
            session.visibleWindowCount(),
            session.active_window_id,
        });
        try self.drawText(&cursor, "WINDOW STRIP");

        var visible_count: usize = 0;
        var index: usize = 0;
        while (index < session.window_count) : (index += 1) {
            const window = session.windowAtOrder(index) orelse continue;
            if (!window.visible) continue;
            visible_count += 1;
            try self.drawWindowSummary(&cursor, session, window);
        }

        if (visible_count == 0) {
            try self.drawText(&cursor, "ACTIVE none");
            return;
        }

        const active_window = session.findWindowConst(session.active_window_id) orelse return error.ActiveWindowMissing;
        try self.drawText(&cursor, "ACTIVE WINDOW");
        try self.drawActiveWindow(&cursor, active_window);
        try self.drawReviewSection(&cursor, session);
    }

    pub fn containsText(self: *const Framebuffer, needle: []const u8) bool {
        if (needle.len == 0) return true;
        var cursor: usize = 0;
        while (cursor < self.height) : (cursor += 1) {
            if (std.mem.indexOf(u8, self.rowConst(cursor), needle) != null) return true;
        }
        return false;
    }

    pub fn writeText(self: *const Framebuffer, out: []u8) Error![]const u8 {
        var used: usize = 0;
        var cursor: usize = 0;
        while (cursor < self.height) : (cursor += 1) {
            const line = trimRightSpaces(self.rowConst(cursor));
            if (used + line.len + 1 > out.len) return error.NoSpaceLeft;
            @memcpy(out[used..][0..line.len], line);
            used += line.len;
            out[used] = '\n';
            used += 1;
        }
        return out[0..used];
    }

    fn drawWindowSummary(
        self: *Framebuffer,
        cursor: *usize,
        session: *const compositor_session.Session,
        window: *const compositor_session.WindowRecord,
    ) Error!void {
        const marker = if (window.id == session.active_window_id) "active" else "visible";
        try self.drawFmt(cursor, "{s} window={d} type={s} title={s} surface={d} modal={s} workspace={d} detail={s}", .{
            marker,
            window.id,
            @tagName(window.view_type),
            window.titleSlice(),
            window.ui_surface_id orelse 0,
            yesNo(window.modal),
            window.workspace_id,
            window.detailSlice(),
        });
    }

    fn drawActiveWindow(
        self: *Framebuffer,
        cursor: *usize,
        window: *const compositor_session.WindowRecord,
    ) Error!void {
        try self.drawFmt(cursor, "active_window={d} active_type={s} title={s} surface={d} modal={s}", .{
            window.id,
            @tagName(window.view_type),
            window.titleSlice(),
            window.ui_surface_id orelse 0,
            yesNo(window.modal),
        });
        if (window.workspace_id != 0 or window.detail_len != 0) {
            try self.drawFmt(cursor, "active_content workspace={d} detail={s}", .{
                window.workspace_id,
                window.detailSlice(),
            });
        }
        if (window.bundle_id_len != 0 or window.display_name_len != 0) {
            try self.drawFmt(cursor, "active_app bundle={s} display={s}", .{
                window.bundleIdSlice(),
                window.displayNameSlice(),
            });
        }
    }

    fn drawReviewSection(
        self: *Framebuffer,
        cursor: *usize,
        session: *const compositor_session.Session,
    ) Error!void {
        var wrote_header = false;
        var window_index: usize = 0;
        while (window_index < session.window_count) : (window_index += 1) {
            const window = session.windowAtOrder(window_index) orelse continue;
            if (!window.visible or window.view_type != .app_panel or window.item_count == 0) continue;
            if (!wrote_header) {
                try self.drawText(cursor, "REVIEW CARDS");
                wrote_header = true;
            }
            try self.drawFmt(cursor, "review_window={d} bundle={s} display={s} items={d}", .{
                window.id,
                window.bundleIdSlice(),
                window.displayNameSlice(),
                window.item_count,
            });
            try self.drawReviewItems(cursor, session, window.id);
        }
    }

    fn drawReviewItems(
        self: *Framebuffer,
        cursor: *usize,
        session: *const compositor_session.Session,
        window_id: u64,
    ) Error!void {
        var item_index: usize = 0;
        while (item_index < session.item_count) : (item_index += 1) {
            const item = session.itemAtOrder(item_index) orelse continue;
            if (item.window_id != window_id) continue;
            const object_scope = if (item.object_scope_len == 0) "none" else item.objectScopeSlice();
            const network_path = if (item.network_path_len == 0) "none" else item.networkPathSlice();
            try self.drawFmt(cursor, "permission kind={s} resource={s} reason={s}", .{
                @tagName(item.kind),
                item.resourceSlice(),
                item.reasonSlice(),
            });
            try self.drawFmt(cursor, "permission_scope object={s} network={s} local={s} lease={d}", .{
                object_scope,
                network_path,
                yesNo(item.requested_local_only),
                item.requested_lease_ticks,
            });
            try self.drawFmt(cursor, "permission_decision kind={s} resource={s} decision={s} local={s} lease={d}", .{
                @tagName(item.kind),
                item.resourceSlice(),
                decisionLabel(item.decision),
                yesNo(item.decision_local_only),
                item.decision_lease_ticks,
            });
            if (item.decision == .pending) {
                try self.drawFmt(cursor, "control=allow window={d} kind={s} resource={s}", .{
                    window_id,
                    @tagName(item.kind),
                    item.resourceSlice(),
                });
                try self.drawFmt(cursor, "control=allow_local window={d} kind={s} resource={s}", .{
                    window_id,
                    @tagName(item.kind),
                    item.resourceSlice(),
                });
                if (item.requested_lease_ticks != 0) {
                    try self.drawFmt(cursor, "control=allow_local_requested_lease window={d} kind={s} resource={s} lease={d}", .{
                        window_id,
                        @tagName(item.kind),
                        item.resourceSlice(),
                        item.requested_lease_ticks,
                    });
                }
                try self.drawFmt(cursor, "control=deny window={d} kind={s} resource={s}", .{
                    window_id,
                    @tagName(item.kind),
                    item.resourceSlice(),
                });
            }
        }
    }

    fn drawText(self: *Framebuffer, cursor: *usize, text: []const u8) Error!void {
        if (cursor.* >= self.height) return error.DisplayTooSmall;
        const line = self.rowMut(cursor.*);
        const len = @min(text.len, self.width);
        @memcpy(line[0..len], text[0..len]);
        cursor.* += 1;
    }

    fn drawFmt(self: *Framebuffer, cursor: *usize, comptime fmt: []const u8, args: anytype) Error!void {
        var line_buffer: [512]u8 = undefined;
        const rendered = try std.fmt.bufPrint(&line_buffer, fmt, args);
        try self.drawText(cursor, rendered);
    }

    fn rowMut(self: *Framebuffer, index: usize) []u8 {
        return self.cells[index * self.width ..][0..self.width];
    }

    fn rowConst(self: *const Framebuffer, index: usize) []const u8 {
        return self.cells[index * self.width ..][0..self.width];
    }
};

fn trimRightSpaces(line: []const u8) []const u8 {
    var end = line.len;
    while (end != 0 and line[end - 1] == ' ') : (end -= 1) {}
    return line[0..end];
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn decisionLabel(decision: compositor_session.DecisionState) []const u8 {
    return switch (decision) {
        .pending => "pending",
        .allow => "allow",
        .deny => "deny",
    };
}

fn expectDisplayContains(display: *const Framebuffer, needle: []const u8) !void {
    if (!display.containsText(needle)) return error.ExpectedDisplayTextMissing;
}

fn makeAppTask(runtime: *task_runtime.Runtime) !*task_runtime.TaskRecord {
    return runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .app, .serial = 71 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 4096,
        },
        .ui_surface_id = 31,
        .local_only = true,
        .initial_component = .{
            .label = "trip",
            .entry = "app.trip",
        },
    });
}

test "compositor display framebuffer renders windows switching recovery and permission decisions" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try makeAppTask(&runtime);
    var session = compositor_session.Session.init();

    const document_window = try session.openDocumentView(app_task, 1_200, "trip/brief.md");
    var storage: [DEFAULT_STORAGE_BYTES]u8 = undefined;
    var display = try Framebuffer.init(&storage, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    try display.renderSession(&session);
    try expectDisplayContains(&display, "active_type=document_view");
    try expectDisplayContains(&display, "title=Document: trip/brief.md");
    try expectDisplayContains(&display, "surface=31");

    const workspace_window = try session.openWorkspaceView(app_task, 1_200, "Trip Workspace");
    try display.renderSession(&session);
    try expectDisplayContains(&display, "active_type=workspace_view");
    try expectDisplayContains(&display, "title=Workspace: Trip Workspace");

    const bundle = @import("../policy/manifest.zig").BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .publisher = "zigos.local",
    };
    const review_window = try session.beginPermissionReview(8, app_task, bundle);
    const object_request = @import("../policy/manifest.zig").PermissionRequest{
        .kind = .object_access,
        .resource = "ws:trip",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 400,
    };
    const network_request = @import("../policy/manifest.zig").PermissionRequest{
        .kind = .network_egress,
        .resource = "net:trip",
        .rights = .{ .network_policy = .{} },
        .local_only = false,
        .max_lease_ticks = 80,
    };
    _ = try session.ensureReviewItem(review_window.id, bundle, object_request);
    _ = try session.ensureReviewItem(review_window.id, bundle, network_request);
    try display.renderSession(&session);
    try expectDisplayContains(&display, "active_type=app_panel");
    try expectDisplayContains(&display, "permission kind=object_access resource=ws:trip");
    try expectDisplayContains(&display, "control=allow_local_requested_lease window=3 kind=object_access resource=ws:trip lease=400");
    try expectDisplayContains(&display, "control=deny window=3 kind=network_egress resource=net:trip");
    _ = try session.recordDecision(review_window.id, object_request, true, true, 240);
    _ = try session.recordDecision(review_window.id, network_request, false, false, null);
    try display.renderSession(&session);
    try expectDisplayContains(&display, "permission_decision kind=object_access resource=ws:trip decision=allow");
    try expectDisplayContains(&display, "permission_decision kind=network_egress resource=net:trip decision=deny");

    const task_window = try session.openTaskView(app_task, "Coordinate Trip");
    try display.renderSession(&session);
    try expectDisplayContains(&display, "active_type=full_screen_task_view");
    try expectDisplayContains(&display, "title=Coordinate Trip");

    const snapshot = session.snapshot();
    _ = try session.switchView(workspace_window.id);
    try display.renderSession(&session);
    try expectDisplayContains(&display, "active_type=workspace_view");
    try expectDisplayContains(&display, "active_window=2");

    session.reset();
    session.restore(snapshot);
    try display.renderSession(&session);
    try expectDisplayContains(&display, "type=document_view");
    try expectDisplayContains(&display, "type=workspace_view");
    try expectDisplayContains(&display, "type=app_panel");
    try expectDisplayContains(&display, "type=full_screen_task_view");
    try expectDisplayContains(&display, "permission_scope object=ws:trip network=none local=yes lease=400");
    try expectDisplayContains(&display, "permission_scope object=none network=net:trip local=no lease=80");
    try std.testing.expectEqual(document_window.id, session.windowAtOrder(0).?.id);
    try std.testing.expectEqual(task_window.id, session.active_window_id);
}

test "compositor display framebuffer rejects undersized surfaces" {
    var storage: [MIN_WIDTH * MIN_HEIGHT]u8 = undefined;
    try std.testing.expectError(error.DisplayTooSmall, Framebuffer.init(&storage, MIN_WIDTH - 1, MIN_HEIGHT));
    try std.testing.expectError(error.DisplayTooSmall, Framebuffer.init(&storage, MIN_WIDTH, MIN_HEIGHT - 1));
    try std.testing.expectError(error.DisplayTooSmall, Framebuffer.init(storage[0 .. storage.len - 1], MIN_WIDTH, MIN_HEIGHT));
}
