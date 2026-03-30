const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("../task/task_runtime.zig");

const copyText = native_util.copyText;

pub const MAX_WINDOWS: usize = 8;
pub const MAX_REVIEW_ITEMS: usize = 32;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_REASON_BYTES: usize = 128;
pub const MAX_RESOURCE_BYTES: usize = 96;

pub const ViewType = enum(u8) {
    document_view,
    workspace_view,
    app_panel,
    full_screen_task_view,
};

pub const DecisionState = enum(u8) {
    pending,
    allow,
    deny,
};

pub const WindowRecord = struct {
    id: u64,
    reviewer_task_id: u64 = 0,
    subject_task_id: u64 = 0,
    ui_surface_id: ?u64 = null,
    view_type: ViewType = .app_panel,
    visible: bool = true,
    modal: bool = true,
    bundle_id_len: usize = 0,
    bundle_id: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    display_name_len: usize = 0,
    display_name: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    title_len: usize = 0,
    title: [MAX_TITLE_BYTES]u8 = [_]u8{0} ** MAX_TITLE_BYTES,
    item_count: usize = 0,

    pub fn bundleIdSlice(self: *const WindowRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn displayNameSlice(self: *const WindowRecord) []const u8 {
        return self.display_name[0..self.display_name_len];
    }

    pub fn titleSlice(self: *const WindowRecord) []const u8 {
        return self.title[0..self.title_len];
    }
};

pub const ReviewItemRecord = struct {
    window_id: u64 = 0,
    kind: manifest.PermissionKind = .object_access,
    label_len: usize = 0,
    label: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    resource_len: usize = 0,
    resource: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    reason_len: usize = 0,
    reason: [MAX_REASON_BYTES]u8 = [_]u8{0} ** MAX_REASON_BYTES,
    object_scope_len: usize = 0,
    object_scope: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    network_path_len: usize = 0,
    network_path: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    requested_local_only: bool = false,
    requested_lease_ticks: u64 = 0,
    decision: DecisionState = .pending,
    decision_local_only: bool = false,
    decision_has_lease: bool = false,
    decision_lease_ticks: u64 = 0,

    pub fn labelSlice(self: *const ReviewItemRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn resourceSlice(self: *const ReviewItemRecord) []const u8 {
        return self.resource[0..self.resource_len];
    }

    pub fn reasonSlice(self: *const ReviewItemRecord) []const u8 {
        return self.reason[0..self.reason_len];
    }

    pub fn objectScopeSlice(self: *const ReviewItemRecord) []const u8 {
        return self.object_scope[0..self.object_scope_len];
    }

    pub fn networkPathSlice(self: *const ReviewItemRecord) []const u8 {
        return self.network_path[0..self.network_path_len];
    }
};

pub const Error = error{
    WindowNotFound,
    WindowTableFull,
    ReviewItemNotFound,
    ReviewItemTableFull,
};

pub const Session = struct {
    next_window_id: u64 = 1,
    windows: [MAX_WINDOWS]WindowRecord = [_]WindowRecord{zeroWindow()} ** MAX_WINDOWS,
    window_count: usize = 0,
    items: [MAX_REVIEW_ITEMS]ReviewItemRecord = [_]ReviewItemRecord{zeroItem()} ** MAX_REVIEW_ITEMS,
    item_count: usize = 0,

    pub fn init() Session {
        return .{};
    }

    pub fn beginPermissionReview(
        self: *Session,
        reviewer_task_id: u64,
        app_task: *const task_runtime.TaskRecord,
        bundle: manifest.BundleManifest,
    ) Error!*WindowRecord {
        if (self.findWindowForTaskBundle(app_task.id, bundle.bundle_id)) |window| {
            return window;
        }
        if (self.window_count >= self.windows.len) return error.WindowTableFull;

        const window = &self.windows[self.window_count];
        window.* = zeroWindow();
        window.id = self.next_window_id;
        self.next_window_id += 1;
        window.reviewer_task_id = reviewer_task_id;
        window.subject_task_id = app_task.id;
        window.ui_surface_id = app_task.ui_surface_id;
        window.view_type = .app_panel;
        window.visible = true;
        window.modal = true;
        window.bundle_id_len = copyText(&window.bundle_id, bundle.bundle_id);
        window.display_name_len = copyText(&window.display_name, bundle.display_name);
        const title = std.fmt.bufPrint(&window.title, "{s} permission review", .{bundle.display_name}) catch
            window.title[0..copyText(&window.title, bundle.display_name)];
        window.title_len = title.len;
        self.window_count += 1;
        return window;
    }

    pub fn ensureReviewItem(
        self: *Session,
        window_id: u64,
        bundle: manifest.BundleManifest,
        request: manifest.PermissionRequest,
    ) Error!*ReviewItemRecord {
        if (self.findReviewItem(window_id, request.kind, request.resource)) |item| {
            return item;
        }
        if (self.item_count >= self.items.len) return error.ReviewItemTableFull;

        const window = self.findWindow(window_id) orelse return error.WindowNotFound;
        const item = &self.items[self.item_count];
        item.* = zeroItem();
        item.window_id = window_id;
        item.kind = request.kind;
        item.label_len = copyText(&item.label, permissionLabel(request.kind));
        item.resource_len = copyText(&item.resource, request.resource);
        item.reason_len = deriveReason(&item.reason, bundle, request);
        item.object_scope_len = deriveObjectScope(&item.object_scope, request);
        item.network_path_len = deriveNetworkPath(&item.network_path, request);
        item.requested_local_only = request.local_only;
        item.requested_lease_ticks = request.max_lease_ticks;
        self.item_count += 1;
        window.item_count += 1;
        return item;
    }

    pub fn recordDecision(
        self: *Session,
        window_id: u64,
        request: manifest.PermissionRequest,
        allow: bool,
        local_only: bool,
        lease_ticks: ?u64,
    ) Error!*ReviewItemRecord {
        const item = self.findReviewItem(window_id, request.kind, request.resource) orelse return error.ReviewItemNotFound;
        item.decision = if (allow) .allow else .deny;
        item.decision_local_only = allow and local_only;
        item.decision_has_lease = lease_ticks != null;
        item.decision_lease_ticks = lease_ticks orelse 0;
        return item;
    }

    pub fn findWindow(self: *Session, window_id: u64) ?*WindowRecord {
        for (self.windows[0..self.window_count]) |*window| {
            if (window.id == window_id) return window;
        }
        return null;
    }

    pub fn findWindowConst(self: *const Session, window_id: u64) ?*const WindowRecord {
        for (self.windows[0..self.window_count]) |*window| {
            if (window.id == window_id) return window;
        }
        return null;
    }

    pub fn findWindowForTaskBundle(self: *Session, task_id: u64, bundle_id: []const u8) ?*WindowRecord {
        for (self.windows[0..self.window_count]) |*window| {
            if (window.subject_task_id != task_id) continue;
            if (std.mem.eql(u8, window.bundleIdSlice(), bundle_id)) return window;
        }
        return null;
    }

    pub fn findWindowForTaskBundleConst(self: *const Session, task_id: u64, bundle_id: []const u8) ?*const WindowRecord {
        for (self.windows[0..self.window_count]) |*window| {
            if (window.subject_task_id != task_id) continue;
            if (std.mem.eql(u8, window.bundleIdSlice(), bundle_id)) return window;
        }
        return null;
    }

    pub fn findReviewItem(
        self: *Session,
        window_id: u64,
        kind: manifest.PermissionKind,
        resource: []const u8,
    ) ?*ReviewItemRecord {
        for (self.items[0..self.item_count]) |*item| {
            if (item.window_id != window_id) continue;
            if (item.kind != kind) continue;
            if (std.mem.eql(u8, item.resourceSlice(), resource)) return item;
        }
        return null;
    }

    pub fn findReviewItemConst(
        self: *const Session,
        window_id: u64,
        kind: manifest.PermissionKind,
        resource: []const u8,
    ) ?*const ReviewItemRecord {
        for (self.items[0..self.item_count]) |*item| {
            if (item.window_id != window_id) continue;
            if (item.kind != kind) continue;
            if (std.mem.eql(u8, item.resourceSlice(), resource)) return item;
        }
        return null;
    }
};

pub fn renderWindowToBuffer(buffer: []u8, window: *const WindowRecord) ![]const u8 {
    const surface_id = window.ui_surface_id orelse 0;
    return std.fmt.bufPrint(buffer, "UI window: id={d} surface={d} type={s} modal={s} title={s} bundle={s}", .{
        window.id,
        surface_id,
        viewTypeLabel(window.view_type),
        yesNo(window.modal),
        window.titleSlice(),
        window.bundleIdSlice(),
    });
}

pub fn renderReviewItemToBuffer(
    buffer: []u8,
    window_id: u64,
    item: *const ReviewItemRecord,
) ![]const u8 {
    const object_scope = if (item.object_scope_len == 0) "none" else item.objectScopeSlice();
    const network_path = if (item.network_path_len == 0) "none" else item.networkPathSlice();
    var used: usize = 0;
    used += (try std.fmt.bufPrint(buffer[used..], "UI card: window={d} kind={s} label={s} resource={s} why={s} object_scope={s} network_path={s} requested_local_only={s}", .{
        window_id,
        @tagName(item.kind),
        item.labelSlice(),
        item.resourceSlice(),
        item.reasonSlice(),
        object_scope,
        network_path,
        yesNo(item.requested_local_only),
    })).len;
    if (item.requested_lease_ticks != 0) {
        used += (try std.fmt.bufPrint(buffer[used..], " requested_lease={d}", .{item.requested_lease_ticks})).len;
    }
    return buffer[0..used];
}

pub fn renderDecisionToBuffer(
    buffer: []u8,
    window_id: u64,
    item: *const ReviewItemRecord,
) ![]const u8 {
    var used: usize = 0;
    used += (try std.fmt.bufPrint(buffer[used..], "UI card update: window={d} kind={s} resource={s} decision={s}", .{
        window_id,
        @tagName(item.kind),
        item.resourceSlice(),
        decisionLabel(item.decision),
    })).len;
    if (item.decision == .allow) {
        used += (try std.fmt.bufPrint(buffer[used..], " decision_local_only={s}", .{yesNo(item.decision_local_only)})).len;
        if (item.decision_has_lease) {
            used += (try std.fmt.bufPrint(buffer[used..], " decision_lease={d}", .{item.decision_lease_ticks})).len;
        }
    }
    return buffer[0..used];
}

fn deriveReason(buffer: *[MAX_REASON_BYTES]u8, bundle: manifest.BundleManifest, request: manifest.PermissionRequest) usize {
    const display_name = bundle.display_name;
    const rendered = switch (request.kind) {
        .object_access => std.fmt.bufPrint(buffer, "{s} needs access to local task objects for read and write operations", .{display_name}),
        .network_egress => std.fmt.bufPrint(buffer, "{s} needs the named network path to exchange task data", .{display_name}),
        .device_access => std.fmt.bufPrint(buffer, "{s} needs direct device access for the selected hardware target", .{display_name}),
        .clipboard => std.fmt.bufPrint(buffer, "{s} needs clipboard access to import or export user content", .{display_name}),
        .camera => std.fmt.bufPrint(buffer, "{s} needs camera access to capture video input", .{display_name}),
        .mic => std.fmt.bufPrint(buffer, "{s} needs microphone access to capture audio input", .{display_name}),
        .sensor => std.fmt.bufPrint(buffer, "{s} needs sensor access to react to local hardware state", .{display_name}),
        .location => std.fmt.bufPrint(buffer, "{s} needs location access to contextualize the current task", .{display_name}),
        .contacts => std.fmt.bufPrint(buffer, "{s} needs contacts access to address task participants", .{display_name}),
        .screen_capture => std.fmt.bufPrint(buffer, "{s} needs screen capture access to share visible task output", .{display_name}),
        .notification_post => std.fmt.bufPrint(buffer, "{s} needs notification posting to surface task progress", .{display_name}),
        .background_execution => std.fmt.bufPrint(buffer, "{s} needs background execution to finish deferred work after the foreground task", .{display_name}),
        .peer_ipc => std.fmt.bufPrint(buffer, "{s} needs local peer IPC to hand work to another trusted task", .{display_name}),
    } catch return copyText(buffer, display_name);
    return rendered.len;
}

fn deriveObjectScope(buffer: *[MAX_RESOURCE_BYTES]u8, request: manifest.PermissionRequest) usize {
    return if (request.kind == .object_access) copyText(buffer, request.resource) else 0;
}

fn deriveNetworkPath(buffer: *[MAX_RESOURCE_BYTES]u8, request: manifest.PermissionRequest) usize {
    return if (request.kind == .network_egress) copyText(buffer, request.resource) else 0;
}

fn permissionLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "Object access",
        .network_egress => "Network egress",
        .device_access => "Device access",
        .clipboard => "Clipboard",
        .camera => "Camera",
        .mic => "Microphone",
        .sensor => "Sensor",
        .location => "Location",
        .contacts => "Contacts",
        .screen_capture => "Screen capture",
        .notification_post => "Notification posting",
        .background_execution => "Background execution",
        .peer_ipc => "Peer IPC",
    };
}

fn decisionLabel(decision: DecisionState) []const u8 {
    return switch (decision) {
        .pending => "pending",
        .allow => "allow",
        .deny => "deny",
    };
}

fn viewTypeLabel(view_type: ViewType) []const u8 {
    return switch (view_type) {
        .document_view => "document_view",
        .workspace_view => "workspace_view",
        .app_panel => "app_panel",
        .full_screen_task_view => "full_screen_task_view",
    };
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn zeroWindow() WindowRecord {
    return .{ .id = 0 };
}

fn zeroItem() ReviewItemRecord {
    return .{};
}

test "compositor session creates app-panel permission review windows and cards" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 3,
        .local_only = true,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
    });
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
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

    var session = Session.init();
    const window = try session.beginPermissionReview(6, app_task, bundle);
    try std.testing.expectEqual(@as(?u64, 3), window.ui_surface_id);
    try std.testing.expectEqual(ViewType.app_panel, window.view_type);
    try std.testing.expectEqualStrings("Notes permission review", window.titleSlice());

    const object_item = try session.ensureReviewItem(window.id, bundle, permissions[0]);
    _ = try session.ensureReviewItem(window.id, bundle, permissions[1]);
    try std.testing.expectEqualStrings("workspace:notes", object_item.objectScopeSlice());
    try std.testing.expectEqual(@as(u64, 400), object_item.requested_lease_ticks);

    _ = try session.recordDecision(window.id, permissions[0], true, true, 400);
    try std.testing.expectEqual(DecisionState.allow, session.findReviewItemConst(window.id, .object_access, "workspace:notes").?.decision);

    var header_buffer: [256]u8 = undefined;
    var item_buffer: [512]u8 = undefined;
    var decision_buffer: [256]u8 = undefined;
    const header = try renderWindowToBuffer(&header_buffer, window);
    const item = try renderReviewItemToBuffer(&item_buffer, window.id, object_item);
    const decision = try renderDecisionToBuffer(&decision_buffer, window.id, object_item);

    try std.testing.expect(std.mem.indexOf(u8, header, "type=app_panel") != null);
    try std.testing.expect(std.mem.indexOf(u8, item, "why=Notes needs access to local task objects") != null);
    try std.testing.expect(std.mem.indexOf(u8, decision, "decision=allow") != null);
}

test "compositor session reuses an existing window for repeated bundle review" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 5,
        .local_only = true,
    });
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
    };

    var session = Session.init();
    const first = try session.beginPermissionReview(11, app_task, bundle);
    const second = try session.beginPermissionReview(11, app_task, bundle);

    try std.testing.expectEqual(first.id, second.id);
    try std.testing.expectEqual(@as(usize, 1), session.window_count);
}
