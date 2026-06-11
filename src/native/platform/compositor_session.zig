const std = @import("std");
const abi = @import("../core/abi.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const capability = @import("../kernel_api/capability.zig");
const humane_permissions = @import("../policy/humane_permissions.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");

const copyText = native_util.copyText;
const yesNo = native_util.yesNo;

pub const MAX_WINDOWS: usize = 8;
pub const MAX_REVIEW_ITEMS: usize = 32;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_REASON_BYTES: usize = 128;
pub const MAX_RESOURCE_BYTES: usize = 96;
pub const MAX_WINDOW_DETAIL_BYTES: usize = 96;
pub const SERVICE_ENDPOINT_BYTES: usize = abi.ENDPOINT_INLINE_BYTES;

pub const ViewType = enum(u8) {
    document_view,
    workspace_view,
    app_panel,
    full_screen_task_view,
    sync_conflict_review,
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
    workspace_id: u64 = 0,
    bundle_id_len: usize = 0,
    bundle_id: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    display_name_len: usize = 0,
    display_name: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    title_len: usize = 0,
    title: [MAX_TITLE_BYTES]u8 = [_]u8{0} ** MAX_TITLE_BYTES,
    detail_len: usize = 0,
    detail: [MAX_WINDOW_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_WINDOW_DETAIL_BYTES,
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

    pub fn detailSlice(self: *const WindowRecord) []const u8 {
        return self.detail[0..self.detail_len];
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
    TaskNotFound,
    InvalidSurface,
    MalformedRequest,
    RequestTooLarge,
    ResponseTooLarge,
    RecoveryStateMissing,
};

const WINDOW_INDEX_CAPACITY: usize = MAX_WINDOWS * 2;
const REVIEW_ITEM_INDEX_CAPACITY: usize = MAX_REVIEW_ITEMS * 2;
const WIRE_MAGIC_REQUEST = [_]u8{ 'Z', 'U', 'X', '1' };
const WIRE_MAGIC_RESPONSE = [_]u8{ 'Z', 'U', 'R', '1' };

const WindowSlot = struct {
    in_use: bool = false,
    window: WindowRecord = zeroWindow(),
};

const ReviewItemSlot = struct {
    in_use: bool = false,
    key: u64 = 0,
    item: ReviewItemRecord = zeroItem(),
};

const WindowArena = indexed_arena.IndexedArenaWithKey(u64, WindowSlot, MAX_WINDOWS, WINDOW_INDEX_CAPACITY, windowSlotId);
const ReviewItemArena = indexed_arena.IndexedArenaWithKey(u64, ReviewItemSlot, MAX_REVIEW_ITEMS, REVIEW_ITEM_INDEX_CAPACITY, reviewItemSlotKey);
const TaskBundleIndex = indexed_arena.UniqueIndex(WINDOW_INDEX_CAPACITY);

pub const Operation = enum(u8) {
    open_view = 1,
    switch_view = 2,
    review_permission = 3,
    record_decision = 4,
    recover_state = 5,
    close_task_windows = 6,
};

pub const ServiceStatus = enum(u8) {
    ok = 0,
    not_found = 1,
    table_full = 2,
    invalid_request = 3,
    recovery_missing = 4,
};

pub const ServiceRequest = struct {
    operation: Operation,
    view_type: ViewType = .document_view,
    permission_kind: manifest.PermissionKind = .object_access,
    allow: bool = false,
    local_only: bool = false,
    required: bool = true,
    has_lease: bool = false,
    subject_task_id: u64 = 0,
    reviewer_task_id: u64 = 0,
    window_id: u64 = 0,
    workspace_id: u64 = 0,
    lease_ticks: u64 = 0,
    max_lease_ticks: u64 = 0,
    bundle_id: []const u8 = "",
    display_name: []const u8 = "",
    resource: []const u8 = "",
    detail: []const u8 = "",
    egress_intent: manifest.DataEgressIntent = .{},
};

pub const ServiceResponse = struct {
    operation: Operation,
    status: ServiceStatus = .ok,
    decision: DecisionState = .pending,
    recovered: bool = false,
    window_id: u64 = 0,
    active_window_id: u64 = 0,
    visible_window_count: u16 = 0,
    review_item_count: u16 = 0,
};

pub const SessionSnapshot = struct {
    next_window_id: u64 = 1,
    active_window_id: u64 = 0,
    windows: WindowArena = WindowArena.init(),
    window_order: [MAX_WINDOWS]u64 = [_]u64{0} ** MAX_WINDOWS,
    window_count: usize = 0,
    items: ReviewItemArena = ReviewItemArena.init(),
    item_order: [MAX_REVIEW_ITEMS]u64 = [_]u64{0} ** MAX_REVIEW_ITEMS,
    item_count: usize = 0,
    task_bundle_index: TaskBundleIndex = TaskBundleIndex.init(),
};

pub const CheckpointStore = struct {
    valid: bool = false,
    snapshot: SessionSnapshot = .{},

    pub fn reset(self: *CheckpointStore) void {
        self.* = .{};
    }
};

pub const Session = struct {
    next_window_id: u64 = 1,
    active_window_id: u64 = 0,
    windows: WindowArena = WindowArena.init(),
    window_order: [MAX_WINDOWS]u64 = [_]u64{0} ** MAX_WINDOWS,
    window_count: usize = 0,
    items: ReviewItemArena = ReviewItemArena.init(),
    item_order: [MAX_REVIEW_ITEMS]u64 = [_]u64{0} ** MAX_REVIEW_ITEMS,
    item_count: usize = 0,
    task_bundle_index: TaskBundleIndex = TaskBundleIndex.init(),

    pub fn init() Session {
        return .{};
    }

    pub fn reset(self: *Session) void {
        self.* = init();
    }

    pub fn beginPermissionReview(
        self: *Session,
        reviewer_task_id: u64,
        app_task: *const task_runtime.TaskRecord,
        bundle: manifest.BundleManifest,
    ) Error!*WindowRecord {
        const surface_id = try requireTaskSurface(app_task);
        if (self.findWindowForTaskBundle(app_task.id, bundle.bundle_id)) |window| {
            return window;
        }

        const window = try self.allocateWindow();
        window.reviewer_task_id = reviewer_task_id;
        window.subject_task_id = app_task.id;
        window.ui_surface_id = surface_id;
        window.view_type = .app_panel;
        window.visible = true;
        window.modal = true;
        window.bundle_id_len = copyText(&window.bundle_id, bundle.bundle_id);
        window.display_name_len = copyText(&window.display_name, bundle.display_name);
        const title = std.fmt.bufPrint(&window.title, "{s} permission review", .{bundle.display_name}) catch
            window.title[0..copyText(&window.title, bundle.display_name)];
        window.title_len = title.len;
        self.indexWindowForTaskBundle(window);
        self.active_window_id = window.id;
        return window;
    }

    pub fn openDocumentView(
        self: *Session,
        app_task: *const task_runtime.TaskRecord,
        workspace_id: u64,
        path: []const u8,
    ) Error!*WindowRecord {
        return self.createWindow(.document_view, app_task, workspace_id, "", "", "Document", path, false);
    }

    pub fn openWorkspaceView(
        self: *Session,
        app_task: *const task_runtime.TaskRecord,
        workspace_id: u64,
        label: []const u8,
    ) Error!*WindowRecord {
        return self.createWindow(.workspace_view, app_task, workspace_id, "", "", "Workspace", label, false);
    }

    pub fn openTaskView(
        self: *Session,
        app_task: *const task_runtime.TaskRecord,
        title: []const u8,
    ) Error!*WindowRecord {
        return self.createWindow(.full_screen_task_view, app_task, 0, "", "", title, "", false);
    }

    pub fn openSyncConflictReview(
        self: *Session,
        app_task: *const task_runtime.TaskRecord,
        workspace_id: u64,
        detail: []const u8,
    ) Error!*WindowRecord {
        return self.createWindow(.sync_conflict_review, app_task, workspace_id, "", "", "Sync conflicts", detail, true);
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
        const window = self.findWindow(window_id) orelse return error.WindowNotFound;

        const key = reviewItemKey(window_id, request.kind, request.resource);
        const slot_index = self.items.reserveIndex(key) orelse return error.ReviewItemTableFull;
        const slot = &self.items.slots[slot_index];
        slot.key = key;
        const item = &slot.item;
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
        self.item_order[self.item_count] = key;
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
        const slot = self.windows.get(window_id) orelse return null;
        return &slot.window;
    }

    pub fn findWindowConst(self: *const Session, window_id: u64) ?*const WindowRecord {
        const slot = self.windows.getConst(window_id) orelse return null;
        return &slot.window;
    }

    pub fn findWindowForTaskBundle(self: *Session, task_id: u64, bundle_id: []const u8) ?*WindowRecord {
        const key = taskBundleKey(task_id, bundle_id);
        const slot = self.windows.findByUniqueIndex(&self.task_bundle_index, key, .{
            .task_id = task_id,
            .bundle_id = bundle_id,
        }, taskBundleMatches) orelse return null;
        return &slot.window;
    }

    pub fn findWindowForTaskBundleConst(self: *const Session, task_id: u64, bundle_id: []const u8) ?*const WindowRecord {
        const key = taskBundleKey(task_id, bundle_id);
        const slot = self.windows.findConstByUniqueIndex(&self.task_bundle_index, key, .{
            .task_id = task_id,
            .bundle_id = bundle_id,
        }, taskBundleMatches) orelse return null;
        return &slot.window;
    }

    pub fn probeVisibleWindow(self: *const Session, buffer: []u8) bool {
        for (self.window_order[0..self.window_count]) |window_id| {
            const window = self.findWindowConst(window_id) orelse continue;
            if (!window.visible) continue;
            _ = renderWindowToBuffer(buffer, window) catch return false;
            return true;
        }
        return false;
    }

    pub fn findReviewItem(
        self: *Session,
        window_id: u64,
        kind: manifest.PermissionKind,
        resource: []const u8,
    ) ?*ReviewItemRecord {
        const key = reviewItemKey(window_id, kind, resource);
        const slot = self.items.get(key) orelse return null;
        if (!reviewItemMatches(.{ .window_id = window_id, .kind = kind, .resource = resource }, slot)) return null;
        return &slot.item;
    }

    pub fn findReviewItemConst(
        self: *const Session,
        window_id: u64,
        kind: manifest.PermissionKind,
        resource: []const u8,
    ) ?*const ReviewItemRecord {
        const key = reviewItemKey(window_id, kind, resource);
        const slot = self.items.getConst(key) orelse return null;
        if (!reviewItemMatches(.{ .window_id = window_id, .kind = kind, .resource = resource }, slot)) return null;
        return &slot.item;
    }

    pub fn windowAtOrder(self: *const Session, index: usize) ?*const WindowRecord {
        if (index >= self.window_count) return null;
        return self.findWindowConst(self.window_order[index]);
    }

    pub fn itemAtOrder(self: *const Session, index: usize) ?*const ReviewItemRecord {
        if (index >= self.item_count) return null;
        const slot = self.items.getConst(self.item_order[index]) orelse return null;
        return &slot.item;
    }

    pub fn visibleWindowCount(self: *const Session) usize {
        var count: usize = 0;
        for (self.window_order[0..self.window_count]) |window_id| {
            const window = self.findWindowConst(window_id) orelse continue;
            if (window.visible) count += 1;
        }
        return count;
    }

    pub fn closeWindowsForTask(self: *Session, task_id: u64) usize {
        if (task_id == 0) return 0;

        var closed: usize = 0;
        var order_index: usize = 0;
        while (order_index < self.window_count) {
            const window_id = self.window_order[order_index];
            const window = self.findWindow(window_id) orelse {
                self.removeWindowOrderAt(order_index);
                continue;
            };
            if (window.subject_task_id != task_id) {
                order_index += 1;
                continue;
            }

            self.removeReviewItemsForWindow(window.id);
            if (window.bundle_id_len != 0) {
                self.task_bundle_index.remove(taskBundleKey(window.subject_task_id, window.bundleIdSlice()));
            }
            _ = self.windows.remove(window.id);
            self.removeWindowOrderAt(order_index);
            closed += 1;
        }

        if (self.findWindowConst(self.active_window_id) == null) {
            self.active_window_id = self.firstVisibleWindowId();
        }
        return closed;
    }

    pub fn switchView(self: *Session, window_id: u64) Error!*WindowRecord {
        const window = self.findWindow(window_id) orelse return error.WindowNotFound;
        window.visible = true;
        self.active_window_id = window.id;
        return window;
    }

    pub fn snapshot(self: *const Session) SessionSnapshot {
        return .{
            .next_window_id = self.next_window_id,
            .active_window_id = self.active_window_id,
            .windows = self.windows,
            .window_order = self.window_order,
            .window_count = self.window_count,
            .items = self.items,
            .item_order = self.item_order,
            .item_count = self.item_count,
            .task_bundle_index = self.task_bundle_index,
        };
    }

    pub fn restore(self: *Session, stored: SessionSnapshot) void {
        self.next_window_id = stored.next_window_id;
        self.active_window_id = stored.active_window_id;
        self.windows = stored.windows;
        self.window_order = stored.window_order;
        self.window_count = stored.window_count;
        self.items = stored.items;
        self.item_order = stored.item_order;
        self.item_count = stored.item_count;
        self.task_bundle_index = stored.task_bundle_index;
    }

    fn createWindow(
        self: *Session,
        view_type: ViewType,
        app_task: *const task_runtime.TaskRecord,
        workspace_id: u64,
        bundle_id: []const u8,
        display_name: []const u8,
        title_prefix: []const u8,
        detail: []const u8,
        modal: bool,
    ) Error!*WindowRecord {
        const surface_id = try requireTaskSurface(app_task);
        const window = try self.allocateWindow();
        window.subject_task_id = app_task.id;
        window.ui_surface_id = surface_id;
        window.view_type = view_type;
        window.visible = true;
        window.modal = modal;
        window.workspace_id = workspace_id;
        window.bundle_id_len = copyText(&window.bundle_id, bundle_id);
        window.display_name_len = copyText(&window.display_name, display_name);
        window.title_len = deriveWindowTitle(&window.title, title_prefix, detail);
        window.detail_len = copyText(&window.detail, detail);
        self.active_window_id = window.id;
        return window;
    }

    fn allocateWindow(self: *Session) Error!*WindowRecord {
        const window_id = self.next_window_id;
        const slot_index = self.windows.reserveIndex(window_id) orelse return error.WindowTableFull;
        self.next_window_id += 1;
        const slot = &self.windows.slots[slot_index];
        slot.window = zeroWindow();
        slot.window.id = window_id;
        self.window_order[self.window_count] = window_id;
        self.window_count += 1;
        return &slot.window;
    }

    fn indexWindowForTaskBundle(self: *Session, window: *const WindowRecord) void {
        if (window.subject_task_id == 0 or window.bundle_id_len == 0) return;
        self.task_bundle_index.insert(taskBundleKey(window.subject_task_id, window.bundleIdSlice()), self.windows.slotIndexOf(window.id).?);
    }

    fn removeReviewItemsForWindow(self: *Session, window_id: u64) void {
        var order_index: usize = 0;
        while (order_index < self.item_count) {
            const key = self.item_order[order_index];
            const slot = self.items.get(key) orelse {
                self.removeItemOrderAt(order_index);
                continue;
            };
            if (slot.item.window_id != window_id) {
                order_index += 1;
                continue;
            }

            _ = self.items.remove(key);
            self.removeItemOrderAt(order_index);
        }
    }

    fn removeWindowOrderAt(self: *Session, order_index: usize) void {
        if (order_index >= self.window_count) return;
        var index = order_index;
        while (index + 1 < self.window_count) : (index += 1) {
            self.window_order[index] = self.window_order[index + 1];
        }
        self.window_count -= 1;
        self.window_order[self.window_count] = 0;
    }

    fn removeItemOrderAt(self: *Session, order_index: usize) void {
        if (order_index >= self.item_count) return;
        var index = order_index;
        while (index + 1 < self.item_count) : (index += 1) {
            self.item_order[index] = self.item_order[index + 1];
        }
        self.item_count -= 1;
        self.item_order[self.item_count] = 0;
    }

    fn firstVisibleWindowId(self: *const Session) u64 {
        for (self.window_order[0..self.window_count]) |window_id| {
            const window = self.findWindowConst(window_id) orelse continue;
            if (window.visible) return window.id;
        }
        return 0;
    }
};

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    runtime: *task_runtime.Runtime,
    session: *Session,
    checkpoint_store: ?*CheckpointStore = null,

    pub fn init(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        session: *Session,
    ) Service {
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .runtime = runtime,
            .session = session,
        };
    }

    pub fn initWithCheckpoint(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        session: *Session,
        checkpoint_store: *CheckpointStore,
    ) Service {
        var service = init(service_id, task_id, runtime, session);
        service.checkpoint_store = checkpoint_store;
        return service;
    }

    pub fn dispatch(self: *Service, request: ServiceRequest) ServiceResponse {
        var response = ServiceResponse{
            .operation = request.operation,
            .active_window_id = self.session.active_window_id,
            .visible_window_count = @intCast(self.session.visibleWindowCount()),
            .review_item_count = @intCast(self.session.item_count),
        };

        self.apply(request, &response) catch |err| {
            response.status = statusForError(err);
            return response;
        };

        if (request.operation != .recover_state) {
            self.checkpoint();
        }
        response.active_window_id = self.session.active_window_id;
        response.visible_window_count = @intCast(self.session.visibleWindowCount());
        response.review_item_count = @intCast(self.session.item_count);
        return response;
    }

    pub fn dispatchPayload(self: *Service, payload: []const u8, out: []u8) Error![]const u8 {
        const request = try decodeRequest(payload);
        const response = self.dispatch(request);
        return encodeResponse(out, response);
    }

    fn apply(self: *Service, request: ServiceRequest, response: *ServiceResponse) Error!void {
        switch (request.operation) {
            .open_view => {
                const task = self.runtime.find(request.subject_task_id) orelse return error.TaskNotFound;
                const window = try self.session.createWindow(
                    request.view_type,
                    task,
                    request.workspace_id,
                    request.bundle_id,
                    request.display_name,
                    titlePrefixForView(request.view_type),
                    request.detail,
                    request.view_type == .app_panel or request.view_type == .sync_conflict_review,
                );
                response.window_id = window.id;
            },
            .switch_view => {
                const window = try self.session.switchView(request.window_id);
                response.window_id = window.id;
            },
            .review_permission => {
                const task = self.runtime.find(request.subject_task_id) orelse return error.TaskNotFound;
                const bundle = manifest.BundleManifest{
                    .bundle_id = request.bundle_id,
                    .display_name = request.display_name,
                    .publisher = "zigos.local",
                };
                const permission = permissionRequestFromService(request);
                const window = try self.session.beginPermissionReview(request.reviewer_task_id, task, bundle);
                if (request.resource.len != 0) {
                    _ = try self.session.ensureReviewItem(window.id, bundle, permission);
                }
                response.window_id = window.id;
            },
            .record_decision => {
                const permission = permissionRequestFromService(request);
                const item = try self.session.recordDecision(
                    request.window_id,
                    permission,
                    request.allow,
                    request.local_only,
                    if (request.has_lease) request.lease_ticks else null,
                );
                response.window_id = request.window_id;
                response.decision = item.decision;
            },
            .recover_state => {
                const store = self.checkpoint_store orelse return error.RecoveryStateMissing;
                if (!store.valid) return error.RecoveryStateMissing;
                self.session.restore(store.snapshot);
                response.recovered = true;
            },
            .close_task_windows => {
                _ = self.session.closeWindowsForTask(request.subject_task_id);
            },
        }
    }

    fn checkpoint(self: *Service) void {
        const store = self.checkpoint_store orelse return;
        store.snapshot = self.session.snapshot();
        store.valid = true;
    }
};

pub fn encodeRequest(buffer: []u8, request: ServiceRequest) Error![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &WIRE_MAGIC_REQUEST);
    try writeByte(buffer, &used, @intFromEnum(request.operation));
    try writeByte(buffer, &used, @intFromEnum(request.view_type));
    try writeByte(buffer, &used, @intFromEnum(request.permission_kind));
    try writeByte(buffer, &used, requestFlags(request));
    try writeU64(buffer, &used, request.subject_task_id);
    try writeU64(buffer, &used, request.reviewer_task_id);
    try writeU64(buffer, &used, request.window_id);
    try writeU64(buffer, &used, request.workspace_id);
    try writeU64(buffer, &used, request.lease_ticks);
    try writeU64(buffer, &used, request.max_lease_ticks);
    try writeText(buffer, &used, request.bundle_id);
    try writeText(buffer, &used, request.display_name);
    try writeText(buffer, &used, request.resource);
    try writeText(buffer, &used, request.detail);
    try writeByte(buffer, &used, @intFromEnum(request.egress_intent.kind));
    try writeText(buffer, &used, request.egress_intent.object);
    try writeText(buffer, &used, request.egress_intent.principal);
    try writeText(buffer, &used, request.egress_intent.service);
    try writeText(buffer, &used, request.egress_intent.event_type);
    return buffer[0..used];
}

pub fn decodeRequest(payload: []const u8) Error!ServiceRequest {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &WIRE_MAGIC_REQUEST)) return error.MalformedRequest;
    const operation = std.enums.fromInt(Operation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const view_type = std.enums.fromInt(ViewType, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const permission_kind = std.enums.fromInt(manifest.PermissionKind, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const flags = try readByte(payload, &cursor);
    const subject_task_id = try readU64(payload, &cursor);
    const reviewer_task_id = try readU64(payload, &cursor);
    const window_id = try readU64(payload, &cursor);
    const workspace_id = try readU64(payload, &cursor);
    const lease_ticks = try readU64(payload, &cursor);
    const max_lease_ticks = try readU64(payload, &cursor);
    const bundle_id = try readText(payload, &cursor);
    const display_name = try readText(payload, &cursor);
    const resource = try readText(payload, &cursor);
    const detail = try readText(payload, &cursor);
    const egress_intent_kind = std.enums.fromInt(manifest.DataEgressIntentKind, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const egress_intent_object = try readText(payload, &cursor);
    const egress_intent_principal = try readText(payload, &cursor);
    const egress_intent_service = try readText(payload, &cursor);
    const egress_intent_event_type = try readText(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .view_type = view_type,
        .permission_kind = permission_kind,
        .allow = (flags & 0x01) != 0,
        .local_only = (flags & 0x02) != 0,
        .required = (flags & 0x04) != 0,
        .has_lease = (flags & 0x08) != 0,
        .subject_task_id = subject_task_id,
        .reviewer_task_id = reviewer_task_id,
        .window_id = window_id,
        .workspace_id = workspace_id,
        .lease_ticks = lease_ticks,
        .max_lease_ticks = max_lease_ticks,
        .bundle_id = bundle_id,
        .display_name = display_name,
        .resource = resource,
        .detail = detail,
        .egress_intent = .{
            .kind = egress_intent_kind,
            .object = egress_intent_object,
            .principal = egress_intent_principal,
            .service = egress_intent_service,
            .event_type = egress_intent_event_type,
        },
    };
}

pub fn encodeResponse(buffer: []u8, response: ServiceResponse) Error![]const u8 {
    var used: usize = 0;
    try writeBytes(buffer, &used, &WIRE_MAGIC_RESPONSE);
    try writeByte(buffer, &used, @intFromEnum(response.operation));
    try writeByte(buffer, &used, @intFromEnum(response.status));
    try writeByte(buffer, &used, @intFromEnum(response.decision));
    try writeByte(buffer, &used, if (response.recovered) 1 else 0);
    try writeU64(buffer, &used, response.window_id);
    try writeU64(buffer, &used, response.active_window_id);
    try writeU16(buffer, &used, response.visible_window_count);
    try writeU16(buffer, &used, response.review_item_count);
    return buffer[0..used];
}

pub fn decodeResponse(payload: []const u8) Error!ServiceResponse {
    var cursor: usize = 0;
    if (!std.mem.eql(u8, try readBytes(payload, &cursor, 4), &WIRE_MAGIC_RESPONSE)) return error.MalformedRequest;
    const operation = std.enums.fromInt(Operation, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const status = std.enums.fromInt(ServiceStatus, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const decision = std.enums.fromInt(DecisionState, try readByte(payload, &cursor)) orelse return error.MalformedRequest;
    const recovered = (try readByte(payload, &cursor)) != 0;
    const window_id = try readU64(payload, &cursor);
    const active_window_id = try readU64(payload, &cursor);
    const visible_window_count = try readU16(payload, &cursor);
    const review_item_count = try readU16(payload, &cursor);
    if (cursor != payload.len) return error.MalformedRequest;
    return .{
        .operation = operation,
        .status = status,
        .decision = decision,
        .recovered = recovered,
        .window_id = window_id,
        .active_window_id = active_window_id,
        .visible_window_count = visible_window_count,
        .review_item_count = review_item_count,
    };
}

pub fn renderWindowToBuffer(buffer: []u8, window: *const WindowRecord) ![]const u8 {
    const surface_id = window.ui_surface_id orelse 0;
    var used: usize = 0;
    used += (try std.fmt.bufPrint(buffer[used..], "UI window: id={d} surface={d} type={s} modal={s} title={s} bundle={s} display={s}", .{
        window.id,
        surface_id,
        viewTypeLabel(window.view_type),
        yesNo(window.modal),
        window.titleSlice(),
        window.bundleIdSlice(),
        window.displayNameSlice(),
    })).len;
    if (window.workspace_id != 0) {
        used += (try std.fmt.bufPrint(buffer[used..], " workspace={d}", .{window.workspace_id})).len;
    }
    if (window.detail_len != 0) {
        used += (try std.fmt.bufPrint(buffer[used..], " detail={s}", .{window.detailSlice()})).len;
    }
    return buffer[0..used];
}

pub fn renderReviewItemToBuffer(
    buffer: []u8,
    window_id: u64,
    item: *const ReviewItemRecord,
) ![]const u8 {
    const object_scope = if (item.object_scope_len == 0) "none" else item.objectScopeSlice();
    const network_path = if (item.network_path_len == 0) "none" else item.networkPathSlice();
    const data_leaves = if (item.kind == .network_egress and item.network_path_len != 0)
        network_path
    else
        "none";
    var used: usize = 0;
    used += (try std.fmt.bufPrint(buffer[used..], "UI card: window={d} kind={s} label={s} resource={s} why={s} object_scope={s} network_path={s} data_leaves={s} requested_local_only={s}", .{
        window_id,
        @tagName(item.kind),
        item.labelSlice(),
        item.resourceSlice(),
        item.reasonSlice(),
        object_scope,
        network_path,
        data_leaves,
        yesNo(item.requested_local_only),
    })).len;
    if (item.requested_lease_ticks != 0) {
        used += (try std.fmt.bufPrint(buffer[used..], " requested_lease={d}", .{item.requested_lease_ticks})).len;
    }
    var lease_buffer: [96]u8 = undefined;
    const lease_summary = humane_permissions.requestedLeaseLabel(&lease_buffer, item.requested_lease_ticks) catch "unavailable";
    used += (try std.fmt.bufPrint(buffer[used..], " grant_scope={s} lease_summary={s} revoke_hint={s}", .{
        humane_permissions.scopeSummaryLabel(item.kind, item.requested_local_only),
        lease_summary,
        humane_permissions.revocationHint(item.kind),
    })).len;
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
        used += (try std.fmt.bufPrint(buffer[used..], " revoke_hint={s}", .{humane_permissions.revocationHint(item.kind)})).len;
    }
    return buffer[0..used];
}

fn windowSlotId(slot: *const WindowSlot) u64 {
    return slot.window.id;
}

fn reviewItemSlotKey(slot: *const ReviewItemSlot) u64 {
    return slot.key;
}

fn taskBundleKey(task_id: u64, bundle_id: []const u8) u64 {
    var hash = native_util.fnv1a64AppendU64LittleEndian(native_util.FNV1A_64_OFFSET_BASIS, task_id);
    hash = native_util.fnv1a64WithSeed(hash, bundle_id);
    return indexed_arena.nonZeroKey(hash);
}

fn taskBundleMatches(context: anytype, slot: *const WindowSlot) bool {
    return slot.window.reviewer_task_id != 0 and
        slot.window.subject_task_id == context.task_id and
        std.mem.eql(u8, slot.window.bundleIdSlice(), context.bundle_id);
}

fn reviewItemKey(window_id: u64, kind: manifest.PermissionKind, resource: []const u8) u64 {
    var hash = native_util.fnv1a64AppendU64LittleEndian(native_util.FNV1A_64_OFFSET_BASIS, window_id);
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(kind));
    hash = native_util.fnv1a64WithSeed(hash, resource);
    return indexed_arena.nonZeroKey(hash);
}

fn reviewItemMatches(context: anytype, slot: anytype) bool {
    return slot.item.window_id == context.window_id and
        slot.item.kind == context.kind and
        std.mem.eql(u8, slot.item.resourceSlice(), context.resource);
}

fn permissionRequestFromService(request: ServiceRequest) manifest.PermissionRequest {
    return .{
        .kind = request.permission_kind,
        .resource = request.resource,
        .rights = emptyRightsForKind(request.permission_kind),
        .required = request.required,
        .local_only = request.local_only,
        .max_lease_ticks = request.max_lease_ticks,
        .egress_intent = request.egress_intent,
    };
}

fn emptyRightsForKind(kind: manifest.PermissionKind) capability.CapabilityRights {
    return switch (kind) {
        .object_access, .contacts => .{ .object = .{} },
        .network_egress => .{ .network_policy = .{} },
        .device_access, .camera, .mic, .sensor, .location, .screen_capture => .{ .device = .{} },
        .clipboard => .{ .workspace = .{} },
        .notification_post, .background_execution => .{ .task = .{} },
        .peer_ipc => .{ .endpoint = .{} },
    };
}

fn titlePrefixForView(view_type: ViewType) []const u8 {
    return switch (view_type) {
        .document_view => "Document",
        .workspace_view => "Workspace",
        .app_panel => "Panel",
        .full_screen_task_view => "Task",
        .sync_conflict_review => "Sync conflicts",
    };
}

fn statusForError(err: Error) ServiceStatus {
    return switch (err) {
        error.WindowNotFound, error.ReviewItemNotFound, error.TaskNotFound => .not_found,
        error.WindowTableFull, error.ReviewItemTableFull => .table_full,
        error.RecoveryStateMissing => .recovery_missing,
        error.InvalidSurface, error.MalformedRequest, error.RequestTooLarge, error.ResponseTooLarge => .invalid_request,
    };
}

fn requireTaskSurface(app_task: *const task_runtime.TaskRecord) Error!u64 {
    const surface_id = app_task.ui_surface_id orelse return error.InvalidSurface;
    if (surface_id == 0) return error.InvalidSurface;
    return surface_id;
}

fn requestFlags(request: ServiceRequest) u8 {
    var flags: u8 = 0;
    if (request.allow) flags |= 0x01;
    if (request.local_only) flags |= 0x02;
    if (request.required) flags |= 0x04;
    if (request.has_lease) flags |= 0x08;
    return flags;
}

fn writeByte(buffer: []u8, used: *usize, value: u8) Error!void {
    if (used.* + 1 > buffer.len) return error.RequestTooLarge;
    buffer[used.*] = value;
    used.* += 1;
}

fn writeBytes(buffer: []u8, used: *usize, bytes: []const u8) Error!void {
    if (used.* + bytes.len > buffer.len) return error.RequestTooLarge;
    @memcpy(buffer[used.* .. used.* + bytes.len], bytes);
    used.* += bytes.len;
}

fn writeU16(buffer: []u8, used: *usize, value: u16) Error!void {
    if (used.* + 2 > buffer.len) return error.ResponseTooLarge;
    std.mem.writeInt(u16, buffer[used.*..][0..2], value, .little);
    used.* += 2;
}

fn writeU64(buffer: []u8, used: *usize, value: u64) Error!void {
    if (used.* + 8 > buffer.len) return error.RequestTooLarge;
    std.mem.writeInt(u64, buffer[used.*..][0..8], value, .little);
    used.* += 8;
}

fn writeText(buffer: []u8, used: *usize, text: []const u8) Error!void {
    if (text.len > std.math.maxInt(u8)) return error.RequestTooLarge;
    try writeByte(buffer, used, @intCast(text.len));
    try writeBytes(buffer, used, text);
}

fn readByte(buffer: []const u8, cursor: *usize) Error!u8 {
    if (cursor.* + 1 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 1;
    return buffer[cursor.*];
}

fn readBytes(buffer: []const u8, cursor: *usize, len: usize) Error![]const u8 {
    if (cursor.* + len > buffer.len) return error.MalformedRequest;
    defer cursor.* += len;
    return buffer[cursor.* .. cursor.* + len];
}

fn readU16(buffer: []const u8, cursor: *usize) Error!u16 {
    if (cursor.* + 2 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 2;
    return std.mem.readInt(u16, buffer[cursor.*..][0..2], .little);
}

fn readU64(buffer: []const u8, cursor: *usize) Error!u64 {
    if (cursor.* + 8 > buffer.len) return error.MalformedRequest;
    defer cursor.* += 8;
    return std.mem.readInt(u64, buffer[cursor.*..][0..8], .little);
}

fn readText(buffer: []const u8, cursor: *usize) Error![]const u8 {
    const len = try readByte(buffer, cursor);
    return readBytes(buffer, cursor, len);
}

fn deriveReason(buffer: *[MAX_REASON_BYTES]u8, bundle: manifest.BundleManifest, request: manifest.PermissionRequest) usize {
    const display_name = bundle.display_name;
    const rendered = switch (request.kind) {
        .object_access => std.fmt.bufPrint(buffer, "{s} needs access to local task objects for read and write operations", .{display_name}),
        .network_egress => if (request.egress_intent.declared())
            deriveDataEgressReason(buffer, display_name, request.egress_intent)
        else
            std.fmt.bufPrint(buffer, "{s} needs an approved data route for task data egress", .{display_name}),
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
        .network_egress => "Data egress",
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

fn deriveDataEgressReason(
    buffer: *[MAX_REASON_BYTES]u8,
    display_name: []const u8,
    intent: manifest.DataEgressIntent,
) error{NoSpaceLeft}![]u8 {
    return switch (intent.kind) {
        .unspecified => std.fmt.bufPrint(buffer, "{s} needs an approved data route for task data egress", .{display_name}),
        .sync_object => std.fmt.bufPrint(buffer, "{s} needs to sync {s} with {s}", .{
            display_name,
            intent.object,
            intent.principal,
        }),
        .call_service => std.fmt.bufPrint(buffer, "{s} needs to call service {s}", .{
            display_name,
            intent.service,
        }),
        .publish_event => std.fmt.bufPrint(buffer, "{s} needs to publish event {s}", .{
            display_name,
            intent.event_type,
        }),
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
        .sync_conflict_review => "sync_conflict_review",
    };
}

fn deriveWindowTitle(buffer: *[MAX_TITLE_BYTES]u8, title_prefix: []const u8, detail: []const u8) usize {
    if (detail.len == 0) {
        return copyText(buffer, title_prefix);
    }
    const rendered = std.fmt.bufPrint(buffer, "{s}: {s}", .{ title_prefix, detail }) catch return copyText(buffer, detail);
    return rendered.len;
}

fn zeroWindow() WindowRecord {
    return .{ .id = 0 };
}

fn zeroItem() ReviewItemRecord {
    return .{};
}

test "compositor service wire protocol opens switches reviews decides and recovers" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 9 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 12,
        .local_only = true,
    });
    var session = Session.init();
    var checkpoint_store = CheckpointStore{};
    var service = Service.initWithCheckpoint(44, 45, &runtime, &session, &checkpoint_store);

    var request_buffer: [SERVICE_ENDPOINT_BYTES]u8 = undefined;
    var response_buffer: [SERVICE_ENDPOINT_BYTES]u8 = undefined;
    const open_payload = try encodeRequest(&request_buffer, .{
        .operation = .open_view,
        .view_type = .workspace_view,
        .subject_task_id = app_task.id,
        .workspace_id = 41,
        .detail = "Trip",
    });
    const open_response = try decodeResponse(try service.dispatchPayload(open_payload, &response_buffer));
    try std.testing.expectEqual(ServiceStatus.ok, open_response.status);
    try std.testing.expectEqual(@as(u16, 1), open_response.visible_window_count);

    const missing_switch = service.dispatch(.{
        .operation = .switch_view,
        .window_id = 99_999,
    });
    try std.testing.expectEqual(ServiceStatus.not_found, missing_switch.status);

    const review_response = service.dispatch(.{
        .operation = .review_permission,
        .subject_task_id = app_task.id,
        .reviewer_task_id = 45,
        .permission_kind = .object_access,
        .local_only = true,
        .max_lease_ticks = 30,
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .resource = "ws:trip",
    });
    try std.testing.expectEqual(ServiceStatus.ok, review_response.status);
    try std.testing.expectEqual(@as(u16, 1), review_response.review_item_count);

    const decision_response = service.dispatch(.{
        .operation = .record_decision,
        .window_id = review_response.window_id,
        .permission_kind = .object_access,
        .allow = true,
        .local_only = true,
        .has_lease = true,
        .lease_ticks = 30,
        .resource = "ws:trip",
    });
    try std.testing.expectEqual(ServiceStatus.ok, decision_response.status);
    try std.testing.expectEqual(DecisionState.allow, decision_response.decision);
    try std.testing.expect(checkpoint_store.valid);

    session.reset();
    const recover_response = service.dispatch(.{ .operation = .recover_state });
    try std.testing.expectEqual(ServiceStatus.ok, recover_response.status);
    try std.testing.expect(recover_response.recovered);
    try std.testing.expectEqual(@as(usize, 2), session.window_count);
    try std.testing.expectEqual(DecisionState.allow, session.findReviewItemConst(review_response.window_id, .object_access, "ws:trip").?.decision);
}

test "compositor service closes task windows during app removal" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 24 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 24,
        .local_only = true,
    });
    var session = Session.init();
    var checkpoint_store = CheckpointStore{};
    var service = Service.initWithCheckpoint(64, 65, &runtime, &session, &checkpoint_store);

    try std.testing.expectEqual(ServiceStatus.ok, service.dispatch(.{
        .operation = .open_view,
        .view_type = .workspace_view,
        .subject_task_id = app_task.id,
        .workspace_id = 24,
        .detail = "Trip Workspace",
    }).status);
    try std.testing.expectEqual(ServiceStatus.ok, service.dispatch(.{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = app_task.id,
        .workspace_id = 24,
        .detail = "trip.md",
    }).status);
    const review_response = service.dispatch(.{
        .operation = .review_permission,
        .subject_task_id = app_task.id,
        .reviewer_task_id = 65,
        .permission_kind = .object_access,
        .local_only = true,
        .max_lease_ticks = 30,
        .bundle_id = "app.trip.remove",
        .display_name = "Trip",
        .resource = "workspace:trip",
    });
    try std.testing.expectEqual(ServiceStatus.ok, review_response.status);
    try std.testing.expectEqual(@as(usize, 3), session.window_count);
    try std.testing.expectEqual(@as(usize, 1), session.item_count);
    try std.testing.expect(session.findWindowForTaskBundleConst(app_task.id, "app.trip.remove") != null);

    const close_response = service.dispatch(.{
        .operation = .close_task_windows,
        .subject_task_id = app_task.id,
    });
    try std.testing.expectEqual(ServiceStatus.ok, close_response.status);
    try std.testing.expectEqual(@as(u16, 0), close_response.visible_window_count);
    try std.testing.expectEqual(@as(u16, 0), close_response.review_item_count);
    try std.testing.expectEqual(@as(usize, 0), session.window_count);
    try std.testing.expectEqual(@as(usize, 0), session.item_count);
    try std.testing.expectEqual(@as(u64, 0), session.active_window_id);
    try std.testing.expect(session.findWindowForTaskBundleConst(app_task.id, "app.trip.remove") == null);
    try std.testing.expect(checkpoint_store.valid);

    const reopened = service.dispatch(.{
        .operation = .open_view,
        .view_type = .workspace_view,
        .subject_task_id = app_task.id,
        .workspace_id = 24,
        .detail = "Trip Workspace",
    });
    try std.testing.expectEqual(ServiceStatus.ok, reopened.status);
    try std.testing.expectEqual(@as(usize, 1), session.window_count);
    try std.testing.expectEqual(@as(u16, 1), reopened.visible_window_count);
}

test "compositor service rejects tasks without valid display surfaces" {
    var runtime = task_runtime.Runtime.init();
    const headless_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 21 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    const zero_surface_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 22 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 0,
        .local_only = true,
    });
    var session = Session.init();
    var checkpoint_store = CheckpointStore{};
    var service = Service.initWithCheckpoint(60, 61, &runtime, &session, &checkpoint_store);

    const headless_response = service.dispatch(.{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = headless_task.id,
        .workspace_id = 7,
        .detail = "headless.md",
    });
    try std.testing.expectEqual(ServiceStatus.invalid_request, headless_response.status);
    try std.testing.expectEqual(@as(usize, 0), session.window_count);
    try std.testing.expect(!checkpoint_store.valid);

    const zero_surface_response = service.dispatch(.{
        .operation = .review_permission,
        .subject_task_id = zero_surface_task.id,
        .reviewer_task_id = 61,
        .permission_kind = .object_access,
        .bundle_id = "app.zero",
        .display_name = "Zero",
        .resource = "ws:zero",
    });
    try std.testing.expectEqual(ServiceStatus.invalid_request, zero_surface_response.status);
    try std.testing.expectEqual(@as(usize, 0), session.window_count);
    try std.testing.expectError(error.InvalidSurface, session.openTaskView(headless_task, "Missing Surface"));
}

test "task-first compositor flow persists app-linked task views and audit state" {
    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(70, .{ .kind = .service, .serial = 70 });

    const app_image = task_runtime.syntheticUserspaceImage("trip-task", "app.trip.coordinate");
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 70 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 4 * 1024,
        },
        .ui_surface_id = 91,
        .local_only = true,
        .initial_component = .{
            .label = "trip-task",
            .entry = "app.trip.coordinate",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 70_001,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.trip",
        },
        .userspace_image = &app_image,
    });
    const app_task_id = app_task.id;

    var session = Session.init();
    var compositor_checkpoint_store = CheckpointStore{};
    var compositor_service = Service.initWithCheckpoint(71, 72, &runtime, &session, &compositor_checkpoint_store);

    const task_response = compositor_service.dispatch(.{
        .operation = .open_view,
        .view_type = .full_screen_task_view,
        .subject_task_id = app_task_id,
        .workspace_id = 800,
        .detail = "Coordinate Trip",
    });
    try std.testing.expectEqual(ServiceStatus.ok, task_response.status);

    const document_response = compositor_service.dispatch(.{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = app_task_id,
        .workspace_id = 800,
        .detail = "trip/brief.md",
    });
    try std.testing.expectEqual(ServiceStatus.ok, document_response.status);

    const panel_response = compositor_service.dispatch(.{
        .operation = .open_view,
        .view_type = .app_panel,
        .subject_task_id = app_task_id,
        .workspace_id = 800,
        .bundle_id = "app.trip",
        .display_name = "Trip",
        .detail = "Calendar Panel",
    });
    try std.testing.expectEqual(ServiceStatus.ok, panel_response.status);
    try std.testing.expectEqual(panel_response.window_id, session.active_window_id);

    _ = try runtime.attachComponent(app_task_id, .{
        .label = "calendar-panel",
        .entry = "app.trip.calendar",
    }, 12);
    try runtime.audit(app_task_id, .{
        .kind = .service_connected,
        .detail = @intCast(panel_response.window_id),
        .tick = 13,
    });

    const switch_response = compositor_service.dispatch(.{
        .operation = .switch_view,
        .window_id = task_response.window_id,
    });
    try std.testing.expectEqual(ServiceStatus.ok, switch_response.status);
    try std.testing.expectEqual(task_response.window_id, switch_response.active_window_id);
    try std.testing.expect(compositor_checkpoint_store.valid);
    runtime_service.checkpoint(14);

    const ephemeral_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 71 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 512,
        },
        .local_only = true,
    });
    const ephemeral_task_id = ephemeral_task.id;

    session.reset();
    runtime.reset();
    try std.testing.expect(runtime_service.restartFromCheckpoint(15));
    const recover_response = compositor_service.dispatch(.{ .operation = .recover_state });
    try std.testing.expectEqual(ServiceStatus.ok, recover_response.status);
    try std.testing.expect(recover_response.recovered);

    const restored_task = runtime.find(app_task_id) orelse return error.TaskNotFound;
    try std.testing.expect(runtime.find(ephemeral_task_id) == null);
    try std.testing.expect(restored_task.runsAsUserspaceProcess());
    try std.testing.expectEqual(@as(?u64, 91), restored_task.ui_surface_id);
    try std.testing.expectEqualStrings("app.trip", restored_task.launchBundleIdSlice());
    try std.testing.expectEqual(@as(usize, 2), restored_task.execution_component_count);
    try std.testing.expectEqualStrings("calendar-panel", restored_task.executionComponents()[1].labelSlice());
    try std.testing.expectEqual(@as(usize, 2), restored_task.audit_count);
    try std.testing.expectEqual(task_runtime.AuditEventKind.component_attached, restored_task.auditEventAt(0).?.kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.service_connected, restored_task.auditEventAt(1).?.kind);

    try std.testing.expectEqual(@as(usize, 3), session.window_count);
    try std.testing.expectEqual(task_response.window_id, session.active_window_id);
    const restored_task_window = session.findWindowConst(task_response.window_id) orelse return error.WindowNotFound;
    const restored_document_window = session.findWindowConst(document_response.window_id) orelse return error.WindowNotFound;
    const restored_panel_window = session.findWindowConst(panel_response.window_id) orelse return error.WindowNotFound;
    try std.testing.expectEqual(app_task_id, restored_task_window.subject_task_id);
    try std.testing.expectEqual(app_task_id, restored_document_window.subject_task_id);
    try std.testing.expectEqual(app_task_id, restored_panel_window.subject_task_id);
    try std.testing.expectEqual(@as(?u64, 91), restored_panel_window.ui_surface_id);
    try std.testing.expectEqual(ViewType.full_screen_task_view, restored_task_window.view_type);
    try std.testing.expectEqual(ViewType.document_view, restored_document_window.view_type);
    try std.testing.expectEqual(ViewType.app_panel, restored_panel_window.view_type);
    try std.testing.expectEqualStrings("app.trip", restored_panel_window.bundleIdSlice());
    try std.testing.expectEqualStrings("Trip", restored_panel_window.displayNameSlice());

    var render_buffer: [512]u8 = undefined;
    const rendered_task = try renderWindowToBuffer(&render_buffer, restored_task_window);
    try std.testing.expect(std.mem.indexOf(u8, rendered_task, "type=full_screen_task_view") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_task, "title=Task: Coordinate Trip") != null);
    const rendered_panel = try renderWindowToBuffer(&render_buffer, restored_panel_window);
    try std.testing.expect(std.mem.indexOf(u8, rendered_panel, "bundle=app.trip") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_panel, "display=Trip") != null);
}

test "compositor session creates app-panel permission review windows and cards" {
    const manifest_fixtures = @import("../policy/manifest_fixtures.zig");

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
    const permissions = manifest_fixtures.notes_permissions[0..2];
    var bundle = manifest_fixtures.notesBundle();
    bundle.requested_permissions = permissions;

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
    try std.testing.expect(std.mem.indexOf(u8, item, "grant_scope=this object on this device") != null);
    try std.testing.expect(std.mem.indexOf(u8, item, "lease_summary=up to 400 ticks") != null);
    try std.testing.expect(std.mem.indexOf(u8, decision, "decision=allow") != null);
    try std.testing.expect(std.mem.indexOf(u8, decision, "revoke_hint=remove this app from the object's share sheet") != null);
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

test "compositor session opens document workspace and full-screen task views" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .ui_surface_id = 7,
        .local_only = true,
        .initial_component = .{
            .label = "organizer",
            .entry = "app.organizer",
        },
    });

    var session = Session.init();
    const document = try session.openDocumentView(app_task, 41, "documents/plan.md");
    const workspace_window = try session.openWorkspaceView(app_task, 41, "Trip Project");
    const fullscreen = try session.openTaskView(app_task, "Edit Media Project");

    try std.testing.expectEqual(ViewType.document_view, document.view_type);
    try std.testing.expectEqual(@as(u64, 41), document.workspace_id);
    try std.testing.expectEqualStrings("documents/plan.md", document.detailSlice());
    try std.testing.expectEqual(ViewType.workspace_view, workspace_window.view_type);
    try std.testing.expectEqualStrings("Trip Project", workspace_window.detailSlice());
    try std.testing.expectEqual(ViewType.full_screen_task_view, fullscreen.view_type);
    try std.testing.expectEqualStrings("Edit Media Project", fullscreen.titleSlice());

    var buffer: [320]u8 = undefined;
    const rendered = try renderWindowToBuffer(&buffer, document);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "type=document_view") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "detail=documents/plan.md") != null);

    const workspace_rendered = try renderWindowToBuffer(&buffer, workspace_window);
    try std.testing.expect(std.mem.indexOf(u8, workspace_rendered, "type=workspace_view") != null);

    const fullscreen_rendered = try renderWindowToBuffer(&buffer, fullscreen);
    try std.testing.expect(std.mem.indexOf(u8, fullscreen_rendered, "type=full_screen_task_view") != null);
    try std.testing.expect(session.probeVisibleWindow(&buffer));
}
