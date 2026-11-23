const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const capability = @import("../kernel_api/capability.zig");
const humane_permissions = @import("../policy/humane_permissions.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
const units = @import("../core/units.zig");
const table_backing = @import("../core/table_backing.zig");

const copyText = native_util.copyText;
const yesNo = native_util.yesNo;

pub const MAX_WINDOWS: usize = 8;
pub const MAX_REVIEW_ITEMS: usize = 32;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_REASON_BYTES: usize = 128;
pub const MAX_RESOURCE_BYTES: usize = 96;
pub const MAX_WINDOW_DETAIL_BYTES: usize = 96;
pub const MAX_PRESENTED_SURFACES: usize = MAX_WINDOWS;
pub const WindowOrderIndex = u8;
pub const SessionCount = u8;
pub const WINDOW_RECORD_SIZE_CEILING_BYTES: usize = 344;
pub const REVIEW_ITEM_RECORD_SIZE_CEILING_BYTES: usize = 248;
// Eight bounded text snapshots add 4,288 bytes; resident session handles stay
// unchanged because the surface arena is allocated on first presentation.
pub const SESSION_SNAPSHOT_SIZE_CEILING_BYTES: usize = 19_560;
pub const CHECKPOINT_STORE_SIZE_CEILING_BYTES: usize = 19_568;
pub const SESSION_SIZE_CEILING_BYTES: usize = 216;
const LEASE_SUMMARY_BUFFER_BYTES: usize = 96;
// BSP-owned like every compositor session; see Session.display_revision.
var display_revision_sequence: u64 = 0;

comptime {
    if (MAX_WINDOWS > std.math.maxInt(WindowOrderIndex) or
        MAX_REVIEW_ITEMS > std.math.maxInt(SessionCount) or
        MAX_TITLE_BYTES > std.math.maxInt(u8) or
        MAX_LABEL_BYTES > std.math.maxInt(u8) or
        MAX_REASON_BYTES > std.math.maxInt(u8) or
        MAX_RESOURCE_BYTES > std.math.maxInt(u8) or
        MAX_WINDOW_DETAIL_BYTES > std.math.maxInt(u8))
    {
        @compileError("compositor record metadata no longer fits compact counters");
    }
}

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

pub const SwitchDirection = enum(u8) {
    next,
    previous,
};

pub const SwitchResult = struct {
    window: *WindowRecord,
    visible_index: usize,
};

pub const PresentResult = enum(u8) {
    accepted,
    duplicate,
};

pub const WindowRecord = struct {
    id: u64,
    reviewer_task_id: u64 = 0,
    subject_task_id: u64 = 0,
    ui_surface_id: ?u64 = null,
    view_type: ViewType = .app_panel,
    modal: bool = true,
    workspace_id: u64 = 0,
    bundle_id_len: u8 = 0,
    bundle_id: [MAX_LABEL_BYTES]u8 = @as([MAX_LABEL_BYTES]u8, @splat(0)),
    display_name_len: u8 = 0,
    display_name: [MAX_LABEL_BYTES]u8 = @as([MAX_LABEL_BYTES]u8, @splat(0)),
    title_len: u8 = 0,
    title: [MAX_TITLE_BYTES]u8 = @as([MAX_TITLE_BYTES]u8, @splat(0)),
    detail_len: u8 = 0,
    detail: [MAX_WINDOW_DETAIL_BYTES]u8 = @as([MAX_WINDOW_DETAIL_BYTES]u8, @splat(0)),
    item_count: u8 = 0,

    pub fn bundleIdSlice(self: *const WindowRecord) []const u8 {
        return self.bundle_id[0..@as(usize, self.bundle_id_len)];
    }

    pub fn displayNameSlice(self: *const WindowRecord) []const u8 {
        return self.display_name[0..@as(usize, self.display_name_len)];
    }

    pub fn titleSlice(self: *const WindowRecord) []const u8 {
        return self.title[0..@as(usize, self.title_len)];
    }

    pub fn detailSlice(self: *const WindowRecord) []const u8 {
        return self.detail[0..@as(usize, self.detail_len)];
    }

    comptime {
        if (@sizeOf(@This()) > WINDOW_RECORD_SIZE_CEILING_BYTES) {
            @compileError("compositor window record exceeds its compact size ceiling");
        }
    }
};

pub const ReviewItemRecord = struct {
    window_id: u64 = 0,
    kind: manifest.PermissionKind = .object_access,
    resource_len: u8 = 0,
    resource: [MAX_RESOURCE_BYTES]u8 = @as([MAX_RESOURCE_BYTES]u8, @splat(0)),
    reason_len: u8 = 0,
    reason: [MAX_REASON_BYTES]u8 = @as([MAX_REASON_BYTES]u8, @splat(0)),
    requested_local_only: bool = false,
    requested_lease_ticks: manifest.LeaseTicks = 0,
    decision: DecisionState = .pending,
    decision_local_only: bool = false,
    decision_has_lease: bool = false,
    decision_lease_ticks: manifest.LeaseTicks = 0,

    pub fn labelSlice(self: *const ReviewItemRecord) []const u8 {
        return manifest.permissionDisplayLabel(self.kind);
    }

    pub fn resourceSlice(self: *const ReviewItemRecord) []const u8 {
        return self.resource[0..@as(usize, self.resource_len)];
    }

    pub fn reasonSlice(self: *const ReviewItemRecord) []const u8 {
        return self.reason[0..@as(usize, self.reason_len)];
    }

    // Scope and route are views of the reviewed resource for the matching kind.
    pub fn objectScopeSlice(self: *const ReviewItemRecord) []const u8 {
        return if (self.kind == .object_access) self.resourceSlice() else "";
    }

    pub fn networkPathSlice(self: *const ReviewItemRecord) []const u8 {
        return if (self.kind == .network_egress) self.resourceSlice() else "";
    }

    comptime {
        if (@sizeOf(@This()) > REVIEW_ITEM_RECORD_SIZE_CEILING_BYTES) {
            @compileError("compositor review item record exceeds its compact size ceiling");
        }
    }
};

pub const SurfaceRecord = struct {
    task_id: u64 = 0,
    presentation: abi.SurfacePresentation = std.mem.zeroes(abi.SurfacePresentation),
    text: ?abi.SurfaceText = null,
};

pub const Error = error{
    WindowIdExhausted,
    WindowNotFound,
    WindowTableFull,
    ReviewItemNotFound,
    ReviewItemTableFull,
    TaskNotFound,
    InvalidSurface,
    MalformedRequest,
    RecoveryStateMissing,
    NoVisibleWindows,
    SurfaceTableFull,
    MalformedPresentation,
    StalePresentation,
    PresentationConflict,
    OutOfMemory,
};

const WINDOW_INDEX_CAPACITY: usize = MAX_WINDOWS * 2;
const NO_WINDOW_ORDER_INDEX: WindowOrderIndex = @intCast(MAX_WINDOWS);
const REVIEW_ITEM_INDEX_CAPACITY: usize = MAX_REVIEW_ITEMS * 2;
const SURFACE_INDEX_CAPACITY: usize = MAX_PRESENTED_SURFACES * 2;
const NO_SURFACE_SLOT_INDEX: u16 = std.math.maxInt(u16);

pub const WindowSlot = struct {
    in_use: bool = false,
    order_index: WindowOrderIndex = NO_WINDOW_ORDER_INDEX,
    window: WindowRecord = zeroWindow(),
};

const WindowAllocation = struct {
    slot_index: usize,
    window: *WindowRecord,
};

const ReviewItemSlot = struct {
    in_use: bool = false,
    key: u64 = 0,
    item: ReviewItemRecord = zeroItem(),
};

const SurfaceSlot = struct {
    in_use: bool = false,
    previous_active_index: u16 = NO_SURFACE_SLOT_INDEX,
    next_active_index: u16 = NO_SURFACE_SLOT_INDEX,
    surface: SurfaceRecord = .{},
};

const WindowArena = indexed_arena.IndexedArenaWithKey(u64, WindowSlot, MAX_WINDOWS, WINDOW_INDEX_CAPACITY, windowSlotId);
pub const ReviewItemArena = indexed_arena.IndexedArenaWithKey(u64, ReviewItemSlot, MAX_REVIEW_ITEMS, REVIEW_ITEM_INDEX_CAPACITY, reviewItemSlotKey);
const SurfaceArena = indexed_arena.IndexedArenaWithKey(u64, SurfaceSlot, MAX_PRESENTED_SURFACES, SURFACE_INDEX_CAPACITY, surfaceSlotId);
const SurfaceTaskIndex = indexed_arena.UniqueIndex(SURFACE_INDEX_CAPACITY);
const TaskBundleIndex = indexed_arena.UniqueIndex(WINDOW_INDEX_CAPACITY);
const TaskWindowIndex = indexed_arena.MultimapIndex(MAX_WINDOWS, MAX_WINDOWS, WINDOW_INDEX_CAPACITY);
const ReviewerWindowIndex = indexed_arena.MultimapIndex(MAX_WINDOWS, MAX_WINDOWS, WINDOW_INDEX_CAPACITY);
pub const WindowReviewItemIndex = indexed_arena.MultimapIndex(MAX_REVIEW_ITEMS, MAX_REVIEW_ITEMS, REVIEW_ITEM_INDEX_CAPACITY);

pub const WindowState = struct {
    windows: WindowArena = WindowArena.init(),
    window_order: [MAX_WINDOWS]u64 = @as([MAX_WINDOWS]u64, @splat(0)),
    task_bundle_index: TaskBundleIndex = TaskBundleIndex.init(),
    task_window_index: TaskWindowIndex = TaskWindowIndex.init(),
    reviewer_window_index: ReviewerWindowIndex = ReviewerWindowIndex.init(),
};

const ReviewItemBacking = struct {
    items: ReviewItemArena = ReviewItemArena.init(),
    item_order: [MAX_REVIEW_ITEMS]u64 = @as([MAX_REVIEW_ITEMS]u64, @splat(0)),
    window_review_item_index: WindowReviewItemIndex = WindowReviewItemIndex.init(),
};

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
    id_exhausted = 5,
    resource_exhausted = 6,
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
    lease_ticks: manifest.LeaseTicks = 0,
    max_lease_ticks: manifest.LeaseTicks = 0,
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
    window_order: [MAX_WINDOWS]u64 = @as([MAX_WINDOWS]u64, @splat(0)),
    window_count: SessionCount = 0,
    items: ReviewItemArena = ReviewItemArena.init(),
    item_order: [MAX_REVIEW_ITEMS]u64 = @as([MAX_REVIEW_ITEMS]u64, @splat(0)),
    item_count: SessionCount = 0,
    task_bundle_index: TaskBundleIndex = TaskBundleIndex.init(),
    task_window_index: TaskWindowIndex = TaskWindowIndex.init(),
    reviewer_window_index: ReviewerWindowIndex = ReviewerWindowIndex.init(),
    window_review_item_index: WindowReviewItemIndex = WindowReviewItemIndex.init(),
    surfaces: SurfaceArena = SurfaceArena.init(),
    surface_task_index: SurfaceTaskIndex = SurfaceTaskIndex.init(),
    active_surface_head: u16 = NO_SURFACE_SLOT_INDEX,
    active_surface_tail: u16 = NO_SURFACE_SLOT_INDEX,

    comptime {
        if (@sizeOf(@This()) > SESSION_SNAPSHOT_SIZE_CEILING_BYTES) {
            @compileError("compositor snapshot exceeds its compact size ceiling");
        }
    }
};

pub const CheckpointStore = struct {
    valid: bool = false,
    snapshot: SessionSnapshot = .{},

    pub fn initializeAllocated(self: *CheckpointStore) void {
        self.valid = false;
        self.snapshot = undefined;
    }

    pub fn reset(self: *CheckpointStore) void {
        self.* = .{};
    }

    comptime {
        if (@sizeOf(@This()) > CHECKPOINT_STORE_SIZE_CEILING_BYTES) {
            @compileError("compositor checkpoint store exceeds its compact size ceiling");
        }
    }
};

pub const Session = struct {
    // Live native authentication chrome never enters a checkpoint or a task's
    // surface snapshot. The exclusive input owner retains and detaches it.
    trusted_view: ?*const @import("trusted_identity_entry.zig").View = null,
    next_window_id: u64 = 1,
    active_window_id: u64 = 0,
    window_state: table_backing.Lazy(WindowState, null) = .{},
    window_count: SessionCount = 0,
    review_items: table_backing.Lazy(ReviewItemBacking, null) = .{},
    item_count: SessionCount = 0,
    surfaces: table_backing.Lazy(SurfaceArena, null) = .{},
    surface_task_index: SurfaceTaskIndex = SurfaceTaskIndex.init(),
    active_surface_head: u16 = NO_SURFACE_SLOT_INDEX,
    active_surface_tail: u16 = NO_SURFACE_SLOT_INDEX,
    // Cache only the low lifetime range; larger lifecycle generations simply
    // miss the pruning cache. The other half tracks trusted focus changes.
    last_surface_prune_generation: u32 = 0,
    focus_epoch: u32 = 1,
    // Changes whenever anything the desktop view draws changes, so an
    // unchanged frame is never recomposed. Values come from one kernel-wide
    // sequence: a reset session cannot repeat a revision still on screen.
    display_revision: u64 = 0,

    pub fn init() Session {
        return .{};
    }

    fn touchDisplay(self: *Session) void {
        display_revision_sequence += 1;
        self.display_revision = display_revision_sequence;
    }

    // Binding or detaching native identity chrome changes the composed frame.
    pub fn setTrustedView(self: *Session, view: ?*const @import("trusted_identity_entry.zig").View) void {
        self.trusted_view = view;
        self.touchDisplay();
    }

    fn changeFocus(self: *Session, window_id: u64) void {
        if (self.active_window_id == window_id) return;
        self.focus_epoch +|= 1;
        self.active_window_id = window_id;
        self.touchDisplay();
    }

    comptime {
        if (@sizeOf(@This()) > SESSION_SIZE_CEILING_BYTES) {
            @compileError(std.fmt.comptimePrint(
                "compositor session size {d} exceeds its compact size ceiling",
                .{@sizeOf(@This())},
            ));
        }
    }

    pub fn deinit(self: *Session) void {
        self.releaseWindowState();
        self.releaseReviewItems();
        self.releaseSurfaceArena();
        self.changeFocus(0);
        self.window_count = 0;
        self.item_count = 0;
        self.touchDisplay();
    }

    pub fn reset(self: *Session) void {
        const trusted_view = self.trusted_view;
        self.deinit();
        self.* = .{ .trusted_view = trusted_view };
        self.touchDisplay();
    }

    fn windowState(self: *Session) ?*WindowState {
        return self.window_state.get();
    }

    fn windowStateConst(self: *const Session) ?*const WindowState {
        return self.window_state.get();
    }

    fn ensureWindowState(self: *Session) error{OutOfMemory}!*WindowState {
        return self.window_state.ensure() catch error.OutOfMemory;
    }

    fn releaseWindowState(self: *Session) void {
        self.window_state.release();
    }

    fn reviewItemsPtr(self: *Session) ?*ReviewItemBacking {
        return self.review_items.get();
    }

    fn reviewItemsConst(self: *const Session) ?*const ReviewItemBacking {
        return self.review_items.get();
    }

    fn ensureReviewItems(self: *Session) error{OutOfMemory}!*ReviewItemBacking {
        return self.review_items.ensure() catch error.OutOfMemory;
    }

    fn releaseReviewItems(self: *Session) void {
        self.review_items.release();
    }

    fn surfaceArena(self: *Session) ?*SurfaceArena {
        return self.surfaces.get();
    }

    fn surfaceArenaConst(self: *const Session) ?*const SurfaceArena {
        return self.surfaces.get();
    }

    fn ensureSurfaceArena(self: *Session) error{OutOfMemory}!*SurfaceArena {
        return self.surfaces.ensure() catch error.OutOfMemory;
    }

    fn releaseSurfaceArena(self: *Session) void {
        self.surfaces.release();
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
        // Another bundle's window already holds this hashed key.
        if (self.windowStateConst()) |window_state| {
            if (window_state.task_bundle_index.contains(taskBundleKey(app_task.id, bundle.bundle_id))) return error.PresentationConflict;
        }

        const allocation = try self.allocateWindow();
        const window = allocation.window;
        window.reviewer_task_id = reviewer_task_id;
        window.subject_task_id = app_task.id;
        window.ui_surface_id = surface_id;
        window.view_type = .app_panel;
        window.modal = true;
        window.bundle_id_len = @intCast(copyText(&window.bundle_id, bundle.bundle_id));
        window.display_name_len = @intCast(copyText(&window.display_name, bundle.display_name));
        const title = std.fmt.bufPrint(&window.title, "{s} permission review", .{bundle.display_name}) catch
            window.title[0..copyText(&window.title, bundle.display_name)];
        window.title_len = @intCast(title.len);
        self.indexWindowForTaskBundle(allocation.slot_index, window);
        self.indexWindowForTask(allocation.slot_index, window);
        self.indexWindowForReviewer(allocation.slot_index, window);
        self.changeFocus(window.id);
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
        const review_items = try self.ensureReviewItems();

        const key = reviewItemKey(window_id, request.kind, request.resource);
        const slot_index = review_items.items.reserveIndex(key) orelse return error.ReviewItemTableFull;
        const slot = &review_items.items.slots[slot_index];
        slot.key = key;
        const item = &slot.item;
        item.* = zeroItem();
        item.window_id = window_id;
        item.kind = request.kind;
        item.resource_len = @intCast(copyText(&item.resource, request.resource));
        item.reason_len = @intCast(deriveReason(&item.reason, bundle, request));
        item.requested_local_only = request.local_only;
        item.requested_lease_ticks = request.max_lease_ticks;
        self.indexReviewItemForWindow(slot_index, item);
        review_items.item_order[@as(usize, self.item_count)] = key;
        self.item_count += 1;
        window.item_count += 1;
        self.touchDisplay();
        return item;
    }

    pub fn recordDecision(
        self: *Session,
        window_id: u64,
        request: manifest.PermissionRequest,
        allow: bool,
        local_only: bool,
        lease_ticks: ?manifest.LeaseTicks,
    ) Error!*ReviewItemRecord {
        const item = self.findReviewItem(window_id, request.kind, request.resource) orelse return error.ReviewItemNotFound;
        item.decision = if (allow) .allow else .deny;
        item.decision_local_only = allow and local_only;
        item.decision_has_lease = lease_ticks != null;
        item.decision_lease_ticks = lease_ticks orelse 0;
        self.touchDisplay();
        return item;
    }

    // Contentless presents record ordered revisions without any text.
    pub fn presentSurface(
        self: *Session,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
    ) Error!PresentResult {
        if (!abi.isCanonicalSurfacePresentation(presentation)) return error.MalformedPresentation;
        return self.storePresentation(task, presentation, null);
    }

    pub fn presentSurfaceText(
        self: *Session,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
        text: *const abi.SurfaceText,
    ) Error!PresentResult {
        if (!abi.isCanonicalSurfacePresentation(presentation) or !text.isCanonical()) return error.MalformedPresentation;
        return self.storePresentation(task, presentation, text);
    }

    // The kernel validates canonical form on its private copies before it
    // hands them to the compositor. Task, surface and window binding are
    // still checked here, because the kernel does not know compositor windows.
    pub fn presentKernelValidatedSurfaceText(
        self: *Session,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
        text: *const abi.SurfaceText,
    ) Error!PresentResult {
        if (builtin.mode == .debug) std.debug.assert(abi.isCanonicalSurfacePresentation(presentation) and text.isCanonical());
        return self.storePresentation(task, presentation, text);
    }

    fn storePresentation(
        self: *Session,
        task: *const task_runtime.TaskRecord,
        presentation: *const abi.SurfacePresentation,
        text: ?*const abi.SurfaceText,
    ) Error!PresentResult {
        if (task.id == 0 or task.state != .active) return error.MalformedPresentation;
        if (task.ui_surface_id == null or task.ui_surface_id.? != presentation.surface_id) return error.InvalidSurface;
        if (text) |content| {
            if (content.window_id != 0) {
                const window = self.findWindowConst(content.window_id) orelse return error.InvalidSurface;
                if (window.subject_task_id != task.id or window.ui_surface_id != presentation.surface_id) return error.InvalidSurface;
            }
        }

        if (self.surfaceArena()) |surfaces| {
            if (surfaces.slotIndexOf(presentation.surface_id)) |slot_index| {
                const slot = &surfaces.slots[slot_index];
                if (slot.surface.task_id != task.id) return error.InvalidSurface;
                if (builtin.mode == .debug) {
                    std.debug.assert(self.surface_task_index.lookup(surfaceTaskKey(task.id)) == slot_index);
                }
                const previous_revision = slot.surface.presentation.revision;
                if (presentation.revision < previous_revision) return error.StalePresentation;
                if (presentation.revision == previous_revision) {
                    if (std.meta.eql(slot.surface.text, if (text) |content| content.* else null)) return .duplicate;
                    return error.PresentationConflict;
                }
                slot.surface.presentation = presentation.*;
                slot.surface.text = if (text) |content| content.* else null;
                self.touchDisplay();
                return .accepted;
            }
        }

        if (self.surface_task_index.lookup(surfaceTaskKey(task.id)) != null) {
            native_util.impossibleByInvariant("active task owns at most one presented surface");
        }
        const surfaces = try self.ensureSurfaceArena();
        const slot_index = surfaces.reserveIndex(presentation.surface_id) orelse return error.SurfaceTableFull;
        surfaces.slots[slot_index].surface = .{
            .task_id = task.id,
            .presentation = presentation.*,
            .text = if (text) |content| content.* else null,
        };
        self.surface_task_index.insertAbsent(surfaceTaskKey(task.id), slot_index);
        self.linkActiveSurface(surfaces, slot_index);
        self.touchDisplay();
        return .accepted;
    }

    pub fn surfacePresentation(self: *const Session, surface_id: u64) ?*const SurfaceRecord {
        const surfaces = self.surfaceArenaConst() orelse return null;
        const slot = surfaces.getConst(surface_id) orelse return null;
        return &slot.surface;
    }

    pub fn presentedSurfaceCount(self: *const Session) usize {
        const surfaces = self.surfaceArenaConst() orelse return 0;
        return surfaces.countInUse();
    }

    pub fn pruneSurfacePresentations(self: *Session, runtime: *const task_runtime.Runtime) usize {
        const lifecycle_generation = runtime.taskLifecycleGeneration();
        if (self.last_surface_prune_generation == lifecycle_generation) return 0;
        const surfaces = self.surfaceArena() orelse {
            self.last_surface_prune_generation = @intCast(@min(lifecycle_generation, std.math.maxInt(u32)));
            return 0;
        };

        var removed: usize = 0;
        var index: usize = self.active_surface_head;
        while (index != NO_SURFACE_SLOT_INDEX) {
            if (index >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface chain points outside slots");
            const slot = &surfaces.slots[index];
            if (!slot.in_use) native_util.impossibleByInvariant("active surface chain points at a free slot");
            const next_index = slot.next_active_index;
            const task = runtime.findConst(slot.surface.task_id) orelse {
                if (self.removeSurfaceSlot(surfaces, index)) removed += 1;
                index = next_index;
                continue;
            };
            if (task.state != .active or task.ui_surface_id != slot.surface.presentation.surface_id) {
                if (self.removeSurfaceSlot(surfaces, index)) removed += 1;
            }
            index = next_index;
        }
        self.last_surface_prune_generation = @intCast(@min(lifecycle_generation, std.math.maxInt(u32)));
        return removed;
    }

    // Callers that change a field the desktop draws must touch the display.
    pub fn findWindow(self: *Session, window_id: u64) ?*WindowRecord {
        const window_state = self.windowState() orelse return null;
        const slot = window_state.windows.get(window_id) orelse return null;
        return &slot.window;
    }

    pub fn findWindowConst(self: *const Session, window_id: u64) ?*const WindowRecord {
        const window_state = self.windowStateConst() orelse return null;
        const slot = window_state.windows.getConst(window_id) orelse return null;
        return &slot.window;
    }

    pub fn findWindowForTaskBundle(self: *Session, task_id: u64, bundle_id: []const u8) ?*WindowRecord {
        const window_state = self.windowState() orelse return null;
        const key = taskBundleKey(task_id, bundle_id);
        const slot = window_state.windows.findByUniqueIndex(&window_state.task_bundle_index, key, .{
            .task_id = task_id,
            .bundle_id = bundle_id,
        }, taskBundleMatches) orelse return null;
        return &slot.window;
    }

    pub fn findWindowForTaskBundleConst(self: *const Session, task_id: u64, bundle_id: []const u8) ?*const WindowRecord {
        const window_state = self.windowStateConst() orelse return null;
        const key = taskBundleKey(task_id, bundle_id);
        const slot = window_state.windows.findConstByUniqueIndex(&window_state.task_bundle_index, key, .{
            .task_id = task_id,
            .bundle_id = bundle_id,
        }, taskBundleMatches) orelse return null;
        return &slot.window;
    }

    pub fn setModalReviewer(self: *Session, window_id: u64, reviewer_task_id: u64) Error!*WindowRecord {
        if (reviewer_task_id == 0) return error.MalformedRequest;
        const window_state = self.windowState() orelse return error.WindowNotFound;
        const slot_index = window_state.windows.slotIndexOf(window_id) orelse return error.WindowNotFound;
        const window = &window_state.windows.slots[slot_index].window;
        if (window.modal and window.reviewer_task_id == reviewer_task_id) return window;
        if (self.active_window_id == window.id) self.focus_epoch +|= 1;
        self.removeWindowFromReviewerIndex(slot_index, window);
        window.modal = true;
        window.reviewer_task_id = reviewer_task_id;
        self.indexWindowForReviewer(slot_index, window);
        return window;
    }

    pub fn probeVisibleWindow(self: *const Session, buffer: []u8) bool {
        const window_state = self.windowStateConst() orelse return false;
        for (window_state.window_order[0..@as(usize, self.window_count)]) |window_id| {
            const window = self.findWindowConst(window_id) orelse continue;
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
        const review_items = self.reviewItemsPtr() orelse return null;
        const key = reviewItemKey(window_id, kind, resource);
        const slot = review_items.items.get(key) orelse return null;
        if (!reviewItemMatches(.{ .window_id = window_id, .kind = kind, .resource = resource }, slot)) return null;
        return &slot.item;
    }

    pub fn findReviewItemConst(
        self: *const Session,
        window_id: u64,
        kind: manifest.PermissionKind,
        resource: []const u8,
    ) ?*const ReviewItemRecord {
        const review_items = self.reviewItemsConst() orelse return null;
        const key = reviewItemKey(window_id, kind, resource);
        const slot = review_items.items.getConst(key) orelse return null;
        if (!reviewItemMatches(.{ .window_id = window_id, .kind = kind, .resource = resource }, slot)) return null;
        return &slot.item;
    }

    pub fn windowAtOrder(self: *const Session, index: usize) ?*const WindowRecord {
        if (index >= @as(usize, self.window_count)) return null;
        const window_state = self.windowStateConst() orelse
            native_util.impossibleByInvariant("non-empty compositor order retains window state");
        const window_id = window_state.window_order[index];
        const slot = window_state.windows.getConst(window_id) orelse
            native_util.impossibleByInvariant("window order points at a missing window");
        if (@as(usize, slot.order_index) != index) native_util.impossibleByInvariant("window order index matches its array position");
        return &slot.window;
    }

    pub fn itemAtOrder(self: *const Session, index: usize) ?*const ReviewItemRecord {
        if (index >= @as(usize, self.item_count)) return null;
        const review_items = self.reviewItemsConst() orelse
            native_util.impossibleByInvariant("non-empty compositor review order retains backing");
        const slot = review_items.items.getConst(review_items.item_order[index]) orelse return null;
        return &slot.item;
    }

    pub fn visibleWindowCount(self: *const Session) usize {
        return self.window_count;
    }

    pub fn taskOwnsVisibleWindow(self: *const Session, task_id: u64) bool {
        if (task_id == 0) return false;
        const window_state = self.windowStateConst() orelse return false;
        return self.indexHasVisibleWindow(&window_state.task_window_index, taskWindowKey(task_id), task_id, false) or
            self.indexHasVisibleWindow(&window_state.reviewer_window_index, taskWindowKey(task_id), task_id, true);
    }

    pub fn activeWindow(self: *const Session) ?*const WindowRecord {
        return self.findWindowConst(self.active_window_id);
    }

    pub fn activeWindowOrderIndex(self: *const Session) ?usize {
        if (self.active_window_id == 0) return null;
        const window_state = self.windowStateConst() orelse return null;
        const slot = window_state.windows.getConst(self.active_window_id) orelse return null;
        if (slot.order_index >= self.window_count) native_util.impossibleByInvariant("active window order index fits the live order");
        if (window_state.window_order[@as(usize, slot.order_index)] != self.active_window_id) {
            native_util.impossibleByInvariant("active window order index points at the active window");
        }
        return @intCast(slot.order_index);
    }

    pub fn switchVisible(self: *Session, direction: SwitchDirection) Error!SwitchResult {
        if (self.window_count == 0) return error.NoVisibleWindows;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("visible compositor windows retain window state");
        const visible_window_count: usize = self.window_count;

        const target_index = if (self.activeWindowOrderIndex()) |current|
            switch (direction) {
                .next => (current + 1) % visible_window_count,
                .previous => (current + visible_window_count - 1) % visible_window_count,
            }
        else switch (direction) {
            .next => 0,
            .previous => visible_window_count - 1,
        };
        const window_id = window_state.window_order[target_index];
        const slot = window_state.windows.get(window_id) orelse
            native_util.impossibleByInvariant("visible window order points at a live window");
        if (@as(usize, slot.order_index) != target_index) {
            native_util.impossibleByInvariant("visible window order index points at the expected window");
        }
        self.changeFocus(window_id);
        return .{ .window = &slot.window, .visible_index = target_index };
    }

    pub fn closeWindow(self: *Session, window_id: u64) bool {
        const state = self.windowState() orelse return false;
        const slot_index = state.windows.slotIndexOf(window_id) orelse return false;
        if (!self.closeWindowSlot(slot_index)) return false;
        if (self.findWindowConst(self.active_window_id) == null) self.changeFocus(self.firstVisibleWindowId());
        return true;
    }

    pub fn closeWindowsForTask(self: *Session, task_id: u64) usize {
        if (task_id == 0) return 0;

        const window_state = self.windowState() orelse {
            self.removeSurfacesForTask(task_id);
            return 0;
        };

        var closed: usize = 0;
        var slot_index = window_state.task_window_index.head(taskWindowKey(task_id));
        while (slot_index != indexed_arena.no_index) {
            const next_slot_index = window_state.task_window_index.next(slot_index);
            if (slot_index >= MAX_WINDOWS) native_util.impossibleByInvariant("task window index points outside window slots");
            const slot = &window_state.windows.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("task window index points at a free window slot");
            if (slot.window.subject_task_id != task_id) native_util.impossibleByInvariant("task window index points at the wrong task");
            if (self.closeWindowSlot(slot_index)) closed += 1;
            slot_index = next_slot_index;
        }

        if (self.findWindowConst(self.active_window_id) == null) {
            self.changeFocus(self.firstVisibleWindowId());
        }
        self.removeSurfacesForTask(task_id);
        return closed;
    }

    pub fn switchView(self: *Session, window_id: u64) Error!*WindowRecord {
        const window = self.findWindow(window_id) orelse return error.WindowNotFound;
        self.changeFocus(window.id);
        return window;
    }

    pub fn snapshotInto(self: *const Session, stored: *SessionSnapshot) void {
        const window_state = self.windowStateConst();
        stored.* = .{
            .next_window_id = self.next_window_id,
            .active_window_id = self.active_window_id,
            .windows = if (window_state) |state| state.windows else WindowArena.init(),
            .window_order = if (window_state) |state| state.window_order else @as([MAX_WINDOWS]u64, @splat(0)),
            .window_count = self.window_count,
            .items = undefined,
            .item_order = undefined,
            .item_count = self.item_count,
            .task_bundle_index = if (window_state) |state| state.task_bundle_index else TaskBundleIndex.init(),
            .task_window_index = if (window_state) |state| state.task_window_index else TaskWindowIndex.init(),
            .reviewer_window_index = if (window_state) |state| state.reviewer_window_index else ReviewerWindowIndex.init(),
            .window_review_item_index = undefined,
            .surfaces = if (self.surfaceArenaConst()) |surfaces| surfaces.* else SurfaceArena.init(),
            .surface_task_index = self.surface_task_index,
            .active_surface_head = self.active_surface_head,
            .active_surface_tail = self.active_surface_tail,
        };
        @memset(std.mem.asBytes(&stored.items), 0);
        @memset(&stored.item_order, 0);
        @memset(std.mem.asBytes(&stored.window_review_item_index), 0);
        if (self.reviewItemsConst()) |review_items| {
            stored.items = review_items.items;
            stored.item_order = review_items.item_order;
            stored.window_review_item_index = review_items.window_review_item_index;
        } else if (self.item_count != 0) {
            native_util.impossibleByInvariant("non-empty compositor review state retains backing");
        }
        if (window_state == null and self.window_count != 0) {
            native_util.impossibleByInvariant("non-empty compositor window state retains backing");
        }
    }

    pub fn restoreFromSnapshot(self: *Session, stored: *const SessionSnapshot) Error!void {
        const retained_window_state = self.windowState() != null;
        const window_state = if (stored.window_count == 0) null else try self.ensureWindowState();
        errdefer if (!retained_window_state and window_state != null) self.releaseWindowState();
        const retained_review_items = self.reviewItemsPtr() != null;
        const review_items = if (stored.item_count == 0) null else try self.ensureReviewItems();
        errdefer if (!retained_review_items and review_items != null) self.releaseReviewItems();
        const retained_surfaces = self.surfaceArena() != null;
        const surfaces = if (stored.surfaces.claimedCount() == 0) null else try self.ensureSurfaceArena();
        errdefer if (!retained_surfaces and surfaces != null) self.releaseSurfaceArena();
        self.focus_epoch +|= 1;
        self.touchDisplay();
        self.next_window_id = stored.next_window_id;
        self.changeFocus(stored.active_window_id);
        self.window_count = stored.window_count;
        self.item_count = stored.item_count;
        self.surface_task_index = stored.surface_task_index;
        self.active_surface_head = stored.active_surface_head;
        self.active_surface_tail = stored.active_surface_tail;
        self.last_surface_prune_generation = 0;
        if (window_state) |state| {
            state.windows = stored.windows;
            state.window_order = stored.window_order;
            state.task_bundle_index = stored.task_bundle_index;
            state.task_window_index = stored.task_window_index;
            state.reviewer_window_index = stored.reviewer_window_index;
        } else {
            self.releaseWindowState();
        }
        if (review_items) |items| {
            items.items = stored.items;
            items.item_order = stored.item_order;
            items.window_review_item_index = stored.window_review_item_index;
        } else {
            self.releaseReviewItems();
        }
        if (surfaces) |surface_arena| {
            surface_arena.* = stored.surfaces;
        } else {
            self.releaseSurfaceArena();
        }
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
        const allocation = try self.allocateWindow();
        const window = allocation.window;
        window.subject_task_id = app_task.id;
        window.ui_surface_id = surface_id;
        window.view_type = view_type;
        window.modal = modal;
        window.workspace_id = workspace_id;
        window.bundle_id_len = @intCast(copyText(&window.bundle_id, bundle_id));
        window.display_name_len = @intCast(copyText(&window.display_name, display_name));
        window.title_len = @intCast(deriveWindowTitle(&window.title, title_prefix, detail));
        window.detail_len = @intCast(copyText(&window.detail, detail));
        self.indexWindowForTask(allocation.slot_index, window);
        self.changeFocus(window.id);
        return window;
    }

    fn allocateWindow(self: *Session) Error!WindowAllocation {
        const window_id = self.next_window_id;
        if (window_id == 0) return error.WindowIdExhausted;
        const window_state = try self.ensureWindowState();
        if (window_state.windows.countInUse() >= MAX_WINDOWS) return error.WindowTableFull;
        const slot_index = window_state.windows.reserveIndex(window_id) orelse return error.WindowTableFull;
        self.next_window_id +%= 1;
        self.touchDisplay();
        const slot = &window_state.windows.slots[slot_index];
        slot.window = zeroWindow();
        slot.window.id = window_id;
        const order_index: usize = self.window_count;
        slot.order_index = @intCast(order_index);
        window_state.window_order[order_index] = window_id;
        self.window_count += 1;
        return .{ .slot_index = slot_index, .window = &slot.window };
    }

    fn indexWindowForTaskBundle(self: *Session, slot_index: usize, window: *const WindowRecord) void {
        if (window.subject_task_id == 0 or window.bundle_id_len == 0) return;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        window_state.task_bundle_index.insertAbsent(taskBundleKey(window.subject_task_id, window.bundleIdSlice()), slot_index);
    }

    fn indexWindowForTask(self: *Session, slot_index: usize, window: *const WindowRecord) void {
        if (window.subject_task_id == 0) return;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        if (!window_state.task_window_index.append(taskWindowKey(window.subject_task_id), slot_index)) {
            native_util.impossibleByInvariant("task window index capacity covers window slots");
        }
    }

    fn indexWindowForReviewer(self: *Session, slot_index: usize, window: *const WindowRecord) void {
        if (!window.modal or window.reviewer_task_id == 0) return;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        if (!window_state.reviewer_window_index.append(taskWindowKey(window.reviewer_task_id), slot_index)) {
            native_util.impossibleByInvariant("reviewer window index capacity covers window slots");
        }
    }

    fn removeWindowFromTaskIndex(self: *Session, slot_index: usize, window: *const WindowRecord) void {
        if (window.subject_task_id == 0) return;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        if (!window_state.task_window_index.remove(taskWindowKey(window.subject_task_id), slot_index)) {
            native_util.impossibleByInvariant("task window index missing live window");
        }
    }

    fn removeWindowFromReviewerIndex(self: *Session, slot_index: usize, window: *const WindowRecord) void {
        if (!window.modal or window.reviewer_task_id == 0) return;
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        if (!window_state.reviewer_window_index.remove(taskWindowKey(window.reviewer_task_id), slot_index)) {
            native_util.impossibleByInvariant("reviewer window index missing live review window");
        }
    }

    fn indexHasVisibleWindow(
        self: *const Session,
        index: *const TaskWindowIndex,
        key: u64,
        task_id: u64,
        reviewer: bool,
    ) bool {
        const window_state = self.windowStateConst() orelse
            native_util.impossibleByInvariant("indexed compositor windows retain window state");
        const slot_index = index.head(key);
        if (slot_index == indexed_arena.no_index) return false;
        if (slot_index >= MAX_WINDOWS) native_util.impossibleByInvariant("task ownership index points outside window slots");
        const slot = &window_state.windows.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("task ownership index points at an inactive window");
        const indexed_task_id = if (reviewer) slot.window.reviewer_task_id else slot.window.subject_task_id;
        if (indexed_task_id != task_id) native_util.impossibleByInvariant("task ownership index points at the wrong task");
        return true;
    }

    fn removeSurfacesForTask(self: *Session, task_id: u64) void {
        if (task_id == 0) return;
        const slot_index = self.surface_task_index.lookup(surfaceTaskKey(task_id)) orelse return;
        const surfaces = self.surfaceArena() orelse
            native_util.impossibleByInvariant("indexed compositor surfaces retain arena backing");
        if (slot_index >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("surface task index points outside slots");
        const slot = &surfaces.slots[slot_index];
        if (!slot.in_use or slot.surface.task_id != task_id) native_util.impossibleByInvariant("surface task index points at the wrong task");
        if (!self.removeSurfaceSlot(surfaces, slot_index)) native_util.impossibleByInvariant("task-owned surface remains live until task teardown");
    }

    fn linkActiveSurface(self: *Session, surfaces: *SurfaceArena, slot_index: usize) void {
        if (slot_index >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface append points outside slots");
        const slot = &surfaces.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("active surface append requires a live slot");
        const encoded_index: u16 = @intCast(slot_index);
        slot.previous_active_index = self.active_surface_tail;
        slot.next_active_index = NO_SURFACE_SLOT_INDEX;
        if (self.active_surface_tail == NO_SURFACE_SLOT_INDEX) {
            self.active_surface_head = encoded_index;
        } else {
            if (self.active_surface_tail >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface tail points outside slots");
            surfaces.slots[self.active_surface_tail].next_active_index = encoded_index;
        }
        self.active_surface_tail = encoded_index;
    }

    fn unlinkActiveSurface(self: *Session, surfaces: *SurfaceArena, slot_index: usize) void {
        if (slot_index >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface unlink points outside slots");
        const slot = &surfaces.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("active surface unlink requires a live slot");
        const previous = slot.previous_active_index;
        const next = slot.next_active_index;
        if (previous == NO_SURFACE_SLOT_INDEX) {
            if (self.active_surface_head != slot_index) native_util.impossibleByInvariant("active surface head matches its first link");
            self.active_surface_head = next;
        } else {
            if (previous >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface previous link points outside slots");
            surfaces.slots[previous].next_active_index = next;
        }
        if (next == NO_SURFACE_SLOT_INDEX) {
            if (self.active_surface_tail != slot_index) native_util.impossibleByInvariant("active surface tail matches its final link");
            self.active_surface_tail = previous;
        } else {
            if (next >= MAX_PRESENTED_SURFACES) native_util.impossibleByInvariant("active surface next link points outside slots");
            surfaces.slots[next].previous_active_index = previous;
        }
        slot.previous_active_index = NO_SURFACE_SLOT_INDEX;
        slot.next_active_index = NO_SURFACE_SLOT_INDEX;
    }

    fn removeSurfaceSlot(self: *Session, surfaces: *SurfaceArena, slot_index: usize) bool {
        if (slot_index >= MAX_PRESENTED_SURFACES) return false;
        const slot = &surfaces.slots[slot_index];
        if (!slot.in_use) return false;
        const task_key = surfaceTaskKey(slot.surface.task_id);
        if (builtin.mode == .debug) {
            std.debug.assert(self.surface_task_index.lookup(task_key) == slot_index);
        }
        self.surface_task_index.remove(task_key);
        self.unlinkActiveSurface(surfaces, slot_index);
        self.touchDisplay();
        return surfaces.removeIndex(slot_index);
    }

    fn closeWindowSlot(self: *Session, slot_index: usize) bool {
        if (slot_index >= MAX_WINDOWS) return false;
        const window_state = self.windowState() orelse return false;
        const slot = &window_state.windows.slots[slot_index];
        if (!slot.in_use) return false;
        const window = &slot.window;
        const window_id = window.id;

        self.touchDisplay();
        self.removeReviewItemsForWindow(window_id);
        if (window.bundle_id_len != 0) {
            window_state.task_bundle_index.remove(taskBundleKey(window.subject_task_id, window.bundleIdSlice()));
        }
        self.removeWindowFromTaskIndex(slot_index, window);
        self.removeWindowFromReviewerIndex(slot_index, window);
        self.removeWindowOrderAt(@intCast(slot.order_index), window_id);
        _ = window_state.windows.removeIndex(slot_index);
        if (self.window_count == 0) self.releaseWindowState();
        return true;
    }

    fn removeReviewItemsForWindow(self: *Session, window_id: u64) void {
        if (self.item_count == 0) return;
        const review_items = self.reviewItemsPtr() orelse
            native_util.impossibleByInvariant("non-empty compositor review state retains backing");
        var slot_index = review_items.window_review_item_index.head(windowReviewItemKey(window_id));
        while (slot_index != indexed_arena.no_index) {
            const next_slot_index = review_items.window_review_item_index.next(slot_index);
            if (slot_index >= MAX_REVIEW_ITEMS) native_util.impossibleByInvariant("window review-item index points outside review item slots");
            const slot = &review_items.items.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("window review-item index points at a free review item slot");
            if (slot.item.window_id != window_id) native_util.impossibleByInvariant("window review-item index points at the wrong window");
            self.removeReviewItemSlot(slot_index);
            slot_index = next_slot_index;
        }
    }

    fn indexReviewItemForWindow(self: *Session, slot_index: usize, item: *const ReviewItemRecord) void {
        const review_items = self.reviewItemsPtr() orelse
            native_util.impossibleByInvariant("indexed compositor review items retain backing");
        if (!review_items.window_review_item_index.append(windowReviewItemKey(item.window_id), slot_index)) {
            native_util.impossibleByInvariant("window review-item index capacity covers review item slots");
        }
    }

    fn removeReviewItemSlot(self: *Session, slot_index: usize) void {
        if (slot_index >= MAX_REVIEW_ITEMS) return;
        const review_items = self.reviewItemsPtr() orelse return;
        const slot = &review_items.items.slots[slot_index];
        if (!slot.in_use) return;
        const key = slot.key;
        const window_id = slot.item.window_id;
        if (!review_items.window_review_item_index.remove(windowReviewItemKey(window_id), slot_index)) {
            native_util.impossibleByInvariant("window review-item index missing live item");
        }
        _ = review_items.items.removeIndex(slot_index);
        self.removeItemOrderByKey(key);
    }

    fn removeWindowOrderAt(self: *Session, order_index: usize, window_id: u64) void {
        const window_state = self.windowState() orelse
            native_util.impossibleByInvariant("non-empty compositor order retains window state");
        const window_count: usize = self.window_count;
        if (order_index >= window_count or window_state.window_order[order_index] != window_id) {
            native_util.impossibleByInvariant("removed window order index points at the removed window");
        }
        var index = order_index;
        while (index + 1 < window_count) : (index += 1) {
            const shifted_window_id = window_state.window_order[index + 1];
            const shifted_slot = window_state.windows.get(shifted_window_id) orelse
                native_util.impossibleByInvariant("shifted window order points at a live window");
            shifted_slot.order_index = @intCast(index);
            window_state.window_order[index] = shifted_window_id;
        }
        self.window_count -= 1;
        window_state.window_order[@as(usize, self.window_count)] = 0;
        const removed_slot = window_state.windows.get(window_id) orelse
            native_util.impossibleByInvariant("removed window remains live while order compacts");
        removed_slot.order_index = NO_WINDOW_ORDER_INDEX;
    }

    fn removeItemOrderAt(self: *Session, order_index: usize) void {
        const item_count: usize = self.item_count;
        if (order_index >= item_count) return;
        const review_items = self.reviewItemsPtr() orelse
            native_util.impossibleByInvariant("non-empty compositor review order retains backing");
        var index = order_index;
        while (index + 1 < item_count) : (index += 1) {
            review_items.item_order[index] = review_items.item_order[index + 1];
        }
        self.item_count -= 1;
        review_items.item_order[@as(usize, self.item_count)] = 0;
        if (self.item_count == 0) self.releaseReviewItems();
    }

    fn removeItemOrderByKey(self: *Session, key: u64) void {
        const review_items = self.reviewItemsPtr() orelse return;
        var order_index: usize = 0;
        while (order_index < @as(usize, self.item_count)) : (order_index += 1) {
            if (review_items.item_order[order_index] == key) {
                self.removeItemOrderAt(order_index);
                return;
            }
        }
    }

    fn firstVisibleWindowId(self: *const Session) u64 {
        if (self.window_count == 0) return 0;
        const window = self.windowAtOrder(0) orelse
            native_util.impossibleByInvariant("non-empty compositor order has a first window");
        return window.id;
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

    pub fn switchVisible(self: *Service, direction: SwitchDirection) Error!SwitchResult {
        const result = try self.session.switchVisible(direction);
        self.checkpoint();
        return result;
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
                try self.session.restoreFromSnapshot(&store.snapshot);
                response.recovered = true;
            },
            .close_task_windows => {
                _ = self.session.closeWindowsForTask(request.subject_task_id);
            },
        }
    }

    fn checkpoint(self: *Service) void {
        const store = self.checkpoint_store orelse return;
        self.session.snapshotInto(&store.snapshot);
        store.valid = true;
    }
};

pub fn renderWindowToBuffer(buffer: []u8, window: *const WindowRecord) ![]const u8 {
    const surface_id = window.ui_surface_id orelse 0;
    var used: usize = 0;
    used += (try std.fmt.bufPrint(buffer[used..], "UI window: id={d} surface={d} type={s} modal={s} title={s} bundle={s} display={s}", .{
        window.id,
        surface_id,
        @tagName(window.view_type),
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
    const object_scope = if (item.objectScopeSlice().len == 0) "none" else item.objectScopeSlice();
    const network_path = if (item.networkPathSlice().len == 0) "none" else item.networkPathSlice();
    const data_leaves = if (item.networkPathSlice().len != 0)
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
    var lease_buffer: [LEASE_SUMMARY_BUFFER_BYTES]u8 = undefined;
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
        @tagName(item.decision),
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

fn surfaceSlotId(slot: *const SurfaceSlot) u64 {
    return slot.surface.presentation.surface_id;
}

fn surfaceTaskKey(task_id: u64) u64 {
    return indexed_arena.nonZeroKey(task_id);
}

fn taskBundleKey(task_id: u64, bundle_id: []const u8) u64 {
    var hash = native_util.fnv1a64AppendU64LittleEndian(native_util.FNV1A_64_OFFSET_BASIS, task_id);
    hash = native_util.fnv1a64WithSeed(hash, bundle_id);
    return indexed_arena.nonZeroKey(hash);
}

fn taskWindowKey(task_id: u64) u64 {
    return indexed_arena.nonZeroKey(task_id);
}

fn windowReviewItemKey(window_id: u64) u64 {
    return indexed_arena.nonZeroKey(window_id);
}

fn taskBundleMatches(context: anytype, slot: *const WindowSlot) bool {
    return slot.window.reviewer_task_id != 0 and
        slot.window.subject_task_id == context.task_id and
        std.mem.eql(u8, slot.window.bundleIdSlice(), context.bundle_id);
}

fn reviewItemKey(window_id: u64, kind: manifest.PermissionKind, resource: []const u8) u64 {
    var hash = native_util.fnv1a64AppendU64LittleEndian(native_util.FNV1A_64_OFFSET_BASIS, window_id);
    hash = native_util.fnv1a64AppendByte(hash, @backingInt(kind));
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
        error.WindowIdExhausted => .id_exhausted,
        error.WindowNotFound, error.ReviewItemNotFound, error.TaskNotFound => .not_found,
        error.WindowTableFull, error.ReviewItemTableFull, error.SurfaceTableFull => .table_full,
        error.RecoveryStateMissing => .recovery_missing,
        error.OutOfMemory => .resource_exhausted,
        error.InvalidSurface, error.MalformedRequest, error.MalformedPresentation, error.StalePresentation, error.PresentationConflict, error.NoVisibleWindows => .invalid_request,
    };
}

fn requireTaskSurface(app_task: *const task_runtime.TaskRecord) Error!u64 {
    const surface_id = app_task.ui_surface_id orelse return error.InvalidSurface;
    if (surface_id == 0) return error.InvalidSurface;
    return surface_id;
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

fn compositorTestBudget(endpoint_slots: u16) task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 100,
        .memory_bytes = units.kibibytes(1),
        .endpoint_slots = endpoint_slots,
        .shared_memory_bytes = units.kibibytes(1),
    };
}

fn testSurfacePresentation(surface_id: u64) abi.SurfacePresentation {
    return .{ .surface_id = surface_id, .revision = 1 };
}

const EPHEMERAL_TEST_SHARED_MEMORY_BYTES: usize = 512;
const TEST_WINDOW_RENDER_BUFFER_BYTES: usize = 512;
const TEST_REVIEW_HEADER_BUFFER_BYTES: usize = 256;
const TEST_REVIEW_ITEM_BUFFER_BYTES: usize = 512;
const TEST_REVIEW_DECISION_BUFFER_BYTES: usize = 256;
const TEST_COMPACT_RENDER_BUFFER_BYTES: usize = 320;

test "compositor compact record metadata preserves exact text capacities" {
    try std.testing.expect(@FieldType(WindowSlot, "order_index") == WindowOrderIndex);
    try std.testing.expect(@FieldType(Session, "window_count") == SessionCount);
    try std.testing.expect(@FieldType(Session, "item_count") == SessionCount);
    try std.testing.expectEqual(@as(usize, SESSION_SNAPSHOT_SIZE_CEILING_BYTES), @sizeOf(SessionSnapshot));
    try std.testing.expectEqual(@as(usize, CHECKPOINT_STORE_SIZE_CEILING_BYTES), @sizeOf(CheckpointStore));
    try std.testing.expectEqual(@as(usize, SESSION_SIZE_CEILING_BYTES), @sizeOf(Session));

    const long_label = @as([MAX_LABEL_BYTES + 1]u8, @splat('l'));
    const long_resource = @as([MAX_RESOURCE_BYTES + 1]u8, @splat('r'));
    const long_reason = @as([MAX_REASON_BYTES + 1]u8, @splat('d'));

    var window = zeroWindow();
    window.bundle_id_len = @intCast(copyText(&window.bundle_id, &long_label));
    window.display_name_len = @intCast(copyText(&window.display_name, &long_label));
    window.title_len = @intCast(copyText(&window.title, &long_label));
    window.detail_len = @intCast(copyText(&window.detail, &long_resource));
    window.item_count = @intCast(MAX_REVIEW_ITEMS);
    try std.testing.expectEqual(@as(usize, MAX_LABEL_BYTES), window.bundleIdSlice().len);
    try std.testing.expectEqual(@as(usize, MAX_LABEL_BYTES), window.displayNameSlice().len);
    try std.testing.expectEqual(@as(usize, MAX_TITLE_BYTES), window.titleSlice().len);
    try std.testing.expectEqual(@as(usize, MAX_WINDOW_DETAIL_BYTES), window.detailSlice().len);
    try std.testing.expectEqual(@as(u8, MAX_REVIEW_ITEMS), window.item_count);

    var item = zeroItem();
    item.resource_len = @intCast(copyText(&item.resource, &long_resource));
    item.reason_len = @intCast(copyText(&item.reason, &long_reason));
    try std.testing.expectEqual(@as(usize, MAX_RESOURCE_BYTES), item.resourceSlice().len);
    try std.testing.expectEqual(@as(usize, MAX_REASON_BYTES), item.reasonSlice().len);
    try std.testing.expectEqual(@as(usize, MAX_RESOURCE_BYTES), item.objectScopeSlice().len);
    try std.testing.expectEqualStrings("", item.networkPathSlice());
    item.kind = .network_egress;
    try std.testing.expectEqual(@as(usize, MAX_RESOURCE_BYTES), item.networkPathSlice().len);
    try std.testing.expectEqualStrings("", item.objectScopeSlice());
}

test "zero-filled compositor review backing is an empty arena order and index" {
    var review_items: ReviewItemBacking = undefined;
    @memset(std.mem.asBytes(&review_items), 0);

    try std.testing.expectEqual(@as(usize, 0), review_items.items.countInUse());
    try std.testing.expectEqual(@as(u64, 0), review_items.item_order[0]);

    const slot_index = review_items.items.reserveIndex(7).?;
    try std.testing.expectEqual(@as(usize, 0), slot_index);
    try std.testing.expect(review_items.window_review_item_index.append(11, slot_index));
    try std.testing.expectEqual(@as(usize, 1), review_items.window_review_item_index.count(11));
    try std.testing.expect(review_items.window_review_item_index.remove(11, slot_index));
    try std.testing.expect(review_items.items.removeIndex(slot_index));
}

test "zero-filled compositor surface arena preserves empty and reusable slot invariants" {
    var surfaces: SurfaceArena = undefined;
    @memset(std.mem.asBytes(&surfaces), 0);

    try std.testing.expectEqual(@as(usize, 0), surfaces.countInUse());
    const slot_index = surfaces.reserveIndex(7).?;
    try std.testing.expectEqual(@as(usize, 0), slot_index);
    try std.testing.expect(surfaces.removeIndex(slot_index));
    try std.testing.expectEqual(slot_index, surfaces.reserveIndex(8).?);
}

test "compositor service opens switches reviews decides and recovers" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 9 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 12,
        .local_only = true,
    });
    var session = Session.init();
    var checkpoint_store = CheckpointStore{};
    var service = Service.initWithCheckpoint(44, 45, &runtime, &session, &checkpoint_store);

    const open_response = service.dispatch(.{
        .operation = .open_view,
        .view_type = .workspace_view,
        .subject_task_id = app_task.id,
        .workspace_id = 41,
        .detail = "Trip",
    });
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
        .budget = compositorTestBudget(4),
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
    try std.testing.expectEqual(@as(usize, 3), session.visibleWindowCount());
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
    try std.testing.expectEqual(@as(usize, 0), session.visibleWindowCount());
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
    try std.testing.expectEqual(@as(usize, 1), session.visibleWindowCount());
    try std.testing.expectEqual(@as(u16, 1), reopened.visible_window_count);
}

test "compositor task window index survives restore and closes only matching task" {
    const manifest_fixtures = @import("../policy/manifest_fixtures.zig");

    var runtime = task_runtime.Runtime.init();
    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 41 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 41,
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 42 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 42,
        .local_only = true,
    });

    const permissions = manifest_fixtures.notes_permissions[0..2];
    var bundle = manifest_fixtures.notesBundle();
    bundle.requested_permissions = permissions;

    var session = Session.init();
    const first_document = try session.openDocumentView(first_task, 900, "first.md");
    const first_document_id = first_document.id;
    const second_document = try session.openDocumentView(second_task, 901, "second.md");
    const second_document_id = second_document.id;
    const first_review = try session.beginPermissionReview(77, first_task, bundle);
    _ = try session.ensureReviewItem(first_review.id, bundle, permissions[0]);
    _ = try session.ensureReviewItem(first_review.id, bundle, permissions[1]);
    const second_review = try session.beginPermissionReview(78, second_task, bundle);
    _ = try session.ensureReviewItem(second_review.id, bundle, permissions[0]);
    _ = try session.openTaskView(second_task, "Second Task");
    try std.testing.expectEqual(@as(usize, 5), session.window_count);
    try std.testing.expectEqual(@as(usize, 5), session.visibleWindowCount());
    try std.testing.expectEqual(@as(usize, 3), session.item_count);
    try std.testing.expectEqual(first_review.id, session.findWindowForTaskBundleConst(first_task.id, bundle.bundle_id).?.id);
    try std.testing.expect(session.taskOwnsVisibleWindow(first_task.id));
    try std.testing.expect(session.taskOwnsVisibleWindow(second_task.id));
    try std.testing.expect(session.taskOwnsVisibleWindow(77));
    try std.testing.expect(session.taskOwnsVisibleWindow(78));
    try std.testing.expect(!session.taskOwnsVisibleWindow(79));

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expect(restored.taskOwnsVisibleWindow(first_task.id));
    try std.testing.expect(restored.taskOwnsVisibleWindow(77));

    try std.testing.expectEqual(@as(usize, 2), restored.closeWindowsForTask(first_task.id));
    try std.testing.expect(restored.findWindowConst(first_document_id) == null);
    try std.testing.expect(restored.findWindowForTaskBundleConst(first_task.id, bundle.bundle_id) == null);
    try std.testing.expect(restored.findWindowConst(second_document_id) != null);
    try std.testing.expect(restored.findReviewItemConst(second_review.id, permissions[0].kind, permissions[0].resource) != null);
    try std.testing.expectEqual(@as(usize, 3), restored.window_count);
    try std.testing.expectEqual(@as(usize, 3), restored.visibleWindowCount());
    try std.testing.expectEqual(@as(usize, 1), restored.item_count);
    try std.testing.expect(!restored.taskOwnsVisibleWindow(first_task.id));
    try std.testing.expect(!restored.taskOwnsVisibleWindow(77));
    try std.testing.expect(restored.taskOwnsVisibleWindow(second_task.id));
    try std.testing.expect(restored.taskOwnsVisibleWindow(78));

    try std.testing.expectEqual(@as(usize, 3), restored.closeWindowsForTask(second_task.id));
    try std.testing.expectEqual(@as(usize, 0), restored.window_count);
    try std.testing.expectEqual(@as(usize, 0), restored.visibleWindowCount());
    try std.testing.expectEqual(@as(usize, 0), restored.item_count);
    try std.testing.expectEqual(@as(u64, 0), restored.active_window_id);
    try std.testing.expect(!restored.taskOwnsVisibleWindow(second_task.id));
    try std.testing.expect(!restored.taskOwnsVisibleWindow(78));
}

test "compositor window order indexes saturated switching removal and restore" {
    var runtime = task_runtime.Runtime.init();
    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 51 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 51,
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 52 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 52,
        .local_only = true,
    });

    var session = Session.init();
    var window_ids: [MAX_WINDOWS]u64 = @as([MAX_WINDOWS]u64, @splat(0));
    for (&window_ids, 0..) |*window_id, order_index| {
        const owner = if (order_index % 2 == 0) first_task else second_task;
        const window = try session.openTaskView(owner, "Saturated order");
        window_id.* = window.id;
        try std.testing.expectEqual(order_index, session.windowStateConst().?.windows.getConst(window.id).?.order_index);
        try std.testing.expectEqual(window.id, session.windowAtOrder(order_index).?.id);
    }
    try std.testing.expectError(error.WindowTableFull, session.openTaskView(first_task, "Overflow"));
    try std.testing.expectEqual(@as(?usize, MAX_WINDOWS - 1), session.activeWindowOrderIndex());

    const wrapped_first = try session.switchVisible(.next);
    try std.testing.expectEqual(@as(usize, 0), wrapped_first.visible_index);
    try std.testing.expectEqual(window_ids[0], wrapped_first.window.id);
    const wrapped_last = try session.switchVisible(.previous);
    try std.testing.expectEqual(@as(usize, MAX_WINDOWS - 1), wrapped_last.visible_index);
    try std.testing.expectEqual(window_ids[MAX_WINDOWS - 1], wrapped_last.window.id);

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(?usize, MAX_WINDOWS - 1), restored.activeWindowOrderIndex());
    for (window_ids, 0..) |window_id, order_index| {
        try std.testing.expectEqual(window_id, restored.windowAtOrder(order_index).?.id);
    }

    try std.testing.expectEqual(@as(usize, MAX_WINDOWS / 2), restored.closeWindowsForTask(first_task.id));
    try std.testing.expectEqual(@as(usize, MAX_WINDOWS / 2), restored.window_count);
    try std.testing.expectEqual(@as(?usize, MAX_WINDOWS / 2 - 1), restored.activeWindowOrderIndex());
    for (0..MAX_WINDOWS / 2) |order_index| {
        const expected_window_id = window_ids[order_index * 2 + 1];
        try std.testing.expectEqual(expected_window_id, restored.windowAtOrder(order_index).?.id);
        try std.testing.expectEqual(order_index, restored.windowStateConst().?.windows.getConst(expected_window_id).?.order_index);
    }

    const compact_wrapped_first = try restored.switchVisible(.next);
    try std.testing.expectEqual(@as(usize, 0), compact_wrapped_first.visible_index);
    try std.testing.expectEqual(window_ids[1], compact_wrapped_first.window.id);
    const compact_wrapped_last = try restored.switchVisible(.previous);
    try std.testing.expectEqual(@as(usize, MAX_WINDOWS / 2 - 1), compact_wrapped_last.visible_index);
    try std.testing.expectEqual(window_ids[MAX_WINDOWS - 1], compact_wrapped_last.window.id);

    try std.testing.expectEqual(@as(usize, MAX_WINDOWS / 2), restored.closeWindowsForTask(second_task.id));
    try std.testing.expectEqual(@as(?usize, null), restored.activeWindowOrderIndex());
    try std.testing.expectError(error.NoVisibleWindows, restored.switchVisible(.next));
}

test "compositor service rejects tasks without valid display surfaces" {
    var runtime = task_runtime.Runtime.init();
    const headless_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 21 },
        .component_class = .app_component,
        .budget = compositorTestBudget(2),
        .local_only = true,
    });
    const zero_surface_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 22 },
        .component_class = .app_component,
        .budget = compositorTestBudget(2),
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
    const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service.bind(70, .{ .kind = .service, .serial = 70 });

    const app_image = try generated_image_fixtures.appImage();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 70 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(4),
        },
        .ui_surface_id = 91,
        .local_only = true,
        .initial_component = .{
            .label = "viewer",
            .entry = "app.viewer",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 70_001,
            .signed = true,
            .bundle_id = "app.viewer",
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
        .bundle_id = "app.viewer",
        .display_name = "Viewer",
        .detail = "Calendar Panel",
    });
    try std.testing.expectEqual(ServiceStatus.ok, panel_response.status);
    try std.testing.expectEqual(panel_response.window_id, session.active_window_id);

    _ = try runtime.attachComponent(app_task_id, .{
        .label = "viewer-panel",
        .entry = "app.viewer.panel",
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
    try runtime_service.checkpoint(14);

    const ephemeral_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 71 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 1,
            .shared_memory_bytes = EPHEMERAL_TEST_SHARED_MEMORY_BYTES,
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
    try std.testing.expectEqualStrings("app.viewer", restored_task.launchBundleIdSlice());
    try std.testing.expectEqual(@as(usize, 2), restored_task.execution_component_count);
    try std.testing.expectEqualStrings("viewer-panel", restored_task.executionComponents()[1].labelSlice());
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
    try std.testing.expectEqualStrings("app.viewer", restored_panel_window.bundleIdSlice());
    try std.testing.expectEqualStrings("Viewer", restored_panel_window.displayNameSlice());

    var render_buffer: [TEST_WINDOW_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered_task = try renderWindowToBuffer(&render_buffer, restored_task_window);
    try std.testing.expect(std.mem.indexOf(u8, rendered_task, "type=full_screen_task_view") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_task, "title=Task: Coordinate Trip") != null);
    const rendered_panel = try renderWindowToBuffer(&render_buffer, restored_panel_window);
    try std.testing.expect(std.mem.indexOf(u8, rendered_panel, "bundle=app.viewer") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_panel, "display=Viewer") != null);
}

test "compositor session creates app-panel permission review windows and cards" {
    const manifest_fixtures = @import("../policy/manifest_fixtures.zig");

    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
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
    try std.testing.expectEqual(@as(manifest.LeaseTicks, 400), object_item.requested_lease_ticks);

    _ = try session.recordDecision(window.id, permissions[0], true, true, 400);
    try std.testing.expectEqual(DecisionState.allow, session.findReviewItemConst(window.id, .object_access, "workspace:notes").?.decision);

    var header_buffer: [TEST_REVIEW_HEADER_BUFFER_BYTES]u8 = undefined;
    var item_buffer: [TEST_REVIEW_ITEM_BUFFER_BYTES]u8 = undefined;
    var decision_buffer: [TEST_REVIEW_DECISION_BUFFER_BYTES]u8 = undefined;
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
        .budget = compositorTestBudget(4),
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

test "a task-bundle key hash collision is a lookup miss and a review conflict" {
    var runtime = task_runtime.Runtime.init();
    defer runtime.reset();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 6,
        .local_only = true,
    });
    const first_bundle = manifest.BundleManifest{
        .bundle_id = "app.collision-first",
        .display_name = "Collision First",
        .publisher = "zigos.dev",
    };
    const second_bundle = manifest.BundleManifest{
        .bundle_id = "app.collision-second",
        .display_name = "Collision Second",
        .publisher = "zigos.dev",
    };

    var session = Session.init();
    defer session.deinit();
    const first = try session.beginPermissionReview(11, app_task, first_bundle);
    // Model a collision: the second bundle's key resolves to the first window.
    const index = &session.windowState().?.task_bundle_index;
    const first_key = taskBundleKey(app_task.id, first_bundle.bundle_id);
    const second_key = taskBundleKey(app_task.id, second_bundle.bundle_id);
    const slot_index = index.lookup(first_key).?;
    index.remove(first_key);
    index.insert(second_key, slot_index);

    try std.testing.expect(session.findWindowForTaskBundle(app_task.id, second_bundle.bundle_id) == null);
    try std.testing.expectError(error.PresentationConflict, session.beginPermissionReview(11, app_task, second_bundle));
    try std.testing.expectEqual(@as(usize, 1), session.window_count);
    try std.testing.expectEqual(first.id, session.findWindowConst(first.id).?.id);
    try std.testing.expectEqualStrings(first_bundle.bundle_id, session.findWindowConst(first.id).?.bundleIdSlice());
    try std.testing.expectEqual(@as(?usize, slot_index), index.lookup(second_key));
}

test "compositor session opens document workspace and full-screen task views" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
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
    try std.testing.expectEqual(@as(usize, 3), session.visibleWindowCount());

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(usize, 3), restored.window_count);
    try std.testing.expectEqual(@as(usize, 3), restored.visibleWindowCount());

    try std.testing.expectEqual(ViewType.document_view, document.view_type);
    try std.testing.expectEqual(@as(u64, 41), document.workspace_id);
    try std.testing.expectEqualStrings("documents/plan.md", document.detailSlice());
    try std.testing.expectEqual(ViewType.workspace_view, workspace_window.view_type);
    try std.testing.expectEqualStrings("Trip Project", workspace_window.detailSlice());
    try std.testing.expectEqual(ViewType.full_screen_task_view, fullscreen.view_type);
    try std.testing.expectEqualStrings("Edit Media Project", fullscreen.titleSlice());

    var buffer: [TEST_COMPACT_RENDER_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderWindowToBuffer(&buffer, document);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "type=document_view") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "detail=documents/plan.md") != null);

    const workspace_rendered = try renderWindowToBuffer(&buffer, workspace_window);
    try std.testing.expect(std.mem.indexOf(u8, workspace_rendered, "type=workspace_view") != null);

    const fullscreen_rendered = try renderWindowToBuffer(&buffer, fullscreen);
    try std.testing.expect(std.mem.indexOf(u8, fullscreen_rendered, "type=full_screen_task_view") != null);
    try std.testing.expect(session.probeVisibleWindow(&buffer));
}

test "compositor window ids stop at exhaustion" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 4 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 8,
        .local_only = true,
    });

    var session = Session.init();
    session.next_window_id = std.math.maxInt(u64);
    const final_window = try session.openDocumentView(app_task, 42, "documents/final.md");
    try std.testing.expectEqual(std.math.maxInt(u64), final_window.id);
    try std.testing.expectEqual(@as(u64, 0), session.next_window_id);
    try std.testing.expectError(error.WindowIdExhausted, session.openWorkspaceView(app_task, 42, "Final Project"));
    try std.testing.expectEqual(@as(usize, 1), session.window_count);
    try std.testing.expect(session.findWindowConst(0) == null);
    try std.testing.expectEqual(ServiceStatus.id_exhausted, statusForError(error.WindowIdExhausted));
    try std.testing.expectEqual(ServiceStatus.resource_exhausted, statusForError(error.OutOfMemory));

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 0), restored.next_window_id);
    try std.testing.expectError(error.WindowIdExhausted, restored.openTaskView(app_task, "Final Task"));
}

test "compositor session owns bounded monotonic surface presentations" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 81 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 71,
        .local_only = true,
    });
    var session = Session.init();

    var presentation = abi.SurfacePresentation{ .surface_id = 71, .revision = 2 };

    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(app_task, &presentation));
    try std.testing.expectEqual(PresentResult.duplicate, try session.presentSurface(app_task, &presentation));
    try std.testing.expectEqual(@as(usize, 1), session.presentedSurfaceCount());
    const surface_slot_index = session.surfaces.get().?.slotIndexOf(71).?;
    try std.testing.expectEqual(@as(?usize, surface_slot_index), session.surface_task_index.lookup(surfaceTaskKey(app_task.id)));
    try std.testing.expectEqual(@as(u16, @intCast(surface_slot_index)), session.active_surface_head);
    try std.testing.expectEqual(@as(u16, @intCast(surface_slot_index)), session.active_surface_tail);
    try std.testing.expectEqual(@as(u64, 2), session.surfacePresentation(71).?.presentation.revision);
    _ = try session.openTaskView(app_task, "Notes");

    presentation.revision = 3;
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(app_task, &presentation));

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 3), restored.surfacePresentation(71).?.presentation.revision);
    try std.testing.expectEqual(@as(?usize, surface_slot_index), restored.surface_task_index.lookup(surfaceTaskKey(app_task.id)));
    try std.testing.expectEqual(@as(u16, @intCast(surface_slot_index)), restored.active_surface_head);

    presentation.revision = 2;
    try std.testing.expectError(error.StalePresentation, restored.presentSurface(app_task, &presentation));
    presentation.revision = 3;
    const blank = abi.SurfaceText{ .state = .{ .model = 1 } };
    try std.testing.expectError(error.PresentationConflict, restored.presentSurfaceText(app_task, &presentation, &blank));
    const foreign_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 82 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 72,
        .local_only = true,
    });
    try std.testing.expectError(error.InvalidSurface, restored.presentSurface(foreign_task, &presentation));

    try std.testing.expect(try runtime.terminateTask(app_task.id, 100));
    try std.testing.expectEqual(@as(usize, 1), restored.pruneSurfacePresentations(&runtime));
    try std.testing.expect(restored.surface_task_index.lookup(surfaceTaskKey(app_task.id)) == null);
    try std.testing.expectEqual(NO_SURFACE_SLOT_INDEX, restored.active_surface_head);
    try std.testing.expectEqual(NO_SURFACE_SLOT_INDEX, restored.active_surface_tail);
    try std.testing.expectEqual(@as(usize, 1), restored.closeWindowsForTask(app_task.id));
    try std.testing.expectEqual(@as(usize, 0), restored.presentedSurfaceCount());
}

test "compositor text snapshots isolate mutations and reject revision and window conflicts" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 82 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 72,
        .local_only = true,
    });
    var session = Session.init();
    const window = try session.openTaskView(task, "Notes");
    var presentation = testSurfacePresentation(72);
    var text = abi.SurfaceText{ .window_id = window.id, .state = .{ .model = 1, .selection_anchor = 5 }, .text_length = 5, .cursor = 5 };
    @memcpy(text.text[0..5], "Draft");
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurfaceText(task, &presentation, &text));
    try std.testing.expectEqual(PresentResult.duplicate, try session.presentSurfaceText(task, &presentation, &text));
    text.state.selection_anchor = 0;
    try std.testing.expectError(error.PresentationConflict, session.presentSurfaceText(task, &presentation, &text));
    text.state.selection_anchor = 5;
    text.text[0] = 'X';
    try std.testing.expectEqualStrings("Draft", session.surfacePresentation(72).?.text.?.textSlice());
    try std.testing.expectError(error.PresentationConflict, session.presentSurfaceText(task, &presentation, &text));
    presentation.revision += 1;
    text.window_id += 1;
    try std.testing.expectError(error.InvalidSurface, session.presentSurfaceText(task, &presentation, &text));
    text.window_id = window.id;
    text.text[511] = 'X';
    try std.testing.expectError(error.MalformedPresentation, session.presentSurfaceText(task, &presentation, &text));
    text.text[511] = 0;
    text.cursor = 6;
    try std.testing.expectError(error.MalformedPresentation, session.presentSurfaceText(task, &presentation, &text));
    text.cursor = 5;
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurfaceText(task, &presentation, &text));
    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqualStrings("Xraft", restored.surfacePresentation(72).?.text.?.textSlice());
    _ = restored.closeWindowsForTask(task.id);
    try std.testing.expect(restored.surfacePresentation(72) == null);
}

test "compositor surface pruning caches unchanged task lifecycle generations" {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 83 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 73,
        .local_only = true,
    });
    const app_task_id = app_task.id;
    var session = Session.init();
    const presentation = testSurfacePresentation(73);
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(app_task, &presentation));

    try std.testing.expectEqual(@as(u64, 0), session.last_surface_prune_generation);
    try std.testing.expectEqual(@as(usize, 0), session.pruneSurfacePresentations(&runtime));
    try std.testing.expectEqual(runtime.taskLifecycleGeneration(), session.last_surface_prune_generation);
    try std.testing.expectEqual(@as(usize, 0), session.pruneSurfacePresentations(&runtime));
    try std.testing.expect(session.surfacePresentation(73) != null);

    try std.testing.expect(try runtime.suspendTask(app_task_id, 110));
    try std.testing.expectEqual(@as(usize, 1), session.pruneSurfacePresentations(&runtime));
    try std.testing.expect(session.surfacePresentation(73) == null);

    try std.testing.expect(try runtime.resumeTask(app_task_id, 111));
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(runtime.find(app_task_id).?, &presentation));
    try std.testing.expectEqual(@as(usize, 0), session.pruneSurfacePresentations(&runtime));
    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    try session.restoreFromSnapshot(&snapshot);
    try std.testing.expectEqual(@as(u64, 0), session.last_surface_prune_generation);
    try std.testing.expectEqual(@as(usize, 0), session.pruneSurfacePresentations(&runtime));

    // Lifecycle generations beyond the compact cache remain correct: they
    // take the bounded prune path instead of aliasing an earlier generation.
    runtime.task_lifecycle_generation = @as(u64, std.math.maxInt(u32)) + 1;
    try std.testing.expectEqual(@as(usize, 0), session.pruneSurfacePresentations(&runtime));
    try std.testing.expect(try runtime.suspendTask(app_task_id, 112));
    try std.testing.expectEqual(@as(usize, 1), session.pruneSurfacePresentations(&runtime));
    try std.testing.expect(try runtime.resumeTask(app_task_id, 113));
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(runtime.find(app_task_id).?, &presentation));
    runtime.reset();
    try std.testing.expectEqual(@as(usize, 1), session.pruneSurfacePresentations(&runtime));
    try std.testing.expect(session.surfacePresentation(73) == null);
}

test "compositor surface indexes saturate prune restore and reuse exact slots" {
    var runtime = task_runtime.Runtime.init();
    var session = Session.init();
    var task_ids: [MAX_PRESENTED_SURFACES]u64 = @as([MAX_PRESENTED_SURFACES]u64, @splat(0));
    var surface_ids: [MAX_PRESENTED_SURFACES]u64 = @as([MAX_PRESENTED_SURFACES]u64, @splat(0));
    var slot_indexes: [MAX_PRESENTED_SURFACES]usize = @as([MAX_PRESENTED_SURFACES]usize, @splat(0));

    for (0..MAX_PRESENTED_SURFACES) |index| {
        const surface_id: u64 = 1_000 + @as(u64, @intCast(index));
        const task = try runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = surface_id },
            .component_class = .app_component,
            .budget = compositorTestBudget(4),
            .ui_surface_id = surface_id,
            .local_only = true,
        });
        const presentation = testSurfacePresentation(surface_id);
        try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(task, &presentation));
        task_ids[index] = task.id;
        surface_ids[index] = surface_id;
        slot_indexes[index] = session.surfaces.get().?.slotIndexOf(surface_id).?;
        try std.testing.expectEqual(@as(?usize, slot_indexes[index]), session.surface_task_index.lookup(surfaceTaskKey(task.id)));
    }

    try std.testing.expectEqual(@as(usize, MAX_PRESENTED_SURFACES), session.presentedSurfaceCount());
    try std.testing.expectEqual(@as(u16, @intCast(slot_indexes[0])), session.active_surface_head);
    try std.testing.expectEqual(@as(u16, @intCast(slot_indexes[MAX_PRESENTED_SURFACES - 1])), session.active_surface_tail);
    const overflow_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2_000 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 2_000,
        .local_only = true,
    });
    const overflow_presentation = testSurfacePresentation(2_000);
    try std.testing.expectError(error.SurfaceTableFull, session.presentSurface(overflow_task, &overflow_presentation));

    const removed_index = MAX_PRESENTED_SURFACES / 2;
    const removed_slot_index = slot_indexes[removed_index];
    try std.testing.expectEqual(@as(usize, 0), session.closeWindowsForTask(task_ids[removed_index]));
    try std.testing.expect(session.surfacePresentation(surface_ids[removed_index]) == null);
    try std.testing.expect(session.surface_task_index.lookup(surfaceTaskKey(task_ids[removed_index])) == null);
    try std.testing.expectEqual(@as(usize, MAX_PRESENTED_SURFACES - 1), session.presentedSurfaceCount());

    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(overflow_task, &overflow_presentation));
    try std.testing.expectEqual(removed_slot_index, session.surfaces.get().?.slotIndexOf(2_000).?);
    try std.testing.expectEqual(@as(u16, @intCast(removed_slot_index)), session.active_surface_tail);
    try std.testing.expectEqual(@as(usize, MAX_PRESENTED_SURFACES), session.presentedSurfaceCount());

    var snapshot: SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    var restored = Session.init();
    try restored.restoreFromSnapshot(&snapshot);
    try std.testing.expect(try runtime.terminateTask(task_ids[1], 101));
    try std.testing.expect(try runtime.terminateTask(task_ids[MAX_PRESENTED_SURFACES - 2], 102));
    try std.testing.expectEqual(@as(usize, 2), restored.pruneSurfacePresentations(&runtime));
    try std.testing.expect(restored.surface_task_index.lookup(surfaceTaskKey(task_ids[1])) == null);
    try std.testing.expect(restored.surface_task_index.lookup(surfaceTaskKey(task_ids[MAX_PRESENTED_SURFACES - 2])) == null);
    try std.testing.expectEqual(@as(usize, MAX_PRESENTED_SURFACES - 2), restored.presentedSurfaceCount());

    var previous = NO_SURFACE_SLOT_INDEX;
    var active_index: usize = restored.active_surface_head;
    var active_count: usize = 0;
    var seen: [MAX_PRESENTED_SURFACES]bool = @as([MAX_PRESENTED_SURFACES]bool, @splat(false));
    while (active_index != NO_SURFACE_SLOT_INDEX) {
        try std.testing.expect(active_index < MAX_PRESENTED_SURFACES);
        try std.testing.expect(!seen[active_index]);
        seen[active_index] = true;
        const slot = &restored.surfaces.get().?.slots[active_index];
        try std.testing.expect(slot.in_use);
        try std.testing.expectEqual(previous, slot.previous_active_index);
        try std.testing.expectEqual(@as(?usize, active_index), restored.surface_task_index.lookup(surfaceTaskKey(slot.surface.task_id)));
        previous = @intCast(active_index);
        active_index = slot.next_active_index;
        active_count += 1;
    }
    try std.testing.expectEqual(@as(usize, MAX_PRESENTED_SURFACES - 2), active_count);
    try std.testing.expectEqual(restored.active_surface_tail, previous);
}

test "compositor orders presentation revisions per surface" {
    var runtime = task_runtime.Runtime.init();
    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 101 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 101,
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 102 },
        .component_class = .app_component,
        .budget = compositorTestBudget(4),
        .ui_surface_id = 102,
        .local_only = true,
    });
    var session = Session.init();
    defer session.deinit();
    var first = testSurfacePresentation(101);
    first.revision = 100;
    var second = testSurfacePresentation(102);
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(first_task, &first));
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(second_task, &second));

    first.revision = 99;
    try std.testing.expectError(error.StalePresentation, session.presentSurface(first_task, &first));
    try std.testing.expectEqual(@as(u64, 100), session.surfacePresentation(101).?.presentation.revision);

    first.revision = 101;
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(first_task, &first));
    try std.testing.expectEqual(PresentResult.duplicate, try session.presentSurface(second_task, &second));
    second.revision = 2;
    try std.testing.expectEqual(PresentResult.accepted, try session.presentSurface(second_task, &second));
    try std.testing.expectEqual(@as(u64, 101), session.surfacePresentation(101).?.presentation.revision);
    try std.testing.expectEqual(@as(u64, 2), session.surfacePresentation(102).?.presentation.revision);
}
