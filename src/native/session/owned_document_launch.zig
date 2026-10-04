//! Native Notes selection and approval retain no application authority until
//! the authenticated owner approves one measured task and one exact document.
const builtin = @import("builtin");
const std = @import("std");
const ids = @import("../core/ids.zig");
const principal = @import("../core/principal.zig");
const unlock = @import("../platform/unlock_context.zig");
const operation_guard = @import("../platform/operation_guard.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const object_signer = @import("../storage/sealed_object_signer.zig");
const document_view = @import("../platform/trusted_document_view.zig");
const document_grants = @import("document_grants.zig");
const document_worker = @import("../services/document_operation_worker.zig");
const component_port = @import("../kernel_api/component_port.zig");
const input_router = @import("../platform/input_router.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const units = @import("../core/units.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding) @import("../../kernel/memory/memory.zig") else struct {};

pub const DocumentAccess = struct {
    owner: principal.PrincipalId,
    binding: unlock.Binding,
    expires_at_ticks: u64,
    signer: object_signer.Signer,
    authorization: document_grants.Authorization,
};

pub const WORKSPACE_LABEL = "Notes";
pub const MAX_ACTIVE_GRANTS: usize = 4;
pub const PAGE_ENTRIES: usize = 4;

const Grant = document_grants.Grant;

const Created = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    published: bool = false,
    checkpoint_generation: u64 = 0,
};

// A failed flush keeps exactly this immutable candidate. Retrying must not
// append another version, and cancellation must not erase a published object.
const Creation = struct {
    pending: ?Created = null,

    fn run(self: *Creation, storage: *storage_service.Service, access: DocumentAccess, path: []const u8, signer: object_signer.Signer, guard: *const operation_guard.Guard) !Created {
        var now = try operation_guard.currentTicks(guard, 0);
        try signer.validateService(storage.owner, storage.task_id, now);
        try storage.requireDurableBoundary();
        if (self.pending == null) {
            const before = try ownedWorkspace(storage, access.owner);
            const workspace_id = if (before) |record| record.id.raw() else 0;
            if (before) |record| try requireAbsent(storage, record.id.raw(), path);
            const metadata = try signer.signMetadata(path, "", now);
            now = try operation_guard.currentTicks(guard, now);
            try signer.validateService(storage.owner, storage.task_id, now);
            const after = try ownedWorkspace(storage, access.owner);
            if ((if (after) |record| record.id.raw() else @as(u64, 0)) != workspace_id) return error.DocumentChanged;
            if (after) |record| try requireAbsent(storage, record.id.raw(), path);
            storage.beginCheckpointBatch();
            defer storage.endCheckpointBatch();
            const record = after orelse try storage.createWorkspace(.{ .owner = access.owner, .label = WORKSPACE_LABEL });
            const version = try storage.putVersion(.{ .object_type = .document, .payload = "", .metadata = metadata });
            self.pending = .{ .workspace_id = record.id.raw(), .object_id = version.object_id.raw(), .version_id = version.version_id.raw() };
        }
        var pending = self.pending.?;
        const record = (try ownedWorkspace(storage, access.owner)) orelse return error.DocumentChanged;
        if (record.id.raw() != pending.workspace_id) return error.DocumentChanged;
        const version = storage.version(pending.version_id) orelse return error.DocumentChanged;
        if (version.object_id.raw() != pending.object_id or version.object_type != .document) return error.DocumentChanged;
        if (!pending.published) {
            try requireAbsent(storage, pending.workspace_id, path);
            storage.beginCheckpointBatch();
            defer storage.endCheckpointBatch();
            try storage.beginTransaction(pending.workspace_id);
            errdefer storage.abortTransaction(pending.workspace_id) catch {};
            try storage.stagePut(pending.workspace_id, path, pending.object_id, pending.version_id, .document);
            _ = try storage.commit(pending.workspace_id, now);
            pending.published = true;
            self.pending = pending;
        }
        try requireCreated(storage, pending, path);
        const generation = try storage.checkpointDurable();
        pending.checkpoint_generation = generation;
        self.pending = pending;
        now = try operation_guard.currentTicks(guard, now);
        try signer.validateService(storage.owner, storage.task_id, now);
        try requireCreated(storage, pending, path);
        return pending;
    }
};

const State = struct {
    display: document_view.View = .{},
    reported_revision: u64 = 0,
    access: ?DocumentAccess = null,
    storage: ?*storage_service.Service = null,
    kernel: ?*component_port.KernelPort = null,
    router: ?*input_router.Router = null,
    compositor: ?*compositor_session.Session = null,
    source_reader: ?*const fn () ?u64 = null,
    source_epoch: u64 = 0,
    focus_epoch: u32 = 0,
    window_id: u64 = 0,
    last_ticks: u64 = 0,
    deadline: u64 = 0,
    accepted_sequence: u64 = 0,
    prepared: ?document_grants.PreparedIdentity = null,
    selected: workspace.Entry = .{},
    workspace_id: u64 = 0,
    page: [PAGE_ENTRIES]workspace.Entry = @splat(.{}),
    first: u16 = 0,
    creation: Creation = .{},
    job_requested: bool = false,
    job_active: bool = false,
    job_done: bool = false,
    awaiting_terminal: bool = false,
    cancelled: bool = false,
    upstream_guard: ?*const operation_guard.Guard = null,
    grants: [MAX_ACTIVE_GRANTS]?Grant = @splat(null),
};

pub const Launch = struct {
    backing: ?*State = null,
    token: u64 = 0,

    pub fn init() Launch {
        return .{};
    }

    pub fn view(self: *Launch) ?*document_view.View {
        return if (self.backing) |s| &s.display else null;
    }

    pub fn ensureView(self: *Launch) !*document_view.View {
        if (self.backing) |s| return &s.display;
        const s: *State = if (builtin.target.os.tag == .freestanding) blk: {
            const allocation = kernel_memory.kmalloc(@sizeOf(State)) orelse return error.NoSpaceLeft;
            break :blk @ptrCast(@alignCast(allocation));
        } else try std.heap.page_allocator.create(State);
        s.* = .{};
        self.backing = s;
        return &s.display;
    }

    fn advance(self: *Launch, s: *State) !void {
        self.token = std.math.add(u64, self.token, 1) catch return error.LaunchTokenExhausted;
        s.display.token = self.token;
        s.display.touch();
        if (s.display.phase == .disabled) return error.LaunchRevisionExhausted;
    }

    // Only the trusted entry can queue a request with a scanout acknowledgement
    // and a fresh hardware report. Merely invoking this native method is not an
    // approval or application grant.
    pub fn request(self: *Launch, manager: anytype, access: DocumentAccess, kind: document_view.Kind, now: u64) !void {
        const s = self.backing orelse return error.DocumentViewUnavailable;
        const decision = s.display.take() orelse return error.FreshDocumentInputRequired;
        if (decision.action != .request or decision.action.request != kind or s.display.phase != .requested) return error.FreshDocumentInputRequired;
        try requireDecision(s, decision);
        if (manager.ownedDocumentJobBusy() or s.job_active or s.prepared != null) return error.DocumentOperationBusy;
        try requireAccess(manager.storageServicePtr(), access, now);
        if (s.access) |previous| if (!sameAccess(previous, access)) return error.OperationAuthorityChanged;
        if (freeGrant(s) == null) return error.DocumentTableFull;
        const router = manager.inputRouterPtr();
        const compositor = manager.compositorSessionPtr();
        const source = router.source orelse return error.DocumentInputUnavailable;
        const reader = source.continuity_epoch orelse return error.DocumentInputUnavailable;
        const epoch = reader() orelse return error.DocumentInputUnavailable;
        if (epoch == std.math.maxInt(u64) or router.source_epoch != epoch or router.last_report_sequence < decision.report_sequence or
            compositor.focus_epoch == std.math.maxInt(u32)) return error.OperationAuthorityChanged;
        const deadline = std.math.add(u64, now, 5 * 60 * units.TIMER_FREQUENCY_HZ) catch return error.OperationExpired;
        s.access = access;
        s.storage = manager.storageServicePtr();
        s.kernel = manager.kernelPort() orelse return error.KernelUnavailable;
        s.router = router;
        s.compositor = compositor;
        s.source_reader = reader;
        s.source_epoch = epoch;
        s.focus_epoch = compositor.focus_epoch;
        s.window_id = compositor.active_window_id;
        s.last_ticks = now;
        s.deadline = @min(access.expires_at_ticks, deadline);
        s.cancelled = false;
        s.creation = .{};
        s.job_requested = false;
        s.job_done = false;
        s.awaiting_terminal = false;
        s.workspace_id = if (try ownedWorkspace(s.storage.?, access.owner)) |record| record.id.raw() else 0;
        const task = try manager.prepareOwnedNotesTask(access.binding, now);
        errdefer manager.cancelPreparedDocumentTask(task.id, now) catch {};
        s.prepared = try document_grants.PreparedIdentity.capture(manager.runtimePtr(), task.id);
        s.display.kind = kind;
        if (kind == .new) {
            s.selected = try newSelection(s.storage.?, s.workspace_id);
            try showReview(self, s);
        } else {
            if (s.workspace_id == 0) return error.WorkspaceNotFound;
            try selectPage(self, s, 0);
        }
    }

    pub fn creationJob(self: *Launch) document_worker.JobInterface {
        return .{ .context = self, .ready = jobReady, .run = jobRun, .cancel = jobCancel };
    }

    fn jobReady(context: *anyopaque, now: u64) bool {
        const self: *Launch = @ptrCast(@alignCast(context));
        const s = self.backing orelse return false;
        return s.job_requested and !s.job_active and !s.cancelled and now >= s.last_ticks and now < s.deadline;
    }

    fn jobCheck(context: *anyopaque) operation_guard.Error!u64 {
        const s: *State = @ptrCast(@alignCast(context));
        if (s.cancelled) return error.Cancelled;
        try requireContinuity(s);
        const now = try operation_guard.currentTicks(s.upstream_guard, s.last_ticks);
        if (now >= s.deadline) return error.OperationExpired;
        s.last_ticks = now;
        return now;
    }

    fn jobRun(context: *anyopaque, signer: object_signer.Signer, guard: *const operation_guard.Guard) void {
        const self: *Launch = @ptrCast(@alignCast(context));
        const s = self.backing orelse return;
        if (!s.job_requested or s.cancelled or s.job_active) return;
        s.job_active = true;
        s.awaiting_terminal = true;
        s.job_requested = false;
        s.upstream_guard = guard;
        defer {
            s.upstream_guard = null;
            s.job_active = false;
        }
        const live = operation_guard.Guard{ .context = s, .check_fn = jobCheck };
        const created = s.creation.run(s.storage.?, s.access.?, s.selected.pathSlice(), signer, &live) catch |err| {
            if (s.cancelled or err == error.Cancelled or err == error.OperationAuthorityChanged or err == error.OperationExpired or err == error.OperationClockRollback) {
                s.cancelled = true;
                s.display.phase = .disabled;
            } else s.display.phase = if (s.creation.pending != null) .retry else .failed;
            s.display.touch();
            return;
        };
        s.workspace_id = created.workspace_id;
        s.selected.object_id = ids.object(created.object_id);
        s.selected.version_id = ids.version(created.version_id);
        s.job_done = true;
    }

    fn jobCancel(context: *anyopaque, now: u64) void {
        const self: *Launch = @ptrCast(@alignCast(context));
        const s = self.backing orelse return;
        s.cancelled = true;
        s.job_requested = false;
        s.display.phase = .disabled;
        s.display.pending = null;
        s.display.touch();
        // Revocation cannot yield or free buffers still borrowed by the worker.
        if (s.kernel) |kernel| if (s.storage) |storage| for (s.grants) |slot| {
            if (slot) |granted| document_grants.revoke(kernel, storage, granted, now);
        };
    }

    pub fn cancel(self: *Launch, manager: anytype, now: u64) void {
        jobCancel(self, now);
        manager.cancelOwnedDocumentJob(now);
        self.reap(manager, null, now);
        if (!manager.ownedDocumentJobBusy()) self.retirePrepared(manager, now);
    }

    fn cancelTransaction(self: *Launch, manager: anytype, now: u64) void {
        const s = self.backing orelse return;
        s.cancelled = true;
        s.job_requested = false;
        s.display.phase = .disabled;
        s.display.pending = null;
        s.display.touch();
        manager.cancelOwnedDocumentJob(now);
        if (!manager.ownedDocumentJobBusy()) self.retirePrepared(manager, now);
    }

    fn retirePrepared(self: *Launch, manager: anytype, now: u64) void {
        const s = self.backing orelse return;
        if (s.prepared) |prepared| manager.cancelPreparedOwnedDocument(prepared, now) catch {};
        s.prepared = null;
        s.creation = .{};
        s.selected = .{};
        s.job_done = false;
        s.job_requested = false;
        s.awaiting_terminal = false;
    }

    fn reap(self: *Launch, manager: anytype, access: ?DocumentAccess, now: u64) void {
        const s = self.backing orelse return;
        const same_session = if (access) |live| if (s.access) |old| sameAccess(live, old) else false else false;
        for (&s.grants) |*slot| {
            const granted = slot.* orelse continue;
            if (same_session and manager.ownedDocumentGrantLive(granted, now)) continue;
            manager.revokeApprovedDocument(granted, now);
            slot.* = null;
        }
    }

    pub fn service(self: *Launch, manager: anytype, access: ?DocumentAccess, now: u64) bool {
        const s = self.backing orelse return false;
        const changed = self.serviceStep(manager, access, now);
        const display_changed = s.reported_revision != s.display.revision;
        s.reported_revision = s.display.revision;
        return changed or display_changed;
    }

    fn serviceStep(self: *Launch, manager: anytype, access: ?DocumentAccess, now: u64) bool {
        const s = self.backing orelse return false;
        self.reap(manager, access, now);
        if (self.token == std.math.maxInt(u64) or s.display.revision == std.math.maxInt(u64)) {
            const changed = s.display.phase != .disabled or s.display.pending != null or s.job_requested;
            if (!s.cancelled and (s.prepared != null or s.job_requested or s.job_active or s.awaiting_terminal)) {
                self.cancelTransaction(manager, now);
            } else {
                s.display.phase = .disabled;
                s.display.pending = null;
                if (changed) s.display.touch();
            }
            if (!manager.ownedDocumentJobBusy() and s.prepared != null) {
                self.retirePrepared(manager, now);
                return true;
            }
            return changed;
        }
        const live = access orelse {
            const changed = s.display.phase != .disabled or s.prepared != null or s.job_requested;
            if (changed) self.cancel(manager, now);
            return changed;
        };
        requireAccess(manager.storageServicePtr(), live, now) catch {
            self.cancel(manager, now);
            return true;
        };
        if (s.access) |previous| if (!sameAccess(previous, live)) {
            self.cancel(manager, now);
            if (manager.ownedDocumentJobBusy()) return true;
            s.access = null;
        };
        if (s.cancelled) {
            if (manager.ownedDocumentJobBusy()) return false;
            self.retirePrepared(manager, now);
            s.cancelled = false;
            s.access = live;
            s.display.phase = .home;
            self.advance(s) catch {
                s.display.phase = .disabled;
                return true;
            };
            return true;
        }
        if (s.access == null or s.display.phase == .disabled) {
            s.access = live;
            s.display.phase = .home;
            self.advance(s) catch {
                s.display.phase = .disabled;
                return true;
            };
            return true;
        }
        if (s.display.phase == .failed and s.prepared != null and !manager.ownedDocumentJobBusy()) {
            self.retirePrepared(manager, now);
            return true;
        }
        if (s.prepared != null) {
            if (now < s.last_ticks or now >= s.deadline) {
                self.cancelTransaction(manager, now);
                return true;
            }
            requireContinuity(s) catch {
                self.cancelTransaction(manager, now);
                return true;
            };
            s.last_ticks = now;
        }
        if (s.awaiting_terminal and !manager.ownedDocumentJobBusy()) s.awaiting_terminal = false;
        if (s.job_done and !s.awaiting_terminal) {
            self.activate(manager, live, now) catch self.fail(manager, now);
            return true;
        }
        const decision = s.display.pending orelse return false;
        if (decision.action == .request) {
            self.request(manager, live, decision.action.request, now) catch self.fail(manager, now);
            return true;
        }
        _ = s.display.take();
        requireDecision(s, decision) catch {
            self.cancel(manager, now);
            return true;
        };
        switch (decision.action) {
            .deny => self.cancelTransaction(manager, now),
            .page => |forward| {
                if (s.display.phase != .browsing or (if (forward) !s.display.next else !s.display.previous)) {
                    self.fail(manager, now);
                } else {
                    const first = if (forward) std.math.add(u16, s.first, PAGE_ENTRIES) catch {
                        self.fail(manager, now);
                        return true;
                    } else s.first -| @as(u16, PAGE_ENTRIES);
                    selectPage(self, s, first) catch self.fail(manager, now);
                }
            },
            .select => |index| {
                if (s.display.phase != .browsing or index >= s.display.count) {
                    self.fail(manager, now);
                } else {
                    s.selected = s.page[index];
                    requireSelection(s) catch {
                        self.fail(manager, now);
                        return true;
                    };
                    showReview(self, s) catch self.fail(manager, now);
                }
            },
            .approve => {
                if (s.display.phase != .review or !s.display.allow_selected) {
                    self.cancelTransaction(manager, now);
                } else if (s.display.kind == .new) {
                    s.display.phase = .working;
                    s.display.touch();
                    s.job_requested = true;
                } else self.activate(manager, live, now) catch self.fail(manager, now);
            },
            .retry => {
                if (s.display.phase != .retry or s.creation.pending == null or manager.ownedDocumentJobBusy()) {
                    self.fail(manager, now);
                } else {
                    s.display.phase = .working;
                    s.display.touch();
                    s.job_requested = true;
                }
            },
            .request => unreachable,
        }
        return true;
    }

    fn activate(self: *Launch, manager: anytype, access: DocumentAccess, now: u64) !void {
        const s = self.backing.?;
        _ = std.math.add(u64, self.token, 1) catch return error.LaunchTokenExhausted;
        if (s.display.revision == std.math.maxInt(u64)) return error.LaunchRevisionExhausted;
        try requireContinuity(s);
        try requireSelection(s);
        const prepared = s.prepared orelse return error.TaskNotPrepared;
        const current = try document_grants.PreparedIdentity.capture(manager.runtimePtr(), prepared.task_id);
        if (!std.meta.eql(prepared, current)) return error.TaskNotPrepared;
        const index = freeGrant(s) orelse return error.DocumentTableFull;
        const granted = try manager.grantApprovedDocument(prepared.task_id, s.workspace_id, s.selected.object_id.raw(), s.selected.pathSlice(), access.expires_at_ticks, now);
        errdefer manager.revokeApprovedDocument(granted, now);
        if (!std.meta.eql(granted.prepared, prepared)) return error.TaskNotPrepared;
        _ = try manager.activateApprovedDocument(granted, access.signer, now);
        s.display.phase = .home;
        try self.advance(s);
        s.grants[index] = granted;
        s.prepared = null;
        s.creation = .{};
        s.job_done = false;
        s.display.phase = .home;
        s.display.path = .{};
        s.display.allow_selected = false;
    }

    fn fail(self: *Launch, manager: anytype, now: u64) void {
        const s = self.backing orelse return;
        if (manager.ownedDocumentJobBusy()) {
            self.cancelTransaction(manager, now);
            return;
        }
        self.retirePrepared(manager, now);
        s.display.phase = .failed;
        s.display.pending = null;
        s.display.touch();
    }

    pub fn ready(self: *const Launch, now: u64) bool {
        const s = self.backing orelse return false;
        if (s.reported_revision != s.display.revision) return true;
        if (s.cancelled and s.prepared != null and !s.job_active) return true;
        if (s.display.pending != null) return true;
        if (s.job_done) return true;
        if (s.prepared != null and now >= s.deadline and !s.cancelled) return true;
        for (s.grants) |slot| if (slot) |granted| if (now > granted.share.expires_at_ticks) return true;
        return false;
    }

    pub fn nextWake(self: *const Launch) ?u64 {
        const s = self.backing orelse return null;
        var wake: ?u64 = if (s.prepared != null and !s.cancelled) s.deadline else null;
        for (s.grants) |slot| if (slot) |granted| {
            const expiry = std.math.add(u64, granted.share.expires_at_ticks, 1) catch granted.share.expires_at_ticks;
            wake = if (wake) |current| @min(current, expiry) else expiry;
        };
        return wake;
    }

    pub fn deinit(self: *Launch, manager: anytype, now: u64) error{DocumentOperationBusy}!void {
        if (manager.ownedDocumentJobBusy() or (if (self.backing) |s| s.job_active else false)) return error.DocumentOperationBusy;
        self.cancel(manager, now);
        const s = self.backing orelse return;
        @memset(std.mem.asBytes(s), 0);
        if (builtin.target.os.tag == .freestanding) kernel_memory.kfree(@ptrCast(s)) else std.heap.page_allocator.destroy(s);
        self.backing = null;
    }
};

pub const layout = .{
    .handle_bytes = @sizeOf(Launch),
    .state_bytes = @sizeOf(State),
    .view_bytes = @sizeOf(document_view.View),
    .grant_bytes = @sizeOf(Grant),
    .ledger_bytes = @sizeOf([MAX_ACTIVE_GRANTS]?Grant),
};

comptime {
    if (@sizeOf(Launch) > 16) @compileError("owned document launch exceeds its lazy native handle");
    if (@sizeOf(State) > 4096) @compileError("owned document launch exceeds one bounded state page");
}

fn freeGrant(s: *const State) ?usize {
    for (s.grants, 0..) |slot, index| if (slot == null) return index;
    return null;
}

fn requireDecision(s: *State, decision: document_view.Decision) !void {
    const revision = std.math.add(u64, decision.revision, 1) catch return error.FreshDocumentInputRequired;
    if (decision.token == 0 or decision.token != s.display.token or revision != s.display.revision or
        decision.report_sequence == 0 or decision.report_sequence <= s.accepted_sequence or
        decision.report_sequence != s.display.last_report_sequence) return error.FreshDocumentInputRequired;
    s.accepted_sequence = decision.report_sequence;
}

fn sameAccess(a: DocumentAccess, b: DocumentAccess) bool {
    return a.owner.eql(b.owner) and std.meta.eql(a.binding, b.binding) and a.signer.key.authority == b.signer.key.authority and
        a.signer.key.handle_id == b.signer.key.handle_id and std.mem.eql(u8, &a.signer.key.sealed_digest, &b.signer.key.sealed_digest);
}

fn requireAccess(storage: *const storage_service.Service, access: DocumentAccess, now: u64) !void {
    if (access.owner.kind != .user or access.owner.serial == 0 or !access.binding.valid() or
        access.expires_at_ticks <= now or access.expires_at_ticks == std.math.maxInt(u64) or
        !access.authorization.owner.eql(access.owner) or access.authorization.subjects.user_id != access.owner.serial or
        access.authorization.expires_at_ticks != access.expires_at_ticks) return error.OperationAuthorityChanged;
    try access.signer.validateService(storage.owner, storage.task_id, now);
}

fn requireContinuity(s: *const State) operation_guard.Error!void {
    const router = s.router orelse return error.OperationAuthorityChanged;
    const compositor = s.compositor orelse return error.OperationAuthorityChanged;
    const source = router.source orelse return error.OperationAuthorityChanged;
    if (source.continuity_epoch != s.source_reader or router.source_epoch != s.source_epoch or
        s.source_reader.?() != s.source_epoch or compositor.focus_epoch != s.focus_epoch or
        compositor.active_window_id != s.window_id) return error.OperationAuthorityChanged;
}

fn newSelection(storage: *storage_service.Service, workspace_id: u64) !workspace.Entry {
    var path: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
    for (1..workspace.MAX_WORKSPACE_ENTRIES + 2) |number| {
        const name = try std.fmt.bufPrint(&path, "note-{d}.md", .{number});
        if (workspace_id != 0) requireAbsent(storage, workspace_id, name) catch |err| switch (err) {
            error.DocumentChanged => continue,
            else => return err,
        };
        return workspace.Entry.init(name, ids.ObjectId.zero, ids.VersionId.zero, .document);
    }
    return error.EntryTableFull;
}

fn showReview(self: *Launch, s: *State) !void {
    s.display.phase = .review;
    s.display.path = try document_view.Label.init(s.selected.pathSlice());
    s.display.allow_selected = false;
    try self.advance(s);
}

fn selectPage(self: *Launch, s: *State, first: u16) !void {
    const storage = s.storage.?;
    const record = (try ownedWorkspace(storage, s.access.?.owner)) orelse return error.WorkspaceNotFound;
    if (record.id.raw() != s.workspace_id) return error.DocumentChanged;
    s.first = first;
    s.display.count = 0;
    s.display.selected = 0;
    s.display.previous = first != 0;
    s.display.next = false;
    s.display.paths = @splat(.{});
    s.page = @splat(.{});
    var visible: usize = 0;
    for (try storage.entries(s.workspace_id)) |entry| {
        if (entry.object_type != .document) continue;
        const label = document_view.Label.init(entry.pathSlice()) catch continue;
        visible += 1;
        if (visible <= first) continue;
        if (s.display.count == PAGE_ENTRIES) {
            s.display.next = true;
            break;
        }
        s.page[s.display.count] = entry;
        s.display.paths[s.display.count] = label;
        s.display.count += 1;
    }
    s.display.phase = .browsing;
    try self.advance(s);
}

fn requireSelection(s: *const State) !void {
    const storage = s.storage.?;
    const record = (try ownedWorkspace(storage, s.access.?.owner)) orelse return error.DocumentChanged;
    if (record.id.raw() != s.workspace_id) return error.DocumentChanged;
    const current = try storage.resolve(s.workspace_id, s.selected.pathSlice());
    if (current.object_type != .document or !current.object_id.eql(s.selected.object_id) or !current.version_id.eql(s.selected.version_id)) return error.DocumentChanged;
}

fn ownedWorkspace(storage: *storage_service.Service, owner: principal.PrincipalId) !?*workspace.WorkspaceRecord {
    var found: ?*workspace.WorkspaceRecord = null;
    for (&storage.workspaces.workspaces.slots) |*slot| {
        if (!slot.in_use or !slot.workspace.owner.eql(owner) or !std.mem.eql(u8, slot.workspace.labelSlice(), WORKSPACE_LABEL)) continue;
        if (found != null) return error.AmbiguousNotesWorkspace;
        found = &slot.workspace;
    }
    return found;
}

fn requireAbsent(storage: *const storage_service.Service, workspace_id: u64, path: []const u8) !void {
    _ = storage.resolve(workspace_id, path) catch |err| switch (err) {
        error.EntryNotFound => return,
        else => return err,
    };
    return error.DocumentChanged;
}

fn requireCreated(storage: *const storage_service.Service, pending: Created, path: []const u8) !void {
    const entry = try storage.resolve(pending.workspace_id, path);
    if (entry.object_id.raw() != pending.object_id or entry.version_id.raw() != pending.version_id or entry.object_type != .document) return error.DocumentChanged;
    const head = storage.latestVersion(ids.object(pending.object_id)) orelse return error.DocumentChanged;
    if (head.id.raw() != pending.version_id) return error.DocumentChanged;
}

// Only the read-only owner envelope and hardware report counter are modeled.
// Preparation, policy grants, channels, task cleanup and storage are actual
// booted manager paths; this fixture does not authenticate or enroll a user.
const LaunchTest = if (builtin.is_test) struct {
    const manager_mod = @import("session_manager.zig");
    const bridge = @import("owned_document_bridge.zig");
    const signing_fixture_mod = @import("../../tests/fixtures/document_signer.zig");
    const tasks = @import("../task/task_runtime.zig");
    const catalog = @import("../task/userspace_loader.zig");
    const caps = @import("../kernel_api/capability.zig");
    const xhci = @import("../../kernel/drivers/xhci.zig");
    const OwnerEnvelope = struct { context: *anyopaque, document_access: *const fn (*anyopaque, u64) ?DocumentAccess };
    pub const DocumentTask = manager_mod.SessionManager.DocumentTask;
    var active: ?*@This() = null;
    manager: *manager_mod.SessionManager,
    launch: Launch = .{},
    signing: signing_fixture_mod.Fixture = .{},
    access: DocumentAccess = undefined,
    identity_owner: ?OwnerEnvelope = null,
    session_active: bool = true,
    epoch: u64 = 1,
    now: u64 = 10,
    workspace_id: u64 = 0,
    activation_error: ?anyerror = null,
    worker: ?*@import("../task/cooperative_worker.zig").Worker = null,
    worker_is_creation_job: bool = true,

    fn create() !*@This() {
        manager_mod.testing.resetState();
        manager_mod.boot();
        const self = try std.testing.allocator.create(@This());
        self.* = .{ .manager = manager_mod.system() };
        active = self;
        errdefer self.destroy();
        const storage = self.storageServicePtr();
        const signer = try self.signing.init(.{ .kind = .user, .serial = 1 }, storage.owner, storage.task_id, @import("../storage/document_save_test.zig").signer);
        self.access = .{ .owner = .{ .kind = .user, .serial = 1 }, .binding = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) }, .expires_at_ticks = 1000, .signer = signer, .authorization = .{ .policies = &self.signing.policies, .subjects = self.signing.authority.subjects, .owner = .{ .kind = .user, .serial = 1 }, .expires_at_ticks = 1000 } };
        self.identity_owner = .{ .context = self, .document_access = documentAccess };
        self.inputRouterPtr().bindHardwareSource(.{ .poll_report = noReport, .input_proof = noProof, .continuity_epoch = sourceEpoch });
        _ = try self.launch.ensureView();
        try std.testing.expect(self.launch.service(self, self.access, self.now));
        storage.beginCheckpointBatch();
        defer storage.endCheckpointBatch();
        self.workspace_id = (try storage.createWorkspace(.{ .owner = self.access.owner, .label = WORKSPACE_LABEL })).id.raw();
        try storage.beginTransaction(self.workspace_id);
        for ([_][]const u8{ "note-1.md", "second.md" }) |path| {
            const result = try storage.putVersion(.{ .object_type = .document, .payload = "note", .metadata = try signer.signMetadata(path, "note", self.now) });
            try storage.stagePut(self.workspace_id, path, result.object_id, result.version_id, .document);
        }
        _ = try storage.commit(self.workspace_id, self.now);
        return self;
    }

    fn destroy(self: *@This()) void {
        self.launch.deinit(self, self.now) catch @panic("terminal launch fixture teardown must succeed");
        self.signing.service.unload();
        manager_mod.testing.resetState();
        active = null;
        std.testing.allocator.destroy(self);
    }
    fn documentAccess(context: *anyopaque, now: u64) ?DocumentAccess {
        const self: *@This() = @ptrCast(@alignCast(context));
        return if (self.session_active and now < self.access.expires_at_ticks) self.access else null;
    }
    fn noReport() ?xhci.HardwareBootKeyboardReport {
        return null;
    }
    fn noProof() ?xhci.InputProof {
        return null;
    }
    fn sourceEpoch() ?u64 {
        return active.?.epoch;
    }
    pub fn storageServicePtr(self: *@This()) *storage_service.Service {
        return self.manager.storageServicePtr();
    }
    pub fn kernelPort(self: *@This()) ?*component_port.KernelPort {
        return self.manager.kernelPort();
    }
    pub fn runtimePtr(self: *@This()) *tasks.Runtime {
        return self.manager.runtimePtr();
    }
    pub fn userspaceCatalogPtr(self: *@This()) *catalog.Catalog {
        return self.manager.userspaceCatalogPtr();
    }
    pub fn capabilityTablePtr(self: *@This()) *caps.CapabilityTable {
        return self.manager.capabilityTablePtr();
    }
    pub fn inputRouterPtr(self: *@This()) *input_router.Router {
        return self.manager.inputRouterPtr();
    }
    pub fn compositorSessionPtr(self: *@This()) *compositor_session.Session {
        return self.manager.compositorSessionPtr();
    }
    pub fn prepareOwnedNotesTask(self: *@This(), binding: unlock.Binding, now: u64) !*tasks.TaskRecord {
        return bridge.prepare(self, binding, now);
    }
    pub fn grantApprovedDocument(self: *@This(), task_id: u64, workspace_id: u64, object_id: u64, path: []const u8, expiry: u64, now: u64) !Grant {
        return bridge.grant(self, task_id, workspace_id, object_id, path, expiry, now);
    }
    pub fn activateApprovedDocument(self: *@This(), granted: Grant, signer: object_signer.Signer, now: u64) !DocumentTask {
        return self.manager.activateApprovedDocument(granted, signer, now) catch |err| {
            self.activation_error = err;
            return err;
        };
    }
    pub fn revokeApprovedDocument(self: *@This(), granted: Grant, now: u64) void {
        self.manager.revokeApprovedDocument(granted, now);
    }
    pub fn cancelPreparedDocumentTask(self: *@This(), task_id: u64, now: u64) !void {
        try self.manager.cancelPreparedDocumentTask(task_id, now);
    }
    pub fn cancelPreparedOwnedDocument(self: *@This(), prepared: document_grants.PreparedIdentity, now: u64) !void {
        try self.manager.cancelPreparedOwnedDocument(prepared, now);
    }
    pub fn ownedDocumentJobBusy(self: *@This()) bool {
        if (self.worker) |worker| if (worker.state == .running or worker.state == .suspended) return true;
        return self.manager.ownedDocumentJobBusy();
    }
    pub fn cancelOwnedDocumentJob(self: *@This(), now: u64) void {
        // Mirror Coordinator.cancelJob: an editor save owns the Session too,
        // but cancellation of a new selection must not cancel that save.
        if (self.worker_is_creation_job) if (self.worker) |worker| worker.cancel();
        self.manager.cancelOwnedDocumentJob(now);
    }
    pub fn ownedDocumentGrantLive(self: *@This(), granted: Grant, now: u64) bool {
        return self.manager.ownedDocumentGrantLive(granted, now);
    }
    fn report(self: *@This(), sequence: u64) void {
        self.inputRouterPtr().last_report_sequence = sequence;
    }
    fn beginOpen(self: *@This()) !void {
        const screen = self.launch.view().?;
        screen.presented(80, 30, true);
        self.report(1);
        try std.testing.expect(screen.shortcut(.open, 1));
        try std.testing.expect(self.launch.service(self, self.access, self.now));
        try std.testing.expectEqual(document_view.Phase.browsing, screen.phase);
    }
    fn reviewFirst(self: *@This()) !void {
        const screen = self.launch.view().?;
        screen.presented(80, 30, true);
        self.report(2);
        try std.testing.expect(screen.handle(.{ .kind = .activate }, 2));
        try std.testing.expect(self.launch.service(self, self.access, self.now));
        try std.testing.expectEqual(document_view.Phase.review, screen.phase);
        screen.presented(80, 30, true);
        self.report(3);
        try std.testing.expect(screen.handle(.{ .kind = .focus_next }, 3));
        try std.testing.expect(screen.allow_selected);
    }
    fn openReviewDocument(self: *@This()) !struct { grant: Grant, binding: @import("../task/userspace_bootstrap_mailbox.zig").DocumentBinding } {
        const s = self.launch.backing.?;
        const prepared = s.prepared.?;
        const granted = try self.grantApprovedDocument(prepared.task_id, s.workspace_id, s.selected.object_id.raw(), s.selected.pathSlice(), self.access.expires_at_ticks, self.now);
        const kernel = self.kernelPort().?;
        const task = self.runtimePtr().find(prepared.task_id).?;
        const storage = self.storageServicePtr();
        const service = self.runtimePtr().find(storage.task_id).?;
        const bootstrap = @import("../task/userspace_executor.zig").resolveMailboxAuthorities(service, self.capabilityTablePtr(), self.now).bootstrap_capability_id;
        const temporary = try self.capabilityTablePtr().mintBootRoot(.{
            .holder = task.owner,
            .issuer = kernel.kernel.policy_authority,
            .target = .{ .kind = .service, .id = storage.service_id },
            .rights = .{ .service = .{ .endpoint_create = true } },
            .scope = .{ .task_id = task.id, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = self.now, .expires_at_ticks = self.access.expires_at_ticks },
        });
        defer self.capabilityTablePtr().rollbackSingleGrant(temporary.id);
        try tasks.grantCapabilityToTask(task, temporary.id);
        defer _ = tasks.revokeCapabilityFromTask(task, temporary.id);
        const binding = try self.manager.documents.open(kernel, storage, .{
            .authority = .{ .principal = task.owner, .task_id = task.id, .capability_id = granted.capability_id, .now_ticks = self.now },
            .client_bootstrap_capability_id = temporary.id,
            .server_bootstrap_capability_id = bootstrap,
            .workspace_id = granted.workspace_id,
            .path = granted.share.scopePathSlice(),
            .signer = self.access.signer,
        }, self.now);
        try std.testing.expect(self.ownedDocumentGrantLive(granted, self.now));
        s.grants[0] = granted;
        s.prepared = null;
        s.display.phase = .home;
        try self.launch.advance(s);
        _ = self.launch.service(self, self.access, self.now);
        return .{ .grant = granted, .binding = binding };
    }
} else struct {};

test "owned Notes browsing and exact approval leave prepared measured task without ambient grants" {
    const f = try LaunchTest.create();
    defer f.destroy();
    const runtime = f.runtimePtr();
    const active_before = runtime.countTasksInState(.active);
    const grants_before = f.capabilityTablePtr().activeCount();
    const screen = f.launch.view().?;
    f.report(1);
    try std.testing.expect(!screen.shortcut(.open, 1));
    try std.testing.expect(!f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(active_before, runtime.countTasksInState(.active));
    try f.beginOpen();
    const prepared = f.launch.backing.?.prepared.?;
    const task = runtime.findConst(prepared.task_id).?;
    try std.testing.expect(task.hasLoadedExecutable());
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(f.manager.userspaceSchedulerPtr().taskDispatchStats(task.id) == null);
    try std.testing.expectEqual(grants_before, f.capabilityTablePtr().activeCount());
    try std.testing.expectEqual(@as(u8, 2), screen.count);
    try std.testing.expectEqualStrings("note-1.md", screen.paths[0].slice());
    try f.reviewFirst();
    f.report(4);
    try std.testing.expect(!screen.handle(.{ .kind = .activate }, 4));
    try std.testing.expectEqual(grants_before, f.capabilityTablePtr().activeCount());
    screen.presented(80, 30, true);
    try std.testing.expect(screen.handle(.{ .kind = .activate }, 4));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    // Hosted execution refuses its real userspace mailbox binding. The actual
    // channel/activation failure must unwind all approval and bootstrap grants.
    try std.testing.expectEqual(document_view.Phase.failed, screen.phase);
    try std.testing.expectEqual(error.DocumentLaunchUnavailable, f.activation_error.?);
    try std.testing.expectEqual(@as(usize, grants_before), f.capabilityTablePtr().activeCount());
    try std.testing.expectEqual(active_before, runtime.countTasksInState(.active));
    try std.testing.expect(f.storageServicePtr().findShareGrant(f.workspace_id, task.owner) == null);
    try std.testing.expect(f.manager.userspaceSchedulerPtr().taskDispatchStats(prepared.task_id) == null);
}

test "owned Notes approved creation retains its actual worker backing through input cancellation" {
    const f = try LaunchTest.create();
    defer f.destroy();
    const Paused = struct {
        const cooperative = @import("../task/cooperative_worker.zig");
        const sealing = @import("../platform/secret_sealing.zig");
        fixture: *LaunchTest,
        guard: operation_guard.Guard = undefined,
        pause: bool = true,
        fn check(context: *anyopaque) operation_guard.Error!u64 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (cooperative.current().?.cancel_requested) return error.Cancelled;
            return self.fixture.now;
        }
        fn open(context: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.pause) {
                self.pause = false;
                cooperative.current().?.yield();
            }
            return @import("../../tests/fixtures/secret_provider.zig").provider().open(binding, blob, out);
        }
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const job = self.fixture.launch.creationJob();
            job.run(job.context, self.fixture.access.signer, &self.guard);
        }
    };
    const screen = f.launch.view().?;
    const versions_before = f.storageServicePtr().versionCount();
    const grants_before = f.capabilityTablePtr().activeCount();
    const active_before = f.runtimePtr().countTasksInState(.active);
    screen.presented(80, 30, true);
    f.report(1);
    try std.testing.expect(screen.shortcut(.new, 1));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(document_view.Phase.review, screen.phase);
    try std.testing.expectEqualStrings("note-2.md", screen.path.slice());
    screen.presented(80, 30, true);
    f.report(2);
    try std.testing.expect(screen.handle(.{ .kind = .focus_next }, 2));
    screen.presented(80, 30, true);
    f.report(3);
    try std.testing.expect(screen.handle(.{ .kind = .activate }, 3));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(document_view.Phase.working, screen.phase);
    const job = f.launch.creationJob();
    try std.testing.expect(job.ready(job.context, f.now));
    var paused = Paused{ .fixture = f };
    paused.guard = .{ .context = &paused, .check_fn = Paused.check };
    f.signing.service.attachHardwareProvider(.{ .context = &paused, .operations = &.{ .seal = @import("../../tests/fixtures/secret_provider.zig").provider().operations.?.seal, .open = Paused.open } });
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = Paused.cooperative.Worker{ .stack = &stack };
    f.worker = &worker;
    try worker.start(&paused, Paused.run);
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.suspended, worker.state);
    const backing = f.launch.backing.?;
    const path = backing.selected;
    try std.testing.expectError(error.DocumentOperationBusy, f.launch.deinit(f, f.now));
    try std.testing.expect(f.launch.backing.? == backing and !backing.cancelled);
    f.epoch += 1;
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expect(worker.cancel_requested and backing.cancelled);
    try std.testing.expectEqualSlices(u8, path.pathSlice(), backing.selected.pathSlice());
    try std.testing.expect(backing.prepared != null);
    try std.testing.expect(!job.ready(job.context, f.now));
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.complete, worker.state);
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(document_view.Phase.home, screen.phase);
    try std.testing.expectEqual(versions_before, f.storageServicePtr().versionCount());
    try std.testing.expectEqual(grants_before, f.capabilityTablePtr().activeCount());
    try std.testing.expectEqual(active_before, f.runtimePtr().countTasksInState(.active));
    f.worker = null;
}

test "owned Notes review rejects epoch focus expiry and selected version changes before grants" {
    const Failure = enum { session, source, focus_round_trip, expiry, version };
    for (std.enums.values(Failure)) |failure| {
        const f = try LaunchTest.create();
        defer f.destroy();
        const active_before = f.runtimePtr().countTasksInState(.active);
        const grants_before = f.capabilityTablePtr().activeCount();
        try f.beginOpen();
        try f.reviewFirst();
        const prepared = f.launch.backing.?.prepared.?;
        const screen = f.launch.view().?;
        screen.presented(80, 30, true);
        f.report(4);
        try std.testing.expect(screen.handle(.{ .kind = .activate }, 4));
        switch (failure) {
            .session => f.access.binding.session_nonce[0] ^= 1,
            .source => f.epoch += 1,
            .focus_round_trip => f.compositorSessionPtr().focus_epoch += 2,
            .expiry => f.now = f.access.expires_at_ticks,
            .version => {
                const selected = f.launch.backing.?.selected;
                const result = try f.storageServicePtr().putVersion(.{ .preferred_object_id = selected.object_id, .parent_version_id = selected.version_id, .object_type = .document, .payload = "changed", .metadata = try f.access.signer.signMetadata(selected.pathSlice(), "changed", f.now) });
                try f.storageServicePtr().beginTransaction(f.workspace_id);
                try f.storageServicePtr().stagePut(f.workspace_id, selected.pathSlice(), result.object_id, result.version_id, .document);
                _ = try f.storageServicePtr().commit(f.workspace_id, f.now);
            },
        }
        _ = f.launch.service(f, if (failure == .expiry) null else f.access, f.now);
        try std.testing.expectEqual(grants_before, f.capabilityTablePtr().activeCount());
        try std.testing.expectEqual(active_before, f.runtimePtr().countTasksInState(.active));
        try std.testing.expect(f.runtimePtr().findConst(prepared.task_id).?.state == .terminated);
        try std.testing.expect(f.launch.backing.?.prepared == null);
    }
}

test "owned Notes terminal signing failure retires prepared task and publishes its view once" {
    const f = try LaunchTest.create();
    defer f.destroy();
    const Paused = struct {
        const cooperative = @import("../task/cooperative_worker.zig");
        const sealing = @import("../platform/secret_sealing.zig");
        fixture: *LaunchTest,
        guard: operation_guard.Guard = undefined,
        fn check(context: *anyopaque) operation_guard.Error!u64 {
            const self: *@This() = @ptrCast(@alignCast(context));
            return self.fixture.now;
        }
        fn open(_: ?*anyopaque, _: *const sealing.Binding, _: []const u8, _: *sealing.Value) sealing.Error!usize {
            cooperative.current().?.yield();
            return error.HardwareOperationFailed;
        }
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const job = self.fixture.launch.creationJob();
            job.run(job.context, self.fixture.access.signer, &self.guard);
        }
    };
    const active_before = f.runtimePtr().countTasksInState(.active);
    const versions_before = f.storageServicePtr().versionCount();
    const screen = f.launch.view().?;
    screen.presented(80, 30, true);
    f.report(1);
    try std.testing.expect(screen.shortcut(.new, 1));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    screen.presented(80, 30, true);
    f.report(2);
    try std.testing.expect(screen.handle(.{ .kind = .focus_next }, 2));
    screen.presented(80, 30, true);
    f.report(3);
    try std.testing.expect(screen.handle(.{ .kind = .activate }, 3));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    const prepared = f.launch.backing.?.prepared.?;
    var paused = Paused{ .fixture = f };
    paused.guard = .{ .context = &paused, .check_fn = Paused.check };
    f.signing.service.attachHardwareProvider(.{ .context = &paused, .operations = &.{ .seal = @import("../../tests/fixtures/secret_provider.zig").provider().operations.?.seal, .open = Paused.open } });
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = Paused.cooperative.Worker{ .stack = &stack };
    f.worker = &worker;
    try worker.start(&paused, Paused.run);
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.suspended, worker.state);
    try std.testing.expect(!f.launch.service(f, f.access, f.now));
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(document_view.Phase.failed, screen.phase);
    try std.testing.expect(f.launch.ready(f.now));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(active_before, f.runtimePtr().countTasksInState(.active));
    try std.testing.expect(f.runtimePtr().findConst(prepared.task_id).?.state == .terminated);
    try std.testing.expect(f.launch.backing.?.prepared == null);
    try std.testing.expectEqual(versions_before, f.storageServicePtr().versionCount());
    try std.testing.expect(!f.launch.ready(f.now));
    try std.testing.expect(!f.launch.service(f, f.access, f.now));
    f.worker = null;
}

test "owned Notes exhausted token and view revision retire selection once and preserve earlier grants" {
    for ([_]bool{ false, true }) |revision_exhausted| {
        const f = try LaunchTest.create();
        defer f.destroy();
        try f.beginOpen();
        try f.reviewFirst();
        const s = f.launch.backing.?;
        const granted = (try f.openReviewDocument()).grant;
        const screen = f.launch.view().?;
        screen.presented(80, 30, true);
        f.report(4);
        try std.testing.expect(screen.shortcut(.new, 4));
        try std.testing.expect(f.launch.service(f, f.access, f.now));
        const selected = s.prepared.?;
        if (revision_exhausted) screen.revision = std.math.maxInt(u64) else f.launch.token = std.math.maxInt(u64);
        try std.testing.expect(f.launch.service(f, f.access, f.now));
        try std.testing.expectEqual(document_view.Phase.disabled, screen.phase);
        try std.testing.expect(s.prepared == null);
        try std.testing.expect(f.runtimePtr().findConst(selected.task_id).?.state == .terminated);
        try std.testing.expect(f.ownedDocumentGrantLive(granted, f.now));
        try std.testing.expect(s.grants[0] != null);
        try std.testing.expect(!f.launch.ready(f.now));
        try std.testing.expect(!f.launch.service(f, f.access, f.now));
        try std.testing.expect(!f.launch.service(f, f.access, f.now));
        try std.testing.expect(f.ownedDocumentGrantLive(granted, f.now));
    }
}

test "owned Notes new selection during an actual suspended editor save preserves the prior channel and grant" {
    const f = try LaunchTest.create();
    defer f.destroy();
    try f.beginOpen();
    try f.reviewFirst();
    const opened = try f.openReviewDocument();
    const granted = opened.grant;
    const protocol = @import("../../userspace/document_protocol.zig");
    const Paused = struct {
        const cooperative = @import("../task/cooperative_worker.zig");
        const sealing = @import("../platform/secret_sealing.zig");
        fixture: *LaunchTest,
        pause: bool = true,
        fn open(context: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.pause) {
                self.pause = false;
                cooperative.current().?.yield();
            }
            return @import("../../tests/fixtures/secret_provider.zig").provider().open(binding, blob, out);
        }
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!self.fixture.manager.documents.serviceForSigner(self.fixture.access.signer, self.fixture.now))
                @panic("the queued editor commit must be serviced");
        }
    };
    const kernel = f.kernelPort().?;
    var bytes: [protocol.MAX_FRAME_BYTES]u8 = undefined;
    const begin = try protocol.encode(&bytes, .{ .request_id = 1, .body = .{ .begin = .{ .expected_version_id = opened.binding.version_id, .length = 0, .digest = protocol.digest("") } } });
    try kernel.endpointSend(.{ .header = component_port.makeHeader(.endpoint_send, granted.prepared.task_id), .endpoint_capability_id = opened.binding.endpoint_capability_id, .correlation_id = 1, .payload = begin }, f.now);
    try std.testing.expect(f.manager.documents.serviceForSigner(f.access.signer, f.now));
    const commit = try protocol.encode(&bytes, .{ .request_id = 1, .body = .commit });
    try kernel.endpointSend(.{ .header = component_port.makeHeader(.endpoint_send, granted.prepared.task_id), .endpoint_capability_id = opened.binding.endpoint_capability_id, .correlation_id = 1, .payload = commit }, f.now);
    var paused = Paused{ .fixture = f };
    f.signing.service.attachHardwareProvider(.{ .context = &paused, .operations = &.{ .seal = @import("../../tests/fixtures/secret_provider.zig").provider().operations.?.seal, .open = Paused.open } });
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = Paused.cooperative.Worker{ .stack = &stack };
    f.worker = &worker;
    f.worker_is_creation_job = false;
    defer {
        while (worker.state == .running or worker.state == .suspended) worker.step() catch @panic("editor fixture drains before teardown");
        f.worker = null;
    }
    try worker.start(&paused, Paused.run);
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.suspended, worker.state);
    try std.testing.expectEqual(opened.binding.version_id, (try f.storageServicePtr().resolve(granted.workspace_id, granted.share.scopePathSlice())).version_id.raw());
    const active_before = f.runtimePtr().countTasksInState(.active);
    const screen = f.launch.view().?;
    screen.presented(80, 30, true);
    f.report(4);
    try std.testing.expect(screen.shortcut(.new, 4));
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expect(!worker.cancel_requested);
    try std.testing.expect(f.ownedDocumentGrantLive(granted, f.now));
    try std.testing.expect(f.launch.backing.?.prepared == null);
    try std.testing.expectEqual(active_before, f.runtimePtr().countTasksInState(.active));
    try worker.step();
    try std.testing.expectEqual(Paused.cooperative.Worker.State.complete, worker.state);
    try std.testing.expect(f.ownedDocumentGrantLive(granted, f.now));
    const current = try f.storageServicePtr().resolve(granted.workspace_id, granted.share.scopePathSlice());
    try std.testing.expect(current.version_id.raw() != opened.binding.version_id);
    try std.testing.expectEqualStrings("", try f.storageServicePtr().versionPayload(f.storageServicePtr().version(current.version_id).?));
    var attached: @import("../core/abi.zig").CapabilityDescriptor = undefined;
    const received = (try kernel.endpointRecv(.{ .header = component_port.makeHeader(.endpoint_recv, granted.prepared.task_id), .endpoint_capability_id = opened.binding.endpoint_capability_id, .receiver_task_id = granted.prepared.task_id, .payload_out = &bytes, .attached_capability_out = &attached }, f.now)).?;
    try std.testing.expectEqual(protocol.Status.saved, (try protocol.decode(bytes[0..received.message.payload_len])).body.receipt.status);
    try std.testing.expect(f.launch.service(f, f.access, f.now));
    try std.testing.expectEqual(document_view.Phase.home, screen.phase);
    try std.testing.expect(!f.launch.service(f, f.access, f.now));
}

const CreationTest = if (builtin.is_test) struct {
    const Device = @import("../storage/document_save_test.zig").Fixture;
    const cooperative = @import("../task/cooperative_worker.zig");
    const sealing = @import("../platform/secret_sealing.zig");
    const provider_fixture = @import("../../tests/fixtures/secret_provider.zig");
    device: *Device,
    signer: object_signer.Signer,
    access: DocumentAccess,
    creation: Creation = .{},
    guard: operation_guard.Guard = undefined,
    now: u64 = 10,
    cancelled: bool = false,
    pause_sign: bool = false,
    pause_flush: bool = false,
    result: ?Created = null,
    failure: ?anyerror = null,

    fn check(context: *anyopaque) operation_guard.Error!u64 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.cancelled) return error.Cancelled;
        if (self.now >= self.access.expires_at_ticks) return error.OperationExpired;
        return self.now;
    }

    fn open(context: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        if (self.pause_sign) {
            self.pause_sign = false;
            cooperative.current().?.yield();
        }
        return provider_fixture.provider().open(binding, blob, out);
    }

    fn beforeFlush(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.pause_flush) {
            self.pause_flush = false;
            cooperative.current().?.yield();
        }
    }

    fn run(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.result = self.creation.run(&self.device.service, self.access, "note-1.md", self.signer, &self.guard) catch |err| {
            self.failure = err;
            return;
        };
    }
} else struct {};

test "owned Notes creation requires live approval after actual signing wait" {
    const device = try CreationTest.Device.init(true);
    defer device.deinit();
    var signer_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const signer = try signer_fixture.init(.{ .kind = .user, .serial = 1 }, device.service.owner, device.service.task_id, @import("../storage/document_save_test.zig").signer);
    var test_context = CreationTest{ .device = device, .signer = signer, .access = .{ .owner = .{ .kind = .user, .serial = 1 }, .binding = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) }, .expires_at_ticks = 50, .signer = signer, .authorization = .{ .policies = &signer_fixture.policies, .subjects = signer_fixture.authority.subjects, .owner = .{ .kind = .user, .serial = 1 }, .expires_at_ticks = 50 } }, .pause_sign = true };
    test_context.guard = .{ .context = &test_context, .check_fn = CreationTest.check };
    signer_fixture.service.attachHardwareProvider(.{ .context = &test_context, .operations = &.{ .seal = CreationTest.provider_fixture.provider().operations.?.seal, .open = CreationTest.open } });
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = CreationTest.cooperative.Worker{ .stack = &stack };
    try worker.start(&test_context, CreationTest.run);
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.suspended, worker.state);
    try std.testing.expectEqual(@as(usize, 1), device.service.versionCount());
    try std.testing.expect((try ownedWorkspace(&device.service, test_context.access.owner)) == null);
    test_context.cancelled = true;
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(error.Cancelled, test_context.failure.?);
    try std.testing.expect(test_context.result == null and test_context.creation.pending == null);
    try std.testing.expectEqual(@as(usize, 1), device.service.versionCount());
    try std.testing.expect((try ownedWorkspace(&device.service, test_context.access.owner)) == null);
}

test "owned Notes creation retains one candidate through failed durable flush and retry" {
    const device = try CreationTest.Device.init(true);
    defer device.deinit();
    var signer_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const signer = try signer_fixture.init(.{ .kind = .user, .serial = 1 }, device.service.owner, device.service.task_id, @import("../storage/document_save_test.zig").signer);
    var test_context = CreationTest{ .device = device, .signer = signer, .access = .{ .owner = .{ .kind = .user, .serial = 1 }, .binding = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) }, .expires_at_ticks = 50, .signer = signer, .authorization = .{ .policies = &signer_fixture.policies, .subjects = signer_fixture.authority.subjects, .owner = .{ .kind = .user, .serial = 1 }, .expires_at_ticks = 50 } }, .pause_flush = true };
    test_context.guard = .{ .context = &test_context, .check_fn = CreationTest.check };
    device.before_flush = .{ .context = &test_context, .call = CreationTest.beforeFlush };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = CreationTest.cooperative.Worker{ .stack = &stack };
    try worker.start(&test_context, CreationTest.run);
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.suspended, worker.state);
    const candidate = test_context.creation.pending.?;
    try std.testing.expect(candidate.published and candidate.checkpoint_generation == 0);
    try std.testing.expectEqual(@as(usize, 2), device.service.versionCount());
    device.fail_flushes = true;
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(error.DurabilityBarrierFailed, test_context.failure.?);
    try std.testing.expect(test_context.result == null);
    device.fail_flushes = false;
    test_context.failure = null;
    try worker.start(&test_context, CreationTest.run);
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.complete, worker.state);
    try std.testing.expect(test_context.failure == null and test_context.result != null);
    try std.testing.expectEqual(candidate.version_id, test_context.result.?.version_id);
    try std.testing.expectEqual(@as(usize, 2), device.service.versionCount());
    device.crash();
    try requireCreated(&device.service, test_context.result.?, "note-1.md");
}

test "owned Notes creation withholds cancelled receipt without erasing durable successor" {
    const device = try CreationTest.Device.init(true);
    defer device.deinit();
    var signer_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const signer = try signer_fixture.init(.{ .kind = .user, .serial = 1 }, device.service.owner, device.service.task_id, @import("../storage/document_save_test.zig").signer);
    var test_context = CreationTest{ .device = device, .signer = signer, .access = .{ .owner = .{ .kind = .user, .serial = 1 }, .binding = .{ .boot_instance = @splat(1), .session_nonce = @splat(2) }, .expires_at_ticks = 50, .signer = signer, .authorization = .{ .policies = &signer_fixture.policies, .subjects = signer_fixture.authority.subjects, .owner = .{ .kind = .user, .serial = 1 }, .expires_at_ticks = 50 } }, .pause_flush = true };
    test_context.guard = .{ .context = &test_context, .check_fn = CreationTest.check };
    device.before_flush = .{ .context = &test_context, .call = CreationTest.beforeFlush };
    var stack: [128 * 1024]u8 align(16) = undefined;
    var worker = CreationTest.cooperative.Worker{ .stack = &stack };
    try worker.start(&test_context, CreationTest.run);
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.suspended, worker.state);
    test_context.cancelled = true;
    try worker.step();
    try std.testing.expectEqual(CreationTest.cooperative.Worker.State.complete, worker.state);
    try std.testing.expectEqual(error.Cancelled, test_context.failure.?);
    try std.testing.expect(test_context.result == null);
    const preserved = test_context.creation.pending.?;
    try std.testing.expect(preserved.published and preserved.checkpoint_generation != 0);
    device.crash();
    try requireCreated(&device.service, preserved, "note-1.md");
}
