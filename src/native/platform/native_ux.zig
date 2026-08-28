const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const humane_permissions = @import("../policy/humane_permissions.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const workspace = @import("../storage/workspace.zig");
const copyText = native_util.copyText;
const yesNo = native_util.yesNo;

pub const MAX_FLOWS: usize = 16;
pub const MAX_DETAIL_BYTES: usize = 128;
pub const MAX_BUNDLE_ID_BYTES: usize = 64;
pub const APPEND_ONLY_FLOW_LOG = true;
pub const FLOW_RECORD_SIZE_CEILING_BYTES: usize = 248;
pub const CONTROLLER_SIZE_CEILING_BYTES: usize = MAX_FLOWS * FLOW_RECORD_SIZE_CEILING_BYTES + @sizeOf(usize);
const REVIEW_FLOW_TEST_BUFFER_BYTES: usize = 384;

pub const FlowKind = enum(u8) {
    start_task,
    open_workspace,
    pair_device,
    review_permission_request,
    recover_system,
    open_document,
    edit_document,
    open_app_panel,
    focus_task,
    install_app,
    update_app,
    rollback_app_update,
    remove_app,
    sync_workspace,
    sync_conflict_review,
    containment_denial,
    share_document,
};

pub const FlowRecord = struct {
    id: u64,
    kind: FlowKind,
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    approved: bool = false,
    permission_kind: manifest.PermissionKind = .object_access,
    permission_required: bool = false,
    permission_local_only: bool = false,
    decision_local_only: bool = false,
    decision_has_lease: bool = false,
    decision_lease_ticks: manifest.LeaseTicks = 0,
    bundle_id_len: u8 = 0,
    bundle_id: [MAX_BUNDLE_ID_BYTES]u8 = [_]u8{0} ** MAX_BUNDLE_ID_BYTES,
    detail_len: u8 = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const FlowRecord) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn bundleIdSlice(self: *const FlowRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn permissionResourceSlice(self: *const FlowRecord) []const u8 {
        return self.detailSlice();
    }

    comptime {
        if (@sizeOf(@This()) > FLOW_RECORD_SIZE_CEILING_BYTES) {
            @compileError("native UX flow records exceed their compact text-sharing layout");
        }
    }
};

pub const Error = error{
    FlowTableFull,
} || task_runtime.Error || workspace.Error || sync_service.Error || sync_service.AuthorityError;

pub const Controller = struct {
    flows: [MAX_FLOWS]FlowRecord = [_]FlowRecord{zeroFlow()} ** MAX_FLOWS,
    flow_count: usize = 0,

    pub fn init() Controller {
        return .{};
    }

    pub fn initializeAllocated(self: *Controller) void {
        @memset(std.mem.asBytes(self), 0);
        for (&self.flows) |*flow| {
            flow.subject.kind = .service;
        }
    }

    comptime {
        if (@sizeOf(@This()) > CONTROLLER_SIZE_CEILING_BYTES) {
            @compileError("native UX controller exceeds its compact append-only layout");
        }
    }

    pub fn startTask(
        self: *Controller,
        runtime: *task_runtime.Runtime,
        request: task_runtime.TaskCreateRequest,
    ) Error!*task_runtime.TaskRecord {
        const task = try runtime.createTask(request);
        _ = try self.record(.start_task, task.id, 0, request.owner, request.initial_component.label, false);
        return task;
    }

    pub fn openWorkspace(
        self: *Controller,
        storage: *storage_service.Service,
        workspace_id: anytype,
        path: []const u8,
        owner: principal.PrincipalId,
    ) Error!workspace.Entry {
        const entry = try storage.resolve(workspace_id, path);
        _ = try self.record(.open_workspace, 0, object_store.ids.raw(workspace_id), owner, path, true);
        return entry;
    }

    pub fn openDocument(
        self: *Controller,
        storage: *storage_service.Service,
        workspace_id: anytype,
        path: []const u8,
        task_id: u64,
        owner: principal.PrincipalId,
    ) Error!workspace.Entry {
        const entry = try storage.resolve(workspace_id, path);
        _ = try self.record(.open_document, task_id, object_store.ids.raw(workspace_id), owner, path, true);
        return entry;
    }

    pub fn editDocument(
        self: *Controller,
        workspace_id: u64,
        task_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
    ) Error!*FlowRecord {
        return self.record(.edit_document, task_id, workspace_id, subject, detail, true);
    }

    pub fn openAppPanel(
        self: *Controller,
        task_id: u64,
        workspace_id: u64,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
    ) Error!*FlowRecord {
        const flow = try self.record(.open_app_panel, task_id, workspace_id, subject, bundle_id, true);
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn focusTask(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        title: []const u8,
    ) Error!*FlowRecord {
        return self.record(.focus_task, task_id, 0, subject, title, true);
    }

    pub fn installApp(
        self: *Controller,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
    ) Error!*FlowRecord {
        const flow = try self.record(.install_app, 0, 0, subject, bundle_id, true);
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn updateApp(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
    ) Error!*FlowRecord {
        const flow = try self.record(.update_app, task_id, 0, subject, bundle_id, true);
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn rollbackAppUpdate(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
    ) Error!*FlowRecord {
        const flow = try self.record(.rollback_app_update, task_id, 0, subject, bundle_id, true);
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn removeApp(
        self: *Controller,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
    ) Error!*FlowRecord {
        const flow = try self.record(.remove_app, 0, 0, subject, bundle_id, true);
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn syncWorkspace(
        self: *Controller,
        workspace_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
    ) Error!*FlowRecord {
        return self.record(.sync_workspace, 0, workspace_id, subject, detail, true);
    }

    pub fn syncConflictReview(
        self: *Controller,
        workspace_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
    ) Error!*FlowRecord {
        return self.record(.sync_conflict_review, 0, workspace_id, subject, detail, false);
    }

    pub fn shareDocument(
        self: *Controller,
        workspace_id: u64,
        task_id: u64,
        recipient: principal.PrincipalId,
        detail: []const u8,
    ) Error!*FlowRecord {
        return self.record(.share_document, task_id, workspace_id, recipient, detail, true);
    }

    pub fn containmentDenial(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
    ) Error!*FlowRecord {
        return self.record(.containment_denial, task_id, 0, subject, detail, false);
    }

    pub fn pairDevice(
        self: *Controller,
        sync: *sync_service.SyncPort,
        authority: sync_service.AuthorityContext,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        label: []const u8,
        user_signer: signing.SignerIdentity,
        device_signer: signing.SignerIdentity,
        tick: u64,
    ) Error!void {
        _ = try sync.enrollTrustedDevice(authority, user, device, label, user_signer, device_signer, tick);
        _ = try self.record(.pair_device, 0, 0, device, label, true);
    }

    pub fn reviewPermissionRequest(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        kind: manifest.PermissionKind,
        approved: bool,
    ) Error!bool {
        const request = manifest.PermissionRequest{
            .kind = kind,
            .resource = @tagName(kind),
            .rights = .{ .policy = .{} },
        };
        _ = try self.reviewPermissionDecision(task_id, subject, "", request, approved, false, null);
        return approved;
    }

    pub fn reviewPermissionDecision(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        bundle_id: []const u8,
        request: manifest.PermissionRequest,
        approved: bool,
        decision_local_only: bool,
        decision_lease_ticks: ?manifest.LeaseTicks,
    ) Error!*FlowRecord {
        const flow = try self.record(.review_permission_request, task_id, 0, subject, request.resource, approved);
        flow.permission_kind = request.kind;
        flow.permission_required = request.required;
        flow.permission_local_only = request.local_only;
        flow.decision_local_only = decision_local_only;
        flow.decision_has_lease = decision_lease_ticks != null;
        flow.decision_lease_ticks = decision_lease_ticks orelse 0;
        flow.bundle_id_len = @intCast(copyText(&flow.bundle_id, bundle_id));
        return flow;
    }

    pub fn recoverSystem(
        self: *Controller,
        task_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
    ) Error!void {
        _ = try self.record(.recover_system, task_id, 0, subject, detail, true);
    }

    pub fn flowAtOrder(self: *const Controller, order_index: usize) ?*const FlowRecord {
        if (order_index >= self.flow_count) return null;
        return &self.flows[order_index];
    }

    pub fn flowById(self: *const Controller, flow_id: u64) ?*const FlowRecord {
        if (flow_id == 0 or flow_id > self.flow_count) return null;
        return &self.flows[@intCast(flow_id - 1)];
    }

    fn record(
        self: *Controller,
        kind: FlowKind,
        task_id: u64,
        workspace_id: u64,
        subject: principal.PrincipalId,
        detail: []const u8,
        approved: bool,
    ) Error!*FlowRecord {
        if (self.flow_count >= MAX_FLOWS) return error.FlowTableFull;
        const flow = &self.flows[self.flow_count];
        flow.* = zeroFlow();
        flow.id = @intCast(self.flow_count + 1);
        flow.kind = kind;
        flow.task_id = task_id;
        flow.workspace_id = workspace_id;
        flow.subject = subject;
        flow.approved = approved;
        flow.detail_len = @intCast(copyText(&flow.detail, detail));
        self.flow_count += 1;
        return flow;
    }
};

pub fn renderReviewFlowToBuffer(buffer: []u8, flow: *const FlowRecord) ![]const u8 {
    if (flow.kind != .review_permission_request) return error.UnsupportedFlowKind;

    var used: usize = 0;
    const decision = if (flow.approved) "allow" else "deny";
    try appendFmt(buffer, &used, "UX review: task={d} bundle={s} kind={s} resource={s} decision={s}", .{
        flow.task_id,
        flow.bundleIdSlice(),
        @tagName(flow.permission_kind),
        flow.permissionResourceSlice(),
        decision,
    });
    try appendFmt(buffer, &used, " required={s} requested_local_only={s}", .{
        yesNo(flow.permission_required),
        yesNo(flow.permission_local_only),
    });
    try appendFmt(buffer, &used, " scope={s}", .{
        humane_permissions.scopeSummaryLabel(flow.permission_kind, flow.permission_local_only or flow.decision_local_only),
    });
    if (flow.approved) {
        try appendFmt(buffer, &used, " decision_local_only={s}", .{yesNo(flow.decision_local_only)});
        if (flow.decision_has_lease) {
            try appendFmt(buffer, &used, " lease={d}", .{flow.decision_lease_ticks});
        }
        try appendFmt(buffer, &used, " revoke_hint={s}", .{humane_permissions.revocationHint(flow.permission_kind)});
    }
    return buffer[0..used];
}

fn zeroFlow() FlowRecord {
    return .{
        .id = 0,
        .kind = .start_task,
    };
}

test "allocated native ux controller initializes empty reusable flow state" {
    const controller = try std.testing.allocator.create(Controller);
    defer std.testing.allocator.destroy(controller);
    controller.initializeAllocated();

    const subject = principal.PrincipalId{ .kind = .user, .serial = 7 };
    try controller.recoverSystem(11, subject, "allocated recovery");
    const flow = controller.flowAtOrder(0).?;
    try std.testing.expectEqual(@as(u64, 1), flow.id);
    try std.testing.expectEqual(FlowKind.recover_system, flow.kind);
    try std.testing.expect(flow.subject.eql(subject));
    try std.testing.expectEqualStrings("allocated recovery", flow.detailSlice());
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
}

test "native ux records task workspace pairing review and recovery flows" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const paired_device = principal.PrincipalId{ .kind = .device, .serial = 31 };
    const object_signer = signing.SignerIdentity{
        .label = "platform-storage",
        .seed = signing.seedFromByte(0x81),
    };
    const user_signer = signing.SignerIdentity{
        .label = "platform-user",
        .seed = signing.seedFromByte(0x82),
    };
    const device_signer = signing.SignerIdentity{
        .label = "platform-device",
        .seed = signing.seedFromByte(0x83),
    };

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(930, 61, storage_owner, &storage_checkpoint_store);
    const notes = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(990),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(object_signer, "notes", "text/plain", .document, "notes-v1", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "ux-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var sync = sync_service.Service.init(931, 62, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_authority_capability = try sync_capabilities.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = sync.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync_owner,
        .capability_id = sync_authority_capability.id,
        .now_ticks = 12,
    };
    _ = try sync_port.ensureUserRoot(sync_authority, user, "cameron", user_signer);

    var controller = Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = user,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 4_000,
            .memory_bytes = units.kibibytes(256),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(8),
            .background_allowed = false,
        },
        .local_only = true,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
    });
    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/notes.md", user);
    try controller.pairDevice(&sync_port, sync_authority, user, paired_device, "tablet", user_signer, device_signer, 12);
    try std.testing.expect(try controller.reviewPermissionRequest(task.id, user, .object_access, true));
    try controller.recoverSystem(task.id, user, "recovery-environment");

    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqualStrings("documents/notes.md", controller.flowAtOrder(1).?.detailSlice());
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(notes.version_id, opened.version_id);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, controller.flowAtOrder(3).?.permission_kind);
    try std.testing.expectEqualStrings("object_access", controller.flowAtOrder(3).?.permissionResourceSlice());

    storage_checkpoint_store.resetPersistent();
}

test "native ux renders structured permission review decisions" {
    var controller = Controller.init();
    const subject = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const flow = try controller.reviewPermissionDecision(
        44,
        subject,
        "app.notes",
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        true,
        true,
        400,
    );
    var buffer: [REVIEW_FLOW_TEST_BUFFER_BYTES]u8 = undefined;
    const rendered = try renderReviewFlowToBuffer(&buffer, flow);

    try std.testing.expect(flow.permissionResourceSlice().ptr == flow.detailSlice().ptr);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "bundle=app.notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "kind=object_access") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "resource=workspace:notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision=allow") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "scope=this object on this device") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision_local_only=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "lease=400") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "revoke_hint=remove this app from the object's share sheet") != null);
}

test "native ux records app lifecycle sync containment and removal flows" {
    var controller = Controller.init();
    const subject = principal.PrincipalId{ .kind = .user, .serial = 11 };

    _ = try controller.installApp(subject, "app.trip");
    _ = try controller.syncWorkspace(77, subject, "device-to-device");
    _ = try controller.syncConflictReview(77, subject, "1 conflict");
    _ = try controller.updateApp(44, subject, "app.trip");
    _ = try controller.rollbackAppUpdate(44, subject, "app.trip");
    _ = try controller.containmentDenial(44, subject, "direct host access blocked");
    _ = try controller.removeApp(subject, "app.trip");

    try std.testing.expectEqual(@as(usize, 7), controller.flow_count);
    try std.testing.expectEqual(FlowKind.install_app, controller.flowAtOrder(0).?.kind);
    try std.testing.expectEqualStrings("app.trip", controller.flowAtOrder(0).?.bundleIdSlice());
    try std.testing.expectEqual(FlowKind.sync_workspace, controller.flowAtOrder(1).?.kind);
    try std.testing.expectEqual(@as(u64, 77), controller.flowAtOrder(1).?.workspace_id);
    try std.testing.expectEqual(FlowKind.sync_conflict_review, controller.flowAtOrder(2).?.kind);
    try std.testing.expect(!controller.flowAtOrder(2).?.approved);
    try std.testing.expectEqual(FlowKind.containment_denial, controller.flowAtOrder(5).?.kind);
    try std.testing.expect(!controller.flowAtOrder(5).?.approved);
    try std.testing.expectEqual(FlowKind.remove_app, controller.flowAtOrder(6).?.kind);
    try std.testing.expectEqualStrings("app.trip", controller.flowAtOrder(6).?.bundleIdSlice());
}

test "native ux flow ids follow append order and stop at capacity" {
    var controller = Controller.init();
    const subject = principal.PrincipalId{ .kind = .user, .serial = 12 };

    for (0..MAX_FLOWS) |index| {
        const flow = try controller.installApp(subject, "app.full");
        try std.testing.expectEqual(@as(u64, @intCast(index + 1)), flow.id);
        try std.testing.expectEqual(flow, controller.flowAtOrder(index).?);
        try std.testing.expectEqual(flow, controller.flowById(flow.id).?);
    }
    try std.testing.expectError(error.FlowTableFull, controller.removeApp(subject, "app.full"));
    try std.testing.expectEqual(MAX_FLOWS, controller.flow_count);
    try std.testing.expect(controller.flowById(0) == null);
    try std.testing.expect(controller.flowById(MAX_FLOWS + 1) == null);
}
