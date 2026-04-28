const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const workspace = @import("../storage/workspace.zig");
const copyText = native_util.copyText;

pub const MAX_FLOWS: usize = 16;
pub const MAX_DETAIL_BYTES: usize = 128;
pub const MAX_BUNDLE_ID_BYTES: usize = 64;
pub const MAX_PERMISSION_RESOURCE_BYTES: usize = 96;

pub const FlowKind = enum(u8) {
    start_task,
    open_workspace,
    pair_device,
    review_permission_request,
    recover_system,
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
    decision_lease_ticks: u64 = 0,
    bundle_id_len: usize = 0,
    bundle_id: [MAX_BUNDLE_ID_BYTES]u8 = [_]u8{0} ** MAX_BUNDLE_ID_BYTES,
    permission_resource_len: usize = 0,
    permission_resource: [MAX_PERMISSION_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_PERMISSION_RESOURCE_BYTES,
    detail_len: usize = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const FlowRecord) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn bundleIdSlice(self: *const FlowRecord) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn permissionResourceSlice(self: *const FlowRecord) []const u8 {
        return self.permission_resource[0..self.permission_resource_len];
    }
};

pub const Error = error{
    FlowTableFull,
} || task_runtime.Error || workspace.Error || sync_service.Error;

pub const Controller = struct {
    next_flow_id: u64 = 1,
    flows: [MAX_FLOWS]FlowRecord = [_]FlowRecord{zeroFlow()} ** MAX_FLOWS,
    flow_count: usize = 0,

    pub fn init() Controller {
        return .{};
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
        workspace_id: u64,
        path: []const u8,
        owner: principal.PrincipalId,
    ) Error!workspace.Entry {
        const entry = try storage.resolve(workspace_id, path);
        _ = try self.record(.open_workspace, 0, workspace_id, owner, path, true);
        return entry;
    }

    pub fn pairDevice(
        self: *Controller,
        sync: *sync_service.Service,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        label: []const u8,
        user_signer: signing.SignerIdentity,
        device_signer: signing.SignerIdentity,
        tick: u64,
    ) Error!void {
        _ = try sync.enrollTrustedDevice(user, device, label, user_signer, device_signer, tick);
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
        decision_lease_ticks: ?u64,
    ) Error!*FlowRecord {
        const flow = try self.record(.review_permission_request, task_id, 0, subject, request.resource, approved);
        flow.permission_kind = request.kind;
        flow.permission_required = request.required;
        flow.permission_local_only = request.local_only;
        flow.decision_local_only = decision_local_only;
        flow.decision_has_lease = decision_lease_ticks != null;
        flow.decision_lease_ticks = decision_lease_ticks orelse 0;
        flow.bundle_id_len = copyText(&flow.bundle_id, bundle_id);
        flow.permission_resource_len = copyText(&flow.permission_resource, request.resource);
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
        flow.id = self.next_flow_id;
        self.next_flow_id += 1;
        flow.kind = kind;
        flow.task_id = task_id;
        flow.workspace_id = workspace_id;
        flow.subject = subject;
        flow.approved = approved;
        flow.detail_len = copyText(&flow.detail, detail);
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
    if (flow.approved) {
        try appendFmt(buffer, &used, " decision_local_only={s}", .{yesNo(flow.decision_local_only)});
        if (flow.decision_has_lease) {
            try appendFmt(buffer, &used, " lease={d}", .{flow.decision_lease_ticks});
        }
    }
    return buffer[0..used];
}

fn zeroFlow() FlowRecord {
    return .{
        .id = 0,
        .kind = .start_task,
    };
}

fn appendText(buffer: []u8, used: *usize, text: []const u8) !void {
    if (used.* + text.len > buffer.len) return error.NoSpaceLeft;
    @memcpy(buffer[used.*..][0..text.len], text);
    used.* += text.len;
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
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
        .seed = [_]u8{0x81} ** 32,
    };
    const user_signer = signing.SignerIdentity{
        .label = "platform-user",
        .seed = [_]u8{0x82} ** 32,
    };
    const device_signer = signing.SignerIdentity{
        .label = "platform-device",
        .seed = [_]u8{0x83} ** 32,
    };

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.initWithStore(930, 61, storage_owner, &storage_checkpoint_store);
    const notes = try storage.putVersion(.{
        .preferred_object_id = 990,
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
    _ = try sync.ensureUserRoot(user, "cameron", user_signer);

    var controller = Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = user,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 4_000,
            .memory_bytes = 256 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 8 * 1024,
            .background_allowed = false,
        },
        .local_only = true,
        .initial_component = .{
            .label = "notes",
            .entry = "app.notes",
        },
    });
    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/notes.md", user);
    try controller.pairDevice(&sync, user, paired_device, "tablet", user_signer, device_signer, 12);
    try std.testing.expect(try controller.reviewPermissionRequest(task.id, user, .object_access, true));
    try controller.recoverSystem(task.id, user, "recovery-environment");

    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqualStrings("documents/notes.md", controller.flows[1].detailSlice());
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expectEqual(notes.version_id, opened.version_id);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, controller.flows[3].permission_kind);
    try std.testing.expectEqualStrings("object_access", controller.flows[3].permissionResourceSlice());

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
    var buffer: [256]u8 = undefined;
    const rendered = try renderReviewFlowToBuffer(&buffer, flow);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "bundle=app.notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "kind=object_access") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "resource=workspace:notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision=allow") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "decision_local_only=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "lease=400") != null);
}
