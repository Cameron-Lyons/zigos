const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");

pub const LifecycleOperation = policy_object.LifecycleOperation;
pub const RESULT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const TRANSITION_TASK_INDEX_LOOKUPS: u8 = 1;
pub const TRANSITION_HANDLE_DERIVATIONS: u8 = 0;

pub const Error = task_runtime.Error || event_ledger.Error || error{
    InvalidLifecycleTransition,
    PolicyDenied,
    TaskOwnerMismatch,
};

pub const ControlRequest = struct {
    subject: principal.PrincipalId,
    target_owner: principal.PrincipalId,
    task_id: u64,
    operation: LifecycleOperation,
    checkpoint_present: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const ControlResult = struct {
    task_id: u64,
    state: task_runtime.TaskState,
};

pub const Service = struct {
    runtime: *task_runtime.Runtime,

    pub fn init(runtime: *task_runtime.Runtime) Service {
        return .{ .runtime = runtime };
    }

    pub fn control(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: ControlRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!ControlResult {
        const task = self.runtime.find(request.task_id) orelse {
            try recordLifecycle(ledger, request, false);
            return error.TaskNotFound;
        };
        if (!task.owner.eql(request.target_owner)) {
            try recordLifecycle(ledger, request, false);
            return error.TaskOwnerMismatch;
        }

        const decision = policies.lifecycleDecision(subjects, .{
            .operation = request.operation,
            .checkpoint_present = request.checkpoint_present,
        });
        if (!decision.allowed) {
            try recordLifecycle(ledger, request, false);
            return error.PolicyDenied;
        }

        const transitioned = switch (request.operation) {
            .suspend_task => self.runtime.suspendResolvedTask(task, request.now_ticks),
            .resume_task => self.runtime.resumeResolvedTask(task, request.now_ticks),
            .terminate_task => self.runtime.terminateResolvedTask(task, request.now_ticks, null),
        };
        try recordLifecycle(ledger, request, transitioned);
        if (!transitioned) return error.InvalidLifecycleTransition;

        return .{
            .task_id = task.id,
            .state = task.state,
        };
    }
};

fn recordLifecycle(
    ledger: ?*event_ledger.Ledger,
    request: ControlRequest,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordTaskLifecycle(
            request.subject,
            request.task_id,
            ledgerOperation(request.operation),
            allowed,
            request.checkpoint_present,
            request.now_ticks,
            request.detail,
        );
    }
}

fn ledgerOperation(operation: LifecycleOperation) event_ledger.TaskLifecycleOperation {
    return switch (operation) {
        .suspend_task => .suspend_task,
        .resume_task => .resume_task,
        .terminate_task => .terminate_task,
    };
}

test "task lifecycle service gates app suspend resume terminate and redacts audit details" {
    var runtime = task_runtime.Runtime.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 810 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 811 };
    const task = try runtime.createTask(.{
        .owner = app,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(16),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(4),
            .background_allowed = false,
        },
        .local_only = true,
    });

    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 44 },
        .label = "lifecycle policy",
        .task_lifecycle_allowed = true,
        .require_lifecycle_checkpoint_before_terminate = true,
    }, signing.SignerIdentity{
        .label = "lifecycle-policy-key",
        .seed = signing.seedFromByte(0x92),
    });
    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var ledger = event_ledger.Ledger.init();
    var service = Service.init(&runtime);

    try std.testing.expectError(error.TaskOwnerMismatch, service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = user,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 9,
        .detail = "private wrong owner suspend",
    }, &ledger));
    try std.testing.expectEqual(task_runtime.TaskState.active, runtime.find(task.id).?.state);

    const suspended = try service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 10,
        .detail = "private suspend reason",
    }, &ledger);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, suspended.state);
    try std.testing.expectEqual(task_runtime.AuditEventKind.suspended, runtime.find(task.id).?.latestAuditEvent().?.kind);

    try std.testing.expectError(error.InvalidLifecycleTransition, service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 11,
        .detail = "private duplicate suspend",
    }, &ledger));

    const resumed = try service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .resume_task,
        .now_ticks = 12,
        .detail = "private resume reason",
    }, &ledger);
    try std.testing.expectEqual(task_runtime.TaskState.active, resumed.state);
    try std.testing.expectEqual(task_runtime.AuditEventKind.resumed, runtime.find(task.id).?.latestAuditEvent().?.kind);

    try std.testing.expectError(error.PolicyDenied, service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .terminate_task,
        .now_ticks = 13,
        .detail = "private terminate without checkpoint",
    }, &ledger));
    try std.testing.expectEqual(task_runtime.TaskState.active, runtime.find(task.id).?.state);

    const terminated = try service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .terminate_task,
        .checkpoint_present = true,
        .now_ticks = 14,
        .detail = "private terminate after checkpoint",
    }, &ledger);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, terminated.state);
    try std.testing.expectEqual(task_runtime.AuditEventKind.terminated, runtime.find(task.id).?.latestAuditEvent().?.kind);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 6), summary.task_lifecycle_events);
    try std.testing.expectEqual(@as(usize, 3), summary.task_lifecycle_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.task_lifecycle_terminations);
    try std.testing.expect(summary.protected_details_redacted >= summary.task_lifecycle_events);

    var buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private terminate after checkpoint") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=task_lifecycle") != null);
}
