const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const native_util = @import("../core/util.zig");
const notification_center = @import("notification_center.zig");
const principal = @import("../core/principal.zig");

pub const MAX_JOBS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 64;

pub const JobKind = enum(u8) {
    media_export,
    print_document,
};

pub const Visibility = enum(u8) {
    hidden,
    task,
    user,
};

pub const JobState = enum(u8) {
    queued,
    running,
    completed,
};

pub const JobRequest = struct {
    kind: JobKind,
    task_id: u64,
    workspace_id: u64,
    source_principal: principal.PrincipalId,
    label: []const u8,
    printer_identity: []const u8 = "",
    local_only: bool = true,
    visibility: Visibility = .user,
};

pub const JobRecord = struct {
    id: u64,
    kind: JobKind,
    task_id: u64,
    workspace_id: u64,
    source_principal: principal.PrincipalId,
    state: JobState,
    visibility: Visibility,
    local_only: bool,
    engine: accelerator_scheduler.Engine,
    claim_id: ?u64,
    notification_id: ?u64,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    printer_identity_len: usize,
    printer_identity: [MAX_LABEL_BYTES]u8,

    pub fn labelSlice(self: *const JobRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn printerIdentitySlice(self: *const JobRecord) []const u8 {
        return self.printer_identity[0..self.printer_identity_len];
    }
};

pub const Error = error{
    JobNotFound,
    JobTableFull,
    LabelTooLong,
    PrinterIdentityTooLong,
    PrinterRequiresLocalOnly,
} || accelerator_scheduler.Error || notification_center.Error;

const JobSlot = struct {
    in_use: bool = false,
    job: JobRecord = zeroJob(),
};

pub const Service = struct {
    next_job_id: u64 = 1,
    jobs: [MAX_JOBS]JobSlot = [_]JobSlot{JobSlot{}} ** MAX_JOBS,

    pub fn init() Service {
        return .{};
    }

    pub fn submit(
        self: *Service,
        request: JobRequest,
        scheduler: *accelerator_scheduler.Controller,
        notifications: *notification_center.Center,
        now_ticks: u64,
    ) Error!*JobRecord {
        _ = now_ticks;
        if (request.kind == .print_document and !request.local_only) return error.PrinterRequiresLocalOnly;

        const claim = try scheduler.claim(.{
            .task_id = request.task_id,
            .request = schedulerRequest(request.kind),
            .require_accelerator = request.kind == .media_export,
        });
        for (&self.jobs) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.job = zeroJob();
            slot.job.id = self.next_job_id;
            self.next_job_id += 1;
            slot.job.kind = request.kind;
            slot.job.task_id = request.task_id;
            slot.job.workspace_id = request.workspace_id;
            slot.job.source_principal = request.source_principal;
            slot.job.state = .running;
            slot.job.visibility = request.visibility;
            slot.job.local_only = request.local_only;
            slot.job.engine = claim.engine;
            slot.job.claim_id = claim.id;
            slot.job.label_len = native_util.copyTextExact(&slot.job.label, request.label) catch return error.LabelTooLong;
            slot.job.printer_identity_len = native_util.copyTextExact(&slot.job.printer_identity, request.printer_identity) catch return error.PrinterIdentityTooLong;
            if (slot.job.visibility == .task or slot.job.visibility == .user) {
                const notice = notifications.post(.{
                    .source = request.source_principal,
                    .reason = .policy_notice,
                    .urgency = .passive,
                    .task_id = request.task_id,
                    .detail = request.label,
                    .suppression_policy = .replace_same_source_reason_task,
                }) catch |err| {
                    _ = scheduler.releaseClaim(claim.id, null) catch |release_err| {
                        slot.in_use = false;
                        slot.job = zeroJob();
                        return release_err;
                    };
                    slot.in_use = false;
                    slot.job = zeroJob();
                    return err;
                };
                slot.job.notification_id = notice.id;
            }
            return &slot.job;
        }

        _ = try scheduler.releaseClaim(claim.id, null);
        return error.JobTableFull;
    }

    pub fn complete(
        self: *Service,
        job_id: u64,
        scheduler: *accelerator_scheduler.Controller,
        notifications: *notification_center.Center,
        now_ticks: u64,
    ) Error!?u64 {
        const job = self.find(job_id) orelse return error.JobNotFound;
        job.state = .completed;
        if (job.claim_id) |claim_id| {
            _ = try scheduler.releaseClaim(claim_id, null);
            job.claim_id = null;
        }
        if (job.visibility == .hidden) return null;

        const reason: notification_center.Reason = switch (job.kind) {
            .media_export => .media_export_complete,
            .print_document => .print_complete,
        };
        const notice = try notifications.post(.{
            .source = job.source_principal,
            .reason = reason,
            .urgency = .normal,
            .task_id = if (job.visibility == .task) job.task_id else null,
            .detail = job.labelSlice(),
            .expires_at_ticks = now_ticks + 100,
            .suppression_policy = .replace_same_source_reason_task,
        });
        job.notification_id = notice.id;
        return notice.id;
    }

    pub fn find(self: *Service, job_id: u64) ?*JobRecord {
        for (&self.jobs) |*slot| {
            if (slot.in_use and slot.job.id == job_id) return &slot.job;
        }
        return null;
    }
};

fn schedulerRequest(kind: JobKind) accelerator_scheduler.Request {
    return switch (kind) {
        .media_export => .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = 32 * 1024,
        },
        .print_document => .{
            .class = .background_light,
        },
    };
}

fn zeroJob() JobRecord {
    return .{
        .id = 0,
        .kind = .media_export,
        .task_id = 0,
        .workspace_id = 0,
        .source_principal = .{ .kind = .service, .serial = 0 },
        .state = .queued,
        .visibility = .hidden,
        .local_only = true,
        .engine = .cpu,
        .claim_id = null,
        .notification_id = null,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .printer_identity_len = 0,
        .printer_identity = [_]u8{0} ** MAX_LABEL_BYTES,
    };
}

test "media print service uses scheduled engines and emits completion notifications" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 12 };

    const export_job = try service.submit(.{
        .kind = .media_export,
        .task_id = 77,
        .workspace_id = 5,
        .source_principal = source,
        .label = "render trailer",
        .visibility = .task,
    }, &scheduler, &notifications, 10);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, export_job.engine);
    try std.testing.expectEqual(@as(?u64, 1), export_job.notification_id);
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());

    const print_job = try service.submit(.{
        .kind = .print_document,
        .task_id = 78,
        .workspace_id = 5,
        .source_principal = source,
        .label = "print invoice",
        .printer_identity = "printer://office-1",
        .local_only = true,
        .visibility = .user,
    }, &scheduler, &notifications, 11);
    try std.testing.expectEqualStrings("printer://office-1", print_job.printerIdentitySlice());

    const completion_id = (try service.complete(print_job.id, &scheduler, &notifications, 20)).?;
    try std.testing.expect(completion_id >= 3);
    try std.testing.expectEqual(JobState.completed, print_job.state);
    try std.testing.expectEqual(notification_center.Reason.print_complete, notifications.latestVisible(20).?.reason);
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());
    _ = try service.complete(export_job.id, &scheduler, &notifications, 21);
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "media print service rejects remote printing and hidden jobs stay silent" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 13 };

    try std.testing.expectError(error.PrinterRequiresLocalOnly, service.submit(.{
        .kind = .print_document,
        .task_id = 80,
        .workspace_id = 6,
        .source_principal = source,
        .label = "remote print",
        .printer_identity = "printer://remote",
        .local_only = false,
    }, &scheduler, &notifications, 5));

    const hidden = try service.submit(.{
        .kind = .media_export,
        .task_id = 81,
        .workspace_id = 6,
        .source_principal = source,
        .label = "background render",
        .visibility = .hidden,
    }, &scheduler, &notifications, 6);
    try std.testing.expectEqual(@as(?u64, null), hidden.notification_id);
    try std.testing.expectEqual(@as(?u64, null), try service.complete(hidden.id, &scheduler, &notifications, 7));
    try std.testing.expectEqual(@as(usize, 0), notifications.activeCount(7));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}
