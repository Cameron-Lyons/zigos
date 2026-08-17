const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const notification_center = @import("notification_center.zig");
const principal = @import("../core/principal.zig");
const units = @import("../core/units.zig");

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
    JobIdExhausted,
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

fn jobSlotId(slot: *const JobSlot) u64 {
    return slot.job.id;
}

const JobArena = indexed_arena.IndexedArenaWithKey(u64, JobSlot, MAX_JOBS, MAX_JOBS * 2, jobSlotId);
const CompletedJobIndex = indexed_arena.MultimapIndex(MAX_JOBS, 1, 2);
const COMPLETED_JOB_KEY: u64 = 1;

pub const Service = struct {
    next_job_id: u64 = 1,
    jobs: JobArena = JobArena.init(),
    completed_job_index: CompletedJobIndex = CompletedJobIndex.init(),

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
        if (request.label.len > MAX_LABEL_BYTES) return error.LabelTooLong;
        if (request.printer_identity.len > MAX_LABEL_BYTES) return error.PrinterIdentityTooLong;

        const job_id = self.next_job_id;
        if (job_id == 0) return error.JobIdExhausted;
        const retired_job_id = if (self.jobs.countInUse() >= MAX_JOBS)
            self.oldestCompletedJobId() orelse return error.JobTableFull
        else
            0;
        var job = zeroJob();
        job.id = job_id;
        job.kind = request.kind;
        job.task_id = request.task_id;
        job.workspace_id = request.workspace_id;
        job.source_principal = request.source_principal;
        job.state = .running;
        job.visibility = request.visibility;
        job.local_only = request.local_only;
        job.label_len = native_util.copyTextExact(&job.label, request.label) catch return error.LabelTooLong;
        job.printer_identity_len = native_util.copyTextExact(&job.printer_identity, request.printer_identity) catch return error.PrinterIdentityTooLong;

        const claim = try scheduler.claim(.{
            .task_id = request.task_id,
            .request = schedulerRequest(request.kind),
            .require_accelerator = request.kind == .media_export,
        });
        job.engine = claim.engine;
        job.claim_id = claim.id;
        if (job.visibility == .task or job.visibility == .user) {
            const notice = notifications.post(.{
                .source = request.source_principal,
                .reason = .policy_notice,
                .urgency = .passive,
                .task_id = request.task_id,
                .detail = request.label,
                .suppression_policy = .replace_same_source_reason_task,
            }) catch |err| {
                _ = try scheduler.releaseClaim(claim.id, null);
                return err;
            };
            job.notification_id = notice.id;
        }

        if (retired_job_id != 0) {
            self.retireCompletedJob(retired_job_id);
        }
        const slot_index = self.jobs.insertIndex(job_id, .{ .job = job }) orelse
            native_util.impossibleByInvariant("prechecked print job insertion must succeed");
        const slot = &self.jobs.slots[slot_index];
        self.next_job_id +%= 1;
        return &slot.job;
    }

    pub fn complete(
        self: *Service,
        job_id: u64,
        scheduler: *accelerator_scheduler.Controller,
        notifications: *notification_center.Center,
        now_ticks: u64,
    ) Error!?u64 {
        const job = self.find(job_id) orelse return error.JobNotFound;
        if (job.state == .completed) return job.notification_id;
        if (job.visibility == .hidden) {
            if (job.claim_id) |claim_id| {
                _ = try scheduler.releaseClaim(claim_id, null);
            }
            job.claim_id = null;
            self.markJobCompleted(job_id, job);
            return null;
        }

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
        if (job.claim_id) |claim_id| {
            _ = try scheduler.releaseClaim(claim_id, null);
        }
        job.claim_id = null;
        job.notification_id = notice.id;
        self.markJobCompleted(job_id, job);
        return notice.id;
    }

    pub fn find(self: *Service, job_id: u64) ?*JobRecord {
        const slot = self.jobs.get(job_id) orelse return null;
        return &slot.job;
    }

    fn oldestCompletedJobId(self: *const Service) ?u64 {
        const slot_index = self.completed_job_index.head(COMPLETED_JOB_KEY);
        if (slot_index == indexed_arena.no_index) return null;
        return self.completedJobSlotAt(slot_index).job.id;
    }

    fn markJobCompleted(self: *Service, job_id: u64, job: *JobRecord) void {
        if (job.state != .running) native_util.impossibleByInvariant("only running media and print jobs can complete");
        const slot_index = self.jobs.slotIndexOf(job_id) orelse
            native_util.impossibleByInvariant("completing media and print job has an arena slot");
        if (&self.jobs.slots[slot_index].job != job) native_util.impossibleByInvariant("completion job pointer matches indexed slot");
        if (!self.completed_job_index.append(COMPLETED_JOB_KEY, slot_index)) {
            native_util.impossibleByInvariant("completed media and print job index covers job slots");
        }
        job.state = .completed;
    }

    fn retireCompletedJob(self: *Service, job_id: u64) void {
        const slot_index = self.jobs.slotIndexOf(job_id) orelse
            native_util.impossibleByInvariant("completed media and print job disappeared before reuse");
        _ = self.completedJobSlotAt(slot_index);
        if (!self.completed_job_index.remove(COMPLETED_JOB_KEY, slot_index)) {
            native_util.impossibleByInvariant("completed media and print job index is missing its reusable head");
        }
        if (!self.jobs.removeIndex(slot_index)) native_util.impossibleByInvariant("completed media and print job slot remains live until reuse");
    }

    fn completedJobSlotAt(self: *const Service, slot_index: usize) *const JobSlot {
        if (slot_index >= MAX_JOBS) native_util.impossibleByInvariant("completed media and print job index points outside slots");
        const slot = &self.jobs.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("completed media and print job index points at a free slot");
        if (slot.job.state != .completed) native_util.impossibleByInvariant("completed media and print job index points at an unfinished job");
        return slot;
    }
};

fn schedulerRequest(kind: JobKind) accelerator_scheduler.Request {
    return switch (kind) {
        .media_export => .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = units.kibibytes(32),
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
    const next_notification_id = notifications.next_notification_id;
    try std.testing.expectEqual(@as(?u64, completion_id), try service.complete(print_job.id, &scheduler, &notifications, 21));
    try std.testing.expectEqual(next_notification_id, notifications.next_notification_id);
    try std.testing.expectEqual(@as(usize, 1), service.completed_job_index.count(COMPLETED_JOB_KEY));
    _ = try service.complete(export_job.id, &scheduler, &notifications, 21);
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "media print service rejects remote printing and hidden jobs stay silent" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 13 };
    const too_long_label = [_]u8{'x'} ** (MAX_LABEL_BYTES + 1);
    const too_long_printer = [_]u8{'p'} ** (MAX_LABEL_BYTES + 1);

    try std.testing.expectError(error.PrinterRequiresLocalOnly, service.submit(.{
        .kind = .print_document,
        .task_id = 80,
        .workspace_id = 6,
        .source_principal = source,
        .label = "remote print",
        .printer_identity = "printer://remote",
        .local_only = false,
    }, &scheduler, &notifications, 5));

    try std.testing.expectError(error.LabelTooLong, service.submit(.{
        .kind = .media_export,
        .task_id = 81,
        .workspace_id = 6,
        .source_principal = source,
        .label = too_long_label[0..],
    }, &scheduler, &notifications, 6));
    try std.testing.expectError(error.PrinterIdentityTooLong, service.submit(.{
        .kind = .print_document,
        .task_id = 82,
        .workspace_id = 6,
        .source_principal = source,
        .label = "local print",
        .printer_identity = too_long_printer[0..],
    }, &scheduler, &notifications, 7));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
    try std.testing.expect(service.find(1) == null);

    const hidden = try service.submit(.{
        .kind = .media_export,
        .task_id = 83,
        .workspace_id = 6,
        .source_principal = source,
        .label = "background render",
        .visibility = .hidden,
    }, &scheduler, &notifications, 8);
    try std.testing.expectEqual(@as(u64, 1), hidden.id);
    try std.testing.expectEqual(@as(?u64, null), hidden.notification_id);
    try std.testing.expectEqual(@as(?u64, null), try service.complete(hidden.id, &scheduler, &notifications, 9));
    try std.testing.expectEqual(@as(usize, 1), service.completed_job_index.count(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(@as(?u64, null), try service.complete(hidden.id, &scheduler, &notifications, 10));
    try std.testing.expectEqual(@as(usize, 1), service.completed_job_index.count(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(@as(usize, 0), notifications.activeCount(9));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "media print service job ids stop at exhaustion and full tables do not consume ids" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 14 };

    service.next_job_id = std.math.maxInt(u64);
    const max_job = try service.submit(.{
        .kind = .print_document,
        .task_id = 90,
        .workspace_id = 7,
        .source_principal = source,
        .label = "max id print",
        .visibility = .hidden,
    }, &scheduler, &notifications, 10);
    try std.testing.expectEqual(std.math.maxInt(u64), max_job.id);
    try std.testing.expectEqual(@as(u64, 0), service.next_job_id);
    try std.testing.expect(service.find(0) == null);

    try std.testing.expectError(error.JobIdExhausted, service.submit(.{
        .kind = .print_document,
        .task_id = 91,
        .workspace_id = 7,
        .source_principal = source,
        .label = "exhausted id print",
        .visibility = .hidden,
    }, &scheduler, &notifications, 11));
    try std.testing.expectEqual(@as(usize, 1), service.jobs.countInUse());
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());

    var full_scheduler = accelerator_scheduler.Controller.init();
    var full_notifications = notification_center.Center.init();
    var full_service = Service.init();
    for (0..MAX_JOBS) |index| {
        _ = try full_service.submit(.{
            .kind = .print_document,
            .task_id = @intCast(100 + index),
            .workspace_id = 8,
            .source_principal = source,
            .label = "full table print",
            .visibility = .hidden,
        }, &full_scheduler, &full_notifications, 20);
    }
    const next_before_full = full_service.next_job_id;
    try std.testing.expectError(error.JobTableFull, full_service.submit(.{
        .kind = .print_document,
        .task_id = 200,
        .workspace_id = 8,
        .source_principal = source,
        .label = "rejected full table print",
        .visibility = .hidden,
    }, &full_scheduler, &full_notifications, 21));
    try std.testing.expectEqual(next_before_full, full_service.next_job_id);
}

test "media print service retains recent completions and recycles the oldest completed job" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 14 };

    var job_ids: [MAX_JOBS]u64 = [_]u64{0} ** MAX_JOBS;
    var job_index: usize = 0;
    while (job_index < MAX_JOBS) : (job_index += 1) {
        const job = try service.submit(.{
            .kind = .print_document,
            .task_id = 90 + job_index,
            .workspace_id = 7,
            .source_principal = source,
            .label = "quiet print",
            .printer_identity = "printer://local",
            .local_only = true,
            .visibility = .hidden,
        }, &scheduler, &notifications, 30 + job_index);
        job_ids[job_index] = job.id;
    }
    try std.testing.expectEqual(@as(u16, MAX_JOBS), scheduler.activeClaimCount());

    try std.testing.expectEqual(@as(?u64, null), try service.complete(job_ids[2], &scheduler, &notifications, 60));
    try std.testing.expectEqual(@as(?u64, null), try service.complete(job_ids[0], &scheduler, &notifications, 61));
    for (job_ids[3..], 0..) |job_id, completion_index| {
        try std.testing.expectEqual(@as(?u64, null), try service.complete(job_id, &scheduler, &notifications, 62 + completion_index));
    }
    try std.testing.expectEqual(@as(?u64, null), try service.complete(job_ids[1], &scheduler, &notifications, 90));

    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.jobs.countInUse());
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.completed_job_index.count(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(service.jobs.slotIndexOf(job_ids[2]).?, service.completed_job_index.head(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
    const replacement = try service.submit(.{
        .kind = .print_document,
        .task_id = 200,
        .workspace_id = 7,
        .source_principal = source,
        .label = "overflow",
        .printer_identity = "printer://local",
        .local_only = true,
        .visibility = .hidden,
    }, &scheduler, &notifications, 99);
    try std.testing.expectEqual(@as(u64, MAX_JOBS + 1), replacement.id);
    try std.testing.expect(service.find(job_ids[2]) == null);
    try std.testing.expect(service.find(job_ids[0]) != null);
    try std.testing.expect(service.find(job_ids[1]) != null);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.jobs.countInUse());
    try std.testing.expectEqual(@as(usize, MAX_JOBS - 1), service.completed_job_index.count(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(service.jobs.slotIndexOf(job_ids[0]).?, service.completed_job_index.head(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());
    _ = try service.complete(replacement.id, &scheduler, &notifications, 100);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.completed_job_index.count(COMPLETED_JOB_KEY));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "media print service visible completion waits for completion notification capacity" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 15 };

    const job = try service.submit(.{
        .kind = .print_document,
        .task_id = 210,
        .workspace_id = 9,
        .source_principal = source,
        .label = "visible print",
        .visibility = .task,
    }, &scheduler, &notifications, 30);
    try std.testing.expectEqual(JobState.running, job.state);
    try std.testing.expect(job.claim_id != null);
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());

    for (0..notification_center.MAX_NOTIFICATIONS - notifications.activeCount(30)) |index| {
        _ = try notifications.post(.{
            .source = source,
            .reason = .policy_notice,
            .urgency = .normal,
            .task_id = @intCast(300 + index),
            .detail = "filler notice",
        });
    }

    try std.testing.expectError(error.NotificationTableFull, service.complete(job.id, &scheduler, &notifications, 31));
    try std.testing.expectEqual(JobState.running, job.state);
    try std.testing.expect(job.claim_id != null);
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());
}
