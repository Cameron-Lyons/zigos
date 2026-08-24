const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const notification_center = @import("notification_center.zig");
const principal = @import("../core/principal.zig");
const units = @import("../core/units.zig");

pub const MAX_JOBS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 64;
pub const BOUNDED_JOB_SCAN = true;
pub const DIRECT_JOB_LOOKUP = true;
pub const COMPACT_COMPLETION_QUEUE = true;
pub const COMPACT_JOB_TEXT_METADATA = true;
pub const JOB_RECORD_SIZE_CEILING_BYTES: usize = 208;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 3_352;

comptime {
    if (MAX_JOBS > std.math.maxInt(u8) or MAX_LABEL_BYTES > std.math.maxInt(u8)) {
        @compileError("media and print metadata exceeds compact field capacity");
    }
}

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
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    printer_identity_len: u8,
    printer_identity: [MAX_LABEL_BYTES]u8,

    pub fn labelSlice(self: *const JobRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    pub fn printerIdentitySlice(self: *const JobRecord) []const u8 {
        return self.printer_identity[0..@as(usize, self.printer_identity_len)];
    }
};

pub const Error = error{
    JobNotFound,
    JobTableFull,
    LabelTooLong,
    PrinterIdentityTooLong,
    PrinterRequiresLocalOnly,
} || accelerator_scheduler.Error || notification_center.Error;

pub const JobId = indexed_arena.GenerationalHandle("MediaPrintJob");

pub const Service = struct {
    jobs: [MAX_JOBS]JobRecord = [_]JobRecord{zeroJob()} ** MAX_JOBS,
    completed_job_slots: [MAX_JOBS]u8 = [_]u8{0} ** MAX_JOBS,
    job_count: u8 = 0,
    completed_job_head: u8 = 0,
    completed_job_count: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("media and print service exceeds its fixed-state size ceiling");
        }
    }

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

        const slot_index = self.availableJobSlot() orelse return error.JobTableFull;
        const job_id = self.nextJobId(slot_index);
        var job = zeroJob();
        job.id = job_id;
        job.kind = request.kind;
        job.task_id = request.task_id;
        job.workspace_id = request.workspace_id;
        job.source_principal = request.source_principal;
        job.state = .running;
        job.visibility = request.visibility;
        job.local_only = request.local_only;
        job.label_len = @intCast(native_util.copyTextExact(&job.label, request.label) catch return error.LabelTooLong);
        job.printer_identity_len = @intCast(native_util.copyTextExact(&job.printer_identity, request.printer_identity) catch return error.PrinterIdentityTooLong);

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

        const job_slot = &self.jobs[slot_index];
        if (job_slot.id != 0) {
            self.retireCompletedJob(slot_index);
        } else {
            self.job_count += 1;
        }
        job_slot.* = job;
        return job_slot;
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
        const slot_index = self.findJobSlotIndex(job_id) orelse return null;
        return &self.jobs[slot_index];
    }

    pub fn jobCount(self: *const Service) usize {
        return @as(usize, self.job_count);
    }

    pub fn completedJobCount(self: *const Service) usize {
        return @as(usize, self.completed_job_count);
    }

    fn oldestCompletedJobId(self: *const Service) ?u64 {
        const slot_index = self.oldestCompletedJobSlotIndex() orelse return null;
        return self.completedJobSlotAt(slot_index).id;
    }

    fn markJobCompleted(self: *Service, job_id: u64, job: *JobRecord) void {
        if (job.state != .running) native_util.impossibleByInvariant("only running media and print jobs can complete");
        const slot_index = self.findJobSlotIndex(job_id) orelse
            native_util.impossibleByInvariant("completing media and print job has a live slot");
        if (&self.jobs[slot_index] != job) native_util.impossibleByInvariant("completion job pointer matches bounded slot");
        job.state = .completed;
        if (self.completed_job_count >= MAX_JOBS) {
            native_util.impossibleByInvariant("completed media and print job queue covers job slots");
        }
        const tail = (@as(usize, self.completed_job_head) + @as(usize, self.completed_job_count)) % MAX_JOBS;
        self.completed_job_slots[tail] = @intCast(slot_index);
        self.completed_job_count += 1;
    }

    fn retireCompletedJob(self: *Service, slot_index: usize) void {
        const oldest_slot_index = self.oldestCompletedJobSlotIndex() orelse
            native_util.impossibleByInvariant("full media and print table has a completed job before reuse");
        if (oldest_slot_index != slot_index) {
            native_util.impossibleByInvariant("media and print service reuses the oldest completed job");
        }
        _ = self.completedJobSlotAt(slot_index);
        self.completed_job_head = @intCast((@as(usize, self.completed_job_head) + 1) % MAX_JOBS);
        self.completed_job_count -= 1;
    }

    fn availableJobSlot(self: *const Service) ?usize {
        if (self.job_count < MAX_JOBS) {
            for (&self.jobs, 0..) |*job, slot_index| {
                if (job.id == 0) return slot_index;
            }
            native_util.impossibleByInvariant("media and print job count leaves a free slot");
        }
        return self.oldestCompletedJobSlotIndex();
    }

    fn findJobSlotIndex(self: *const Service, job_id: u64) ?usize {
        const handle = JobId{ .value = job_id };
        if (handle.isZero()) return null;
        const slot_index = handle.slotIndex();
        if (slot_index >= MAX_JOBS) return null;
        return if (self.jobs[slot_index].id == job_id) slot_index else null;
    }

    fn oldestCompletedJobSlotIndex(self: *const Service) ?usize {
        if (self.completed_job_count == 0) return null;
        return @as(usize, self.completed_job_slots[self.completed_job_head]);
    }

    fn completedJobSlotAt(self: *const Service, slot_index: usize) *const JobRecord {
        if (slot_index >= MAX_JOBS) native_util.impossibleByInvariant("completed media and print queue points outside slots");
        const job = &self.jobs[slot_index];
        if (job.id == 0) native_util.impossibleByInvariant("completed media and print queue points at a free slot");
        if (job.state != .completed) native_util.impossibleByInvariant("completed media and print queue points at an unfinished job");
        return job;
    }

    fn nextJobId(self: *const Service, slot_index: usize) u64 {
        const current_generation = (JobId{ .value = self.jobs[slot_index].id }).generation();
        const incremented = current_generation +% 1;
        const generation = if (incremented == 0) 1 else incremented;
        return JobId.fromParts(slot_index, generation).value;
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

test "media and print job metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(JobRecord, "label_len"));
    try std.testing.expectEqual(u8, @FieldType(JobRecord, "printer_identity_len"));
    try std.testing.expectEqual(@as(usize, 208), @sizeOf(JobRecord));
    try std.testing.expectEqual(@as(usize, 3_352), @sizeOf(Service));
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
    try std.testing.expectEqual(@as(usize, 1), service.completedJobCount());
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
    try std.testing.expectEqual(JobId.fromParts(0, 1).value, hidden.id);
    try std.testing.expectEqual(@as(?u64, null), hidden.notification_id);
    try std.testing.expectEqual(@as(?u64, null), try service.complete(hidden.id, &scheduler, &notifications, 9));
    try std.testing.expectEqual(@as(usize, 1), service.completedJobCount());
    try std.testing.expectEqual(@as(?u64, null), try service.complete(hidden.id, &scheduler, &notifications, 10));
    try std.testing.expectEqual(@as(usize, 1), service.completedJobCount());
    try std.testing.expectEqual(@as(usize, 0), notifications.activeCount(9));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "media print service uses direct generational ids through bounded capacity" {
    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var service = Service.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 14 };

    for (0..MAX_JOBS) |index| {
        const job = try service.submit(.{
            .kind = .print_document,
            .task_id = @intCast(100 + index),
            .workspace_id = 8,
            .source_principal = source,
            .label = "full table print",
            .visibility = .hidden,
        }, &scheduler, &notifications, 20);
        const job_id = JobId{ .value = job.id };
        try std.testing.expectEqual(index, job_id.slotIndex());
        try std.testing.expectEqual(@as(u32, 1), job_id.generation());
    }
    try std.testing.expectEqual(MAX_JOBS, service.jobCount());
    try std.testing.expectEqual(@as(u16, MAX_JOBS), scheduler.activeClaimCount());
    try std.testing.expect(service.find(0) == null);
    try std.testing.expect(service.find(JobId.fromParts(MAX_JOBS, 1).value) == null);
    try std.testing.expectError(error.JobTableFull, service.submit(.{
        .kind = .print_document,
        .task_id = 200,
        .workspace_id = 8,
        .source_principal = source,
        .label = "rejected full table print",
        .visibility = .hidden,
    }, &scheduler, &notifications, 21));
    try std.testing.expectEqual(@as(u16, MAX_JOBS), scheduler.activeClaimCount());
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

    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.jobCount());
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.completedJobCount());
    try std.testing.expectEqual(job_ids[2], service.oldestCompletedJobId().?);
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
    try std.testing.expectEqual(@as(usize, 2), (JobId{ .value = replacement.id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 2), (JobId{ .value = replacement.id }).generation());
    try std.testing.expect(service.find(job_ids[2]) == null);
    try std.testing.expect(service.find(job_ids[0]) != null);
    try std.testing.expect(service.find(job_ids[1]) != null);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.jobCount());
    try std.testing.expectEqual(@as(usize, MAX_JOBS - 1), service.completedJobCount());
    try std.testing.expectEqual(job_ids[0], service.oldestCompletedJobId().?);
    try std.testing.expectEqual(@as(u16, 1), scheduler.activeClaimCount());
    _ = try service.complete(replacement.id, &scheduler, &notifications, 100);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.completedJobCount());
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
    try std.testing.expectEqual(job_ids[0], service.oldestCompletedJobId().?);

    const wrapped_replacement = try service.submit(.{
        .kind = .print_document,
        .task_id = 201,
        .workspace_id = 7,
        .source_principal = source,
        .label = "wrapped overflow",
        .printer_identity = "printer://local",
        .local_only = true,
        .visibility = .hidden,
    }, &scheduler, &notifications, 101);
    try std.testing.expectEqual(@as(usize, 0), (JobId{ .value = wrapped_replacement.id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 2), (JobId{ .value = wrapped_replacement.id }).generation());
    try std.testing.expect(service.find(job_ids[0]) == null);
    try std.testing.expectEqual(job_ids[3], service.oldestCompletedJobId().?);
    try std.testing.expectEqual(@as(usize, MAX_JOBS - 1), service.completedJobCount());
    _ = try service.complete(wrapped_replacement.id, &scheduler, &notifications, 102);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), service.completedJobCount());
    try std.testing.expectEqual(job_ids[3], service.oldestCompletedJobId().?);
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
