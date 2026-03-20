const std = @import("std");
const parser = @import("parser/pipeline.zig");

pub const MAX_BACKGROUND_JOBS = 8;
pub const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;

pub const BackgroundJob = struct {
    active: bool = false,
    id: u32 = 0,
    pid: u32 = 0,
    stopped: bool = false,
    command_len: usize = 0,
    command: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,

    pub fn commandSlice(self: *const BackgroundJob) []const u8 {
        return self.command[0..self.command_len];
    }
};

pub const RegisterError = error{
    TooManyJobs,
    CommandTooLong,
};

pub const JobTable = struct {
    jobs: [MAX_BACKGROUND_JOBS]BackgroundJob = [_]BackgroundJob{BackgroundJob{}} ** MAX_BACKGROUND_JOBS,
    next_job_id: u32 = 1,
    foreground_pid: ?u32 = null,

    pub fn latestPid(self: *JobTable) ?u32 {
        const job = self.current() orelse return null;
        return job.pid;
    }

    pub fn register(self: *JobTable, pid: u32, command: []const u8) RegisterError!*BackgroundJob {
        if (command.len >= MAX_COMMAND_LENGTH) return error.CommandTooLong;

        for (&self.jobs) |*job| {
            if (job.active) continue;
            job.* = .{
                .active = true,
                .id = self.next_job_id,
                .pid = pid,
                .stopped = false,
                .command_len = command.len,
            };
            if (command.len > 0) {
                @memcpy(job.command[0..command.len], command);
            }
            self.next_job_id += 1;
            return job;
        }

        return error.TooManyJobs;
    }

    pub fn findByPid(self: *JobTable, pid: u32) ?*BackgroundJob {
        for (&self.jobs) |*job| {
            if (job.active and job.pid == pid) return job;
        }
        return null;
    }

    pub fn current(self: *JobTable) ?*BackgroundJob {
        var best: ?*BackgroundJob = null;
        for (&self.jobs) |*job| {
            if (!job.active) continue;
            if (best == null or job.id > best.?.id) {
                best = job;
            }
        }
        return best;
    }

    pub fn byId(self: *JobTable, job_id: u32) ?*BackgroundJob {
        for (&self.jobs) |*job| {
            if (job.active and job.id == job_id) return job;
        }
        return null;
    }

    pub fn select(self: *JobTable, spec: ?[]const u8) ?*BackgroundJob {
        const value = spec orelse return self.current();
        const job_id = parseJobId(value) orelse return null;
        return self.byId(job_id);
    }
};

pub fn parseJobId(spec: []const u8) ?u32 {
    const digits = if (spec.len > 0 and spec[0] == '%') spec[1..] else spec;
    if (digits.len == 0) return null;

    var result: u32 = 0;
    for (digits) |char| {
        if (char < '0' or char > '9') return null;
        result = result * 10 + (char - '0');
    }
    return result;
}

test "parseJobId accepts numeric and percent-prefixed ids" {
    try std.testing.expectEqual(@as(?u32, 7), parseJobId("7"));
    try std.testing.expectEqual(@as(?u32, 42), parseJobId("%42"));
    try std.testing.expectEqual(@as(?u32, null), parseJobId(""));
    try std.testing.expectEqual(@as(?u32, null), parseJobId("%"));
    try std.testing.expectEqual(@as(?u32, null), parseJobId("abc"));
}

test "job table selects current and explicit jobs" {
    var table = JobTable{};
    const job1 = try table.register(11, "sleep 1");
    const job2 = try table.register(22, "sleep 2");

    try std.testing.expectEqual(@as(u32, 22), table.latestPid().?);
    try std.testing.expect(table.select(null) == job2);
    try std.testing.expect(table.select("%1") == job1);
    try std.testing.expect(table.select("2") == job2);

    job2.active = false;
    try std.testing.expect(table.select(null) == job1);
    try std.testing.expectEqualStrings("sleep 1", job1.commandSlice());
}

test "job table rejects commands that exceed storage" {
    var table = JobTable{};
    var oversized = [_]u8{'x'} ** MAX_COMMAND_LENGTH;
    try std.testing.expectError(error.CommandTooLong, table.register(1, oversized[0..]));
}
