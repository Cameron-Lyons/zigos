const std = @import("std");
const setup = @import("../../native/platform/trusted_setup_entry.zig");
const recovery = @import("../../native/services/identity_recovery_record.zig");
const Backend = setup.Backend;
const Result = setup.Result;

pub const Fixture = struct {
    remaining: usize = 0,
    running: bool = false,
    cancelled: bool = false,
    preparing: bool = false,
    loading: bool = false,
    load_kind: @TypeOf(@as(Result, .{}).kind) = .fresh,
    prepares: usize = 0,
    commits: usize = 0,
    record: recovery.Record = .{ .trusted = .{ .object_id = 1001, .digest = @splat(8) }, .key = @splat(9) },
    pub fn backend(self: *@This()) Backend {
        return .{ .context = self, .start_load = startLoad, .start_prepare = startPrepare, .start_commit = startCommit, .poll = poll, .cancel = cancel, .busy = busy };
    }
    fn startLoad(context: *anyopaque, _: u64) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.running = true;
        self.cancelled = false;
        self.loading = true;
    }
    fn startPrepare(context: *anyopaque, value: []const u8, _: u64) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, value, "12345678")) return error.BadTestPin;
        self.prepares += 1;
        self.running = true;
        self.cancelled = false;
        self.preparing = true;
        self.loading = false;
    }
    fn startCommit(context: *anyopaque, value: *const recovery.Record, _: u64) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        try std.testing.expectEqualDeep(self.record, value.*);
        self.commits += 1;
        self.running = true;
        self.cancelled = false;
        self.preparing = false;
        self.loading = false;
    }
    fn poll(context: *anyopaque, _: u64) !Result {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.remaining != 0) {
            self.remaining -= 1;
            return .{};
        }
        self.running = false;
        if (self.cancelled) return error.Cancelled;
        if (self.loading) return .{ .kind = self.load_kind, .identity = try @import("identity_enrollment.zig").record(), .trusted = self.record.trusted };
        return if (self.preparing) .{ .kind = .prepared, .recovery_record = self.record } else .{ .kind = .committed, .identity = try @import("identity_enrollment.zig").record(), .trusted = self.record.trusted };
    }
    fn cancel(context: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.cancelled = true;
    }
    fn busy(context: *anyopaque) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        return self.running;
    }
};
