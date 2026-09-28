const std = @import("std");
const entry = @import("../../native/platform/trusted_pin_entry.zig");

// Host-test authenticator. Production uses the TPM-backed session adapter.
pub const Fixture = struct {
    locks: usize = 0,
    attempts: usize = 0,
    expected: []const u8 = "73019428",
    reject: ?anyerror = null,
    expires_at: u64 = 0,
    active: bool = false,
    pending: bool = false,
    cancelled: bool = false,
    polls_remaining: usize = 0,
    late_success: bool = false,
    failure: ?anyerror = null,

    pub fn authenticator(self: *Fixture) entry.Authenticator {
        return .{ .context = self, .lock_fn = lock, .start_fn = start, .poll_fn = poll, .busy_fn = busy, .deadline_fn = deadline };
    }
    fn lock(context: *anyopaque) void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        self.locks += 1;
        if (self.pending) self.cancelled = true;
        self.active = false;
        self.expires_at = 0;
    }
    fn start(context: *anyopaque, pin: []const u8, now: u64) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        self.attempts += 1;
        if (self.pending) return error.WorkerBusy;
        self.pending = true;
        self.cancelled = false;
        self.failure = if (!std.mem.eql(u8, pin, self.expected)) error.PinRejected else self.reject;
        self.expires_at = now + 100;
    }
    fn poll(context: *anyopaque, _: u64) !bool {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (!self.pending) return error.NoAuthenticationAttempt;
        if (self.polls_remaining != 0) {
            self.polls_remaining -= 1;
            return false;
        }
        self.pending = false;
        if (self.cancelled and !self.late_success) return error.Cancelled;
        if (self.failure) |err| return err;
        self.active = true;
        return true;
    }
    fn busy(context: *anyopaque) bool {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return self.pending;
    }
    fn deadline(context: *anyopaque) u64 {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return self.expires_at;
    }
};
