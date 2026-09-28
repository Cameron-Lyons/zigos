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

    pub fn authenticator(self: *Fixture) entry.Authenticator {
        return .{ .context = self, .lock_fn = lock, .unlock_fn = unlock, .deadline_fn = deadline };
    }
    fn lock(context: *anyopaque) void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        self.locks += 1;
        self.active = false;
        self.expires_at = 0;
    }
    fn unlock(context: *anyopaque, pin: []const u8, now: u64) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        self.attempts += 1;
        if (!std.mem.eql(u8, pin, self.expected)) return error.PinRejected;
        self.active = true;
        self.expires_at = now + 100;
        if (self.reject) |err| return err;
    }
    fn deadline(context: *anyopaque) u64 {
        const self: *Fixture = @ptrCast(@alignCast(context));
        return self.expires_at;
    }
};
