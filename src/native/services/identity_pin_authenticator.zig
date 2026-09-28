//! Stable bridge between native trusted input and the TPM session owner.
const entry = @import("../platform/trusted_pin_entry.zig");
const identity_session = @import("identity_session.zig");
const pin = @import("../platform/tpm2_pin.zig");
const catalog = @import("../storage/vault_catalog.zig");

pub fn Adapter(comptime Io: type) type {
    return struct {
        const Self = @This();
        session: *identity_session.Session(Io),
        capsule: *const pin.Capsule,
        boot_instance: [16]u8,
        lifetime_ticks: u64,
        scratch: *[catalog.MAX_BYTES]u8,

        pub fn authenticator(self: *Self) entry.Authenticator {
            return .{ .context = self, .lock_fn = lock, .unlock_fn = unlock, .deadline_fn = deadline };
        }

        fn lock(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.session.lock();
        }

        fn unlock(context: *anyopaque, value: []const u8, now_ticks: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.session.unlock(self.capsule, value, self.boot_instance, now_ticks, self.lifetime_ticks, self.scratch);
        }

        fn deadline(context: *anyopaque) u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.session.expires_at_ticks;
        }
    };
}
