const std = @import("std");

pub const Error = error{ InvalidUnlockContext, UnlockContextUnavailable, UnlockContextMismatch };

pub const Binding = struct {
    boot_instance: [16]u8 = @splat(0),
    session_nonce: [16]u8 = @splat(0),

    pub fn valid(self: Binding) bool {
        return !std.mem.allEqual(u8, &self.boot_instance, 0) and !std.mem.allEqual(u8, &self.session_nonce, 0);
    }
};

// Stable, service-owned replay domain. Creating one does not authenticate a
// user. Trusted session teardown/lock invalidates it; restarting requires fresh
// CSPRNG output and the current boot's public instance ID. Never checkpoint it.
pub const Session = struct {
    current: Binding = .{},
    active: bool = false,

    pub fn begin(self: *Session, boot_instance: [16]u8, random: anytype) !void {
        self.lock();
        var next = Binding{ .boot_instance = boot_instance };
        if (std.mem.allEqual(u8, &boot_instance, 0)) return error.InvalidUnlockContext;
        try random.random(&next.session_nonce);
        if (!next.valid() or std.mem.eql(u8, &next.session_nonce, &self.current.session_nonce)) return error.InvalidUnlockContext;
        self.current = next;
        self.active = true;
    }

    pub fn lock(self: *Session) void {
        self.active = false;
    }

    pub fn binding(self: *const Session) Error!Binding {
        if (!self.active or !self.current.valid()) return error.UnlockContextUnavailable;
        return self.current;
    }

    pub fn require(self: *const Session, supplied: Binding) Error!void {
        const expected = try self.binding();
        if (!std.mem.eql(u8, &supplied.boot_instance, &expected.boot_instance) or
            !std.mem.eql(u8, &supplied.session_nonce, &expected.session_nonce)) return error.UnlockContextMismatch;
    }
};

comptime {
    if (@sizeOf(Session) > 40) @compileError("unlock replay domain exceeds bounded service state");
}

test "unlock context invalidates old bindings on lock restart and entropy failure" {
    const Random = struct {
        byte: u8 = 1,
        fail: bool = false,
        pub fn random(self: *@This(), out: []u8) !void {
            @memset(out, self.byte);
            if (self.fail) return error.EntropyUnavailable;
        }
    };
    var entropy = Random{};
    var session = Session{};
    try std.testing.expectError(error.UnlockContextUnavailable, session.binding());
    try session.begin(@splat(2), &entropy);
    const first = try session.binding();
    try session.require(first);
    session.lock();
    try std.testing.expectError(error.UnlockContextUnavailable, session.require(first));
    try std.testing.expectError(error.InvalidUnlockContext, session.begin(@splat(2), &entropy));
    entropy.byte = 3;
    try session.begin(@splat(2), &entropy);
    try std.testing.expectError(error.UnlockContextMismatch, session.require(first));
    entropy.fail = true;
    try std.testing.expectError(error.EntropyUnavailable, session.begin(@splat(2), &entropy));
    try std.testing.expectError(error.UnlockContextUnavailable, session.binding());
    entropy.fail = false;
    entropy.byte = 0;
    try std.testing.expectError(error.InvalidUnlockContext, session.begin(@splat(2), &entropy));
    try std.testing.expectError(error.InvalidUnlockContext, session.begin(@splat(0), &entropy));
}
