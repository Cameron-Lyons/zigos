//! Exclusive native authentication input. PIN bytes never enter task inboxes,
//! surface snapshots, clipboard state, diagnostics, or the public view.
const std = @import("std");
const input = @import("../drivers/input_driver_task.zig");

pub const MAX_PIN_BYTES = 32;
pub const MIN_PIN_BYTES = 6;
pub const Status = enum { hidden, entering, too_short, too_long, pending, verifying, rejected, locked_out, unavailable };
pub const View = struct { status: Status = .hidden, digits: u8 = 0 };

// Stable, exclusive service owner. Unlock consumes the borrowed PIN within the
// call and activates only after all authentication/recovery checks succeed.
pub const Authenticator = struct {
    context: *anyopaque,
    lock_fn: *const fn (*anyopaque) void,
    unlock_fn: *const fn (*anyopaque, []const u8, u64) anyerror!void,
    deadline_fn: *const fn (*anyopaque) u64,
};

test "trusted PIN entry bounds edits and erases success rejection and timeout" {
    var backend = @import("../../tests/fixtures/pin_authenticator.zig").Fixture{};
    var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 20 };
    entry.lock(1);
    entry.handle(.{ .kind = .text, .data = 'a' }, 2);
    entry.handle(.{ .kind = .paste }, 2);
    entry.handle(.{ .kind = .activate }, 2);
    try std.testing.expectEqual(Status.too_short, entry.view.status);
    try std.testing.expectEqual(@as(usize, 0), backend.attempts);
    for ("73019429") |byte| entry.handle(.{ .kind = .text, .data = byte }, 3);
    entry.handle(.{ .kind = .backspace }, 4);
    try std.testing.expectEqual(@as(u8, 0), entry.pin[7]);
    entry.handle(.{ .kind = .text, .data = '8' }, 4);
    entry.handle(.{ .kind = .activate }, 5);
    try std.testing.expect(entry.prepareVerification(5));
    entry.verify(5);
    try std.testing.expect(backend.active and !entry.capturing());
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
    try std.testing.expectEqual(@as(?u64, 105), entry.nextWake());
    entry.tick(105);
    try std.testing.expect(entry.capturing() and !backend.active);
    for ([_]?anyerror{ error.PinRejected, error.PinLockedOut, error.HardwareUnavailable }) |failure| {
        entry.lock(106);
        backend.reject = failure;
        for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 107);
        entry.handle(.{ .kind = .activate }, 108);
        try std.testing.expect(entry.prepareVerification(108));
        entry.verify(108);
        try std.testing.expect(entry.capturing() and !backend.active);
        try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
        try std.testing.expectEqual(@as(u8, 0), entry.view.digits);
    }
    entry.lock(110);
    for (0..MAX_PIN_BYTES + 1) |_| entry.handle(.{ .kind = .text, .data = '7' }, 111);
    try std.testing.expectEqual(Status.too_long, entry.view.status);
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
    entry.handle(.{ .kind = .activate }, 112);
    try std.testing.expect(!entry.prepareVerification(112));
    entry.handle(.{ .kind = .dismiss_recovery }, 112);
    try std.testing.expectEqual(Status.entering, entry.view.status);
    entry.handle(.{ .kind = .text, .data = '7' }, 113);
    try std.testing.expectEqual(@as(?u64, 133), entry.nextWake());
    entry.tick(133);
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
    try std.testing.expect(entry.nextWake() == null);
    entry.handle(.{ .kind = .text, .data = '7' }, 134);
    entry.tick(132);
    try std.testing.expect(std.mem.allEqual(u8, &entry.pin, 0));
    backend.reject = null;
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 140);
    entry.handle(.{ .kind = .activate }, 140);
    try std.testing.expect(entry.prepareVerification(140));
    entry.verify(140);
    try std.testing.expect(!entry.capturing());
    backend.expires_at = 0; // The owner revoked the session outside input handling.
    backend.active = false;
    entry.tick(141);
    try std.testing.expect(entry.capturing());
    try std.testing.expect(entry.nextWake() == null);
}

pub const Entry = struct {
    authenticator: Authenticator,
    input_timeout_ticks: u64,
    view: View = .{},
    revision: u64 = 1,
    pin: [MAX_PIN_BYTES]u8 = @splat(0),
    input_deadline: ?u64 = null,
    session_deadline: ?u64 = null,
    last_ticks: u64 = 0,

    pub fn capturing(self: *const Entry) bool {
        return self.view.status != .hidden;
    }

    pub fn lock(self: *Entry, now_ticks: u64) void {
        self.authenticator.lock_fn(self.authenticator.context);
        self.erase();
        self.session_deadline = null;
        self.last_ticks = now_ticks;
        self.view.status = .entering;
        self.revision +|= 1;
    }

    pub fn inputInterrupted(self: *Entry, now_ticks: u64) void {
        self.lock(now_ticks);
        self.view.status = .unavailable;
    }

    pub fn tick(self: *Entry, now_ticks: u64) void {
        if (now_ticks < self.last_ticks or (if (self.session_deadline) |deadline| now_ticks >= deadline or self.authenticator.deadline_fn(self.authenticator.context) == 0 else false)) {
            self.lock(now_ticks);
            return;
        }
        self.last_ticks = now_ticks;
        if (self.input_deadline) |deadline| if (now_ticks >= deadline) {
            self.erase();
            self.view.status = .entering;
            self.revision +|= 1;
        };
    }

    pub fn nextWake(self: *const Entry) ?u64 {
        return self.input_deadline orelse self.session_deadline;
    }

    pub fn handle(self: *Entry, event: input.KeyboardEvent, now_ticks: u64) void {
        self.tick(now_ticks);
        if (!self.capturing()) return;
        if (event.kind == .dismiss_recovery) {
            self.erase();
            if (self.view.status != .locked_out and self.view.status != .unavailable) self.view.status = .entering;
            return;
        }
        switch (self.view.status) {
            .entering, .too_short, .rejected => {},
            else => return,
        }
        switch (event.kind) {
            .text => {
                if (event.data < '0' or event.data > '9') return;
                if (self.view.digits == self.pin.len) {
                    self.erase();
                    self.view.status = .too_long;
                    return;
                }
                const deadline = std.math.add(u64, now_ticks, self.input_timeout_ticks) catch {
                    self.inputInterrupted(now_ticks);
                    return;
                };
                if (self.input_timeout_ticks == 0) {
                    self.inputInterrupted(now_ticks);
                    return;
                }
                self.pin[self.view.digits] = event.data;
                self.view.digits += 1;
                self.input_deadline = deadline;
                self.view.status = .entering;
            },
            .backspace => {
                if (self.view.digits != 0) {
                    self.view.digits -= 1;
                    std.crypto.secureZero(u8, self.pin[self.view.digits..][0..1]);
                }
                if (self.view.digits == 0) self.input_deadline = null;
                self.view.status = .entering;
            },
            .activate => {
                self.view.status = if (self.view.digits < MIN_PIN_BYTES) .too_short else .pending;
            },
            // No paste, task switch, focus navigation, or global recovery
            // command is forwarded while the trusted prompt owns input.
            else => {},
        }
    }

    // The native owner presents this busy state before calling verify, which
    // may perform slow hardware I/O. Input routing never calls the verifier.
    pub fn prepareVerification(self: *Entry, now_ticks: u64) bool {
        self.tick(now_ticks);
        if (self.view.status != .pending) return false;
        self.view.status = .verifying;
        return true;
    }

    pub fn verify(self: *Entry, now_ticks: u64) void {
        self.tick(now_ticks);
        if (self.view.status != .verifying) return;
        defer self.erase();
        defer self.revision +|= 1;
        self.authenticator.unlock_fn(self.authenticator.context, self.pin[0..self.view.digits], now_ticks) catch |err| {
            self.authenticator.lock_fn(self.authenticator.context);
            self.view.status = switch (err) {
                error.PinRejected => .rejected,
                error.PinLockedOut => .locked_out,
                else => .unavailable,
            };
            return;
        };
        const deadline = self.authenticator.deadline_fn(self.authenticator.context);
        if (deadline <= now_ticks) {
            self.inputInterrupted(now_ticks);
            return;
        }
        self.session_deadline = deadline;
        self.last_ticks = now_ticks;
        self.view.status = .hidden;
    }

    fn erase(self: *Entry) void {
        std.crypto.secureZero(u8, &self.pin);
        self.view.digits = 0;
        self.input_deadline = null;
    }

    comptime {
        if (@sizeOf(@This()) > 128) @compileError("trusted PIN entry exceeds bounded state");
    }
};
