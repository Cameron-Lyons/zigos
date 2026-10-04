//! Exclusive native authentication input. Secrets never enter task inboxes,
//! surface snapshots, clipboard state, diagnostics, or the public view.
const std = @import("std");
const input = @import("../drivers/input_driver_task.zig");
const recovery = @import("recovery_key.zig");
const document_view = @import("trusted_document_view.zig");

pub const MAX_PIN_BYTES = 32;
pub const MIN_PIN_BYTES = 6;
pub const MAX_ENTRY_BYTES = @import("../services/identity_recovery_record.zig").CODE_BYTES;
pub const Method = enum { pin, recovery };
pub const Status = enum { hidden, entering, too_short, too_long, invalid_code, pending, verifying, cancelling, rejected, locked_out, unavailable };
pub const View = struct { review: @import("trusted_credential_review.zig").Review = .{}, documents: ?*document_view.View = null, status: Status = .hidden, characters: u8 = 0, method: Method = .pin, recovery_available: bool = false, recovery_characters: u8 = recovery.CODE_BYTES };

// Stable, exclusive service owner. Start copies/decodes the borrowed input; poll performs
// one bounded worker step. Cancellation retains all backing until busy is false.
pub const Authenticator = struct {
    context: *anyopaque,
    recovery_available: bool = false,
    recovery_characters: u8 = recovery.CODE_BYTES,
    lock_fn: *const fn (*anyopaque) void,
    start_fn: *const fn (*anyopaque, Method, []const u8, u64) anyerror!void,
    poll_fn: *const fn (*anyopaque, u64) anyerror!bool,
    busy_fn: *const fn (*anyopaque) bool,
    deadline_fn: *const fn (*anyopaque) u64,
};

test "trusted PIN entry bounds edits and erases success rejection and timeout" {
    var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{};
    var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 20 };
    entry.lock(1);
    entry.handle(.{ .kind = .text, .data = 'a' }, 2);
    entry.handle(.{ .kind = .paste }, 2);
    entry.handle(.{ .kind = .activate }, 2);
    try std.testing.expectEqual(Status.too_short, entry.view.status);
    try std.testing.expectEqual(@as(usize, 0), backend.attempts);
    for ("73019429") |byte| entry.handle(.{ .kind = .text, .data = byte }, 3);
    entry.handle(.{ .kind = .backspace }, 4);
    try std.testing.expectEqual(@as(u8, 0), entry.value[7]);
    entry.handle(.{ .kind = .text, .data = '8' }, 4);
    entry.handle(.{ .kind = .activate }, 5);
    try std.testing.expect(entry.prepareVerification(5));
    entry.verify(5);
    try std.testing.expect(backend.active and !entry.capturing());
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
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
        try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
        try std.testing.expectEqual(@as(u8, 0), entry.view.characters);
    }
    entry.lock(110);
    for (0..MAX_PIN_BYTES + 1) |_| entry.handle(.{ .kind = .text, .data = '7' }, 111);
    try std.testing.expectEqual(Status.too_long, entry.view.status);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.handle(.{ .kind = .activate }, 112);
    try std.testing.expect(!entry.prepareVerification(112));
    entry.handle(.{ .kind = .dismiss_recovery }, 112);
    try std.testing.expectEqual(Status.entering, entry.view.status);
    entry.handle(.{ .kind = .text, .data = '7' }, 113);
    try std.testing.expectEqual(@as(?u64, 133), entry.nextWake());
    entry.tick(133);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    try std.testing.expect(entry.nextWake() == null);
    entry.handle(.{ .kind = .text, .data = '7' }, 134);
    entry.tick(132);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
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
    value: [MAX_ENTRY_BYTES]u8 = @splat(0),
    pin_locked_out: bool = false,
    input_deadline: ?u64 = null,
    session_deadline: ?u64 = null,
    poll_deadline: ?u64 = null,
    last_ticks: u64 = 0,

    pub fn capturing(self: *const Entry) bool {
        return self.view.status != .hidden or self.view.review.visible() or (if (self.view.documents) |documents| documents.visible() else false);
    }

    pub fn lock(self: *Entry, now_ticks: u64) void {
        self.authenticator.lock_fn(self.authenticator.context);
        self.clearReview();
        if (self.view.documents) |documents| {
            documents.phase = .disabled;
            documents.pending = null;
            documents.touch();
        }
        self.erase();
        self.session_deadline = null;
        self.last_ticks = now_ticks;
        self.pin_locked_out = false;
        self.view.method = .pin;
        self.view.recovery_available = self.authenticator.recovery_available;
        self.view.recovery_characters = self.authenticator.recovery_characters;
        self.view.status = if (self.busy()) .cancelling else .entering;
        if (self.view.recovery_characters != recovery.CODE_BYTES and self.view.recovery_characters != MAX_ENTRY_BYTES)
            self.view.status = .unavailable;
        self.poll_deadline = if (self.busy()) now_ticks +| 1 else null;
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
        if (self.view.review.visible() and now_ticks >= self.view.review.expires_at and self.view.review.state != .denied) {
            self.view.review.state = .denied;
            self.revision +|= 1;
        }
        if (self.poll_deadline) |deadline| if (now_ticks >= deadline) self.poll(now_ticks);
        if (self.input_deadline) |deadline| if (now_ticks >= deadline) {
            self.erase();
            self.view.status = .entering;
            self.revision +|= 1;
        };
    }

    pub fn nextWake(self: *const Entry) ?u64 {
        const wake = self.poll_deadline orelse self.input_deadline orelse self.session_deadline;
        if (self.view.review.visible()) return @min(wake orelse self.view.review.expires_at, self.view.review.expires_at);
        return wake;
    }

    pub fn handle(self: *Entry, event: input.KeyboardEvent, now_ticks: u64) void {
        self.handlePhysical(event, now_ticks, 0);
    }

    pub fn desktopShortcut(self: *Entry, event: input.KeyboardEvent, now_ticks: u64, sequence: u64) bool {
        self.tick(now_ticks);
        if (self.capturing() or self.busy() or self.session_deadline == null) return false;
        const kind: document_view.Kind = switch (event.kind) {
            .new_document => .new,
            .open_document => .open,
            else => return false,
        };
        const documents = self.view.documents orelse return false;
        if (!documents.shortcut(kind, sequence)) return false;
        self.revision +|= 1;
        return true;
    }

    pub fn handlePhysical(self: *Entry, event: input.KeyboardEvent, now_ticks: u64, sequence: u64) void {
        self.tick(now_ticks);
        if (!self.capturing()) return;
        if (self.view.review.visible()) {
            if (self.view.review.handle(event)) self.revision +|= 1;
            return;
        }
        if (self.view.status == .hidden) if (self.view.documents) |documents| {
            if (documents.handle(event, sequence)) self.revision +|= 1;
            return;
        };
        // Ctrl+R is private to this prompt. Mode changes erase partial input
        // and advance the router's neutral-report barrier. A running or already
        // submitted attempt must be cancelled before selecting another method.
        if (event.kind == .show_recovery) {
            if (self.view.recovery_characters != recovery.CODE_BYTES and self.view.recovery_characters != MAX_ENTRY_BYTES) return;
            if (!self.authenticator.recovery_available or self.busy() or self.view.status == .pending or self.view.status == .verifying or self.view.status == .cancelling) return;
            self.erase();
            self.view.method = if (self.view.method == .pin) .recovery else .pin;
            self.view.status = if (self.view.method == .pin and self.pin_locked_out) .locked_out else .entering;
            self.revision +|= 1;
            return;
        }
        if (event.kind == .dismiss_recovery) {
            if (self.view.status == .verifying or self.view.status == .pending or self.view.status == .cancelling) {
                self.lock(now_ticks);
                return;
            }
            self.erase();
            if (self.view.status != .locked_out and self.view.status != .unavailable) self.view.status = .entering;
            return;
        }
        switch (self.view.status) {
            .entering, .too_short, .invalid_code, .rejected => {},
            else => return,
        }
        switch (event.kind) {
            .text => {
                var byte = event.data;
                if (self.view.method == .pin) {
                    if (byte < '0' or byte > '9') return;
                } else {
                    if (byte == '-' or byte == ' ') return;
                    byte = std.ascii.toUpper(byte);
                    if (recovery.symbol(byte) == null) return;
                }
                const limit: usize = if (self.view.method == .pin) MAX_PIN_BYTES else self.view.recovery_characters;
                if (self.view.characters == limit) {
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
                self.value[self.view.characters] = byte;
                self.view.characters += 1;
                self.input_deadline = deadline;
                self.view.status = .entering;
            },
            .backspace => {
                if (self.view.characters != 0) {
                    self.view.characters -= 1;
                    std.crypto.secureZero(u8, self.value[self.view.characters..][0..1]);
                }
                if (self.view.characters == 0) self.input_deadline = null;
                self.view.status = .entering;
            },
            .activate => {
                const minimum: usize = if (self.view.method == .pin) MIN_PIN_BYTES else self.view.recovery_characters;
                self.view.status = if (self.view.characters < minimum) .too_short else .pending;
            },
            // No paste, task switch, focus navigation, or global recovery
            // command is forwarded while the trusted prompt owns input.
            else => {},
        }
    }

    // Present the busy state before submitting to the worker. The input secret is
    // erased before the first worker step, and no hardware wait blocks routing.
    pub fn prepareVerification(self: *Entry, now_ticks: u64) bool {
        self.tick(now_ticks);
        if (self.view.status != .pending) return false;
        self.view.status = .verifying;
        self.input_deadline = null;
        return true;
    }

    pub fn verify(self: *Entry, now_ticks: u64) void {
        if (self.view.status != .verifying or self.poll_deadline != null) return;
        self.authenticator.start_fn(self.authenticator.context, self.view.method, self.value[0..self.view.characters], now_ticks) catch |err| {
            self.erase();
            self.failed(err, now_ticks);
            return;
        };
        self.erase();
        self.poll_deadline = now_ticks;
        self.poll(now_ticks);
    }

    pub fn beginReview(self: *Entry, application: []const u8, rp: []const u8, origin: []const u8, expires_at: u64, now: u64) !void {
        self.tick(now);
        if (self.capturing() or self.busy() or self.session_deadline == null or
            expires_at <= now or expires_at > self.session_deadline.?) return error.IdentityUnavailable;
        self.view.review = try @import("trusted_credential_review.zig").Review.init(application, rp, origin, expires_at);
        self.revision +|= 1;
    }

    pub fn clearReview(self: *Entry) void {
        if (!self.view.review.visible()) return;
        self.view.review = .{};
        self.revision +|= 1;
    }

    pub fn busy(self: *const Entry) bool {
        return self.authenticator.busy_fn(self.authenticator.context);
    }

    // Exclusive teardown only. Normal lock/Escape is nonblocking. Owners can
    // cancel and service ticks before detaching to avoid waiting here. Never
    // release a backing store while a suspended protocol still borrows it.
    pub fn quiesce(self: *Entry) void {
        self.lock(self.last_ticks);
        while (self.busy()) self.poll(self.last_ticks);
    }

    fn failed(self: *Entry, err: anyerror, now_ticks: u64) void {
        const was_verifying = self.view.status == .verifying;
        self.authenticator.lock_fn(self.authenticator.context);
        self.poll_deadline = if (self.busy()) now_ticks +| 1 else null;
        if (was_verifying) self.view.status = switch (err) {
            error.PinRejected, error.RecoveryAuthenticationFailed, error.RecoveryEnrollmentChanged => .rejected,
            error.InvalidRecoveryCode => .invalid_code,
            error.PinLockedOut => .locked_out,
            error.Cancelled => .entering,
            else => .unavailable,
        } else if (self.view.status == .cancelling and !self.busy()) self.view.status = .entering;
        if (self.view.method == .pin and err == error.PinLockedOut) self.pin_locked_out = true;
        self.revision +|= 1;
    }

    fn poll(self: *Entry, now_ticks: u64) void {
        const complete = self.authenticator.poll_fn(self.authenticator.context, now_ticks) catch |err| {
            self.failed(err, now_ticks);
            return;
        };
        if (!complete) {
            self.poll_deadline = now_ticks +| 1;
            return;
        }
        self.poll_deadline = null;
        if (self.view.status != .verifying) {
            self.authenticator.lock_fn(self.authenticator.context);
            if (self.view.status == .cancelling) self.view.status = .entering;
            self.revision +|= 1;
            return;
        }
        const deadline = self.authenticator.deadline_fn(self.authenticator.context);
        if (deadline <= now_ticks) {
            self.inputInterrupted(now_ticks);
            return;
        }
        self.session_deadline = deadline;
        self.pin_locked_out = false;
        self.last_ticks = now_ticks;
        self.view.status = .hidden;
        self.revision +|= 1;
    }

    fn erase(self: *Entry) void {
        std.crypto.secureZero(u8, &self.value);
        self.view.characters = 0;
        self.input_deadline = null;
    }

    comptime {
        // Includes bounded consent text and one pointer to the lazy native
        // document view; only one entry exists per account owner.
        if (@sizeOf(@This()) > 520) @compileError("trusted authentication entry exceeds bounded state");
    }
};

test "trusted credential consent cancels at deadline lock interruption and clock rollback" {
    for (0..5) |variant| {
        var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{ .active = true, .expires_at = 100 };
        var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 20, .session_deadline = 100 };
        try entry.beginReview("app.notes", "example.test", "https://example.test", 30, 10);
        try std.testing.expectEqual(@as(?u64, 30), entry.nextWake());
        entry.view.review.presented = true;
        entry.handle(.{ .kind = .focus_next }, 11);
        entry.view.review.presented = true;
        entry.handle(.{ .kind = .activate }, 12);
        try std.testing.expect(entry.view.review.state == .approved and entry.capturing());
        switch (variant) {
            0 => entry.tick(30),
            1 => entry.lock(13),
            2 => entry.inputInterrupted(13),
            3 => entry.tick(9),
            4 => {
                backend.expires_at = 0;
                entry.tick(13);
            },
            else => unreachable,
        }
        try std.testing.expect(entry.view.review.state != .approved);
        entry.clearReview();
        try std.testing.expect(std.mem.allEqual(u8, &entry.view.review.application, 0));
        try std.testing.expectEqual(@as(usize, 0), backend.attempts);
    }
}

test "trusted recovery rejects unsupported input lengths across mode changes" {
    var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{};
    for ([_]u8{ 0, 55, 57, 127, 129, 255 }) |length| {
        var auth = backend.authenticator();
        auth.recovery_available = true;
        auth.recovery_characters = length;
        var entry = Entry{ .authenticator = auth, .input_timeout_ticks = 20 };
        entry.lock(1);
        entry.handle(.{ .kind = .show_recovery }, 2);
        for (0..256) |_| entry.handle(.{ .kind = .text, .data = '1' }, 2);
        entry.handle(.{ .kind = .activate }, 2);
        entry.handle(.{ .kind = .dismiss_recovery }, 2);
        try std.testing.expect(entry.view.status == .unavailable and entry.view.characters == 0);
        try std.testing.expect(!entry.prepareVerification(2));
        try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    }
    try std.testing.expectEqual(@as(usize, 0), backend.attempts);
}

test "trusted PIN worker keeps input private across cancellation late replies and teardown" {
    var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{ .polls_remaining = 3 };
    var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 2 };
    entry.lock(1);
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 2);
    entry.handle(.{ .kind = .activate }, 2);
    try std.testing.expect(entry.prepareVerification(2));
    entry.verify(2);
    try std.testing.expect(entry.busy() and entry.view.status == .verifying);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    try std.testing.expectEqual(@as(?u64, 3), entry.nextWake());
    entry.tick(4); // The edit timeout must not cancel submitted work.
    try std.testing.expect(entry.view.status == .verifying and !backend.cancelled);
    entry.handle(.{ .kind = .dismiss_recovery }, 4);
    try std.testing.expect(entry.view.status == .cancelling and backend.cancelled);
    backend.late_success = true; // Even an invalid late success cannot unlock.
    entry.handle(.{ .kind = .text, .data = '7' }, 4);
    try std.testing.expectEqual(@as(u8, 0), entry.view.characters);
    entry.tick(5);
    entry.tick(6);
    try std.testing.expect(!entry.busy() and !backend.active and entry.capturing());
    try std.testing.expectEqual(Status.entering, entry.view.status);
    backend.late_success = false;
    backend.polls_remaining = 2;
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 7);
    entry.handle(.{ .kind = .activate }, 7);
    try std.testing.expect(entry.prepareVerification(7));
    entry.verify(7);
    entry.tick(6); // A reversed clock cancels without abandoning the worker.
    try std.testing.expect(entry.busy() and backend.cancelled);
    entry.quiesce();
    try std.testing.expect(!entry.busy() and !backend.active);
    try std.testing.expect(entry.nextWake() == null);
    backend.polls_remaining = 1;
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 8);
    entry.handle(.{ .kind = .activate }, 8);
    try std.testing.expect(entry.prepareVerification(8));
    entry.verify(8);
    entry.tick(108); // Completion after its lease expired stays locked.
    try std.testing.expect(!entry.busy() and !backend.active and entry.capturing());
}

test "trusted recovery entry normalizes grouped codes and isolates modes lockout and cancellation" {
    const key: recovery.Key = @splat(7);
    var code: [recovery.CODE_BYTES]u8 = undefined;
    try recovery.encode(&key, &code);
    var grouped: [recovery.DISPLAY_BYTES]u8 = undefined;
    try recovery.format(&key, &grouped);
    var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{ .expected = &code, .expected_method = .recovery, .recovery_available = true };
    var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 20 };
    entry.lock(1);
    entry.handle(.{ .kind = .text, .data = '7' }, 1);
    entry.handle(.{ .kind = .show_recovery }, 1);
    try std.testing.expect(entry.view.method == .recovery and entry.view.recovery_available);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.handle(.{ .kind = .activate }, 2);
    try std.testing.expect(entry.view.status == .too_short and backend.attempts == 0);
    for (grouped) |byte| entry.handle(.{ .kind = .text, .data = std.ascii.toLower(byte) }, 2);
    try std.testing.expectEqualSlices(u8, &code, entry.value[0..code.len]);
    entry.handle(.{ .kind = .text, .data = '7' }, 2);
    try std.testing.expect(entry.view.status == .too_long);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.handle(.{ .kind = .dismiss_recovery }, 3);
    for ([_]?anyerror{ error.InvalidRecoveryCode, error.RecoveryAuthenticationFailed, null }) |failure| {
        backend.reject = failure;
        for (grouped) |byte| entry.handle(.{ .kind = .text, .data = std.ascii.toLower(byte) }, 3);
        entry.handle(.{ .kind = .activate }, 3);
        entry.handle(.{ .kind = .show_recovery }, 3); // Submitted input cannot change methods.
        try std.testing.expect(entry.view.method == .recovery);
        try std.testing.expect(entry.prepareVerification(3));
        entry.verify(3);
        try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
        try std.testing.expectEqual(if (failure != null and failure.? == error.InvalidRecoveryCode) Status.invalid_code else if (failure != null) Status.rejected else Status.hidden, entry.view.status);
    }
    entry.lock(4);
    backend.reject = error.PinLockedOut;
    backend.expected_method = .pin;
    backend.expected = "73019428";
    for (backend.expected) |byte| entry.handle(.{ .kind = .text, .data = byte }, 4);
    entry.handle(.{ .kind = .activate }, 4);
    try std.testing.expect(entry.prepareVerification(4));
    entry.verify(4);
    try std.testing.expect(entry.view.status == .locked_out);
    entry.handle(.{ .kind = .show_recovery }, 4);
    try std.testing.expect(entry.view.method == .recovery and entry.view.status == .entering);
    entry.handle(.{ .kind = .text, .data = 'A' }, 4);
    entry.handle(.{ .kind = .show_recovery }, 4);
    try std.testing.expect(entry.view.method == .pin and entry.view.status == .locked_out);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.handle(.{ .kind = .show_recovery }, 4);
    backend.expected_method = .recovery;
    backend.expected = &code;
    backend.reject = null;
    backend.polls_remaining = 2;
    for (code) |byte| entry.handle(.{ .kind = .text, .data = byte }, 5);
    entry.handle(.{ .kind = .activate }, 5);
    try std.testing.expect(entry.prepareVerification(5));
    entry.verify(5);
    entry.handle(.{ .kind = .show_recovery }, 5);
    try std.testing.expect(entry.view.method == .recovery and entry.busy());
    entry.handle(.{ .kind = .dismiss_recovery }, 5);
    entry.quiesce();
    try std.testing.expect(!backend.active and !entry.busy() and entry.view.method == .pin);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.handle(.{ .kind = .show_recovery }, 6);
    entry.handle(.{ .kind = .text, .data = 'A' }, 6);
    entry.tick(26);
    try std.testing.expect(entry.view.method == .recovery and entry.view.characters == 0);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0));
    entry.authenticator.recovery_available = false;
    entry.lock(27);
    entry.handle(.{ .kind = .show_recovery }, 27);
    try std.testing.expect(entry.view.method == .pin and !entry.view.recovery_available);
}

test "document shortcuts fail closed for locked inactive expired and synthetic native input" {
    var backend = @import("../../tests/fixtures/authenticator.zig").Fixture{};
    var documents = document_view.View{ .phase = .home, .token = 3 };
    var entry = Entry{ .authenticator = backend.authenticator(), .input_timeout_ticks = 50 };
    entry.view.documents = &documents;
    entry.lock(1);
    documents.phase = .home;
    documents.presented(40, 20, true);
    try std.testing.expect(!entry.desktopShortcut(.{ .kind = .new_document }, 2, 1));
    entry.view.status = .hidden;
    try std.testing.expect(!entry.desktopShortcut(.{ .kind = .open_document }, 2, 2));
    backend.active = true;
    backend.expires_at = 50;
    entry.session_deadline = 50;
    try std.testing.expect(!entry.desktopShortcut(.{ .kind = .new_document }, 2, 0));
    try std.testing.expect(documents.pending == null);
    try std.testing.expect(entry.desktopShortcut(.{ .kind = .new_document }, 2, 3));
    _ = documents.take();
    documents.phase = .review;
    documents.path = try document_view.Label.init("notes/private.md");
    documents.allow_selected = true;
    documents.touch();
    documents.presented(40, 20, true);
    entry.handle(.{ .kind = .activate }, 2);
    try std.testing.expect(documents.pending == null);
    entry.handlePhysical(.{ .kind = .activate }, 50, 4);
    try std.testing.expect(documents.phase == .disabled and documents.pending == null and !backend.active);
    backend.active = true;
    backend.expires_at = 60;
    entry.session_deadline = 60;
    entry.view.status = .hidden;
    documents.phase = .home;
    documents.presented(40, 20, true);
    backend.active = false;
    backend.expires_at = 0;
    try std.testing.expect(!entry.desktopShortcut(.{ .kind = .new_document }, 51, 5));
    try std.testing.expect(documents.phase == .disabled and documents.pending == null);
}
