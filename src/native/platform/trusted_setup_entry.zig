//! Native first-user interaction. App tasks receive neither these keystrokes
//! nor the recovery record. Keep the owner alive through cancellation cleanup.
const std = @import("std");
const input = @import("../drivers/input_driver_task.zig");
const pin = @import("tpm2_pin.zig");
const recovery = @import("../services/identity_recovery_record.zig");
const enrollment = @import("../services/identity_enrollment.zig");

pub const Status = enum { choose_pin, confirm_pin, preparing, record_recovery, confirm_recovery, committing, cancelling, resume_setup, complete, unavailable };
pub const Notice = enum { none, too_short, too_long, mismatch, invalid_record, failed, timeout, interrupted };
pub const View = struct {
    status: Status = .choose_pin,
    notice: Notice = .none,
    characters: u8 = 0,
    // Populated only while the native export view is deliberately visible.
    recovery_code: [recovery.DISPLAY_BYTES]u8 = @splat(0),
};
pub const Result = struct {
    kind: enum { pending, prepared, committed } = .pending,
    recovery_record: recovery.Record = .{},
    identity: ?enrollment.Record = null,
    pub fn erase(self: *Result) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};
pub const Backend = struct {
    context: *anyopaque,
    start_prepare: *const fn (*anyopaque, []const u8, u64) anyerror!void,
    start_commit: *const fn (*anyopaque, *const recovery.Record, u64) anyerror!void,
    poll: *const fn (*anyopaque, u64) anyerror!Result,
    cancel: *const fn (*anyopaque) void,
    busy: *const fn (*anyopaque) bool,
};
const Operation = enum { prepare, commit };

pub const Entry = struct {
    backend: Backend,
    input_timeout_ticks: u64,
    view: View = .{},
    revision: u64 = 1,
    last_ticks: u64 = 0,
    value: [recovery.CODE_BYTES]u8 = @splat(0),
    first_pin: [32]u8 = @splat(0),
    pin_len: u8 = 0,
    recovery_record: recovery.Record = .{},
    identity: ?enrollment.Record = null,
    pending: ?Operation = null,
    poll_deadline: ?u64 = null,
    input_deadline: ?u64 = null,
    committing: bool = false,

    pub fn capturing(_: *const Entry) bool {
        return true;
    }
    pub fn busy(self: *const Entry) bool {
        return self.backend.busy(self.backend.context);
    }
    pub fn nextWake(self: *const Entry) ?u64 {
        return self.poll_deadline orelse self.input_deadline;
    }

    pub fn lock(self: *Entry, now: u64) void {
        self.backend.cancel(self.backend.context);
        self.erase();
        self.pending = null;
        self.identity = null;
        self.last_ticks = now;
        self.poll_deadline = if (self.busy()) now +| 1 else null;
        self.transition(if (self.busy()) .cancelling else if (self.committing) .resume_setup else .choose_pin, .none);
    }

    pub fn inputInterrupted(self: *Entry, now: u64) void {
        self.lock(now);
        self.view.notice = .interrupted;
    }

    pub fn quiesce(self: *Entry) void {
        self.lock(self.last_ticks);
        while (self.busy()) self.poll(self.last_ticks);
        self.erase();
    }

    pub fn tick(self: *Entry, now: u64) void {
        if (now < self.last_ticks) {
            self.inputInterrupted(now);
            return;
        }
        self.last_ticks = now;
        if (self.poll_deadline) |deadline| if (now >= deadline) self.poll(now);
        if (self.input_deadline) |deadline| if (now >= deadline) {
            self.lock(now);
            self.view.notice = .timeout;
        };
    }

    pub fn handle(self: *Entry, event: input.KeyboardEvent, now: u64) void {
        self.tick(now);
        if (event.kind == .dismiss_recovery) {
            self.lock(now);
            return;
        }
        if (self.busy() or self.pending != null) return;
        if (event.kind == .show_recovery and self.view.status != .complete) {
            self.erase();
            self.transition(.resume_setup, .none);
            return;
        }
        if (self.view.status == .record_recovery) {
            if (event.kind == .activate) {
                std.crypto.secureZero(u8, &self.view.recovery_code);
                self.transition(.confirm_recovery, .none);
                self.armTimeout(now);
            }
            return;
        }
        const is_pin = self.view.status == .choose_pin or self.view.status == .confirm_pin;
        if (!is_pin and self.view.status != .confirm_recovery and self.view.status != .resume_setup) return;
        switch (event.kind) {
            .text => {
                var byte = event.data;
                if (is_pin) {
                    if (byte < '0' or byte > '9') return;
                } else {
                    if (byte == '-' or byte == ' ') return;
                    byte = std.ascii.toUpper(byte);
                    if (recovery.symbol(byte) == null) return;
                }
                const limit: usize = if (is_pin) 32 else recovery.CODE_BYTES;
                if (self.view.characters == limit) {
                    self.eraseInput();
                    self.view.notice = .too_long;
                    return;
                }
                self.value[self.view.characters] = byte;
                self.view.characters += 1;
                self.view.notice = .none;
                self.armTimeout(now);
            },
            .backspace => {
                if (self.view.characters != 0) {
                    self.view.characters -= 1;
                    self.value[self.view.characters] = 0;
                }
                self.view.notice = .none;
            },
            .activate => self.submit(now),
            else => {}, // No paste, task navigation or app shortcuts.
        }
    }

    fn submit(self: *Entry, now: u64) void {
        const value = self.value[0..self.view.characters];
        switch (self.view.status) {
            .choose_pin => {
                pin.validatePin(value) catch {
                    self.view.notice = .too_short;
                    return;
                };
                @memcpy(self.first_pin[0..value.len], value);
                self.pin_len = @intCast(value.len);
                self.eraseInput();
                self.transition(.confirm_pin, .none);
                self.armTimeout(now);
            },
            .confirm_pin => {
                if (value.len != self.pin_len or !std.crypto.timing_safe.eql([32]u8, self.value[0..32].*, self.first_pin)) {
                    self.erase();
                    self.transition(.choose_pin, .mismatch);
                    return;
                }
                self.eraseInput();
                self.pending = .prepare;
                self.input_deadline = null;
                self.transition(.preparing, .none);
            },
            .confirm_recovery, .resume_setup => {
                var record = recovery.Record{};
                defer record.erase();
                recovery.Record.decode(value, &record) catch {
                    self.eraseInput();
                    self.view.notice = .invalid_record;
                    return;
                };
                if (self.view.status == .confirm_recovery) {
                    var expected: [recovery.CODE_BYTES]u8 = undefined;
                    defer std.crypto.secureZero(u8, &expected);
                    self.recovery_record.encode(&expected) catch {
                        self.failed(error.InvalidRecoveryRecord, now);
                        return;
                    };
                    if (!std.crypto.timing_safe.eql([recovery.CODE_BYTES]u8, self.value, expected)) {
                        self.eraseInput();
                        self.view.notice = .mismatch;
                        return;
                    }
                }
                self.recovery_record = record;
                self.eraseInput();
                self.pending = .commit;
                self.input_deadline = null;
                self.transition(.committing, .none);
            },
            else => {},
        }
    }

    pub fn prepareWork(self: *Entry, now: u64) bool {
        self.tick(now);
        return self.pending != null and !self.busy();
    }

    pub fn runWork(self: *Entry, now: u64) void {
        const operation = self.pending orelse return;
        self.pending = null;
        defer self.erase();
        switch (operation) {
            .prepare => self.backend.start_prepare(self.backend.context, self.first_pin[0..self.pin_len], now) catch |err| {
                self.failed(err, now);
                return;
            },
            .commit => {
                self.committing = true;
                self.backend.start_commit(self.backend.context, &self.recovery_record, now) catch |err| {
                    self.failed(err, now);
                    return;
                };
            },
        }
        self.poll_deadline = now;
        // Input is erased before the worker takes its first step.
    }

    fn poll(self: *Entry, now: u64) void {
        var result = self.backend.poll(self.backend.context, now) catch |err| {
            self.failed(err, now);
            return;
        };
        defer result.erase();
        if (result.kind == .pending) {
            self.poll_deadline = now +| 1;
            return;
        }
        self.poll_deadline = null;
        switch (result.kind) {
            .prepared => {
                if (self.view.status != .preparing) {
                    self.lock(now);
                    return;
                }
                self.recovery_record = result.recovery_record;
                self.recovery_record.format(&self.view.recovery_code) catch |err| {
                    self.failed(err, now);
                    return;
                };
                self.transition(.record_recovery, .none);
                self.armTimeout(now);
            },
            .committed => {
                if (self.view.status != .committing or result.identity == null) {
                    self.failed(error.InvalidSetupResult, now);
                    return;
                }
                self.identity = result.identity;
                self.transition(.complete, .none);
            },
            .pending => unreachable,
        }
    }

    fn failed(self: *Entry, _: anyerror, now: u64) void {
        self.lock(now);
        self.view.notice = .failed;
    }

    fn transition(self: *Entry, status: Status, notice: Notice) void {
        self.view.status = status;
        self.view.notice = notice;
        self.revision +|= 1;
    }

    fn armTimeout(self: *Entry, now: u64) void {
        if (self.input_timeout_ticks == 0) {
            self.inputInterrupted(now);
            return;
        }
        self.input_deadline = std.math.add(u64, now, self.input_timeout_ticks) catch {
            self.inputInterrupted(now);
            return;
        };
    }

    fn eraseInput(self: *Entry) void {
        std.crypto.secureZero(u8, &self.value);
        self.view.characters = 0;
    }

    fn erase(self: *Entry) void {
        self.eraseInput();
        std.crypto.secureZero(u8, &self.first_pin);
        self.pin_len = 0;
        self.recovery_record.erase();
        std.crypto.secureZero(u8, &self.view.recovery_code);
        self.input_deadline = null;
    }

    comptime {
        if (@sizeOf(@This()) > 2048) @compileError("trusted setup entry exceeds bounded state");
    }
};

const TestBackend = @import("../../tests/fixtures/setup_entry.zig").Fixture;

fn typeTest(entry: *Entry, value: []const u8, now: u64) void {
    for (value) |byte| entry.handle(.{ .kind = .text, .data = byte }, now);
}
fn submitTest(entry: *Entry, now: u64) void {
    entry.handle(.{ .kind = .activate }, now);
}

test "trusted setup confirms PIN and independently retained recovery record before commit" {
    var backend = TestBackend{};
    var entry = Entry{ .backend = backend.backend(), .input_timeout_ticks = 100 };
    defer entry.quiesce();
    entry.lock(1);
    typeTest(&entry, "12345678", 1);
    submitTest(&entry, 1);
    try std.testing.expectEqual(Status.confirm_pin, entry.view.status);
    typeTest(&entry, "12345679", 2);
    submitTest(&entry, 2);
    try std.testing.expectEqual(Status.choose_pin, entry.view.status);
    try std.testing.expectEqual(Notice.mismatch, entry.view.notice);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0) and std.mem.allEqual(u8, &entry.first_pin, 0));
    try std.testing.expectEqual(@as(usize, 0), backend.prepares);
    typeTest(&entry, "12345678", 3);
    submitTest(&entry, 3);
    typeTest(&entry, "12345678", 4);
    submitTest(&entry, 4);
    try std.testing.expect(entry.prepareWork(4));
    entry.runWork(4);
    try std.testing.expect(entry.busy());
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0) and std.mem.allEqual(u8, &entry.first_pin, 0));
    entry.tick(5);
    try std.testing.expectEqual(Status.record_recovery, entry.view.status);
    var code: [recovery.CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    try backend.record.encode(&code);
    var display: [recovery.DISPLAY_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &display);
    try backend.record.format(&display);
    try std.testing.expectEqualSlices(u8, &display, &entry.view.recovery_code);
    submitTest(&entry, 6);
    try std.testing.expectEqual(Status.confirm_recovery, entry.view.status);
    try std.testing.expect(std.mem.allEqual(u8, &entry.view.recovery_code, 0));
    submitTest(&entry, 7);
    try std.testing.expectEqual(Notice.invalid_record, entry.view.notice);
    var other = backend.record;
    other.trusted.digest[0] ^= 1;
    try other.encode(&code);
    typeTest(&entry, &code, 8);
    submitTest(&entry, 8);
    try std.testing.expectEqual(Notice.mismatch, entry.view.notice);
    try std.testing.expectEqual(@as(usize, 0), backend.commits);
    for (display) |byte| entry.handle(.{ .kind = .text, .data = std.ascii.toLower(byte) }, 9);
    submitTest(&entry, 9);
    try std.testing.expect(entry.prepareWork(9));
    entry.runWork(9);
    try std.testing.expectEqual(@as(usize, 1), backend.commits);
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0) and std.mem.allEqual(u8, std.mem.asBytes(&entry.recovery_record), 0));
    entry.tick(10);
    try std.testing.expect(entry.view.status == .complete and entry.identity != null and entry.capturing());
    try std.testing.expect(entry.nextWake() == null);
}

test "trusted setup cancellation timeout and resumed commit retain no input secrets" {
    var backend = TestBackend{};
    var entry = Entry{ .backend = backend.backend(), .input_timeout_ticks = 10 };
    defer entry.quiesce();
    entry.lock(1);
    typeTest(&entry, "12345678", 1);
    submitTest(&entry, 1);
    entry.tick(11);
    try std.testing.expect(entry.view.status == .choose_pin and entry.view.notice == .timeout);
    try std.testing.expect(std.mem.allEqual(u8, &entry.first_pin, 0));
    for (0..2) |_| {
        typeTest(&entry, "12345678", 12);
        submitTest(&entry, 12);
    }
    entry.runWork(12);
    entry.inputInterrupted(13);
    try std.testing.expect(entry.busy() and entry.view.status == .cancelling);
    entry.tick(14);
    try std.testing.expect(!entry.busy() and entry.view.status == .choose_pin);
    entry.handle(.{ .kind = .show_recovery }, 15);
    var code: [recovery.CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    try backend.record.encode(&code);
    typeTest(&entry, &code, 16);
    submitTest(&entry, 16);
    entry.runWork(16);
    backend.remaining = 1;
    entry.handle(.{ .kind = .dismiss_recovery }, 17);
    try std.testing.expect(entry.view.status == .cancelling and entry.busy());
    entry.tick(18);
    try std.testing.expect(entry.view.status == .resume_setup and !entry.busy());
    try std.testing.expect(std.mem.allEqual(u8, &entry.value, 0) and std.mem.allEqual(u8, &entry.view.recovery_code, 0));
    typeTest(&entry, &code, 19);
    submitTest(&entry, 19);
    entry.runWork(19);
    entry.tick(18); // Clock rollback must cancel a submitted operation.
    entry.quiesce();
    try std.testing.expect(entry.view.status == .resume_setup and entry.identity == null and !entry.busy());
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&entry.recovery_record), 0));
}
