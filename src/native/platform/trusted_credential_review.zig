//! Public text for one native credential decision. Contains no signing authority.
const std = @import("std");
const input = @import("../drivers/input_driver_task.zig");

pub const State = enum { hidden, reviewing, approved, denied };
pub const Review = struct {
    state: State = .hidden,
    application: [64]u8 = @splat(0),
    relying_party: [64]u8 = @splat(0),
    origin: [96]u8 = @splat(0),
    application_len: u8 = 0,
    relying_party_len: u8 = 0,
    origin_len: u8 = 0,
    expires_at: u64 = 0,
    allow_selected: bool = false,
    presented: bool = false,

    pub fn init(application: []const u8, relying_party: []const u8, origin: []const u8, expires_at: u64) !Review {
        var self = Review{ .state = .reviewing, .expires_at = expires_at };
        inline for (.{ "application", "relying_party", "origin" }) |field| {
            const value = if (comptime std.mem.eql(u8, field, "application")) application else if (comptime std.mem.eql(u8, field, "relying_party")) relying_party else origin;
            if (value.len == 0 or value.len > @field(self, field).len) return error.InvalidCredentialReview;
            // Canonical native identifiers only. Control characters, Unicode
            // lookalikes and whitespace cannot disguise the displayed target.
            for (value) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidCredentialReview;
            @memcpy(@field(self, field)[0..value.len], value);
            @field(self, field ++ "_len") = @intCast(value.len);
        }
        return self;
    }

    pub fn visible(self: *const Review) bool {
        return self.state != .hidden;
    }

    // Three wrapped identifiers, labels, decision buttons and help must all fit.
    // Never authorize a target whose distinguishing suffix was clipped.
    pub fn fits(self: *const Review, columns: usize, rows: usize) bool {
        if (columns < 40) return false;
        const lines = (self.application_len + columns - 1) / columns +
            (self.relying_party_len + columns - 1) / columns + (self.origin_len + columns - 1) / columns;
        return rows >= 13 + lines;
    }

    pub fn handle(self: *Review, event: input.KeyboardEvent) bool {
        if (self.state != .reviewing) return false;
        switch (event.kind) {
            .dismiss_recovery => self.state = .denied,
            .focus_next, .focus_previous => {
                if (!self.presented) return false;
                self.allow_selected = !self.allow_selected;
                // A new rendered selection and a released key are required.
                self.presented = false;
            },
            .activate => {
                if (!self.presented) return false;
                self.state = if (self.allow_selected) .approved else .denied;
            },
            else => return false,
        }
        return true;
    }
};

test "trusted credential review rejects misleading text and requires visible explicit approval" {
    try std.testing.expectError(error.InvalidCredentialReview, Review.init("app\nAllow", "example.test", "https://example.test", 10));
    try std.testing.expectError(error.InvalidCredentialReview, Review.init("app", "example.test", "https://exаmple.test", 10));
    var review = try Review.init("app.notes", "example.test", "https://example.test", 10);
    try std.testing.expect(!review.handle(.{ .kind = .activate }));
    try std.testing.expect(!review.handle(.{ .kind = .paste }));
    review.presented = true;
    try std.testing.expect(review.handle(.{ .kind = .activate }));
    try std.testing.expectEqual(State.denied, review.state);
    review.state = .reviewing;
    try std.testing.expect(review.handle(.{ .kind = .focus_next }));
    try std.testing.expect(!review.handle(.{ .kind = .activate }));
    review.presented = true;
    try std.testing.expect(review.handle(.{ .kind = .activate }));
    try std.testing.expectEqual(State.approved, review.state);
    try std.testing.expect(!review.handle(.{ .kind = .activate }));
    try std.testing.expect(review.fits(40, 16) and !review.fits(40, 15));
    try std.testing.expect(!review.fits(39, 30));
}
