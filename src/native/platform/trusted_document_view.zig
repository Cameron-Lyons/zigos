//! Public native document controls. Application code never owns this state.
//! Decisions retain the exact displayed generation and fresh hardware sequence.
const std = @import("std");
const input = @import("../drivers/input_driver_task.zig");
const layout = @import("../core/text_layout.zig");
const labels = @import("../../userspace/launcher_protocol.zig");
const font = @import("../../kernel/platform/unicode_font.zig");

pub const Kind = enum { new, open };
pub const Phase = enum { disabled, home, requested, browsing, review, working, retry, failed };
pub const Action = union(enum) { request: Kind, page: bool, select: u8, approve, deny, retry };
pub const Decision = struct { action: Action, token: u64, revision: u64, report_sequence: u64 };
pub const Label = struct {
    bytes: [labels.MAX_LABEL_BYTES]u8 = @splat(0),
    len: u8 = 0,

    pub fn init(text: []const u8) !Label {
        if (!labels.validLabel(text)) return error.InvalidDocumentLabel;
        if (text[0] == ' ' or text[text.len - 1] == ' ') return error.InvalidDocumentLabel;
        var clusters = layout.unicode.Iterator{ .text = text };
        while (clusters.next()) |cluster| {
            if (!font.supportsCluster(text[cluster.start..cluster.end])) return error.InvalidDocumentLabel;
        }
        var value = Label{ .len = @intCast(text.len) };
        @memcpy(value.bytes[0..text.len], text);
        return value;
    }
    pub fn slice(self: *const Label) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const View = struct {
    phase: Phase = .disabled,
    kind: Kind = .open,
    token: u64 = 0,
    revision: u64 = 1,
    paths: [labels.PAGE_ENTRIES]Label = @splat(.{}),
    count: u8 = 0,
    selected: u8 = 0,
    previous: bool = false,
    next: bool = false,
    path: Label = .{},
    allow_selected: bool = false,
    pending: ?Decision = null,
    presented_revision: u64 = 0,
    last_report_sequence: u64 = 0,

    pub fn visible(self: *const View) bool {
        return self.phase != .disabled and self.phase != .home;
    }
    pub fn touch(self: *View) void {
        if (self.revision == std.math.maxInt(u64)) {
            self.phase = .disabled;
            self.pending = null;
        } else self.revision += 1;
        self.presented_revision = 0;
    }
    pub fn presented(self: *View, columns: usize, rows: usize, success: bool) void {
        self.presented_revision = if (success and self.fits(columns, rows)) self.revision else 0;
    }
    pub fn fits(self: *const View, columns: usize, rows: usize) bool {
        if (columns < 40 or rows < 10 or self.phase == .disabled) return false;
        return switch (self.phase) {
            .browsing => blk: {
                var required: usize = 7;
                for (self.paths[0..self.count]) |*path| required += lines(path.slice(), columns) + 1;
                break :blk rows >= required;
            },
            .review => rows >= 13 + lines(self.path.slice(), columns),
            else => true,
        };
    }
    fn queue(self: *View, action: Action, sequence: u64) bool {
        if (self.pending != null or sequence == 0 or sequence <= self.last_report_sequence or
            self.token == 0 or self.presented_revision != self.revision) return false;
        self.pending = .{ .action = action, .token = self.token, .revision = self.revision, .report_sequence = sequence };
        self.last_report_sequence = sequence;
        self.touch();
        return true;
    }
    pub fn shortcut(self: *View, kind: Kind, sequence: u64) bool {
        if (self.phase != .home or !self.queue(.{ .request = kind }, sequence)) return false;
        self.kind = kind;
        self.phase = .requested;
        return true;
    }
    pub fn handle(self: *View, event: input.KeyboardEvent, sequence: u64) bool {
        if (!self.visible()) return false;
        if (event.kind == .dismiss_recovery) {
            // Cancellation needs no screen acknowledgement, but still comes
            // from fresh physical input and consumes this generation once.
            if (self.pending != null or sequence == 0 or sequence <= self.last_report_sequence or self.token == 0) return false;
            self.pending = .{ .action = .deny, .token = self.token, .revision = self.revision, .report_sequence = sequence };
            self.last_report_sequence = sequence;
            self.touch();
            return true;
        }
        if (self.phase == .browsing) {
            switch (event.kind) {
                .cursor_up, .cursor_down => {
                    if (self.count == 0 or self.pending != null or self.presented_revision != self.revision or
                        sequence == 0 or sequence <= self.last_report_sequence) return false;
                    self.last_report_sequence = sequence;
                    self.selected = if (event.kind == .cursor_up) self.selected -| 1 else @min(self.selected + 1, self.count - 1);
                    self.touch();
                    return true;
                },
                .page_up => return self.previous and self.queue(.{ .page = false }, sequence),
                .page_down => return self.next and self.queue(.{ .page = true }, sequence),
                .activate => return self.count != 0 and self.queue(.{ .select = self.selected }, sequence),
                else => return false,
            }
        }
        if (self.phase == .review) {
            switch (event.kind) {
                .focus_next, .focus_previous => {
                    if (self.pending != null or self.presented_revision != self.revision or sequence == 0 or sequence <= self.last_report_sequence) return false;
                    self.last_report_sequence = sequence;
                    self.allow_selected = !self.allow_selected;
                    self.touch();
                    return true;
                },
                .activate => return self.queue(if (self.allow_selected) .approve else .deny, sequence),
                else => return false,
            }
        }
        if (self.phase == .retry and event.kind == .activate) return self.queue(.retry, sequence);
        return false;
    }
    pub fn take(self: *View) ?Decision {
        const value = self.pending;
        self.pending = null;
        return value;
    }
};

test "native document labels reject fallback stripped and blank path identities" {
    const paths = [_][]const u8{
        "notes/👩‍💻.md",
        "notes/👨‍💻.md",
        "notes/e\u{200c}.md",
        "notes/e\u{200d}.md",
        "notes/\u{10fffc}.md",
        "notes/\u{10fffd}.md",
        "notes/a\u{a0}b.md",
        "notes/a\u{202f}b.md",
        "notes/e\u{732}.md",
        "notes/e\u{738}.md",
        "notes/\u{1c0}\u{730}.md",
        "notes/a.md ",
        " notes/a.md",
    };
    for (paths) |path| try std.testing.expectError(error.InvalidDocumentLabel, Label.init(path));
}

test "native document labels retain supported narrow wide combining and internal space paths" {
    for ([_][]const u8{ "notes/café.md", "草稿.md", "notes/e\u{301}.md", "two words.md", "草稿/界\u{732}.md" }) |path| {
        const label = try Label.init(path);
        try std.testing.expectEqualStrings(path, label.slice());
        var view = View{ .phase = .review, .kind = .open, .token = 7, .path = label, .allow_selected = true };
        view.presented(40, 20, true);
        try std.testing.expect(view.handle(.{ .kind = .activate }, 1));
        try std.testing.expect(view.take().?.action == .approve);
    }
}

pub fn lines(text: []const u8, columns: usize) usize {
    var iterator = (layout.Layout{ .text = text, .columns = columns }).rows();
    var count: usize = 0;
    while (iterator.next() != null) count += 1;
    return count;
}

test "document controls require complete scanout and distinct fresh physical decisions" {
    var view = View{ .phase = .home, .token = 1 };
    try std.testing.expect(!view.shortcut(.new, 1));
    view.presented(40, 10, true);
    try std.testing.expect(view.shortcut(.new, 1));
    try std.testing.expectEqual(Kind.new, view.take().?.action.request);
    view.phase = .review;
    view.path = try Label.init("notes/private.md");
    view.touch();
    view.presented(40, 13, true);
    try std.testing.expect(!view.handle(.{ .kind = .focus_next }, 2));
    view.presented(40, 14, true);
    try std.testing.expect(view.handle(.{ .kind = .focus_next }, 2));
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 2));
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 3));
    view.presented(40, 14, true);
    try std.testing.expect(view.handle(.{ .kind = .activate }, 3));
    const decision = view.take().?;
    try std.testing.expect(decision.action == .approve and decision.token == 1 and decision.report_sequence == 3);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 3));
}

test "document picker retains complete Unicode names and refuses invisible or replayed selection" {
    var view = View{ .phase = .browsing, .token = 2, .count = 2, .next = true };
    view.paths[0] = try Label.init("草稿.md");
    view.paths[1] = try Label.init(&@as([96]u8, @splat('a')));
    try std.testing.expect(!view.fits(40, 12));
    view.presented(40, 13, true);
    try std.testing.expect(view.handle(.{ .kind = .cursor_down }, 1));
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 2));
    view.presented(40, 13, true);
    try std.testing.expect(view.handle(.{ .kind = .activate }, 2));
    try std.testing.expectEqual(@as(u8, 1), view.take().?.action.select);
    try std.testing.expectError(error.InvalidDocumentLabel, Label.init("notes\nAllow"));
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 2));
}

test "document decisions retain exact token revision and report sequence across failed scanout and stale retries" {
    var view = View{ .phase = .review, .kind = .new, .token = 91, .allow_selected = true };
    view.path = try Label.init(&@as([96]u8, @splat('p')));
    try std.testing.expect(view.fits(40, 16) and !view.fits(40, 15));
    view.presented(40, 15, true);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 1));
    view.presented(40, 16, false);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 2));
    const revision = view.revision;
    view.presented(40, 16, true);
    try std.testing.expect(view.handle(.{ .kind = .activate }, 3));
    const decision = view.take().?;
    try std.testing.expect(decision.action == .approve and decision.token == 91 and decision.revision == revision and decision.report_sequence == 3);
    view.phase = .retry;
    view.token = 92;
    view.touch();
    view.presented(40, 16, true);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 3));
    try std.testing.expect(view.handle(.{ .kind = .activate }, 4));
    try std.testing.expect(view.take().?.action == .retry);
    view.phase = .disabled;
    view.presented(40, 16, true);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 5));
    try std.testing.expectEqual(@as(u64, 0), view.presented_revision);
}

test "document cancellation needs fresh physical identity but no invisible Allow acknowledgement" {
    var view = View{ .phase = .review, .token = 6, .allow_selected = true };
    view.path = try Label.init("notes/草稿.md");
    view.presented(40, 20, false);
    try std.testing.expect(!view.handle(.{ .kind = .activate }, 1));
    try std.testing.expect(!view.handle(.{ .kind = .dismiss_recovery }, 0));
    try std.testing.expect(view.handle(.{ .kind = .dismiss_recovery }, 2));
    try std.testing.expect(view.take().?.action == .deny);
    try std.testing.expect(!view.handle(.{ .kind = .dismiss_recovery }, 2));
    view.revision = std.math.maxInt(u64);
    view.touch();
    try std.testing.expect(view.phase == .disabled and view.pending == null and view.presented_revision == 0);
}
