const abi = @import("../core/abi.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");

pub const Content = struct {
    surface_id: u64,
    text: []const u8,
    cursor: usize,
    flags: mailbox.UiStateFlags,
    window_id: u64 = 0,
    model: mailbox.UiModelKind = .generic,
    focus_index: u16 = 0,
};
const compositor = @import("compositor_session.zig");
const scanout = @import("../../kernel/platform/text_scanout.zig");

// Compose the user-facing view from compositor-owned snapshots. The diagnostic
// text framebuffer remains separate so its proof labels never become UI copy.
pub fn render(frame: *scanout.Frame, session: *const compositor.Session, content: ?Content) void {
    frame.clear();
    frame.put(0, 0, "Zigos", .accent);
    if (frame.rows < 10) return;
    if (frame.columns >= 40) frame.put(frame.columns - 21, 0, "Alt+Tab  Switch task", .muted);
    frame.fillRow(2, .selected);

    const window = session.activeWindow() orelse {
        frame.put(1, 2, "Workspace", .selected);
        frame.put(0, 5, "No open tasks.", .muted);
        return;
    };
    frame.put(1, 2, window.titleSlice(), .selected);
    if (window.detail_len != 0) frame.put(0, 3, window.detailSlice(), .muted);

    const surface = if (content) |value| if (window.ui_surface_id == value.surface_id and
        (value.window_id == 0 or value.window_id == window.id)) value else null else null;
    var text_row: usize = 5;
    if (window.item_count != 0) {
        var index: usize = 0;
        while (index < session.item_count and text_row + 4 < frame.rows - 3) : (index += 1) {
            const item = session.itemAtOrder(index) orelse continue;
            if (item.window_id != window.id) continue;
            frame.put(0, text_row, item.resourceSlice(), .accent);
            frame.put(0, text_row + 1, item.reasonSlice(), .body);
            frame.put(0, text_row + 2, switch (item.decision) {
                .pending => "Awaiting your decision",
                .allow => "Allowed",
                .deny => "Denied",
            }, .muted);
            text_row += 4;
        }
    }

    if (surface) |record| {
        const state = &record;
        const flags = state.flags;
        if (state.model == .compositor and flags.active) {
            const end = @import("std").mem.indexOfScalar(u8, state.text, '\n') orelse state.text.len;
            frame.put(0, text_row, state.text[0..end], .body);
            frame.put(0, text_row + 2, " Open ", if (state.focus_index == 0) .selected else .body);
            frame.put(10, text_row + 2, " Cancel ", if (state.focus_index == 1) .selected else .body);
            frame.put(0, frame.rows - 1, "Tab  Choose  |  Enter  Confirm", .muted);
            return;
        } else if (flags.loading) {
            frame.put(0, text_row, "Opening document...", .muted);
        } else if (flags.load_failed) {
            frame.put(0, text_row, "Unable to open document. Your draft is unchanged.", .warning);
        } else if (state.text.len == 0 and state.model != .notes) {
            frame.put(0, text_row, "Ready for input.", .muted);
        } else {
            drawText(frame, text_row, state.text, state.cursor);
        }
        frame.put(0, frame.rows - 2, if (flags.dirty) "Unsaved changes" else if (state.model == .notes) "Local document" else "Local session", .muted);
        if (flags.input_overflow) frame.put(0, frame.rows - 2, "Text is full. Remove text to continue.", .warning);
        if (flags.recovery_visible) frame.put(0, frame.rows - 2, "Recovery requested", .warning);
    } else {
        frame.put(0, text_row, "Waiting for task content...", .muted);
    }
    if (surface) |state| {
        if (state.model == .notes) frame.put(0, frame.rows - 1, "Type to edit  |  Ctrl+Enter  Save", .muted);
    }
}

fn drawText(frame: *scanout.Frame, start_row: usize, text: []const u8, cursor: usize) void {
    var row = start_row;
    var column: usize = 0;
    for (text, 0..) |byte, index| {
        if (row >= frame.rows - 3) return;
        if (index == cursor) frame.cells[row * frame.columns + column].cursor = true;
        if (byte == '\n') {
            column = 0;
            row += 1;
        } else {
            frame.cells[row * frame.columns + column].character = byte;
            column += 1;
            if (column == frame.columns) {
                column = 0;
                row += 1;
            }
        }
    }
    if (cursor == text.len and row < frame.rows - 3) frame.cells[row * frame.columns + column].cursor = true;
}

test "desktop view renders owned surface text and removes stale task content" {
    const std = @import("std");
    const task_runtime = @import("../task/task_runtime.zig");
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 71 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 65536, .endpoint_slots = 4, .shared_memory_bytes = 4096 },
        .ui_surface_id = 31,
        .local_only = true,
    });
    var session = compositor.Session.init();
    _ = try session.openTaskView(task, "Notes");
    var presentation = std.mem.zeroes(abi.SurfacePresentation);
    presentation.surface_id = 31;
    presentation.revision = 1;
    presentation.buffer_object_id = 31;
    presentation.buffer_bytes = 512;
    _ = try session.presentSurface(task, &presentation);
    const content = Content{ .surface_id = 31, .text = "First\nDraft", .cursor = 11, .flags = .{ .dirty = true } };
    var frame = try scanout.Frame.init(60, 20);
    render(&frame, &session, content);
    try expectText(&frame, 1, 2, "Notes");
    try expectText(&frame, 0, 5, "First");
    try expectText(&frame, 0, 6, "Draft");
    try std.testing.expect(frame.cells[6 * frame.columns + 5].cursor);
    try expectText(&frame, 0, 18, "Unsaved changes");

    _ = session.closeWindowsForTask(task.id);
    render(&frame, &session, content);
    try expectText(&frame, 0, 5, "No open tasks.");
    for (frame.cells[6 * frame.columns ..][0..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
}

test "desktop text wraps clips and clears the previous cursor" {
    const std = @import("std");
    var frame = try scanout.Frame.init(20, 10);
    drawText(&frame, 5, "abcdefghijklmnopqrstUV", 22);
    try expectText(&frame, 0, 5, "abcdefghijklmnopqrst");
    try expectText(&frame, 0, 6, "UV");
    try std.testing.expect(frame.cells[6 * 20 + 2].cursor);
    frame.clear();
    drawText(&frame, 6, "abcdefghijklmnopqrstUV", 22);
    try expectText(&frame, 0, 6, "abcdefghijklmnopqrst");
    for (frame.cells[7 * 20 ..][0..20]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    var tiny = try scanout.Frame.init(4, 1);
    const empty = compositor.Session.init();
    render(&tiny, &empty, null);
    try expectText(&tiny, 0, 0, "Zigo");
}

fn expectText(frame: *const scanout.Frame, column: usize, row: usize, text: []const u8) !void {
    const std = @import("std");
    for (text, 0..) |byte, index| try std.testing.expectEqual(byte, frame.cells[row * frame.columns + column + index].character);
}
