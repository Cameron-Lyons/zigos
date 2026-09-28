const abi = @import("../core/abi.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");

pub const Content = struct {
    surface_id: u64,
    text: []const u8,
    cursor: usize,
    selection_anchor: ?usize = null,
    flags: mailbox.UiStateFlags,
    window_id: u64 = 0,
    model: mailbox.UiModelKind = .generic,
    focus_index: u16 = 0,
    save_state: abi.DocumentSaveState = .none,
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
            drawText(frame, text_row, state.text, state.cursor, state.selection_anchor);
        }
        if (state.model == .notes) {
            const status = saveStatus(state.save_state, flags.dirty);
            frame.put(0, frame.rows - 2, status.text, status.style);
        } else frame.put(0, frame.rows - 2, if (flags.dirty) "Unsaved changes" else "Local session", .muted);
        if (state.model != .notes or state.save_state == .none) {
            if (flags.input_overflow) frame.put(0, frame.rows - 2, "Text is full. Remove text to continue.", .warning);
            if (flags.recovery_visible) frame.put(0, frame.rows - 2, "Recovery requested", .warning);
        }
        if (state.model == .notes and flags.clipboard_failed)
            frame.put(0, frame.rows - 2, "Clipboard action unavailable. Your draft is unchanged.", .warning);
        if (state.model == .notes and state.save_state == .saved and !flags.dirty and flags.input_overflow)
            frame.put(0, frame.rows - 2, "Text is full. Remove text to continue.", .warning);
    } else {
        frame.put(0, text_row, "Waiting for task content...", .muted);
    }
    if (surface) |state| {
        if (state.model == .notes) frame.put(0, frame.rows - 1, switch (state.save_state) {
            .none, .saving, .saved => "Ctrl+Z  Undo  |  Ctrl+Shift+Z  Redo  |  Ctrl+Enter  Save",
            .retryable => "Type to edit  |  Ctrl+Enter  Retry save",
            .permission_denied, .document_changed, .unavailable, .failed => "Type to edit  |  Draft kept in this session",
        }, .muted);
    }
}

fn saveStatus(state: abi.DocumentSaveState, dirty: bool) struct { text: []const u8, style: scanout.Style } {
    return switch (state) {
        .none => .{ .text = if (dirty) "Unsaved changes" else "Local document", .style = .muted },
        .saving => .{ .text = "Saving...", .style = .accent },
        .saved => .{ .text = if (dirty) "Unsaved changes" else "Saved locally", .style = .muted },
        .retryable => .{ .text = "Save failed. Ctrl+Enter to retry.", .style = .warning },
        .permission_denied => .{ .text = "Save denied. Your draft is still here.", .style = .warning },
        .document_changed => .{ .text = "Document changed elsewhere. Your draft is still here.", .style = .warning },
        .unavailable => .{ .text = "Storage unavailable. Your draft is still here.", .style = .warning },
        .failed => .{ .text = "Save failed. Your draft is still here.", .style = .warning },
    };
}

fn drawText(frame: *scanout.Frame, start_row: usize, text: []const u8, cursor: usize, selection_anchor: ?usize) void {
    const visible_rows = (frame.rows -| 3) -| start_row;
    if (visible_rows == 0) return;
    // Derive a bounded viewport from the acknowledged cursor. The compositor
    // owns no editor scroll state, and repeated snapshots produce the same cells.
    var cursor_row: usize = 0;
    var cursor_column: usize = 0;
    for (text[0..@min(cursor, text.len)]) |byte| {
        advanceTextPosition(byte, frame.columns, &cursor_row, &cursor_column);
    }
    const first_row = cursor_row -| (visible_rows - 1);
    const anchor = selection_anchor orelse cursor;
    const selection_start = @min(anchor, cursor);
    const selection_end = @max(anchor, cursor);
    var row: usize = 0;
    var column: usize = 0;
    for (text, 0..) |byte, index| {
        if (row >= first_row + visible_rows) return;
        if (row >= first_row) {
            const cell = &frame.cells[(start_row + row - first_row) * frame.columns + column];
            if (index == cursor) cell.cursor = true;
            if (index >= selection_start and index < selection_end) cell.style = .selected;
            if (byte != '\n') cell.character = byte;
        }
        advanceTextPosition(byte, frame.columns, &row, &column);
    }
    if (cursor == text.len and row >= first_row and row < first_row + visible_rows)
        frame.cells[(start_row + row - first_row) * frame.columns + column].cursor = true;
}

fn advanceTextPosition(byte: u8, columns: usize, row: *usize, column: *usize) void {
    if (byte == '\n' or column.* + 1 == columns) {
        column.* = 0;
        row.* += 1;
    } else column.* += 1;
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

test "desktop text wraps scrolls to its cursor and clears old cells" {
    const std = @import("std");
    var frame = try scanout.Frame.init(20, 10);
    drawText(&frame, 5, "abcdefghijklmnopqrstUV", 22, null);
    try expectText(&frame, 0, 5, "abcdefghijklmnopqrst");
    try expectText(&frame, 0, 6, "UV");
    try std.testing.expect(frame.cells[6 * 20 + 2].cursor);
    frame.clear();
    drawText(&frame, 6, "abcdefghijklmnopqrstUV", 22, null);
    try expectText(&frame, 0, 6, "UV");
    try std.testing.expect(frame.cells[6 * 20 + 2].cursor);
    for (frame.cells[7 * 20 ..][0..20]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    frame.clear();
    drawText(&frame, 5, "one\ntwo\nthree\n", 14, null);
    try expectText(&frame, 0, 5, "three");
    try std.testing.expect(frame.cells[6 * 20].cursor);
    frame.clear();
    drawText(&frame, 5, "one\ntwo\nthree\n", 1, null);
    try expectText(&frame, 0, 5, "one");
    try std.testing.expect(frame.cells[5 * 20 + 1].cursor);
    try std.testing.expect(!frame.cells[6 * 20].cursor);
    var tiny = try scanout.Frame.init(4, 1);
    const empty = compositor.Session.init();
    render(&tiny, &empty, null);
    try expectText(&tiny, 0, 0, "Zigo");
}

test "desktop selection highlights both directions across newlines and clears on collapse" {
    const std = @import("std");
    var frame = try scanout.Frame.init(20, 10);
    for ([_]struct { cursor: usize, anchor: usize }{ .{ .cursor = 2, .anchor = 5 }, .{ .cursor = 5, .anchor = 2 } }) |selection| {
        frame.clear();
        drawText(&frame, 5, "abc\ndef", selection.cursor, selection.anchor);
        try std.testing.expectEqual(scanout.Style.body, frame.cells[5 * 20 + 1].style);
        try std.testing.expectEqual(scanout.Style.selected, frame.cells[5 * 20 + 2].style);
        try std.testing.expectEqual(scanout.Style.selected, frame.cells[5 * 20 + 3].style);
        try std.testing.expectEqual(scanout.Style.selected, frame.cells[6 * 20].style);
        try std.testing.expectEqual(scanout.Style.body, frame.cells[6 * 20 + 1].style);
    }
    frame.clear();
    drawText(&frame, 5, "abc\ndef", 5, 5);
    for (frame.cells[5 * 20 .. 7 * 20]) |cell| try std.testing.expectEqual(scanout.Style.body, cell.style);
    frame.clear();
    drawText(&frame, 6, "abcdefghijklmnopqrstUV", 22, 18);
    try expectText(&frame, 0, 6, "UV");
    try std.testing.expectEqual(scanout.Style.selected, frame.cells[6 * 20].style);
    try std.testing.expectEqual(scanout.Style.selected, frame.cells[6 * 20 + 1].style);
    try std.testing.expectEqual(scanout.Style.body, frame.cells[6 * 20 + 2].style);
    try std.testing.expect(frame.cells[6 * 20 + 2].cursor);
}

test "desktop renders document save feedback without treating a dirty receipt as saved" {
    const std = @import("std");
    const task_runtime = @import("../task/task_runtime.zig");
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 72 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 65536, .endpoint_slots = 4, .shared_memory_bytes = 4096 },
        .ui_surface_id = 32,
        .local_only = true,
    });
    var session = compositor.Session.init();
    _ = try session.openTaskView(task, "Notes");
    var content = Content{ .surface_id = 32, .text = "draft", .cursor = 5, .model = .notes, .flags = .{ .dirty = true, .input_overflow = true, .recovery_visible = true } };
    var frame = try scanout.Frame.init(80, 20);
    for ([_]struct { state: abi.DocumentSaveState, text: []const u8, style: scanout.Style }{
        .{ .state = .saving, .text = "Saving...", .style = .accent },
        .{ .state = .retryable, .text = "Save failed. Ctrl+Enter to retry.", .style = .warning },
        .{ .state = .permission_denied, .text = "Save denied. Your draft is still here.", .style = .warning },
        .{ .state = .document_changed, .text = "Document changed elsewhere. Your draft is still here.", .style = .warning },
        .{ .state = .unavailable, .text = "Storage unavailable. Your draft is still here.", .style = .warning },
        .{ .state = .failed, .text = "Save failed. Your draft is still here.", .style = .warning },
        .{ .state = .saved, .text = "Unsaved changes", .style = .muted },
    }) |case| {
        content.save_state = case.state;
        render(&frame, &session, content);
        try expectText(&frame, 0, 5, "draft");
        try expectText(&frame, 0, 18, case.text);
        try std.testing.expectEqual(case.style, frame.cells[18 * frame.columns].style);
    }
    content.flags.dirty = false;
    render(&frame, &session, content);
    try expectText(&frame, 0, 18, "Text is full. Remove text to continue.");
    content.flags.input_overflow = false;
    render(&frame, &session, content);
    try expectText(&frame, 0, 18, "Saved locally");
    try std.testing.expectEqual(@as(u8, ' '), frame.cells[18 * frame.columns + 13].character);
}

fn expectText(frame: *const scanout.Frame, column: usize, row: usize, text: []const u8) !void {
    const std = @import("std");
    for (text, 0..) |byte, index| try std.testing.expectEqual(byte, frame.cells[row * frame.columns + column + index].character);
}
