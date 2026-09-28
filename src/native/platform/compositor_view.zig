const abi = @import("../core/abi.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");

pub const Content = struct {
    surface_id: u64,
    text: []const u8,
    cursor: usize,
    cursor_upstream: bool = false,
    selection_anchor: ?usize = null,
    flags: mailbox.UiStateFlags,
    window_id: u64 = 0,
    model: mailbox.UiModelKind = .generic,
    focus_index: u16 = 0,
    save_state: abi.DocumentSaveState = .none,
};
const compositor = @import("compositor_session.zig");
const scanout = @import("../../kernel/platform/text_scanout.zig");
pub const DOCUMENT_START_ROW: usize = 5;

pub fn textViewport(columns: usize, rows: usize, start_row: usize) abi.text_layout.Viewport {
    const visible = (rows -| 3) -| start_row;
    if (columns == 0 or columns > 255 or visible == 0 or visible > 255) return .{};
    return .{ .columns = @intCast(columns), .rows = @intCast(visible) };
}

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
    var text_row: usize = DOCUMENT_START_ROW;
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
            drawTextAt(frame, text_row, state.text, .{ .offset = state.cursor, .upstream = state.cursor_upstream }, state.selection_anchor);
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
    drawTextAt(frame, start_row, text, .{ .offset = cursor }, selection_anchor);
}

fn drawTextAt(frame: *scanout.Frame, start_row: usize, text: []const u8, caret: abi.text_layout.Caret, selection_anchor: ?usize) void {
    const viewport = textViewport(frame.columns, frame.rows, start_row);
    if (viewport.rows == 0) return;
    const layout = abi.text_layout.Layout{ .text = text, .columns = viewport.columns };
    const position = layout.locate(caret);
    const first_row = position.index -| (@as(usize, viewport.rows) - 1);
    const anchor = selection_anchor orelse caret.offset;
    const selection_start = @min(anchor, caret.offset);
    const selection_end = @max(anchor, caret.offset);
    var iterator = layout.rows();
    var index: usize = 0;
    while (iterator.next()) |row| : (index += 1) {
        if (index < first_row) continue;
        if (index >= first_row + viewport.rows) break;
        const cells = frame.cells[(start_row + index - first_row) * frame.columns ..][0..frame.columns];
        for (text[row.start..row.end], row.start..) |byte, offset| {
            const cell = &cells[offset - row.start];
            cell.character = byte;
            if (offset >= selection_start and offset < selection_end) cell.style = .selected;
        }
        if (row.next > row.end and row.end - row.start < frame.columns and row.end >= selection_start and row.end < selection_end)
            cells[row.end - row.start].style = .selected;
        if (index == position.index) {
            const cell = &cells[@min(position.column, frame.columns - 1)];
            cell.cursor = true;
            cell.cursor_trailing = position.column == frame.columns;
        }
    }
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

test "desktop places an upstream wrap caret after the row and pages without phantom lines" {
    const std = @import("std");
    var frame = try scanout.Frame.init(5, 11);
    const text = "abcdefghij\nxy\n";
    drawTextAt(&frame, 5, text, .{ .offset = 5, .upstream = true }, null);
    try expectText(&frame, 0, 5, "abcde");
    try std.testing.expect(frame.cells[5 * 5 + 4].cursor);
    try std.testing.expect(frame.cells[5 * 5 + 4].cursor_trailing);
    try std.testing.expect(!frame.cells[6 * 5].cursor);
    frame.clear();
    drawTextAt(&frame, 5, text, .{ .offset = 5 }, null);
    try std.testing.expect(frame.cells[6 * 5].cursor);
    try std.testing.expect(!frame.cells[6 * 5].cursor_trailing);
    frame.clear();
    drawTextAt(&frame, 5, text, .{ .offset = 14 }, 0);
    try expectText(&frame, 0, 5, "fghij");
    try expectText(&frame, 0, 6, "xy");
    try std.testing.expect(frame.cells[7 * 5].cursor);
    try std.testing.expectEqual(scanout.Style.selected, frame.cells[6 * 5 + 2].style);
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
