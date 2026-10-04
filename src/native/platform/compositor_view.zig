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
    if (session.trusted_view) |trusted| if (trusted.visible()) {
        switch (trusted.*) {
            .authentication => |authentication| renderAuthentication(frame, authentication),
            .setup => |setup| renderSetup(frame, setup),
            .none => unreachable,
        }
        return;
    };
    if (frame.rows < 10) return;
    if (session.trusted_view) |trusted| if (trusted.* == .authentication) {
        if (trusted.authentication.documents) |documents| if (documents.phase == .home and documents.fits(frame.columns, frame.rows))
            frame.put(0, 1, "Ctrl+N New note | Ctrl+O Open note", .accent);
    };
    if (session.trusted_view != null and frame.columns >= 72) frame.put(14, 0, "Ctrl+Alt+Delete  Lock", .muted);
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
            const std = @import("std");
            const end = std.mem.lastIndexOfScalar(u8, state.text, '\n') orelse state.text.len;
            const labels = state.text[0..end];
            // Keep the selected row visible even at the minimum display height.
            const room = (frame.rows -| text_row) -| 4;
            var lines = std.mem.splitScalar(u8, labels, '\n');
            var selected: usize = 0;
            for (labels[0..@min(state.cursor, labels.len)]) |byte| {
                if (byte == '\n') selected += 1;
            }
            const first = selected + 1 -| room;
            var index: usize = 0;
            var drawn: usize = 0;
            while (lines.next()) |label| : (index += 1) {
                if (index < first) continue;
                if (drawn == room) break;
                frame.put(0, text_row + drawn, label, if (index == selected) .accent else .body);
                drawn += 1;
            }
            const empty = std.mem.eql(u8, state.text[@min(end + 1, state.text.len)..], "Cancel");
            if (!empty) frame.put(0, text_row + drawn + 1, " Open ", if (state.focus_index == 0) .selected else .body);
            frame.put(if (empty) 0 else 10, text_row + drawn + 1, " Cancel ", if (state.focus_index == 1) .selected else .body);
            frame.put(0, frame.rows - 1, "Up/Down  Select | PgUp/PgDn  Browse | Tab  Choose | Enter  Confirm", .muted);
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

fn renderAuthentication(frame: *scanout.Frame, authentication: *const @import("trusted_auth_entry.zig").View) void {
    if (frame.rows < 10) return;
    if (authentication.review.visible()) {
        renderCredentialReview(frame, &authentication.review);
        return;
    }
    if (authentication.status == .hidden) if (authentication.documents) |documents| if (documents.visible()) {
        renderDocuments(frame, documents);
        return;
    };
    const recovering = authentication.method == .recovery;
    frame.fillRow(2, .selected);
    frame.put(1, 2, if (recovering) "Recover Zigos" else "Unlock Zigos", .selected);
    frame.put(0, 4, if (recovering) "Enter your recovery key" else "Enter your device PIN", .body);
    const mask = &@as([@import("trusted_auth_entry.zig").MAX_ENTRY_BYTES]u8, @splat('*'));
    const count = @min(authentication.characters, mask.len);
    var offset: usize = 0;
    var row: usize = 6;
    while (offset < count and row + 2 < frame.rows) : (row += 1) {
        const take = @min(count - offset, frame.columns);
        frame.put(0, row, mask[offset..][0..take], .accent);
        offset += take;
    }
    const message = switch (authentication.status) {
        .hidden, .entering => "",
        .too_short => if (recovering) (if (authentication.recovery_characters == 128) "Enter all 128 recovery characters." else "Enter all 56 recovery characters.") else "Enter at least 6 digits.",
        .too_long => "Entry is too long. Press Esc to start again.",
        .invalid_code => "Check your recovery key for typing errors.",
        .pending, .verifying => if (recovering) "Recovering..." else "Unlocking...",
        .cancelling => "Finishing cancelled attempt...",
        .rejected => if (recovering) "Recovery key not recognized. Try again." else "PIN not recognized. Try again.",
        .locked_out => if (authentication.recovery_available) "Too many attempts. Wait or press Ctrl+R for recovery." else "Too many attempts. Wait before trying again.",
        .unavailable => "Sign-in unavailable. Press Ctrl+Alt+Delete to retry.",
    };
    frame.put(0, @max(row + 1, 8), message, if (authentication.status == .pending or authentication.status == .verifying) .body else .warning);
    frame.put(0, frame.rows - 1, if (authentication.status == .pending or authentication.status == .verifying or authentication.status == .cancelling)
        "Esc  Cancel"
    else if (recovering)
        "Enter  Recover  |  Esc  Clear  |  Ctrl+R  PIN"
    else if (authentication.recovery_available)
        "Enter  Unlock  |  Esc  Clear  |  Ctrl+R  Recovery"
    else
        "Enter  Unlock  |  Esc  Clear PIN", .muted);
}

fn putDocumentLines(frame: *scanout.Frame, row: *usize, text: []const u8, style: scanout.Style) void {
    var lines = (abi.text_layout.Layout{ .text = text, .columns = frame.columns }).rows();
    while (lines.next()) |line| {
        frame.put(0, row.*, text[line.start..line.end], style);
        row.* += 1;
    }
}

fn renderDocuments(frame: *scanout.Frame, documents: *const @import("trusted_document_view.zig").View) void {
    frame.fillRow(2, .selected);
    frame.put(1, 2, if (documents.kind == .new) "New Notes document" else "Open Notes document", .selected);
    if (!documents.fits(frame.columns, frame.rows)) {
        frame.put(0, 4, "More display space is needed.", .warning);
        frame.put(0, 6, "Esc  Cancel", .body);
        return;
    }
    var row: usize = 4;
    switch (documents.phase) {
        .browsing => {
            if (documents.count == 0) frame.put(0, row, "No Notes documents yet.", .muted);
            for (documents.paths[0..documents.count], 0..) |*path, index| {
                putDocumentLines(frame, &row, path.slice(), if (index == documents.selected) .selected else .body);
                row += 1;
            }
            frame.put(0, frame.rows - 2, "PgUp/PgDn  Browse | Enter  Open", .muted);
        },
        .review => {
            frame.put(0, row, "Application: Notes", .body);
            row += 2;
            frame.put(0, row, "Document in your Notes workspace", .muted);
            row += 1;
            putDocumentLines(frame, &row, documents.path.slice(), .accent);
            row += 1;
            frame.put(0, row, "Read and edit only this document", .body);
            frame.put(0, row + 1, "Until lock or session timeout", .muted);
            row += 2;
            frame.put(0, row, " Cancel ", if (!documents.allow_selected) .selected else .body);
            frame.put(12, row, " Allow ", if (documents.allow_selected) .selected else .body);
            frame.put(0, frame.rows - 2, "Tab  Choose | Enter  Confirm", .muted);
        },
        .retry => {
            frame.put(0, row, "Document save needs another attempt.", .warning);
            frame.put(0, row + 2, "Enter  Retry", .body);
        },
        .failed => frame.put(0, row, "Unable to open this document.", .warning),
        else => frame.put(0, row, if (documents.kind == .new) "Creating document..." else "Opening document...", .body),
    }
    frame.put(0, frame.rows - 1, "Esc  Cancel", .muted);
}

fn renderCredentialReview(frame: *scanout.Frame, review: *const @import("trusted_credential_review.zig").Review) void {
    frame.fillRow(2, .selected);
    frame.put(1, 2, "Use a saved credential", .selected);
    if (!review.fits(frame.columns, frame.rows)) {
        frame.put(0, 4, "More display space is needed.", .warning);
        frame.put(0, 6, "Esc  Cancel", .body);
        return;
    }
    var row: usize = 4;
    inline for (.{ "application", "relying_party", "origin" }, .{ "Application", "Account site", "Website" }) |field, label| {
        frame.put(0, row, label, .muted);
        row += 1;
        const value = @field(review, field)[0..@field(review, field ++ "_len")];
        var offset: usize = 0;
        while (offset < value.len) {
            const take = @min(value.len - offset, frame.columns);
            frame.put(0, row, value[offset..][0..take], .accent);
            row += 1;
            offset += take;
        }
        row += 1;
    }
    frame.put(0, row, " Cancel ", if (!review.allow_selected) .selected else .body);
    frame.put(12, row, " Allow once ", if (review.allow_selected) .selected else .body);
    frame.put(0, frame.rows - 1, "Tab  Choose | Enter  Confirm | Esc  Cancel", .muted);
}

test "desktop view shows complete credential targets and acknowledges only sufficient scanout" {
    const std = @import("std");
    var session = compositor.Session.init();
    defer session.deinit();
    var authentication = @import("trusted_auth_entry.zig").View{};
    authentication.review = try @import("trusted_credential_review.zig").Review.init(&@as([64]u8, @splat('a')), &@as([64]u8, @splat('r')), &@as([95]u8, @splat('o')) ++ "z", 100);
    var trusted = @import("trusted_identity_entry.zig").View{ .authentication = &authentication };
    session.trusted_view = &trusted;
    var frame = try scanout.Frame.init(40, 20);
    render(&frame, &session, null);
    try expectText(&frame, 0, 5, &@as([40]u8, @splat('a')));
    try expectText(&frame, 0, 6, &@as([24]u8, @splat('a')));
    try expectText(&frame, 0, 9, &@as([40]u8, @splat('r')));
    try expectText(&frame, 0, 10, &@as([24]u8, @splat('r')));
    try expectText(&frame, 0, 13, &@as([40]u8, @splat('o')));
    try expectText(&frame, 0, 14, &@as([40]u8, @splat('o')));
    try expectText(&frame, 0, 15, &@as([15]u8, @splat('o')) ++ "z");
    try expectText(&frame, 0, 17, " Cancel ");
    try std.testing.expect(!authentication.review.presented);
    trusted.presented(40, 20, true);
    try std.testing.expect(authentication.review.presented);
    trusted.presented(40, 20, false);
    try std.testing.expect(!authentication.review.presented);
    frame = try scanout.Frame.init(40, 19);
    render(&frame, &session, null);
    trusted.presented(frame.columns, frame.rows, true);
    try std.testing.expect(!authentication.review.presented);
    try expectText(&frame, 0, 4, "More display space is needed.");
}

fn renderSetup(frame: *scanout.Frame, setup: *const @import("trusted_setup_entry.zig").View) void {
    if (frame.rows < 10 or frame.columns == 0) return;
    frame.fillRow(2, .selected);
    frame.put(1, 2, "Set up Zigos", .selected);
    if (setup.status == .record_recovery) {
        if (frame.columns < 39 or frame.rows < 14) {
            frame.put(0, 4, "More display space is needed.", .warning);
            frame.put(0, 6, "Press Esc to restart setup.", .body);
            return;
        }
        frame.put(0, 4, "Save all four lines outside this device:", .body);
        for (0..4) |line| frame.put(0, 6 + line, setup.recovery_code[line * 40 ..][0..39], .accent);
        frame.put(0, 11, "Keep this record private.", .body);
        frame.put(0, 12, "You will re-enter it to finish setup.", .muted);
        frame.put(0, frame.rows - 1, "Enter  Saved record  |  Esc  Cancel", .muted);
        return;
    }
    frame.put(0, 4, switch (setup.status) {
        .checking => "Checking your account...",
        .choose_pin => "Choose a PIN with 6 to 32 digits",
        .confirm_pin => "Re-enter your PIN",
        .preparing => "Creating your account...",
        .confirm_recovery => "Re-enter the recovery record you saved",
        .committing => "Finishing setup...",
        .cancelling => "Pausing setup...",
        .resume_setup => "Enter your saved recovery record",
        .complete => "Your account is ready.",
        .unavailable => "Setup is unavailable.",
        .record_recovery => unreachable,
    }, .body);
    const mask = &@as([@import("../services/identity_recovery_record.zig").CODE_BYTES]u8, @splat('*'));
    const count = @min(setup.characters, mask.len);
    var offset: usize = 0;
    var row: usize = 6;
    while (offset < count and row + 2 < frame.rows) : (row += 1) {
        const take = @min(count - offset, frame.columns);
        frame.put(0, row, mask[offset..][0..take], .accent);
        offset += take;
    }
    frame.put(0, @max(row + 1, 8), switch (setup.notice) {
        .none => "",
        .too_short => "Enter at least 6 digits.",
        .too_long => "Entry is too long. Try again.",
        .mismatch => "Entries did not match. Try again.",
        .invalid_record => "Check all 128 recovery characters.",
        .failed => "Setup could not finish. Try again.",
        .timeout => "Setup timed out. Please start again.",
        .interrupted => "Input was interrupted. Please try again.",
    }, .warning);
    frame.put(0, frame.rows - 1, switch (setup.status) {
        .checking => "Esc  Pause",
        .unavailable => "Enter  Retry  |  Ctrl+R  Resume saved setup",
        .preparing, .committing, .cancelling => "Esc  Pause setup",
        .complete => "Finishing your workspace...",
        else => "Enter  Continue  |  Esc  Clear  |  Ctrl+R  Resume",
    }, .muted);
}

test "desktop view confines recovery export to the native setup screen" {
    const std = @import("std");
    const record = @import("../services/identity_recovery_record.zig");
    var session = compositor.Session.init();
    defer session.deinit();
    var setup = @import("trusted_setup_entry.zig").View{ .status = .record_recovery };
    const retained = record.Record{ .trusted = .{ .object_id = 1001, .digest = @splat(8) }, .key = @splat(9) };
    try retained.format(&setup.recovery_code);
    var trusted = @import("trusted_identity_entry.zig").View{ .setup = &setup };
    session.trusted_view = &trusted;
    var frame = try scanout.Frame.init(60, 20);
    const app = Content{ .surface_id = 99, .text = "Private app content", .cursor = 0, .flags = .{ .active = true } };
    render(&frame, &session, app);
    try expectText(&frame, 1, 2, "Set up Zigos");
    for (0..4) |line| try expectText(&frame, 0, 6 + line, setup.recovery_code[line * 40 ..][0..39]);
    setup.status = .confirm_recovery;
    setup.characters = 128;
    render(&frame, &session, app);
    try expectText(&frame, 0, 6, &@as([60]u8, @splat('*')));
    try expectText(&frame, 0, 7, &@as([60]u8, @splat('*')));
    try expectText(&frame, 0, 8, &@as([8]u8, @splat('*')));
    for (frame.cells[9 * frame.columns ..][0..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    setup.status = .committing;
    setup.characters = 0;
    render(&frame, &session, app);
    for (frame.cells[6 * frame.columns ..][0 .. 4 * frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
}

test "desktop view gives trusted authentication exclusive masked chrome" {
    const std = @import("std");
    var session = compositor.Session.init();
    defer session.deinit();
    var authentication = @import("trusted_auth_entry.zig").View{ .status = .entering, .characters = 8 };
    var trusted = @import("trusted_identity_entry.zig").View{ .authentication = &authentication };
    session.trusted_view = &trusted;
    var frame = try scanout.Frame.init(60, 20);
    frame.put(0, 12, "Previous private document", .body);
    const app = Content{ .surface_id = 99, .text = "73019428", .cursor = 8, .flags = .{ .active = true } };
    render(&frame, &session, app);
    try expectText(&frame, 1, 2, "Unlock Zigos");
    try expectText(&frame, 0, 6, "********");
    for (frame.cells[12 * frame.columns ..][0..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    for (frame.cells[6 * frame.columns ..][8..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    authentication.status = .verifying;
    render(&frame, &session, app);
    try expectText(&frame, 0, 8, "Unlocking...");
    authentication.method = .recovery;
    authentication.characters = 56;
    render(&frame, &session, app);
    try expectText(&frame, 1, 2, "Recover Zigos");
    try expectText(&frame, 0, 6, &@as([56]u8, @splat('*')));
    try expectText(&frame, 0, 8, "Recovering...");
    authentication.status = .invalid_code;
    authentication.characters = 0;
    render(&frame, &session, app);
    try expectText(&frame, 0, 8, "Check your recovery key for typing errors.");
    for (frame.cells[6 * frame.columns ..][0..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
    authentication.status = .hidden;
    render(&frame, &session, app);
    try expectText(&frame, 0, 5, "No open tasks.");
    for (frame.cells[6 * frame.columns ..][0..frame.columns]) |cell| try std.testing.expectEqual(scanout.Cell{}, cell);
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
    var row_storage: [scanout.MAX_ROWS]abi.text_layout.Row = undefined;
    const window = layout.visibleWindow(caret, row_storage[0..viewport.rows]);
    const position = window.location;
    const anchor = selection_anchor orelse caret.offset;
    const selection_start = @min(anchor, caret.offset);
    const selection_end = @max(anchor, caret.offset);
    for (0..window.count) |index| {
        const row = window.rowAt(index);
        const cells = frame.cells[(start_row + index) * frame.columns ..][0..frame.columns];
        var clusters = abi.text_layout.unicode.Iterator{ .text = text[0..row.end], .offset = row.start };
        var column: usize = 0;
        while (clusters.next()) |cluster| {
            const width = @min(cluster.columns(column), frame.columns - column);
            frame.putCluster(column, start_row + index, text[cluster.start..cluster.end], width, if (cluster.start >= selection_start and cluster.start < selection_end) .selected else .body);
            column += width;
        }
        if (row.next > row.end and column < frame.columns and row.end >= selection_start and row.end < selection_end)
            cells[column].style = .selected;
        if (window.first_index + index == position.index) {
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

test "desktop row window keeps Unicode selection and cursor after repeated scrolling" {
    const std = @import("std");
    const line = "界e\u{301}\tZ\r\n";
    const text = @as([line.len * 30]u8, @bitCast(@as([30][line.len]u8, @splat(line.*)))) ++ "tail";
    var frame = try scanout.Frame.init(20, 10);
    drawText(&frame, 5, text, text.len, text.len - 4 - line.len + 3);
    const first = frame.cells[5 * frame.columns ..][0..frame.columns];
    try std.testing.expectEqual(@as(u21, '界'), first[0].character);
    try std.testing.expectEqual(.left, first[0].part);
    try std.testing.expectEqual(.right, first[1].part);
    try std.testing.expectEqual(scanout.Style.body, first[0].style);
    try std.testing.expectEqual(@as(u21, 'e'), first[2].character);
    try std.testing.expectEqualStrings("e\u{301}", frame.clusters[first[2].cluster_offset..][0..first[2].cluster_length]);
    try std.testing.expectEqual(@as(u21, ' '), first[3].character);
    try std.testing.expectEqual(@as(u21, 'Z'), first[4].character);
    for (first[2..6]) |cell| try std.testing.expectEqual(scanout.Style.selected, cell.style);
    try expectText(&frame, 0, 6, "tail");
    for (frame.cells[6 * frame.columns ..][0..4]) |cell| try std.testing.expectEqual(scanout.Style.selected, cell.style);
    try std.testing.expect(frame.cells[6 * frame.columns + 4].cursor);
    try std.testing.expectEqual(scanout.Style.body, frame.cells[6 * frame.columns + 4].style);

    frame.clear();
    drawText(&frame, 5, text, 0, null);
    try std.testing.expect(frame.cells[5 * frame.columns].cursor);
    for (frame.cells[5 * frame.columns .. 7 * frame.columns]) |cell| try std.testing.expectEqual(scanout.Style.body, cell.style);
    try std.testing.expect(!frame.cells[6 * frame.columns + 4].cursor);
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

test "desktop view keeps picker selection and controls visible on small displays" {
    const std = @import("std");
    const task_runtime = @import("../task/task_runtime.zig");
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{ .owner = .{ .kind = .app, .serial = 73 }, .component_class = .app_component, .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 65536, .endpoint_slots = 4, .shared_memory_bytes = 4096 }, .ui_surface_id = 33, .local_only = true });
    var session = compositor.Session.init();
    defer session.deinit();
    _ = try session.openTaskView(task, "Open document");
    var content = Content{ .surface_id = 33, .text = "a.md\nb.md\nc.md\nd.md\nOpen    Cancel", .cursor = 15, .model = .compositor, .flags = .{ .active = true }, .focus_index = 0 };
    var small = try scanout.Frame.init(20, 10);
    render(&small, &session, content);
    try expectText(&small, 0, 5, "d.md");
    try std.testing.expectEqual(scanout.Style.accent, small.cells[5 * small.columns].style);
    try expectText(&small, 0, 7, " Open ");
    try expectText(&small, 10, 7, " Cancel ");
    var large = try scanout.Frame.init(80, 20);
    render(&large, &session, content);
    try expectText(&large, 0, 5, "a.md");
    try expectText(&large, 0, 8, "d.md");
    try std.testing.expectEqual(scanout.Style.accent, large.cells[8 * large.columns].style);
    try expectText(&large, 0, 10, " Open ");
    content.text = "No documents available\nCancel";
    content.cursor = 0;
    content.focus_index = 1;
    render(&large, &session, content);
    try expectText(&large, 0, 7, " Cancel ");
    try std.testing.expectEqual(scanout.Style.selected, large.cells[7 * large.columns].style);
    try std.testing.expectEqual(@as(u21, ' '), large.cells[7 * large.columns + 10].character);
}

test "desktop document review renders all96 path bytes and denies incomplete or unsuccessful presentation" {
    const std = @import("std");
    const document = @import("trusted_document_view.zig");
    var session = compositor.Session.init();
    defer session.deinit();
    var runtime = @import("../task/task_runtime.zig").Runtime.init();
    const task = try runtime.createTask(.{ .owner = .{ .kind = .app, .serial = 91 }, .component_class = .app_component, .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 65536, .endpoint_slots = 4, .shared_memory_bytes = 4096 }, .ui_surface_id = 71, .local_only = true });
    _ = try session.openDocumentView(task, 7, "Ordinary application");
    var documents = document.View{ .phase = .review, .kind = .new, .token = 8, .allow_selected = true };
    documents.path = try document.Label.init(&@as([95]u8, @splat('a')) ++ "Z");
    var authentication = @import("trusted_auth_entry.zig").View{ .status = .hidden, .documents = &documents };
    var trusted = @import("trusted_identity_entry.zig").View{ .authentication = &authentication };
    session.trusted_view = &trusted;
    var frame = try scanout.Frame.init(40, 16);
    render(&frame, &session, .{ .surface_id = 71, .text = "@UNTRUSTED TASK CONTENT", .cursor = 0, .flags = .{ .active = true } });
    try expectText(&frame, 1, 2, "New Notes document");
    for (frame.cells[0 .. frame.columns * frame.rows]) |cell| try std.testing.expect(cell.character != '@');
    try expectText(&frame, 0, 4, "Application: Notes");
    try expectText(&frame, 0, 7, &@as([40]u8, @splat('a')));
    try expectText(&frame, 0, 8, &@as([40]u8, @splat('a')));
    try expectText(&frame, 0, 9, &@as([15]u8, @splat('a')) ++ "Z");
    try expectText(&frame, 0, 12, "Until lock or session timeout");
    try expectText(&frame, 0, 11, "Read and edit only this document");
    try expectText(&frame, 12, 13, " Allow ");
    try std.testing.expectEqual(scanout.Style.selected, frame.cells[13 * 40 + 12].style);
    try std.testing.expectEqual(@as(u64, 0), documents.presented_revision);
    try std.testing.expect(!documents.handle(.{ .kind = .activate }, 1));
    trusted.presented(frame.columns, frame.rows, false);
    try std.testing.expect(!documents.handle(.{ .kind = .activate }, 2));
    frame = try scanout.Frame.init(40, 15);
    render(&frame, &session, null);
    try expectText(&frame, 0, 4, "More display space is needed.");
    try expectText(&frame, 0, 6, "Esc  Cancel");
    trusted.presented(frame.columns, frame.rows, true);
    try std.testing.expect(!documents.handle(.{ .kind = .activate }, 3));
    frame = try scanout.Frame.init(40, 16);
    render(&frame, &session, null);
    trusted.presented(frame.columns, frame.rows, true);
    try std.testing.expect(documents.handle(.{ .kind = .activate }, 4));
    try std.testing.expect(documents.take().?.action == .approve);
}

test "desktop native picker preserves Unicode clusters and withholds document acknowledgement under authentication" {
    const std = @import("std");
    const document = @import("trusted_document_view.zig");
    var session = compositor.Session.init();
    defer session.deinit();
    var documents = document.View{ .phase = .browsing, .kind = .open, .token = 12, .count = 2, .selected = 1 };
    documents.paths[0] = try document.Label.init("草稿/é.md");
    documents.paths[1] = try document.Label.init(&@as([95]u8, @splat('p')) ++ "Q");
    var authentication = @import("trusted_auth_entry.zig").View{ .status = .hidden, .documents = &documents };
    var trusted = @import("trusted_identity_entry.zig").View{ .authentication = &authentication };
    session.trusted_view = &trusted;
    var frame = try scanout.Frame.init(40, 13);
    render(&frame, &session, null);
    try std.testing.expectEqual(@as(u21, '草'), frame.cells[4 * 40].character);
    try std.testing.expect(frame.cells[4 * 40].part == .left and frame.cells[4 * 40 + 1].part == .right);
    try std.testing.expectEqual(@as(u21, '稿'), frame.cells[4 * 40 + 2].character);
    const composed = frame.cells[4 * 40 + 5];
    try std.testing.expectEqual(@as(u21, 'e'), composed.character);
    try std.testing.expectEqualStrings("é", frame.clusters[composed.cluster_offset..][0..composed.cluster_length]);
    try expectText(&frame, 0, 6, &@as([40]u8, @splat('p')));
    try expectText(&frame, 0, 7, &@as([40]u8, @splat('p')));
    try expectText(&frame, 0, 8, &@as([15]u8, @splat('p')) ++ "Q");
    try std.testing.expectEqual(scanout.Style.selected, frame.cells[8 * 40 + 15].style);
    try expectText(&frame, 0, 11, "PgUp/PgDn  Browse | Enter  Open");
    trusted.presented(frame.columns, frame.rows, true);
    try std.testing.expectEqual(documents.revision, documents.presented_revision);
    authentication.status = .entering;
    render(&frame, &session, null);
    trusted.presented(frame.columns, frame.rows, true);
    try expectText(&frame, 1, 2, "Unlock Zigos");
    try std.testing.expectEqual(@as(u64, 0), documents.presented_revision);
    try std.testing.expect(!documents.handle(.{ .kind = .activate }, 1));
    authentication.status = .hidden;
    authentication.review = try @import("trusted_credential_review.zig").Review.init("Notes", "example.test", "https://example.test", 100);
    render(&frame, &session, null);
    trusted.presented(frame.columns, frame.rows, true);
    try std.testing.expectEqual(@as(u64, 0), documents.presented_revision);
    try std.testing.expect(!documents.handle(.{ .kind = .activate }, 2));
}
