const builtin = @import("builtin");
const std = @import("std");
const compositor = @import("compositor_session.zig");
const view = @import("compositor_view.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const abi = @import("../core/abi.zig");
const hardware = if (builtin.os.tag == .freestanding) @import("../../kernel/platform/framebuffer_hw.zig") else struct {};

pub fn hasPresented() bool {
    if (comptime builtin.os.tag != .freestanding) return false;
    return hardware.totalPixelWrites() != 0;
}

pub fn inputViewport(session: *const compositor.Session, event: abi.InputEventDescriptor) abi.text_layout.Viewport {
    if (comptime builtin.os.tag != .freestanding) return .{};
    const frame = hardware.frame() orelse return .{};
    const window = session.findWindowConst(event.window_id) orelse return .{};
    if (window.subject_task_id != event.task_id or window.ui_surface_id != event.surface_id or window.item_count != 0) return .{};
    return view.textViewport(frame.columns, frame.rows, view.DOCUMENT_START_ROW);
}

// The native text compositor owns the firmware framebuffer. Snapshot lookup
// never borrows task memory, and the renderer writes only damaged text cells.
pub fn present(session: *const compositor.Session) bool {
    if (comptime builtin.os.tag != .freestanding) return false;
    const frame = hardware.frame() orelse {
        if (session.trusted_view) |trusted| trusted.presented(0, 0, false);
        return false;
    };
    if (session.trusted_view) |trusted| {
        if (trusted.visible()) {
            view.render(frame, session, null);
            trusted.presented(0, 0, false);
            const result = hardware.present() catch return false;
            trusted.presented(frame.columns, frame.rows, true);
            return result.pixels_written != 0;
        }
    }
    var content: ?view.Content = null;
    if (session.activeWindow()) |window| {
        if (session.surfacePresentation(window.ui_surface_id orelse 0)) |surface| {
            if (surface.task_id == window.subject_task_id) {
                if (surface.text) |*text| {
                    content = .{
                        .surface_id = surface.presentation.surface_id,
                        .text = text.textSlice(),
                        .cursor = text.cursor,
                        .selection_anchor = text.state.selection_anchor,
                        .cursor_upstream = text.state.cursor_upstream,
                        .flags = @bitCast(text.state.flags),
                        .window_id = text.window_id,
                        .model = std.enums.fromInt(mailbox.UiModelKind, text.state.model) orelse return false,
                        .focus_index = text.state.focus_index,
                        .save_state = std.enums.fromInt(abi.DocumentSaveState, text.state.save_state) orelse return false,
                    };
                }
            }
        }
    }
    view.render(frame, session, content);
    const result = hardware.present() catch return false;
    return result.pixels_written != 0;
}
