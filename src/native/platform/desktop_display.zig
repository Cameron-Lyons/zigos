const builtin = @import("builtin");
const std = @import("std");
const compositor = @import("compositor_session.zig");
const view = @import("compositor_view.zig");
const document_view = @import("trusted_document_view.zig");
const trusted_identity = @import("trusted_identity_entry.zig");
const mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const abi = @import("../core/abi.zig");
const hardware = if (builtin.os.tag == .freestanding) @import("../../kernel/platform/framebuffer_hw.zig") else struct {};

// Everything the desktop composition reads while no native identity screen
// is visible. An equal key means the glass already shows this exact frame and
// the acknowledgement from its successful scanout still holds.
pub const FrameKey = struct {
    display_revision: u64,
    trusted_view: ?*const trusted_identity.View,
    trusted_kind: std.meta.Tag(trusted_identity.View),
    documents: ?*const document_view.View,
    documents_revision: u64,
    documents_phase: document_view.Phase,
    columns: usize,
    rows: usize,

    pub fn of(session: *const compositor.Session, columns: usize, rows: usize) FrameKey {
        const trusted: trusted_identity.View = if (session.trusted_view) |bound| bound.* else .none;
        const documents: ?*const document_view.View = switch (trusted) {
            .authentication => |authentication| authentication.documents,
            else => null,
        };
        return .{
            .display_revision = session.display_revision,
            .trusted_view = session.trusted_view,
            .trusted_kind = trusted,
            .documents = documents,
            .documents_revision = if (documents) |state| state.revision else 0,
            .documents_phase = if (documents) |state| state.phase else .disabled,
            .columns = columns,
            .rows = rows,
        };
    }
};

// Boot CPU only, like every compositor mutation.
var shown: ?FrameKey = null;
var presented_once = false;

pub fn hasPresented() bool {
    return presented_once;
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
// An unchanged desktop frame costs one key comparison.
pub fn present(session: *const compositor.Session) void {
    if (comptime builtin.os.tag != .freestanding) return;
    const frame = hardware.frame() orelse {
        if (session.trusted_view) |trusted| trusted.presented(0, 0, false);
        return;
    };
    if (session.trusted_view) |trusted| if (trusted.visible()) {
        // Entry keystrokes never touch the session, so native identity
        // screens always recompose and the desktop frame must be redrawn.
        shown = null;
        trusted.presented(0, 0, false);
        view.render(frame, session, null);
        if (!scanOut()) return;
        trusted.presented(frame.columns, frame.rows, true);
        return;
    };
    const key = FrameKey.of(session, frame.columns, frame.rows);
    if (shown) |previous| if (std.meta.eql(previous, key)) return;
    shown = null;
    if (session.trusted_view) |trusted| trusted.presented(0, 0, false);
    view.render(frame, session, activeContent(session) catch return);
    if (!scanOut()) return;
    if (session.trusted_view) |trusted| trusted.presented(frame.columns, frame.rows, true);
    shown = key;
}

fn scanOut() bool {
    const result = hardware.present() catch return false;
    if (result.pixels_written != 0) presented_once = true;
    return true;
}

fn activeContent(session: *const compositor.Session) error{InvalidSurfaceText}!?view.Content {
    const window = session.activeWindow() orelse return null;
    const surface = session.surfacePresentation(window.ui_surface_id orelse 0) orelse return null;
    if (surface.task_id != window.subject_task_id) return null;
    const text = &(surface.text orelse return null);
    return .{
        .surface_id = surface.presentation.surface_id,
        .text = text.textSlice(),
        .cursor = text.cursor,
        .selection_anchor = text.state.selection_anchor,
        .cursor_upstream = text.state.cursor_upstream,
        .flags = @bitCast(text.state.flags),
        .window_id = text.window_id,
        .model = std.enums.fromInt(mailbox.UiModelKind, text.state.model) orelse return error.InvalidSurfaceText,
        .focus_index = text.state.focus_index,
        .save_state = std.enums.fromInt(abi.DocumentSaveState, text.state.save_state) orelse return error.InvalidSurfaceText,
    };
}

fn testTask(runtime: *@import("../task/task_runtime.zig").Runtime, surface_id: u64) !*@import("../task/task_runtime.zig").TaskRecord {
    return runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = surface_id },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 1024, .endpoint_slots = 2, .shared_memory_bytes = 1024 },
        .ui_surface_id = surface_id,
        .local_only = true,
    });
}

test "desktop frame key changes with every drawn session and trusted view input" {
    var runtime = @import("../task/task_runtime.zig").Runtime.init();
    const task = try testTask(&runtime, 41);
    const other = try testTask(&runtime, 42);
    var session = compositor.Session.init();
    defer session.deinit();

    var key = FrameKey.of(&session, 80, 25);
    try std.testing.expect(std.meta.eql(key, FrameKey.of(&session, 80, 25)));
    try std.testing.expect(!std.meta.eql(key, FrameKey.of(&session, 80, 24)));
    const Step = struct {
        fn changed(previous: *FrameKey, current: *const compositor.Session) !void {
            const next = FrameKey.of(current, 80, 25);
            try std.testing.expect(!std.meta.eql(previous.*, next));
            previous.* = next;
        }
    };

    const window = try session.openTaskView(task, "Notes");
    try Step.changed(&key, &session);
    const second = try session.openDocumentView(other, 7, "notes.md");
    try Step.changed(&key, &session);
    _ = try session.switchView(window.id);
    try Step.changed(&key, &session);
    _ = try session.switchVisible(.next);
    try Step.changed(&key, &session);

    var presentation = abi.SurfacePresentation{ .surface_id = 41, .revision = 1 };
    var text = abi.SurfaceText{ .window_id = window.id, .state = .{ .model = 1 } };
    try std.testing.expectEqual(compositor.PresentResult.accepted, try session.presentSurfaceText(task, &presentation, &text));
    try Step.changed(&key, &session);
    try std.testing.expectEqual(compositor.PresentResult.duplicate, try session.presentSurfaceText(task, &presentation, &text));
    try std.testing.expect(std.meta.eql(key, FrameKey.of(&session, 80, 25)));
    presentation.revision = 2;
    text.text_length = 1;
    text.cursor = 1;
    text.state.selection_anchor = 1;
    text.text[0] = 'a';
    try std.testing.expectEqual(compositor.PresentResult.accepted, try session.presentKernelValidatedSurfaceText(task, &presentation, &text));
    try Step.changed(&key, &session);

    const bundle = @import("../policy/manifest.zig").BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.local",
    };
    const review = try session.beginPermissionReview(9, other, bundle);
    try Step.changed(&key, &session);
    const request = @import("../policy/manifest.zig").PermissionRequest{
        .kind = .object_access,
        .resource = "ws:notes",
        .rights = .{ .object = .{ .object_read = true } },
    };
    _ = try session.ensureReviewItem(review.id, bundle, request);
    try Step.changed(&key, &session);
    _ = try session.ensureReviewItem(review.id, bundle, request);
    try std.testing.expect(std.meta.eql(key, FrameKey.of(&session, 80, 25)));
    _ = try session.recordDecision(review.id, request, true, true, null);
    try Step.changed(&key, &session);

    var snapshot: compositor.SessionSnapshot = undefined;
    session.snapshotInto(&snapshot);
    try std.testing.expect(session.closeWindow(second.id));
    try Step.changed(&key, &session);
    try session.restoreFromSnapshot(&snapshot);
    try Step.changed(&key, &session);
    try std.testing.expect(try runtime.terminateTask(task.id, 10));
    try std.testing.expectEqual(@as(usize, 1), session.pruneSurfacePresentations(&runtime));
    try Step.changed(&key, &session);

    var documents = document_view.View{ .phase = .home, .token = 3 };
    var authentication = @import("trusted_auth_entry.zig").View{ .documents = &documents };
    var trusted: trusted_identity.View = .{ .authentication = &authentication };
    session.setTrustedView(&trusted);
    try Step.changed(&key, &session);
    documents.touch();
    try Step.changed(&key, &session);
    documents.phase = .disabled;
    try Step.changed(&key, &session);
    authentication.documents = null;
    try Step.changed(&key, &session);
    trusted = .none;
    try Step.changed(&key, &session);
    session.setTrustedView(null);
    try Step.changed(&key, &session);
    session.reset();
    try Step.changed(&key, &session);
}
