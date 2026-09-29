const std = @import("std");
const abi = @import("../../core/abi.zig");
const mailbox_abi = @import("../../task/userspace_bootstrap_mailbox.zig");
const protocol = @import("../../../userspace/document_protocol.zig");
const ids = @import("../../core/ids.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const userspace_launch = @import("../../task/userspace_launch.zig");
const userspace_executor = @import("../../task/userspace_executor.zig");
const document_sessions = @import("../document_sessions.zig");
const object_signer = @import("../../storage/sealed_object_signer.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");
const paging = @import("../../../kernel/memory/paging64.zig");
const framebuffer = @import("../../../kernel/platform/framebuffer_hw.zig");
const xhci = @import("../../../kernel/drivers/xhci.zig");
const common = @import("../../../kernel/boot/common.zig");
const timer = @import("../../../kernel/timer/timer.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");

const path = "documents/notes.md";
const sibling_path = "documents/notes-sibling.md";
const sibling_text = "Second editor";
const signer = signing.SignerIdentity{ .label = "document-channel-proof", .seed = signing.seedFromByte(0xD1) };
var report_cursor: u8 = 0;
var report_sequence: u64 = 0;
var report_usage: u8 = 0x04;
var report_modifiers: u8 = 0;
var report_keys: [6]u8 = [_]u8{0} ** 6;
var report_mode: enum { edit, open, cancel, key } = .edit;
const cursor_edited_text = "aS\ncond editorb";
const selection_edited_text = "Q\nb";
const undo_edited_text = selection_edited_text ++ "u";

const EditorSession = struct {
    task_id: u64,
    surface_id: u64,
    window_id: u64,
    binding: mailbox_abi.DocumentBinding,
    document_capability_id: u64,
};

// Verification-only modeled HID input; every app operation below executes in
// the generated Notes ELF through the ordinary input and endpoint syscalls.
pub fn run(manager: anytype, graph: anytype, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    var signing_fixture = @import("../../../tests/fixtures/document_signer.zig").Fixture{};
    const document_key = try signing_fixture.initWithClipboard(graph.state.ids.session_user, storage.owner, storage.task_id, signer, true);
    const original = try storage.resolve(workspace_id, path);
    const version = storage.version(original.version_id.raw()) orelse return error.MissingVersion;
    const payload = try storage.versionPayload(version);
    if (payload.len >= protocol.MAX_DOCUMENT_BYTES) return error.DocumentTooLarge;
    var expected: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined;
    @memcpy(expected[0..payload.len], payload);
    const original_length = payload.len;
    expected[original_length] = 'a';

    const sibling = try storage.putVersion(.{
        .object_type = .document,
        .payload = sibling_text,
        .metadata = try object_store.signMetadata(signer, "Sibling document", "text/plain", .document, sibling_text, 0),
    });
    try storage.beginTransaction(workspace_id);
    errdefer storage.abortTransaction(workspace_id) catch {};
    try storage.stagePut(workspace_id, sibling_path, sibling.object_id, sibling.version_id, .document);
    _ = try storage.commit(workspace_id, 0);

    // Exceed the shared stack-slot limit: failed activation must make the
    // slot reusable while sibling tasks keep the Notes address space alive.
    for (0..40) |_| try expectLaunchRollback(manager, graph, workspace_id, document_key);
    common.printBootMarker(boot_markers.document_channel_launch_rollback);

    const input = manager.inputRouterPtr();
    const previous_source = input.source;
    input.bindHardwareSource(.{ .poll_report = nextReport, .input_proof = noHardwareProof });
    defer {
        if (previous_source) |source| input.bindHardwareSource(source) else input.clearHardwareSource();
    }
    try cancelFromCompositor(manager, graph, workspace_id, document_key);
    try browseFromCompositor(manager, graph, workspace_id, document_key);
    // Open executes in the already-running compositor ELF. The Notes tasks
    // share image and page tables, but retain independent editor state.
    const first = try openFromCompositor(manager, graph, workspace_id, document_key);
    defer retireEditor(manager, first);
    const second = try openEditor(manager, graph, workspace_id, sibling_path, 0xD0C2, document_key);
    defer retireEditor(manager, second);
    try awaitPresentation(manager, first, expected[0..original_length], 0);
    try awaitPresentation(manager, second, sibling_text, 0);
    // A running editor's mailbox cannot be overwritten by another open.
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.capabilityTablePtr(), first.task_id, first.binding, .{}, 0)) return error.RunningMailboxRebound;
    common.printBootMarker(boot_markers.document_channel_userspace_open);

    const checkpoint_generation = storage.checkpoint_store.last_checkpoint_generation;
    try editAndSave(manager, first, 0x04);
    try awaitPresentation(manager, first, expected[0 .. original_length + 1], 1);
    try expectStored(manager, workspace_id, path, expected[0 .. original_length + 1], original.version_id.raw());
    if (storage.pendingCheckpointMutations() or storage.checkpoint_store.last_checkpoint_error != null or
        storage.checkpoint_store.last_checkpoint_generation <= checkpoint_generation) return error.SaveNotDurable;
    common.printBootMarker(boot_markers.document_channel_userspace_save);
    common.printBootMarker(boot_markers.document_surface_pixels);

    try editAndSave(manager, second, 0x05);
    try awaitPresentation(manager, second, sibling_text ++ "b", 1);
    try expectStored(manager, workspace_id, sibling_path, sibling_text ++ "b", sibling.version_id.raw());
    try awaitPresentation(manager, first, expected[0 .. original_length + 1], 1);
    try expectStored(manager, workspace_id, path, expected[0 .. original_length + 1], original.version_id.raw());

    try clipboardBetweenEditors(manager, first, second, expected[0 .. original_length + 1]);
    try visualNavigation(manager, graph, workspace_id, document_key);
    try unicodeDocument(manager, graph, workspace_id, document_key, second);
    _ = try manager.compositorSessionPtr().switchView(second.window_id);
    try expectChannelRetired(manager, first);
    const frames_before_retirement = paging.frameStats();
    retireEditor(manager, first);
    const frames_after_retirement = paging.frameStats();
    if (frames_after_retirement.free <= frames_before_retirement.free) return error.EditorStackPagesNotReclaimed;
    // Retiring the first mapping must leave the sibling's editor usable.
    try editAndSave(manager, second, 0x06);
    try awaitPresentation(manager, second, sibling_text ++ "bc", 2);
    try expectStored(manager, workspace_id, sibling_path, sibling_text ++ "bc", sibling.version_id.raw());
    try editAtCursorAndSave(manager, second, workspace_id);
    try selectAndSave(manager, second, workspace_id);
    try undoAndSave(manager, second, workspace_id);
    try expectBatchedInputAndSourceRestart(manager, second);
    try expectHeldInput(manager, second);
    common.printBootMarker(boot_markers.document_channel_sibling_editors);
    try expectDeniedSave(manager, second, workspace_id);
    common.printBootMarker(boot_markers.document_save_feedback);
    try expectChannelRetired(manager, second);
    common.printBootMarker(boot_markers.document_channel_retirement);
}

const PreparedEditor = struct {
    task_id: u64,
    surface_id: u64,
    request: document_sessions.OpenRequest,
};

fn chooseOffer(manager: anytype, prepared: PreparedEditor, cancel: bool) !void {
    const label = path;
    _ = try manager.offerDocumentPicker(@import("../document_launcher.zig").Request.fromDocument(prepared.request), timer.getTicks());
    const window_id = manager.compositorSessionPtr().active_window_id;
    const compositor_task_id = manager.inputRouterPtr().compositor_task_id;
    var ready = false;
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        if (manager.userspaceSchedulerPtr().taskDispatchStats(prepared.task_id) != null) return error.EditorScheduledBeforeChoice;
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), compositor_task_id) orelse continue;
        if (state.launcherBinding().isValid() and state.ui_focus_index == 0 and
            state.ui_presented_revision == state.ui_state_revision and
            std.mem.eql(u8, &state.ui_text_digest, &protocol.digest(label ++ "\nOpen    Cancel")))
        {
            ready = true;
            break;
        }
    }
    if (!ready) return error.LaunchOfferNotPresented;
    if (!framebuffer.verifyText(0, 5, label) or !framebuffer.verifyText(0, 7, " Open ") or
        !framebuffer.verifyText(10, 7, " Cancel ")) return error.LaunchOfferPixelsMissing;
    if (manager.compositorSessionPtr().active_window_id != window_id) return error.LaunchOfferLostFocus;
    report_mode = if (cancel) .cancel else .open;
    report_cursor = 0;
    if (manager.servicePendingInputWork(timer.getTicks()) != @as(usize, if (cancel) 2 else 1)) return error.LaunchInputNotRouted;
}

fn browseFromCompositor(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer) !void {
    const names = [_][]const u8{ "0-picker/a.md", "0-picker/b.md", "0-picker/c.md", "0-picker/d.md", "0-picker/e.md", "0-picker/f.md" };
    const storage = manager.storageServicePtr();
    try storage.beginTransaction(workspace_id);
    errdefer storage.abortTransaction(workspace_id) catch {};
    for (names) |name| {
        const stored = try storage.putVersion(.{ .object_type = .document, .payload = name, .metadata = try document_key.signMetadata("Picker document", name, timer.getTicks()) });
        try storage.stagePut(workspace_id, name, stored.object_id, stored.version_id, .document);
    }
    _ = try storage.commit(workspace_id, timer.getTicks());
    // A fixture provisions the same workspace grant a permission decision would.
    // The production picker itself cannot create grants or signing authority.
    const prepared = try prepareEditor(manager, graph, workspace_id, names[5], 0xD0C5, document_key);
    errdefer manager.cancelPreparedDocumentTask(prepared.task_id, timer.getTicks()) catch {};
    try storage.shareWorkspace(workspace_id, .{ .principal_id = prepared.request.authority.principal, .can_read = true, .can_write = true, .expires_at_ticks = std.math.maxInt(u64), .network_scope = .local_only });
    _ = try manager.offerDocumentPicker(@import("../document_launcher.zig").Request.fromDocument(prepared.request), timer.getTicks());
    const first_page = "0-picker/a.md\n0-picker/b.md\n0-picker/c.md\n0-picker/d.md\nOpen    Cancel";
    const second_page = "0-picker/e.md\n0-picker/f.md\ndocuments/notes-sibling.md\ndocuments/notes.md\nOpen    Cancel";
    try awaitPicker(manager, prepared, first_page, 0);
    try pickerKey(manager, 0x4e); // Page Down
    try awaitPicker(manager, prepared, second_page, 0);
    try pickerKey(manager, 0x4b); // Page Up
    try awaitPicker(manager, prepared, first_page, 0);
    try pickerKey(manager, 0x4e);
    try awaitPicker(manager, prepared, second_page, 0);
    try pickerKey(manager, 0x51); // Down selects the second row.
    try awaitPicker(manager, prepared, second_page, 14);
    if (!framebuffer.verifyText(0, 6, names[5])) return error.PickerSelectionPixelsMissing;
    const frame = framebuffer.frame() orelse return error.PickerSelectionPixelsMissing;
    if (frame.cells[6 * frame.columns].style != .accent) return error.PickerSelectionPixelsMissing;
    try pickerKey(manager, 0x28);
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), prepared.task_id) orelse continue;
        const binding = state.documentBinding();
        if (!binding.isValid()) continue;
        const window = manager.compositorSessionPtr().activeWindow() orelse continue;
        if (window.subject_task_id != prepared.task_id) continue;
        const selected = try storage.resolve(workspace_id, names[5]);
        if (binding.object_id != selected.object_id.raw() or binding.version_id != selected.version_id.raw()) return error.PickerOpenedWrongDocument;
        const editor = EditorSession{ .task_id = prepared.task_id, .surface_id = prepared.surface_id, .window_id = window.id, .binding = binding, .document_capability_id = prepared.request.authority.capability_id };
        defer retireEditor(manager, editor);
        try awaitPresentation(manager, editor, names[5], 0);
        for (0..32) |_| _ = manager.runUserspaceScheduler(timer.getTicks());
        common.printBootMarker(boot_markers.document_picker_userspace);
        return;
    }
    return error.PickerOpenTimedOut;
}

fn awaitPicker(manager: anytype, prepared: PreparedEditor, text: []const u8, cursor: u16) !void {
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        if (manager.userspaceSchedulerPtr().taskDispatchStats(prepared.task_id) != null) return error.EditorScheduledBeforeChoice;
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.inputRouterPtr().compositor_task_id) orelse continue;
        if (state.ui_cursor == cursor and state.ui_presented_revision == state.ui_state_revision and
            std.mem.eql(u8, &state.ui_text_digest, &protocol.digest(text)))
        {
            const first = std.mem.indexOfScalar(u8, text, '\n') orelse unreachable;
            if (!framebuffer.verifyText(0, 5, text[0..first])) return error.PickerPagePixelsMissing;
            return;
        }
    }
    return error.PickerPageNotPresented;
}

fn pickerKey(manager: anytype, usage: u8) !void {
    report_mode = .key;
    report_cursor = 0;
    report_usage = usage;
    report_modifiers = 0;
    report_keys = @splat(0);
    if (manager.servicePendingInputWork(timer.getTicks()) != 1) return error.PickerInputNotRouted;
}

fn openFromCompositor(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer) !EditorSession {
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C1, document_key);
    errdefer manager.cancelPreparedDocumentTask(prepared.task_id, timer.getTicks()) catch {};
    try chooseOffer(manager, prepared, false);
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), prepared.task_id) orelse continue;
        const binding = state.documentBinding();
        if (!binding.isValid()) continue;
        const window = manager.compositorSessionPtr().findWindow(manager.compositorSessionPtr().active_window_id) orelse continue;
        if (window.subject_task_id != prepared.task_id) continue;
        common.printBootMarker(boot_markers.document_launcher_userspace_open);
        return .{ .task_id = prepared.task_id, .surface_id = prepared.surface_id, .window_id = window.id, .binding = binding, .document_capability_id = prepared.request.authority.capability_id };
    }
    return error.LaunchDecisionTimedOut;
}

fn cancelFromCompositor(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer) !void {
    const compositor = manager.compositorSessionPtr();
    const windows_before = compositor.window_count;
    const focus_before = compositor.active_window_id;
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C5, document_key);
    const address_space_id = manager.runtimePtr().find(prepared.task_id).?.address_space_id;
    try chooseOffer(manager, prepared, true);
    var selected_cancel_seen = false;
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        if (framebuffer.frame()) |frame| {
            if (frame.cells[7 * frame.columns + 10].style == .selected and framebuffer.verifyText(10, 7, " Cancel ")) selected_cancel_seen = true;
        }
        if (manager.runtimePtr().find(prepared.task_id)) |task| if (task.state != .terminated) continue;
        if (manager.runtimePtr().findAddressSpaceConst(address_space_id) != null or
            manager.userspaceSchedulerPtr().taskDispatchStats(prepared.task_id) != null or
            compositor.window_count != windows_before or compositor.active_window_id != focus_before) return error.CancelledOfferLeaked;
        if (!selected_cancel_seen) return error.CancelSelectionPixelsMissing;
        // Deliver the receipt before publishing the next offer.
        for (0..32) |_| _ = manager.runUserspaceScheduler(timer.getTicks());
        common.printBootMarker(boot_markers.document_launcher_userspace_cancel);
        return;
    }
    return error.CancelDecisionTimedOut;
}

fn openEditor(manager: anytype, graph: anytype, workspace_id: u64, document_path: []const u8, surface_id: u64, document_key: object_signer.Signer) !EditorSession {
    const prepared = try prepareEditor(manager, graph, workspace_id, document_path, surface_id, document_key);
    const launched = try manager.activateDocumentTask(prepared.request, 0);
    if (manager.focusedInputCapabilityForTask(launched.task_id, 0) == null or
        manager.surfacePresentationCapabilityForTask(launched.task_id, 0) == null) return error.InitialUiAuthorityMissing;
    const stats = manager.userspaceSchedulerPtr().taskDispatchStats(launched.task_id) orelse return error.EditorNotScheduled;
    if (!stats.queued_ready or stats.dispatch_count != 0) return error.EditorDispatchedBeforeActivation;
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.capabilityTablePtr(), launched.task_id, launched.binding, .{}, 0)) return error.PreparedMailboxRebound;
    return .{ .task_id = launched.task_id, .surface_id = surface_id, .window_id = launched.window_id, .binding = launched.binding, .document_capability_id = prepared.request.authority.capability_id };
}

fn prepareEditor(manager: anytype, graph: anytype, workspace_id: u64, document_path: []const u8, surface_id: u64, document_key: object_signer.Signer) !PreparedEditor {
    const storage = manager.storageServicePtr();
    const runtime = manager.runtimePtr();
    const capabilities = manager.capabilityTablePtr();
    const original = try storage.resolve(workspace_id, document_path);
    const owner = principal.PrincipalId{ .kind = .app, .serial = surface_id };
    const task = try userspace_launch.prepareRegisteredDirect(manager.userspaceCatalogPtr(), runtime, "app.notes", .{
        .owner = owner,
        .budget = .{ .cpu_time_ticks = 1_000_000, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = surface_id,
    });
    const task_id = task.id;
    errdefer {
        const now_ticks = timer.getTicks();
        manager.documents.closeTask(task_id, now_ticks);
        _ = manager.compositorSessionPtr().closeWindowsForTask(task_id);
        _ = runtime.terminateTask(task_id, now_ticks) catch false;
        _ = manager.inputRouterPtr().dropForTask(task_id);
    }
    const bootstrap = try capabilities.mintBootRoot(.{
        .holder = owner,
        .issuer = graph.state.ids.policy_authority,
        .target = .{ .kind = .service, .id = storage.service_id },
        .rights = .{ .service = .{ .endpoint_create = true, .time_query = true, .resource_query = true, .accounting_query = true } },
        .scope = .{ .task_id = task_id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
    });
    try runtime.grantCapability(task_id, bootstrap.id);
    const document = try capabilities.mintBootRoot(.{
        .holder = owner,
        .issuer = graph.state.ids.policy_authority,
        .target = .{ .kind = .workspace, .id = workspace_id },
        .rights = .{ .workspace = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = task_id, .workspace_id = workspace_id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
    });
    try runtime.grantCapability(task_id, document.id);
    try storage.shareWorkspace(workspace_id, try (workspace.ShareGrant{
        .principal_id = owner,
        .can_read = true,
        .can_write = true,
        .expires_at_ticks = std.math.maxInt(u64),
        .network_scope = .local_only,
    }).withObjectScope(original.object_id, document_path));
    const service = runtime.find(storage.task_id) orelse return error.ServiceMissing;
    const service_authority = userspace_executor.resolveMailboxAuthorities(service, capabilities, 0).bootstrap_capability_id;
    if (manager.userspaceSchedulerPtr().taskDispatchStats(task_id) != null) return error.EditorScheduledBeforeSetup;
    return .{ .task_id = task_id, .surface_id = surface_id, .request = .{
        .authority = .{ .task_id = task_id, .principal = owner, .capability_id = document.id, .now_ticks = 0 },
        .client_bootstrap_capability_id = bootstrap.id,
        .server_bootstrap_capability_id = service_authority,
        .workspace_id = workspace_id,
        .path = document_path,
        .signer = document_key,
    } };
}

fn expectLaunchRollback(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer) !void {
    const runtime = manager.runtimePtr();
    const capabilities = manager.capabilityTablePtr();
    const endpoints = manager.kernelPort().?.kernel.endpoint_table;
    const compositor = manager.compositorSessionPtr();
    const grants_before = capabilities.activeCount();
    const endpoints_before = endpoints.activeCount();
    const windows_before = compositor.window_count;
    const focus_before = compositor.active_window_id;
    const active_before = runtime.countTasksInState(.active);
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C3, document_key);
    const address_space_id = runtime.find(prepared.task_id).?.address_space_id;
    const scheduler = manager.userspaceSchedulerPtr();
    // Force rejection at the final publish step, after real channel endpoints,
    // mailbox pages, the window, and task-scoped UI grants have been created.
    scheduler.initialized = false;
    const failure = failure: {
        defer scheduler.initialized = true;
        _ = manager.activateDocumentTask(prepared.request, 0) catch |err| break :failure err;
        return error.SchedulerRejectionMissing;
    };
    if (failure != error.SchedulerUnavailable) return failure;
    if (runtime.find(prepared.task_id).?.state != .terminated or
        runtime.findAddressSpaceConst(address_space_id) != null or
        scheduler.taskDispatchStats(prepared.task_id) != null or
        runtime.countTasksInState(.active) != active_before or
        capabilities.activeCount() != grants_before or endpoints.activeCount() != endpoints_before or
        compositor.window_count != windows_before or compositor.active_window_id != focus_before) return error.DocumentLaunchResourcesLeaked;
}

fn retireEditor(manager: anytype, editor: EditorSession) void {
    const now_ticks = timer.getTicks();
    manager.clipboard.closeTask(editor.task_id, now_ticks);
    manager.documents.closeTask(editor.task_id, now_ticks);
    _ = manager.compositorSessionPtr().closeWindowsForTask(editor.task_id);
    _ = manager.runtimePtr().terminateTask(editor.task_id, now_ticks) catch false;
    _ = manager.inputRouterPtr().dropForTask(editor.task_id);
}

fn editAndSave(manager: anytype, editor: EditorSession, usage: u8) !void {
    _ = try manager.compositorSessionPtr().switchView(editor.window_id);
    report_cursor = 0;
    report_mode = .edit;
    report_usage = usage;
    if (manager.servicePendingInputWork(timer.getTicks()) != 2) return error.InputNotRouted;
    try awaitSaving(manager, editor);
}

fn awaitSaving(manager: anytype, editor: EditorSession) !void {
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const surface = manager.compositorSessionPtr().surfacePresentation(editor.surface_id) orelse continue;
        const text = if (surface.text) |*value| value else continue;
        if (text.state.save_state != @intFromEnum(abi.DocumentSaveState.saving)) continue;
        const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
        if (!framebuffer.verifyText(0, frame.rows - 2, "Saving...")) return error.SavingPixelsMissing;
        return;
    }
    return error.SavingStateMissing;
}

fn editAtCursorAndSave(manager: anytype, editor: EditorSession, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    const before = try storage.resolve(workspace_id, sibling_path);
    const checkpoint = storage.checkpoint_store.last_checkpoint_generation;
    try pressCursorKey(manager, editor, 0x4A, 1, sibling_text ++ "bc", 0, false);
    try pressCursorKey(manager, editor, 0x4F, 0, sibling_text ++ "bc", 1, false);
    try pressCursorKey(manager, editor, 0x1B, 0, "Sxecond editorbc", 2, true);
    try pressCursorKey(manager, editor, 0x4C, 0, "Sxcond editorbc", 2, true);
    try pressCursorKey(manager, editor, 0x2A, 0, "Scond editorbc", 1, true);
    try pressCursorKey(manager, editor, 0x28, 0, "S\ncond editorbc", 2, true);
    try pressCursorKey(manager, editor, 0x52, 0, "S\ncond editorbc", 0, true);
    try pressCursorKey(manager, editor, 0x04, 0, "aS\ncond editorbc", 1, true);
    try pressCursorKey(manager, editor, 0x51, 0, "aS\ncond editorbc", 4, true);
    try pressCursorKey(manager, editor, 0x4A, 0, "aS\ncond editorbc", 3, true);
    try pressCursorKey(manager, editor, 0x4D, 0, "aS\ncond editorbc", 16, true);
    try pressCursorKey(manager, editor, 0x50, 0, "aS\ncond editorbc", 15, true);
    try pressCursorKey(manager, editor, 0x4C, 0, cursor_edited_text, 15, true);
    try pressCursorKey(manager, editor, 0x4D, 1, cursor_edited_text, 15, true);
    const staged = try storage.resolve(workspace_id, sibling_path);
    if (staged.version_id.raw() != before.version_id.raw() or
        storage.checkpoint_store.last_checkpoint_generation != checkpoint) return error.CursorEditSavedWithoutRequest;
    // Commit only after all in-place edits have reached the owned surface.
    report_cursor = 0;
    report_mode = .key;
    report_usage = 0x28;
    report_modifiers = 1;
    if (manager.servicePendingInputWork(timer.getTicks()) != 1) return error.CursorInputNotRouted;
    try awaitSaving(manager, editor);
    try awaitPresentation(manager, editor, cursor_edited_text, 3);
    try expectStored(manager, workspace_id, sibling_path, cursor_edited_text, before.version_id.raw());
    if (storage.checkpoint_store.last_checkpoint_generation <= checkpoint) return error.CursorSaveNotDurable;
}

fn pressCursorKey(manager: anytype, editor: EditorSession, usage: u8, modifiers: u8, expected: []const u8, cursor: u16, dirty: bool) !void {
    try pressSelectionKey(manager, editor, usage, modifiers, expected, cursor, cursor, dirty);
}

fn selectAndSave(manager: anytype, editor: EditorSession, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    const before = try storage.resolve(workspace_id, sibling_path);
    const checkpoint = storage.checkpoint_store.last_checkpoint_generation;
    try pressCursorKey(manager, editor, 0x4A, 1, cursor_edited_text, 0, false);
    try pressSelectionKey(manager, editor, 0x4D, 2, cursor_edited_text, 2, 0, false);
    try pressCursorKey(manager, editor, 0x11, 2, "N\ncond editorb", 1, true);
    try pressSelectionKey(manager, editor, 0x4D, 3, "N\ncond editorb", 14, 1, true);
    try pressCursorKey(manager, editor, 0x2A, 0, "N", 1, true);
    try pressSelectionKey(manager, editor, 0x04, 1, "N", 1, 0, true);
    try pressCursorKey(manager, editor, 0x14, 2, "Q", 1, true);
    try pressCursorKey(manager, editor, 0x28, 0, "Q\n", 2, true);
    try pressCursorKey(manager, editor, 0x04, 0, "Q\na", 3, true);
    try pressSelectionKey(manager, editor, 0x50, 2, "Q\na", 2, 3, true);
    try pressCursorKey(manager, editor, 0x05, 0, selection_edited_text, 3, true);
    try pressCursorKey(manager, editor, 0x4A, 1, selection_edited_text, 0, true);
    try pressSelectionKey(manager, editor, 0x51, 2, selection_edited_text, 2, 0, true);
    try pressCursorKey(manager, editor, 0x4F, 0, selection_edited_text, 2, true);
    try pressCursorKey(manager, editor, 0x4D, 1, selection_edited_text, 3, true);
    const staged = try storage.resolve(workspace_id, sibling_path);
    if (staged.version_id.raw() != before.version_id.raw() or
        storage.checkpoint_store.last_checkpoint_generation != checkpoint) return error.SelectionEditSavedWithoutRequest;
    report_cursor = 0;
    report_mode = .key;
    report_usage = 0x28;
    report_modifiers = 1;
    if (manager.servicePendingInputWork(timer.getTicks()) != 1) return error.SelectionInputNotRouted;
    try awaitSaving(manager, editor);
    try awaitPresentation(manager, editor, selection_edited_text, 4);
    try expectStored(manager, workspace_id, sibling_path, selection_edited_text, before.version_id.raw());
    if (storage.checkpoint_store.last_checkpoint_generation <= checkpoint) return error.SelectionSaveNotDurable;
}

fn pressSelectionKey(manager: anytype, editor: EditorSession, usage: u8, modifiers: u8, expected: []const u8, cursor: u16, anchor: u16, dirty: bool) !void {
    try pressKeys(manager, editor, &.{usage}, modifiers, expected, cursor, anchor, dirty);
}

fn pressKeys(manager: anytype, editor: EditorSession, usages: []const u8, modifiers: u8, expected: []const u8, cursor: u16, anchor: u16, dirty: bool) !void {
    return pressKeysAt(manager, editor, usages, modifiers, expected, cursor, anchor, dirty, false);
}

fn pressKeysAt(manager: anytype, editor: EditorSession, usages: []const u8, modifiers: u8, expected: []const u8, cursor: u16, anchor: u16, dirty: bool, upstream: bool) !void {
    const before = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), editor.task_id) orelse return error.EditorMailboxMissing;
    report_cursor = 0;
    report_mode = .key;
    report_usage = usages[0];
    report_keys = [_]u8{0} ** 6;
    @memcpy(report_keys[0..usages.len], usages);
    defer report_keys = [_]u8{0} ** 6;
    report_modifiers = modifiers;
    if (manager.servicePendingInputWork(timer.getTicks()) != usages.len) return error.CursorInputNotRouted;
    try awaitInputPresentation(manager, editor, expected, cursor, anchor, dirty, upstream, before.input_event_count, before.last_input_sequence, usages.len);
}

fn awaitInputPresentation(manager: anytype, editor: EditorSession, expected: []const u8, cursor: u16, anchor: u16, dirty: bool, upstream: bool, before_count: u64, before_sequence: u64, additional: usize) !void {
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), editor.task_id) orelse continue;
        if (state.input_event_count != before_count + additional or state.ui_presented_revision != state.ui_state_revision) continue;
        if (manager.clipboard.transferPendingForTask(editor.task_id)) continue;
        if (state.last_input_sequence <= before_sequence) return error.InputSequenceReused;
        const surface = manager.compositorSessionPtr().surfacePresentation(editor.surface_id) orelse continue;
        const text = if (surface.text) |*value| value else continue;
        const flags: mailbox_abi.UiStateFlags = @bitCast(text.state.flags);
        if (text.cursor != cursor or text.state.cursor_upstream != upstream or text.state.selection_anchor != anchor or state.ui_cursor != cursor or flags.dirty != dirty or
            !std.mem.eql(u8, text.textSlice(), expected)) return error.CursorEditMismatch;
        const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
        const layout = abi.text_layout.Layout{ .text = expected, .columns = frame.columns };
        const position = layout.locate(.{ .offset = cursor, .upstream = upstream });
        const visible = frame.rows - 8;
        const first_row = position.index -| (visible - 1);
        const cursor_row = 5 + position.index - first_row;
        const cursor_column = @min(position.column, frame.columns - 1);
        const cursor_cell = frame.cells[cursor_row * frame.columns + cursor_column];
        if (!cursor_cell.cursor or cursor_cell.cursor_trailing != (position.column == frame.columns)) return error.CursorNotPresented;
        if (!framebuffer.verifyCell(cursor_column, cursor_row)) return error.CursorPixelsMissing;
        var rows = layout.rows();
        var index: usize = 0;
        while (rows.next()) |row| : (index += 1) {
            if (index < first_row) continue;
            if (index >= first_row + visible) break;
            var clusters = abi.text_layout.unicode.Iterator{ .text = expected[0..row.end], .offset = row.start };
            var column: usize = 0;
            while (clusters.next()) |cluster| {
                const width = @min(cluster.columns(column), frame.columns - column);
                const screen_row = 5 + index - first_row;
                const selected = cluster.start >= @min(cursor, anchor) and cluster.start < @max(cursor, anchor);
                for (0..width) |part| {
                    if ((frame.cells[screen_row * frame.columns + column + part].style == .selected) != selected) return error.SelectionNotPresented;
                    if (!framebuffer.verifyCell(column + part, screen_row)) return error.SelectionPixelsMissing;
                }
                column += width;
            }
        }
        return;
    }
    return error.CursorEditTimedOut;
}

fn expectBatchedInputAndSourceRestart(manager: anytype, editor: EditorSession) !void {
    // All six new keys arrive in one HID report. Every event must reach the
    // running editor, not just the first event with that report's identity.
    try pressKeys(manager, editor, &.{ 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 }, 0, undo_edited_text ++ "abcdef", 10, 10, true);
    // Restart the source's report clock while the same task retains its state.
    manager.inputRouterPtr().clearHardwareSource();
    report_sequence = 0;
    manager.inputRouterPtr().bindHardwareSource(.{ .poll_report = nextReport, .input_proof = noHardwareProof });
    try pressCursorKey(manager, editor, 0x0A, 0, undo_edited_text ++ "abcdefg", 11, true);
    try pressCursorKey(manager, editor, 0x1D, 1, undo_edited_text, 4, false);
    common.printBootMarker(boot_markers.document_input_ordering);
}

var held_report: ?xhci.HardwareBootKeyboardReport = null;
fn nextHeldReport() ?xhci.HardwareBootKeyboardReport {
    defer held_report = null;
    return held_report;
}
fn heldSourceEpoch() ?u64 {
    return 1;
}

fn expectHeldInput(manager: anytype, editor: EditorSession) !void {
    const input = manager.inputRouterPtr();
    const source = input.source.?;
    input.bindHardwareSource(.{ .poll_report = nextHeldReport, .input_proof = noHardwareProof, .continuity_epoch = heldSourceEpoch });
    const before = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), editor.task_id) orelse return error.EditorMailboxMissing;
    const start = timer.getTicks();
    held_report = .{ .sequence = 1, .port_id = 1, .slot_id = 1, .endpoint_id = 3, .bytes = .{ 0, 0, 0x04, 0, 0, 0, 0, 0 } };
    if (manager.servicePendingInputWork(start) != 1) return error.HeldPressMissing;
    try awaitInputPresentation(manager, editor, undo_edited_text ++ "a", 5, 5, true, false, before.input_event_count, before.last_input_sequence, 1);
    const deadline = input.nextWake() orelse return error.RepeatDeadlineMissing;
    if (manager.nextServiceWake() == null or manager.nextServiceWake().? > deadline) return error.RepeatIdleWakeMissing;
    // Deterministic clock injection exercises the production router and idle
    // deadline. The generated Notes ELF still consumes/presents every event.
    if (manager.servicePendingInputWork(deadline - 1) != 0 or manager.servicePendingInputWork(deadline) != 1) return error.RepeatDeadlineIncorrect;
    try awaitInputPresentation(manager, editor, undo_edited_text ++ "aa", 6, 6, true, false, before.input_event_count, before.last_input_sequence, 2);
    const release = input.nextWake().?;
    held_report = .{ .sequence = 2, .port_id = 1, .slot_id = 1, .endpoint_id = 3 };
    if (manager.servicePendingInputWork(release) != 0 or input.nextWake() != null or manager.servicePendingInputWork(release + 100) != 0) return error.RepeatSurvivedRelease;
    input.bindHardwareSource(source);
    try pressCursorKey(manager, editor, 0x1D, 1, undo_edited_text, 4, false);
    common.printBootMarker(boot_markers.document_input_repeat);
}

fn visualNavigation(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer) !void {
    const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
    const width = frame.columns;
    const page = frame.rows - 9;
    if (width < 20 or width > 120 or page < 3) return error.InvalidTextViewport;
    var text: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined;
    const first_line = 2 * width + 3;
    for (text[0..first_line], 0..) |*byte, index| byte.* = 'a' + @as(u8, @intCast(index % 26));
    text[first_line] = '\n';
    for (text[first_line + 1 ..], 0..) |*byte, index| byte.* = if (index % 2 == 0) 'x' else '\n';
    const storage = manager.storageServicePtr();
    const stored = try storage.putVersion(.{
        .object_type = .document,
        .payload = &text,
        .metadata = try object_store.signMetadata(signer, "Wrapped document", "text/plain", .document, &text, 0),
    });
    const wrapped_path = "documents/wrapped.md";
    try storage.beginTransaction(workspace_id);
    errdefer storage.abortTransaction(workspace_id) catch {};
    try storage.stagePut(workspace_id, wrapped_path, stored.object_id, stored.version_id, .document);
    _ = try storage.commit(workspace_id, 0);
    const editor = try openEditor(manager, graph, workspace_id, wrapped_path, 0xD0C3, document_key);
    defer retireEditor(manager, editor);
    try awaitPresentation(manager, editor, &text, 0);
    const checkpoint = storage.checkpoint_store.last_checkpoint_generation;
    try pressKeysAt(manager, editor, &.{0x4A}, 1, &text, 0, 0, false, false);
    try pressKeysAt(manager, editor, &.{0x4D}, 0, &text, @intCast(width), @intCast(width), false, true);
    try pressKeysAt(manager, editor, &.{0x51}, 0, &text, @intCast(2 * width), @intCast(2 * width), false, true);
    try pressKeysAt(manager, editor, &.{0x4A}, 0, &text, @intCast(width), @intCast(width), false, false);
    try pressKeysAt(manager, editor, &.{0x51}, 2, &text, @intCast(2 * width), @intCast(width), false, false);
    try pressKeysAt(manager, editor, &.{0x4A}, 1, &text, 0, 0, false, false);
    const page_offset: u16 = @intCast(first_line + 1 + 2 * (page - 3));
    try pressKeysAt(manager, editor, &.{0x4E}, 2, &text, page_offset, 0, false, false);
    try pressKeysAt(manager, editor, &.{0x4B}, 0, &text, 0, 0, false, false);
    const current = try storage.resolve(workspace_id, wrapped_path);
    if (current.version_id.raw() != stored.version_id.raw() or storage.checkpoint_store.last_checkpoint_generation != checkpoint)
        return error.NavigationChangedStorage;
    common.printBootMarker(boot_markers.document_visual_navigation);
}

fn unicodeDocument(manager: anytype, graph: anytype, workspace_id: u64, document_key: object_signer.Signer, sibling: EditorSession) !void {
    // The first clipboard chunk ends in the middle of U+754C.
    const text = "a" ** 67 ++ "界e\u{301} café Ελληνικά\n👩‍💻\r\n終";
    const unicode_path = "documents/unicode.md";
    const storage = manager.storageServicePtr();
    const stored = try storage.putVersion(.{
        .object_type = .document,
        .payload = text,
        .metadata = try object_store.signMetadata(signer, "Unicode document", "text/plain", .document, text, 0),
    });
    try storage.beginTransaction(workspace_id);
    errdefer storage.abortTransaction(workspace_id) catch {};
    try storage.stagePut(workspace_id, unicode_path, stored.object_id, stored.version_id, .document);
    _ = try storage.commit(workspace_id, 0);
    const editor = try openEditor(manager, graph, workspace_id, unicode_path, 0xD0C4, document_key);
    var retired = false;
    defer if (!retired) retireEditor(manager, editor);
    try awaitPresentation(manager, editor, text, 0);
    const checkpoint = storage.checkpoint_store.last_checkpoint_generation;
    try pressCursorKey(manager, editor, 0x2A, 0, text[0 .. text.len - 3], text.len - 3, true);
    try pressCursorKey(manager, editor, 0x1D, 1, text, text.len, false);
    try pressSelectionKey(manager, editor, 0x50, 2, text, text.len - 3, text.len, false);
    try pressCursorKey(manager, editor, 0x4C, 0, text[0 .. text.len - 3], text.len - 3, true);
    try pressSelectionKey(manager, editor, 0x1D, 1, text, text.len - 3, text.len, false);
    try pressSelectionKey(manager, editor, 0x04, 1, text, text.len, 0, false);
    try pressSelectionKey(manager, editor, 0x06, 1, text, text.len, 0, false);
    _ = try manager.compositorSessionPtr().switchView(sibling.window_id);
    const original = sibling_text ++ "b";
    try pressSelectionKey(manager, sibling, 0x04, 1, original, original.len, 0, false);
    try pressCursorKey(manager, sibling, 0x19, 1, text, text.len, true);
    try pressSelectionKey(manager, sibling, 0x1D, 1, original, original.len, 0, false);
    try pressCursorKey(manager, sibling, 0x4F, 0, original, original.len, false);
    _ = try manager.compositorSessionPtr().switchView(editor.window_id);
    try pressCursorKey(manager, editor, 0x4F, 0, text, text.len, false);
    try pressCursorKey(manager, editor, 0x04, 0, text ++ "a", text.len + 1, true);
    if (storage.checkpoint_store.last_checkpoint_generation != checkpoint) return error.UnicodeSavedWithoutRequest;
    report_cursor = 0;
    report_mode = .key;
    report_usage = 0x28;
    report_modifiers = 1;
    if (manager.servicePendingInputWork(timer.getTicks()) != 1) return error.UnicodeInputNotRouted;
    try awaitSaving(manager, editor);
    try awaitPresentation(manager, editor, text ++ "a", 1);
    try expectStored(manager, workspace_id, unicode_path, text ++ "a", stored.version_id.raw());
    retireEditor(manager, editor);
    retired = true;
    const reopened = try openEditor(manager, graph, workspace_id, unicode_path, 0xD0C5, document_key);
    defer retireEditor(manager, reopened);
    try awaitPresentation(manager, reopened, text ++ "a", 0);
    common.printBootMarker(boot_markers.document_unicode);
}

fn clipboardBetweenEditors(manager: anytype, first: EditorSession, second: EditorSession, first_text: []const u8) !void {
    _ = try manager.compositorSessionPtr().switchView(first.window_id);
    try pressSelectionKey(manager, first, 0x04, 1, first_text, @intCast(first_text.len), 0, false);
    try pressSelectionKey(manager, first, 0x06, 1, first_text, @intCast(first_text.len), 0, false);
    _ = try manager.compositorSessionPtr().switchView(second.window_id);
    const original = sibling_text ++ "b";
    try pressSelectionKey(manager, second, 0x04, 1, original, original.len, 0, false);
    try pressCursorKey(manager, second, 0x19, 1, first_text, @intCast(first_text.len), true);
    try pressSelectionKey(manager, second, 0x1D, 1, original, original.len, 0, false);
    try pressCursorKey(manager, second, 0x1B, 1, "", 0, true);
    try pressCursorKey(manager, second, 0x19, 1, original, original.len, true);
    try pressCursorKey(manager, second, 0x1D, 1, "", 0, true);
    try pressSelectionKey(manager, second, 0x1D, 1, original, original.len, 0, false);
    try pressCursorKey(manager, second, 0x4F, 0, original, original.len, false);
    common.printBootMarker(boot_markers.document_clipboard);
}

fn undoAndSave(manager: anytype, editor: EditorSession, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    const before = try storage.resolve(workspace_id, sibling_path);
    const checkpoint = storage.checkpoint_store.last_checkpoint_generation;
    try pressSelectionKey(manager, editor, 0x04, 1, selection_edited_text, 3, 0, false);
    try pressCursorKey(manager, editor, 0x1D, 2, "Z", 1, true);
    try pressSelectionKey(manager, editor, 0x1D, 1, selection_edited_text, 3, 0, false);
    try pressCursorKey(manager, editor, 0x1D, 3, "Z", 1, true);
    try pressSelectionKey(manager, editor, 0x1D, 1, selection_edited_text, 3, 0, false);
    try pressCursorKey(manager, editor, 0x15, 2, "R", 1, true);
    try pressCursorKey(manager, editor, 0x1D, 3, "R", 1, true);
    try pressSelectionKey(manager, editor, 0x1D, 1, selection_edited_text, 3, 0, false);
    try pressCursorKey(manager, editor, 0x4F, 0, selection_edited_text, 3, false);
    try pressCursorKey(manager, editor, 0x18, 0, undo_edited_text, 4, true);
    try pressCursorKey(manager, editor, 0x1D, 1, selection_edited_text, 3, false);
    const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
    if (!framebuffer.verifyText(0, frame.rows - 2, "Saved locally")) return error.UndoSavedPixelsMissing;
    try pressCursorKey(manager, editor, 0x1D, 3, undo_edited_text, 4, true);
    const staged = try storage.resolve(workspace_id, sibling_path);
    if (staged.version_id.raw() != before.version_id.raw() or
        storage.checkpoint_store.last_checkpoint_generation != checkpoint) return error.UndoSavedWithoutRequest;
    report_cursor = 0;
    report_mode = .key;
    report_usage = 0x28;
    report_modifiers = 1;
    if (manager.servicePendingInputWork(timer.getTicks()) != 1) return error.UndoInputNotRouted;
    try awaitSaving(manager, editor);
    try awaitPresentation(manager, editor, undo_edited_text, 5);
    try expectStored(manager, workspace_id, sibling_path, undo_edited_text, before.version_id.raw());
    if (storage.checkpoint_store.last_checkpoint_generation <= checkpoint) return error.UndoSaveNotDurable;
}

fn expectDeniedSave(manager: anytype, editor: EditorSession, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    const before = try storage.resolve(workspace_id, sibling_path);
    try manager.capabilityTablePtr().revokeGrant(editor.document_capability_id);
    try editAndSave(manager, editor, 0x07);
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const surface = manager.compositorSessionPtr().surfacePresentation(editor.surface_id) orelse continue;
        const text = if (surface.text) |*value| value else continue;
        if (text.state.save_state != @intFromEnum(abi.DocumentSaveState.permission_denied)) continue;
        const flags: mailbox_abi.UiStateFlags = @bitCast(text.state.flags);
        if (!flags.dirty or !std.mem.eql(u8, text.textSlice(), undo_edited_text ++ "d")) return error.DeniedSaveLostDraft;
        const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
        if (!framebuffer.verifyText(0, frame.rows - 2, "Save denied. Your draft is still here.")) return error.SaveDeniedPixelsMissing;
        const after = try storage.resolve(workspace_id, sibling_path);
        if (after.version_id.raw() != before.version_id.raw()) return error.DeniedSaveChangedStorage;
        return;
    }
    return error.SaveDeniedStateMissing;
}

fn expectStored(manager: anytype, workspace_id: u64, document_path: []const u8, expected: []const u8, old_version_id: u64) !void {
    const storage = manager.storageServicePtr();
    const saved = try storage.resolve(workspace_id, document_path);
    if (saved.version_id.raw() == old_version_id) return error.DocumentNotSaved;
    const version = storage.version(saved.version_id.raw()) orelse return error.MissingVersion;
    if (!std.mem.eql(u8, expected, try storage.versionPayload(version))) return error.StoredTextMismatch;
    if (storage.pendingCheckpointMutations() or storage.checkpoint_store.last_checkpoint_error != null) return error.SaveNotDurable;
}

fn expectChannelRetired(manager: anytype, editor: EditorSession) !void {
    const capabilities = manager.capabilityTablePtr();
    const endpoints = manager.kernelPort().?.kernel.endpoint_table;
    const binding = editor.binding;
    const client_endpoint_id = (capabilities.query(binding.endpoint_capability_id) orelse return error.ClientGrantMissing).target.id;
    _ = try endpoints.descriptor(ids.endpoint(client_endpoint_id));
    _ = try endpoints.descriptor(ids.endpoint(binding.service_endpoint_id));
    const before_close = endpoints.activeCount();
    manager.documents.closeTask(editor.task_id, timer.getTicks());
    if (endpoints.activeCount() != before_close - 2 or capabilities.query(binding.endpoint_capability_id) != null) return error.ChannelNotRetired;
    for ([_]u64{ client_endpoint_id, binding.service_endpoint_id }) |endpoint_id| {
        _ = endpoints.descriptor(ids.endpoint(endpoint_id)) catch |err| {
            if (err != error.EndpointNotFound) return err;
            continue;
        };
        return error.ChannelEndpointStillLive;
    }
}

fn awaitPresentation(manager: anytype, editor: EditorSession, expected: []const u8, commits: u32) !void {
    const task_id = editor.task_id;
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const surface = manager.compositorSessionPtr().surfacePresentation(editor.surface_id) orelse continue;
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id) orelse continue;
        if (!std.meta.eql(editor.binding, state.documentBinding())) return error.DocumentBindingLost;
        const flags: mailbox_abi.UiStateFlags = @bitCast(state.ui_state_flags);
        if (flags.load_failed) return error.DocumentLoadFailed;
        if (!flags.loading and !flags.dirty and state.ui_commit_count == commits and
            state.ui_presented_revision == surface.presentation.revision and
            state.ui_text_length == expected.len and
            std.mem.eql(u8, &state.ui_text_digest, &protocol.digest(expected)))
        {
            const text = if (surface.text) |*content| content else return error.SurfaceTextMissing;
            if (!std.mem.eql(u8, text.textSlice(), expected)) return error.SurfaceTextMismatch;
            if (commits != 0 and text.state.save_state != @intFromEnum(abi.DocumentSaveState.saved)) return error.SavedStateMissing;
            if (manager.compositorSessionPtr().active_window_id == editor.window_id) {
                const frame = framebuffer.frame() orelse return error.FramebufferUnavailable;
                const layout = abi.text_layout.Layout{ .text = expected, .columns = frame.columns };
                const caret = layout.locate(.{ .offset = text.cursor, .upstream = text.state.cursor_upstream });
                const first_visible = caret.index -| (frame.rows - 9);
                const row = layout.rowAt(first_visible);
                if (!framebuffer.verifyText(0, 5, expected[row.start..row.end])) return error.DocumentPixelsMissing;
                if (commits != 0) {
                    if (!framebuffer.verifyText(0, frame.rows - 2, "Saved locally")) return error.SavedPixelsMissing;
                }
            }
            return;
        }
    }
    const mailbox = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id);
    const stats = manager.userspaceSchedulerPtr().taskDispatchStats(task_id);
    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "ZIGOS:DOCUMENT_CHANNEL:TIMEOUT task={d} mailbox={} stage={d} fault={d} text={d} flags={d} presentation={d} dispatches={d} ready={}", .{
        task_id,                                                       mailbox != null,
        if (mailbox) |value| value.stage else 0,                       if (mailbox) |value| value.fault_code else 0,
        if (mailbox) |value| value.ui_text_length else 0,              if (mailbox) |value| value.ui_state_flags else 0,
        if (mailbox) |value| value.ui_last_presentation_status else 0, if (stats) |value| value.dispatch_count else 0,
        if (stats) |value| value.queued_ready else false,
    });
    common.printBootMarker(line);
    return error.DocumentDispatchTimedOut;
}

fn nextReport() ?xhci.HardwareBootKeyboardReport {
    if (report_cursor >= @as(u8, if (report_mode == .open or report_mode == .key) 2 else 4)) return null;
    defer report_cursor += 1;
    report_sequence += 1;
    var report = xhci.HardwareBootKeyboardReport{
        .sequence = report_sequence,
        .port_id = 1,
        .slot_id = 1,
        .interface_number = 1,
        .endpoint_id = 3,
        .vendor_id = 0x046D,
        .product_id = 0xC31C,
    };
    if (report_cursor == 0) report.bytes[2] = switch (report_mode) {
        .edit, .key => report_usage,
        .open => 0x28,
        .cancel => 0x2B,
    };
    if (report_cursor == 0 and report_mode == .key) report.bytes[0] = report_modifiers;
    if (report_cursor == 0 and report_mode == .key and report_keys[0] != 0) @memcpy(report.bytes[2..8], &report_keys);
    if (report_cursor == 2) {
        report.bytes[0] = if (report_mode == .edit) 0x01 else 0;
        report.bytes[2] = 0x28;
    }
    return report;
}

fn noHardwareProof() ?xhci.InputProof {
    return null;
}
