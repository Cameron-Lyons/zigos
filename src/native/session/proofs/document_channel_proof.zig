const std = @import("std");
const mailbox_abi = @import("../../task/userspace_bootstrap_mailbox.zig");
const protocol = @import("../../../userspace/document_protocol.zig");
const ids = @import("../../core/ids.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const userspace_launch = @import("../../task/userspace_launch.zig");
const userspace_executor = @import("../../task/userspace_executor.zig");
const document_sessions = @import("../document_sessions.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");
const paging = @import("../../../kernel/memory/paging64.zig");
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
var report_mode: enum { edit, open, cancel } = .edit;

const EditorSession = struct {
    task_id: u64,
    surface_id: u64,
    window_id: u64,
    binding: mailbox_abi.DocumentBinding,
};

// Verification-only modeled HID input; every app operation below executes in
// the generated Notes ELF through the ordinary input and endpoint syscalls.
pub fn run(manager: anytype, graph: anytype, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
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
    for (0..40) |_| try expectLaunchRollback(manager, graph, workspace_id);
    common.printBootMarker(boot_markers.document_channel_launch_rollback);

    const input = manager.inputRouterPtr();
    const previous_source = input.source;
    input.bindHardwareSource(.{ .poll_report = nextReport, .input_proof = noHardwareProof });
    defer {
        if (previous_source) |source| input.bindHardwareSource(source) else input.clearHardwareSource();
    }
    try cancelFromCompositor(manager, graph, workspace_id);
    // Open executes in the already-running compositor ELF. The Notes tasks
    // share image and page tables, but retain independent editor state.
    const first = try openFromCompositor(manager, graph, workspace_id);
    defer retireEditor(manager, first);
    const second = try openEditor(manager, graph, workspace_id, sibling_path, 0xD0C2);
    defer retireEditor(manager, second);
    try awaitPresentation(manager, first, expected[0..original_length], 0);
    try awaitPresentation(manager, second, sibling_text, 0);
    // A running editor's mailbox cannot be overwritten by another open.
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.capabilityTablePtr(), first.task_id, first.binding, 0)) return error.RunningMailboxRebound;
    common.printBootMarker(boot_markers.document_channel_userspace_open);

    const checkpoint_generation = storage.checkpoint_store.last_checkpoint_generation;
    try editAndSave(manager, first, 0x04);
    try awaitPresentation(manager, first, expected[0 .. original_length + 1], 1);
    try expectStored(manager, workspace_id, path, expected[0 .. original_length + 1], original.version_id.raw());
    if (storage.pendingCheckpointMutations() or storage.checkpoint_store.last_checkpoint_error != null or
        storage.checkpoint_store.last_checkpoint_generation <= checkpoint_generation) return error.SaveNotDurable;
    common.printBootMarker(boot_markers.document_channel_userspace_save);

    try editAndSave(manager, second, 0x05);
    try awaitPresentation(manager, second, sibling_text ++ "b", 1);
    try expectStored(manager, workspace_id, sibling_path, sibling_text ++ "b", sibling.version_id.raw());
    try awaitPresentation(manager, first, expected[0 .. original_length + 1], 1);
    try expectStored(manager, workspace_id, path, expected[0 .. original_length + 1], original.version_id.raw());

    try expectChannelRetired(manager, first);
    const frames_before_retirement = paging.frameStats();
    retireEditor(manager, first);
    const frames_after_retirement = paging.frameStats();
    if (frames_after_retirement.free <= frames_before_retirement.free) return error.EditorStackPagesNotReclaimed;
    // Retiring the first mapping must leave the sibling's editor usable.
    try editAndSave(manager, second, 0x06);
    try awaitPresentation(manager, second, sibling_text ++ "bc", 2);
    try expectStored(manager, workspace_id, sibling_path, sibling_text ++ "bc", sibling.version_id.raw());
    common.printBootMarker(boot_markers.document_channel_sibling_editors);
    try expectChannelRetired(manager, second);
    common.printBootMarker(boot_markers.document_channel_retirement);
}

const PreparedEditor = struct {
    task_id: u64,
    surface_id: u64,
    request: document_sessions.OpenRequest,
};

fn chooseOffer(manager: anytype, prepared: PreparedEditor, cancel: bool) !void {
    const label = "Notes document";
    _ = try manager.offerDocumentLaunch(prepared.request, label, timer.getTicks());
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
    if (manager.compositorSessionPtr().active_window_id != window_id) return error.LaunchOfferLostFocus;
    report_mode = if (cancel) .cancel else .open;
    report_cursor = 0;
    if (manager.servicePendingInputWork(timer.getTicks()) != @as(usize, if (cancel) 2 else 1)) return error.LaunchInputNotRouted;
}

fn openFromCompositor(manager: anytype, graph: anytype, workspace_id: u64) !EditorSession {
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C1);
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
        return .{ .task_id = prepared.task_id, .surface_id = prepared.surface_id, .window_id = window.id, .binding = binding };
    }
    return error.LaunchDecisionTimedOut;
}

fn cancelFromCompositor(manager: anytype, graph: anytype, workspace_id: u64) !void {
    const compositor = manager.compositorSessionPtr();
    const windows_before = compositor.window_count;
    const focus_before = compositor.active_window_id;
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C5);
    const address_space_id = manager.runtimePtr().find(prepared.task_id).?.address_space_id;
    try chooseOffer(manager, prepared, true);
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        if (manager.runtimePtr().find(prepared.task_id)) |task| if (task.state != .terminated) continue;
        if (manager.runtimePtr().findAddressSpaceConst(address_space_id) != null or
            manager.userspaceSchedulerPtr().taskDispatchStats(prepared.task_id) != null or
            compositor.window_count != windows_before or compositor.active_window_id != focus_before) return error.CancelledOfferLeaked;
        // Deliver the receipt before publishing the next offer.
        for (0..32) |_| _ = manager.runUserspaceScheduler(timer.getTicks());
        common.printBootMarker(boot_markers.document_launcher_userspace_cancel);
        return;
    }
    return error.CancelDecisionTimedOut;
}

fn openEditor(manager: anytype, graph: anytype, workspace_id: u64, document_path: []const u8, surface_id: u64) !EditorSession {
    const prepared = try prepareEditor(manager, graph, workspace_id, document_path, surface_id);
    const launched = try manager.activateDocumentTask(prepared.request, 0);
    if (manager.focusedInputCapabilityForTask(launched.task_id, 0) == null or
        manager.surfacePresentationCapabilityForTask(launched.task_id, 0) == null) return error.InitialUiAuthorityMissing;
    const stats = manager.userspaceSchedulerPtr().taskDispatchStats(launched.task_id) orelse return error.EditorNotScheduled;
    if (!stats.queued_ready or stats.dispatch_count != 0) return error.EditorDispatchedBeforeActivation;
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.capabilityTablePtr(), launched.task_id, launched.binding, 0)) return error.PreparedMailboxRebound;
    return .{ .task_id = launched.task_id, .surface_id = surface_id, .window_id = launched.window_id, .binding = launched.binding };
}

fn prepareEditor(manager: anytype, graph: anytype, workspace_id: u64, document_path: []const u8, surface_id: u64) !PreparedEditor {
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
        .signer = signer,
    } };
}

fn expectLaunchRollback(manager: anytype, graph: anytype, workspace_id: u64) !void {
    const runtime = manager.runtimePtr();
    const capabilities = manager.capabilityTablePtr();
    const endpoints = manager.kernelPort().?.kernel.endpoint_table;
    const compositor = manager.compositorSessionPtr();
    const grants_before = capabilities.activeCount();
    const endpoints_before = endpoints.activeCount();
    const windows_before = compositor.window_count;
    const focus_before = compositor.active_window_id;
    const active_before = runtime.countTasksInState(.active);
    const prepared = try prepareEditor(manager, graph, workspace_id, path, 0xD0C3);
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
            std.mem.eql(u8, &state.ui_text_digest, &protocol.digest(expected))) return;
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
    if (report_cursor >= @as(u8, if (report_mode == .open) 2 else 4)) return null;
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
        .edit => report_usage,
        .open => 0x28,
        .cancel => 0x2B,
    };
    if (report_cursor == 2) {
        report.bytes[0] = if (report_mode == .edit) 0x01 else 0;
        report.bytes[2] = 0x28;
    }
    return report;
}

fn noHardwareProof() ?xhci.InputProof {
    return null;
}
