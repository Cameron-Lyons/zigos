const std = @import("std");
const mailbox_abi = @import("../../task/userspace_bootstrap_mailbox.zig");
const protocol = @import("../../../userspace/document_protocol.zig");
const ids = @import("../../core/ids.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const userspace_launch = @import("../../task/userspace_launch.zig");
const userspace_executor = @import("../../task/userspace_executor.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");
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

    // Both bindings are prepared before either task runs. They share the Notes
    // image and page tables, but each editor must retain its own runtime state.
    const first = try openEditor(manager, graph, workspace_id, path, 0xD0C1);
    defer retireEditor(manager, first);
    const second = try openEditor(manager, graph, workspace_id, sibling_path, 0xD0C2);
    defer retireEditor(manager, second);
    try awaitPresentation(manager, first, expected[0..original_length], 0);
    try awaitPresentation(manager, second, sibling_text, 0);
    // A running editor's mailbox cannot be overwritten by another open.
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), manager.runtimePtr(), manager.capabilityTablePtr(), first.task_id, first.binding, 0)) return error.RunningMailboxRebound;
    common.printBootMarker(boot_markers.document_channel_userspace_open);

    const input = manager.inputRouterPtr();
    const previous_source = input.source;
    input.bindHardwareSource(.{ .poll_report = nextReport, .input_proof = noHardwareProof });
    defer {
        if (previous_source) |source| input.bindHardwareSource(source) else input.clearHardwareSource();
    }
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
    retireEditor(manager, first);
    // Retiring the first mapping must leave the sibling's editor usable.
    try editAndSave(manager, second, 0x06);
    try awaitPresentation(manager, second, sibling_text ++ "bc", 2);
    try expectStored(manager, workspace_id, sibling_path, sibling_text ++ "bc", sibling.version_id.raw());
    common.printBootMarker(boot_markers.document_channel_sibling_editors);
    try expectChannelRetired(manager, second);
    common.printBootMarker(boot_markers.document_channel_retirement);
}

fn openEditor(manager: anytype, graph: anytype, workspace_id: u64, document_path: []const u8, surface_id: u64) !EditorSession {
    const storage = manager.storageServicePtr();
    const runtime = manager.runtimePtr();
    const capabilities = manager.capabilityTablePtr();
    const original = try storage.resolve(workspace_id, document_path);
    const owner = principal.PrincipalId{ .kind = .app, .serial = surface_id };
    const task = try userspace_launch.launchRegisteredDirect(manager.userspaceCatalogPtr(), runtime, "app.notes", .{
        .owner = owner,
        .budget = .{ .cpu_time_ticks = 1_000_000, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = surface_id,
    }, manager.userspaceSchedulerPtr());
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
    const binding = try manager.openDocumentChannel(.{
        .authority = .{ .task_id = task_id, .principal = owner, .capability_id = document.id, .now_ticks = 0 },
        .client_bootstrap_capability_id = bootstrap.id,
        .server_bootstrap_capability_id = service_authority,
        .workspace_id = workspace_id,
        .path = document_path,
        .signer = signer,
    }, 0);
    // Binding twice must fail even before the first dispatch.
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), runtime, capabilities, task_id, binding, 0)) return error.PreparedMailboxRebound;
    const window = try manager.compositorSessionPtr().openDocumentView(task, workspace_id, document_path);
    return .{ .task_id = task_id, .surface_id = surface_id, .window_id = window.id, .binding = binding };
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
        if (!std.meta.eql(editor.binding, state.document)) return error.DocumentBindingLost;
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
    if (report_cursor >= 4) return null;
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
    if (report_cursor == 0) report.bytes[2] = report_usage;
    if (report_cursor == 2) {
        report.bytes[0] = 0x01;
        report.bytes[2] = 0x28;
    }
    return report;
}

fn noHardwareProof() ?xhci.InputProof {
    return null;
}
