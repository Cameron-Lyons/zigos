const std = @import("std");
const mailbox_abi = @import("../../task/userspace_bootstrap_mailbox.zig");
const protocol = @import("../../../userspace/document_protocol.zig");
const ids = @import("../../core/ids.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const userspace_launch = @import("../../task/userspace_launch.zig");
const userspace_executor = @import("../../task/userspace_executor.zig");
const workspace = @import("../../storage/workspace.zig");
const xhci = @import("../../../kernel/drivers/xhci.zig");
const common = @import("../../../kernel/boot/common.zig");
const timer = @import("../../../kernel/timer/timer.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");

const path = "documents/notes.md";
const surface_id = 0xD0C1;
const owner = principal.PrincipalId{ .kind = .app, .serial = 0xD0C1 };
const signer = signing.SignerIdentity{ .label = "document-channel-proof", .seed = signing.seedFromByte(0xD1) };
var report_cursor: u8 = 0;

// Verification-only modeled HID input; every app operation below executes in
// the generated Notes ELF through the ordinary input and endpoint syscalls.
pub fn run(manager: anytype, graph: anytype, workspace_id: u64) !void {
    const storage = manager.storageServicePtr();
    const runtime = manager.runtimePtr();
    const capabilities = manager.capabilityTablePtr();
    const endpoints = manager.kernelPort().?.kernel.endpoint_table;
    const original = try storage.resolve(workspace_id, path);
    const version = storage.version(original.version_id.raw()) orelse return error.MissingVersion;
    const payload = try storage.versionPayload(version);
    if (payload.len >= protocol.MAX_DOCUMENT_BYTES) return error.DocumentTooLarge;
    var expected: [protocol.MAX_DOCUMENT_BYTES]u8 = undefined;
    @memcpy(expected[0..payload.len], payload);
    const original_length = payload.len;
    expected[original_length] = 'a';

    const task = try userspace_launch.launchRegisteredDirect(manager.userspaceCatalogPtr(), runtime, "app.notes", .{
        .owner = owner,
        .budget = .{ .cpu_time_ticks = 1_000_000, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = surface_id,
    }, manager.userspaceSchedulerPtr());
    const task_id = task.id;
    defer {
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
    }).withObjectScope(original.object_id, path));
    const service = runtime.find(storage.task_id) orelse return error.ServiceMissing;
    const service_authority = userspace_executor.resolveMailboxAuthorities(service, capabilities, 0).bootstrap_capability_id;
    const binding = try manager.openDocumentChannel(.{
        .authority = .{ .task_id = task_id, .principal = owner, .capability_id = document.id, .now_ticks = 0 },
        .client_bootstrap_capability_id = bootstrap.id,
        .server_bootstrap_capability_id = service_authority,
        .workspace_id = workspace_id,
        .path = path,
        .signer = signer,
    }, 0);
    _ = try manager.compositorSessionPtr().openDocumentView(task, workspace_id, path);
    try awaitPresentation(manager, task_id, expected[0..original_length], 0);
    const before = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), runtime, task_id) orelse return error.MailboxMissing;
    if (!std.meta.eql(binding, before.document)) return error.BindingLostOnFirstLaunch;
    // A running editor's mailbox cannot be overwritten by another open.
    if (manager.runtime_context.userspace_executor.bindInitialDocument(manager.userspaceCatalogPtr(), runtime, capabilities, task_id, binding, 0)) return error.RunningMailboxRebound;
    common.printBootMarker(boot_markers.document_channel_userspace_open);

    const input = manager.inputRouterPtr();
    const previous_source = input.source;
    input.bindHardwareSource(.{ .poll_report = nextReport, .input_proof = noHardwareProof });
    defer {
        if (previous_source) |source| input.bindHardwareSource(source) else input.clearHardwareSource();
    }
    report_cursor = 0;
    const checkpoint_generation = storage.checkpoint_store.last_checkpoint_generation;
    if (manager.servicePendingInputWork(timer.getTicks()) != 2) return error.InputNotRouted;
    try awaitPresentation(manager, task_id, expected[0 .. original_length + 1], 1);
    const saved = try storage.resolve(workspace_id, path);
    if (saved.version_id.eql(original.version_id)) return error.DocumentNotSaved;
    const saved_version = storage.version(saved.version_id.raw()) orelse return error.MissingVersion;
    if (!std.mem.eql(u8, expected[0 .. original_length + 1], try storage.versionPayload(saved_version))) return error.StoredTextMismatch;
    if (storage.pendingCheckpointMutations() or storage.checkpoint_store.last_checkpoint_error != null or
        storage.checkpoint_store.last_checkpoint_generation <= checkpoint_generation) return error.SaveNotDurable;
    common.printBootMarker(boot_markers.document_channel_userspace_save);

    const client_endpoint_id = (capabilities.query(binding.endpoint_capability_id) orelse return error.ClientGrantMissing).target.id;
    _ = try endpoints.descriptor(ids.endpoint(client_endpoint_id));
    _ = try endpoints.descriptor(ids.endpoint(binding.service_endpoint_id));
    const before_close = endpoints.activeCount();
    manager.documents.closeTask(task_id, timer.getTicks());
    if (endpoints.activeCount() != before_close - 2 or capabilities.query(binding.endpoint_capability_id) != null) return error.ChannelNotRetired;
    for ([_]u64{ client_endpoint_id, binding.service_endpoint_id }) |endpoint_id| {
        _ = endpoints.descriptor(ids.endpoint(endpoint_id)) catch |err| {
            if (err != error.EndpointNotFound) return err;
            continue;
        };
        return error.ChannelEndpointStillLive;
    }
    common.printBootMarker(boot_markers.document_channel_retirement);
}

fn awaitPresentation(manager: anytype, task_id: u64, expected: []const u8, commits: u32) !void {
    for (0..512) |_| {
        _ = manager.runUserspaceScheduler(timer.getTicks());
        const surface = manager.compositorSessionPtr().surfacePresentation(surface_id) orelse continue;
        const state = manager.runtime_context.userspace_executor.bootstrapMailboxSnapshot(manager.userspaceCatalogPtr(), manager.runtimePtr(), task_id) orelse continue;
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
    var report = xhci.HardwareBootKeyboardReport{
        .sequence = @as(u64, report_cursor) + 1,
        .port_id = 1,
        .slot_id = 1,
        .interface_number = 1,
        .endpoint_id = 3,
        .vendor_id = 0x046D,
        .product_id = 0xC31C,
    };
    if (report_cursor == 0) report.bytes[2] = 0x04;
    if (report_cursor == 2) {
        report.bytes[0] = 0x01;
        report.bytes[2] = 0x28;
    }
    return report;
}

fn noHardwareProof() ?xhci.InputProof {
    return null;
}
