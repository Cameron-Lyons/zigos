const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const contract = @import("../session/contract.zig");
const native_util = @import("../core/util.zig");
const object_store_mod = @import("../storage/object_store.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const storage_volume_mod = @import("../storage/storage_volume.zig");
const support = @import("scenario_support.zig");

pub fn run(context: *support.Context) support.StorageScenarioState {
    support.common.printBootMarker("ZIGOS:STORAGE:BOOTSTRAP:START");
    var storage_reloaded = false;
    if (context.storage_checkpoint_store.hasCachedPersistentState()) {
        support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:CACHE_READY");
    } else {
        support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:RESET_START");
        context.storage_checkpoint_store.resetPreparedState();
        support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:RESET_DONE");
        if (storage_volume_mod.hasAttachedDevice()) {
            support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:DEVICE_READY");
            support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:LOAD_START");
            storage_reloaded = context.storage_checkpoint_store.loadPreparedStateFromAttachedVolume();
            if (storage_reloaded) {
                support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:LOAD_OK");
            } else {
                support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:LOAD_MISS");
            }
        } else {
            support.common.printBootMarker("ZIGOS:STORAGE:PERSIST:NO_DEVICE");
        }
    }
    context.storage_service_instance.* = storage_service_mod.Service.bindPrepared(
        context.storage_checkpoint_store,
        context.storage_service_id,
        context.storage_task_id,
        context.storage_service_principal,
        storage_reloaded,
    );
    context.storage_service_instance.bindCapabilityTable(context.capability_table);
    context.storage_service_instance.checkpoint_enabled = false;
    support.common.printBootMarker("ZIGOS:STORAGE:BOOTSTRAP:DONE");
    support.common.printBootMarker("ZIGOS:STORAGE:SEED:BOOTSTRAP_READY");

    var notes_object_id = object_store_mod.ids.object(native_util.fnv1a64("workspace:notes"));
    support.common.printBootMarker("ZIGOS:STORAGE:SEED:CHECK_START");
    if (context.storage_service_instance.findWorkspace(context.session_user, "notes-workspace") == null) {
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:EMPTY");
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:PUT_V1_START");
        const notes_v1_metadata = object_store_mod.signMetadata(
            support.storage_signer,
            "notes",
            "text/markdown",
            .document,
            "# Notes\n- bootstrap slice\n",
            80,
        ) catch unreachable;
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:PUT_V1_METADATA_OK");
        const notes_v1_request = object_store_mod.PutRequest{
            .preferred_object_id = notes_object_id,
            .object_type = .document,
            .payload = "# Notes\n- bootstrap slice\n",
            .metadata = notes_v1_metadata,
        };
        _ = context.storage_service_instance.putVersionRef(&notes_v1_request) catch unreachable;
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:PUT_V1_STORE_DONE");
        if (context.storage_service_instance.hasAnySnapshots()) {
            support.common.printBootMarker("ZIGOS:STORAGE:SEED:SNAPSHOT_DIRTY_BEFORE_CHECKPOINT");
        }
        if (context.storage_service_instance.hasAnyWorkspaceRecords()) {
            support.common.printBootMarker("ZIGOS:STORAGE:SEED:WORKSPACE_DIRTY_BEFORE_CHECKPOINT");
        }
        const notes_v1_before_checkpoint = support.latestInsertedVersion(context.storage_service_instance).?;
        notes_object_id = notes_v1_before_checkpoint.object_id;
        const notes_v1_version_id = notes_v1_before_checkpoint.id;
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:PUT_V1_PRECHECK_OK");
        support.common.printBootMarker("ZIGOS:STORAGE:SEED:PUT_V1_DONE");
        const notes_v1 = support.latestInsertedVersion(context.storage_service_instance).?;
        notes_object_id = notes_v1.object_id;
        const notes_v2_request = object_store_mod.PutRequest{
            .object_type = .document,
            .payload = "# Notes\n- restored through workspace snapshot\n",
            .metadata = object_store_mod.signMetadata(
                support.storage_signer,
                "notes",
                "text/markdown",
                .document,
                "# Notes\n- restored through workspace snapshot\n",
                81,
            ) catch unreachable,
            .preferred_object_id = null,
            .parent_version_id = notes_v1_version_id,
        };
        _ = context.storage_service_instance.putVersionRef(&notes_v2_request) catch unreachable;
        const notes_v2_version_id = support.latestInsertedVersion(context.storage_service_instance).?.id;
        const blob_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(920),
            .object_type = .blob,
            .payload = "blob-bytes",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "blob", "application/octet-stream", .blob, "blob-bytes", 82) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&blob_request) catch unreachable;
        const inbox_collection_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(921),
            .object_type = .collection,
            .payload = "notes,archive",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "inbox", "application/zigos-collection", .collection, "notes,archive", 83) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&inbox_collection_request) catch unreachable;
        const inbox_collection = support.latestInsertedVersion(context.storage_service_instance).?;
        const secret_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(922),
            .object_type = .secret,
            .payload = "enc:workspace-secret",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "secret", "application/zigos-secret", .secret, "enc:workspace-secret", 84) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&secret_request) catch unreachable;
        const cover_media_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(923),
            .object_type = .media_asset,
            .payload = "jpeg:cover",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "cover", "image/jpeg", .media_asset, "jpeg:cover", 85) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&cover_media_request) catch unreachable;
        const cover_media = support.latestInsertedVersion(context.storage_service_instance).?;
        const model_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(924),
            .object_type = .model_artifact,
            .payload = "tiny-embed-v1",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "embed", "application/zigos-model", .model_artifact, "tiny-embed-v1", 86) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&model_request) catch unreachable;
        const event_request = object_store_mod.PutRequest{
            .preferred_object_id = object_store_mod.ids.object(925),
            .object_type = .event_stream,
            .payload = "append:event-1",
            .metadata = object_store_mod.signMetadata(support.storage_signer, "events", "application/zigos-event-stream", .event_stream, "append:event-1", 87) catch unreachable,
        };
        _ = context.storage_service_instance.putVersionRef(&event_request) catch unreachable;

        const seeded_workspace = context.storage_service_instance.createWorkspace(.{
            .owner = context.session_user,
            .label = "notes-workspace",
        }) catch unreachable;
        context.storage_service_instance.shareWorkspace(seeded_workspace.id, .{
            .principal_id = context.sync_service_principal,
            .can_read = true,
            .can_write = true,
            .can_export = true,
            .network_scope = .relay_assisted,
            .reshare_policy = .owner_only,
            .audit_visibility = .shared_participants,
        }) catch unreachable;

        context.storage_service_instance.beginTransaction(seeded_workspace.id) catch unreachable;
        context.storage_service_instance.stagePut(seeded_workspace.id, "documents/notes.md", notes_object_id, notes_v1_version_id, .document) catch unreachable;
        context.storage_service_instance.stagePut(seeded_workspace.id, "collections/inbox", inbox_collection.object_id, inbox_collection.id, .collection) catch unreachable;
        context.storage_service_instance.stagePut(seeded_workspace.id, "assets/cover.jpg", cover_media.object_id, cover_media.id, .media_asset) catch unreachable;
        _ = context.storage_service_instance.commit(seeded_workspace.id, 88) catch unreachable;

        const baseline_snapshot = context.storage_service_instance.snapshot(seeded_workspace.id, "baseline", support.workspace_signer) catch unreachable;

        context.storage_service_instance.beginTransaction(seeded_workspace.id) catch unreachable;
        context.storage_service_instance.stagePut(seeded_workspace.id, "documents/notes.md", notes_object_id, notes_v2_version_id, .document) catch unreachable;
        _ = context.storage_service_instance.commit(seeded_workspace.id, 89) catch unreachable;
        _ = context.storage_service_instance.restore(seeded_workspace.id, baseline_snapshot.id, 90) catch unreachable;

        context.storage_service_instance.beginTransaction(seeded_workspace.id) catch unreachable;
        context.storage_service_instance.stageDelete(seeded_workspace.id, "documents/notes.md") catch unreachable;
        _ = context.storage_service_instance.commit(seeded_workspace.id, 91) catch unreachable;
        _ = context.storage_service_instance.recoverDeleted(seeded_workspace.id, "documents/notes.md", 92) catch unreachable;

        context.storage_service_instance.exportSnapshotInto(seeded_workspace.id, baseline_snapshot.id, support.export_signer, context.export_package) catch unreachable;
        _ = context.storage_service_instance.importWorkspaceFromPackage(context.storage_service_principal, "imported-notes", context.export_package, 93) catch unreachable;
    }

    if (storage_reloaded) {
        support.common.printBootMarker(boot_markers.storage_persistence_reloaded);
    }

    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:NOTES_WORKSPACE:START");
    const notes_workspace = context.storage_service_instance.findWorkspace(context.session_user, "notes-workspace") orelse
        context.storage_service_instance.findWorkspaceByLabel("notes-workspace").?;
    support.common.printBootMarker(boot_markers.storage_reload_notes_workspace_done);
    const notes_workspace_id = notes_workspace.id.raw();
    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:BASELINE:START");
    const baseline_snapshot = context.storage_service_instance.findSnapshot(notes_workspace_id, "baseline") orelse blk: {
        support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:BASELINE:MISS");
        break :blk context.storage_service_instance.snapshot(notes_workspace_id, "baseline", support.workspace_signer) catch unreachable;
    };
    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:BASELINE:DONE");
    const baseline_snapshot_id = baseline_snapshot.id.raw();
    const baseline_snapshot_signer = baseline_snapshot.signerSlice();
    context.storage_service_instance.exportSnapshotInto(
        notes_workspace_id,
        baseline_snapshot_id,
        support.export_signer,
        context.export_package,
    ) catch unreachable;
    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:EXPORT_REFRESH:DONE");
    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:IMPORTED_WORKSPACE:START");
    const imported_workspace = context.storage_service_instance.findWorkspace(context.storage_service_principal, "imported-notes") orelse
        context.storage_service_instance.findWorkspaceByLabel("imported-notes") orelse blk: {
        support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:IMPORTED_WORKSPACE:MISS");
        break :blk context.storage_service_instance.importWorkspaceFromPackage(
            context.storage_service_principal,
            "imported-notes",
            context.export_package,
            93,
        ) catch unreachable;
    };
    support.common.printBootMarker(boot_markers.storage_reload_imported_workspace_done);
    const imported_workspace_id = imported_workspace.id.raw();
    const notes_entry = context.storage_service_instance.resolve(notes_workspace_id, "documents/notes.md") catch unreachable;
    support.common.printBootMarker("ZIGOS:STORAGE:RELOAD:NOTES_ENTRY:DONE");
    const latest_notes_version_id = context.storage_service_instance.latestVersion(notes_object_id).?.id.raw();
    support.common.printBootMarker(boot_markers.storage_reload_latest_version_done);

    if (contract.serviceDescriptor(.storage_object).?.boundary == .userspace_service and
        context.storage_service_instance.latestVersion(notes_object_id) != null)
    {
        support.common.printBootMarker(boot_markers.storage_object_store_ready);
    }
    if (context.storage_service_instance.objectCount() >= 7 and context.storage_service_instance.versionCount() >= 8) {
        support.common.printBootMarker("ZIGOS:STORAGE:OBJECT_TYPES:READY");
    }
    if (context.storage_service_instance.workspaceHasAccess(notes_workspace_id, .{
        .principal_id = context.sync_service_principal,
        .wants_write = true,
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 94,
    })) {
        support.common.printBootMarker("ZIGOS:STORAGE:WORKSPACE:SHARING_OK");
    }
    if (notes_workspace.entryCount() == 3 and notes_workspace.generation >= 1) {
        support.common.printBootMarker(boot_markers.storage_workspace_transaction_ok);
    }
    if (std.mem.eql(u8, baseline_snapshot_signer, "zigos-workspace-key")) {
        support.common.printBootMarker("ZIGOS:STORAGE:SNAPSHOT:OK");
    }
    if (latest_notes_version_id != notes_entry.version_id.raw()) {
        support.common.printBootMarker("ZIGOS:STORAGE:RESTORE:OK");
    }
    if (notes_workspace.deletedCount() != 0 and !notes_entry.version_id.isZero()) {
        support.common.printBootMarker("ZIGOS:STORAGE:DELETE_RECOVERY:OK");
    }
    if ((context.storage_service_instance.resolve(imported_workspace_id, "documents/notes.md") catch unreachable).version_id.eql(notes_entry.version_id)) {
        support.common.printBootMarker("ZIGOS:STORAGE:EXPORT_IMPORT:OK");
    }

    context.storage_service_instance.checkpoint();
    _ = context.supervisor.recordCrash(context.storage_service_id, 94, 0x53);
    _ = context.supervisor.requestRestart(context.storage_service_id, 95);
    _ = context.runtime.rehostTask(context.storage_task_id, 95) catch unreachable;
    context.storage_service_instance.* = if (storage_volume_mod.hasAttachedDevice())
        storage_service_mod.Service.reloadFromAttachedVolume(
            context.storage_service_id,
            context.storage_task_id,
            context.storage_service_principal,
            context.storage_checkpoint_store,
        )
    else
        storage_service_mod.Service.initWithStore(
            context.storage_service_id,
            context.storage_task_id,
            context.storage_service_principal,
            context.storage_checkpoint_store,
        );
    context.storage_service_instance.bindCapabilityTable(context.capability_table);
    context.storage_service_instance.checkpoint_enabled = false;
    _ = context.supervisor.completeRestart(context.storage_service_id, 96);
    if (context.supervisor.hasDiagnostic(context.storage_service_id, .restart_completed) and
        (context.storage_service_instance.resolve(notes_workspace_id, "documents/notes.md") catch unreachable).version_id.eql(notes_entry.version_id))
    {
        support.common.printBootMarker(boot_markers.storage_service_recovered);
    }

    const bridge_view = context.storage_service_instance.bridgeResolve(.{
        .workspace_id = notes_workspace_id,
        .path = "/documents/notes.md",
        .access = .read,
    }, .{
        .task_id = context.notes_task_id,
        .principal = context.notes_object_capability.holder,
        .capability_id = context.notes_object_capability.id,
        .now_ticks = 94,
    }) catch unreachable;
    if (!bridge_view.authoritative and bridge_view.object_id == notes_object_id.raw() and
        bridge_view.version_id == notes_entry.version_id.raw())
    {
        support.common.printBootMarker(boot_markers.storage_file_bridge_derived);
    }

    const invalid_path_capability = context.capability_table.mintBootRoot(.{
        .holder = context.session_user,
        .issuer = context.policy_authority,
        .target = .{ .kind = .service, .id = context.storage_service_id },
        .rights = .{ .service = .{} },
        .scope = .{
            .workspace_id = notes_workspace_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{},
    }) catch unreachable;
    if (context.storage_service_instance.bridgeResolve(.{
        .workspace_id = notes_workspace_id,
        .path = "documents/notes.md",
        .access = .read,
    }, .{
        .task_id = context.storage_task_id,
        .principal = context.session_user,
        .capability_id = invalid_path_capability.id,
        .now_ticks = 94,
    })) |_| {} else |err| {
        if (err == error.CapabilityRequired) {
            support.common.printBootMarker(boot_markers.storage_path_authority_deprecated);
        }
    }

    return .{
        .notes_workspace_id = notes_workspace_id,
        .notes_object_id = notes_object_id.raw(),
        .latest_notes_version_id = latest_notes_version_id,
    };
}
