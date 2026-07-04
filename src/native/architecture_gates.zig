// Architecture gates: each flag is a comptime introspection of the live code,
// not a hardcoded `true`. backlog_gates.expectAllMetadataTrue asserts every flag
// holds, so removing or renaming a gated arena/index/decl makes the corresponding
// flag false and fails the gate.
//
// Absence claims ("removed legacy fixed-table scan", "removed monolithic codec",
// etc.) are intentionally NOT modeled: the removal of a pattern cannot be proven
// by introspection, and the positive presence checks below already prove the
// indexed replacements exist. This file is test-only (imported solely by
// src/tests/spec/backlog_gates.zig), so its module imports do not enter any
// production binary.

const indexed_arena = @import("core/indexed_arena.zig");
const service_registry = @import("services/service_registry.zig");
const component_abi_schema = @import("services/component_abi_schema.zig");
const userspace_scheduler = @import("task/userspace_scheduler.zig");
const accelerator_scheduler = @import("task/accelerator_scheduler.zig");
const indexing_service = @import("services/indexing_service.zig");
const event_ledger = @import("platform/event_ledger.zig");
const compositor_session = @import("platform/compositor_session.zig");
const native_ux = @import("platform/native_ux.zig");
const sync_transport_harness = @import("sync/sync_transport_harness.zig");
const sync_transport = @import("sync/sync_transport.zig");
const sync_service = @import("sync/sync_service.zig");
const sync_service_test = @import("sync/sync_service_test.zig");
const sync_adapters = @import("sync/sync_adapters.zig");
const sync_state_store = @import("sync/sync_state_store.zig");
const workspace = @import("storage/workspace.zig");
const storage_volume = @import("storage/storage_volume.zig");
const secure_pasteboard = @import("services/secure_pasteboard.zig");
const sensitive_capture_service = @import("services/sensitive_capture_service.zig");
const agent_delegation_service = @import("services/agent_delegation_service.zig");
const object_resilience_service = @import("services/object_resilience_service.zig");
const personal_context_service = @import("services/personal_context_service.zig");
const package_service = @import("services/package_service.zig");
const driver_service = @import("drivers/driver_service.zig");
const network_policy = @import("sync/network_policy.zig");
const policy_object = @import("policy/policy_object.zig");
const userspace_loader = @import("task/userspace_loader.zig");
const background_dispatch = @import("task/background_dispatch.zig");
const notification_center = @import("services/notification_center.zig");
const os_identity = @import("platform/os_identity.zig");
const service_catalog = @import("session/service_catalog.zig");
const session_bootstrap = @import("session/session_bootstrap.zig");
const service_bootstrap = @import("session/service_bootstrap.zig");
const session_service_bootstrap = @import("session/session_service_bootstrap.zig");

// A trivial instantiation of the indexed arena so its tracked-count field can be
// introspected (the arena is a generic factory, so the field lives on the
// instantiated type).
const ProbeArenaSlot = struct { in_use: bool = false };
fn probeArenaKey(_: *const ProbeArenaSlot) u64 {
    return 0;
}
const ProbeArena = indexed_arena.IndexedArenaWithKey(u64, ProbeArenaSlot, 1, 2, probeArenaKey);

pub const sync_private_overlay = .{
    .transport_harness = .{
        .uses_signed_encrypted_frames = @hasField(sync_transport_harness.SignedEncryptedFrame, "signature"),
        .verifies_signed_frames = @hasDecl(sync_transport_harness, "verifySignedFrame"),
        .rejects_foreign_session_task_submitters = @hasDecl(sync_transport_harness.BootedOverlayRelayService, "submitSignedFrame"),
    },
    .service_test = .{
        .runs_deterministic_two_device_overlay_replication = @hasDecl(sync_service_test, "deterministicTwoDeviceOverlayReplication"),
        .opens_overlay_sessions = @hasDecl(sync_service.SyncPort, "openOverlaySession"),
        .replicates_workspaces = @hasDecl(sync_service.SyncPort, "replicateWorkspace"),
        .submits_relay_packets = @hasDecl(sync_transport.Relay, "submit"),
    },
    .sync_service = .{
        .sends_overlay_relay_frames_via_service_port = @hasDecl(sync_service.Service, "sendOverlayRelayFrameViaService"),
    },
};

pub const indexed_hot_path_tables = .{
    .indexed_arena = .{
        .tracks_used_count = @hasField(ProbeArena, "used_count"),
    },
    .service_registry = .{
        .uses_binding_arena = @hasField(service_registry.Registry, "bindings"),
        .uses_typed_interface_ids = @hasField(service_registry.Binding, "interface_id"),
    },
    .component_abi_schema = .{
        .defines_interface_ids = @hasDecl(component_abi_schema, "InterfaceId"),
        .binds_services_by_interface_id = @hasDecl(component_abi_schema, "interfaceIdForService"),
    },
    .userspace_scheduler = .{
        .uses_scheduler_slot_arena = @hasField(userspace_scheduler.Scheduler, "slots"),
        .uses_ready_heads = @hasField(userspace_scheduler.Scheduler, "ready_heads"),
        .selects_ready_resource_class = @hasDecl(userspace_scheduler.Scheduler, "readyQueueDepth"),
        .wakes_tasks = @hasDecl(userspace_scheduler.Scheduler, "wakeTask"),
        .refills_task_budget = @hasDecl(userspace_scheduler.Scheduler, "refillTaskBudget"),
        .tracks_deadline_tick = @hasField(userspace_scheduler.AcceleratorClaimRecord, "deadline_tick"),
        .configures_resource_state = @hasDecl(userspace_scheduler.Scheduler, "configureResourceState"),
        .uses_accelerator_claim_heads = @hasField(userspace_scheduler.Scheduler, "accelerator_claim_heads"),
        .grants_next_accelerator_claim = @hasDecl(userspace_scheduler.Scheduler, "grantNextAcceleratorClaim"),
    },
    .accelerator_scheduler = .{
        .uses_claim_arena = @hasField(accelerator_scheduler.Controller, "claims"),
        .uses_claim_task_index = @hasField(accelerator_scheduler.Controller, "claim_task_index"),
    },
    .indexing_service = .{
        .uses_document_arena = @hasField(indexing_service.Service, "documents"),
    },
    // Services migrated from [MAX]Slot + firstFreeSlot linear scans to
    // indexed_arena.IndexedArenaWithKey: the slots field must be an arena
    // (its reserve() method replaced firstFreeSlot()).
    .secure_pasteboard = .{
        .uses_grant_arena = @hasDecl(@FieldType(secure_pasteboard.Service, "slots"), "reserve"),
    },
    .sensitive_capture_service = .{
        .uses_session_arena = @hasDecl(@FieldType(sensitive_capture_service.Service, "slots"), "reserve"),
    },
    .agent_delegation_service = .{
        .uses_delegation_arena = @hasDecl(@FieldType(agent_delegation_service.Service, "slots"), "reserve"),
    },
    .object_resilience_service = .{
        .uses_snapshot_arena = @hasDecl(@FieldType(object_resilience_service.Service, "slots"), "reserve"),
    },
    .personal_context_service = .{
        .uses_lease_arena = @hasDecl(@FieldType(personal_context_service.Service, "slots"), "reserve"),
    },
    .package_service = .{
        .uses_bundle_arena = @hasDecl(@FieldType(package_service.Service, "slots"), "reserve"),
    },
    .driver_service = .{
        .uses_driver_arena = @hasDecl(@FieldType(driver_service.Directory, "slots"), "reserve"),
    },
    .network_policy = .{
        .uses_policy_arena = @hasDecl(@FieldType(network_policy.Directory, "policies"), "reserve"),
    },
    .policy_object = .{
        .uses_policy_arena = @hasDecl(@FieldType(policy_object.Directory, "slots"), "reserve"),
    },
    .userspace_loader = .{
        .uses_image_arena = @hasDecl(@FieldType(userspace_loader.Catalog, "images"), "reserve"),
    },
    .background_dispatch = .{
        .uses_record_arena = @hasDecl(@FieldType(background_dispatch.Controller, "records"), "reserve"),
    },
    .notification_center = .{
        .uses_notification_arena = @hasDecl(@FieldType(notification_center.Center, "notifications"), "reserve"),
    },
    .os_identity = .{
        .uses_credential_arena = @hasDecl(@FieldType(os_identity.Store, "credentials"), "reserve"),
    },
    .event_ledger = .{
        .uses_event_arena = @hasField(event_ledger.Ledger, "events"),
        .indexes_kind = @hasField(event_ledger.Ledger, "kind_index"),
        .indexes_subject = @hasField(event_ledger.Ledger, "subject_index"),
        .indexes_task = @hasField(event_ledger.Ledger, "task_index"),
        .visits_indexes = @hasDecl(event_ledger.Ledger, "queryEvents"),
    },
    .compositor_session = .{
        .uses_window_arena = @hasField(compositor_session.Session, "windows"),
        .uses_review_item_arena = @hasField(compositor_session.Session, "items"),
    },
    .native_ux = .{
        .uses_flow_arena = @hasField(native_ux.Controller, "flows"),
        .supports_ordered_flow_lookup = @hasDecl(native_ux.Controller, "flowAtOrder"),
    },
    .sync_transport_harness = .{
        .uses_relay_packet_arena = @hasField(sync_transport_harness.Relay, "packets"),
        .uses_relay_session_index = @hasField(sync_transport_harness.Relay, "session_index"),
    },
    .sync_service = .{
        .uses_overlay_session_arena = @hasField(sync_service.Service, "overlay_sessions"),
        .tracks_closed_overlay_sessions = @hasField(sync_service.Service, "closed_overlay_sessions"),
        .tracks_active_overlay_session_count = @hasField(sync_service.Service, "active_overlay_session_count"),
        .indexes_workspace_policies = @hasField(sync_service.Service, "workspace_policy_index"),
        .indexes_overlays = @hasField(sync_service.Service, "overlay_index"),
        .indexes_replica_scopes = @hasField(sync_service.Service, "replica_scope_index"),
        .indexes_database_contracts = @hasField(sync_service.Service, "database_contract_index"),
        .indexes_database_contract_equivalence = @hasField(sync_service.Service, "database_contract_equivalent_index"),
        .indexes_database_contract_bundles = @hasField(sync_service.Service, "database_contract_bundle_index"),
        .indexes_conflicts = @hasField(sync_service.Service, "conflict_index"),
        .indexes_conflict_objects = @hasField(sync_service.Service, "conflict_object_index"),
        .indexes_conflict_scopes = @hasField(sync_service.Service, "conflict_scope_index"),
        .indexes_inbound_transport_duplicates = @hasField(sync_service.Service, "inbound_transport_duplicate_index"),
        .indexes_inbound_transport_targets = @hasField(sync_service.Service, "inbound_transport_target_index"),
        .indexes_inbound_transport_high_water = @hasField(sync_service.Service, "inbound_transport_high_water_index"),
        .indexes_inbound_transport_paths = @hasField(sync_service.Service, "inbound_transport_path_index"),
        .indexes_outbound_transport_frames = @hasField(sync_service.Service, "outbound_transport_frame_index"),
        .indexes_outbound_transport_targets = @hasField(sync_service.Service, "outbound_transport_target_index"),
        .indexes_outbound_transport_paths = @hasField(sync_service.Service, "outbound_transport_path_index"),
        .tracks_transport_frame_counts = @hasField(sync_service.Service, "outbound_transport_frame_count") and
            @hasField(sync_service.Service, "inbound_transport_frame_count"),
        .tracks_transport_frame_allocation_cursors = @hasField(sync_service.Service, "next_outbound_transport_frame_slot_index") and
            @hasField(sync_service.Service, "next_inbound_transport_frame_slot_index"),
        .tracks_sync_table_allocation_cursors = @hasField(sync_service.Service, "next_workspace_policy_slot_index") and
            @hasField(sync_service.Service, "next_overlay_slot_index") and
            @hasField(sync_service.Service, "next_replica_slot_index") and
            @hasField(sync_service.Service, "next_conflict_slot_index") and
            @hasField(sync_service.Service, "next_database_contract_slot_index"),
    },
    .sync_adapters = .{
        .uses_transport_frame_arena = @hasField(sync_adapters.TransportQueue, "frames"),
        .uses_transport_frame_target_index = @hasField(sync_adapters.TransportQueue, "target_index"),
        .uses_transport_frame_path_index = @hasField(sync_adapters.TransportQueue, "path_index"),
    },
    .sync_state_store = .{
        .persists_state_records = @hasDecl(sync_state_store, "persist"),
        .loads_state_records = @hasDecl(sync_state_store, "load"),
    },
    .workspace = .{
        .uses_path_index = @hasField(workspace.WorkspaceRecord, "path_index"),
        .tracks_mutation_log = @hasField(workspace.WorkspaceRecord, "mutation_log"),
        .tracks_share_table = @hasField(workspace.WorkspaceRecord, "share_table"),
        .tracks_staging_state = @hasField(workspace.WorkspaceRecord, "staging"),
        .tracks_recoverable_deletes = @hasField(workspace.WorkspaceRecord, "recoverable_deletes"),
        .caches_leaf_hashes = @hasField(workspace.WorkspacePathIndex, "leaf_hashes"),
        .uses_index_root_address = @hasField(workspace.WorkspacePathIndex, "root_address"),
        .supports_indexed_path_lookup = @hasField(workspace.WorkspacePathIndex, "path_slots"),
    },
    .storage_volume = .{
        .persists_workspace_state = @hasDecl(storage_volume, "saveToImage"),
        .replays_state_by_primary_index = @hasDecl(storage_volume, "loadFromImage"),
        .requires_target_nvme_attachment = @hasDecl(storage_volume.Volume, "hasProductionStorageBackend"),
    },
    .service_catalog = .{
        .uses_bootstrap_owner_keys = @hasField(service_catalog.ServiceCatalogEntry, "owner_key"),
        .uses_bootstrap_service_record_keys = @hasField(service_catalog.ServiceCatalogEntry, "service_record_key"),
    },
    .session_bootstrap = .{
        .uses_catalog_owner_lookup = @hasDecl(session_bootstrap, "ownerForServiceClass"),
        .uses_catalog_service_record_lookup = @hasDecl(session_bootstrap, "serviceRecordForClass"),
        .iterates_service_catalog = @hasDecl(session_bootstrap, "registerCoreServices"),
    },
    .service_bootstrap = .{
        .has_launch_service_request = @hasDecl(service_bootstrap, "LaunchServiceRequest"),
    },
    .session_service_bootstrap = .{
        .launches_contract_services = @hasDecl(session_service_bootstrap, "bootServices"),
    },
    .session_manager_boot_flow = .{
        .delegates_service_record_lookup = @hasDecl(session_bootstrap, "serviceRecordForClass"),
    },
};
