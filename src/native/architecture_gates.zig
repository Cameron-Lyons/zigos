const indexed_arena = @import("core/indexed_arena.zig");
const principal = @import("core/principal.zig");
const service_registry = @import("services/service_registry.zig");
const component_abi_schema = @import("services/component_abi_schema.zig");
const userspace_scheduler = @import("task/userspace_scheduler.zig");
const userspace_executor = @import("task/userspace_executor.zig");
const userspace_loader = @import("task/userspace_loader.zig");
const task_runtime = @import("task/task_runtime.zig");
const accelerator_scheduler = @import("task/accelerator_scheduler.zig");
const background_dispatch = @import("task/background_dispatch.zig");
const indexing_service = @import("services/indexing_service.zig");
const event_ledger = @import("platform/event_ledger.zig");
const compositor_session = @import("platform/compositor_session.zig");
const input_router = @import("platform/input_router.zig");
const native_ux = @import("platform/native_ux.zig");
const sync_transport_harness = @import("sync/sync_transport_harness.zig");
const sync_transport = @import("sync/sync_transport.zig");
const device_graph = @import("sync/device_graph.zig");
const sync_service = @import("sync/sync_service.zig");
const sync_service_test = @import("sync/sync_service_test.zig");
const sync_adapters = @import("sync/sync_adapters.zig");
const sync_state_support = @import("sync/sync_state_support.zig");
const sync_state_store = @import("sync/sync_state_store.zig");
const object_store = @import("storage/object_store.zig");
const workspace = @import("storage/workspace.zig");
const storage_volume = @import("storage/storage_volume.zig");
const policy_object = @import("policy/policy_object.zig");
const secure_secret_store = @import("platform/secure_secret_store.zig");
const os_identity = @import("platform/os_identity.zig");
const secret_vault_service = @import("services/secret_vault_service.zig");
const media_print_service = @import("services/media_print_service.zig");
const notification_center = @import("services/notification_center.zig");
const secure_pasteboard = @import("services/secure_pasteboard.zig");
const capability = @import("kernel_api/capability.zig");
const shared_memory = @import("kernel_api/shared_memory.zig");
const sensitive_capture_service = @import("services/sensitive_capture_service.zig");
const agent_delegation_service = @import("services/agent_delegation_service.zig");
const object_resilience_service = @import("services/object_resilience_service.zig");
const personal_context_service = @import("services/personal_context_service.zig");
const package_service = @import("services/package_service.zig");
const public_store = @import("services/public_store.zig");
const driver_service = @import("drivers/driver_service.zig");
const driver_runtime = @import("drivers/driver_runtime.zig");
const device_broker = @import("kernel_api/device_broker.zig");
const network_policy = @import("sync/network_policy.zig");
const supervisor = @import("session/supervisor.zig");
const service_catalog = @import("session/service_catalog.zig");
const session_bootstrap = @import("session/session_bootstrap.zig");
const session_manager_boot_flow = @import("session/session_manager_boot_flow.zig");
const service_bootstrap = @import("session/service_bootstrap.zig");
const session_service_bootstrap = @import("session/session_service_bootstrap.zig");

const ProbeArenaSlot = struct { in_use: bool = false };
fn probeArenaKey(_: *const ProbeArenaSlot) u64 {
    return 0;
}
const ProbeArena = indexed_arena.IndexedArenaWithKey(u64, ProbeArenaSlot, 1, 2, probeArenaKey);

pub const sync_private_overlay = .{
    .native_transport = .{
        .uses_signed_encrypted_frames = @hasField(sync_transport.SignedEncryptedFrame, "signature"),
        .verifies_signed_frames = @hasDecl(sync_transport, "verifySignedFrame"),
        .opens_endpoint_backed_relays = @hasDecl(sync_transport.NativeTransportService, "openRelay"),
        .falls_back_through_relay_service = @hasDecl(sync_transport.NativeTransportService, "sendWithRelayFallback"),
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
        .inserts_complete_values_at_exact_indexes = @hasDecl(ProbeArena, "insertIndexAt"),
    },
    .service_registry = .{
        .uses_binding_arena = @hasField(service_registry.Registry, "bindings"),
        .uses_typed_interface_ids = @hasField(service_registry.Binding, "interface_id"),
    },
    .component_abi_schema = .{
        .defines_interface_ids = @hasDecl(component_abi_schema, "InterfaceId"),
        .binds_services_by_interface_id = @hasDecl(component_abi_schema, "interfaceIdForService"),
    },
    .principal_keyring = .{
        .uses_key_arena = @hasDecl(@FieldType(principal.Keyring, "slots"), "reserveIndex"),
        .uses_principal_index = @hasField(principal.Keyring, "principal_index"),
        .uses_publisher_index = @hasField(principal.Keyring, "publisher_index"),
    },
    .capability_table = .{
        .uses_capability_arena = @hasDecl(@FieldType(capability.CapabilityTable, "slots"), "reserveIndex"),
        .uses_target_generation_arena = @hasDecl(@FieldType(capability.CapabilityTable, "target_generations"), "reserveIndex"),
        .supports_direct_capability_slot_insertion = @hasDecl(@FieldType(capability.CapabilityTable, "slots"), "insertIndexAt"),
        .uses_holder_multimap = @hasField(capability.CapabilityTable, "holder_index"),
        .uses_target_multimap = @hasField(capability.CapabilityTable, "target_index"),
        .tracks_mutation_generation = @hasField(capability.CapabilityTable, "mutation_generation"),
    },
    .shared_memory = .{
        .uses_compact_mmu_object_mapping_head = @hasField(shared_memory.Object, "mmu_mapping_head"),
        .tracks_mmu_object_mapping_count = @hasField(shared_memory.Object, "mmu_mapping_count"),
        .uses_object_owner_index = @hasField(shared_memory.Table, "object_owner_index"),
        .uses_object_task_mapping_index = @hasField(shared_memory.Table, "object_task_mapping_index"),
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
        .uses_accelerator_deadline_heads = @hasField(userspace_scheduler.Scheduler, "accelerator_deadline_heads"),
        .uses_accelerator_claim_task_index = @hasField(userspace_scheduler.Scheduler, "accelerator_claim_task_index"),
        .grants_next_accelerator_claim = @hasDecl(userspace_scheduler.Scheduler, "grantNextAcceleratorClaim"),
        .caches_ui_presentation_eligibility = userspace_scheduler.STEADY_UI_ELIGIBILITY_CATALOG_LOOKUPS == 0,
        .uses_generational_task_handles_for_dispatch = @hasDecl(task_runtime.Runtime, "findByHandle") and
            userspace_scheduler.SCHEDULED_TASK_INDEX_LOOKUPS_PER_DISPATCH == 0,
    },
    .userspace_executor = .{
        .resolves_mailbox_authorities_together = @hasDecl(userspace_executor, "resolveMailboxAuthorities"),
        .caches_mailbox_authorities = @hasDecl(userspace_executor, "resolveMailboxAuthoritiesCached"),
        .activates_one_user_address_space_per_dispatch = userspace_executor.USER_ADDRESS_SPACE_ACTIVATIONS_PER_DISPATCH == 1,
        .accepts_prevalidated_task_records = @typeInfo(@TypeOf(userspace_executor.Executor.executeTask)).@"fn".params[4].type.? == *const task_runtime.TaskRecord,
        .installs_static_handoff_stack_once_per_bind = userspace_executor.STATIC_HANDOFF_STACK_INSTALLS_PER_BIND == 1,
        .avoids_steady_address_space_image_indexes = userspace_executor.STEADY_ADDRESS_SPACE_IMAGE_INDEX_LOOKUPS == 0,
        .avoids_steady_mapping_index_lookups = @hasDecl(userspace_executor.Executor, "mappingHandle") and
            userspace_executor.STEADY_MAPPING_INDEX_LOOKUPS_PER_DISPATCH == 0,
    },
    .userspace_loader = .{
        .uses_image_arena = @hasDecl(@FieldType(userspace_loader.Catalog, "images"), "reserveIndex"),
        .uses_bundle_index = @hasField(userspace_loader.Catalog, "bundle_index"),
    },
    .task_runtime = .{
        .uses_task_arena = @hasDecl(@FieldType(task_runtime.Runtime, "tasks"), "reserveIndex"),
        .uses_address_space_arena = @hasDecl(@FieldType(task_runtime.Runtime, "address_spaces"), "reserveIndex"),
        .uses_initial_component_label_index = @hasField(task_runtime.Runtime, "task_initial_component_label_index"),
        .tracks_task_state_counts = @hasField(task_runtime.Runtime, "task_state_counts"),
        .tracks_task_lifecycle_generation = @hasField(task_runtime.Runtime, "task_lifecycle_generation"),
        .tracks_task_capability_generation = @hasDecl(task_runtime.TaskRecord, "capabilityGeneration"),
        .installs_address_spaces_as_records = @hasDecl(task_runtime.Runtime, "installAddressSpaceRecord"),
    },
    .accelerator_scheduler = .{
        .uses_claim_arena = @hasField(accelerator_scheduler.Controller, "claims"),
        .uses_claim_task_index = @hasField(accelerator_scheduler.Controller, "claim_task_index"),
    },
    .background_dispatch = .{
        .uses_record_arena = @hasDecl(@FieldType(background_dispatch.Controller, "records"), "reserveIndex"),
        .tracks_active_count = @hasField(background_dispatch.Controller, "active_count"),
        .uses_active_record_index = @hasField(background_dispatch.Controller, "active_record_index"),
        .uses_reusable_record_index = @hasField(background_dispatch.Controller, "reusable_record_index"),
        .tracks_latest_record_id = @hasField(background_dispatch.Controller, "latest_record_id"),
    },
    .indexing_service = .{
        .uses_document_arena = @hasField(indexing_service.Service, "documents"),
        .uses_workspace_index = @hasField(indexing_service.Service, "workspace_index"),
    },
    .secure_secret_store = .{
        .uses_secret_arena = @hasDecl(@FieldType(secure_secret_store.Store, "secrets"), "reserve"),
        .uses_handle_arena = @hasDecl(@FieldType(secure_secret_store.Store, "handles"), "reserve"),
    },
    .os_identity = .{
        .uses_credential_arena = @hasDecl(@FieldType(os_identity.Store, "credentials"), "reserveIndex"),
    },

    .secret_vault_service = .{
        .uses_handle_arena = @hasDecl(@FieldType(secret_vault_service.Service, "handles"), "reserve"),
        .uses_secret_handle_index = @hasField(secret_vault_service.Service, "secret_handle_index"),
        .uses_active_handle_index = @hasField(secret_vault_service.Service, "active_handle_index"),
        .tracks_active_handles = @hasField(secret_vault_service.Service, "active_handle_count"),
    },
    .media_print_service = .{
        .uses_job_arena = @hasDecl(@FieldType(media_print_service.Service, "jobs"), "reserveIndex"),
        .uses_completed_job_index = @hasField(media_print_service.Service, "completed_job_index"),
    },
    .notification_center = .{
        .uses_notification_arena = @hasDecl(@FieldType(notification_center.Center, "notifications"), "reserveIndex"),
        .uses_source_reason_index = @hasField(notification_center.Center, "source_reason_index"),
        .tracks_permanent_attention_counts = @hasField(notification_center.Center, "permanent_attention_counts"),
        .uses_expiring_attention_index = @hasField(notification_center.Center, "expiring_attention_index"),
        .tracks_visible_notification_chain = @hasField(notification_center.Center, "visible_tail_slot"),
        .tracks_visible_notification_count = @hasField(notification_center.Center, "visible_notification_count"),
    },
    .secure_pasteboard = .{
        .uses_grant_arena = @hasDecl(@FieldType(secure_pasteboard.Service, "slots"), "reserve"),
    },
    .sensitive_capture_service = .{
        .uses_session_arena = @hasDecl(@FieldType(sensitive_capture_service.Service, "slots"), "reserve"),
        .tracks_active_sessions = @hasField(sensitive_capture_service.Service, "active_session_count"),
        .tracks_privacy_indicators = @hasField(sensitive_capture_service.Service, "privacy_indicator_counts"),
        .uses_active_session_index = @hasField(sensitive_capture_service.Service, "active_session_index"),
        .uses_active_kind_index = @hasField(sensitive_capture_service.Service, "active_kind_index"),
    },
    .agent_delegation_service = .{
        .uses_delegation_arena = @hasDecl(@FieldType(agent_delegation_service.Service, "slots"), "reserve"),
        .tracks_active_delegations = @hasField(agent_delegation_service.Service, "active_delegation_count"),
        .tracks_lowest_active_generation = @hasField(agent_delegation_service.Service, "lowest_active_generation"),
        .uses_generation_index = @hasField(agent_delegation_service.Service, "delegation_generation_index"),
        .tracks_active_generation_buckets = @hasField(agent_delegation_service.Service, "active_generation_buckets"),
        .uses_active_generation_bucket_arena = @hasDecl(@FieldType(agent_delegation_service.Service, "active_generation_buckets"), "reserve"),
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
    .public_store = .{
        .uses_release_arena = @hasDecl(@FieldType(public_store.Channel, "releases"), "reserveIndexAt"),
        .uses_bundle_release_index = @hasField(public_store.Channel, "bundle_release_index"),
        .uses_trusted_publisher_arena = @hasDecl(@FieldType(public_store.Channel, "trusted_publishers"), "reserve"),
    },
    .driver_service = .{
        .uses_driver_arena = @hasDecl(@FieldType(driver_service.Directory, "slots"), "reserve"),
    },
    .driver_runtime = .{
        .uses_activation_arena = @hasDecl(@FieldType(driver_runtime.Runtime, "arena"), "reserveIndex"),
        .uses_activation_class_index = @hasField(driver_runtime.Runtime, "class_index"),
        .uses_activation_service_index = @hasField(driver_runtime.Runtime, "service_index"),
    },
    .device_broker = .{
        .uses_controller_arena = device_broker.dma_program_indexing.uses_controller_arena,
        .uses_controller_free_list = device_broker.dma_program_indexing.uses_controller_free_list,
        .uses_unpublished_controller_queue = device_broker.dma_program_indexing.uses_unpublished_controller_queue,
        .tracks_controller_used_count = device_broker.dma_program_indexing.tracks_controller_used_count,
        .uses_dma_program_arena = device_broker.dma_program_indexing.uses_arena,
        .uses_dma_program_device_index = device_broker.dma_program_indexing.uses_device_index,
    },
    .network_policy = .{
        .uses_policy_arena = @hasDecl(@FieldType(network_policy.Directory, "policies"), "reserve"),
    },
    .policy_object = .{
        .uses_policy_arena = @hasDecl(@FieldType(policy_object.Directory, "policies"), "reserve"),
        .uses_scope_index = @hasField(policy_object.Directory, "scope_index"),
    },
    .event_ledger = .{
        .uses_event_arena = @hasField(event_ledger.Ledger, "events"),
        .indexes_kind = @hasField(event_ledger.Ledger, "kind_index"),
        .indexes_subject = @hasField(event_ledger.Ledger, "subject_index"),
        .indexes_task = @hasField(event_ledger.Ledger, "task_index"),
        .visits_indexes = @hasDecl(event_ledger.Ledger, "queryEvents"),
        .removes_evicted_indexes = @hasDecl(event_ledger.Ledger, "removeEventIndexes"),
    },
    .compositor_session = .{
        .uses_window_arena = @hasField(compositor_session.Session, "windows"),
        .uses_review_item_arena = @hasField(compositor_session.Session, "items"),
        .uses_task_bundle_index = @hasField(compositor_session.Session, "task_bundle_index"),
        .uses_task_window_index = @hasField(compositor_session.Session, "task_window_index"),
        .uses_reviewer_window_index = @hasField(compositor_session.Session, "reviewer_window_index"),
        .uses_window_review_item_index = @hasField(compositor_session.Session, "window_review_item_index"),
        .tracks_visible_window_count = @hasField(compositor_session.Session, "visible_window_count"),
        .supports_indexed_task_window_ownership = @hasDecl(compositor_session.Session, "taskOwnsVisibleWindow"),
        .supports_indexed_active_window_order = @hasDecl(compositor_session.Session, "activeWindowOrderIndex"),
        .uses_surface_task_index = @hasField(compositor_session.Session, "surface_task_index"),
        .tracks_active_surface_chain = @hasField(compositor_session.Session, "active_surface_head"),
        .caches_surface_prune_generation = @hasField(compositor_session.Session, "last_surface_prune_generation"),
    },
    .input_router = .{
        .uses_inbox_arena = @hasDecl(@FieldType(input_router.Router, "inboxes"), "reserveIndex"),
        .tracks_active_inbox_chain = @hasField(input_router.Router, "active_inbox_head"),
    },
    .native_ux = .{
        .uses_flow_arena = @hasField(native_ux.Controller, "flows"),
        .supports_ordered_flow_lookup = @hasDecl(native_ux.Controller, "flowAtOrder"),
    },
    .sync_transport_harness = .{
        .uses_relay_packet_arena = @hasField(sync_transport_harness.Relay, "packets"),
        .uses_relay_session_index = @hasField(sync_transport_harness.Relay, "session_index"),
    },
    .sync_transport = .{
        .uses_packet_capture_arena = @hasDecl(@FieldType(sync_transport.PacketCapture, "packets"), "reserveIndex"),
        .tracks_last_packet_id = @hasField(sync_transport.PacketCapture, "last_packet_id"),
    },
    .device_graph = .{
        .uses_user_root_arena = @hasDecl(@FieldType(device_graph.Graph, "user_roots"), "reserveIndex"),
        .uses_device_arena = @hasDecl(@FieldType(device_graph.Graph, "devices"), "reserveIndex"),
        .tracks_trusted_device_count = @hasField(device_graph.Graph, "trusted_device_count"),
        .rebuilds_loaded_indexes = @hasDecl(device_graph.Graph, "rebuildIndexes"),
    },
    .sync_service = .{
        .uses_overlay_session_arena = @hasField(sync_service.Service, "overlay_sessions"),
        .uses_workspace_policy_index = @hasField(sync_service.Service, "workspace_policy_index"),
        .uses_overlay_index = @hasField(sync_service.Service, "overlay_index"),
        .uses_database_contract_id_index = @hasField(sync_service.Service, "database_contract_id_index"),
        .uses_database_contract_bundle_index = @hasField(sync_service.Service, "database_contract_bundle_index"),
        .uses_database_contract_equivalent_index = @hasField(sync_service.Service, "database_contract_equivalent_index"),
        .uses_conflict_path_index = @hasField(sync_service.Service, "conflict_path_index"),
        .uses_conflict_object_index = @hasField(sync_service.Service, "conflict_object_index"),
        .uses_conflict_scope_index = @hasField(sync_service.Service, "conflict_scope_index"),
        .uses_outbound_transport_path_index = @hasField(sync_service.Service, "outbound_transport_path_index"),
        .uses_inbound_transport_path_index = @hasField(sync_service.Service, "inbound_transport_path_index"),
        .tracks_closed_overlay_sessions = @hasField(sync_service.Service, "closed_overlay_sessions"),
        .tracks_active_overlay_session_count = @hasField(sync_service.Service, "active_overlay_session_count"),
        .indexes_workspace_policies = @hasField(sync_service.Service, "workspace_policy_index"),
        .indexes_overlays = @hasField(sync_service.Service, "overlay_index"),
        .indexes_replica_scopes = @hasField(sync_service.Service, "replica_scope_index"),
        .indexes_database_contracts = @hasField(sync_service.Service, "database_contract_id_index"),
        .indexes_database_contract_equivalence = @hasField(sync_service.Service, "database_contract_equivalent_index"),
        .indexes_database_contract_bundles = @hasField(sync_service.Service, "database_contract_bundle_index"),
        .indexes_conflicts = @hasField(sync_service.Service, "conflict_path_index"),
        .indexes_conflict_objects = @hasField(sync_service.Service, "conflict_object_index"),
        .indexes_conflict_scopes = @hasField(sync_service.Service, "conflict_scope_index"),
        .indexes_inbound_transport_duplicates = @hasField(sync_service.Service, "inbound_transport_target_index") and
            @hasField(sync_service.Service, "inbound_transport_path_index") and
            @hasDecl(@FieldType(sync_state_support.PersistentState, "inbound_transport_frames"), "reserveIndex"),
        .indexes_inbound_transport_targets = @hasField(sync_service.Service, "inbound_transport_target_index"),
        .indexes_inbound_transport_high_water = @hasField(sync_service.Service, "inbound_transport_frame_count") and
            @hasField(sync_service.Service, "inbound_transport_target_index"),
        .indexes_inbound_transport_paths = @hasField(sync_service.Service, "inbound_transport_path_index"),
        .indexes_outbound_transport_frames = @hasDecl(@FieldType(sync_state_support.PersistentState, "outbound_transport_frames"), "reserveIndex"),
        .indexes_outbound_transport_targets = @hasField(sync_service.Service, "outbound_transport_target_index"),
        .indexes_outbound_transport_paths = @hasField(sync_service.Service, "outbound_transport_path_index"),
        .tracks_transport_frame_counts = @hasField(sync_service.Service, "outbound_transport_frame_count") and
            @hasField(sync_service.Service, "inbound_transport_frame_count"),
        .tracks_transport_frame_allocation_cursors = @hasField(sync_service.Service, "next_outbound_transport_frame_slot_index") and
            @hasField(sync_service.Service, "next_inbound_transport_frame_slot_index"),
        .tracks_sync_table_allocation_cursors = @hasField(@FieldType(sync_state_support.PersistentState, "workspace_policies"), "next_unclaimed_index") and
            @hasField(@FieldType(sync_state_support.PersistentState, "overlays"), "next_unclaimed_index") and
            @hasField(@FieldType(sync_state_support.PersistentState, "replica_entries"), "next_unclaimed_index") and
            @hasField(@FieldType(sync_state_support.PersistentState, "conflicts"), "next_unclaimed_index") and
            @hasField(@FieldType(sync_state_support.PersistentState, "database_contracts"), "next_unclaimed_index"),
    },
    .sync_adapters = .{
        .uses_transport_frame_arena = @hasField(sync_adapters.TransportQueue, "frames"),
        .uses_transport_frame_target_index = @hasField(sync_adapters.TransportQueue, "target_index"),
        .uses_transport_frame_path_index = @hasField(sync_adapters.TransportQueue, "path_index"),
    },
    .sync_state_store = .{
        .persists_state_records = @hasDecl(sync_state_store, "persist"),
        .loads_state_records = @hasDecl(sync_state_store, "load"),
        .uses_workspace_policy_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "workspace_policies"), "reserveIndex"),
        .uses_replica_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "replica_entries"), "reserveIndex"),
        .uses_conflict_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "conflicts"), "reserveIndex"),
        .uses_database_contract_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "database_contracts"), "reserveIndex"),
        .uses_overlay_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "overlays"), "reserveIndex"),
        .uses_outbound_transport_frame_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "outbound_transport_frames"), "reserveIndex"),
        .uses_inbound_transport_frame_arena = @hasDecl(@FieldType(sync_state_support.PersistentState, "inbound_transport_frames"), "reserveIndex"),
    },
    .workspace = .{
        .uses_path_index = @hasField(workspace.WorkspaceRecord, "path_index"),
        .tracks_mutation_log = @hasField(workspace.WorkspaceRecord, "mutation_log"),
        .tracks_share_table = @hasField(workspace.WorkspaceRecord, "share_table"),
        .uses_share_grant_principal_index = @hasField(workspace.WorkspaceShareTable, "share_grant_principal_index"),
        .tracks_staging_state = @hasField(workspace.WorkspaceRecord, "staging"),
        .tracks_recoverable_deletes = @hasField(workspace.WorkspaceRecord, "recoverable_deletes"),
        .caches_leaf_hashes = @hasField(workspace.WorkspacePathIndex, "leaf_hashes"),
        .uses_index_root_address = @hasField(workspace.WorkspacePathIndex, "root_address"),
        .supports_indexed_path_lookup = @hasField(workspace.WorkspacePathIndex, "path_slots"),
        .supports_borrowed_path_lookup = @hasDecl(workspace.Directory, "resolveBorrowed"),
        .supports_indexed_object_lookup = @hasField(workspace.WorkspacePathIndex, "object_slots"),
        .supports_indexed_snapshot_lookup = @hasDecl(workspace.Directory, "findSnapshotConst"),
        .tracks_workspace_count = @hasDecl(workspace.Directory, "workspaceCount"),
        .tracks_snapshot_count = @hasDecl(workspace.Directory, "snapshotCount"),
        .tracks_oldest_snapshot_generation = @hasField(workspace.WorkspaceRecord, "oldest_snapshot_generation"),
        .exposes_oldest_snapshot_generation = @hasDecl(workspace.WorkspaceRecord, "oldestSnapshotGeneration"),
    },
    .storage_volume = .{
        .persists_workspace_state = @hasDecl(storage_volume, "saveToImage"),
        .replays_state_by_primary_index = @hasDecl(storage_volume, "loadFromImage"),
        .requires_target_nvme_attachment = @hasDecl(storage_volume.Volume, "hasProductionStorageBackend"),
        .tracks_latest_inserted_version = @hasField(object_store.Store, "latest_inserted_version_id"),
        .exposes_latest_inserted_version_lookup = @hasDecl(object_store.Store, "latestInsertedVersionConst"),
        .uses_object_type_index = @hasField(object_store.Store, "object_type_index"),
        .tracks_max_blob_payload_bytes = @hasField(object_store.Store, "max_blob_payload_bytes"),
        .exposes_max_blob_payload_bytes = @hasDecl(object_store.Store, "maxBlobPayloadBytes"),
    },
    .service_catalog = .{
        .uses_bootstrap_owner_keys = @hasField(service_catalog.ServiceCatalogEntry, "owner_key"),
        .uses_bootstrap_service_record_keys = @hasField(service_catalog.ServiceCatalogEntry, "service_record_key"),
        .uses_catalog_class_index = service_catalog.service_catalog_indexing.uses_catalog_class_index,
        .uses_service_contract_class_index = service_catalog.service_catalog_indexing.uses_service_contract_class_index,
        .uses_published_contract_class_index = service_catalog.service_catalog_indexing.uses_published_contract_class_index,
    },
    .supervisor = .{
        .uses_service_arena = supervisor.supervisor_indexing.uses_service_arena,
        .uses_service_class_index = supervisor.supervisor_indexing.uses_service_class_index,
        .uses_diagnostic_service_index = supervisor.supervisor_indexing.uses_diagnostic_service_index,
        .uses_diagnostic_service_kind_index = supervisor.supervisor_indexing.uses_diagnostic_service_kind_index,
        .uses_diagnostic_ring_cursor = @hasField(supervisor.Supervisor, "next_diagnostic_slot"),
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
        .caches_surface_authority_lifecycle_generation = @hasField(session_manager_boot_flow.SessionManager, "surface_authority_scanned_lifecycle_generation"),
    },
};
