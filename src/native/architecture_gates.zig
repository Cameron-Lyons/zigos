pub const sync_private_overlay = .{
    .transport_harness = .{
        .uses_signed_encrypted_frames = true,
        .verifies_signed_frames = true,
        .rejects_foreign_session_task_submitters = true,
    },
    .service_test = .{
        .runs_deterministic_two_device_overlay_replication = true,
        .opens_overlay_sessions = true,
        .replicates_workspaces = true,
        .submits_relay_packets = true,
    },
    .sync_service = .{
        .sends_overlay_relay_frames_via_service_port = true,
    },
};

pub const indexed_hot_path_tables = .{
    .indexed_arena = .{
        .tracks_used_count = true,
    },
    .service_registry = .{
        .uses_binding_arena = true,
        .uses_typed_interface_ids = true,
        .uses_interface_id_request_keys = true,
        .removed_legacy_fixed_table_scan = true,
    },
    .component_abi_schema = .{
        .defines_interface_ids = true,
        .binds_services_by_interface_id = true,
    },
    .userspace_scheduler = .{
        .uses_scheduler_slot_arena = true,
        .uses_ready_heads = true,
        .selects_ready_resource_class = true,
        .wakes_tasks = true,
        .refills_task_budget = true,
        .tracks_deadline_tick = true,
        .configures_resource_state = true,
        .uses_accelerator_claim_heads = true,
        .grants_next_accelerator_claim = true,
        .removed_legacy_linear_slot_scan = true,
    },
    .accelerator_scheduler = .{
        .uses_claim_arena = true,
        .uses_claim_task_index = true,
        .removed_legacy_fixed_claim_array = true,
    },
    .indexing_service = .{
        .uses_document_arena = true,
        .removed_legacy_fixed_table_scan = true,
    },
    .event_ledger = .{
        .uses_event_arena = true,
        .indexes_kind = true,
        .indexes_subject = true,
        .indexes_task = true,
        .visits_indexes = true,
    },
    .compositor_session = .{
        .uses_window_arena = true,
        .uses_review_item_arena = true,
        .removed_legacy_fixed_window_arrays = true,
    },
    .native_ux = .{
        .uses_flow_arena = true,
        .supports_ordered_flow_lookup = true,
        .removed_legacy_fixed_flow_array = true,
    },
    .sync_transport_harness = .{
        .uses_relay_packet_arena = true,
        .uses_relay_session_index = true,
        .removed_legacy_packet_scan = true,
    },
    .sync_service = .{
        .uses_overlay_session_arena = true,
        .tracks_closed_overlay_sessions = true,
        .tracks_active_overlay_session_count = true,
        .removed_legacy_fixed_overlay_session_array = true,
    },
    .sync_adapters = .{
        .uses_transport_frame_arena = true,
        .uses_transport_frame_target_index = true,
        .uses_transport_frame_path_index = true,
        .removed_legacy_fixed_frame_array = true,
    },
    .sync_state_store = .{
        .persists_state_records_v4 = true,
        .uses_record_store_puts = true,
        .deletes_stale_records = true,
        .removed_monolithic_state_codec = true,
    },
    .workspace = .{
        .uses_path_index = true,
        .tracks_mutation_log = true,
        .tracks_share_table = true,
        .tracks_staging_state = true,
        .tracks_recoverable_deletes = true,
        .caches_leaf_hashes = true,
        .uses_index_root_address = true,
        .supports_indexed_path_lookup = true,
        .rebuilds_path_merkle = true,
    },
    .storage_volume = .{
        .persists_workspace_state_v4 = true,
        .hashes_workspace_root_address = true,
        .rejects_legacy_demo_images = true,
        .replays_workspaces_by_primary_index = true,
        .replays_snapshots_by_primary_index = true,
        .requires_target_nvme_attachment = true,
        .removed_monolithic_workspace_state_buffer = true,
    },
    .service_catalog = .{
        .uses_bootstrap_owner_keys = true,
        .uses_bootstrap_service_record_keys = true,
    },
    .session_bootstrap = .{
        .uses_catalog_owner_lookup = true,
        .uses_catalog_service_record_lookup = true,
        .iterates_service_catalog = true,
    },
    .service_bootstrap = .{
        .has_launch_service_request = true,
    },
    .session_service_bootstrap = .{
        .launches_contract_services = true,
        .delegates_owner_lookup_to_catalog = true,
        .delegates_service_id_lookup_to_catalog = true,
    },
    .session_manager_boot_flow = .{
        .delegates_service_record_lookup = true,
    },
};
