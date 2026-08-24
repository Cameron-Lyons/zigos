const indexed_arena = @import("core/indexed_arena.zig");
const id_index = @import("core/id_index.zig");
const principal = @import("core/principal.zig");
const signing = @import("core/signing.zig");
const sdk_idl = @import("sdk/idl.zig");
const sdk_app_platform = @import("sdk/app_platform.zig");
const sdk_component_abi = @import("sdk/component_abi.zig");
const sdk_object_store = @import("sdk/object_store_api.zig");
const sdk_permissions = @import("sdk/permissions.zig");
const sdk_simulator = @import("sdk/simulator.zig");
const sdk_ui = @import("sdk/ui.zig");
const service_registry = @import("services/service_registry.zig");
const component_abi_schema = @import("services/component_abi_schema.zig");
const userspace_scheduler = @import("task/userspace_scheduler.zig");
const userspace_executor = @import("task/userspace_executor.zig");
const userspace_loader = @import("task/userspace_loader.zig");
const task_runtime = @import("task/task_runtime.zig");
const debug_contract = @import("security/debug_contract.zig");
const accelerator_scheduler = @import("task/accelerator_scheduler.zig");
const background_dispatch = @import("task/background_dispatch.zig");
const indexing_service = @import("services/indexing_service.zig");
const event_ledger = @import("platform/event_ledger.zig");
const recovery_environment = @import("platform/recovery_environment.zig");
const attestation_service = @import("platform/attestation_service.zig");
const immutable_base = @import("platform/immutable_base.zig");
const measured_boot = @import("platform/measured_boot.zig");
const kernel_dmar = @import("../kernel/platform/dmar.zig");
const compositor_session = @import("platform/compositor_session.zig");
const input_router = @import("platform/input_router.zig");
const input_driver_task = @import("drivers/input_driver_task.zig");
const permission_review_service = @import("policy/permission_review_service.zig");
const policy_mediation = @import("policy/policy_mediation.zig");
const xhci = @import("../kernel/drivers/xhci.zig");
const native_ux = @import("platform/native_ux.zig");
const sync_transport_harness = @import("sync/sync_transport_harness.zig");
const sync_transport = @import("sync/sync_transport.zig");
const device_graph = @import("sync/device_graph.zig");
const sync_service = @import("sync/sync_service.zig");
const sync_latest_mutations = @import("sync/sync_service/latest_mutations.zig");
const sync_service_test = @import("sync/sync_service_test.zig");
const sync_adapters = @import("sync/sync_adapters.zig");
const sync_state_support = @import("sync/sync_state_support.zig");
const sync_state_store = @import("sync/sync_state_store.zig");
const object_store = @import("storage/object_store.zig");
const workspace = @import("storage/workspace.zig");
const storage_volume = @import("storage/storage_volume.zig");
const storage_root_slot = @import("storage/volume/root_slot.zig");
const policy_object = @import("policy/policy_object.zig");
const secure_secret_store = @import("platform/secure_secret_store.zig");
const os_identity = @import("platform/os_identity.zig");
const secret_vault_service = @import("services/secret_vault_service.zig");
const media_print_service = @import("services/media_print_service.zig");
const network_session_service = @import("services/network_session_service.zig");
const notification_center = @import("services/notification_center.zig");
const secure_pasteboard = @import("services/secure_pasteboard.zig");
const capability = @import("kernel_api/capability.zig");
const endpoint = @import("kernel_api/endpoint.zig");
const shared_memory = @import("kernel_api/shared_memory.zig");
const sensitive_capture_service = @import("services/sensitive_capture_service.zig");
const agent_delegation_service = @import("services/agent_delegation_service.zig");
const object_resilience_service = @import("services/object_resilience_service.zig");
const personal_context_service = @import("services/personal_context_service.zig");
const package_service = @import("services/package_service.zig");
const public_store = @import("services/public_store.zig");
const driver_service = @import("drivers/driver_service.zig");
const driver_runtime = @import("drivers/driver_runtime.zig");
const bootstrap_driver_port = @import("drivers/bootstrap_driver_port.zig");
const network_driver_task = @import("drivers/network_driver_task.zig");
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
const ProbeGenerationalArena = indexed_arena.GenerationalArena("ProbeHandle", ProbeArenaSlot, 1);
const ProbePagedArena = indexed_arena.PagedIndexedArenaWithKey(u64, ProbeArenaSlot, 1, 1, 2, probeArenaKey);

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
        .uses_split_primary_index_storage = id_index.SlotIndex(256) == u8 and
            id_index.SlotIndex(257) == u16 and
            @sizeOf(id_index.Table(1_536)) == 16_896,
        .uses_capacity_sized_arena_free_lists = indexed_arena.ReusableIndex(255) == u8 and
            indexed_arena.ReusableIndex(256) == u16 and
            @sizeOf(@FieldType(ProbeArena, "free_next")) == 1 and
            @sizeOf(@FieldType(ProbeArena, "free_head")) == 1,
        .uses_capacity_sized_arena_metadata = indexed_arena.COMPACT_ARENA_METADATA and
            @FieldType(ProbeArena, "next_unclaimed_index") == u8 and
            @FieldType(ProbeArena, "used_count") == u8 and
            @FieldType(ProbeArena, "dirty_count") == u8 and
            @FieldType(ProbeGenerationalArena, "next_unclaimed_index") == u8 and
            @FieldType(ProbeGenerationalArena, "used_count") == u8 and
            @FieldType(ProbePagedArena, "next_unclaimed_index") == u8 and
            @FieldType(ProbePagedArena, "used_count") == u8,
    },
    .service_registry = .{
        .uses_binding_arena = @hasField(service_registry.Registry, "bindings"),
        .uses_typed_interface_ids = @hasDecl(service_registry.Binding, "interfaceId"),
        .derives_static_contract_metadata = service_registry.DERIVES_STATIC_CONTRACT_METADATA,
    },
    .component_abi_schema = .{
        .defines_interface_ids = @hasDecl(component_abi_schema, "InterfaceId"),
        .binds_services_by_interface_id = @hasDecl(component_abi_schema, "interfaceIdForService"),
        .stores_compact_contract_metadata = component_abi_schema.COMPACT_INTERFACE_CONTRACT_METADATA and
            @FieldType(component_abi_schema.InterfaceContract, "operation_count") == u8,
        .keeps_contracts_within_ceiling = @sizeOf(component_abi_schema.InterfaceContract) <= component_abi_schema.INTERFACE_CONTRACT_SIZE_CEILING_BYTES,
    },
    .sdk_component_abi = .{
        .stores_compact_binding_metadata = sdk_component_abi.COMPACT_COMPONENT_BINDING_METADATA and
            @FieldType(sdk_component_abi.Binding, "operation_count") == u8,
        .keeps_bindings_within_ceiling = @sizeOf(sdk_component_abi.Binding) <= sdk_component_abi.BINDING_SIZE_CEILING_BYTES,
    },
    .sdk_idl = .{
        .uses_borrowed_large_output_apis = @hasDecl(sdk_idl, "parseInto") and
            @hasDecl(sdk_idl, "generateInto") and
            !@hasDecl(sdk_idl, "parse") and
            !@hasDecl(sdk_idl, "generate") and
            @hasDecl(sdk_app_platform, "compileInto") and
            !@hasDecl(sdk_app_platform, "compile") and
            @hasDecl(sdk_simulator.Simulator, "parseAndGenerateInto") and
            !@hasDecl(sdk_simulator.Simulator, "parseAndGenerate"),
        .stores_compact_bounded_metadata = sdk_idl.COMPACT_IDL_METADATA and
            @FieldType(sdk_idl.TypeRef, "name_len") == u8 and
            @FieldType(sdk_idl.Field, "name_len") == u8 and
            @FieldType(sdk_idl.Record, "name_len") == u8 and
            @FieldType(sdk_idl.Record, "field_start") == u8 and
            @FieldType(sdk_idl.Record, "field_count") == u8 and
            @FieldType(sdk_idl.PermissionDecl, "resource_len") == u8 and
            @FieldType(sdk_idl.ObjectDecl, "name_len") == u8 and
            @FieldType(sdk_idl.ObjectDecl, "path_len") == u8 and
            @FieldType(sdk_idl.SyncDecl, "prefix_len") == u8 and
            @FieldType(sdk_idl.Operation, "name_len") == u8 and
            @FieldType(sdk_idl.Operation, "request_type_len") == u8 and
            @FieldType(sdk_idl.Operation, "response_type_len") == u8 and
            @FieldType(sdk_idl.Interface, "name_len") == u8 and
            @FieldType(sdk_idl.Interface, "operation_start") == u8 and
            @FieldType(sdk_idl.Interface, "operation_count") == u8 and
            @FieldType(sdk_idl.Document, "interface_count") == u8 and
            @FieldType(sdk_idl.Document, "operation_count") == u8 and
            @FieldType(sdk_idl.Document, "record_count") == u8 and
            @FieldType(sdk_idl.Document, "field_count") == u8 and
            @FieldType(sdk_idl.Document, "permission_count") == u8 and
            @FieldType(sdk_idl.Document, "object_count") == u8 and
            @FieldType(sdk_idl.Document, "sync_count") == u8 and
            @FieldType(sdk_idl.GeneratedSource, "len") == u16,
        .keeps_fixed_state_within_ceilings = @sizeOf(sdk_idl.TypeRef) <= sdk_idl.TYPE_REF_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.Field) <= sdk_idl.FIELD_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.Record) <= sdk_idl.RECORD_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.PermissionDecl) <= sdk_idl.PERMISSION_DECL_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.ObjectDecl) <= sdk_idl.OBJECT_DECL_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.SyncDecl) <= sdk_idl.SYNC_DECL_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.Operation) <= sdk_idl.OPERATION_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.Interface) <= sdk_idl.INTERFACE_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.Document) <= sdk_idl.DOCUMENT_SIZE_CEILING_BYTES and
            @sizeOf(sdk_idl.GeneratedSource) <= sdk_idl.GENERATED_SOURCE_SIZE_CEILING_BYTES,
    },
    .sdk_review = .{
        .stores_compact_ui_metadata = sdk_ui.COMPACT_REVIEW_UI_METADATA and
            @FieldType(sdk_ui.Node, "child_count") == u8 and
            @FieldType(sdk_ui.AccessibilityReport, "node_count") == u8 and
            @FieldType(sdk_ui.AccessibilityReport, "issue_count") == u8,
        .stores_compact_permission_metadata = sdk_permissions.COMPACT_PERMISSION_REVIEW_METADATA and
            @FieldType(sdk_permissions.ReviewPlan, "grant_count") == u8 and
            @FieldType(sdk_permissions.ReviewPlan, "node_count") == u8 and
            @FieldType(sdk_permissions.HarnessResult, "required_count") == u8 and
            @FieldType(sdk_permissions.HarnessResult, "optional_count") == u8 and
            @FieldType(sdk_permissions.HarnessResult, "denied_required_count") == u8 and
            @FieldType(sdk_permissions.HarnessResult, "denied_optional_count") == u8,
        .derives_permission_harness_command_count = sdk_permissions.DERIVES_HARNESS_COMMAND_COUNT and
            !@hasField(sdk_permissions.Harness, "command_count") and
            @hasDecl(sdk_permissions.Harness, "commandCount"),
        .stores_compact_simulator_results = sdk_simulator.COMPACT_SIMULATOR_RESULT_METADATA and
            @FieldType(sdk_simulator.PermissionReviewResult, "request_count") == u8 and
            @FieldType(sdk_simulator.PermissionReviewResult, "grant_count") == u8 and
            @FieldType(sdk_simulator.PermissionReviewResult, "review_len") == u16 and
            @FieldType(sdk_simulator.LaunchResult, "component_count") == u8 and
            @FieldType(sdk_simulator.LaunchResult, "asset_count") == u8 and
            @FieldType(sdk_simulator.LaunchResult, "permission_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "interface_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "operation_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "record_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "native_declaration_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "lint_issue_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "permission_grant_count") == u8 and
            @FieldType(sdk_simulator.NativeAppHarnessResult, "accessibility_issue_count") == u8,
        .keeps_fixed_state_within_ceilings = @sizeOf(sdk_ui.Node) <= sdk_ui.NODE_SIZE_CEILING_BYTES and
            @sizeOf(sdk_ui.AccessibilityReport) <= sdk_ui.ACCESSIBILITY_REPORT_SIZE_CEILING_BYTES and
            @sizeOf(sdk_permissions.ReviewPlan) <= sdk_permissions.REVIEW_PLAN_SIZE_CEILING_BYTES and
            @sizeOf(sdk_permissions.HarnessResult) <= sdk_permissions.HARNESS_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(sdk_permissions.Harness) <= sdk_permissions.HARNESS_SIZE_CEILING_BYTES and
            @sizeOf(sdk_simulator.PermissionReviewResult) <= sdk_simulator.PERMISSION_REVIEW_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(sdk_simulator.LaunchResult) <= sdk_simulator.LAUNCH_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(sdk_simulator.NativeAppHarnessResult) <= sdk_simulator.NATIVE_APP_HARNESS_RESULT_SIZE_CEILING_BYTES,
    },
    .sdk_object_store = .{
        .stores_compact_handle_metadata = sdk_object_store.COMPACT_OBJECT_HANDLE_METADATA and
            @FieldType(sdk_object_store.ObjectHandle, "label_len") == u8 and
            @FieldType(sdk_object_store.ObjectHandle, "content_type_len") == u8,
        .keeps_handles_within_ceilings = @sizeOf(sdk_object_store.ObjectHandle) <= sdk_object_store.OBJECT_HANDLE_SIZE_CEILING_BYTES and
            @sizeOf(sdk_object_store.LoadedObject) <= sdk_object_store.LOADED_OBJECT_SIZE_CEILING_BYTES,
    },
    .release_signing = .{
        .stores_compact_verifier_metadata = signing.COMPACT_RELEASE_VERIFIER_METADATA and
            @FieldType(signing.ReleaseVerifierMetadata, "public_key_len") == u16,
        .keeps_verifier_metadata_within_ceiling = @sizeOf(signing.ReleaseVerifierMetadata) <= signing.RELEASE_VERIFIER_METADATA_SIZE_CEILING_BYTES,
    },
    .principal_keyring = .{
        .uses_key_arena = @hasDecl(@FieldType(principal.Keyring, "slots"), "reserveIndex"),
        .uses_principal_index = @hasField(principal.Keyring, "principal_index"),
        .uses_publisher_index = @hasField(principal.Keyring, "publisher_index"),
        .stores_compact_key_metadata = principal.COMPACT_KEY_RECORD_METADATA and
            @FieldType(principal.PrincipalKeyRecord, "publisher_len") == u8,
        .keeps_keyring_state_within_ceilings = @sizeOf(principal.PrincipalKeyRecord) <= principal.PRINCIPAL_KEY_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(principal.Keyring) <= principal.KEYRING_SIZE_CEILING_BYTES,
    },
    .capability_table = .{
        .uses_capability_arena = @hasDecl(@FieldType(capability.CapabilityTable, "slots"), "reserveHandle"),
        .uses_generational_capability_ids = @hasDecl(@FieldType(capability.CapabilityTable, "slots"), "getByHandle"),
        .stores_compact_grant_metadata = capability.COMPACT_GRANT_METADATA and
            @FieldType(capability.GrantPlan, "entry_count") == u8 and
            @FieldType(capability.GrantReservation, "slot_indexes") == [capability.MAX_GRANT_PLAN_ENTRIES]capability.CapabilitySlotIndex and
            @FieldType(capability.GrantReservation, "new_target_count") == u8,
        .keeps_grant_reservation_within_ceiling = @sizeOf(capability.GrantReservation) <= capability.GRANT_RESERVATION_SIZE_CEILING_BYTES,
        .avoids_capability_primary_index_lookups = capability.CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_QUERY == 0,
        .avoids_capability_id_collision_probes = capability.CAPABILITY_ID_COLLISION_PROBES_PER_INSERT == 0,
        .uses_target_generation_arena = @hasDecl(@FieldType(capability.CapabilityTable, "target_generations"), "reserveIndex"),
        .supports_direct_capability_slot_insertion = @hasDecl(@FieldType(capability.CapabilityTable, "slots"), "reserveHandleAt"),
        .uses_holder_multimap = @hasField(capability.CapabilityTable, "holder_index"),
        .uses_target_multimap = @hasField(capability.CapabilityTable, "target_index"),
        .tracks_mutation_generation = @hasField(capability.CapabilityTable, "mutation_generation"),
        .retires_task_bound_and_targeting_authority = @hasDecl(capability.CapabilityTable, "retireTaskAuthority"),
        .retires_dead_target_authority = @hasDecl(capability.CapabilityTable, "retireTargetAuthority"),
    },
    .endpoint_table = .{
        .uses_generational_endpoint_ids = @hasDecl(@FieldType(endpoint.Table, "arena"), "getByHandle"),
        .avoids_endpoint_primary_index_lookups = endpoint.ENDPOINT_PRIMARY_INDEX_LOOKUPS_PER_OPERATION == 0,
        .avoids_endpoint_id_collision_probes = endpoint.ENDPOINT_ID_COLLISION_PROBES_PER_INSERT == 0,
        .retires_task_owned_endpoints = @hasDecl(endpoint.Table, "retireTask"),
    },
    .shared_memory = .{
        .uses_generational_object_ids = @hasDecl(shared_memory.ObjectArena, "getByHandle"),
        .avoids_object_primary_index_lookups = shared_memory.SHARED_MEMORY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION == 0,
        .avoids_object_id_collision_probes = shared_memory.SHARED_MEMORY_ID_COLLISION_PROBES_PER_INSERT == 0,
        .uses_compact_mmu_object_mapping_head = @hasField(shared_memory.Object, "mmu_mapping_head"),
        .tracks_mmu_object_mapping_count = @hasField(shared_memory.Object, "mmu_mapping_count"),
        .uses_object_owner_index = @hasDecl(shared_memory.ObjectOwnerIndex, "append"),
        .bounds_object_task_mapping_scans = shared_memory.OBJECT_TASK_MAPPING_SCAN_BOUND == shared_memory.MAX_MAPPINGS_PER_OBJECT,
        .bounds_mmu_object_mapping_scans = shared_memory.MMU_OBJECT_MAPPING_SCAN_BOUND == shared_memory.MAX_MAPPINGS_PER_OBJECT + 3,
        .avoids_mmu_primary_index_lookups = shared_memory.MMU_PRIMARY_INDEX_LOOKUPS_PER_OPERATION == 0,
        .uses_reusable_mmu_mapping_slots = @hasDecl(@FieldType(shared_memory.FreestandingMmu, "mappings"), "reserveIndex"),
        .retires_task_owned_objects_and_peer_mappings = @hasDecl(shared_memory.Table, "retireTask"),
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
        .uses_accelerator_claim_task_index = @hasField(userspace_scheduler.AcceleratorClaimBacking, "task_index"),
        .grants_next_accelerator_claim = @hasDecl(userspace_scheduler.Scheduler, "grantNextAcceleratorClaim"),
        .stores_compact_queue_metadata = userspace_scheduler.COMPACT_QUEUE_METADATA and
            @FieldType(userspace_scheduler.Scheduler, "ready_heads") == [userspace_scheduler.RESOURCE_CLASS_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "ready_tails") == [userspace_scheduler.RESOURCE_CLASS_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "ready_counts") == [userspace_scheduler.RESOURCE_CLASS_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "ready_task_count") == userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "accelerator_claim_heads") == [userspace_scheduler.ENGINE_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "accelerator_claim_tails") == [userspace_scheduler.ENGINE_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "accelerator_deadline_heads") == [userspace_scheduler.ENGINE_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "accelerator_deadline_tails") == [userspace_scheduler.ENGINE_COUNT]userspace_scheduler.QueueSlotIndex and
            @FieldType(userspace_scheduler.Scheduler, "accelerator_claim_counts") == [userspace_scheduler.ENGINE_COUNT]userspace_scheduler.QueueSlotIndex,
        .keeps_queue_state_within_ceilings = @sizeOf(userspace_scheduler.Scheduler) <= userspace_scheduler.SCHEDULER_SIZE_CEILING_BYTES and
            @sizeOf(userspace_scheduler.AcceleratorClaimBacking) <= userspace_scheduler.ACCELERATOR_CLAIM_BACKING_SIZE_CEILING_BYTES,
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
        .uses_mapping_arena = @hasDecl(userspace_executor.MappingArena, "reserveHandle"),
        .avoids_cold_mapping_slot_scans = userspace_executor.COLD_MAPPING_LINEAR_SLOT_SCANS == 0,
        .avoids_steady_retirement_slot_scans = userspace_executor.STEADY_RETIREMENT_SLOT_SCANS_PER_DISPATCH == 0,
        .avoids_unrelated_capability_mutation_authority_scans = userspace_executor.UNRELATED_CAPABILITY_MUTATION_AUTHORITY_SCANS == 0,
        .avoids_unchanged_resume_mailbox_writes = userspace_executor.UNCHANGED_RESUME_KERNEL_MAILBOX_FIELD_WRITES_PER_DISPATCH == 0,
    },
    .userspace_loader = .{
        .uses_image_arena = @hasDecl(@FieldType(userspace_loader.Catalog, "images"), "reserveIndex"),
        .uses_bundle_index = @hasField(userspace_loader.Catalog, "bundle_index"),
    },
    .task_runtime = .{
        .uses_task_arena = @hasDecl(@FieldType(task_runtime.Runtime, "tasks"), "reserveIndex"),
        .uses_address_space_arena = @hasDecl(task_runtime.Runtime.AddressSpaceArenaType, "reserveIndex"),
        .heap_backs_address_space_arena_on_freestanding = task_runtime.HEAP_BACKED_ADDRESS_SPACE_ARENA_ON_FREESTANDING,
        .stores_compact_task_provenance = @sizeOf(task_runtime.TaskProvenanceRecord) < @sizeOf(task_runtime.ProvenanceRecord),
        .keeps_executable_mapping_only_in_address_space = !@hasField(task_runtime.TaskColdRecord, "userspace_image"),
        .uses_initial_component_label_index = @hasField(task_runtime.Runtime, "task_initial_component_label_index"),
        .tracks_task_state_counts = task_runtime.COMPACT_LIFECYCLE_METADATA and
            @FieldType(task_runtime.Runtime, "task_state_counts") == [@typeInfo(task_runtime.TaskState).@"enum".fields.len]task_runtime.TaskStateCount,
        .keeps_runtime_within_target_ceiling = @sizeOf(task_runtime.Runtime) <= task_runtime.RUNTIME_SIZE_CEILING_BYTES,
        .tracks_task_lifecycle_generation = @hasField(task_runtime.Runtime, "task_lifecycle_generation"),
        .bounds_task_capability_scans = task_runtime.TASK_CAPABILITY_SCAN_BOUND == task_runtime.MAX_TASK_CAPABILITIES,
        .avoids_task_capability_primary_index_lookups = task_runtime.TASK_CAPABILITY_PRIMARY_INDEX_LOOKUPS_PER_OPERATION == 0,
        .tracks_task_capability_generation = @hasDecl(task_runtime.TaskRecord, "capabilityGeneration"),
        .removes_retired_capability_attachments = @hasDecl(task_runtime.Runtime, "revokeCapabilityEverywhere"),
        .installs_address_spaces_as_records = @hasDecl(task_runtime.Runtime, "installAddressSpaceRecord"),
    },
    .debug_contract = .{
        .stores_compact_contract_text_lengths = debug_contract.COMPACT_DEBUG_TEXT_METADATA and
            @FieldType(debug_contract.DenialExplanation, "operation_len") == u8 and
            @FieldType(debug_contract.DenialExplanation, "required_authority_len") == u8 and
            @FieldType(debug_contract.DenialExplanation, "blocking_policy_len") == u8 and
            @FieldType(debug_contract.ProvenanceRecord, "operation_len") == u8 and
            @FieldType(debug_contract.ProvenanceRecord, "detail_len") == u8,
        .keeps_debug_state_within_ceilings = @sizeOf(debug_contract.DenialExplanation) <= debug_contract.DENIAL_EXPLANATION_SIZE_CEILING_BYTES and
            @sizeOf(debug_contract.ProvenanceRecord) <= debug_contract.PROVENANCE_RECORD_SIZE_CEILING_BYTES,
    },
    .accelerator_scheduler = .{
        .uses_claim_arena = @hasField(accelerator_scheduler.Controller, "claims"),
        .uses_claim_task_index = @hasField(accelerator_scheduler.Controller, "claim_task_index"),
    },
    .background_dispatch = .{
        .uses_bounded_record_scan = background_dispatch.BOUNDED_RECORD_SCAN,
        .stores_compact_dispatch_metadata = background_dispatch.COMPACT_DISPATCH_METADATA and
            @FieldType(background_dispatch.DispatchRecord, "background_task_id_len") == u8 and
            @FieldType(background_dispatch.Controller, "active_count") == u8 and
            @FieldType(background_dispatch.Controller, "record_count") == u8 and
            @FieldType(background_dispatch.Controller, "next_reusable_slot") == u8,
        .keeps_dispatch_state_within_ceilings = @sizeOf(background_dispatch.DispatchRecord) <= background_dispatch.DISPATCH_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(background_dispatch.Controller) <= background_dispatch.CONTROLLER_SIZE_CEILING_BYTES,
        .tracks_active_count = @hasField(background_dispatch.Controller, "active_count"),
        .uses_fair_reuse_cursor = @hasField(background_dispatch.Controller, "next_reusable_slot"),
        .tracks_latest_record_id = @hasField(background_dispatch.Controller, "latest_record_id"),
    },
    .indexing_service = .{
        .uses_bounded_document_scan = indexing_service.BOUNDED_DOCUMENT_SCAN,
        .uses_dense_document_table = indexing_service.DENSE_DOCUMENT_TABLE,
        .stores_compact_document_metadata = indexing_service.COMPACT_DOCUMENT_METADATA,
        .drops_document_indexes = !@hasField(indexing_service.Service, "workspace_index") and
            @FieldType(indexing_service.Service, "documents") == [indexing_service.MAX_DOCUMENTS]indexing_service.DocumentRecord,
        .keeps_fixed_state_within_ceiling = @sizeOf(indexing_service.Service) <= indexing_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .secure_secret_store = .{
        .uses_bounded_secret_lookup = secure_secret_store.BOUNDED_SECRET_LOOKUP,
        .uses_dense_secret_table = secure_secret_store.DENSE_SECRET_TABLE and
            @FieldType(secure_secret_store.Store, "secrets") == [secure_secret_store.MAX_SECRETS]secure_secret_store.SecretRecord,
        .stores_compact_secret_metadata = secure_secret_store.COMPACT_SECRET_METADATA and
            @FieldType(secure_secret_store.SecretRecord, "label_len") == u8 and
            @FieldType(secure_secret_store.SecretRecord, "value_len") == u8,
        .bounds_secret_lookup_comparisons = secure_secret_store.SECRET_LOOKUP_COMPARISON_BOUND == 5,
        .drops_secret_arena = @FieldType(secure_secret_store.Store, "secrets") == [secure_secret_store.MAX_SECRETS]secure_secret_store.SecretRecord,
        .uses_handle_arena = @hasDecl(@FieldType(secure_secret_store.Store, "handles"), "reserve"),
        .uses_direct_generational_handles = secure_secret_store.DIRECT_HANDLE_LOOKUP and
            @hasDecl(@FieldType(secure_secret_store.Store, "handles"), "getByHandle"),
        .uses_in_place_handle_replacement = @hasDecl(@FieldType(secure_secret_store.Store, "handles"), "replaceHandle"),
        .supports_handle_replacement = @hasDecl(secure_secret_store.Store, "replaceHandle"),
        .keeps_fixed_state_within_ceiling = @sizeOf(secure_secret_store.Store) <= secure_secret_store.STORE_SIZE_CEILING_BYTES,
    },
    .os_identity = .{
        .uses_bounded_credential_lookup = os_identity.BOUNDED_CREDENTIAL_LOOKUP,
        .uses_dense_credential_table = os_identity.DENSE_CREDENTIAL_TABLE and
            @FieldType(os_identity.Store, "credentials") == [os_identity.MAX_CREDENTIALS]os_identity.CredentialRecord,
        .stores_compact_credential_metadata = os_identity.COMPACT_CREDENTIAL_METADATA and
            @FieldType(os_identity.CredentialRecord, "relying_party_id_len") == u8 and
            @FieldType(os_identity.CredentialRecord, "label_len") == u8,
        .stores_compact_proof_and_assertion_metadata = os_identity.COMPACT_IDENTITY_PROOF_METADATA and
            @FieldType(os_identity.LocalUnlockProof, "relying_party_id_len") == u8 and
            @FieldType(os_identity.LocalUnlockProof, "challenge_len") == u8 and
            @FieldType(os_identity.Assertion, "relying_party_id_len") == u8 and
            @FieldType(os_identity.Assertion, "origin_len") == u8 and
            @FieldType(os_identity.Assertion, "challenge_len") == u8,
        .keeps_proofs_and_requests_within_ceilings = @sizeOf(os_identity.LocalUnlockProof) <= os_identity.LOCAL_UNLOCK_PROOF_SIZE_CEILING_BYTES and
            @sizeOf(os_identity.Assertion) <= os_identity.ASSERTION_SIZE_CEILING_BYTES and
            @sizeOf(os_identity.AssertionRequest) <= os_identity.ASSERTION_REQUEST_SIZE_CEILING_BYTES and
            @sizeOf(os_identity.RecoveryApproval) <= os_identity.RECOVERY_APPROVAL_SIZE_CEILING_BYTES and
            @sizeOf(os_identity.RecoveryRequest) <= os_identity.RECOVERY_REQUEST_SIZE_CEILING_BYTES,
        .bounds_credential_lookup_comparisons = os_identity.CREDENTIAL_LOOKUP_COMPARISON_BOUND == 5,
        .drops_credential_arena = @FieldType(os_identity.Store, "credentials") == [os_identity.MAX_CREDENTIALS]os_identity.CredentialRecord,
        .keeps_fixed_state_within_ceiling = @sizeOf(os_identity.Store) <= os_identity.STORE_SIZE_CEILING_BYTES,
    },

    .secret_vault_service = .{
        .uses_handle_arena = @hasDecl(@FieldType(secret_vault_service.Service, "handles"), "reserve"),
        .uses_direct_generational_handles = secret_vault_service.DIRECT_HANDLE_LOOKUP and
            @hasDecl(@FieldType(secret_vault_service.Service, "handles"), "getByHandle"),
        .uses_in_place_handle_replacement = @hasDecl(@FieldType(secret_vault_service.Service, "handles"), "replaceHandle"),
        .uses_bounded_handle_scan = secret_vault_service.BOUNDED_HANDLE_SCAN,
        .reclaims_terminal_handles = secret_vault_service.RECLAIMS_TERMINAL_HANDLES,
        .drops_secondary_handle_indexes = !@hasField(secret_vault_service.Service, "secret_handle_index") and
            !@hasField(secret_vault_service.Service, "active_handle_index"),
        .tracks_active_handles = @hasField(secret_vault_service.Service, "active_handle_count"),
        .stores_compact_active_handle_metadata = secret_vault_service.COMPACT_ACTIVE_HANDLE_COUNT_METADATA and
            @FieldType(secret_vault_service.Service, "active_handle_count") == u8,
        .uses_fair_terminal_reuse = @hasField(secret_vault_service.Service, "next_reusable_handle"),
        .keeps_fixed_state_within_ceiling = @sizeOf(secret_vault_service.Service) <= secret_vault_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .media_print_service = .{
        .uses_bounded_job_scan = media_print_service.BOUNDED_JOB_SCAN,
        .uses_compact_completion_queue = media_print_service.COMPACT_COMPLETION_QUEUE,
        .stores_compact_job_text_metadata = media_print_service.COMPACT_JOB_TEXT_METADATA and
            @FieldType(media_print_service.JobRecord, "label_len") == u8 and
            @FieldType(media_print_service.JobRecord, "printer_identity_len") == u8,
        .keeps_job_records_within_ceiling = @sizeOf(media_print_service.JobRecord) <= media_print_service.JOB_RECORD_SIZE_CEILING_BYTES,
        .keeps_fixed_state_within_ceiling = @sizeOf(media_print_service.Service) <= media_print_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .network_session_service = .{
        .uses_direct_session_lookup = network_session_service.DIRECT_SESSION_LOOKUP,
        .reclaims_terminal_sessions = network_session_service.RECLAIMS_TERMINAL_SESSIONS,
        .stores_compact_destination_length = network_session_service.COMPACT_DESTINATION_LENGTH,
        .keeps_fixed_state_within_ceiling = @sizeOf(network_session_service.Service) <= network_session_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .notification_center = .{
        .uses_bounded_notification_scan = notification_center.BOUNDED_NOTIFICATION_SCAN,
        .reclaims_suppressed_notifications = notification_center.RECLAIMS_SUPPRESSED_NOTIFICATIONS,
        .stores_compact_notification_metadata = notification_center.COMPACT_NOTIFICATION_METADATA and
            @FieldType(notification_center.AttentionDecision, "active_visible") == u8 and
            @FieldType(notification_center.AttentionDecision, "active_interruptions") == u8 and
            @FieldType(notification_center.AttentionCounts, "active_visible") == u8 and
            @FieldType(notification_center.AttentionCounts, "active_interruptions") == u8,
        .uses_fixed_notification_table = @FieldType(notification_center.Center, "notifications") == [notification_center.MAX_NOTIFICATIONS]notification_center.Notification,
        .drops_secondary_notification_indexes = !@hasField(notification_center.Center, "source_reason_index") and
            !@hasField(notification_center.Center, "expiring_attention_index") and
            !@hasField(notification_center.Center, "suppressed_notification_index"),
        .tracks_permanent_attention_counts = @hasField(notification_center.Center, "permanent_attention_counts"),
        .drops_visible_notification_chain = !@hasField(notification_center.Center, "visible_tail_slot") and
            !@hasField(notification_center.Center, "visible_prev_by_slot") and
            !@hasField(notification_center.Center, "visible_next_by_slot"),
        .tracks_visible_notification_count = @hasField(notification_center.Center, "visible_notification_count"),
        .keeps_fixed_state_within_ceiling = @sizeOf(notification_center.AttentionDecision) <= notification_center.ATTENTION_DECISION_SIZE_CEILING_BYTES and
            @sizeOf(notification_center.AttentionCounts) <= notification_center.ATTENTION_COUNTS_SIZE_CEILING_BYTES and
            @sizeOf(notification_center.AttentionPostResult) <= notification_center.ATTENTION_POST_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(notification_center.Center) <= notification_center.CENTER_SIZE_CEILING_BYTES,
    },
    .secure_pasteboard = .{
        .uses_bounded_grant_scan = secure_pasteboard.BOUNDED_GRANT_SCAN,
        .reclaims_terminal_grants = secure_pasteboard.RECLAIMS_TERMINAL_GRANTS,
        .stores_compact_grant_lengths = secure_pasteboard.COMPACT_GRANT_LENGTHS,
        .keeps_fixed_state_within_ceiling = @sizeOf(secure_pasteboard.Service) <= secure_pasteboard.SERVICE_SIZE_CEILING_BYTES,
    },
    .sensitive_capture_service = .{
        .uses_direct_session_lookup = sensitive_capture_service.DIRECT_SESSION_LOOKUP,
        .reclaims_inactive_session_slots = sensitive_capture_service.RECLAIMS_INACTIVE_SESSION_SLOTS,
        .keeps_fixed_state_within_ceiling = @sizeOf(sensitive_capture_service.Service) <= sensitive_capture_service.SERVICE_SIZE_CEILING_BYTES,
        .tracks_active_sessions = @hasField(sensitive_capture_service.Service, "active_session_count"),
        .tracks_privacy_indicators = @hasField(sensitive_capture_service.Service, "privacy_indicator_counts"),
    },
    .agent_delegation_service = .{
        .uses_delegation_arena = @hasDecl(@FieldType(agent_delegation_service.Service, "slots"), "reserve"),
        .stores_compact_active_delegation_metadata = agent_delegation_service.COMPACT_ACTIVE_DELEGATION_METADATA and
            @FieldType(agent_delegation_service.Service, "active_delegation_count") == u8,
        .keeps_fixed_state_within_ceiling = @sizeOf(agent_delegation_service.Service) <= agent_delegation_service.SERVICE_SIZE_CEILING_BYTES,
        .tracks_active_delegations = @hasField(agent_delegation_service.Service, "active_delegation_count"),
        .tracks_lowest_active_generation = @hasField(agent_delegation_service.Service, "lowest_active_generation"),
        .uses_generation_index = @hasField(agent_delegation_service.Service, "delegation_generation_index"),
        .tracks_active_generation_buckets = @hasField(agent_delegation_service.Service, "active_generation_buckets"),
        .uses_active_generation_bucket_arena = @hasDecl(@FieldType(agent_delegation_service.Service, "active_generation_buckets"), "reserve"),
    },
    .object_resilience_service = .{
        .uses_bounded_snapshot_scan = object_resilience_service.BOUNDED_SNAPSHOT_SCAN,
        .reclaims_revoked_snapshots = object_resilience_service.RECLAIMS_REVOKED_SNAPSHOTS,
        .keeps_fixed_state_within_ceiling = @sizeOf(object_resilience_service.Service) <= object_resilience_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .personal_context_service = .{
        .uses_direct_lease_lookup = personal_context_service.DIRECT_LEASE_LOOKUP,
        .reclaims_terminal_leases = personal_context_service.RECLAIMS_TERMINAL_LEASES,
        .keeps_fixed_state_within_ceiling = @sizeOf(personal_context_service.Service) <= personal_context_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .package_service = .{
        .uses_bundle_arena = @hasDecl(package_service.BundleArena, "reserve"),
        .uses_revision_permission_text_pool = @hasField(package_service.BundleRevision, "permission_text"),
        .uses_compact_permission_text_refs = @sizeOf(@FieldType(package_service.StoredPermission, "resource")) == 4 and
            @sizeOf(package_service.StoredPermission) < package_service.MAX_PERMISSION_RESOURCE_BYTES,
        .uses_compact_result_metadata = package_service.COMPACT_PACKAGE_RESULT_METADATA and
            @FieldType(package_service.RemoveResult, "removed_revision_count") == u8 and
            @FieldType(package_service.OffboardResult, "removed_revision_count") == u8 and
            @FieldType(package_service.PackageLaunchProvenance, "signature_public_key_len") == u8,
        .keeps_results_within_ceilings = @sizeOf(package_service.RemoveResult) <= package_service.REMOVE_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(package_service.OffboardResult) <= package_service.OFFBOARD_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(package_service.PackageLaunchProvenance) <= package_service.PACKAGE_LAUNCH_PROVENANCE_SIZE_CEILING_BYTES and
            @sizeOf(package_service.LaunchPlan) <= package_service.LAUNCH_PLAN_SIZE_CEILING_BYTES,
    },
    .public_store = .{
        .uses_bounded_release_scan = public_store.BOUNDED_RELEASE_SCAN and
            public_store.RELEASE_SCAN_BOUND == public_store.MAX_RELEASES_PER_CHANNEL,
        .uses_bounded_trusted_publisher_scan = public_store.BOUNDED_TRUSTED_PUBLISHER_SCAN and
            public_store.TRUSTED_PUBLISHER_SCAN_BOUND == public_store.MAX_TRUSTED_PUBLISHERS_PER_CHANNEL,
        .uses_dense_release_table = public_store.DENSE_RELEASE_TABLE and
            @FieldType(public_store.Channel, "releases") == [public_store.MAX_RELEASES_PER_CHANNEL]public_store.Release,
        .uses_dense_trusted_publisher_table = public_store.DENSE_TRUSTED_PUBLISHER_TABLE and
            @FieldType(public_store.Channel, "trusted_publishers") == [public_store.MAX_TRUSTED_PUBLISHERS_PER_CHANNEL]public_store.TrustedPublisherRecord,
        .uses_direct_release_identity_comparison = public_store.DIRECT_RELEASE_IDENTITY_COMPARISON,
        .drops_public_store_indexes = !@hasField(public_store.Channel, "bundle_release_index"),
        .keeps_fixed_state_within_ceiling = @sizeOf(public_store.Channel) <= public_store.CHANNEL_SIZE_CEILING_BYTES,
    },
    .driver_service = .{
        .uses_driver_arena = @hasDecl(@FieldType(driver_service.Directory, "slots"), "reserve"),
        .stores_compact_record_metadata = driver_service.COMPACT_DRIVER_RECORD_METADATA and
            @FieldType(driver_service.DriverRecord, "dma_range_count") == u8 and
            @FieldType(driver_service.DriverRecord, "signer_len") == u8,
        .keeps_driver_state_within_ceilings = @sizeOf(driver_service.DriverRecord) <= driver_service.DRIVER_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(driver_service.Directory) <= driver_service.DIRECTORY_SIZE_CEILING_BYTES,
    },
    .driver_publication = .{
        .stores_compact_publisher_lengths = bootstrap_driver_port.COMPACT_PUBLICATION_METADATA and
            @FieldType(bootstrap_driver_port.DeviceDataPlanePublication, "publisher_len") == u8 and
            @FieldType(bootstrap_driver_port.NetworkPublication, "publisher_len") == u8 and
            @FieldType(bootstrap_driver_port.StoragePublication, "publisher_len") == u8,
        .keeps_publications_within_ceilings = @sizeOf(bootstrap_driver_port.DeviceDataPlanePublication) <= bootstrap_driver_port.DEVICE_DATA_PLANE_PUBLICATION_SIZE_CEILING_BYTES and
            @sizeOf(bootstrap_driver_port.NetworkPublication) <= bootstrap_driver_port.NETWORK_PUBLICATION_SIZE_CEILING_BYTES and
            @sizeOf(bootstrap_driver_port.StoragePublication) <= bootstrap_driver_port.STORAGE_PUBLICATION_SIZE_CEILING_BYTES,
    },
    .driver_runtime = .{
        .uses_activation_arena = @hasDecl(@FieldType(driver_runtime.Runtime, "arena"), "reserveIndex"),
        .uses_activation_class_index = @hasField(driver_runtime.Runtime, "class_index"),
        .uses_activation_service_index = @hasField(driver_runtime.Runtime, "service_index"),
        .stores_compact_activation_metadata = driver_runtime.COMPACT_ACTIVATION_METADATA and
            @FieldType(driver_runtime.ActivationRecord, "publisher_len") == u8,
        .keeps_activation_state_within_ceilings = @sizeOf(driver_runtime.ActivationRecord) <= driver_runtime.ACTIVATION_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(driver_runtime.Runtime) <= driver_runtime.RUNTIME_SIZE_CEILING_BYTES,
    },
    .network_driver_task = .{
        .stores_compact_bounded_metadata = network_driver_task.COMPACT_BOUNDED_METADATA and
            @FieldType(network_driver_task.ReceiveResult, "length") == u16 and
            @FieldType(network_driver_task.NativeServiceIdentityConnection, "service_identity_len") == u8 and
            @FieldType(network_driver_task.NativeLocalDiscoveryConnection, "discovery_class_len") == u8 and
            @FieldType(network_driver_task.NativeLocalDiscoveryFrame, "probe_len") == u8 and
            @FieldType(network_driver_task.NativeLocalDiscoveryFrame, "discovery_class_len") == u8 and
            network_driver_task.bounded_metadata_layout.uses_compact_active_frame_lengths and
            network_driver_task.bounded_metadata_layout.uses_compact_receive_queue_indices,
        .keeps_bounded_state_within_ceilings = @sizeOf(network_driver_task.ReceiveResult) <= network_driver_task.RECEIVE_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(network_driver_task.NativeServiceIdentityConnection) <= network_driver_task.SERVICE_IDENTITY_CONNECTION_SIZE_CEILING_BYTES and
            @sizeOf(network_driver_task.NativeLocalDiscoveryConnection) <= network_driver_task.LOCAL_DISCOVERY_CONNECTION_SIZE_CEILING_BYTES and
            @sizeOf(network_driver_task.NativeLocalDiscoveryFrame) <= network_driver_task.LOCAL_DISCOVERY_FRAME_SIZE_CEILING_BYTES and
            network_driver_task.bounded_metadata_layout.queued_receive_frame_size_bytes <= network_driver_task.QUEUED_RECEIVE_FRAME_SIZE_CEILING_BYTES,
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
        .stores_compact_policy_metadata = network_policy.COMPACT_POLICY_METADATA and
            @FieldType(network_policy.PolicyRecord, "label_len") == u8 and
            @FieldType(network_policy.PolicyRecord, "target_len") == u8,
        .keeps_policy_state_within_ceilings = @sizeOf(network_policy.PolicyRecord) <= network_policy.POLICY_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(network_policy.Directory) <= network_policy.DIRECTORY_SIZE_CEILING_BYTES,
        .uses_policy_arena = @hasDecl(@FieldType(network_policy.Directory, "policies"), "reserve"),
    },
    .policy_object = .{
        .stores_compact_policy_metadata = policy_object.COMPACT_POLICY_METADATA and
            @FieldType(policy_object.PolicyObject, "label_len") == u8 and
            @FieldType(policy_object.PolicyObject, "allowed_install_source_count") == u8 and
            @FieldType(policy_object.PolicyObject, "allowed_install_source_lens") == [policy_object.MAX_ALLOW_LIST]u8 and
            @FieldType(policy_object.PolicyObject, "allowed_network_destination_count") == u8 and
            @FieldType(policy_object.PolicyObject, "allowed_network_destination_lens") == [policy_object.MAX_ALLOW_LIST]u8 and
            @FieldType(policy_object.PolicyObject, "allowed_sync_destination_count") == u8 and
            @FieldType(policy_object.PolicyObject, "allowed_sync_destination_lens") == [policy_object.MAX_ALLOW_LIST]u8,
        .keeps_policy_state_within_ceilings = @sizeOf(policy_object.PolicyObject) <= policy_object.POLICY_OBJECT_SIZE_CEILING_BYTES and
            @sizeOf(policy_object.Directory) <= policy_object.DIRECTORY_SIZE_CEILING_BYTES,
        .uses_policy_arena = @hasDecl(@FieldType(policy_object.Directory, "policies"), "reserve"),
        .uses_scope_index = @hasField(policy_object.Directory, "scope_index"),
    },
    .event_ledger = .{
        .stores_compact_event_text_metadata = event_ledger.COMPACT_EVENT_TEXT_METADATA and
            @FieldType(event_ledger.Event, "policy_label_len") == u8 and
            @FieldType(event_ledger.Event, "missing_capability_len") == u8 and
            @FieldType(event_ledger.Event, "detail_len") == u16,
        .keeps_event_state_within_ceilings = @sizeOf(event_ledger.Event) <= event_ledger.EVENT_SIZE_CEILING_BYTES and
            @sizeOf(event_ledger.EventBacking) <= event_ledger.EVENT_BACKING_SIZE_CEILING_BYTES,
        .uses_event_arena = @hasField(event_ledger.EventBacking, "events"),
        .indexes_kind = @hasField(event_ledger.EventBacking, "kind_index"),
        .indexes_subject = @hasField(event_ledger.EventBacking, "subject_index"),
        .indexes_task = @hasField(event_ledger.EventBacking, "task_index"),
        .visits_indexes = @hasDecl(event_ledger.Ledger, "queryEvents"),
        .removes_evicted_indexes = @hasDecl(event_ledger.Ledger, "removeEventIndexes"),
    },
    .recovery_environment = .{
        .derives_action_count_from_slice = recovery_environment.DERIVES_ACTION_COUNT_FROM_SLICE and
            !@hasField(recovery_environment.EntrySession, "action_count") and
            @hasDecl(recovery_environment.EntrySession, "actionCount"),
        .keeps_entry_session_within_ceiling = @sizeOf(recovery_environment.EntrySession) <= recovery_environment.ENTRY_SESSION_SIZE_CEILING_BYTES,
    },
    .attestation_service = .{
        .stores_compact_bounded_metadata = attestation_service.COMPACT_ATTESTATION_METADATA and
            @FieldType(attestation_service.Statement, "record_count") == u8 and
            @FieldType(attestation_service.Statement, "remote_party_len") == u8 and
            @FieldType(attestation_service.RemoteAttestationRequest, "revoked_root_generation_count") == u8 and
            @FieldType(attestation_service.RemoteAttestationResponse, "policy_label_len") == u8 and
            @FieldType(attestation_service.Service, "remote_nonce_history_count") == u8,
        .keeps_attestation_state_within_ceilings = @sizeOf(attestation_service.Statement) <= attestation_service.STATEMENT_SIZE_CEILING_BYTES and
            @sizeOf(attestation_service.RemoteAttestationRequest) <= attestation_service.REMOTE_REQUEST_SIZE_CEILING_BYTES and
            @sizeOf(attestation_service.RemoteAttestationResponse) <= attestation_service.REMOTE_RESPONSE_SIZE_CEILING_BYTES and
            @sizeOf(attestation_service.Service) <= attestation_service.SERVICE_SIZE_CEILING_BYTES,
    },
    .immutable_base = .{
        .stores_compact_image_metadata = immutable_base.COMPACT_IMMUTABLE_BASE_METADATA and
            @FieldType(immutable_base.SystemImage, "label_len") == u8 and
            @FieldType(immutable_base.SystemImage, "signer_len") == u8 and
            @FieldType(immutable_base.BootSelection, "signer_len") == u8,
        .keeps_image_state_within_ceilings = @sizeOf(immutable_base.SystemImage) <= immutable_base.SYSTEM_IMAGE_SIZE_CEILING_BYTES and
            @sizeOf(immutable_base.BootSelection) <= immutable_base.BOOT_SELECTION_SIZE_CEILING_BYTES and
            @sizeOf(immutable_base.Manager) <= immutable_base.MANAGER_SIZE_CEILING_BYTES,
    },
    .dmar = .{
        .stores_compact_summary_counts = kernel_dmar.COMPACT_SUMMARY_COUNT_METADATA and
            @FieldType(kernel_dmar.Summary, "remapping_unit_count") == u8 and
            @FieldType(kernel_dmar.Summary, "reserved_memory_region_count") == u32 and
            @FieldType(kernel_dmar.Summary, "reserved_memory_with_non_pci_scope_count") == u32 and
            @FieldType(kernel_dmar.Summary, "ats_capability_count") == u32,
        .keeps_summary_within_ceiling = @sizeOf(kernel_dmar.Summary) <= kernel_dmar.SUMMARY_SIZE_CEILING_BYTES,
    },
    .measured_boot = .{
        .stores_compact_measurement_metadata = measured_boot.COMPACT_MEASUREMENT_METADATA and
            @FieldType(measured_boot.MeasurementRecord, "label_len") == u8 and
            @FieldType(measured_boot.BuildArtifactEntry, "label_len") == u8,
        .stores_compact_manifest_counts = @FieldType(measured_boot.ArtifactManifest, "entry_count") == u8 and
            @FieldType(measured_boot.BuildArtifactManifest, "entry_count") == u8,
        .stores_compact_boot_record_counts = @FieldType(measured_boot.BootRecord, "record_count") == u8 and
            @FieldType(measured_boot.BootloaderMeasurementHandoff, "record_count") == u8 and
            @FieldType(measured_boot.Recorder, "record_count") == u8,
        .keeps_measurement_records_within_ceiling = @sizeOf(measured_boot.MeasurementRecord) <= measured_boot.MEASUREMENT_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(measured_boot.BuildArtifactEntry) <= measured_boot.BUILD_ARTIFACT_ENTRY_SIZE_CEILING_BYTES,
        .keeps_manifests_within_ceilings = @sizeOf(measured_boot.ArtifactManifest) <= measured_boot.ARTIFACT_MANIFEST_SIZE_CEILING_BYTES and
            @sizeOf(measured_boot.BuildArtifactManifest) <= measured_boot.BUILD_ARTIFACT_MANIFEST_SIZE_CEILING_BYTES,
        .keeps_boot_state_within_ceilings = @sizeOf(measured_boot.BootRecord) <= measured_boot.BOOT_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(measured_boot.BootloaderMeasurementHandoff) <= measured_boot.BOOTLOADER_HANDOFF_SIZE_CEILING_BYTES and
            @sizeOf(measured_boot.Recorder) <= measured_boot.RECORDER_SIZE_CEILING_BYTES,
    },
    .compositor_session = .{
        .uses_borrowed_snapshot_apis = @hasDecl(compositor_session.Session, "snapshotInto") and
            @hasDecl(compositor_session.Session, "restoreFromSnapshot") and
            !@hasDecl(compositor_session.Session, "snapshot") and
            !@hasDecl(compositor_session.Session, "restore"),
        .stores_compact_window_metadata = compositor_session.COMPACT_RECORD_METADATA and
            @FieldType(compositor_session.WindowRecord, "bundle_id_len") == u8 and
            @FieldType(compositor_session.WindowRecord, "display_name_len") == u8 and
            @FieldType(compositor_session.WindowRecord, "title_len") == u8 and
            @FieldType(compositor_session.WindowRecord, "detail_len") == u8 and
            @FieldType(compositor_session.WindowRecord, "item_count") == u8,
        .stores_compact_review_item_metadata = @FieldType(compositor_session.ReviewItemRecord, "label_len") == u8 and
            @FieldType(compositor_session.ReviewItemRecord, "resource_len") == u8 and
            @FieldType(compositor_session.ReviewItemRecord, "reason_len") == u8 and
            @FieldType(compositor_session.ReviewItemRecord, "object_scope_len") == u8 and
            @FieldType(compositor_session.ReviewItemRecord, "network_path_len") == u8,
        .stores_compact_session_counts = compositor_session.COMPACT_SESSION_COUNT_METADATA and
            @FieldType(compositor_session.WindowSlot, "order_index") == compositor_session.WindowOrderIndex and
            @FieldType(compositor_session.Session, "window_count") == compositor_session.SessionCount and
            @FieldType(compositor_session.Session, "visible_window_count") == compositor_session.SessionCount and
            @FieldType(compositor_session.Session, "item_count") == compositor_session.SessionCount and
            @FieldType(compositor_session.SessionSnapshot, "window_count") == compositor_session.SessionCount and
            @FieldType(compositor_session.SessionSnapshot, "visible_window_count") == compositor_session.SessionCount and
            @FieldType(compositor_session.SessionSnapshot, "item_count") == compositor_session.SessionCount,
        .keeps_records_within_ceilings = @sizeOf(compositor_session.WindowRecord) <= compositor_session.WINDOW_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(compositor_session.ReviewItemRecord) <= compositor_session.REVIEW_ITEM_RECORD_SIZE_CEILING_BYTES,
        .keeps_snapshot_state_within_ceilings = @sizeOf(compositor_session.SessionSnapshot) <= compositor_session.SESSION_SNAPSHOT_SIZE_CEILING_BYTES and
            @sizeOf(compositor_session.CheckpointStore) <= compositor_session.CHECKPOINT_STORE_SIZE_CEILING_BYTES,
        .keeps_session_within_target_ceiling = @sizeOf(compositor_session.Session) <= compositor_session.SESSION_SIZE_CEILING_BYTES,
        .uses_window_arena = @hasField(compositor_session.Session, "windows"),
        .uses_review_item_arena = @hasDecl(compositor_session.ReviewItemArena, "reserveIndex"),
        .uses_task_bundle_index = @hasField(compositor_session.Session, "task_bundle_index"),
        .uses_task_window_index = @hasField(compositor_session.Session, "task_window_index"),
        .uses_reviewer_window_index = @hasField(compositor_session.Session, "reviewer_window_index"),
        .uses_window_review_item_index = @hasDecl(compositor_session.WindowReviewItemIndex, "append"),
        .tracks_visible_window_count = @hasField(compositor_session.Session, "visible_window_count"),
        .supports_indexed_task_window_ownership = @hasDecl(compositor_session.Session, "taskOwnsVisibleWindow"),
        .supports_indexed_active_window_order = @hasDecl(compositor_session.Session, "activeWindowOrderIndex"),
        .uses_surface_task_index = @hasField(compositor_session.Session, "surface_task_index"),
        .tracks_active_surface_chain = @hasField(compositor_session.Session, "active_surface_head"),
        .caches_surface_prune_generation = @hasField(compositor_session.Session, "last_surface_prune_generation"),
        .heap_backs_surface_arena_on_freestanding = compositor_session.HEAP_BACKED_SURFACE_ARENA_ON_FREESTANDING,
    },
    .input_router = .{
        .uses_inbox_arena = @hasDecl(@FieldType(input_router.Router, "inboxes"), "reserveIndex"),
        .tracks_active_inbox_chain = @hasField(input_router.Router, "active_inbox_head"),
    },
    .input_queues = .{
        .stores_compact_xhci_metadata = xhci.COMPACT_INPUT_QUEUE_METADATA and
            @FieldType(xhci.HidReport, "report_len") == u8 and
            @FieldType(xhci.BootKeyboardReportPublisher, "head") == u8 and
            @FieldType(xhci.BootKeyboardReportPublisher, "tail") == u8 and
            @FieldType(xhci.BootKeyboardReportPublisher, "count") == u8 and
            @FieldType(xhci.HidController, "head") == u8 and
            @FieldType(xhci.HidController, "tail") == u8 and
            @FieldType(xhci.HidController, "count") == u8 and
            @FieldType(xhci.HidController, "recycled_slot_count") == u8,
        .stores_compact_decoder_metadata = input_driver_task.COMPACT_EVENT_QUEUE_METADATA and
            @FieldType(input_driver_task.Decoder, "head") == u8 and
            @FieldType(input_driver_task.Decoder, "tail") == u8 and
            @FieldType(input_driver_task.Decoder, "count") == u8,
        .stores_compact_command_metadata = permission_review_service.COMPACT_COMMAND_QUEUE_METADATA and
            @FieldType(permission_review_service.CommandInput, "pending_line_len") == u8 and
            @FieldType(permission_review_service.CommandInput, "pending_command_lens") == [permission_review_service.MAX_PHYSICAL_INPUT_COMMANDS]u8 and
            @FieldType(permission_review_service.CommandInput, "pending_command_head") == u8 and
            @FieldType(permission_review_service.CommandInput, "pending_command_tail") == u8 and
            @FieldType(permission_review_service.CommandInput, "pending_command_count") == u8,
        .keeps_input_state_within_ceilings = @sizeOf(xhci.HidReport) <= xhci.HID_REPORT_SIZE_CEILING_BYTES and
            @sizeOf(xhci.BootKeyboardReportPublisher) <= xhci.BOOT_KEYBOARD_REPORT_PUBLISHER_SIZE_CEILING_BYTES and
            @sizeOf(xhci.HidController) <= xhci.HID_CONTROLLER_SIZE_CEILING_BYTES and
            @sizeOf(input_driver_task.Decoder) <= input_driver_task.DECODER_SIZE_CEILING_BYTES and
            @sizeOf(permission_review_service.CommandInput) <= permission_review_service.COMMAND_INPUT_SIZE_CEILING_BYTES,
    },
    .permission_review = .{
        .stores_compact_rendered_progress = permission_review_service.COMPACT_REVIEW_PROGRESS_METADATA and
            @FieldType(permission_review_service.RenderedReviewSurface, "active_index") == u8 and
            @FieldType(permission_review_service.RenderedReviewSurface, "decision_count") == u8,
        .keeps_rendered_surface_within_ceiling = @sizeOf(permission_review_service.RenderedReviewSurface) <=
            permission_review_service.RENDERED_REVIEW_SURFACE_SIZE_CEILING_BYTES,
    },
    .policy_activation = .{
        .stores_compact_summary_metadata = policy_mediation.COMPACT_ACTIVATION_SUMMARY_METADATA and
            @FieldType(policy_mediation.ActivationSummary, "granted_count") == u8 and
            @FieldType(policy_mediation.ActivationSummary, "denied_count") == u8 and
            @FieldType(policy_mediation.ActivationSummary, "required_denials") == u8 and
            @FieldType(policy_mediation.ActivationSummary, "decision_count") == u8,
        .keeps_summary_within_ceiling = @sizeOf(policy_mediation.ActivationSummary) <= policy_mediation.ACTIVATION_SUMMARY_SIZE_CEILING_BYTES,
    },
    .native_ux = .{
        .uses_append_only_flow_log = native_ux.APPEND_ONLY_FLOW_LOG,
        .uses_compact_flow_lengths = @FieldType(native_ux.FlowRecord, "detail_len") == u8 and
            @FieldType(native_ux.FlowRecord, "bundle_id_len") == u8,
        .supports_ordered_flow_lookup = @hasDecl(native_ux.Controller, "flowAtOrder"),
    },
    .sync_transport_harness = .{
        .stores_compact_relay_metadata = sync_transport_harness.COMPACT_RELAY_METADATA and
            @FieldType(sync_transport_harness.EncryptedPacket, "ciphertext_len") == u16 and
            @FieldType(sync_transport_harness.BootedOverlayRelayService, "relay_domain_len") == u8 and
            @FieldType(sync_transport_harness.TransportSession, "relay_domain_len") == u8,
        .keeps_relay_state_within_ceilings = @sizeOf(sync_transport_harness.EncryptedPacket) <= sync_transport_harness.ENCRYPTED_PACKET_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport_harness.SignedEncryptedFrame) <= sync_transport_harness.SIGNED_ENCRYPTED_FRAME_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport_harness.Relay) <= sync_transport_harness.RELAY_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport_harness.BootedOverlayRelayService) <= sync_transport_harness.BOOTED_RELAY_SERVICE_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport_harness.TransportSession) <= sync_transport_harness.TRANSPORT_SESSION_SIZE_CEILING_BYTES,
        .uses_relay_packet_arena = @hasField(sync_transport_harness.Relay, "packets"),
        .uses_relay_session_index = @hasField(sync_transport_harness.Relay, "session_index"),
    },
    .sync_transport = .{
        .stores_compact_capture_metadata = sync_transport.COMPACT_CAPTURE_METADATA and
            @FieldType(sync_transport.CapturedPacket, "len") == u16,
        .stores_compact_native_result_metadata = sync_transport.COMPACT_NATIVE_RESULT_METADATA and
            @FieldType(sync_transport.NativeDelivery, "payload_len") == sync_transport.NativePayloadLength and
            @FieldType(sync_transport.ObjectShareEnvelope, "payload_len") == sync_transport.ObjectSharePayloadLength,
        .keeps_capture_state_within_ceilings = @sizeOf(sync_transport.CapturedPacket) <= sync_transport.CAPTURED_PACKET_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport.PacketCapture) <= sync_transport.PACKET_CAPTURE_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport.NativeTransportService) <= sync_transport.NATIVE_TRANSPORT_SERVICE_SIZE_CEILING_BYTES,
        .keeps_native_results_within_ceilings = @sizeOf(sync_transport.NativeDelivery) <= sync_transport.NATIVE_DELIVERY_SIZE_CEILING_BYTES and
            @sizeOf(sync_transport.ObjectShareEnvelope) <= sync_transport.OBJECT_SHARE_ENVELOPE_SIZE_CEILING_BYTES,
        .uses_packet_capture_arena = @hasDecl(@FieldType(sync_transport.PacketCapture, "packets"), "reserveIndex"),
        .tracks_last_packet_id = @hasField(sync_transport.PacketCapture, "last_packet_id"),
    },
    .device_graph = .{
        .stores_compact_identity_metadata = device_graph.COMPACT_IDENTITY_METADATA and
            @FieldType(device_graph.PlatformDeviceRoot, "label_len") == u8 and
            @FieldType(device_graph.UserRootRecord, "label_len") == u8 and
            @FieldType(device_graph.DeviceRecord, "label_len") == u8 and
            @FieldType(device_graph.DeviceRecord, "platform_key_label_len") == u8 and
            @FieldType(device_graph.Graph, "trusted_device_count") == u8,
        .keeps_identity_state_within_ceilings = @sizeOf(device_graph.PlatformDeviceRoot) <= device_graph.PLATFORM_DEVICE_ROOT_SIZE_CEILING_BYTES and
            @sizeOf(device_graph.UserRootRecord) <= device_graph.USER_ROOT_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(device_graph.DeviceRecord) <= device_graph.DEVICE_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(device_graph.Graph) <= device_graph.GRAPH_SIZE_CEILING_BYTES,
        .uses_user_root_arena = @hasDecl(@FieldType(device_graph.Graph, "user_roots"), "reserveIndex"),
        .uses_device_arena = @hasDecl(@FieldType(device_graph.Graph, "devices"), "reserveIndex"),
        .tracks_trusted_device_count = @hasField(device_graph.Graph, "trusted_device_count"),
        .rebuilds_loaded_indexes = @hasDecl(device_graph.Graph, "rebuildIndexes"),
    },
    .sync_service = .{
        .stores_compact_latest_mutation_indexes = sync_latest_mutations.COMPACT_MUTATION_INDEX_METADATA and
            @sizeOf(sync_latest_mutations.MutationIndex) == 1,
        .keeps_latest_mutation_index_within_ceiling = @sizeOf(sync_latest_mutations.Index) <= sync_latest_mutations.INDEX_SIZE_CEILING_BYTES,
        .stores_compact_overlay_session_metadata = sync_service.COMPACT_OVERLAY_SESSION_METADATA and
            @FieldType(sync_service.OverlaySession, "service_identity_len") == u8 and
            @FieldType(sync_service.OverlaySession, "relay_domain_len") == u8 and
            @FieldType(sync_service.OverlaySession, "private_service_len") == u8 and
            @FieldType(sync_service.OverlayRelayFrameResult, "service_identity_len") == u8 and
            @FieldType(sync_service.OverlayRelayFrameResult, "relay_domain_len") == u8 and
            @FieldType(sync_service.OverlayRelayFrameResult, "private_service_len") == u8,
        .keeps_overlay_session_state_within_ceilings = @sizeOf(sync_service.OverlaySession) <= sync_service.OVERLAY_SESSION_SIZE_CEILING_BYTES and
            @sizeOf(sync_service.OverlayRelayFrameResult) <= sync_service.OVERLAY_RELAY_FRAME_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(sync_service.Service) <= sync_service.SERVICE_SIZE_CEILING_BYTES,
        .stores_compact_service_queue_metadata = sync_service.COMPACT_SERVICE_QUEUE_METADATA and
            @FieldType(sync_service.Service, "outbound_transport_frame_count") == u8 and
            @FieldType(sync_service.Service, "inbound_transport_frame_count") == u8 and
            @FieldType(sync_service.Service, "next_outbound_transport_frame_slot_index") == u8 and
            @FieldType(sync_service.Service, "next_inbound_transport_frame_slot_index") == u8 and
            @FieldType(sync_service.Service, "active_overlay_session_count") == u8,
        .stores_compact_replication_result_metadata = sync_service.COMPACT_REPLICATION_SUMMARY_METADATA and
            sync_service.COMPACT_PEER_REPLICATION_RESULT_METADATA and
            @FieldType(sync_service.ReplicationSummary, "selected_entry_count") == u8 and
            @FieldType(sync_service.ReplicationSummary, "skipped_entry_count") == u8 and
            @FieldType(sync_service.ReplicationSummary, "snapshot_count") == u16 and
            @FieldType(sync_service.ReplicationSummary, "conflict_count") == u8 and
            @FieldType(sync_service.ReplicationSummary, "transport_frame_count") == u8 and
            @FieldType(sync_service.PeerReplicationResult, "accepted_frame_count") == u8 and
            @FieldType(sync_service.PeerReplicationResult, "persisted_object_count") == u8 and
            @FieldType(sync_service.PeerReplicationResult, "relay_delivery_count") == u32 and
            @FieldType(sync_service.PeerReplicationResult, "payload_bytes") == u32,
        .keeps_replication_results_within_ceilings = @sizeOf(sync_service.ReplicationSummary) <= sync_service.REPLICATION_SUMMARY_SIZE_CEILING_BYTES and
            @sizeOf(sync_service.PeerReplicationResult) <= sync_service.PEER_REPLICATION_RESULT_SIZE_CEILING_BYTES,
        .stores_compact_sync_record_metadata = sync_state_support.COMPACT_RECORD_METADATA and
            @FieldType(sync_state_support.WorkspacePolicy, "selective_prefix_count") == u8 and
            @FieldType(sync_state_support.WorkspacePolicy, "selective_prefix_lens") == [sync_state_support.MAX_SELECTIVE_PREFIXES]u8 and
            @FieldType(sync_state_support.WorkspacePolicy, "relay_domain_len") == u8 and
            @FieldType(sync_state_support.OverlayRecord, "service_identity_len") == u8 and
            @FieldType(sync_state_support.OverlayRecord, "private_service_count") == u8 and
            @FieldType(sync_state_support.OverlayRecord, "private_service_lens") == [sync_state_support.MAX_PRIVATE_SERVICES]u8 and
            @FieldType(sync_state_support.DatabaseContract, "bundle_id_len") == u8 and
            @FieldType(sync_state_support.DatabaseContract, "label_len") == u8,
        .stores_compact_sync_paths = @FieldType(sync_state_support.ReplicaEntry, "path_len") == sync_state_support.SyncPathLength and
            @FieldType(sync_state_support.ConflictRecord, "path_len") == sync_state_support.SyncPathLength and
            @FieldType(sync_state_support.ConflictReviewRecord, "path_len") == sync_state_support.SyncPathLength and
            @FieldType(sync_state_support.TransportFrame, "path_len") == sync_state_support.SyncPathLength,
        .keeps_sync_records_within_ceilings = @sizeOf(sync_state_support.WorkspacePolicy) <= sync_state_support.WORKSPACE_POLICY_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.OverlayRecord) <= sync_state_support.OVERLAY_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.ReplicaEntry) <= sync_state_support.REPLICA_ENTRY_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.ConflictRecord) <= sync_state_support.CONFLICT_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.ConflictReviewRecord) <= sync_state_support.CONFLICT_REVIEW_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.DatabaseContract) <= sync_state_support.DATABASE_CONTRACT_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.TransportFrame) <= sync_state_support.TRANSPORT_FRAME_SIZE_CEILING_BYTES,
        .keeps_sync_state_within_ceilings = @sizeOf(sync_state_support.PersistentState) <= sync_state_support.PERSISTENT_STATE_SIZE_CEILING_BYTES and
            @sizeOf(sync_state_support.ResidentState) <= sync_state_support.RESIDENT_STATE_SIZE_CEILING_BYTES,
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
        .stores_compact_document_log_metadata = sync_adapters.COMPACT_DOCUMENT_LOG_METADATA and
            @FieldType(sync_adapters.DocumentOperation, "text_len") == u8 and
            @FieldType(sync_adapters.DocumentOperationLog, "operation_count") == u8 and
            @FieldType(sync_adapters.DocumentOperationLog, "clock_count") == u8,
        .keeps_document_log_state_within_ceilings = @sizeOf(sync_adapters.DocumentOperation) <= sync_adapters.DOCUMENT_OPERATION_SIZE_CEILING_BYTES and
            @sizeOf(sync_adapters.DocumentOperationLog) <= sync_adapters.DOCUMENT_OPERATION_LOG_SIZE_CEILING_BYTES,
        .uses_transport_frame_arena = @hasField(sync_adapters.TransportQueue, "frames"),
        .uses_transport_frame_target_index = @hasField(sync_adapters.TransportQueue, "target_index"),
        .uses_transport_frame_path_index = @hasField(sync_adapters.TransportQueue, "path_index"),
    },
    .sync_state_store = .{
        .persists_state_records = @hasDecl(sync_state_store, "persist"),
        .loads_state_records = @hasDecl(sync_state_store, "load"),
        .stores_compact_path_set_metadata = sync_state_store.COMPACT_PATH_SET_METADATA and
            @FieldType(sync_state_store.PathSet, "lens") == [workspace.MAX_WORKSPACE_ENTRIES]u8 and
            @FieldType(sync_state_store.PathSet, "count") == u8,
        .keeps_path_set_within_ceiling = @sizeOf(sync_state_store.PathSet) <= sync_state_store.PATH_SET_SIZE_CEILING_BYTES,
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
        .reuses_mutation_log_tail_for_staging = !@hasField(workspace.WorkspaceStagingState, "staged_entries"),
        .stores_compact_staging_metadata = workspace.COMPACT_STAGING_METADATA and
            @FieldType(workspace.WorkspaceStagingState, "staged_entry_count") == u8 and
            @FieldType(workspace.WorkspaceStagingState, "staged_effective_entry_count") == u8,
        .keeps_staging_state_within_ceiling = @sizeOf(workspace.WorkspaceStagingState) <= workspace.WORKSPACE_STAGING_STATE_SIZE_CEILING_BYTES,
        .stores_compact_snapshot_export_metadata = workspace.COMPACT_SNAPSHOT_EXPORT_METADATA and
            @FieldType(workspace.SnapshotRecord, "label_len") == u8 and
            @FieldType(workspace.SnapshotRecord, "entry_count") == u8 and
            @FieldType(workspace.ExportPackage, "label_len") == u8 and
            @FieldType(workspace.ExportPackage, "entry_count") == u8 and
            @FieldType(workspace.ExportPackage, "signature_format_len") == u8 and
            @FieldType(workspace.ExportPackage, "signature_signer_len") == u8,
        .uses_borrowed_export_package_apis = @hasDecl(workspace.Directory, "exportSnapshotInto") and
            @hasDecl(workspace.Directory, "importWorkspaceFromPackage") and
            !@hasDecl(workspace.Directory, "exportSnapshot") and
            !@hasDecl(workspace.Directory, "importWorkspace"),
        .keeps_snapshot_export_state_within_ceilings = @sizeOf(workspace.SnapshotRecord) <= workspace.SNAPSHOT_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(workspace.ExportPackage) <= workspace.EXPORT_PACKAGE_SIZE_CEILING_BYTES,
        .stores_compact_workspace_label_metadata = workspace.COMPACT_WORKSPACE_LABEL_METADATA and
            @FieldType(workspace.WorkspaceRecord, "label_len") == u8,
        .stores_compact_workspace_table_metadata = workspace.COMPACT_WORKSPACE_TABLE_METADATA and
            @FieldType(workspace.WorkspaceTableCounts, "entry_count") == workspace.WorkspaceEntryCount and
            @FieldType(workspace.WorkspaceTableCounts, "entry_mutation_count") == workspace.WorkspaceMutationCount and
            @FieldType(workspace.WorkspaceTableCounts, "share_grant_count") == workspace.WorkspaceShareGrantCount and
            @FieldType(workspace.WorkspaceTableCounts, "deleted_count") == workspace.RecoverableDeleteCount,
        .keeps_workspace_state_within_ceilings = @sizeOf(workspace.WorkspaceRecord) <= workspace.WORKSPACE_RECORD_SIZE_CEILING_BYTES and
            @sizeOf(workspace.Directory) <= workspace.DIRECTORY_SIZE_CEILING_BYTES,
        .tracks_recoverable_deletes = @hasField(workspace.WorkspaceRecord, "recoverable_deletes"),
        .uses_compact_path_lengths = @sizeOf(workspace.WorkspacePathLength) == 1,
        .caches_leaf_hashes = @hasField(workspace.WorkspacePathIndex, "leaf_hashes"),
        .uses_index_root_address = @hasField(workspace.WorkspacePathIndex, "root_address"),
        .supports_indexed_path_lookup = @hasField(workspace.WorkspacePathIndex, "path_slots"),
        .uses_compact_entry_slot_indexes = @sizeOf(workspace.WorkspaceEntrySlotIndex) == 1,
        .supports_borrowed_path_lookup = @hasDecl(workspace.Directory, "resolveBorrowed"),
        .supports_indexed_object_lookup = @hasField(workspace.WorkspacePathIndex, "object_slots"),
        .supports_indexed_snapshot_lookup = @hasDecl(workspace.Directory, "findSnapshotConst"),
        .tracks_workspace_count = @hasDecl(workspace.Directory, "workspaceCount"),
        .tracks_snapshot_count = @hasDecl(workspace.Directory, "snapshotCount"),
        .tracks_oldest_snapshot_generation = @hasField(workspace.WorkspaceRecord, "oldest_snapshot_generation"),
        .exposes_oldest_snapshot_generation = @hasDecl(workspace.WorkspaceRecord, "oldestSnapshotGeneration"),
    },
    .storage_volume = .{
        .stores_compact_root_summary_metadata = storage_root_slot.COMPACT_ROOT_SUMMARY_METADATA and
            @FieldType(storage_root_slot.RootState, "workspace_summary_count") == u8,
        .keeps_root_state_within_ceiling = @sizeOf(storage_root_slot.RootState) <= storage_root_slot.ROOT_STATE_SIZE_CEILING_BYTES,
        .persists_workspace_state = @hasDecl(storage_volume, "saveToImage"),
        .replays_state_by_primary_index = @hasDecl(storage_volume, "loadFromImage"),
        .requires_target_nvme_attachment = @hasDecl(storage_volume.Volume, "hasProductionStorageBackend"),
        .bounds_log_io_workspace_to_one_data_region = storage_volume.IO_LOG_WORKSPACE_BYTES == storage_volume.DATA_REGION_BYTES,
        .interns_replayed_signer_text = @hasField(storage_volume.Volume, "signer_text_pool") and
            !@hasField(storage_volume.Volume, "version_signers") and
            !@hasField(storage_volume.Volume, "object_signers") and
            !@hasField(storage_volume.Volume, "snapshot_signers") and
            @sizeOf(@FieldType(storage_volume.Volume, "signer_text_pool")) == storage_volume.SIGNER_TEXT_POOL_BYTES,
        .tracks_latest_inserted_version = @hasField(object_store.Store, "latest_inserted_version_id"),
        .exposes_latest_inserted_version_lookup = @hasDecl(object_store.Store, "latestInsertedVersionConst"),
        .uses_compact_blob_chunk_edges = @sizeOf(object_store.BlobChunkSlotIndex) == 2 and @hasField(object_store.BlobRecord, "chunk_slot_indexes"),
        .uses_compact_version_blob_references = @sizeOf(object_store.VersionBlobSlotIndex) == 2 and
            !@hasField(object_store.VersionRecord, "blob_address") and
            !@hasField(object_store.VersionRecord, "payload_len") and
            !@hasField(object_store.VersionRecord, "chunk_count"),
        .uses_compact_object_result_metadata = object_store.COMPACT_OBJECT_RESULT_METADATA and
            @FieldType(object_store.ObjectQueryResult, "label_len") == u8 and
            @FieldType(object_store.ObjectQueryResult, "content_type_len") == u8 and
            @FieldType(object_store.ObjectHistoryEntry, "payload_len") == u32 and
            @FieldType(object_store.ObjectHistoryEntry, "label_len") == u8 and
            @FieldType(object_store.ObjectHistoryEntry, "content_type_len") == u8,
        .keeps_object_results_within_ceilings = @sizeOf(object_store.ObjectQueryResult) <= object_store.OBJECT_QUERY_RESULT_SIZE_CEILING_BYTES and
            @sizeOf(object_store.ObjectHistoryEntry) <= object_store.OBJECT_HISTORY_ENTRY_SIZE_CEILING_BYTES,
        .uses_object_type_index = @hasField(object_store.Store, "object_type_index"),
        .tracks_max_blob_payload_bytes = @hasField(object_store.Store, "max_blob_payload_bytes"),
        .exposes_max_blob_payload_bytes = @hasDecl(object_store.Store, "maxBlobPayloadBytes"),
        .bounds_inline_payload_materialization = object_store.MAX_INLINE_PAYLOAD_BYTES == 2 * object_store.MAX_CHUNK_BYTES and
            object_store.MAX_INLINE_PAYLOAD_BYTES < object_store.MAX_PAYLOAD_BYTES and
            @sizeOf(@FieldType(object_store.Store, "inline_payload_read_buffer")) == object_store.MAX_INLINE_PAYLOAD_BYTES,
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
        .scans_bounded_diagnostic_ring = supervisor.supervisor_indexing.scans_bounded_diagnostic_ring,
        .scans_diagnostics_newest_first = supervisor.supervisor_indexing.scans_diagnostics_newest_first,
        .uses_diagnostic_ring_cursor = @hasField(supervisor.Supervisor, "next_diagnostic_slot"),
        .stores_compact_diagnostic_ring_metadata = supervisor.COMPACT_DIAGNOSTIC_RING_METADATA and
            @FieldType(supervisor.Supervisor, "diagnostic_count") == u8 and
            @FieldType(supervisor.Supervisor, "next_diagnostic_slot") == u8,
        .keeps_supervisor_within_ceiling = @sizeOf(supervisor.Supervisor) <= supervisor.SUPERVISOR_SIZE_CEILING_BYTES,
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
        .heap_backs_capability_table_on_freestanding = session_manager_boot_flow.HEAP_BACKED_CAPABILITY_TABLE_ON_FREESTANDING,
        .heap_backs_userspace_catalog_on_freestanding = session_manager_boot_flow.HEAP_BACKED_USERSPACE_CATALOG_ON_FREESTANDING,
        .heap_backs_userspace_scheduler_on_freestanding = session_manager_boot_flow.HEAP_BACKED_USERSPACE_SCHEDULER_ON_FREESTANDING,
        .heap_backs_task_runtime_on_freestanding = session_manager_boot_flow.HEAP_BACKED_TASK_RUNTIME_ON_FREESTANDING,
        .heap_backs_package_service_on_freestanding = session_manager_boot_flow.HEAP_BACKED_PACKAGE_SERVICE_ON_FREESTANDING,
    },
};
