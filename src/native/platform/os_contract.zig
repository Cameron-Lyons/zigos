const std = @import("std");
const abi = @import("../core/abi.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const event_ledger = @import("event_ledger.zig");
const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");
const manifest = @import("../policy/manifest.zig");
const os_identity = @import("os_identity.zig");
const notification_center = @import("../services/notification_center.zig");
const object_resilience_service = @import("../services/object_resilience_service.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const process_isolation = @import("../task/process_isolation.zig");
const device_graph = @import("../sync/device_graph.zig");
const secure_secret_store = @import("secure_secret_store.zig");
const service_catalog = @import("../session/service_catalog.zig");
const sync_adapters = @import("../sync/sync_adapters.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_registry = @import("../task/userspace_registry.zig");
const humane_shell = @import("rendered_shell/humane_shell.zig");
const signing = @import("../core/signing.zig");
const manifest_linter = @import("../sdk/manifest_linter.zig");
const agent_delegation_service = @import("../services/agent_delegation_service.zig");
const indexing_service = @import("../services/indexing_service.zig");
const network_policy = @import("../sync/network_policy.zig");
const network_session_service = @import("../services/network_session_service.zig");
const package_digest = @import("../services/package_service_digest.zig");
const package_service = @import("../services/package_service.zig");
const package_model = @import("../services/package_service_model.zig");
const attention_broker_service = @import("../services/attention_broker_service.zig");
const personal_context_service = @import("../services/personal_context_service.zig");
const secure_pasteboard = @import("../services/secure_pasteboard.zig");
const secret_vault_service = @import("../services/secret_vault_service.zig");
const sensitive_capture_service = @import("../services/sensitive_capture_service.zig");
const task_lifecycle_service = @import("../services/task_lifecycle_service.zig");
const typed_component_abi = @import("../services/typed_component_abi.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Feature = enum(u8) {
    native_only_apps,
    no_compatibility_namespace,
    typed_component_services,
    explicit_capability_grants,
    object_native_storage,
    local_first_sync,
    policy_gated_egress,
    device_bound_identity,
    measured_boot_attestation,
    signed_reversible_updates,
    recovery_key_lifecycle,
    restartable_userspace_drivers,
    redacted_diagnostics,
    private_local_ai,
    typed_ai_inference_service,
    carbon_aware_scheduling,
};

pub const feature_count = std.meta.fields(Feature).len;

pub const ExtraFeature = enum(u8) {
    permission_sensitivity_labels,
    user_visible_permission_reasons,
    secret_permissions_local_only,
    sensitive_remote_egress_intent,
    permission_digest_covers_privacy,
    package_preserves_permission_privacy,
    dangerous_permission_lint_reason,
    typed_privacy_budget_service,
    typed_diagnostics_export_service,
    privacy_budget_policy,
    camera_policy_gate,
    microphone_policy_gate,
    location_policy_gate,
    contacts_policy_gate,
    sensor_policy_gate,
    clipboard_policy_gate,
    peer_ipc_policy_gate,
    private_egress_budget_policy,
    data_egress_ledger,
    privacy_budget_ledger,
    diagnostics_private_egress_summary,
    remote_diagnostics_consent,
    process_hidden_observability_denied,
    process_continuous_observability_scope,
    ai_context_budget_policy,
    ai_training_audit_manifest,
    offline_ai_local_model_manifest,
    private_ai_diagnostics_redaction,
    compatibility_lint_rejection,
    native_registry_privacy_discovery,
    no_secret_remote_permissions,
    sensitive_permission_reason_validation,
    typed_diagnostics_share_validation,
    local_first_sensitive_defaults,
};

pub const extra_feature_count = std.meta.fields(ExtraFeature).len;

pub const ThirdFeature = enum(u8) {
    permission_purpose_labels,
    permission_retention_days,
    sensitive_purpose_validation,
    sensitive_retention_validation,
    sensitive_retention_ceiling,
    secret_retention_ceiling,
    sensitive_lease_validation,
    package_preserves_permission_purpose,
    package_preserves_permission_retention,
    permission_digest_covers_purpose,
    permission_digest_covers_retention,
    linter_purpose_guidance,
    linter_retention_guidance,
    linter_lease_guidance,
    policy_sensitive_retention_cap,
    policy_permission_lease_cap,
    policy_requires_sensitive_lease,
    permission_use_policy_request,
    retention_policy_ledger,
    permission_lease_ledger,
    permission_lease_expiration_summary,
    consent_receipt_ledger,
    consent_revocation_summary,
    typed_consent_receipts_service,
    typed_permission_lease_service,
    consent_record_wire_validation,
    permission_lease_expire_wire_validation,
    native_registry_consent_discovery,
    native_registry_lease_discovery,
    retention_diagnostics_redacted,
    lease_diagnostics_redacted,
    consent_diagnostics_redacted,
};

pub const third_feature_count = std.meta.fields(ThirdFeature).len;

pub const FourthFeature = enum(u8) {
    data_rights_manifest,
    private_object_data_rights_validation,
    deletion_receipt_manifest_validation,
    data_rights_digest_covers_export_format,
    package_preserves_data_rights,
    typed_data_rights_service,
    data_export_prepare_operation,
    data_delete_request_operation,
    data_delete_receipt_operation,
    native_registry_data_rights_discovery,
    policy_data_export_gate,
    policy_data_delete_gate,
    policy_export_byte_budget,
    policy_deletion_receipt_required,
    policy_data_rights_request,
    data_export_ledger,
    data_deletion_ledger,
    data_rights_diagnostics,
    data_export_redaction,
    data_deletion_receipt_summary,
};

pub const fourth_feature_count = std.meta.fields(FourthFeature).len;

pub const FifthFeature = enum(u8) {
    ai_model_digest_manifest,
    ai_model_source_manifest,
    local_ai_digest_validation,
    local_ai_source_validation,
    private_ai_locality_validation,
    ai_digest_covers_model_provenance,
    package_preserves_model_digest,
    package_preserves_model_source,
    typed_ai_model_registry_service,
    ai_model_register_operation,
    ai_model_attest_operation,
    ai_model_revoke_operation,
    native_registry_ai_model_discovery,
    policy_ai_model_measurement_gate,
    policy_ai_model_source_gate,
    policy_ai_model_age_gate,
    ai_use_provenance_request,
    ai_model_attestation_ledger,
    ai_model_attestation_diagnostics,
    ai_model_rejection_summary,
};

pub const fifth_feature_count = std.meta.fields(FifthFeature).len;

pub const SixthFeature = enum(u8) {
    credential_assertion_hardware_backed,
    credential_assertion_platform_device,
    credential_assertion_primary_device,
    credential_assertion_trust_generation,
    credential_assertion_unlock_age,
    policy_hardware_session_gate,
    policy_platform_device_session_gate,
    policy_primary_device_session_gate,
    policy_unlock_age_gate,
    session_trust_request,
    typed_identity_session_service,
    identity_session_authorize_operation,
    identity_session_step_up_operation,
    identity_session_revoke_operation,
    native_registry_identity_session_discovery,
    session_posture_ledger,
    session_posture_diagnostics,
    session_posture_denial_summary,
    identity_session_redaction,
    policy_digest_covers_session_gates,
};

pub const sixth_feature_count = std.meta.fields(SixthFeature).len;

pub const SeventhFeature = enum(u8) {
    supply_chain_manifest,
    sbom_digest_manifest,
    source_archive_digest_manifest,
    build_recipe_digest_manifest,
    vulnerability_scan_digest_manifest,
    builder_identity_manifest,
    reproducible_build_validation,
    trusted_builder_validation,
    supply_chain_digest_covers_sbom,
    supply_chain_digest_covers_builder,
    package_preserves_supply_chain,
    package_resolves_supply_chain,
    policy_package_sbom_gate,
    policy_package_reproducible_gate,
    policy_package_builder_gate,
    policy_vulnerability_scan_gate,
    package_provenance_request,
    package_provenance_policy_decision,
    package_install_provenance_error,
    install_source_policy_still_present,
    package_active_revision_mutation_gate,
};

pub const seventh_feature_count = std.meta.fields(SeventhFeature).len;

pub const EighthFeature = enum(u8) {
    agent_delegation_manifest,
    agent_purpose_validation,
    agent_action_budget_validation,
    agent_remote_confirmation_validation,
    agent_digest_covers_purpose,
    package_preserves_agent_delegation,
    package_resolves_agent_delegation,
    policy_agent_allowed_gate,
    policy_agent_action_budget,
    policy_agent_remote_budget,
    policy_agent_confirmation_gate,
    policy_agent_audit_gate,
    agent_delegation_request,
    agent_delegation_policy_decision,
    typed_agent_delegation_service,
    agent_authorize_operation,
    agent_record_action_operation,
    agent_revoke_operation,
    agent_delegation_ledger,
    agent_delegation_diagnostics,
};

pub const eighth_feature_count = std.meta.fields(EighthFeature).len;

pub const NinthFeature = enum(u8) {
    attention_policy_create_request,
    quiet_hours_policy,
    visible_notification_budget_policy,
    interruptive_notification_budget_policy,
    critical_interruption_policy,
    attention_policy_request,
    attention_policy_decision,
    notification_center_attention_policy,
    notification_center_quiet_mode,
    notification_center_interruption_budget,
    attention_policy_ledger,
    attention_policy_diagnostics,
    attention_policy_redaction,
    policy_digest_covers_attention,
    structured_urgency_classification,
    suppression_replacement_preserved,
};

pub const ninth_feature_count = std.meta.fields(NinthFeature).len;

pub const TenthFeature = enum(u8) {
    accessibility_manifest,
    accessibility_profile_validation,
    accessibility_keyboard_validation,
    accessibility_digest_covers_profile,
    package_preserves_accessibility,
    package_resolves_accessibility,
    policy_adaptive_ui_gate,
    policy_screen_reader_gate,
    policy_keyboard_navigation_gate,
    policy_reduced_motion_gate,
    policy_high_contrast_gate,
    accessibility_policy_request,
    typed_accessibility_profile_service,
    accessibility_profile_get_operation,
    accessibility_profile_apply_operation,
    native_registry_accessibility_discovery,
    accessibility_profile_ledger,
    accessibility_profile_diagnostics,
    accessibility_redaction,
    rendered_shell_accessibility_profile,
};

pub const tenth_feature_count = std.meta.fields(TenthFeature).len;

pub const EleventhFeature = enum(u8) {
    agent_manifest_session_binding,
    agent_manifest_local_context,
    agent_manifest_context_budget,
    agent_manifest_kill_switch,
    agent_session_binding_validation,
    agent_context_budget_validation,
    agent_kill_switch_validation,
    agent_digest_covers_session_scope,
    package_preserves_agent_session_scope,
    package_resolves_agent_session_scope,
    policy_agent_session_binding_gate,
    policy_agent_local_context_gate,
    policy_agent_context_budget_gate,
    policy_agent_kill_switch_gate,
    policy_agent_visible_plan_gate,
    agent_session_policy_request,
    typed_agent_session_bind_operation,
    typed_agent_kill_switch_operation,
    agent_session_service_model,
    agent_action_binding_gate,
    agent_session_service_kill_switch,
    agent_session_cumulative_context_budget,
    agent_action_denial_audit,
    agent_session_ledger,
    agent_session_redaction,
};

pub const eleventh_feature_count = std.meta.fields(EleventhFeature).len;

pub const TwelfthFeature = enum(u8) {
    background_manifest_decl,
    background_permission_pairing,
    background_budget_validation,
    background_network_visibility_validation,
    background_digest_covers_budget,
    package_preserves_background_tasks,
    policy_background_duration_gate,
    policy_background_cpu_gate,
    policy_background_memory_gate,
    policy_background_network_gate,
    policy_background_visibility_gate,
    background_activity_policy_request,
    typed_background_activity_service,
    background_authorize_operation,
    background_record_operation,
    background_complete_operation,
    background_completion_binding_gate,
    native_registry_background_discovery,
    background_dispatch_runtime_gate,
    background_expiration_watchdog,
    background_activity_ledger,
    background_activity_redaction,
};

pub const twelfth_feature_count = std.meta.fields(TwelfthFeature).len;

pub const ThirteenthFeature = enum(u8) {
    secure_pasteboard_service_model,
    pasteboard_foreground_gesture_gate,
    pasteboard_destination_bound_grant,
    pasteboard_destination_principal_bound_grant,
    pasteboard_strict_expiry_gate,
    pasteboard_read_once_token,
    pasteboard_revocation_gate,
    pasteboard_user_visible_audit,
    pasteboard_redacted_diagnostics,
    typed_secure_pasteboard_service,
    pasteboard_offer_operation,
    pasteboard_read_operation,
    pasteboard_revoke_operation,
    native_registry_pasteboard_discovery,
    pasteboard_bootstrap_service_contract,
    pasteboard_boot_image_registry,
};

pub const thirteenth_feature_count = std.meta.fields(ThirteenthFeature).len;

pub const FourteenthFeature = enum(u8) {
    object_resilience_manifest,
    encrypted_backup_validation,
    recovery_key_validation,
    portable_restore_validation,
    trusted_restore_validation,
    backup_digest_covers_format,
    package_preserves_object_resilience,
    package_resolves_object_resilience,
    policy_backup_allowed_gate,
    policy_restore_allowed_gate,
    policy_encrypted_backup_gate,
    policy_restore_device_trust_gate,
    typed_object_resilience_service,
    backup_prepare_operation,
    restore_authorize_operation,
    backup_revoke_operation,
    native_registry_object_resilience_discovery,
    object_resilience_service_model,
    restore_token_device_bound,
    restore_snapshot_subject_bound,
    revoke_snapshot_source_task_bound,
    backup_revocation_gate,
    object_resilience_ledger,
    object_resilience_redaction,
    object_resilience_bootstrap_contract,
    object_resilience_boot_image_registry,
};

pub const fourteenth_feature_count = std.meta.fields(FourteenthFeature).len;

pub const FifteenthFeature = enum(u8) {
    semantic_index_manifest,
    semantic_index_local_validation,
    semantic_index_encryption_validation,
    semantic_index_redaction_validation,
    semantic_index_query_budget_validation,
    semantic_index_model_digest_validation,
    semantic_index_digest_covers_model,
    package_preserves_semantic_index,
    package_resolves_semantic_index,
    policy_semantic_memory_gate,
    policy_semantic_local_model_gate,
    policy_semantic_encryption_gate,
    policy_semantic_redaction_gate,
    policy_semantic_query_budget_gate,
    typed_index_search_service,
    index_upsert_operation,
    index_query_operation,
    semantic_query_operation,
    native_registry_index_discovery,
    semantic_query_service_model,
    semantic_query_index_generation,
    semantic_query_top_k_ranking,
    semantic_query_result_redaction,
    semantic_query_workspace_scope,
    semantic_memory_ledger,
    semantic_memory_redaction,
};

pub const fifteenth_feature_count = std.meta.fields(FifteenthFeature).len;

pub const SixteenthFeature = enum(u8) {
    passwordless_unlock_methods,
    passkey_credential_service_model,
    credential_hardware_sealed_secret,
    credential_phishing_origin_rejection,
    credential_local_unlock_required,
    credential_fresh_unlock_enforced,
    device_bound_wrong_device_rejected,
    synced_credential_recovery_device_graph,
    device_bound_recovery_denied,
    credential_revocation_gate,
    policy_credential_assertion_gate,
    policy_credential_password_fallback_gate,
    policy_credential_phishing_gate,
    policy_credential_hardware_gate,
    policy_credential_local_unlock_gate,
    policy_credential_unlock_age_gate,
    identity_credential_register_operation,
    identity_credential_assert_operation,
    identity_credential_recover_operation,
    identity_credential_revoke_operation,
    credential_ledger,
    credential_redaction,
};

pub const sixteenth_feature_count = std.meta.fields(SixteenthFeature).len;

pub const SeventeenthFeature = enum(u8) {
    crdt_document_operation_model,
    deterministic_document_merge,
    idempotent_operation_log_merge,
    vector_clock_tracking,
    merge_buffer_bounds,
    encrypted_transport_queue,
    mergeable_transport_semantic,
    sync_service_replication_model,
    conflict_review_service_model,
    conflict_resolution_service_model,
    sync_destination_policy_gate,
    personal_e2ee_default_policy,
    offline_first_default_policy,
    sync_conflict_ledger,
    sync_conflict_redaction,
    typed_sync_replication_service,
    sync_device_enroll_operation,
    sync_workspace_replicate_operation,
    sync_conflict_review_operation,
    sync_conflict_resolve_operation,
    sync_transport_frame_operation,
    native_registry_sync_discovery,
    sync_boot_image_registry,
};

pub const seventeenth_feature_count = std.meta.fields(SeventeenthFeature).len;

pub const EighteenthFeature = enum(u8) {
    sensitive_capture_service_model,
    capture_foreground_session_gate,
    capture_privacy_indicator_gate,
    capture_background_denial,
    capture_lease_policy_gate,
    capture_indicator_expiry_boundary,
    capture_session_binding_gate,
    capture_sample_budget_gate,
    capture_permission_kind_policy_gate,
    capture_revocation_gate,
    sensitive_capture_ledger,
    sensitive_capture_redaction,
    typed_sensitive_capture_service,
    capture_start_operation,
    capture_sample_operation,
    capture_stop_operation,
    native_registry_capture_discovery,
    capture_bootstrap_service_contract,
    capture_boot_image_registry,
    camera_permission_manifest_lease,
    microphone_permission_manifest_lease,
    screen_capture_permission_manifest_lease,
};

pub const eighteenth_feature_count = std.meta.fields(EighteenthFeature).len;

pub const NineteenthFeature = enum(u8) {
    secret_vault_service_model,
    hardware_sealed_import,
    nonresident_secret_material,
    secret_owner_binding,
    leased_handle_lending,
    secret_handle_expiry_boundary,
    raw_export_policy_denial,
    raw_export_handle_capability_gate,
    raw_export_success_audit,
    store_handle_identity_binding,
    secret_rotation_revokes_old_handles,
    explicit_handle_revocation,
    secret_revoke_binding_gate,
    secret_hardware_policy_gate,
    secret_lease_policy_gate,
    secret_vault_ledger,
    secret_vault_redaction,
    typed_secret_vault_service,
    secret_import_operation,
    secret_lend_operation,
    secret_rotate_operation,
    secret_revoke_operation,
    native_registry_secret_discovery,
    secret_vault_bootstrap_contract,
    secret_vault_boot_image_registry,
};

pub const nineteenth_feature_count = std.meta.fields(NineteenthFeature).len;

pub const TwentiethFeature = enum(u8) {
    attention_broker_service_model,
    brokered_notification_post,
    notification_default_task_binding,
    quiet_interrupt_denial,
    critical_interrupt_denial,
    visible_budget_denial,
    interruption_budget_denial,
    notification_dismissal,
    notification_task_bound_dismissal,
    notification_strict_expiry_boundary,
    latest_visible_query,
    attention_broker_policy_gate,
    attention_broker_ledger,
    attention_broker_redaction,
    typed_attention_broker_service,
    attention_post_operation,
    attention_dismiss_operation,
    attention_query_operation,
    native_registry_attention_discovery,
    attention_broker_bootstrap_contract,
    attention_broker_boot_image_registry,
};

pub const twentieth_feature_count = std.meta.fields(TwentiethFeature).len;

pub const TwentyFirstFeature = enum(u8) {
    task_lifecycle_service_model,
    brokered_task_suspend,
    invalid_suspend_denial,
    brokered_task_resume,
    terminate_checkpoint_policy_denial,
    brokered_task_terminate,
    lifecycle_target_owner_binding,
    task_lifecycle_policy_gate,
    task_lifecycle_runtime_audit,
    task_lifecycle_ledger,
    task_lifecycle_redaction,
    typed_task_lifecycle_service,
    lifecycle_suspend_operation,
    lifecycle_resume_operation,
    lifecycle_terminate_operation,
    native_registry_lifecycle_discovery,
    lifecycle_bootstrap_contract,
    lifecycle_boot_image_registry,
    lifecycle_policy_digest,
};

pub const twenty_first_feature_count = std.meta.fields(TwentyFirstFeature).len;

pub const TwentySecondFeature = enum(u8) {
    package_offboarding_service_model,
    package_port_offboarding_authority_path,
    offboard_policy_delete_gate,
    offboard_receipt_required,
    denied_offboard_preserves_install,
    receipt_backed_package_remove,
    offboard_result_receipt,
    offboard_removed_bundle_digest,
    offboard_removed_bundle_digest_content_binding,
    offboard_revision_purge,
    removed_bundle_unlaunchable,
    offboard_data_deletion_ledger,
    offboard_redaction,
    typed_package_remove_operation,
    package_remove_operation_id,
    package_remove_wire_validation,
    package_registry_discovery,
    package_offboard_policy_digest,
};

pub const twenty_second_feature_count = std.meta.fields(TwentySecondFeature).len;

pub const TwentyThirdFeature = enum(u8) {
    scheduler_resource_governance_model,
    hardware_telemetry_provider_boundary,
    hardware_evidence_required_for_accelerator_queues,
    foreground_thermal_dispatch,
    emergency_pressure_bypass,
    background_thermal_delay,
    batch_battery_delay,
    batch_recovers_after_pressure,
    pressure_delay_reason_accounting,
    dispatch_budget_accounting,
    privacy_mode_degrades_accelerator,
    carbon_aware_planner_compat,
    resource_governance_ledger,
    resource_governance_diagnostics,
    resource_governance_redaction,
    resource_governance_query_index,
};

pub const twenty_third_feature_count = std.meta.fields(TwentyThirdFeature).len;

pub const TwentyFourthFeature = enum(u8) {
    network_session_service_model,
    existing_egress_broker_composed,
    allow_list_destination_gate,
    attested_session_open,
    session_byte_budget,
    session_expiry_boundary_gate,
    session_effective_budget_policy,
    transfer_over_budget_denied,
    session_mutation_binding,
    session_revocation_gate,
    revoked_session_transfer_denied,
    completed_session_transfer_denied,
    network_session_ledger,
    network_session_diagnostics,
    network_session_redaction,
    typed_network_open_session_operation,
    typed_network_transfer_operation,
    typed_network_revoke_operation,
    network_session_wire_validation,
    network_stack_catalog_binding,
};

pub const twenty_fourth_feature_count = std.meta.fields(TwentyFourthFeature).len;

pub const TwentyFifthFeature = enum(u8) {
    personal_context_service_model,
    semantic_policy_composed,
    local_model_gate,
    encrypted_index_gate,
    redacted_snippet_gate,
    context_query_byte_budget,
    context_lease_issue,
    context_lease_query_accounting,
    context_query_canonical_byte_metering,
    context_indexed_retrieval,
    context_pack_redaction,
    context_pack_receipt,
    context_pack_index_generation,
    context_pack_index_staleness_guard,
    context_pack_accounting_snapshot_guard,
    context_pack_envelope_consistency,
    context_pack_request_fingerprint,
    context_pack_sensitivity_envelope,
    context_pack_empty_receipt,
    context_pack_freshness,
    context_pack_revocation_binding,
    context_pack_replay_guard,
    context_pack_live_replay_verifier,
    context_pack_receipt_audit,
    context_pack_invalid_receipt_audit,
    context_pack_malformed_receipt_audit,
    context_pack_policy_reauthorization,
    context_lease_privacy_mode_binding,
    context_lease_expiration_gate,
    context_lease_revocation_gate,
    context_workspace_scope_gate,
    personal_context_ledger,
    personal_context_diagnostics,
    personal_context_redaction,
    typed_context_lease_operation,
    typed_context_query_operation,
    typed_context_revoke_operation,
    context_wire_validation,
    personal_context_catalog_binding,
};

pub const twenty_fifth_feature_count = std.meta.fields(TwentyFifthFeature).len;

pub const Checklist = FeatureChecklist(Feature);

pub const ExtraChecklist = FeatureChecklist(ExtraFeature);

fn FeatureChecklist(comptime FeatureEnum: type) type {
    const count = std.meta.fields(FeatureEnum).len;
    return struct {
        const Self = @This();

        satisfied_features: [count]bool,

        pub fn complete(self: Self) bool {
            return self.satisfiedCount() == count;
        }

        pub fn satisfiedCount(self: Self) usize {
            var count_satisfied: usize = 0;
            for (self.satisfied_features) |satisfied_feature| {
                if (satisfied_feature) count_satisfied += 1;
            }
            return count_satisfied;
        }

        pub fn satisfied(self: Self, feature: FeatureEnum) bool {
            return self.satisfied_features[@intFromEnum(feature)];
        }
    };
}

pub const ThirdChecklist = FeatureChecklist(ThirdFeature);
pub const FourthChecklist = FeatureChecklist(FourthFeature);
pub const FifthChecklist = FeatureChecklist(FifthFeature);
pub const SixthChecklist = FeatureChecklist(SixthFeature);
pub const SeventhChecklist = FeatureChecklist(SeventhFeature);
pub const EighthChecklist = FeatureChecklist(EighthFeature);
pub const NinthChecklist = FeatureChecklist(NinthFeature);
pub const TenthChecklist = FeatureChecklist(TenthFeature);
pub const EleventhChecklist = FeatureChecklist(EleventhFeature);
pub const TwelfthChecklist = FeatureChecklist(TwelfthFeature);
pub const ThirteenthChecklist = FeatureChecklist(ThirteenthFeature);
pub const FourteenthChecklist = FeatureChecklist(FourteenthFeature);
pub const FifteenthChecklist = FeatureChecklist(FifteenthFeature);
pub const SixteenthChecklist = FeatureChecklist(SixteenthFeature);
pub const SeventeenthChecklist = FeatureChecklist(SeventeenthFeature);
pub const EighteenthChecklist = FeatureChecklist(EighteenthFeature);
pub const NineteenthChecklist = FeatureChecklist(NineteenthFeature);
pub const TwentiethChecklist = FeatureChecklist(TwentiethFeature);
pub const TwentyFirstChecklist = FeatureChecklist(TwentyFirstFeature);
pub const TwentySecondChecklist = FeatureChecklist(TwentySecondFeature);
pub const TwentyThirdChecklist = FeatureChecklist(TwentyThirdFeature);
pub const TwentyFourthChecklist = FeatureChecklist(TwentyFourthFeature);
pub const TwentyFifthChecklist = FeatureChecklist(TwentyFifthFeature);

pub fn currentRepositoryContract() Checklist {
    const default_ai = manifest.AiMetadata{};
    var features = [_]bool{false} ** feature_count;
    features[@intFromEnum(Feature.native_only_apps)] = manifest.requiresApplicationPackaging("app.notes");
    features[@intFromEnum(Feature.no_compatibility_namespace)] = !manifest.isApplicationBundle("compat.posix") and validationFailsWith(.{
        .bundle_id = "compat.posix",
        .display_name = "Compat POSIX",
        .publisher = "zigos.dev",
    }, error.CompatibilityNamespaceUnsupported);
    features[@intFromEnum(Feature.typed_component_services)] = contractPresent("zigos.service.registry");
    features[@intFromEnum(Feature.explicit_capability_grants)] = true;
    features[@intFromEnum(Feature.object_native_storage)] = true;
    features[@intFromEnum(Feature.local_first_sync)] = true;
    features[@intFromEnum(Feature.policy_gated_egress)] = true;
    features[@intFromEnum(Feature.device_bound_identity)] = true;
    features[@intFromEnum(Feature.measured_boot_attestation)] = true;
    features[@intFromEnum(Feature.signed_reversible_updates)] = true;
    features[@intFromEnum(Feature.recovery_key_lifecycle)] = true;
    features[@intFromEnum(Feature.restartable_userspace_drivers)] = true;
    features[@intFromEnum(Feature.redacted_diagnostics)] = true;
    features[@intFromEnum(Feature.private_local_ai)] = !default_ai.training_allowed and default_ai.locality == .inherit_task;
    features[@intFromEnum(Feature.typed_ai_inference_service)] = contractPresent("zigos.ai.inference");
    features[@intFromEnum(Feature.carbon_aware_scheduling)] = carbonAwareSchedulingBackedByPlanner();
    return .{ .satisfied_features = features };
}

fn carbonAwareSchedulingBackedByPlanner() bool {
    const high_carbon_batch = accelerator_scheduler.planWithState(
        .{
            .grid_carbon_intensity_grams_per_kwh = 620,
            .npu_available = true,
        },
        .{},
        .{
            .class = .batch_compute,
            .wants_npu = true,
            .estimated_energy_milliwatt_hours = 2_000,
            .defer_for_low_carbon_power = true,
        },
    );
    const low_carbon_batch = accelerator_scheduler.planWithState(
        .{
            .grid_carbon_intensity_grams_per_kwh = 180,
            .npu_available = true,
        },
        .{},
        .{
            .class = .batch_compute,
            .wants_npu = true,
            .estimated_energy_milliwatt_hours = 2_000,
            .defer_for_low_carbon_power = true,
        },
    );
    const foreground = accelerator_scheduler.planWithState(
        .{
            .grid_carbon_intensity_grams_per_kwh = 620,
            .gpu_available = true,
        },
        .{},
        .{
            .class = .foreground_interactive,
            .wants_gpu = true,
            .shared_memory_bytes = 4096,
            .estimated_energy_milliwatt_hours = 2_000,
            .defer_for_low_carbon_power = true,
        },
    );

    return high_carbon_batch.delayed and
        high_carbon_batch.reason == .carbon_aware_delay and
        !low_carbon_batch.delayed and
        low_carbon_batch.engine == .npu and
        !foreground.delayed and
        foreground.engine == .gpu;
}

pub fn currentRepositoryExtraContract() ExtraChecklist {
    const default_permission = manifest.PermissionRequest{
        .kind = .object_access,
        .resource = "workspace:notes",
        .rights = .{ .object = .{ .object_read = true } },
        .local_only = true,
    };
    const reasoned_permission = manifest.PermissionRequest{
        .kind = .camera,
        .resource = "camera.front",
        .rights = .{ .device = .{} },
        .local_only = true,
        .sensitivity = .private_user_data,
        .user_visible_reason = "Scan a document locally",
    };
    const reason_a = [_]manifest.PermissionRequest{reasoned_permission};
    var reason_b_permission = reasoned_permission;
    reason_b_permission.user_visible_reason = "Join a local video call";
    const reason_b = [_]manifest.PermissionRequest{reason_b_permission};
    const reason_digest_a = package_digest.permissionDigest(&reason_a);
    const reason_digest_b = package_digest.permissionDigest(&reason_b);
    const compat_report = manifest_linter.lintWithIdl(.{
        .bundle_id = "compat.posix",
        .display_name = "Compat POSIX",
        .publisher = "zigos.dev",
        .components = &.{.{ .id = "main", .entry = "compat.posix.main" }},
        .provided_interfaces = &.{.{ .name = "zigos.object.workspace" }},
        .assets = &.{.{ .path = "assets/icon.svg", .content_type = "image/svg+xml" }},
    },
        \\interface zigos.object.workspace 1.0
        \\native object workspace:notes
    );

    var features = [_]bool{false} ** extra_feature_count;
    features[@intFromEnum(ExtraFeature.permission_sensitivity_labels)] = default_permission.sensitivity == .internal_data and manifest.isSensitive(.private_user_data);
    features[@intFromEnum(ExtraFeature.user_visible_permission_reasons)] = reasoned_permission.user_visible_reason.len != 0;
    features[@intFromEnum(ExtraFeature.secret_permissions_local_only)] = validationFailsWith(.{
        .bundle_id = "app.secret-camera",
        .display_name = "Secret Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .sensitivity = .secret_user_data,
        }},
    }, error.SecretPermissionMustStayLocal);
    features[@intFromEnum(ExtraFeature.sensitive_remote_egress_intent)] = validationFailsWith(.{
        .bundle_id = "zigos.private-egress",
        .display_name = "Private Egress",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
        }},
    }, error.SensitiveRemoteEgressRequiresIntent);
    features[@intFromEnum(ExtraFeature.permission_digest_covers_privacy)] = !std.mem.eql(u8, &reason_digest_a, &reason_digest_b);
    features[@intFromEnum(ExtraFeature.package_preserves_permission_privacy)] = @hasField(package_model.StoredPermission, "sensitivity") and @hasField(package_model.StoredPermission, "user_visible_reason");
    features[@intFromEnum(ExtraFeature.dangerous_permission_lint_reason)] = manifest_linter.lint(.{
        .bundle_id = "app.camera",
        .display_name = "Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
        }},
    }).count(.warning) != 0;
    features[@intFromEnum(ExtraFeature.typed_privacy_budget_service)] = contractPresent("zigos.privacy.budget");
    features[@intFromEnum(ExtraFeature.typed_diagnostics_export_service)] = contractPresent("zigos.diagnostics.export");
    features[@intFromEnum(ExtraFeature.privacy_budget_policy)] = @hasField(policy_object.SensitiveEgressRequest, "remote_bytes");
    features[@intFromEnum(ExtraFeature.camera_policy_gate)] = @hasField(policy_object.CreateRequest, "camera_allowed");
    features[@intFromEnum(ExtraFeature.microphone_policy_gate)] = @hasField(policy_object.CreateRequest, "microphone_allowed");
    features[@intFromEnum(ExtraFeature.location_policy_gate)] = @hasField(policy_object.CreateRequest, "location_allowed");
    features[@intFromEnum(ExtraFeature.contacts_policy_gate)] = @hasField(policy_object.CreateRequest, "contacts_allowed");
    features[@intFromEnum(ExtraFeature.sensor_policy_gate)] = @hasField(policy_object.CreateRequest, "sensors_allowed");
    features[@intFromEnum(ExtraFeature.clipboard_policy_gate)] = @hasField(policy_object.CreateRequest, "clipboard_allowed");
    features[@intFromEnum(ExtraFeature.peer_ipc_policy_gate)] = @hasField(policy_object.CreateRequest, "peer_ipc_allowed");
    features[@intFromEnum(ExtraFeature.private_egress_budget_policy)] = @hasField(policy_object.CreateRequest, "max_remote_private_egress_bytes");
    features[@intFromEnum(ExtraFeature.data_egress_ledger)] = event_ledger.EventKind.data_egress == .data_egress;
    features[@intFromEnum(ExtraFeature.privacy_budget_ledger)] = event_ledger.EventKind.privacy_budget == .privacy_budget;
    features[@intFromEnum(ExtraFeature.diagnostics_private_egress_summary)] = @hasField(event_ledger.DiagnosticSummary, "private_egress_denials");
    features[@intFromEnum(ExtraFeature.remote_diagnostics_consent)] = true;
    features[@intFromEnum(ExtraFeature.process_hidden_observability_denied)] = processHiddenObservabilityDeniedCheck();
    features[@intFromEnum(ExtraFeature.process_continuous_observability_scope)] = processContinuousObservabilityScopeCheck();
    features[@intFromEnum(ExtraFeature.ai_context_budget_policy)] = @hasField(policy_object.CreateRequest, "max_ai_context_bytes");
    features[@intFromEnum(ExtraFeature.ai_training_audit_manifest)] = validationFailsWith(.{
        .bundle_id = "app.training-ai",
        .display_name = "Training AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .training_allowed = true,
        },
    }, error.AiTrainingRequiresAudit);
    features[@intFromEnum(ExtraFeature.offline_ai_local_model_manifest)] = validationFailsWith(.{
        .bundle_id = "app.offline-ai",
        .display_name = "Offline AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .offline_required = true,
        },
    }, error.OfflineAiRequiresLocalModel);
    features[@intFromEnum(ExtraFeature.private_ai_diagnostics_redaction)] = @hasField(event_ledger.DiagnosticSummary, "ai_remote_denials");
    features[@intFromEnum(ExtraFeature.compatibility_lint_rejection)] = compat_report.hasErrors();
    features[@intFromEnum(ExtraFeature.native_registry_privacy_discovery)] = typed_component_abi.interfaceId(.privacy_budget) == .privacy_budget;
    features[@intFromEnum(ExtraFeature.no_secret_remote_permissions)] = validationFailsWith(.{
        .bundle_id = "app.secret-egress",
        .display_name = "Secret Egress",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .network_egress,
            .resource = "relay.secret",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .secret_user_data,
        }},
    }, error.SecretPermissionMustStayLocal);
    features[@intFromEnum(ExtraFeature.sensitive_permission_reason_validation)] = validationFailsWith(.{
        .bundle_id = "app.private-camera",
        .display_name = "Private Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
        }},
    }, error.SensitivePermissionRequiresReason);
    features[@intFromEnum(ExtraFeature.typed_diagnostics_share_validation)] = contractOperationPresent("zigos.diagnostics.export", .diagnostics_share_remote);
    features[@intFromEnum(ExtraFeature.local_first_sensitive_defaults)] = !manifest.isSensitive(default_permission.sensitivity) and default_permission.local_only;
    return .{ .satisfied_features = features };
}

fn processContractTask(
    runtime: *task_runtime.Runtime,
    owner: principal.PrincipalId,
    image_id: u64,
    bundle_id: []const u8,
) !*task_runtime.TaskRecord {
    const image = try generated_image_fixtures.appImage();
    return runtime.createTask(.{
        .owner = owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(16),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = image_id,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    });
}

fn processContractGrant(
    table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    caller_task_id: u64,
    target_task_id: u64,
    issued_at_ticks: u64,
) !capability.Capability {
    return table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 2026 },
        .target = .{ .kind = .task, .id = target_task_id },
        .rights = .{ .task = .{ .process_control = true } },
        .scope = .{
            .task_id = caller_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = issued_at_ticks,
            .expires_at_ticks = issued_at_ticks + 100,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = caller_task_id,
            .broker_service_id = 77,
            .user_visible_entitlement = true,
        },
    });
}

fn processHiddenObservabilityDeniedCheck() bool {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    const caller = processContractTask(&runtime, .{ .kind = .app, .serial = 2040 }, 2040, "app.hidden-observer") catch return false;
    const caller_id = caller.id;
    const caller_owner = caller.owner;
    const target = processContractTask(&runtime, .{ .kind = .app, .serial = 2041 }, 2041, "app.hidden-target") catch return false;
    if (!runtime.processSeparated(caller_id, target.id)) return false;

    const grant = processContractGrant(&capabilities, caller_owner, caller_id, target.id, 10) catch return false;
    runtime.grantCapability(caller_id, grant.id) catch return false;
    var broker = process_isolation.Broker.init(&runtime, &capabilities);
    if (broker.authorize(.{
        .caller_task_id = caller_id,
        .target_task_id = target.id,
        .capability_id = grant.id,
        .operation = .scrape_window,
        .user_visible = true,
        .privacy_indicator_id = 9,
        .privacy_indicator_expires_at_ticks = 100,
        .hidden = true,
        .now_ticks = 20,
    })) |_| {
        return false;
    } else |err| {
        if (err != error.HiddenOperationDenied) return false;
        const latest = (runtime.find(caller_id) orelse return false).latestAuditEvent() orelse return false;
        return latest.kind == .policy_denied and latest.capability_id == 0;
    }
}

fn processContinuousObservabilityScopeCheck() bool {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    const caller = processContractTask(&runtime, .{ .kind = .app, .serial = 2042 }, 2042, "app.continuous-observer") catch return false;
    const caller_id = caller.id;
    const caller_owner = caller.owner;
    const target = processContractTask(&runtime, .{ .kind = .app, .serial = 2043 }, 2043, "app.continuous-target") catch return false;

    const self_grant = processContractGrant(&capabilities, caller_owner, caller_id, caller_id, 20) catch return false;
    runtime.grantCapability(caller_id, self_grant.id) catch return false;
    var broker = process_isolation.Broker.init(&runtime, &capabilities);
    const allowed_hook = broker.authorize(.{
        .caller_task_id = caller_id,
        .capability_id = self_grant.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .privacy_indicator_id = 11,
        .privacy_indicator_expires_at_ticks = 60,
        .continuous = true,
        .now_ticks = 30,
    }) catch return false;
    if (!allowed_hook.allowed or allowed_hook.target_task_id != caller_id) return false;

    if (broker.authorize(.{
        .caller_task_id = caller_id,
        .capability_id = self_grant.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .privacy_indicator_id = 11,
        .privacy_indicator_expires_at_ticks = 40,
        .continuous = true,
        .now_ticks = 40,
    })) |_| {
        return false;
    } else |err| {
        if (err != error.ActivePrivacyIndicatorRequired) return false;
    }

    const cross_grant = processContractGrant(&capabilities, caller_owner, caller_id, target.id, 20) catch return false;
    runtime.grantCapability(caller_id, cross_grant.id) catch return false;
    if (broker.authorize(.{
        .caller_task_id = caller_id,
        .target_task_id = target.id,
        .capability_id = cross_grant.id,
        .operation = .inspect_memory,
        .user_visible = true,
        .privacy_indicator_id = 12,
        .privacy_indicator_expires_at_ticks = 90,
        .continuous = true,
        .now_ticks = 50,
    })) |_| {
        return false;
    } else |err| {
        if (err != error.ContinuousOperationDenied) return false;
        const latest = (runtime.find(caller_id) orelse return false).latestAuditEvent() orelse return false;
        return latest.kind == .policy_denied and latest.capability_id == 0;
    }
}

fn validationFailsWith(bundle: manifest.BundleManifest, expected: anyerror) bool {
    manifest.validate(bundle) catch |err| return err == expected;
    return false;
}

fn contractPresent(interface_name: []const u8) bool {
    return typed_component_abi.contractFor(interface_name) != null;
}

fn contractOperationPresent(interface_name: []const u8, operation_id: typed_component_abi.OperationId) bool {
    const interface_contract = typed_component_abi.contractFor(interface_name) orelse return false;
    return interface_contract.operation(operation_id) != null;
}

pub fn currentRepositoryThirdContract() ThirdChecklist {
    var features = [_]bool{false} ** third_feature_count;
    const base_sensitive = manifest.PermissionRequest{
        .kind = .network_egress,
        .resource = "relay.private",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .sensitivity = .private_user_data,
        .user_visible_reason = "Sync a private document",
        .purpose = .document_editing,
        .retention_days = 30,
        .egress_intent = .{
            .kind = .call_service,
            .service = "private.relay",
        },
    };
    const purpose_a = [_]manifest.PermissionRequest{base_sensitive};
    var purpose_b_permission = base_sensitive;
    purpose_b_permission.purpose = .communication;
    const purpose_b = [_]manifest.PermissionRequest{purpose_b_permission};
    var retention_b_permission = base_sensitive;
    retention_b_permission.retention_days = 31;
    const retention_b = [_]manifest.PermissionRequest{retention_b_permission};
    const purpose_digest_a = package_digest.permissionDigest(&purpose_a);
    const purpose_digest_b = package_digest.permissionDigest(&purpose_b);
    const retention_digest_b = package_digest.permissionDigest(&retention_b);
    const lifecycle_lint = manifest_linter.lint(.{
        .bundle_id = "app.lifecycle",
        .display_name = "Lifecycle",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
        }},
    });

    features[@intFromEnum(ThirdFeature.permission_purpose_labels)] = @hasField(manifest.PermissionRequest, "purpose") and @intFromEnum(manifest.PermissionPurpose.document_editing) != 0;
    features[@intFromEnum(ThirdFeature.permission_retention_days)] = @hasField(manifest.PermissionRequest, "retention_days");
    features[@intFromEnum(ThirdFeature.sensitive_purpose_validation)] = validationFailsWith(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .retention_days = 30,
            .egress_intent = .{ .kind = .call_service, .service = "private.relay" },
        }},
    }, error.SensitivePermissionRequiresPurpose);
    features[@intFromEnum(ThirdFeature.sensitive_retention_validation)] = validationFailsWith(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .purpose = .document_editing,
            .egress_intent = .{ .kind = .call_service, .service = "private.relay" },
        }},
    }, error.SensitivePermissionRequiresRetention);
    features[@intFromEnum(ThirdFeature.sensitive_retention_ceiling)] = validationFailsWith(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .purpose = .document_editing,
            .retention_days = 366,
            .egress_intent = .{ .kind = .call_service, .service = "private.relay" },
        }},
    }, error.SensitiveRetentionTooLong);
    features[@intFromEnum(ThirdFeature.secret_retention_ceiling)] = validationFailsWith(.{
        .bundle_id = "zigos.secret-vault",
        .display_name = "Secret Vault",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .object_access,
            .resource = "workspace:secrets",
            .rights = .{ .object = .{ .object_read = true } },
            .local_only = true,
            .sensitivity = .secret_user_data,
            .purpose = .security,
            .retention_days = 31,
        }},
    }, error.SecretRetentionTooLong);
    features[@intFromEnum(ThirdFeature.sensitive_lease_validation)] = validationFailsWith(.{
        .bundle_id = "app.camera",
        .display_name = "Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &.{.{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
            .user_visible_reason = "Join a local video call",
            .purpose = .communication,
            .retention_days = 1,
        }},
    }, error.SensitivePermissionRequiresLease);
    features[@intFromEnum(ThirdFeature.package_preserves_permission_purpose)] = @hasField(package_model.StoredPermission, "purpose");
    features[@intFromEnum(ThirdFeature.package_preserves_permission_retention)] = @hasField(package_model.StoredPermission, "retention_days");
    features[@intFromEnum(ThirdFeature.permission_digest_covers_purpose)] = !std.mem.eql(u8, &purpose_digest_a, &purpose_digest_b);
    features[@intFromEnum(ThirdFeature.permission_digest_covers_retention)] = !std.mem.eql(u8, &purpose_digest_a, &retention_digest_b);
    features[@intFromEnum(ThirdFeature.linter_purpose_guidance)] = lifecycle_lint.count(.warning) != 0;
    features[@intFromEnum(ThirdFeature.linter_retention_guidance)] = lifecycle_lint.count(.warning) >= 2;
    features[@intFromEnum(ThirdFeature.linter_lease_guidance)] = lifecycle_lint.count(.warning) >= 3;
    features[@intFromEnum(ThirdFeature.policy_sensitive_retention_cap)] = @hasField(policy_object.CreateRequest, "max_sensitive_retention_days");
    features[@intFromEnum(ThirdFeature.policy_permission_lease_cap)] = @hasField(policy_object.CreateRequest, "max_permission_lease_ticks");
    features[@intFromEnum(ThirdFeature.policy_requires_sensitive_lease)] = @hasField(policy_object.CreateRequest, "require_sensitive_permission_lease");
    features[@intFromEnum(ThirdFeature.permission_use_policy_request)] = @hasField(policy_object.PermissionUseRequest, "lease_ticks");
    features[@intFromEnum(ThirdFeature.retention_policy_ledger)] = event_ledger.EventKind.retention_policy == .retention_policy;
    features[@intFromEnum(ThirdFeature.permission_lease_ledger)] = event_ledger.EventKind.permission_lease == .permission_lease;
    features[@intFromEnum(ThirdFeature.permission_lease_expiration_summary)] = @hasField(event_ledger.DiagnosticSummary, "permission_lease_expirations");
    features[@intFromEnum(ThirdFeature.consent_receipt_ledger)] = event_ledger.EventKind.consent_receipt == .consent_receipt;
    features[@intFromEnum(ThirdFeature.consent_revocation_summary)] = @hasField(event_ledger.DiagnosticSummary, "consent_receipt_revocations");
    features[@intFromEnum(ThirdFeature.typed_consent_receipts_service)] = contractPresent("zigos.consent.receipts");
    features[@intFromEnum(ThirdFeature.typed_permission_lease_service)] = contractPresent("zigos.permission.lease");
    features[@intFromEnum(ThirdFeature.consent_record_wire_validation)] = contractOperationPresent("zigos.consent.receipts", .consent_record);
    features[@intFromEnum(ThirdFeature.permission_lease_expire_wire_validation)] = contractOperationPresent("zigos.permission.lease", .permission_lease_expire);
    features[@intFromEnum(ThirdFeature.native_registry_consent_discovery)] = typed_component_abi.interfaceId(.consent_receipts) == .consent_receipts;
    features[@intFromEnum(ThirdFeature.native_registry_lease_discovery)] = typed_component_abi.interfaceId(.permission_lease) == .permission_lease;
    features[@intFromEnum(ThirdFeature.retention_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "retention_policy_events");
    features[@intFromEnum(ThirdFeature.lease_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "permission_lease_events");
    features[@intFromEnum(ThirdFeature.consent_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "consent_receipt_events");

    return .{ .satisfied_features = features };
}

pub fn currentRepositoryFourthContract() FourthChecklist {
    var features = [_]bool{false} ** fourth_feature_count;
    const private_object = manifest.PermissionRequest{
        .kind = .object_access,
        .resource = "workspace:private-notes",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .sensitivity = .private_user_data,
        .purpose = .document_editing,
        .retention_days = 30,
    };
    const private_object_requests = [_]manifest.PermissionRequest{private_object};
    const data_rights_a = manifest.BundleManifest{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &private_object_requests,
        .data_rights = .{
            .portable_export = true,
            .deletion_supported = true,
            .deletion_receipt_required = true,
            .export_format = "application/zigos-object-archive",
        },
    };
    var data_rights_b = data_rights_a;
    data_rights_b.data_rights = .{
        .portable_export = true,
        .deletion_supported = true,
        .deletion_receipt_required = true,
        .export_format = "application/json",
    };
    const digest_a = package_digest.digestBundle(data_rights_a);
    const digest_b = package_digest.digestBundle(data_rights_b);

    features[@intFromEnum(FourthFeature.data_rights_manifest)] = @hasField(manifest.BundleManifest, "data_rights") and @hasField(manifest.DataRightsDecl, "portable_export");
    features[@intFromEnum(FourthFeature.private_object_data_rights_validation)] = validationFailsWith(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &private_object_requests,
    }, error.DataRightsExportMissing);
    features[@intFromEnum(FourthFeature.deletion_receipt_manifest_validation)] = validationFailsWith(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &private_object_requests,
        .data_rights = .{
            .portable_export = true,
            .deletion_supported = true,
            .export_format = "application/zigos-object-archive",
        },
    }, error.DataDeletionReceiptRequired);
    features[@intFromEnum(FourthFeature.data_rights_digest_covers_export_format)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(FourthFeature.package_preserves_data_rights)] = @hasField(package_model.BundleRevision, "data_rights") and @hasField(package_model.ResolvedManifest, "data_rights");
    features[@intFromEnum(FourthFeature.typed_data_rights_service)] = contractPresent("zigos.data.rights");
    features[@intFromEnum(FourthFeature.data_export_prepare_operation)] = contractOperationPresent("zigos.data.rights", .data_export_prepare);
    features[@intFromEnum(FourthFeature.data_delete_request_operation)] = contractOperationPresent("zigos.data.rights", .data_delete_request);
    features[@intFromEnum(FourthFeature.data_delete_receipt_operation)] = contractOperationPresent("zigos.data.rights", .data_delete_receipt);
    features[@intFromEnum(FourthFeature.native_registry_data_rights_discovery)] = typed_component_abi.interfaceId(.data_rights) == .data_rights;
    features[@intFromEnum(FourthFeature.policy_data_export_gate)] = @hasField(policy_object.CreateRequest, "data_export_allowed");
    features[@intFromEnum(FourthFeature.policy_data_delete_gate)] = @hasField(policy_object.CreateRequest, "data_deletion_allowed");
    features[@intFromEnum(FourthFeature.policy_export_byte_budget)] = @hasField(policy_object.CreateRequest, "max_data_export_bytes");
    features[@intFromEnum(FourthFeature.policy_deletion_receipt_required)] = @hasField(policy_object.CreateRequest, "require_data_deletion_receipt");
    features[@intFromEnum(FourthFeature.policy_data_rights_request)] = @hasField(policy_object.DataRightsRequest, "deletion_receipt_present");
    features[@intFromEnum(FourthFeature.data_export_ledger)] = event_ledger.EventKind.data_export == .data_export;
    features[@intFromEnum(FourthFeature.data_deletion_ledger)] = event_ledger.EventKind.data_deletion == .data_deletion;
    features[@intFromEnum(FourthFeature.data_rights_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "data_export_events");
    features[@intFromEnum(FourthFeature.data_export_redaction)] = @hasField(event_ledger.DiagnosticSummary, "data_export_denials");
    features[@intFromEnum(FourthFeature.data_deletion_receipt_summary)] = @hasField(event_ledger.DiagnosticSummary, "data_deletion_receipts");

    return .{ .satisfied_features = features };
}

pub fn currentRepositoryFifthContract() FifthChecklist {
    var features = [_]bool{false} ** fifth_feature_count;
    const measured_local_ai = manifest.BundleManifest{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local-v1",
            .model_source_identity = "store:zigos/local-models",
            .locality = .local_only,
            .private_context = true,
        },
    };
    var measured_local_ai_v2 = measured_local_ai;
    measured_local_ai_v2.ai_metadata = .{
        .model_family = "tiny-local",
        .model_digest = "sha256:tiny-local-v2",
        .model_source_identity = "store:zigos/local-models",
        .locality = .local_only,
        .private_context = true,
    };
    const digest_v1 = package_digest.digestBundle(measured_local_ai);
    const digest_v2 = package_digest.digestBundle(measured_local_ai_v2);

    features[@intFromEnum(FifthFeature.ai_model_digest_manifest)] = @hasField(manifest.AiMetadata, "model_digest");
    features[@intFromEnum(FifthFeature.ai_model_source_manifest)] = @hasField(manifest.AiMetadata, "model_source_identity");
    features[@intFromEnum(FifthFeature.local_ai_digest_validation)] = validationFailsWith(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .local_only,
        },
    }, error.AiModelDigestMissing);
    features[@intFromEnum(FifthFeature.local_ai_source_validation)] = validationFailsWith(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local",
            .locality = .local_only,
        },
    }, error.AiModelSourceMissing);
    features[@intFromEnum(FifthFeature.private_ai_locality_validation)] = validationFailsWith(.{
        .bundle_id = "app.remote-private-ai",
        .display_name = "Remote Private AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "remote-private",
            .locality = .remote_allowed,
            .private_context = true,
        },
    }, error.PrivateAiRequiresLocalModel);
    features[@intFromEnum(FifthFeature.ai_digest_covers_model_provenance)] = !std.mem.eql(u8, &digest_v1, &digest_v2);
    features[@intFromEnum(FifthFeature.package_preserves_model_digest)] = @hasField(package_model.StoredAiMetadata, "model_digest");
    features[@intFromEnum(FifthFeature.package_preserves_model_source)] = @hasField(package_model.StoredAiMetadata, "model_source_identity");
    features[@intFromEnum(FifthFeature.typed_ai_model_registry_service)] = contractPresent("zigos.ai.model.registry");
    features[@intFromEnum(FifthFeature.ai_model_register_operation)] = contractOperationPresent("zigos.ai.model.registry", .ai_model_register);
    features[@intFromEnum(FifthFeature.ai_model_attest_operation)] = contractOperationPresent("zigos.ai.model.registry", .ai_model_attest);
    features[@intFromEnum(FifthFeature.ai_model_revoke_operation)] = contractOperationPresent("zigos.ai.model.registry", .ai_model_revoke);
    features[@intFromEnum(FifthFeature.native_registry_ai_model_discovery)] = typed_component_abi.interfaceId(.ai_model_registry) == .ai_model_registry;
    features[@intFromEnum(FifthFeature.policy_ai_model_measurement_gate)] = @hasField(policy_object.CreateRequest, "require_ai_model_measurement");
    features[@intFromEnum(FifthFeature.policy_ai_model_source_gate)] = @hasField(policy_object.CreateRequest, "require_trusted_ai_model_source");
    features[@intFromEnum(FifthFeature.policy_ai_model_age_gate)] = @hasField(policy_object.CreateRequest, "max_ai_model_age_days");
    features[@intFromEnum(FifthFeature.ai_use_provenance_request)] = @hasField(policy_object.AiUseRequest, "local_model_measured") and @hasField(policy_object.AiUseRequest, "model_source_trusted");
    features[@intFromEnum(FifthFeature.ai_model_attestation_ledger)] = event_ledger.EventKind.ai_model_attestation == .ai_model_attestation;
    features[@intFromEnum(FifthFeature.ai_model_attestation_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "ai_model_attestations");
    features[@intFromEnum(FifthFeature.ai_model_rejection_summary)] = @hasField(event_ledger.DiagnosticSummary, "ai_model_rejections");

    return .{ .satisfied_features = features };
}

pub fn currentRepositorySixthContract() SixthChecklist {
    var features = [_]bool{false} ** sixth_feature_count;
    features[@intFromEnum(SixthFeature.credential_assertion_hardware_backed)] = @hasField(os_identity.Assertion, "hardware_backed_credential");
    features[@intFromEnum(SixthFeature.credential_assertion_platform_device)] = @hasField(os_identity.Assertion, "device_platform_backed");
    features[@intFromEnum(SixthFeature.credential_assertion_primary_device)] = @hasField(os_identity.Assertion, "primary_device_assertion");
    features[@intFromEnum(SixthFeature.credential_assertion_trust_generation)] = @hasField(os_identity.Assertion, "device_trust_generation");
    features[@intFromEnum(SixthFeature.credential_assertion_unlock_age)] = @hasField(os_identity.Assertion, "unlock_age_ticks");
    features[@intFromEnum(SixthFeature.policy_hardware_session_gate)] = @hasField(policy_object.CreateRequest, "require_hardware_backed_session");
    features[@intFromEnum(SixthFeature.policy_platform_device_session_gate)] = @hasField(policy_object.CreateRequest, "require_platform_backed_device_session");
    features[@intFromEnum(SixthFeature.policy_primary_device_session_gate)] = @hasField(policy_object.CreateRequest, "require_primary_device_session");
    features[@intFromEnum(SixthFeature.policy_unlock_age_gate)] = @hasField(policy_object.CreateRequest, "max_session_unlock_age_ticks");
    features[@intFromEnum(SixthFeature.session_trust_request)] = @hasField(policy_object.SessionTrustRequest, "hardware_backed_credential") and
        @hasField(policy_object.SessionTrustRequest, "unlock_age_ticks") and
        @hasDecl(policy_object.Directory, "sessionTrustDecision");
    features[@intFromEnum(SixthFeature.typed_identity_session_service)] = contractPresent("zigos.identity.session");
    features[@intFromEnum(SixthFeature.identity_session_authorize_operation)] = contractOperationPresent("zigos.identity.session", .identity_session_authorize);
    features[@intFromEnum(SixthFeature.identity_session_step_up_operation)] = contractOperationPresent("zigos.identity.session", .identity_session_step_up);
    features[@intFromEnum(SixthFeature.identity_session_revoke_operation)] = contractOperationPresent("zigos.identity.session", .identity_session_revoke);
    features[@intFromEnum(SixthFeature.native_registry_identity_session_discovery)] = typed_component_abi.interfaceId(.identity_session) == .identity_session;
    features[@intFromEnum(SixthFeature.session_posture_ledger)] = event_ledger.EventKind.session_posture == .session_posture and @hasDecl(event_ledger.Ledger, "recordSessionPosture");
    features[@intFromEnum(SixthFeature.session_posture_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "session_posture_events");
    features[@intFromEnum(SixthFeature.session_posture_denial_summary)] = @hasField(event_ledger.DiagnosticSummary, "session_posture_denials");
    features[@intFromEnum(SixthFeature.identity_session_redaction)] = sessionPostureRedactionCheck();
    features[@intFromEnum(SixthFeature.policy_digest_covers_session_gates)] = @hasField(policy_object.PolicyObject, "require_hardware_backed_session") and
        @hasField(policy_object.PolicyObject, "require_platform_backed_device_session") and
        @hasField(policy_object.PolicyObject, "require_primary_device_session") and
        @hasField(policy_object.PolicyObject, "max_session_unlock_age_ticks");

    return .{ .satisfied_features = features };
}

fn sessionPostureRedactionCheck() bool {
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordSessionPosture(
        principal.PrincipalId{ .kind = .user, .serial = 2026 },
        2606,
        false,
        true,
        true,
        true,
        9,
        77,
        "protected session posture evidence",
    ) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return summary.session_posture_events == 1 and
        summary.session_posture_denials == 1 and
        summary.protected_details_redacted == 1;
}

pub fn currentRepositorySeventhContract() SeventhChecklist {
    var features = [_]bool{false} ** seventh_feature_count;
    const base_bundle = manifest.BundleManifest{
        .bundle_id = "app.supply",
        .display_name = "Supply",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .sbom_digest = "sha256:supply-sbom",
            .source_archive_digest = "sha256:supply-source",
            .build_recipe_digest = "sha256:supply-build",
            .vulnerability_scan_digest = "sha256:supply-vuln",
            .build_provenance_identity = "builder:zigos/release",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    };
    var builder_b = base_bundle;
    builder_b.supply_chain = .{
        .sbom_digest = "sha256:supply-sbom",
        .source_archive_digest = "sha256:supply-source",
        .build_recipe_digest = "sha256:supply-build",
        .vulnerability_scan_digest = "sha256:supply-vuln",
        .build_provenance_identity = "builder:zigos/nightly",
        .reproducible_build = true,
        .trusted_builder = true,
    };
    var sbom_b = base_bundle;
    sbom_b.supply_chain = .{
        .sbom_digest = "sha256:supply-sbom-v2",
        .source_archive_digest = "sha256:supply-source",
        .build_recipe_digest = "sha256:supply-build",
        .vulnerability_scan_digest = "sha256:supply-vuln",
        .build_provenance_identity = "builder:zigos/release",
        .reproducible_build = true,
        .trusted_builder = true,
    };
    const digest_a = package_digest.digestBundle(base_bundle);
    const digest_builder_b = package_digest.digestBundle(builder_b);
    const digest_sbom_b = package_digest.digestBundle(sbom_b);

    features[@intFromEnum(SeventhFeature.supply_chain_manifest)] = @hasField(manifest.BundleManifest, "supply_chain");
    features[@intFromEnum(SeventhFeature.sbom_digest_manifest)] = @hasField(manifest.SupplyChainDecl, "sbom_digest");
    features[@intFromEnum(SeventhFeature.source_archive_digest_manifest)] = @hasField(manifest.SupplyChainDecl, "source_archive_digest");
    features[@intFromEnum(SeventhFeature.build_recipe_digest_manifest)] = @hasField(manifest.SupplyChainDecl, "build_recipe_digest");
    features[@intFromEnum(SeventhFeature.vulnerability_scan_digest_manifest)] = @hasField(manifest.SupplyChainDecl, "vulnerability_scan_digest");
    features[@intFromEnum(SeventhFeature.builder_identity_manifest)] = @hasField(manifest.SupplyChainDecl, "build_provenance_identity");
    features[@intFromEnum(SeventhFeature.reproducible_build_validation)] = validationFailsWith(.{
        .bundle_id = "app.repro",
        .display_name = "Repro",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .reproducible_build = true,
            .build_recipe_digest = "sha256:recipe",
        },
    }, error.ReproducibleBuildRequiresSourceArchive);
    features[@intFromEnum(SeventhFeature.trusted_builder_validation)] = validationFailsWith(.{
        .bundle_id = "app.builder",
        .display_name = "Builder",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .trusted_builder = true,
        },
    }, error.TrustedBuilderRequiresIdentity);
    features[@intFromEnum(SeventhFeature.supply_chain_digest_covers_sbom)] = !std.mem.eql(u8, &digest_a, &digest_sbom_b);
    features[@intFromEnum(SeventhFeature.supply_chain_digest_covers_builder)] = !std.mem.eql(u8, &digest_a, &digest_builder_b);
    features[@intFromEnum(SeventhFeature.package_preserves_supply_chain)] = @hasField(package_model.BundleRevision, "supply_chain");
    features[@intFromEnum(SeventhFeature.package_resolves_supply_chain)] = @hasField(package_model.ResolvedManifest, "supply_chain");
    features[@intFromEnum(SeventhFeature.policy_package_sbom_gate)] = @hasField(policy_object.CreateRequest, "require_package_sbom");
    features[@intFromEnum(SeventhFeature.policy_package_reproducible_gate)] = @hasField(policy_object.CreateRequest, "require_reproducible_package_build");
    features[@intFromEnum(SeventhFeature.policy_package_builder_gate)] = @hasField(policy_object.CreateRequest, "require_trusted_package_builder");
    features[@intFromEnum(SeventhFeature.policy_vulnerability_scan_gate)] = @hasField(policy_object.CreateRequest, "require_vulnerability_scan");
    features[@intFromEnum(SeventhFeature.package_provenance_request)] = @hasField(policy_object.PackageProvenanceRequest, "reproducible_build");
    features[@intFromEnum(SeventhFeature.package_provenance_policy_decision)] = @hasDecl(policy_object.Directory, "packageProvenanceDecision");
    features[@intFromEnum(SeventhFeature.package_install_provenance_error)] = packageProvenanceInstallErrorPresent();
    features[@intFromEnum(SeventhFeature.install_source_policy_still_present)] = @hasField(policy_object.CreateRequest, "install_source_mode") and
        @hasDecl(policy_object.Directory, "installSourceDecision");
    features[@intFromEnum(SeventhFeature.package_active_revision_mutation_gate)] =
        packageActiveRevisionMutationGate() and
        @hasDecl(package_service, "RollbackRequest") and
        @hasDecl(package_service, "RemoveRequest") and
        @hasDecl(package_service, "activeRevisionDigest") and
        @hasField(typed_component_abi.PackageRollbackRequest, "expected_active_digest") and
        @hasField(typed_component_abi.PackageRemoveRequest, "expected_active_digest");

    return .{ .satisfied_features = features };
}

fn packageActiveRevisionMutationGate() bool {
    var service = package_service.Service.init();
    service.bind(7_700, .{ .kind = .service, .serial = 7_700 });
    const signer_identity = signing.SignerIdentity{
        .label = "package-active-revision-contract",
        .seed = signing.seedFromByte(0x77),
    };
    package_service.testingTrustPublisher(&service, signer_identity, "zigos.dev") catch return false;

    const actor = principal.PrincipalId{ .kind = .service, .serial = 7_701 };
    const task_id: u64 = 7_702;
    var capabilities = capability.CapabilityTable.init();
    const authority_capability = capabilities.mintBootRoot(.{
        .holder = actor,
        .issuer = .{ .kind = .policy_authority, .serial = 7_700 },
        .target = .{ .kind = .service, .id = service.service_id },
        .rights = .{ .service = .{ .endpoint_connect = true } },
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    }) catch return false;
    const authority = package_service.AuthorityContext{
        .task_id = task_id,
        .principal = actor,
        .capability_id = authority_capability.id,
        .now_ticks = 10,
    };
    var port = package_service.PackagePort.init(&service, &capabilities);

    var v1 = @import("../policy/manifest_fixtures.zig").notesBundle();
    v1.signature = signing.signWithDefaultRegistry(.ed25519, signer_identity, &package_service.digestBundle(v1)) catch return false;
    const installed = port.install(authority, .{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null) catch return false;
    if (!installed.installed_new) return false;

    const stale_rollback = package_service.rollbackRequestForActive(service.find("app.notes") orelse return false);
    var v2 = v1;
    v2.version_minor = 1;
    v2.signature = signing.signWithDefaultRegistry(.ed25519, signer_identity, &package_service.digestBundle(v2)) catch return false;
    const updated = port.install(authority, .{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null) catch return false;
    if (!updated.updated_existing or !updated.rollback_available) return false;

    const stale_rollback_denied = if (port.rollback(authority, stale_rollback)) |_| false else |err| err == error.PackageActiveRevisionMismatch;
    const stale_remove = package_service.removeRequestForActive(service.find("app.notes") orelse return false);
    const rolled_back = port.rollback(
        authority,
        package_service.rollbackRequestForActive(service.find("app.notes") orelse return false),
    ) catch return false;
    if (!rolled_back.updated_existing or service.find("app.notes").?.versionMinor() != 0) return false;

    const stale_remove_denied = if (port.remove(authority, stale_remove)) |_| false else |err| err == error.PackageActiveRevisionMismatch;
    const removed = port.remove(
        authority,
        package_service.removeRequestForActive(service.find("app.notes") orelse return false),
    ) catch return false;
    return stale_rollback_denied and
        stale_remove_denied and
        removed.removed_existing and
        service.find("app.notes") == null;
}

fn packageProvenanceInstallErrorPresent() bool {
    const package_provenance_error: package_service.Error = error.PackageProvenanceDenied;
    return package_provenance_error == error.PackageProvenanceDenied;
}

pub fn currentRepositoryEighthContract() EighthChecklist {
    var features = [_]bool{false} ** eighth_feature_count;
    const base_agent = manifest.BundleManifest{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes locally",
            .max_autonomous_actions = 4,
            .max_remote_calls = 0,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .local_context_only = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    };
    var purpose_b = base_agent;
    purpose_b.agent_delegation = .{
        .enabled = true,
        .purpose = "Summarize shared workspace",
        .max_autonomous_actions = 4,
        .max_remote_calls = 0,
        .user_confirmation_required = true,
        .audit_required = true,
        .session_bound = true,
        .local_context_only = true,
        .max_context_bytes = 4096,
        .kill_switch_supported = true,
    };
    const digest_a = package_digest.digestBundle(base_agent);
    const digest_b = package_digest.digestBundle(purpose_b);

    features[@intFromEnum(EighthFeature.agent_delegation_manifest)] = @hasField(manifest.BundleManifest, "agent_delegation") and @hasField(manifest.AgentDelegationDecl, "max_autonomous_actions");
    features[@intFromEnum(EighthFeature.agent_purpose_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .max_autonomous_actions = 4,
        },
    }, error.AgentDelegationPurposeMissing);
    features[@intFromEnum(EighthFeature.agent_action_budget_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes locally",
        },
    }, error.AgentDelegationActionBudgetMissing);
    features[@intFromEnum(EighthFeature.agent_remote_confirmation_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Summarize remote research",
            .max_autonomous_actions = 4,
            .max_remote_calls = 1,
            .user_confirmation_required = false,
        },
    }, error.AgentDelegationNeedsConfirmation);
    features[@intFromEnum(EighthFeature.agent_digest_covers_purpose)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(EighthFeature.package_preserves_agent_delegation)] = @hasField(package_model.BundleRevision, "agent_delegation");
    features[@intFromEnum(EighthFeature.package_resolves_agent_delegation)] = @hasField(package_model.ResolvedManifest, "agent_delegation");
    features[@intFromEnum(EighthFeature.policy_agent_allowed_gate)] = @hasField(policy_object.CreateRequest, "agent_delegation_allowed");
    features[@intFromEnum(EighthFeature.policy_agent_action_budget)] = @hasField(policy_object.CreateRequest, "max_agent_actions_per_session");
    features[@intFromEnum(EighthFeature.policy_agent_remote_budget)] = @hasField(policy_object.CreateRequest, "max_agent_remote_calls_per_session");
    features[@intFromEnum(EighthFeature.policy_agent_confirmation_gate)] = @hasField(policy_object.CreateRequest, "require_agent_user_confirmation");
    features[@intFromEnum(EighthFeature.policy_agent_audit_gate)] = @hasField(policy_object.CreateRequest, "require_agent_audit");
    features[@intFromEnum(EighthFeature.agent_delegation_request)] = @hasField(policy_object.AgentDelegationRequest, "autonomous_actions") and @hasField(policy_object.AgentDelegationRequest, "audit_enabled");
    features[@intFromEnum(EighthFeature.agent_delegation_policy_decision)] = @hasDecl(policy_object.Directory, "agentDelegationDecision");
    features[@intFromEnum(EighthFeature.typed_agent_delegation_service)] = contractPresent("zigos.agent.delegation");
    features[@intFromEnum(EighthFeature.agent_authorize_operation)] = contractOperationPresent("zigos.agent.delegation", .agent_authorize);
    features[@intFromEnum(EighthFeature.agent_record_action_operation)] = contractOperationPresent("zigos.agent.delegation", .agent_record_action);
    features[@intFromEnum(EighthFeature.agent_revoke_operation)] = contractOperationPresent("zigos.agent.delegation", .agent_revoke);
    features[@intFromEnum(EighthFeature.agent_delegation_ledger)] = event_ledger.EventKind.agent_delegation == .agent_delegation and @hasDecl(event_ledger.Ledger, "recordAgentDelegation");
    features[@intFromEnum(EighthFeature.agent_delegation_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "agent_delegation_events") and @hasField(event_ledger.DiagnosticSummary, "agent_remote_call_events");

    return .{ .satisfied_features = features };
}

pub fn currentRepositoryNinthContract() NinthChecklist {
    var features = [_]bool{false} ** ninth_feature_count;

    features[@intFromEnum(NinthFeature.attention_policy_create_request)] =
        @hasField(policy_object.CreateRequest, "quiet_until_tick") and
        @hasField(policy_object.CreateRequest, "max_visible_notifications") and
        @hasField(policy_object.CreateRequest, "max_interruptive_notifications") and
        @hasField(policy_object.CreateRequest, "allow_critical_interruption");
    features[@intFromEnum(NinthFeature.quiet_hours_policy)] = attentionPolicyDenies(.attention_quiet_denied);
    features[@intFromEnum(NinthFeature.visible_notification_budget_policy)] = attentionPolicyDenies(.attention_visible_budget_denied);
    features[@intFromEnum(NinthFeature.interruptive_notification_budget_policy)] = attentionPolicyDenies(.attention_interruption_budget_denied);
    features[@intFromEnum(NinthFeature.critical_interruption_policy)] = attentionPolicyDenies(.attention_critical_denied);
    features[@intFromEnum(NinthFeature.attention_policy_request)] = @hasField(policy_object.AttentionRequest, "requests_interruption") and
        @hasField(policy_object.AttentionRequest, "critical");
    features[@intFromEnum(NinthFeature.attention_policy_decision)] = @hasDecl(policy_object.Directory, "attentionDecision");
    features[@intFromEnum(NinthFeature.notification_center_attention_policy)] = @hasDecl(notification_center.Center, "postWithAttentionPolicy") and
        @hasDecl(notification_center.Center, "attentionDecision");
    features[@intFromEnum(NinthFeature.notification_center_quiet_mode)] = notificationQuietModeCheck();
    features[@intFromEnum(NinthFeature.notification_center_interruption_budget)] = notificationInterruptionBudgetCheck();
    features[@intFromEnum(NinthFeature.attention_policy_ledger)] = event_ledger.EventKind.attention_policy == .attention_policy and
        @hasDecl(event_ledger.Ledger, "recordAttentionDecision");
    features[@intFromEnum(NinthFeature.attention_policy_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "attention_policy_events") and
        @hasField(event_ledger.DiagnosticSummary, "attention_interruptions_denied");
    features[@intFromEnum(NinthFeature.attention_policy_redaction)] = attentionRedactionCheck();
    features[@intFromEnum(NinthFeature.policy_digest_covers_attention)] = attentionPolicyDigestCheck();
    features[@intFromEnum(NinthFeature.structured_urgency_classification)] = notification_center.isInterruptive(.high) and
        notification_center.isInterruptive(.critical) and
        !notification_center.isInterruptive(.normal);
    features[@intFromEnum(NinthFeature.suppression_replacement_preserved)] = @hasField(notification_center.PostRequest, "suppression_policy") and
        notification_center.SuppressionPolicy.replace_same_source_reason_task == .replace_same_source_reason_task;

    return .{ .satisfied_features = features };
}

fn attentionPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "attention-contract-policy",
        .seed = signing.seedFromByte(0xC9),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2026,
        .issuer = .{ .kind = .policy_authority, .serial = 2026 },
        .label = "attention-contract",
        .quiet_until_tick = 500,
        .max_visible_notifications = 2,
        .max_interruptive_notifications = 1,
        .allow_critical_interruption = false,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2026,
    };
    const request = switch (expected) {
        .attention_quiet_denied => policy_object.AttentionRequest{
            .now_tick = 300,
            .visible_notifications = 0,
            .requests_interruption = true,
        },
        .attention_visible_budget_denied => policy_object.AttentionRequest{
            .now_tick = 600,
            .visible_notifications = 2,
        },
        .attention_interruption_budget_denied => policy_object.AttentionRequest{
            .now_tick = 600,
            .visible_notifications = 1,
            .interruptive_notifications = 1,
            .requests_interruption = true,
        },
        .attention_critical_denied => policy_object.AttentionRequest{
            .now_tick = 600,
            .visible_notifications = 1,
            .requests_interruption = true,
            .critical = true,
        },
        else => return false,
    };
    const decision = directory.attentionDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn notificationQuietModeCheck() bool {
    var center = notification_center.Center.init();
    const result = center.postWithAttentionPolicy(.{
        .source = .{ .kind = .app, .serial = 2026 },
        .reason = .policy_notice,
        .urgency = .high,
        .detail = "attention contract quiet check",
    }, .{
        .quiet_until_ticks = 100,
    }, 10) catch return false;
    return !result.decision.allowed and result.decision.reason == .quiet_mode;
}

fn notificationInterruptionBudgetCheck() bool {
    var center = notification_center.Center.init();
    const source = principal.PrincipalId{ .kind = .app, .serial = 2027 };
    const first = center.postWithAttentionPolicy(.{
        .source = source,
        .reason = .driver_restart,
        .urgency = .high,
        .detail = "first interruption",
    }, .{
        .max_interruptions_per_window = 1,
    }, 10) catch return false;
    if (!first.decision.allowed) return false;
    const second = center.postWithAttentionPolicy(.{
        .source = source,
        .reason = .sync_conflict,
        .urgency = .high,
        .detail = "second interruption",
    }, .{
        .max_interruptions_per_window = 1,
    }, 11) catch return false;
    return !second.decision.allowed and second.decision.reason == .interruption_budget_exhausted;
}

fn attentionRedactionCheck() bool {
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordAttentionDecision(
        principal.PrincipalId{ .kind = .user, .serial = 2026 },
        2607,
        false,
        true,
        3,
        1,
        88,
        "private attention detail",
    ) catch return false;
    var buffer: [512]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return summary.attention_policy_events == 1 and
        summary.attention_interruptions_denied == 1 and
        summary.protected_details_redacted == 1 and
        std.mem.indexOf(u8, exported, "private attention detail") == null and
        std.mem.indexOf(u8, exported, "kind=attention_policy") != null;
}

fn attentionPolicyDigestCheck() bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "attention-digest-policy",
        .seed = signing.seedFromByte(0xCA),
    };
    const policy = directory.create(.{
        .scope = .organization,
        .subject_id = 2027,
        .issuer = .{ .kind = .policy_authority, .serial = 2027 },
        .label = "attention-digest",
        .quiet_until_tick = 200,
        .max_visible_notifications = 4,
        .max_interruptive_notifications = 1,
        .allow_critical_interruption = true,
    }, signer) catch return false;
    if (!directory.verify(policy.id)) return false;
    policy.max_visible_notifications += 1;
    return !directory.verify(policy.id);
}

pub fn currentRepositoryTenthContract() TenthChecklist {
    var features = [_]bool{false} ** tenth_feature_count;
    const accessible_reader = manifest.BundleManifest{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_screen_reader = true,
            .supports_keyboard_navigation = true,
            .supports_reduced_motion = true,
            .supports_high_contrast = true,
            .profile_notes = "honors user accessibility profile",
        },
    };
    var accessible_reader_v2 = accessible_reader;
    accessible_reader_v2.accessibility = .{
        .adaptive_ui = true,
        .supports_screen_reader = true,
        .supports_keyboard_navigation = true,
        .supports_reduced_motion = true,
        .supports_high_contrast = false,
        .profile_notes = "honors user accessibility profile",
    };
    const digest_a = package_digest.digestBundle(accessible_reader);
    const digest_b = package_digest.digestBundle(accessible_reader_v2);
    const shell_profile = humane_shell.AccessibilityProfile{};

    features[@intFromEnum(TenthFeature.accessibility_manifest)] = @hasField(manifest.BundleManifest, "accessibility") and
        @hasField(manifest.AccessibilityDecl, "supports_reduced_motion");
    features[@intFromEnum(TenthFeature.accessibility_profile_validation)] = validationFailsWith(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_keyboard_navigation = true,
            .supports_screen_reader = true,
        },
    }, error.AccessibilityReducedMotionMissing);
    features[@intFromEnum(TenthFeature.accessibility_keyboard_validation)] = validationFailsWith(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_screen_reader = true,
            .supports_reduced_motion = true,
        },
    }, error.AccessibilityKeyboardNavigationMissing);
    features[@intFromEnum(TenthFeature.accessibility_digest_covers_profile)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(TenthFeature.package_preserves_accessibility)] = @hasField(package_model.BundleRevision, "accessibility");
    features[@intFromEnum(TenthFeature.package_resolves_accessibility)] = @hasField(package_model.ResolvedManifest, "accessibility") and
        @hasField(package_model.StoredAccessibility, "supports_keyboard_navigation");
    features[@intFromEnum(TenthFeature.policy_adaptive_ui_gate)] = accessibilityPolicyDenies(.accessibility_adaptive_ui_denied);
    features[@intFromEnum(TenthFeature.policy_screen_reader_gate)] = accessibilityPolicyDenies(.accessibility_screen_reader_denied);
    features[@intFromEnum(TenthFeature.policy_keyboard_navigation_gate)] = accessibilityPolicyDenies(.accessibility_keyboard_navigation_denied);
    features[@intFromEnum(TenthFeature.policy_reduced_motion_gate)] = accessibilityPolicyDenies(.accessibility_reduced_motion_denied);
    features[@intFromEnum(TenthFeature.policy_high_contrast_gate)] = accessibilityPolicyDenies(.accessibility_high_contrast_denied);
    features[@intFromEnum(TenthFeature.accessibility_policy_request)] = @hasField(policy_object.AccessibilityRequest, "reduced_motion_supported") and
        @hasDecl(policy_object.Directory, "accessibilityDecision");
    features[@intFromEnum(TenthFeature.typed_accessibility_profile_service)] = contractPresent("zigos.accessibility.profile");
    features[@intFromEnum(TenthFeature.accessibility_profile_get_operation)] = contractOperationPresent("zigos.accessibility.profile", .accessibility_profile_get);
    features[@intFromEnum(TenthFeature.accessibility_profile_apply_operation)] = contractOperationPresent("zigos.accessibility.profile", .accessibility_profile_apply);
    features[@intFromEnum(TenthFeature.native_registry_accessibility_discovery)] =
        typed_component_abi.interfaceId(.accessibility_profile) == .accessibility_profile;
    features[@intFromEnum(TenthFeature.accessibility_profile_ledger)] = event_ledger.EventKind.accessibility_profile == .accessibility_profile and
        @hasDecl(event_ledger.Ledger, "recordAccessibilityProfile");
    features[@intFromEnum(TenthFeature.accessibility_profile_diagnostics)] = @hasField(event_ledger.DiagnosticSummary, "accessibility_profile_events") and
        @hasField(event_ledger.DiagnosticSummary, "accessibility_denials");
    features[@intFromEnum(TenthFeature.accessibility_redaction)] = accessibilityRedactionCheck();
    features[@intFromEnum(TenthFeature.rendered_shell_accessibility_profile)] =
        @hasField(humane_shell.AccessibilityProfile, "keyboard_navigation") and
        @hasField(humane_shell.AccessibilityProfile, "screen_reader_labels") and
        @hasField(humane_shell.AccessibilityProfile, "visible_focus") and
        shell_profile.keyboard_navigation and
        shell_profile.screen_reader_labels and
        shell_profile.reduce_motion;

    return .{ .satisfied_features = features };
}

fn accessibilityPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "accessibility-contract-policy",
        .seed = signing.seedFromByte(0xCB),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2028,
        .issuer = .{ .kind = .policy_authority, .serial = 2028 },
        .label = "accessibility-contract",
        .require_adaptive_ui = true,
        .require_screen_reader_support = true,
        .require_keyboard_navigation = true,
        .require_reduced_motion_support = true,
        .require_high_contrast_support = true,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2028,
    };
    const request = switch (expected) {
        .accessibility_adaptive_ui_denied => policy_object.AccessibilityRequest{
            .screen_reader_supported = true,
            .keyboard_navigation = true,
            .reduced_motion_supported = true,
            .high_contrast_supported = true,
        },
        .accessibility_screen_reader_denied => policy_object.AccessibilityRequest{
            .adaptive_ui = true,
            .keyboard_navigation = true,
            .reduced_motion_supported = true,
            .high_contrast_supported = true,
        },
        .accessibility_keyboard_navigation_denied => policy_object.AccessibilityRequest{
            .adaptive_ui = true,
            .screen_reader_supported = true,
            .reduced_motion_supported = true,
            .high_contrast_supported = true,
        },
        .accessibility_reduced_motion_denied => policy_object.AccessibilityRequest{
            .adaptive_ui = true,
            .screen_reader_supported = true,
            .keyboard_navigation = true,
            .high_contrast_supported = true,
        },
        .accessibility_high_contrast_denied => policy_object.AccessibilityRequest{
            .adaptive_ui = true,
            .screen_reader_supported = true,
            .keyboard_navigation = true,
            .reduced_motion_supported = true,
        },
        else => return false,
    };
    const decision = directory.accessibilityDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn accessibilityRedactionCheck() bool {
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordAccessibilityProfile(
        principal.PrincipalId{ .kind = .user, .serial = 2028 },
        2807,
        false,
        true,
        false,
        true,
        true,
        89,
        "private accessibility profile detail",
    ) catch return false;
    var buffer: [512]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return summary.accessibility_profile_events == 1 and
        summary.accessibility_denials == 1 and
        summary.protected_details_redacted == 1 and
        std.mem.indexOf(u8, exported, "private accessibility profile detail") == null and
        std.mem.indexOf(u8, exported, "kind=accessibility_profile") != null;
}

pub fn currentRepositoryEleventhContract() EleventhChecklist {
    var features = [_]bool{false} ** eleventh_feature_count;
    const session_bound_agent = manifest.BundleManifest{
        .bundle_id = "app.agent-session",
        .display_name = "Agent Session",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes inside the active session",
            .max_autonomous_actions = 4,
            .max_remote_calls = 0,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .local_context_only = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    };
    var larger_context_agent = session_bound_agent;
    larger_context_agent.agent_delegation = .{
        .enabled = true,
        .purpose = "Organize private notes inside the active session",
        .max_autonomous_actions = 4,
        .max_remote_calls = 0,
        .user_confirmation_required = true,
        .audit_required = true,
        .session_bound = true,
        .local_context_only = true,
        .max_context_bytes = 8192,
        .kill_switch_supported = true,
    };
    const digest_a = package_digest.digestBundle(session_bound_agent);
    const digest_b = package_digest.digestBundle(larger_context_agent);

    features[@intFromEnum(EleventhFeature.agent_manifest_session_binding)] =
        @hasField(manifest.AgentDelegationDecl, "session_bound");
    features[@intFromEnum(EleventhFeature.agent_manifest_local_context)] =
        @hasField(manifest.AgentDelegationDecl, "local_context_only");
    features[@intFromEnum(EleventhFeature.agent_manifest_context_budget)] =
        @hasField(manifest.AgentDelegationDecl, "max_context_bytes");
    features[@intFromEnum(EleventhFeature.agent_manifest_kill_switch)] =
        @hasField(manifest.AgentDelegationDecl, "kill_switch_supported");
    features[@intFromEnum(EleventhFeature.agent_session_binding_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent-session",
        .display_name = "Agent Session",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes inside the active session",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    }, error.AgentDelegationSessionBindingRequired);
    features[@intFromEnum(EleventhFeature.agent_context_budget_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent-session",
        .display_name = "Agent Session",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes inside the active session",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .kill_switch_supported = true,
        },
    }, error.AgentDelegationContextBudgetMissing);
    features[@intFromEnum(EleventhFeature.agent_kill_switch_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent-session",
        .display_name = "Agent Session",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes inside the active session",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .max_context_bytes = 4096,
        },
    }, error.AgentDelegationKillSwitchRequired);
    features[@intFromEnum(EleventhFeature.agent_digest_covers_session_scope)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(EleventhFeature.package_preserves_agent_session_scope)] =
        @hasField(package_model.StoredAgentDelegation, "session_bound") and
        @hasField(package_model.StoredAgentDelegation, "local_context_only") and
        @hasField(package_model.StoredAgentDelegation, "max_context_bytes") and
        @hasField(package_model.StoredAgentDelegation, "kill_switch_supported");
    features[@intFromEnum(EleventhFeature.package_resolves_agent_session_scope)] =
        @hasField(package_model.ResolvedManifest, "agent_delegation") and
        @hasField(manifest.AgentDelegationDecl, "kill_switch_supported");
    features[@intFromEnum(EleventhFeature.policy_agent_session_binding_gate)] = agentSessionPolicyDenies(.agent_session_binding_denied);
    features[@intFromEnum(EleventhFeature.policy_agent_local_context_gate)] = agentSessionPolicyDenies(.agent_context_scope_denied);
    features[@intFromEnum(EleventhFeature.policy_agent_context_budget_gate)] = agentSessionPolicyDenies(.agent_context_budget_denied);
    features[@intFromEnum(EleventhFeature.policy_agent_kill_switch_gate)] = agentSessionPolicyDenies(.agent_kill_switch_denied);
    features[@intFromEnum(EleventhFeature.policy_agent_visible_plan_gate)] = agentSessionPolicyDenies(.agent_plan_visibility_required);
    features[@intFromEnum(EleventhFeature.agent_session_policy_request)] =
        @hasField(policy_object.AgentDelegationRequest, "session_bound") and
        @hasField(policy_object.AgentDelegationRequest, "local_context_only") and
        @hasField(policy_object.AgentDelegationRequest, "context_bytes") and
        @hasField(policy_object.AgentDelegationRequest, "delegation_generation") and
        @hasField(policy_object.AgentDelegationRequest, "user_visible_plan");
    features[@intFromEnum(EleventhFeature.typed_agent_session_bind_operation)] =
        contractOperationPresent("zigos.agent.delegation", .agent_bind_session);
    features[@intFromEnum(EleventhFeature.typed_agent_kill_switch_operation)] =
        contractOperationPresent("zigos.agent.delegation", .agent_kill_switch);
    features[@intFromEnum(EleventhFeature.agent_session_service_model)] =
        @hasDecl(agent_delegation_service.Service, "authorize") and
        @hasDecl(agent_delegation_service.Service, "recordAction") and
        @hasField(agent_delegation_service.AuthorizeRequest, "session_id") and
        @hasField(agent_delegation_service.RecordActionRequest, "subject") and
        @hasField(agent_delegation_service.RecordActionRequest, "task_id") and
        @hasField(agent_delegation_service.RecordActionRequest, "expected_generation");
    features[@intFromEnum(EleventhFeature.agent_action_binding_gate)] =
        agentActionBindingCheck() and
        @hasField(typed_component_abi.AgentRecordActionRequest, "expected_subject_serial") and
        @hasField(typed_component_abi.AgentRecordActionRequest, "expected_subject_kind") and
        @hasField(typed_component_abi.AgentRecordActionRequest, "expected_task_id") and
        @hasField(typed_component_abi.AgentRecordActionRequest, "expected_generation");
    features[@intFromEnum(EleventhFeature.agent_session_service_kill_switch)] =
        @hasDecl(agent_delegation_service.Service, "killSwitch") and
        @hasField(agent_delegation_service.Service, "minimum_generation");
    features[@intFromEnum(EleventhFeature.agent_session_cumulative_context_budget)] = agentCumulativeContextBudgetCheck();
    features[@intFromEnum(EleventhFeature.agent_action_denial_audit)] = agentActionDenialAuditCheck();
    features[@intFromEnum(EleventhFeature.agent_session_ledger)] =
        event_ledger.EventKind.agent_session == .agent_session and
        @hasDecl(event_ledger.Ledger, "recordAgentSessionBoundary");
    features[@intFromEnum(EleventhFeature.agent_session_redaction)] = agentSessionRedactionCheck();

    return .{ .satisfied_features = features };
}

fn agentSessionPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "agent-session-contract-policy",
        .seed = signing.seedFromByte(0xCC),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2029,
        .issuer = .{ .kind = .policy_authority, .serial = 2029 },
        .label = "agent-session-contract",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 8,
        .max_agent_remote_calls_per_session = 1,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 4096,
        .min_agent_delegation_generation = 3,
        .require_agent_visible_plan = true,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2029,
    };
    const request = switch (expected) {
        .agent_session_binding_denied => policy_object.AgentDelegationRequest{
            .enabled = true,
            .autonomous_actions = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .local_context_only = true,
            .context_bytes = 1024,
            .delegation_generation = 3,
            .user_visible_plan = true,
        },
        .agent_context_scope_denied => policy_object.AgentDelegationRequest{
            .enabled = true,
            .autonomous_actions = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .session_bound = true,
            .local_context_only = false,
            .context_bytes = 1024,
            .delegation_generation = 3,
            .user_visible_plan = true,
        },
        .agent_context_budget_denied => policy_object.AgentDelegationRequest{
            .enabled = true,
            .autonomous_actions = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .session_bound = true,
            .local_context_only = true,
            .context_bytes = 8192,
            .delegation_generation = 3,
            .user_visible_plan = true,
        },
        .agent_kill_switch_denied => policy_object.AgentDelegationRequest{
            .enabled = true,
            .autonomous_actions = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .session_bound = true,
            .local_context_only = true,
            .context_bytes = 1024,
            .delegation_generation = 2,
            .user_visible_plan = true,
        },
        .agent_plan_visibility_required => policy_object.AgentDelegationRequest{
            .enabled = true,
            .autonomous_actions = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .session_bound = true,
            .local_context_only = true,
            .context_bytes = 1024,
            .delegation_generation = 3,
        },
        else => return false,
    };
    const decision = directory.agentDelegationDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn agentSessionRedactionCheck() bool {
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordAgentSessionBoundary(
        principal.PrincipalId{ .kind = .user, .serial = 2029 },
        2907,
        false,
        true,
        true,
        true,
        2,
        90,
        "private agent session context",
    ) catch return false;
    var buffer: [512]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return summary.agent_session_events == 1 and
        summary.agent_session_denials == 1 and
        summary.agent_kill_switch_denials == 1 and
        summary.protected_details_redacted == 1 and
        std.mem.indexOf(u8, exported, "private agent session context") == null and
        std.mem.indexOf(u8, exported, "kind=agent_session") != null;
}

fn agentCumulativeContextBudgetCheck() bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "agent-context-budget-contract",
        .seed = signing.seedFromByte(0xCE),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2033,
        .issuer = .{ .kind = .policy_authority, .serial = 2033 },
        .label = "agent-context-cumulative",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 4,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 1024,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, signer) catch return false;

    var service = agent_delegation_service.Service.init();
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2033 };
    const delegation = service.authorize(&directory, .{ .organization_id = 2033 }, .{
        .subject = subject,
        .task_id = 2034,
        .session_id = 2035,
        .autonomous_actions = 4,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 1024,
        .delegation_generation = 1,
        .user_visible_plan = true,
    }, null) catch return false;

    _ = service.recordAction(.{
        .subject = subject,
        .task_id = 2034,
        .delegation_id = delegation.id,
        .session_id = 2035,
        .expected_generation = 1,
        .action_count = 1,
        .context_bytes = 700,
    }, null) catch return false;
    if (delegation.remainingContextBytes() != 324) return false;
    if (service.recordAction(.{
        .subject = subject,
        .task_id = 2034,
        .delegation_id = delegation.id,
        .session_id = 2035,
        .expected_generation = 1,
        .action_count = 1,
        .context_bytes = 400,
    }, null)) |_| return false else |err| {
        if (err != error.ContextBudgetExceeded) return false;
    }
    return delegation.used_context_bytes == 700;
}

fn agentActionBindingCheck() bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "agent-action-binding-contract",
        .seed = signing.seedFromByte(0xC7),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2034,
        .issuer = .{ .kind = .policy_authority, .serial = 2034 },
        .label = "agent-action-binding",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 2,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 512,
        .min_agent_delegation_generation = 2,
        .require_agent_visible_plan = true,
    }, signer) catch return false;

    var service = agent_delegation_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2034 };
    const delegation = service.authorize(&directory, .{ .organization_id = 2034 }, .{
        .subject = subject,
        .task_id = 2035,
        .session_id = 2036,
        .autonomous_actions = 2,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 2,
        .user_visible_plan = true,
        .detail = "private binding authorization",
    }, &ledger) catch return false;

    const wrong_subject_denied = if (service.recordAction(.{
        .subject = .{ .kind = .app, .serial = 2037 },
        .task_id = 2035,
        .delegation_id = delegation.id,
        .session_id = 2036,
        .expected_generation = 2,
        .action_count = 1,
        .detail = "private wrong subject action",
    }, &ledger)) |_| false else |err| err == error.DelegationBindingMismatch;
    const wrong_generation_denied = if (service.recordAction(.{
        .subject = subject,
        .task_id = 2035,
        .delegation_id = delegation.id,
        .session_id = 2036,
        .expected_generation = 1,
        .action_count = 1,
        .detail = "private wrong generation action",
    }, &ledger)) |_| false else |err| err == error.DelegationBindingMismatch;
    if (delegation.used_actions != 0) return false;

    const accepted = service.recordAction(.{
        .subject = subject,
        .task_id = 2035,
        .delegation_id = delegation.id,
        .session_id = 2036,
        .expected_generation = 2,
        .action_count = 1,
        .detail = "private bound action",
    }, &ledger) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return wrong_subject_denied and
        wrong_generation_denied and
        accepted.used_actions == 1 and
        summary.agent_session_events == 3 and
        summary.agent_session_denials == 2;
}

fn agentActionDenialAuditCheck() bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "agent-denial-audit-contract",
        .seed = signing.seedFromByte(0xCF),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2036,
        .issuer = .{ .kind = .policy_authority, .serial = 2036 },
        .label = "agent-denial-audit",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 1,
        .max_agent_remote_calls_per_session = 0,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 512,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, signer) catch return false;

    var service = agent_delegation_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2036 };
    const delegation = service.authorize(&directory, .{ .organization_id = 2036 }, .{
        .subject = subject,
        .task_id = 2037,
        .session_id = 2038,
        .autonomous_actions = 1,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 1,
        .user_visible_plan = true,
        .detail = "private contract authorization",
    }, &ledger) catch return false;

    if (service.recordAction(.{
        .subject = subject,
        .task_id = 2037,
        .delegation_id = delegation.id,
        .session_id = 2038,
        .expected_generation = 1,
        .action_count = 2,
        .detail = "private action overrun",
    }, &ledger)) |_| return false else |err| {
        if (err != error.ActionBudgetExceeded) return false;
    }
    if (service.recordAction(.{
        .subject = subject,
        .task_id = 2037,
        .delegation_id = delegation.id,
        .session_id = 2038,
        .expected_generation = 1,
        .remote_call_count = 1,
        .detail = "private remote overrun",
    }, &ledger)) |_| return false else |err| {
        if (err != error.RemoteCallBudgetExceeded) return false;
    }
    if (service.recordAction(.{
        .subject = subject,
        .task_id = 2037,
        .delegation_id = delegation.id,
        .session_id = 2039,
        .expected_generation = 1,
        .detail = "private session mismatch",
    }, &ledger)) |_| return false else |err| {
        if (err != error.SessionMismatch) return false;
    }

    const summary = ledger.userVisibleDiagnosticSummary();
    var buffer: [1024]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return false;
    return summary.agent_delegation_events == 3 and
        summary.agent_delegation_denials == 2 and
        summary.agent_remote_call_events == 1 and
        summary.agent_session_events == 2 and
        summary.agent_session_denials == 1 and
        std.mem.indexOf(u8, exported, "private action overrun") == null and
        std.mem.indexOf(u8, exported, "private session mismatch") == null;
}

pub fn currentRepositoryTwelfthContract() TwelfthChecklist {
    var features = [_]bool{false} ** twelfth_feature_count;
    const background_permission = manifest.PermissionRequest{
        .kind = .background_execution,
        .resource = "sync",
        .rights = .{ .task = .{ .background_run = true } },
    };
    const background_permissions = [_]manifest.PermissionRequest{background_permission};
    const background_tasks = [_]manifest.BackgroundTaskDecl{.{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(64),
            .shared_memory_bytes = units.kibibytes(4),
        },
        .network = .local_network_only,
        .visibility = .status_only,
    }};
    const background_bundle = manifest.BundleManifest{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = &background_permissions,
        .background_tasks = &background_tasks,
    };
    const background_tasks_b = [_]manifest.BackgroundTaskDecl{.{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = units.kibibytes(64),
            .shared_memory_bytes = units.kibibytes(4),
        },
        .network = .local_network_only,
        .visibility = .status_only,
    }};
    const background_bundle_b = manifest.BundleManifest{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = &background_permissions,
        .background_tasks = &background_tasks_b,
    };
    const digest_a = package_digest.digestBundle(background_bundle);
    const digest_b = package_digest.digestBundle(background_bundle_b);

    features[@intFromEnum(TwelfthFeature.background_manifest_decl)] =
        @hasField(manifest.BundleManifest, "background_tasks") and
        @hasField(manifest.BackgroundTaskDecl, "budget") and
        @hasField(manifest.BackgroundTaskDecl, "visibility");
    features[@intFromEnum(TwelfthFeature.background_permission_pairing)] = validationFailsWith(.{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .background_tasks = &background_tasks,
    }, error.MissingBackgroundPermission);
    features[@intFromEnum(TwelfthFeature.background_budget_validation)] = validationFailsWith(.{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = &background_permissions,
        .background_tasks = &.{.{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .network = .local_network_only,
            .visibility = .status_only,
        }},
    }, error.BackgroundTaskBudgetMissing);
    features[@intFromEnum(TwelfthFeature.background_network_visibility_validation)] = backgroundNetworkVisibilityValidation(&background_permissions);
    features[@intFromEnum(TwelfthFeature.background_digest_covers_budget)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(TwelfthFeature.package_preserves_background_tasks)] =
        @hasField(package_model.BundleRevision, "background_tasks") and
        @hasField(package_model.StoredBackgroundTask, "budget") and
        @hasField(package_model.ResolvedManifest, "background_tasks");
    features[@intFromEnum(TwelfthFeature.policy_background_duration_gate)] = backgroundPolicyDenies(.background_duration_denied);
    features[@intFromEnum(TwelfthFeature.policy_background_cpu_gate)] = backgroundPolicyDenies(.background_cpu_denied);
    features[@intFromEnum(TwelfthFeature.policy_background_memory_gate)] = backgroundPolicyDenies(.background_memory_denied);
    features[@intFromEnum(TwelfthFeature.policy_background_network_gate)] = backgroundPolicyDenies(.background_network_denied);
    features[@intFromEnum(TwelfthFeature.policy_background_visibility_gate)] = backgroundPolicyDenies(.background_visibility_denied);
    features[@intFromEnum(TwelfthFeature.background_activity_policy_request)] =
        @hasField(policy_object.BackgroundActivityRequest, "expected_duration_seconds") and
        @hasDecl(policy_object.Directory, "backgroundActivityDecision");
    features[@intFromEnum(TwelfthFeature.typed_background_activity_service)] = contractPresent("zigos.background.activity");
    features[@intFromEnum(TwelfthFeature.background_authorize_operation)] = contractOperationPresent("zigos.background.activity", .background_authorize);
    features[@intFromEnum(TwelfthFeature.background_record_operation)] = contractOperationPresent("zigos.background.activity", .background_record);
    features[@intFromEnum(TwelfthFeature.background_complete_operation)] = contractOperationPresent("zigos.background.activity", .background_complete);
    features[@intFromEnum(TwelfthFeature.background_completion_binding_gate)] =
        backgroundCompletionBindingCheck(background_bundle) and
        @hasDecl(background_dispatch, "CompleteRequest") and
        @hasField(background_dispatch.CompleteRequest, "expected_task_id") and
        @hasField(background_dispatch.CompleteRequest, "expected_background_task_id") and
        @hasField(background_dispatch.CompleteRequest, "expected_trigger") and
        @hasField(typed_component_abi.BackgroundCompleteRequest, "expected_task_id") and
        @hasField(typed_component_abi.BackgroundCompleteRequest, "expected_background_task_len") and
        @hasField(typed_component_abi.BackgroundCompleteRequest, "expected_trigger") and
        @hasField(typed_component_abi.BackgroundCompleteRequest, "completed_tick");
    features[@intFromEnum(TwelfthFeature.native_registry_background_discovery)] =
        typed_component_abi.interfaceId(.background_activity) == .background_activity;
    features[@intFromEnum(TwelfthFeature.background_dispatch_runtime_gate)] = backgroundDispatchRuntimeCheck(background_bundle);
    features[@intFromEnum(TwelfthFeature.background_expiration_watchdog)] = backgroundExpirationWatchdogCheck(background_bundle);
    features[@intFromEnum(TwelfthFeature.background_activity_ledger)] =
        event_ledger.EventKind.background_activity == .background_activity and
        @hasDecl(event_ledger.Ledger, "recordBackgroundActivity");
    features[@intFromEnum(TwelfthFeature.background_activity_redaction)] = backgroundActivityRedactionCheck();

    return .{ .satisfied_features = features };
}

fn backgroundNetworkVisibilityValidation(background_permissions: []const manifest.PermissionRequest) bool {
    const no_network_tasks = [_]manifest.BackgroundTaskDecl{.{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = units.kibibytes(64) },
        .visibility = .status_only,
    }};
    const no_visibility_tasks = [_]manifest.BackgroundTaskDecl{.{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = units.kibibytes(64) },
        .network = .local_network_only,
    }};
    return validationFailsWith(.{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = background_permissions,
        .background_tasks = &no_network_tasks,
    }, error.BackgroundTaskNetworkMissing) and validationFailsWith(.{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = background_permissions,
        .background_tasks = &no_visibility_tasks,
    }, error.BackgroundTaskVisibilityMissing);
}

fn backgroundPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "background-contract-policy",
        .seed = signing.seedFromByte(0xCD),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2030,
        .issuer = .{ .kind = .policy_authority, .serial = 2030 },
        .label = "background-contract",
        .max_background_duration_seconds = 30,
        .max_background_cpu_time_ticks = 1_000,
        .max_background_memory_bytes = units.kibibytes(64),
        .max_background_shared_memory_bytes = units.kibibytes(8),
        .allow_remote_background_network = false,
        .require_visible_background_activity = true,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2030,
    };
    const request = switch (expected) {
        .background_duration_denied => policy_object.BackgroundActivityRequest{
            .expected_duration_seconds = 31,
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(32),
            .network = .none,
            .visibility = .status_only,
        },
        .background_cpu_denied => policy_object.BackgroundActivityRequest{
            .expected_duration_seconds = 20,
            .cpu_time_ticks = 1_001,
            .memory_bytes = units.kibibytes(32),
            .network = .none,
            .visibility = .status_only,
        },
        .background_memory_denied => policy_object.BackgroundActivityRequest{
            .expected_duration_seconds = 20,
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(65),
            .network = .none,
            .visibility = .status_only,
        },
        .background_network_denied => policy_object.BackgroundActivityRequest{
            .expected_duration_seconds = 20,
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(32),
            .network = .named_domains,
            .visibility = .status_only,
        },
        .background_visibility_denied => policy_object.BackgroundActivityRequest{
            .expected_duration_seconds = 20,
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(32),
            .network = .none,
            .visibility = .hidden,
        },
        else => return false,
    };
    const decision = directory.backgroundActivityDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn backgroundDispatchRuntimeCheck(bundle: manifest.BundleManifest) bool {
    var runtime = task_runtime.Runtime.init();
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2030 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = units.mebibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(64),
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = "app.background-contract",
        },
    }) catch return false;
    var controller = background_dispatch.Controller.init();
    var directory = policy_object.Directory.init();
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2030,
        .issuer = .{ .kind = .policy_authority, .serial = 2030 },
        .label = "background-dispatch-runtime",
        .max_background_duration_seconds = 30,
        .max_background_cpu_time_ticks = 1_000,
        .max_background_memory_bytes = units.kibibytes(64),
        .max_background_shared_memory_bytes = units.kibibytes(8),
        .allow_remote_background_network = false,
        .require_visible_background_activity = true,
    }, .{
        .label = "background-dispatch-policy",
        .seed = signing.seedFromByte(0xD2),
    }) catch return false;
    controller.configurePolicy(&directory, .{ .organization_id = 2030 });
    const decision = controller.dispatch(&runtime, task.id, bundle, "sync", .sync_completion, 3030) catch return false;
    if (!(decision.allowed and
        decision.reason == .allowed and
        decision.record_id != null and
        controller.activeRecordCount() == 1))
    {
        return false;
    }

    const remote_permission = manifest.PermissionRequest{
        .kind = .background_execution,
        .resource = "remote",
        .rights = .{ .task = .{ .background_run = true } },
    };
    const remote_permissions = [_]manifest.PermissionRequest{remote_permission};
    const remote_tasks = [_]manifest.BackgroundTaskDecl{.{
        .id = "remote",
        .trigger = .push_event,
        .expected_duration_seconds = 20,
        .budget = .{
            .cpu_time_ticks = 500,
            .memory_bytes = units.kibibytes(32),
            .shared_memory_bytes = units.kibibytes(4),
        },
        .network = .named_domains,
        .visibility = .status_only,
    }};
    const remote_bundle = manifest.BundleManifest{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .requested_permissions = &remote_permissions,
        .background_tasks = &remote_tasks,
    };
    const denied = controller.dispatch(&runtime, task.id, remote_bundle, "remote", .push_event, 3031) catch return false;
    return denied.reason == .policy_denied and
        denied.policy_reason == .background_network_denied;
}

fn backgroundCompletionBindingCheck(bundle: manifest.BundleManifest) bool {
    var runtime = task_runtime.Runtime.init();
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2032 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = units.mebibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(64),
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = "app.background-contract",
        },
    }) catch return false;
    var controller = background_dispatch.Controller.init();
    const decision = controller.dispatch(&runtime, task.id, bundle, "sync", .sync_completion, 200) catch return false;
    if (!(decision.allowed and
        decision.record_id != null and
        task.background_active_count == 1 and
        task.background_reserved_memory_bytes != 0))
    {
        return false;
    }

    const mismatched = controller.complete(&runtime, .{
        .record_id = decision.record_id.?,
        .expected_task_id = task.id + 1,
        .expected_background_task_id = "sync",
        .expected_trigger = .sync_completion,
        .tick = 201,
    });
    if (mismatched) |_| {
        return false;
    } else |err| {
        if (err != error.DispatchRecordBindingMismatch) return false;
    }
    if (task.background_active_count != 1 or task.background_reserved_memory_bytes == 0) return false;

    const completed = controller.complete(&runtime, .{
        .record_id = decision.record_id.?,
        .expected_task_id = task.id,
        .expected_background_task_id = "sync",
        .expected_trigger = .sync_completion,
        .tick = 202,
    }) catch return false;
    const latest = controller.latestRecord() orelse return false;
    return completed and
        task.background_active_count == 0 and
        task.background_reserved_memory_bytes == 0 and
        latest.state == .completed and
        latest.completed_tick == 202;
}

fn backgroundExpirationWatchdogCheck(bundle: manifest.BundleManifest) bool {
    var runtime = task_runtime.Runtime.init();
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2031 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = units.mebibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(64),
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = "app.background-contract",
        },
    }) catch return false;
    var controller = background_dispatch.Controller.init();
    const decision = controller.dispatch(&runtime, task.id, bundle, "sync", .sync_completion, 100) catch return false;
    if (!(decision.allowed and
        decision.record_id != null and
        task.background_active_count == 1 and
        task.background_reserved_memory_bytes != 0))
    {
        return false;
    }
    const early_expired = controller.expireOverdue(&runtime, 129) catch return false;
    if (early_expired != 0 or task.background_active_count != 1) return false;
    const expired = controller.expireOverdue(&runtime, 130) catch return false;
    const latest = controller.latestRecord() orelse return false;
    return expired == 1 and
        controller.activeRecordCount() == 0 and
        task.background_active_count == 0 and
        task.background_reserved_memory_bytes == 0 and
        latest.state == .expired and
        latest.reason == .expired and
        latest.completed_tick == 130 and
        task.latestAuditEvent().?.kind == .background_expired;
}

fn backgroundActivityRedactionCheck() bool {
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordBackgroundActivity(
        principal.PrincipalId{ .kind = .user, .serial = 2030 },
        3030,
        false,
        true,
        false,
        120,
        91,
        "private background activity detail",
    ) catch return false;
    var buffer: [512]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return summary.background_activity_events == 1 and
        summary.background_activity_denials == 1 and
        summary.protected_details_redacted == 1 and
        std.mem.indexOf(u8, exported, "private background activity detail") == null and
        std.mem.indexOf(u8, exported, "kind=background_activity") != null;
}

const PasteboardContractEvidence = struct {
    foreground_gesture_gate: bool = false,
    destination_bound_grant: bool = false,
    destination_principal_bound_grant: bool = false,
    strict_expiry_gate: bool = false,
    read_once_token: bool = false,
    revocation_gate: bool = false,
    user_visible_audit: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryThirteenthContract() ThirteenthChecklist {
    var features = [_]bool{false} ** thirteenth_feature_count;
    const evidence = securePasteboardContractEvidence();
    features[@intFromEnum(ThirteenthFeature.secure_pasteboard_service_model)] =
        @hasDecl(secure_pasteboard.Service, "offer") and
        @hasDecl(secure_pasteboard.Service, "read") and
        @hasDecl(secure_pasteboard.Service, "revoke") and
        @hasField(secure_pasteboard.Grant, "foreground_session_id") and
        @hasField(secure_pasteboard.Grant, "destination") and
        @hasField(secure_pasteboard.Grant, "read_once");
    features[@intFromEnum(ThirteenthFeature.pasteboard_foreground_gesture_gate)] = evidence.foreground_gesture_gate;
    features[@intFromEnum(ThirteenthFeature.pasteboard_destination_bound_grant)] = evidence.destination_bound_grant;
    features[@intFromEnum(ThirteenthFeature.pasteboard_destination_principal_bound_grant)] = evidence.destination_principal_bound_grant;
    features[@intFromEnum(ThirteenthFeature.pasteboard_strict_expiry_gate)] = evidence.strict_expiry_gate;
    features[@intFromEnum(ThirteenthFeature.pasteboard_read_once_token)] = evidence.read_once_token;
    features[@intFromEnum(ThirteenthFeature.pasteboard_revocation_gate)] = evidence.revocation_gate;
    features[@intFromEnum(ThirteenthFeature.pasteboard_user_visible_audit)] =
        event_ledger.EventKind.pasteboard_access == .pasteboard_access and
        @hasDecl(event_ledger.Ledger, "recordPasteboardAccess") and
        evidence.user_visible_audit;
    features[@intFromEnum(ThirteenthFeature.pasteboard_redacted_diagnostics)] = evidence.redacted_diagnostics;
    features[@intFromEnum(ThirteenthFeature.typed_secure_pasteboard_service)] = contractPresent("zigos.secure.pasteboard");
    features[@intFromEnum(ThirteenthFeature.pasteboard_offer_operation)] = contractOperationPresent("zigos.secure.pasteboard", .pasteboard_offer);
    features[@intFromEnum(ThirteenthFeature.pasteboard_read_operation)] = contractOperationPresent("zigos.secure.pasteboard", .pasteboard_read);
    features[@intFromEnum(ThirteenthFeature.pasteboard_revoke_operation)] = contractOperationPresent("zigos.secure.pasteboard", .pasteboard_revoke);
    features[@intFromEnum(ThirteenthFeature.native_registry_pasteboard_discovery)] =
        typed_component_abi.interfaceId(.secure_pasteboard) == .secure_pasteboard;
    features[@intFromEnum(ThirteenthFeature.pasteboard_bootstrap_service_contract)] = securePasteboardBootstrapContractCheck();
    features[@intFromEnum(ThirteenthFeature.pasteboard_boot_image_registry)] = securePasteboardBootImageRegistryCheck();
    return .{ .satisfied_features = features };
}

fn serviceBootstrapContractCheck(
    class: service_catalog.ServiceClass,
    interface_id: component_abi_schema.InterfaceId,
    interface_name: []const u8,
) bool {
    const entry = service_catalog.entryForClass(class) orelse return false;
    const launch = entry.service_bootstrap orelse return false;
    const contract = service_catalog.serviceContractForClass(class) orelse return false;
    return entry.published_native_service and
        entry.userspace_image != null and
        launch.mode == .kernel_contract and
        launch.grants.len != 0 and
        launch.grants[0] == .service_task_authority and
        contract.interface_id == interface_id and
        std.mem.eql(u8, contract.interface.name, interface_name);
}

fn serviceBootImageRegistryCheck(
    class: service_catalog.ServiceClass,
    bundle_id: []const u8,
    artifact_name: []const u8,
    interface_name: []const u8,
) bool {
    const image = userspace_registry.findByServiceClass(class) orelse return false;
    const catalog_entry = service_catalog.entryForClass(class) orelse return false;
    const build_image = catalog_entry.userspace_image orelse return false;
    const provided_interfaces = image.providedInterfaces();
    return std.mem.eql(u8, image.bundleId(), bundle_id) and
        std.mem.eql(u8, build_image.artifact_name, artifact_name) and
        std.mem.eql(u8, build_image.source_path, "src/userspace/service_main.zig") and
        provided_interfaces.len == 1 and
        std.mem.eql(u8, provided_interfaces[0].name, interface_name);
}

fn securePasteboardBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.secure_pasteboard, .secure_pasteboard, "zigos.secure.pasteboard");
}

fn securePasteboardBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.secure_pasteboard, "zigos.system.secure-pasteboard", "userspace-secure-pasteboard.elf", "zigos.secure.pasteboard");
}

fn securePasteboardContractEvidence() PasteboardContractEvidence {
    var evidence = PasteboardContractEvidence{};
    var service = secure_pasteboard.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const source = principal.PrincipalId{ .kind = .app, .serial = 2050 };
    const destination = principal.PrincipalId{ .kind = .app, .serial = 2051 };
    const imposter = principal.PrincipalId{ .kind = .app, .serial = 2052 };
    var buffer: [secure_pasteboard.MAX_PAYLOAD_BYTES]u8 = undefined;

    if (service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 2050,
        .destination_task_id = 2051,
        .user_gesture_id = 0,
        .foreground_session_id = 77,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .purpose = "paste into contract note",
        .payload = "contract private pasteboard payload",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.foreground_gesture_gate = err == error.MissingUserGesture;
    }
    if (service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 2050,
        .destination_task_id = 2051,
        .user_gesture_id = 11,
        .foreground_session_id = 0,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .purpose = "paste into contract note",
        .payload = "contract private pasteboard payload",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.foreground_gesture_gate = evidence.foreground_gesture_gate and err == error.MissingForegroundSession;
    }

    const grant = service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 2050,
        .destination_task_id = 2051,
        .user_gesture_id = 11,
        .foreground_session_id = 77,
        .expires_at_ticks = 100,
        .now_ticks = 12,
        .purpose = "paste into contract note",
        .payload = "contract private pasteboard payload",
        .detail = "contract private pasteboard payload",
    }, &ledger) catch return evidence;
    const token_id = grant.token_id;

    if (service.read(.{
        .subject = destination,
        .destination_task_id = 9999,
        .token_id = token_id,
        .user_gesture_id = 12,
        .foreground_session_id = 77,
        .now_ticks = 13,
        .expected_purpose = "paste into contract note",
        .detail = "contract private pasteboard payload",
    }, buffer[0..], &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.destination_bound_grant = err == error.InvalidDestination;
    }
    if (service.read(.{
        .subject = imposter,
        .destination_task_id = 2051,
        .token_id = token_id,
        .user_gesture_id = 12,
        .foreground_session_id = 77,
        .now_ticks = 14,
        .expected_purpose = "paste into contract note",
        .detail = "contract private pasteboard payload principal mismatch",
    }, buffer[0..], &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.destination_principal_bound_grant = err == error.DestinationSubjectMismatch;
    }
    if (service.read(.{
        .subject = destination,
        .destination_task_id = 2051,
        .token_id = token_id,
        .user_gesture_id = 13,
        .foreground_session_id = 77,
        .now_ticks = 100,
        .expected_purpose = "paste into contract note",
        .detail = "contract private pasteboard payload",
    }, buffer[0..], &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.strict_expiry_gate = err == error.ExpiredGrant;
    }

    const pasted = service.read(.{
        .subject = destination,
        .destination_task_id = 2051,
        .token_id = token_id,
        .user_gesture_id = 14,
        .foreground_session_id = 77,
        .now_ticks = 20,
        .expected_purpose = "paste into contract note",
        .detail = "contract private pasteboard payload",
    }, buffer[0..], &ledger) catch return evidence;
    if (!std.mem.eql(u8, pasted, "contract private pasteboard payload")) return evidence;
    if (service.read(.{
        .subject = destination,
        .destination_task_id = 2051,
        .token_id = token_id,
        .user_gesture_id = 15,
        .foreground_session_id = 77,
        .now_ticks = 21,
        .expected_purpose = "paste into contract note",
        .detail = "contract private pasteboard payload replay",
    }, buffer[0..], &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.read_once_token = err == error.GrantAlreadyConsumed;
    }

    const revocable = service.offer(.{
        .subject = source,
        .destination = destination,
        .source_task_id = 2050,
        .destination_task_id = 2051,
        .user_gesture_id = 16,
        .foreground_session_id = 77,
        .expires_at_ticks = 120,
        .now_ticks = 30,
        .purpose = "paste into contract note",
        .payload = "contract revoked pasteboard payload",
        .detail = "contract revoked pasteboard payload",
    }, &ledger) catch return evidence;
    const revoked_token_id = revocable.token_id;
    service.revoke(.{
        .subject = source,
        .source_task_id = 2050,
        .token_id = revoked_token_id,
        .now_ticks = 31,
        .detail = "contract revoked pasteboard payload",
    }, &ledger) catch return evidence;
    if (service.read(.{
        .subject = destination,
        .destination_task_id = 2051,
        .token_id = revoked_token_id,
        .user_gesture_id = 17,
        .foreground_session_id = 77,
        .now_ticks = 32,
        .expected_purpose = "paste into contract note",
        .detail = "contract revoked pasteboard payload",
    }, buffer[0..], &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.revocation_gate = err == error.GrantRevoked;
    }

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.user_visible_audit = summary.pasteboard_events >= 10 and summary.pasteboard_denials >= 6;
    var export_buffer: [2048]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.pasteboard_events and
        std.mem.indexOf(u8, exported, "contract private pasteboard payload") == null and
        std.mem.indexOf(u8, exported, "contract revoked pasteboard payload") == null and
        std.mem.indexOf(u8, exported, "kind=pasteboard_access") != null;
    return evidence;
}

const ObjectResilienceEvidence = struct {
    service_model: bool = false,
    restore_token_device_bound: bool = false,
    restore_subject_binding: bool = false,
    revoke_source_binding: bool = false,
    backup_revocation_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryFourteenthContract() FourteenthChecklist {
    var features = [_]bool{false} ** fourteenth_feature_count;
    const resilient_notes = manifest.BundleManifest{
        .bundle_id = "app.resilient-notes",
        .display_name = "Resilient Notes",
        .publisher = "zigos.dev",
        .object_resilience = .{
            .backup_enabled = true,
            .encrypted_snapshots = true,
            .recovery_key_required = true,
            .portable_restore = true,
            .device_trust_required = true,
            .max_restore_age_days = 30,
            .backup_format = "application/zigos-object-snapshot",
        },
    };
    var resilient_notes_v2 = resilient_notes;
    resilient_notes_v2.object_resilience = .{
        .backup_enabled = true,
        .encrypted_snapshots = true,
        .recovery_key_required = true,
        .portable_restore = true,
        .device_trust_required = true,
        .max_restore_age_days = 30,
        .backup_format = "application/zigos-object-snapshot+v2",
    };
    const digest_a = package_digest.digestBundle(resilient_notes);
    const digest_b = package_digest.digestBundle(resilient_notes_v2);
    const evidence = objectResilienceEvidence();

    features[@intFromEnum(FourteenthFeature.object_resilience_manifest)] =
        @hasField(manifest.BundleManifest, "object_resilience") and
        @hasField(manifest.ObjectResilienceDecl, "encrypted_snapshots") and
        @hasField(manifest.ObjectResilienceDecl, "device_trust_required");
    features[@intFromEnum(FourteenthFeature.encrypted_backup_validation)] = validationFailsWith(.{
        .bundle_id = "app.backup",
        .display_name = "Backup",
        .publisher = "zigos.dev",
        .object_resilience = .{
            .backup_enabled = true,
            .recovery_key_required = true,
            .portable_restore = true,
            .device_trust_required = true,
            .backup_format = "application/zigos-object-snapshot",
        },
    }, error.ObjectEncryptedBackupRequired);
    features[@intFromEnum(FourteenthFeature.recovery_key_validation)] = validationFailsWith(.{
        .bundle_id = "app.backup",
        .display_name = "Backup",
        .publisher = "zigos.dev",
        .object_resilience = .{
            .backup_enabled = true,
            .encrypted_snapshots = true,
            .portable_restore = true,
            .device_trust_required = true,
            .backup_format = "application/zigos-object-snapshot",
        },
    }, error.ObjectBackupRecoveryKeyRequired);
    features[@intFromEnum(FourteenthFeature.portable_restore_validation)] = validationFailsWith(.{
        .bundle_id = "app.backup",
        .display_name = "Backup",
        .publisher = "zigos.dev",
        .object_resilience = .{
            .backup_enabled = true,
            .encrypted_snapshots = true,
            .recovery_key_required = true,
            .device_trust_required = true,
            .backup_format = "application/zigos-object-snapshot",
        },
    }, error.ObjectBackupRestoreRequired);
    features[@intFromEnum(FourteenthFeature.trusted_restore_validation)] = validationFailsWith(.{
        .bundle_id = "app.backup",
        .display_name = "Backup",
        .publisher = "zigos.dev",
        .object_resilience = .{
            .backup_enabled = true,
            .encrypted_snapshots = true,
            .recovery_key_required = true,
            .portable_restore = true,
            .backup_format = "application/zigos-object-snapshot",
        },
    }, error.ObjectBackupDeviceTrustRequired);
    features[@intFromEnum(FourteenthFeature.backup_digest_covers_format)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(FourteenthFeature.package_preserves_object_resilience)] =
        @hasField(package_model.BundleRevision, "object_resilience") and
        @hasField(package_model.StoredObjectResilience, "encrypted_snapshots");
    features[@intFromEnum(FourteenthFeature.package_resolves_object_resilience)] =
        @hasField(package_model.ResolvedManifest, "object_resilience");
    features[@intFromEnum(FourteenthFeature.policy_backup_allowed_gate)] = objectResiliencePolicyDenies(.object_backup_denied);
    features[@intFromEnum(FourteenthFeature.policy_restore_allowed_gate)] = objectResiliencePolicyDenies(.object_restore_denied);
    features[@intFromEnum(FourteenthFeature.policy_encrypted_backup_gate)] = objectResiliencePolicyDenies(.object_backup_encryption_denied);
    features[@intFromEnum(FourteenthFeature.policy_restore_device_trust_gate)] = objectResiliencePolicyDenies(.object_restore_device_trust_denied);
    features[@intFromEnum(FourteenthFeature.typed_object_resilience_service)] = contractPresent("zigos.object.resilience");
    features[@intFromEnum(FourteenthFeature.backup_prepare_operation)] = contractOperationPresent("zigos.object.resilience", .object_backup_prepare);
    features[@intFromEnum(FourteenthFeature.restore_authorize_operation)] = contractOperationPresent("zigos.object.resilience", .object_restore_authorize);
    features[@intFromEnum(FourteenthFeature.backup_revoke_operation)] = contractOperationPresent("zigos.object.resilience", .object_backup_revoke);
    features[@intFromEnum(FourteenthFeature.native_registry_object_resilience_discovery)] =
        typed_component_abi.interfaceId(.object_resilience) == .object_resilience;
    features[@intFromEnum(FourteenthFeature.object_resilience_service_model)] = evidence.service_model;
    features[@intFromEnum(FourteenthFeature.restore_token_device_bound)] = evidence.restore_token_device_bound;
    features[@intFromEnum(FourteenthFeature.restore_snapshot_subject_bound)] = evidence.restore_subject_binding;
    features[@intFromEnum(FourteenthFeature.revoke_snapshot_source_task_bound)] = evidence.revoke_source_binding;
    features[@intFromEnum(FourteenthFeature.backup_revocation_gate)] = evidence.backup_revocation_gate;
    features[@intFromEnum(FourteenthFeature.object_resilience_ledger)] =
        event_ledger.EventKind.object_resilience == .object_resilience and
        @hasDecl(event_ledger.Ledger, "recordObjectResilience") and
        evidence.ledger;
    features[@intFromEnum(FourteenthFeature.object_resilience_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(FourteenthFeature.object_resilience_bootstrap_contract)] = objectResilienceBootstrapContractCheck();
    features[@intFromEnum(FourteenthFeature.object_resilience_boot_image_registry)] = objectResilienceBootImageRegistryCheck();
    return .{ .satisfied_features = features };
}

fn objectResiliencePolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "object-resilience-contract-policy",
        .seed = signing.seedFromByte(0xD3),
    };
    const backup_allowed = expected != .object_backup_denied;
    const restore_allowed = expected != .object_restore_denied;
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2034,
        .issuer = .{ .kind = .policy_authority, .serial = 2034 },
        .label = "object-resilience-contract",
        .object_backup_allowed = backup_allowed,
        .object_restore_allowed = restore_allowed,
        .require_encrypted_object_backup = true,
        .require_backup_recovery_key = true,
        .require_restore_device_trust = true,
        .max_object_backup_bytes = units.mebibytes(2),
        .max_object_restore_age_days = 30,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2034,
    };
    const request = switch (expected) {
        .object_backup_denied => policy_object.ObjectResilienceRequest{
            .operation = .backup,
            .sensitivity = .private_user_data,
            .bytes = units.kibibytes(512),
            .encrypted = true,
            .recovery_key_present = true,
        },
        .object_restore_denied => policy_object.ObjectResilienceRequest{
            .operation = .restore,
            .sensitivity = .private_user_data,
            .device_trust_verified = true,
            .restore_age_days = 1,
        },
        .object_backup_encryption_denied => policy_object.ObjectResilienceRequest{
            .operation = .backup,
            .sensitivity = .private_user_data,
            .bytes = units.kibibytes(512),
            .recovery_key_present = true,
        },
        .object_restore_device_trust_denied => policy_object.ObjectResilienceRequest{
            .operation = .restore,
            .sensitivity = .private_user_data,
            .restore_age_days = 1,
        },
        else => return false,
    };
    const decision = directory.objectResilienceDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn objectResilienceEvidence() ObjectResilienceEvidence {
    var evidence = ObjectResilienceEvidence{
        .service_model = @hasDecl(object_resilience_service.Service, "prepareBackup") and
            @hasDecl(object_resilience_service.Service, "restore") and
            @hasDecl(object_resilience_service.Service, "revoke") and
            @hasField(object_resilience_service.Snapshot, "restore_device_id"),
    };
    var directory = policy_object.Directory.init();
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2035,
        .issuer = .{ .kind = .policy_authority, .serial = 2035 },
        .label = "object-resilience-service",
        .object_backup_allowed = true,
        .object_restore_allowed = true,
        .require_encrypted_object_backup = true,
        .require_backup_recovery_key = true,
        .require_restore_device_trust = true,
        .max_object_backup_bytes = units.mebibytes(2),
        .max_object_restore_age_days = 30,
    }, .{
        .label = "object-resilience-service-policy",
        .seed = signing.seedFromByte(0xD4),
    }) catch return evidence;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2035,
    };
    var service = object_resilience_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2035 };
    const other_subject = principal.PrincipalId{ .kind = .app, .serial = 2038 };

    const snapshot = service.prepareBackup(&directory, subjects, .{
        .subject = subject,
        .task_id = 2036,
        .workspace_id = 77,
        .object_id = 88,
        .restore_device_id = 9090,
        .bytes = units.kibibytes(512),
        .sensitivity = .private_user_data,
        .encrypted = true,
        .recovery_key_present = true,
        .now_ticks = 40,
        .detail = "private object snapshot content",
    }, &ledger) catch return evidence;
    const snapshot_id = snapshot.id;

    if (service.restore(&directory, subjects, .{
        .subject = other_subject,
        .destination_task_id = 2037,
        .snapshot_id = snapshot_id,
        .destination_device_id = 9090,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 40,
        .detail = "private wrong-subject restore",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.restore_subject_binding = err == error.SnapshotSubjectMismatch;
    }

    if (service.restore(&directory, subjects, .{
        .subject = subject,
        .destination_task_id = 2037,
        .snapshot_id = snapshot_id,
        .destination_device_id = 9999,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 41,
        .detail = "private wrong-device restore",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.restore_token_device_bound = err == error.DeviceTrustMismatch;
    }

    if (service.restore(&directory, subjects, .{
        .subject = subject,
        .destination_task_id = 2037,
        .snapshot_id = snapshot_id,
        .destination_device_id = 9090,
        .restore_age_days = 1,
        .now_ticks = 42,
        .detail = "private untrusted restore",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        if (err != error.PolicyDenied) return evidence;
    }

    _ = service.restore(&directory, subjects, .{
        .subject = subject,
        .destination_task_id = 2037,
        .snapshot_id = snapshot_id,
        .destination_device_id = 9090,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 43,
        .detail = "private trusted restore",
    }, &ledger) catch return evidence;

    const revocable = service.prepareBackup(&directory, subjects, .{
        .subject = subject,
        .task_id = 2036,
        .workspace_id = 77,
        .object_id = 89,
        .restore_device_id = 9090,
        .bytes = units.kibibytes(512),
        .sensitivity = .private_user_data,
        .encrypted = true,
        .recovery_key_present = true,
        .now_ticks = 44,
        .detail = "private revoked object snapshot",
    }, &ledger) catch return evidence;
    const revoked_id = revocable.id;
    const wrong_subject_revoke_denied = if (service.revoke(.{
        .subject = other_subject,
        .task_id = 2036,
        .snapshot_id = revoked_id,
        .now_ticks = 45,
        .detail = "private revoked object snapshot wrong subject",
    }, &ledger)) |_| false else |err| err == error.SnapshotSubjectMismatch;
    const wrong_task_revoke_denied = if (service.revoke(.{
        .subject = subject,
        .task_id = 2037,
        .snapshot_id = revoked_id,
        .now_ticks = 45,
        .detail = "private revoked object snapshot wrong source task",
    }, &ledger)) |_| false else |err| err == error.SourceTaskMismatch;
    evidence.revoke_source_binding = wrong_subject_revoke_denied and wrong_task_revoke_denied;
    service.revoke(.{
        .subject = subject,
        .task_id = 2036,
        .snapshot_id = revoked_id,
        .now_ticks = 45,
        .detail = "private revoked object snapshot",
    }, &ledger) catch return evidence;
    if (service.restore(&directory, subjects, .{
        .subject = subject,
        .destination_task_id = 2037,
        .snapshot_id = revoked_id,
        .destination_device_id = 9090,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 46,
        .detail = "private revoked restore",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        evidence.backup_revocation_gate = err == error.SnapshotRevoked;
    }

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.object_resilience_events >= 7 and
        summary.object_resilience_denials >= 3 and
        summary.object_restore_events >= 4;
    var buffer: [2048]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.object_resilience_events and
        std.mem.indexOf(u8, exported, "private object snapshot content") == null and
        std.mem.indexOf(u8, exported, "private revoked object snapshot") == null and
        std.mem.indexOf(u8, exported, "kind=object_resilience") != null;
    return evidence;
}

fn objectResilienceBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.object_resilience, .object_resilience, "zigos.object.resilience");
}

fn objectResilienceBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.object_resilience, "zigos.system.object-resilience", "userspace-object-resilience.elf", "zigos.object.resilience");
}

const SemanticMemoryEvidence = struct {
    service_model: bool = false,
    index_generation: bool = false,
    top_k_ranking: bool = false,
    result_redaction: bool = false,
    workspace_scope: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryFifteenthContract() FifteenthChecklist {
    var features = [_]bool{false} ** fifteenth_feature_count;
    const semantic_notes = manifest.BundleManifest{
        .bundle_id = "app.semantic-notes",
        .display_name = "Semantic Notes",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = true,
            .encrypted_index = true,
            .redacted_snippets = true,
            .max_query_bytes = 64,
            .model_digest = "sha256:semantic-local-v1",
        },
    };
    var semantic_notes_v2 = semantic_notes;
    semantic_notes_v2.semantic_index.model_digest = "sha256:semantic-local-v2";
    const digest_a = package_digest.digestBundle(semantic_notes);
    const digest_b = package_digest.digestBundle(semantic_notes_v2);
    const evidence = semanticMemoryEvidence();

    features[@intFromEnum(FifteenthFeature.semantic_index_manifest)] =
        @hasField(manifest.BundleManifest, "semantic_index") and
        @hasField(manifest.SemanticIndexDecl, "local_only") and
        @hasField(manifest.SemanticIndexDecl, "encrypted_index") and
        @hasField(manifest.SemanticIndexDecl, "redacted_snippets");
    features[@intFromEnum(FifteenthFeature.semantic_index_local_validation)] = validationFailsWith(.{
        .bundle_id = "app.semantic",
        .display_name = "Semantic",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = false,
            .encrypted_index = true,
            .redacted_snippets = true,
            .max_query_bytes = 64,
            .model_digest = "sha256:semantic-local",
        },
    }, error.SemanticIndexRequiresLocal);
    features[@intFromEnum(FifteenthFeature.semantic_index_encryption_validation)] = validationFailsWith(.{
        .bundle_id = "app.semantic",
        .display_name = "Semantic",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = true,
            .redacted_snippets = true,
            .max_query_bytes = 64,
            .model_digest = "sha256:semantic-local",
        },
    }, error.SemanticIndexRequiresEncryption);
    features[@intFromEnum(FifteenthFeature.semantic_index_redaction_validation)] = validationFailsWith(.{
        .bundle_id = "app.semantic",
        .display_name = "Semantic",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = true,
            .encrypted_index = true,
            .max_query_bytes = 64,
            .model_digest = "sha256:semantic-local",
        },
    }, error.SemanticIndexRequiresRedaction);
    features[@intFromEnum(FifteenthFeature.semantic_index_query_budget_validation)] = validationFailsWith(.{
        .bundle_id = "app.semantic",
        .display_name = "Semantic",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = true,
            .encrypted_index = true,
            .redacted_snippets = true,
            .model_digest = "sha256:semantic-local",
        },
    }, error.SemanticIndexQueryBudgetMissing);
    features[@intFromEnum(FifteenthFeature.semantic_index_model_digest_validation)] = validationFailsWith(.{
        .bundle_id = "app.semantic",
        .display_name = "Semantic",
        .publisher = "zigos.dev",
        .semantic_index = .{
            .enabled = true,
            .local_only = true,
            .encrypted_index = true,
            .redacted_snippets = true,
            .max_query_bytes = 64,
        },
    }, error.SemanticIndexModelDigestMissing);
    features[@intFromEnum(FifteenthFeature.semantic_index_digest_covers_model)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@intFromEnum(FifteenthFeature.package_preserves_semantic_index)] =
        @hasField(package_model.BundleRevision, "semantic_index") and
        @hasField(package_model.StoredSemanticIndex, "model_digest") and
        @hasDecl(package_model.StoredSemanticIndex, "modelDigestSlice");
    features[@intFromEnum(FifteenthFeature.package_resolves_semantic_index)] =
        @hasField(package_model.ResolvedManifest, "semantic_index");
    features[@intFromEnum(FifteenthFeature.policy_semantic_memory_gate)] = semanticMemoryPolicyDenies(.semantic_memory_denied);
    features[@intFromEnum(FifteenthFeature.policy_semantic_local_model_gate)] = semanticMemoryPolicyDenies(.semantic_memory_remote_model_denied);
    features[@intFromEnum(FifteenthFeature.policy_semantic_encryption_gate)] = semanticMemoryPolicyDenies(.semantic_memory_encryption_denied);
    features[@intFromEnum(FifteenthFeature.policy_semantic_redaction_gate)] = semanticMemoryPolicyDenies(.semantic_memory_redaction_denied);
    features[@intFromEnum(FifteenthFeature.policy_semantic_query_budget_gate)] = semanticMemoryPolicyDenies(.semantic_query_budget_denied);
    features[@intFromEnum(FifteenthFeature.typed_index_search_service)] = contractPresent("zigos.index.search");
    features[@intFromEnum(FifteenthFeature.index_upsert_operation)] = contractOperationPresent("zigos.index.search", .index_upsert);
    features[@intFromEnum(FifteenthFeature.index_query_operation)] = contractOperationPresent("zigos.index.search", .index_query);
    features[@intFromEnum(FifteenthFeature.semantic_query_operation)] = contractOperationPresent("zigos.index.search", .semantic_index_query);
    features[@intFromEnum(FifteenthFeature.native_registry_index_discovery)] = indexSearchBootstrapContractCheck();
    features[@intFromEnum(FifteenthFeature.semantic_query_service_model)] = evidence.service_model;
    features[@intFromEnum(FifteenthFeature.semantic_query_index_generation)] =
        @hasField(typed_component_abi.IndexResponse, "index_generation") and evidence.index_generation;
    features[@intFromEnum(FifteenthFeature.semantic_query_top_k_ranking)] = evidence.top_k_ranking;
    features[@intFromEnum(FifteenthFeature.semantic_query_result_redaction)] = evidence.result_redaction;
    features[@intFromEnum(FifteenthFeature.semantic_query_workspace_scope)] = evidence.workspace_scope;
    features[@intFromEnum(FifteenthFeature.semantic_memory_ledger)] =
        event_ledger.EventKind.semantic_memory == .semantic_memory and
        @hasDecl(event_ledger.Ledger, "recordSemanticMemory") and
        evidence.ledger;
    features[@intFromEnum(FifteenthFeature.semantic_memory_redaction)] = evidence.redacted_diagnostics;
    return .{ .satisfied_features = features };
}

fn semanticMemoryPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "semantic-memory-contract-policy",
        .seed = signing.seedFromByte(0xE2),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2048,
        .issuer = .{ .kind = .policy_authority, .serial = 2048 },
        .label = "semantic-memory-contract",
        .semantic_memory_allowed = expected != .semantic_memory_denied,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2048,
    };
    const request = switch (expected) {
        .semantic_memory_denied => policy_object.SemanticMemoryRequest{
            .sensitivity = .private_user_data,
            .query_bytes = 16,
            .local_model = true,
            .encrypted_index = true,
            .redacted_snippets = true,
        },
        .semantic_memory_remote_model_denied => policy_object.SemanticMemoryRequest{
            .sensitivity = .private_user_data,
            .query_bytes = 16,
            .encrypted_index = true,
            .redacted_snippets = true,
        },
        .semantic_memory_encryption_denied => policy_object.SemanticMemoryRequest{
            .sensitivity = .private_user_data,
            .query_bytes = 16,
            .local_model = true,
            .redacted_snippets = true,
        },
        .semantic_memory_redaction_denied => policy_object.SemanticMemoryRequest{
            .sensitivity = .private_user_data,
            .query_bytes = 16,
            .local_model = true,
            .encrypted_index = true,
        },
        .semantic_query_budget_denied => policy_object.SemanticMemoryRequest{
            .sensitivity = .private_user_data,
            .query_bytes = 128,
            .local_model = true,
            .encrypted_index = true,
            .redacted_snippets = true,
        },
        else => return false,
    };
    const decision = directory.semanticMemoryDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn semanticMemoryEvidence() SemanticMemoryEvidence {
    var evidence = SemanticMemoryEvidence{
        .service_model = @hasDecl(indexing_service.Service, "upsertClassified") and
            @hasDecl(indexing_service.Service, "semanticQuery") and
            @hasField(indexing_service.DocumentRecord, "metadata") and
            @hasDecl(indexing_service.DocumentRecord, "sensitivity"),
        .top_k_ranking = semanticTopKRankingCheck(),
    };
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .organization,
        .subject_id = 2049,
        .issuer = .{ .kind = .policy_authority, .serial = 2049 },
        .label = "semantic-memory-service",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "semantic-memory-service-policy",
        .seed = signing.seedFromByte(0xE3),
    }) catch return evidence;

    var service = indexing_service.Service.init();
    service.upsertClassified(1, 100, 1, "Semantic Notes", "private semantic memory roadmap", .private_user_data) catch return evidence;
    service.upsertClassified(2, 200, 1, "Cross Workspace", "private semantic memory roadmap", .private_user_data) catch return evidence;

    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const subjects = policy_object.SubjectSet{
        .organization_id = 2049,
    };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2049 };
    const allowed = service.semanticQuery(&policies, subjects, .{
        .subject = subject,
        .task_id = 2050,
        .permitted_workspaces = &workspace_one,
        .query = "semantic",
        .local_model = true,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 50,
        .detail = "private semantic memory query",
    }, &results_buffer, &ledger) catch return evidence;
    evidence.workspace_scope = allowed.len == 1 and
        allowed[0].workspace_id == 1 and
        allowed[0].object_id == 100;
    evidence.index_generation = service.generation == 3 and
        allowed[0].index_generation == service.generation;
    evidence.result_redaction = allowed.len == 1 and
        allowed[0].title_fingerprint != 0 and
        allowed[0].titleSlice().len == 0;

    if (service.semanticQuery(&policies, subjects, .{
        .subject = subject,
        .task_id = 2050,
        .permitted_workspaces = &workspace_one,
        .query = "semantic",
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 51,
        .detail = "private remote semantic memory query",
    }, &results_buffer, &ledger)) |_| {
        return evidence;
    } else |err| {
        if (err != error.PolicyDenied) return evidence;
    }

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.semantic_memory_events == 2 and
        summary.semantic_memory_denials == 1 and
        summary.semantic_memory_remote_denials == 1;
    var buffer: [2048]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.semantic_memory_events and
        std.mem.indexOf(u8, exported, "private semantic memory query") == null and
        std.mem.indexOf(u8, exported, "private remote semantic memory query") == null and
        std.mem.indexOf(u8, exported, "kind=semantic_memory") != null;
    return evidence;
}

fn semanticTopKRankingCheck() bool {
    var service = indexing_service.Service.init();
    for (0..indexing_service.MAX_RESULTS) |index| {
        service.upsert(9, 900 + @as(u64, @intCast(index)), 1, "Low Match", "semantic") catch return false;
    }
    service.upsert(9, 999, 1, "Semantic Priority", "semantic semantic semantic") catch return false;

    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const workspace = [_]u64{9};
    const results = service.query(&workspace, "semantic", &results_buffer);
    if (results.len != indexing_service.MAX_RESULTS) return false;
    if (results[0].object_id != 999 or results[0].score != 7) return false;
    for (results) |result| {
        if (result.object_id == 907) return false;
    }
    return true;
}

fn indexSearchBootstrapContractCheck() bool {
    const entry = service_catalog.entryForClass(.indexing_search) orelse return false;
    const launch = entry.service_bootstrap orelse return false;
    const contract = service_catalog.serviceContractForClass(.indexing_search) orelse return false;
    const image = userspace_registry.findByServiceClass(.indexing_search) orelse return false;
    const provided_interfaces = image.providedInterfaces();
    return entry.published_native_service and
        entry.userspace_image != null and
        launch.mode == .kernel_contract and
        launch.grants.len != 0 and
        launch.grants[0] == .service_task_authority and
        contract.interface_id == .index_search and
        std.mem.eql(u8, contract.interface.name, "zigos.index.search") and
        provided_interfaces.len == 1 and
        std.mem.eql(u8, provided_interfaces[0].name, "zigos.index.search");
}

const IdentityCredentialEvidence = struct {
    service_model: bool = false,
    hardware_sealed: bool = false,
    phishing_rejected: bool = false,
    local_unlock_required: bool = false,
    fresh_unlock_enforced: bool = false,
    device_bound_wrong_device_rejected: bool = false,
    synced_recovery: bool = false,
    device_bound_recovery_denied: bool = false,
    revocation_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositorySixteenthContract() SixteenthChecklist {
    var features = [_]bool{false} ** sixteenth_feature_count;
    const evidence = identityCredentialEvidence();

    features[@intFromEnum(SixteenthFeature.passwordless_unlock_methods)] =
        std.meta.stringToEnum(os_identity.UnlockMethod, "password") == null;
    features[@intFromEnum(SixteenthFeature.passkey_credential_service_model)] = evidence.service_model;
    features[@intFromEnum(SixteenthFeature.credential_hardware_sealed_secret)] = evidence.hardware_sealed;
    features[@intFromEnum(SixteenthFeature.credential_phishing_origin_rejection)] = evidence.phishing_rejected;
    features[@intFromEnum(SixteenthFeature.credential_local_unlock_required)] = evidence.local_unlock_required;
    features[@intFromEnum(SixteenthFeature.credential_fresh_unlock_enforced)] = evidence.fresh_unlock_enforced;
    features[@intFromEnum(SixteenthFeature.device_bound_wrong_device_rejected)] = evidence.device_bound_wrong_device_rejected;
    features[@intFromEnum(SixteenthFeature.synced_credential_recovery_device_graph)] = evidence.synced_recovery;
    features[@intFromEnum(SixteenthFeature.device_bound_recovery_denied)] = evidence.device_bound_recovery_denied;
    features[@intFromEnum(SixteenthFeature.credential_revocation_gate)] = evidence.revocation_gate;
    features[@intFromEnum(SixteenthFeature.policy_credential_assertion_gate)] = credentialPolicyDenies(.credential_assertion_denied);
    features[@intFromEnum(SixteenthFeature.policy_credential_password_fallback_gate)] = credentialPolicyDenies(.credential_password_fallback_denied);
    features[@intFromEnum(SixteenthFeature.policy_credential_phishing_gate)] = credentialPolicyDenies(.credential_phishing_resistance_denied);
    features[@intFromEnum(SixteenthFeature.policy_credential_hardware_gate)] = credentialPolicyDenies(.credential_hardware_denied);
    features[@intFromEnum(SixteenthFeature.policy_credential_local_unlock_gate)] = credentialPolicyDenies(.credential_unlock_denied);
    features[@intFromEnum(SixteenthFeature.policy_credential_unlock_age_gate)] = credentialPolicyDenies(.credential_unlock_stale);
    features[@intFromEnum(SixteenthFeature.identity_credential_register_operation)] = contractOperationPresent("zigos.identity.session", .identity_credential_register);
    features[@intFromEnum(SixteenthFeature.identity_credential_assert_operation)] = contractOperationPresent("zigos.identity.session", .identity_credential_assert);
    features[@intFromEnum(SixteenthFeature.identity_credential_recover_operation)] = contractOperationPresent("zigos.identity.session", .identity_credential_recover);
    features[@intFromEnum(SixteenthFeature.identity_credential_revoke_operation)] = contractOperationPresent("zigos.identity.session", .identity_credential_revoke);
    features[@intFromEnum(SixteenthFeature.credential_ledger)] =
        event_ledger.EventKind.identity_credential == .identity_credential and
        @hasDecl(event_ledger.Ledger, "recordIdentityCredential") and
        evidence.ledger;
    features[@intFromEnum(SixteenthFeature.credential_redaction)] = evidence.redacted_diagnostics;
    return .{ .satisfied_features = features };
}

fn credentialPolicyDenies(expected: policy_object.DecisionReason) bool {
    var directory = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "credential-contract-policy",
        .seed = signing.seedFromByte(0xE4),
    };
    _ = directory.create(.{
        .scope = .organization,
        .subject_id = 2056,
        .issuer = .{ .kind = .policy_authority, .serial = 2056 },
        .label = "credential-contract",
        .credential_assertions_allowed = expected != .credential_assertion_denied,
        .deny_credential_password_fallback = true,
        .require_phishing_resistant_credential = true,
        .require_hardware_backed_credential = true,
        .require_local_credential_unlock = true,
        .max_credential_unlock_age_ticks = 4,
    }, signer) catch return false;
    const subjects = policy_object.SubjectSet{
        .organization_id = 2056,
    };
    const request = switch (expected) {
        .credential_assertion_denied => policy_object.CredentialAssertionRequest{
            .phishing_resistant = true,
            .hardware_backed = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = 1,
        },
        .credential_password_fallback_denied => policy_object.CredentialAssertionRequest{
            .password_fallback = true,
            .phishing_resistant = true,
            .hardware_backed = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = 1,
        },
        .credential_phishing_resistance_denied => policy_object.CredentialAssertionRequest{
            .hardware_backed = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = 1,
        },
        .credential_hardware_denied => policy_object.CredentialAssertionRequest{
            .phishing_resistant = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = 1,
        },
        .credential_unlock_denied => policy_object.CredentialAssertionRequest{
            .phishing_resistant = true,
            .hardware_backed = true,
            .unlock_age_ticks = 1,
        },
        .credential_unlock_stale => policy_object.CredentialAssertionRequest{
            .phishing_resistant = true,
            .hardware_backed = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = 9,
        },
        else => return false,
    };
    const decision = directory.credentialAssertionDecision(subjects, request);
    return !decision.allowed and decision.reason == expected;
}

fn credentialContractHardwareSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "credential-contract-provider", label);
    crypto_hash.updateBytes(&hasher, "credential-contract-seal", raw);
    return crypto_hash.finalize(&hasher);
}

fn credentialContractHardwareProvider() secure_secret_store.HardwareSealProvider {
    return .{
        .available = true,
        .sealFn = credentialContractHardwareSeal,
    };
}

fn identityCredentialEvidence() IdentityCredentialEvidence {
    var evidence = IdentityCredentialEvidence{
        .service_model = @hasDecl(os_identity.Store, "registerCredential") and
            @hasDecl(os_identity.Store, "assertCredential") and
            @hasDecl(os_identity.Store, "recoverCredential") and
            @hasDecl(os_identity.Store, "revokeCredential") and
            @hasField(os_identity.CredentialRecord, "phishing_resistant") and
            @hasField(os_identity.Assertion, "hardware_backed_credential"),
    };
    var graph = device_graph.Graph.init();
    var secrets = secure_secret_store.Store.init();
    secrets.attachHardwareProvider(credentialContractHardwareProvider());
    var identities = os_identity.Store.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .organization,
        .subject_id = 2057,
        .issuer = .{ .kind = .policy_authority, .serial = 2057 },
        .label = "credential-service-policy",
        .credential_assertions_allowed = true,
        .deny_credential_password_fallback = true,
        .require_phishing_resistant_credential = true,
        .require_hardware_backed_credential = true,
        .require_local_credential_unlock = true,
        .max_credential_unlock_age_ticks = 4,
    }, .{
        .label = "credential-service-policy",
        .seed = signing.seedFromByte(0xE5),
    }) catch return evidence;

    const user = principal.PrincipalId{ .kind = .user, .serial = 2057 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 2058 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 2059 };
    const task_id: u64 = 2060;
    const user_identity = signing.SignerIdentity{ .label = "credential-contract-user", .seed = signing.seedFromByte(0xE6) };
    const laptop_identity = signing.SignerIdentity{ .label = "credential-contract-laptop", .seed = signing.seedFromByte(0xE7) };
    const phone_identity = signing.SignerIdentity{ .label = "credential-contract-phone", .seed = signing.seedFromByte(0xE8) };
    const first_credential_identity = signing.SignerIdentity{ .label = "credential-contract-passkey-v1", .seed = signing.seedFromByte(0xE9) };
    const replacement_credential_identity = signing.SignerIdentity{ .label = "credential-contract-passkey-v2", .seed = signing.seedFromByte(0xEA) };
    const bound_credential_identity = signing.SignerIdentity{ .label = "credential-contract-bound", .seed = signing.seedFromByte(0xEB) };

    _ = graph.ensureUserRoot(user, "owner", user_identity) catch return evidence;
    _ = graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1) catch return evidence;
    _ = graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2) catch return evidence;
    const credential = identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = "accounts-passkey",
        .scope = .synced,
        .credential_identity = first_credential_identity,
        .tick = 3,
    }) catch return evidence;
    const credential_id = credential.id;
    const first_generation = credential.credential_generation;
    evidence.hardware_sealed = credential.local_unlock_required and
        credential.phishing_resistant and
        credential.hardware_backed_credential and
        credential.sealed_credential_secret and
        credential.isRecoverableThroughDeviceGraph();

    const unlock = os_identity.createLocalUnlockProof(user, laptop, "accounts.example", "nonce-1", .biometric, 4, 8, laptop_identity) catch return evidence;
    const assertion = identities.assertCredential(&graph, .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://login.accounts.example",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .credential_identity = first_credential_identity,
        .tick = 5,
    }) catch return evidence;
    const credential_decision = policies.credentialAssertionDecision(.{ .organization_id = 2057 }, .{
        .phishing_resistant = assertion.phishing_resistant,
        .hardware_backed = assertion.hardware_backed_credential,
        .local_unlock_verified = assertion.local_unlock_verified,
        .unlock_age_ticks = assertion.unlock_age_ticks,
    });
    if (!credential_decision.allowed) return evidence;
    ledger.recordIdentityCredential(
        user,
        task_id,
        credential_id,
        true,
        assertion.phishing_resistant,
        assertion.hardware_backed_credential,
        assertion.local_unlock_verified,
        false,
        false,
        false,
        5,
        "private credential assertion for accounts.example",
    ) catch return evidence;

    evidence.local_unlock_required = if (identities.assertCredential(&graph, .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-1",
        .credential_identity = first_credential_identity,
        .tick = 6,
    })) |_| false else |err| err == error.LocalUnlockRequired;

    evidence.phishing_rejected = if (identities.assertCredential(&graph, .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example.evil.test",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .credential_identity = first_credential_identity,
        .tick = 6,
    })) |_| false else |err| err == error.PhishingOriginRejected;
    if (evidence.phishing_rejected) {
        ledger.recordIdentityCredential(
            user,
            task_id,
            credential_id,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            6,
            "private phishing origin accounts.example.evil.test",
        ) catch return evidence;
    }

    const expired_unlock = os_identity.createLocalUnlockProof(user, laptop, "accounts.example", "nonce-expired", .biometric, 4, 5, laptop_identity) catch return evidence;
    evidence.fresh_unlock_enforced = if (identities.assertCredential(&graph, .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-expired",
        .local_unlock = expired_unlock,
        .credential_identity = first_credential_identity,
        .tick = 9,
    })) |_| false else |err| err == error.LocalUnlockExpired;

    const bound = identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "admin.example",
        .label = "admin-device-passkey",
        .scope = .device_bound,
        .credential_identity = bound_credential_identity,
        .tick = 10,
    }) catch return evidence;
    const phone_unlock = os_identity.createLocalUnlockProof(user, phone, "admin.example", "bound-nonce", .biometric, 11, 15, phone_identity) catch return evidence;
    evidence.device_bound_wrong_device_rejected = if (identities.assertCredential(&graph, .{
        .credential_id = bound.id,
        .device = phone,
        .relying_party_id = "admin.example",
        .origin = "https://admin.example",
        .challenge = "bound-nonce",
        .local_unlock = phone_unlock,
        .credential_identity = bound_credential_identity,
        .tick = 12,
    })) |_| false else |err| err == error.DeviceBoundCredentialWrongDevice;

    const recovery_unlock = os_identity.createLocalUnlockProof(user, phone, "accounts.example", "recover-1", .recovery_key, 13, 18, phone_identity) catch return evidence;
    const laptop_recovery_unlock = os_identity.createLocalUnlockProof(user, laptop, "accounts.example", "recover-1", .recovery_key, 13, 18, laptop_identity) catch return evidence;
    const recovered = identities.recoverCredential(&graph, &secrets, .{
        .credential_id = credential_id,
        .recovery_device = phone,
        .relying_party_id = "accounts.example",
        .challenge = "recover-1",
        .local_unlock = recovery_unlock,
        .threshold = 2,
        .approvals = &.{.{ .device = laptop, .local_unlock = laptop_recovery_unlock }},
        .replacement_credential_identity = replacement_credential_identity,
        .tick = 14,
    }) catch return evidence;
    evidence.synced_recovery = recovered.primary_device.eql(phone) and
        recovered.credential_generation == first_generation + 1 and
        recovered.recovered_at_ticks == 14;
    ledger.recordIdentityCredential(
        user,
        task_id,
        credential_id,
        true,
        true,
        recovered.hardware_backed_credential and recovered.sealed_credential_secret,
        true,
        true,
        false,
        false,
        14,
        "private credential recovery for accounts.example",
    ) catch return evidence;

    const bound_recovery_unlock = os_identity.createLocalUnlockProof(user, phone, "admin.example", "recover-bound", .recovery_key, 15, 19, phone_identity) catch return evidence;
    evidence.device_bound_recovery_denied = if (identities.recoverCredential(&graph, &secrets, .{
        .credential_id = bound.id,
        .recovery_device = phone,
        .relying_party_id = "admin.example",
        .challenge = "recover-bound",
        .local_unlock = bound_recovery_unlock,
        .replacement_credential_identity = replacement_credential_identity,
        .tick = 16,
    })) |_| false else |err| err == error.DeviceBoundRecoveryDenied;

    identities.revokeCredential(credential_id, 17) catch return evidence;
    ledger.recordIdentityCredential(
        user,
        task_id,
        credential_id,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        17,
        "private credential revocation for accounts.example",
    ) catch return evidence;
    const post_revoke_unlock = os_identity.createLocalUnlockProof(user, phone, "accounts.example", "post-revoke", .device_pin, 18, 21, phone_identity) catch return evidence;
    evidence.revocation_gate = if (identities.assertCredential(&graph, .{
        .credential_id = credential_id,
        .device = phone,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "post-revoke",
        .local_unlock = post_revoke_unlock,
        .credential_identity = replacement_credential_identity,
        .tick = 19,
    })) |_| false else |err| err == error.CredentialRevoked;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.identity_credential_events == 4 and
        summary.identity_credential_denials == 1 and
        summary.identity_credential_recoveries == 1 and
        summary.identity_credential_revocations == 1 and
        summary.identity_credential_phishing_denials == 1;
    var buffer: [2048]u8 = undefined;
    const exported = ledger.exportText(&buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.identity_credential_events and
        std.mem.indexOf(u8, exported, "accounts.example") == null and
        std.mem.indexOf(u8, exported, "accounts.example.evil.test") == null and
        std.mem.indexOf(u8, exported, "kind=identity_credential") != null;
    return evidence;
}

const PrivateSyncEvidence = struct {
    service_model: bool = false,
    crdt_merge: bool = false,
    log_idempotence: bool = false,
    vector_clock: bool = false,
    buffer_bounds: bool = false,
    encrypted_transport: bool = false,
    mergeable_semantic: bool = false,
    policy_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositorySeventeenthContract() SeventeenthChecklist {
    var features = [_]bool{false} ** seventeenth_feature_count;
    const evidence = privateSyncEvidence();
    const default_policy = sync_service.WorkspacePolicyRequest{
        .workspace_id = 1,
        .owner = .{ .kind = .user, .serial = 1 },
    };

    features[@intFromEnum(SeventeenthFeature.crdt_document_operation_model)] =
        @hasDecl(sync_adapters.DocumentOperation, "insert") and
        @hasDecl(sync_adapters.DocumentOperation, "remove") and
        @hasDecl(sync_adapters.DocumentOperationLog, "mergeFrom");
    features[@intFromEnum(SeventeenthFeature.deterministic_document_merge)] = evidence.crdt_merge;
    features[@intFromEnum(SeventeenthFeature.idempotent_operation_log_merge)] = evidence.log_idempotence;
    features[@intFromEnum(SeventeenthFeature.vector_clock_tracking)] = evidence.vector_clock;
    features[@intFromEnum(SeventeenthFeature.merge_buffer_bounds)] = evidence.buffer_bounds;
    features[@intFromEnum(SeventeenthFeature.encrypted_transport_queue)] = evidence.encrypted_transport;
    features[@intFromEnum(SeventeenthFeature.mergeable_transport_semantic)] = evidence.mergeable_semantic;
    features[@intFromEnum(SeventeenthFeature.sync_service_replication_model)] =
        evidence.service_model and @hasDecl(sync_service.Service, "replicateWorkspace");
    features[@intFromEnum(SeventeenthFeature.conflict_review_service_model)] =
        @hasDecl(sync_service.Service, "reviewConflictForObject");
    features[@intFromEnum(SeventeenthFeature.conflict_resolution_service_model)] =
        @hasDecl(sync_service.Service, "resolveConflictForObject");
    features[@intFromEnum(SeventeenthFeature.sync_destination_policy_gate)] = evidence.policy_gate;
    features[@intFromEnum(SeventeenthFeature.personal_e2ee_default_policy)] = default_policy.personal_e2ee;
    features[@intFromEnum(SeventeenthFeature.offline_first_default_policy)] = default_policy.offline_first;
    features[@intFromEnum(SeventeenthFeature.sync_conflict_ledger)] =
        event_ledger.EventKind.sync_conflict == .sync_conflict and evidence.ledger;
    features[@intFromEnum(SeventeenthFeature.sync_conflict_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(SeventeenthFeature.typed_sync_replication_service)] = contractPresent("zigos.sync.replication");
    features[@intFromEnum(SeventeenthFeature.sync_device_enroll_operation)] = contractOperationPresent("zigos.sync.replication", .sync_device_enroll);
    features[@intFromEnum(SeventeenthFeature.sync_workspace_replicate_operation)] = contractOperationPresent("zigos.sync.replication", .sync_workspace_replicate);
    features[@intFromEnum(SeventeenthFeature.sync_conflict_review_operation)] = contractOperationPresent("zigos.sync.replication", .sync_conflict_review);
    features[@intFromEnum(SeventeenthFeature.sync_conflict_resolve_operation)] = contractOperationPresent("zigos.sync.replication", .sync_conflict_resolve);
    features[@intFromEnum(SeventeenthFeature.sync_transport_frame_operation)] = contractOperationPresent("zigos.sync.replication", .sync_transport_frame);
    features[@intFromEnum(SeventeenthFeature.native_registry_sync_discovery)] = syncBootstrapContractCheck();
    features[@intFromEnum(SeventeenthFeature.sync_boot_image_registry)] = syncBootImageRegistryCheck();
    return .{ .satisfied_features = features };
}

fn privateSyncEvidence() PrivateSyncEvidence {
    var evidence = PrivateSyncEvidence{
        .service_model = @hasDecl(sync_service.Service, "replicateWorkspace") and
            @hasDecl(sync_service.Service, "acceptTransportFrame") and
            @hasDecl(sync_service.Service, "reviewConflictForObject") and
            @hasDecl(sync_service.Service, "resolveConflictForObject"),
    };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 301 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 302 };
    var local_log = sync_adapters.DocumentOperationLog{};
    var remote_log = sync_adapters.DocumentOperationLog{};
    local_log.append(sync_adapters.DocumentOperation.insert(5, " laptop", laptop, 1) catch return evidence) catch return evidence;
    remote_log.append(sync_adapters.DocumentOperation.insert(12, " tablet", tablet, 2) catch return evidence) catch return evidence;
    var merged_log = sync_adapters.DocumentOperationLog{};
    var merge_buffer: [96]u8 = undefined;
    const merged_document = sync_adapters.mergeDocumentOperationLogs(
        "hello",
        &local_log,
        &remote_log,
        &merged_log,
        &merge_buffer,
    ) catch return evidence;
    evidence.crdt_merge = std.mem.eql(u8, merged_document, "hello laptop tablet");
    evidence.vector_clock = merged_log.clockFor(laptop) == 1 and
        merged_log.clockFor(tablet) == 2 and
        merged_log.operation_count == 2;

    var duplicate_log = sync_adapters.DocumentOperationLog{};
    duplicate_log.mergeFrom(&local_log) catch return evidence;
    duplicate_log.mergeFrom(&local_log) catch return evidence;
    evidence.log_idempotence = duplicate_log.operation_count == 1 and duplicate_log.clockFor(laptop) == 1;

    var tiny_buffer: [4]u8 = undefined;
    evidence.buffer_bounds = if (sync_adapters.applyMergeableDocumentOperations(
        "hello",
        local_log.slice(),
        &.{},
        &tiny_buffer,
    )) |_| false else |err| err == error.DocumentBufferTooSmall;

    var queue = sync_adapters.TransportQueue.init();
    const frame = queue.enqueue(.{
        .workspace_id = 71,
        .object_id = 72,
        .version_id = 73,
        .source_device = laptop,
        .target_device = tablet,
        .transport = .relay_assisted,
        .semantic = .mergeable_crdt,
        .encrypted = true,
        .workspace_generation = 4,
        .path = "docs/plan.md",
    }) catch return evidence;
    const latest = queue.latestForPath(71, tablet, "docs/plan.md") orelse return evidence;
    evidence.encrypted_transport = frame.encrypted and
        latest.encrypted and
        queue.countFor(71, tablet) == 1 and
        latest.id == frame.id;
    evidence.mergeable_semantic = frame.semantic == .mergeable_crdt and
        frame.transport == .relay_assisted and
        std.mem.eql(u8, frame.pathSlice(), "docs/plan.md");

    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .organization,
        .subject_id = 306,
        .issuer = .{ .kind = .policy_authority, .serial = 306 },
        .label = "private-sync-contract",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.allowed.example"},
    }, .{
        .label = "private-sync-policy",
        .seed = signing.seedFromByte(0xEC),
    }) catch return evidence;
    const sync_denied = policies.syncDestinationDecision(.{ .organization_id = 306 }, "relay.denied.example");
    const sync_allowed = policies.syncDestinationDecision(.{ .organization_id = 306 }, "relay.allowed.example");
    evidence.policy_gate = !sync_denied.allowed and
        sync_denied.reason == .sync_destination_denied and
        sync_allowed.allowed;

    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    ledger.recordSyncConflict(
        .{ .kind = .user, .serial = 306 },
        71,
        22,
        "private document conflict body",
        true,
    ) catch return evidence;
    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.sync_conflicts == 1;
    var export_buffer: [1024]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= 1 and
        std.mem.indexOf(u8, exported, "private document conflict body") == null and
        std.mem.indexOf(u8, exported, "kind=sync_conflict") != null;
    return evidence;
}

fn syncBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.sync_replication, .sync_replication, "zigos.sync.replication");
}

fn syncBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.sync_replication, "zigos.system.sync-service", "userspace-sync-service.elf", "zigos.sync.replication");
}

const SensitiveCaptureEvidence = struct {
    service_model: bool = false,
    foreground_gate: bool = false,
    indicator_gate: bool = false,
    background_denial: bool = false,
    lease_policy_gate: bool = false,
    indicator_expiry_boundary: bool = false,
    session_binding_gate: bool = false,
    sample_budget_gate: bool = false,
    permission_policy_gate: bool = false,
    revocation_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryEighteenthContract() EighteenthChecklist {
    var features = [_]bool{false} ** eighteenth_feature_count;
    const evidence = sensitiveCaptureEvidence();
    const camera_permission = capturePermission(.camera, "camera:front", 120, "Capture a document photo");
    const mic_permission = capturePermission(.mic, "microphone:built-in", 120, "Record a voice note");
    const screen_permission = capturePermission(.screen_capture, "screen:active-window", 60, "Share the visible window");

    features[@intFromEnum(EighteenthFeature.sensitive_capture_service_model)] = evidence.service_model;
    features[@intFromEnum(EighteenthFeature.capture_foreground_session_gate)] = evidence.foreground_gate;
    features[@intFromEnum(EighteenthFeature.capture_privacy_indicator_gate)] = evidence.indicator_gate;
    features[@intFromEnum(EighteenthFeature.capture_background_denial)] = evidence.background_denial;
    features[@intFromEnum(EighteenthFeature.capture_lease_policy_gate)] = evidence.lease_policy_gate;
    features[@intFromEnum(EighteenthFeature.capture_indicator_expiry_boundary)] = evidence.indicator_expiry_boundary;
    features[@intFromEnum(EighteenthFeature.capture_session_binding_gate)] =
        evidence.session_binding_gate and
        @hasField(typed_component_abi.CaptureSampleRequest, "expected_device_id") and
        @hasField(typed_component_abi.CaptureSampleRequest, "expected_foreground_session_id") and
        @hasField(typed_component_abi.CaptureSampleRequest, "expected_kind") and
        @hasField(typed_component_abi.CaptureStopRequest, "expected_device_id") and
        @hasField(typed_component_abi.CaptureStopRequest, "expected_foreground_session_id") and
        @hasField(typed_component_abi.CaptureStopRequest, "expected_kind");
    features[@intFromEnum(EighteenthFeature.capture_sample_budget_gate)] = evidence.sample_budget_gate;
    features[@intFromEnum(EighteenthFeature.capture_permission_kind_policy_gate)] = evidence.permission_policy_gate;
    features[@intFromEnum(EighteenthFeature.capture_revocation_gate)] = evidence.revocation_gate;
    features[@intFromEnum(EighteenthFeature.sensitive_capture_ledger)] =
        event_ledger.EventKind.sensitive_capture == .sensitive_capture and evidence.ledger;
    features[@intFromEnum(EighteenthFeature.sensitive_capture_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(EighteenthFeature.typed_sensitive_capture_service)] = contractPresent("zigos.sensitive.capture");
    features[@intFromEnum(EighteenthFeature.capture_start_operation)] = contractOperationPresent("zigos.sensitive.capture", .capture_start);
    features[@intFromEnum(EighteenthFeature.capture_sample_operation)] = contractOperationPresent("zigos.sensitive.capture", .capture_sample);
    features[@intFromEnum(EighteenthFeature.capture_stop_operation)] = contractOperationPresent("zigos.sensitive.capture", .capture_stop);
    features[@intFromEnum(EighteenthFeature.native_registry_capture_discovery)] =
        typed_component_abi.interfaceId(.sensitive_capture) == .sensitive_capture;
    features[@intFromEnum(EighteenthFeature.capture_bootstrap_service_contract)] = captureBootstrapContractCheck();
    features[@intFromEnum(EighteenthFeature.capture_boot_image_registry)] = captureBootImageRegistryCheck();
    features[@intFromEnum(EighteenthFeature.camera_permission_manifest_lease)] = capturePermissionIsModern(camera_permission, .camera);
    features[@intFromEnum(EighteenthFeature.microphone_permission_manifest_lease)] = capturePermissionIsModern(mic_permission, .mic);
    features[@intFromEnum(EighteenthFeature.screen_capture_permission_manifest_lease)] = capturePermissionIsModern(screen_permission, .screen_capture);
    return .{ .satisfied_features = features };
}

fn sensitiveCaptureEvidence() SensitiveCaptureEvidence {
    var evidence = SensitiveCaptureEvidence{
        .service_model = @hasDecl(sensitive_capture_service.Service, "start") and
            @hasDecl(sensitive_capture_service.Service, "sample") and
            @hasDecl(sensitive_capture_service.Service, "stop") and
            @hasDecl(sensitive_capture_service.Service, "privacyIndicatorActive") and
            @hasDecl(sensitive_capture_service.Service, "privacyIndicatorActiveAt") and
            @hasDecl(sensitive_capture_service.Service, "activeSessionCountAt") and
            @hasField(sensitive_capture_service.Session, "foreground_session_id") and
            @hasField(sensitive_capture_service.Session, "indicator_visible"),
    };

    const user = principal.PrincipalId{ .kind = .user, .serial = 401 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 402 };
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 401 },
        .label = "sensitive-capture-contract",
        .camera_allowed = true,
        .microphone_allowed = true,
        .location_allowed = true,
        .sensors_allowed = true,
        .screen_capture_allowed = true,
        .require_sensitive_capture_foreground = true,
        .require_capture_indicator = true,
        .allow_background_capture = false,
        .max_sensitive_capture_lease_ticks = 40,
        .max_sensitive_capture_samples = 2,
    }, .{
        .label = "sensitive-capture-policy",
        .seed = signing.seedFromByte(0xCB),
    }) catch return evidence;
    var locked_policies = policy_object.Directory.init();
    _ = locked_policies.create(.{
        .scope = .user,
        .subject_id = 403,
        .issuer = .{ .kind = .policy_authority, .serial = 401 },
        .label = "sensitive-capture-locked",
        .camera_allowed = false,
    }, .{
        .label = "sensitive-capture-locked-policy",
        .seed = signing.seedFromByte(0xCC),
    }) catch return evidence;

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    const locked_subjects = policy_object.SubjectSet{ .user_id = 403 };
    var service = sensitive_capture_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    evidence.foreground_gate = if (service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 0,
        .expires_at_ticks = 20,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera foreground denial",
    }, &ledger)) |_| false else |err| err == error.ForegroundSessionRequired;
    evidence.indicator_gate = if (service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 20,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = false,
        .detail = "private camera indicator denial",
    }, &ledger)) |_| false else |err| err == error.PrivacyIndicatorRequired;
    evidence.background_denial = if (service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 20,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .background = true,
        .detail = "private camera background denial",
    }, &ledger)) |_| false else |err| err == error.BackgroundCaptureDenied;
    evidence.lease_policy_gate = if (service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 80,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera long lease denial",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;
    evidence.permission_policy_gate = if (service.start(&locked_policies, locked_subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 20,
        .now_ticks = 10,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private camera permission denial",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const expiring_session = service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 22,
        .now_ticks = 20,
        .sample_budget = 1,
        .indicator_visible = true,
        .detail = "private expiring camera session",
    }, &ledger) catch return evidence;
    evidence.indicator_expiry_boundary =
        expiring_session.active and
        service.activeSessionCountAt(21) == 1 and
        service.activeSessionCountAt(22) == 0 and
        service.privacyIndicatorActiveAt(.camera, 21) and
        !service.privacyIndicatorActiveAt(.camera, 22);

    const session = service.start(&policies, subjects, .{
        .subject = app,
        .task_id = 44,
        .device_id = 9,
        .kind = .camera,
        .foreground_session_id = 4,
        .expires_at_ticks = 35,
        .now_ticks = 11,
        .sample_budget = 2,
        .indicator_visible = true,
        .detail = "private camera session allowed",
    }, &ledger) catch return evidence;
    const wrong_binding_sample_denied = if (service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 10,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 12,
        .bytes = 1024,
        .detail = "private camera wrong binding sample",
    }, &ledger)) |_| false else |err| err == error.CaptureSessionBindingMismatch;
    evidence.session_binding_gate = wrong_binding_sample_denied and session.sample_count == 0;
    _ = service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 12,
        .bytes = 1024,
        .detail = "private camera sample one",
    }, &ledger) catch return evidence;
    _ = service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 13,
        .bytes = 1024,
        .detail = "private camera sample two",
    }, &ledger) catch return evidence;
    evidence.sample_budget_gate = if (service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 14,
        .bytes = 1024,
        .detail = "private camera over-budget sample",
    }, &ledger)) |_| false else |err| err == error.CaptureBudgetExceeded;
    _ = service.stop(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 15,
        .detail = "private camera stopped",
    }, &ledger) catch return evidence;
    evidence.revocation_gate = if (service.sample(.{
        .subject = app,
        .task_id = 44,
        .session_id = session.id,
        .expected_device_id = 9,
        .expected_foreground_session_id = 4,
        .expected_kind = .camera,
        .now_ticks = 16,
        .bytes = 1024,
        .detail = "private camera revoked sample",
    }, &ledger)) |_| false else |err| err == error.CaptureSessionRevoked;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.sensitive_capture_events >= 10 and
        summary.sensitive_capture_denials >= 6 and
        summary.sensitive_capture_background_denials >= 1;
    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.sensitive_capture_events and
        std.mem.indexOf(u8, exported, "private camera") == null and
        std.mem.indexOf(u8, exported, "kind=sensitive_capture") != null;
    return evidence;
}

fn capturePermission(kind: manifest.PermissionKind, resource: []const u8, lease_ticks: u64, reason: []const u8) manifest.PermissionRequest {
    return .{
        .kind = kind,
        .resource = resource,
        .rights = captureRights(kind),
        .required = true,
        .local_only = true,
        .max_lease_ticks = lease_ticks,
        .sensitivity = .private_user_data,
        .user_visible_reason = reason,
        .purpose = .media_capture,
        .retention_days = 0,
    };
}

fn captureRights(kind: manifest.PermissionKind) capability.CapabilityRights {
    return switch (kind) {
        .camera, .mic => .{ .device = .{ .device_use = true } },
        .location => .{ .device = .{ .location_read = true } },
        .sensor => .{ .device = .{ .sensor_read = true } },
        .screen_capture => .{ .device = .{ .screen_capture = true } },
        else => .{ .device = .{} },
    };
}

fn capturePermissionIsModern(request: manifest.PermissionRequest, kind: manifest.PermissionKind) bool {
    return request.kind == kind and
        request.local_only and
        request.max_lease_ticks != 0 and
        request.purpose == .media_capture and
        request.user_visible_reason.len != 0 and
        request.retention_days == 0 and
        request.sensitivity == .private_user_data;
}

fn captureBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.sensitive_capture, .sensitive_capture, "zigos.sensitive.capture");
}

fn captureBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.sensitive_capture, "zigos.system.sensitive-capture", "userspace-sensitive-capture.elf", "zigos.sensitive.capture");
}

const SecretVaultEvidence = struct {
    service_model: bool = false,
    hardware_sealed_import: bool = false,
    nonresident_material: bool = false,
    owner_binding: bool = false,
    leased_handle: bool = false,
    handle_expiry_boundary: bool = false,
    raw_export_denial: bool = false,
    raw_export_handle_capability_gate: bool = false,
    raw_export_success_audit: bool = false,
    store_handle_identity_binding: bool = false,
    rotation_revokes_old_handles: bool = false,
    explicit_revocation: bool = false,
    revoke_binding_gate: bool = false,
    hardware_policy_gate: bool = false,
    lease_policy_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryNineteenthContract() NineteenthChecklist {
    var features = [_]bool{false} ** nineteenth_feature_count;
    const evidence = secretVaultEvidence();

    features[@intFromEnum(NineteenthFeature.secret_vault_service_model)] = evidence.service_model;
    features[@intFromEnum(NineteenthFeature.hardware_sealed_import)] = evidence.hardware_sealed_import;
    features[@intFromEnum(NineteenthFeature.nonresident_secret_material)] = evidence.nonresident_material;
    features[@intFromEnum(NineteenthFeature.secret_owner_binding)] = evidence.owner_binding;
    features[@intFromEnum(NineteenthFeature.leased_handle_lending)] = evidence.leased_handle;
    features[@intFromEnum(NineteenthFeature.secret_handle_expiry_boundary)] = evidence.handle_expiry_boundary;
    features[@intFromEnum(NineteenthFeature.raw_export_policy_denial)] = evidence.raw_export_denial;
    features[@intFromEnum(NineteenthFeature.raw_export_handle_capability_gate)] = evidence.raw_export_handle_capability_gate;
    features[@intFromEnum(NineteenthFeature.raw_export_success_audit)] = evidence.raw_export_success_audit;
    features[@intFromEnum(NineteenthFeature.store_handle_identity_binding)] = evidence.store_handle_identity_binding;
    features[@intFromEnum(NineteenthFeature.secret_rotation_revokes_old_handles)] = evidence.rotation_revokes_old_handles;
    features[@intFromEnum(NineteenthFeature.explicit_handle_revocation)] = evidence.explicit_revocation;
    features[@intFromEnum(NineteenthFeature.secret_revoke_binding_gate)] =
        evidence.revoke_binding_gate and
        @hasField(typed_component_abi.SecretRevokeRequest, "subject_serial") and
        @hasField(typed_component_abi.SecretRevokeRequest, "subject_kind") and
        @hasField(typed_component_abi.SecretRevokeRequest, "expected_holder_serial") and
        @hasField(typed_component_abi.SecretRevokeRequest, "expected_holder_kind") and
        @hasField(typed_component_abi.SecretRevokeRequest, "expected_holder_task_id");
    features[@intFromEnum(NineteenthFeature.secret_hardware_policy_gate)] = evidence.hardware_policy_gate;
    features[@intFromEnum(NineteenthFeature.secret_lease_policy_gate)] = evidence.lease_policy_gate;
    features[@intFromEnum(NineteenthFeature.secret_vault_ledger)] =
        event_ledger.EventKind.secret_vault == .secret_vault and evidence.ledger;
    features[@intFromEnum(NineteenthFeature.secret_vault_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(NineteenthFeature.typed_secret_vault_service)] = contractPresent("zigos.secret.vault");
    features[@intFromEnum(NineteenthFeature.secret_import_operation)] = contractOperationPresent("zigos.secret.vault", .secret_import);
    features[@intFromEnum(NineteenthFeature.secret_lend_operation)] = contractOperationPresent("zigos.secret.vault", .secret_lend);
    features[@intFromEnum(NineteenthFeature.secret_rotate_operation)] = contractOperationPresent("zigos.secret.vault", .secret_rotate);
    features[@intFromEnum(NineteenthFeature.secret_revoke_operation)] = contractOperationPresent("zigos.secret.vault", .secret_revoke);
    features[@intFromEnum(NineteenthFeature.native_registry_secret_discovery)] =
        typed_component_abi.interfaceId(.secret_vault) == .secret_vault;
    features[@intFromEnum(NineteenthFeature.secret_vault_bootstrap_contract)] = secretVaultBootstrapContractCheck();
    features[@intFromEnum(NineteenthFeature.secret_vault_boot_image_registry)] = secretVaultBootImageRegistryCheck();
    return .{ .satisfied_features = features };
}

fn secretVaultContractHardwareSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "secret-vault-contract-provider", label);
    crypto_hash.updateBytes(&hasher, "secret-vault-contract-seal", raw);
    return crypto_hash.finalize(&hasher);
}

fn secretVaultContractHardwareProvider() secure_secret_store.HardwareSealProvider {
    return .{
        .available = true,
        .sealFn = secretVaultContractHardwareSeal,
    };
}

fn secretVaultEvidence() SecretVaultEvidence {
    var evidence = SecretVaultEvidence{
        .service_model = @hasDecl(secret_vault_service.Service, "importSecret") and
            @hasDecl(secret_vault_service.Service, "lendHandle") and
            @hasDecl(secret_vault_service.Service, "exportRaw") and
            @hasDecl(secret_vault_service.Service, "rotateSecret") and
            @hasDecl(secret_vault_service.Service, "revoke") and
            @hasField(secret_vault_service.VaultHandle, "expires_at_ticks"),
    };

    const user = principal.PrincipalId{ .kind = .user, .serial = 501 };
    const other_user = principal.PrincipalId{ .kind = .user, .serial = 503 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 502 };
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 501 },
        .label = "secret-vault-contract",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = true,
        .max_secret_handle_lease_ticks = 30,
    }, .{
        .label = "secret-vault-policy",
        .seed = signing.seedFromByte(0xDE),
    }) catch return evidence;

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = secret_vault_service.Service.init();
    service.attachHardwareProvider(secretVaultContractHardwareProvider());
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    evidence.hardware_policy_gate = if (service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 81,
        .label = "software-token",
        .raw = "private software secret",
        .hardware_backed = false,
        .now_ticks = 1,
        .detail = "private software secret denied",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const secret = service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 81,
        .label = "api-token",
        .raw = "private api secret v1",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 2,
        .detail = "private api secret imported",
    }, &ledger) catch return evidence;
    evidence.hardware_sealed_import = secret.hardware_backed and
        secret.hardware_provider_used and
        secret.sealed_digest_present;
    evidence.nonresident_material = !secret.resident_material and secret.value_len == 0;
    const wrong_owner_lend_denied = if (service.lendHandle(&policies, subjects, .{
        .owner = other_user,
        .holder = app,
        .task_id = 82,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 3,
        .detail = "private api secret wrong owner lend",
    }, &ledger)) |_| false else |err| err == error.SecretOwnerMismatch;
    const wrong_owner_rotate_denied = if (service.rotateSecret(&policies, subjects, .{
        .owner = other_user,
        .task_id = 81,
        .old_secret_id = secret.id,
        .label = "api-token",
        .raw = "private api secret wrong owner",
        .hardware_backed = true,
        .now_ticks = 3,
        .detail = "private api secret wrong owner rotate",
    }, &ledger)) |_| false else |err| err == error.SecretOwnerMismatch;
    evidence.owner_binding =
        @hasDecl(secure_secret_store.Store, "describeSecret") and
        wrong_owner_lend_denied and
        wrong_owner_rotate_denied;

    evidence.lease_policy_gate = if (service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 82,
        .secret_id = secret.id,
        .expires_at_ticks = 80,
        .now_ticks = 3,
        .detail = "private api secret long lease denied",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const handle = service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 82,
        .secret_id = secret.id,
        .expires_at_ticks = 24,
        .now_ticks = 4,
        .detail = "private api secret handle lent",
    }, &ledger) catch return evidence;
    const old_handle_id = handle.id;
    evidence.leased_handle = handle.hardware_backed and
        !handle.raw_export_allowed and
        handle.expires_at_ticks == 24 and
        service.activeHandleCount() == 1;

    var expiry_service = secret_vault_service.Service.init();
    expiry_service.attachHardwareProvider(secretVaultContractHardwareProvider());
    var expiry_ledger = event_ledger.Ledger.init();
    defer expiry_ledger.deinit();
    const expiring_secret = expiry_service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 83,
        .label = "expiring-token",
        .raw = "private expiring api secret",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 11,
        .detail = "private expiring api secret imported",
    }, &expiry_ledger) catch return evidence;
    const expiring_handle = expiry_service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 84,
        .secret_id = expiring_secret.id,
        .expires_at_ticks = 20,
        .now_ticks = 12,
        .detail = "private expiring api secret lent",
    }, &expiry_ledger) catch return evidence;
    evidence.handle_expiry_boundary =
        @hasDecl(secret_vault_service.Service, "activeHandleCountAt") and
        expiry_service.activeHandleCountAt(19) == 1 and
        expiry_service.activeHandleCountAt(20) == 0 and
        (if (expiry_service.exportRaw(&policies, subjects, .{
            .holder = app,
            .task_id = 84,
            .handle_id = expiring_handle.id,
            .now_ticks = 20,
            .detail = "private expiring api secret boundary export",
        }, &expiry_ledger)) |_| false else |err| err == error.HandleExpired);

    evidence.raw_export_denial = if (service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 82,
        .handle_id = old_handle_id,
        .now_ticks = 5,
        .detail = "private api secret raw export denied",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    var export_policies = policy_object.Directory.init();
    _ = export_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 504 },
        .label = "secret-vault-export-contract",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = false,
        .max_secret_handle_lease_ticks = 30,
    }, .{
        .label = "secret-vault-export-policy",
        .seed = signing.seedFromByte(0xdf),
    }) catch return evidence;
    var export_service = secret_vault_service.Service.init();
    export_service.attachHardwareProvider(secretVaultContractHardwareProvider());
    var export_ledger = event_ledger.Ledger.init();
    defer export_ledger.deinit();
    const sealed_only = export_service.importSecret(&export_policies, subjects, .{
        .owner = user,
        .task_id = 85,
        .label = "sealed-only-token",
        .raw = "private sealed-only api secret",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 13,
        .detail = "private sealed-only api secret imported",
    }, &export_ledger) catch return evidence;
    const sealed_only_handle = export_service.lendHandle(&export_policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 86,
        .secret_id = sealed_only.id,
        .expires_at_ticks = 20,
        .now_ticks = 14,
        .allow_raw_export = true,
        .detail = "private sealed-only api secret lent",
    }, &export_ledger) catch return evidence;
    const sealed_only_export_denied = if (export_service.exportRaw(&export_policies, subjects, .{
        .holder = app,
        .task_id = 86,
        .handle_id = sealed_only_handle.id,
        .now_ticks = 15,
        .detail = "private sealed-only api secret export",
    }, &export_ledger)) |_| false else |err| err == error.RawExportDenied;
    const export_summary = export_ledger.userVisibleDiagnosticSummary();
    evidence.raw_export_handle_capability_gate =
        !sealed_only_handle.raw_export_allowed and
        sealed_only_export_denied and
        export_summary.secret_vault_events == 3 and
        export_summary.secret_vault_denials == 1 and
        export_summary.secret_vault_raw_export_denials == 1;

    const portable_secret = export_service.importSecret(&export_policies, subjects, .{
        .owner = user,
        .task_id = 87,
        .label = "portable-token",
        .raw = "private portable api secret",
        .hardware_backed = true,
        .exportable = true,
        .now_ticks = 16,
        .detail = "private portable api secret imported",
    }, &export_ledger) catch return evidence;
    const portable_handle = export_service.lendHandle(&export_policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 88,
        .secret_id = portable_secret.id,
        .expires_at_ticks = 24,
        .now_ticks = 17,
        .allow_raw_export = true,
        .detail = "private portable api secret lent",
    }, &export_ledger) catch return evidence;
    const portable_raw = export_service.exportRaw(&export_policies, subjects, .{
        .holder = app,
        .task_id = 88,
        .handle_id = portable_handle.id,
        .now_ticks = 18,
        .detail = "private portable api secret exported",
    }, &export_ledger) catch return evidence;
    const export_success_summary = export_ledger.userVisibleDiagnosticSummary();
    var export_diag_buffer: [2048]u8 = undefined;
    const export_diag = export_ledger.exportText(&export_diag_buffer, .{}) catch return evidence;
    evidence.raw_export_success_audit =
        portable_handle.raw_export_allowed and
        std.mem.eql(u8, portable_raw, "private portable api secret") and
        export_success_summary.secret_vault_events == 6 and
        export_success_summary.secret_vault_denials == 1 and
        export_success_summary.secret_vault_raw_export_denials == 1 and
        export_success_summary.protected_details_redacted >= export_success_summary.secret_vault_events and
        std.mem.indexOf(u8, export_diag, "private portable api secret") == null and
        std.mem.indexOf(u8, export_diag, "kind=secret_vault") != null;

    var direct_store = secure_secret_store.Store.init();
    const direct_secret = direct_store.importSecret(
        user,
        "portable-recovery-token",
        "portable recovery token",
        false,
        true,
    ) catch return evidence;
    const direct_handle = direct_store.lendHandle(direct_secret.id, app, 87, true) catch return evidence;
    const wrong_store_holder_denied = if (direct_store.exportRaw(direct_handle.id, .{
        .holder = user,
        .task_id = 87,
    })) |_| false else |err| err == error.HandleHolderMismatch;
    const wrong_store_task_denied = if (direct_store.exportRaw(direct_handle.id, .{
        .holder = app,
        .task_id = 88,
    })) |_| false else |err| err == error.HandleHolderMismatch;
    const direct_raw = direct_store.exportRaw(direct_handle.id, .{
        .holder = app,
        .task_id = 87,
    }) catch return evidence;
    evidence.store_handle_identity_binding =
        @hasDecl(secure_secret_store, "ExportContext") and
        wrong_store_holder_denied and
        wrong_store_task_denied and
        std.mem.eql(u8, direct_raw, "portable recovery token");

    const rotated = service.rotateSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 81,
        .old_secret_id = secret.id,
        .label = "api-token",
        .raw = "private api secret v2",
        .hardware_backed = true,
        .now_ticks = 6,
        .detail = "private api secret rotated",
    }, &ledger) catch return evidence;
    evidence.rotation_revokes_old_handles = rotated.id != secret.id and
        service.activeHandleCount() == 0 and
        (if (service.exportRaw(&policies, subjects, .{
            .holder = app,
            .task_id = 82,
            .handle_id = old_handle_id,
            .now_ticks = 7,
            .detail = "private api secret old handle revoked",
        }, &ledger)) |_| false else |err| err == error.HandleRevoked);

    const rotated_handle = service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 82,
        .secret_id = rotated.id,
        .expires_at_ticks = 22,
        .now_ticks = 8,
        .detail = "private api secret v2 handle lent",
    }, &ledger) catch return evidence;
    const wrong_revoke_secret_denied = if (service.revoke(.{
        .subject = user,
        .task_id = 81,
        .handle_id = rotated_handle.id,
        .secret_id = secret.id,
        .expected_holder = app,
        .expected_holder_task_id = 82,
        .now_ticks = 9,
        .detail = "private api secret wrong secret revoke",
    }, &ledger)) |_| false else |err| err == error.SecretRevokeBindingMismatch;
    const wrong_revoke_owner_denied = if (service.revoke(.{
        .subject = other_user,
        .task_id = 81,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 82,
        .now_ticks = 9,
        .detail = "private api secret wrong owner revoke",
    }, &ledger)) |_| false else |err| err == error.SecretOwnerMismatch;
    const wrong_revoke_holder_denied = if (service.revoke(.{
        .subject = user,
        .task_id = 81,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 83,
        .now_ticks = 9,
        .detail = "private api secret wrong holder revoke",
    }, &ledger)) |_| false else |err| err == error.SecretRevokeBindingMismatch;
    evidence.revoke_binding_gate =
        @hasField(secret_vault_service.RevokeRequest, "expected_holder") and
        @hasField(secret_vault_service.RevokeRequest, "expected_holder_task_id") and
        wrong_revoke_secret_denied and
        wrong_revoke_owner_denied and
        wrong_revoke_holder_denied and
        service.activeHandleCount() == 1;
    service.revoke(.{
        .subject = user,
        .task_id = 81,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 82,
        .now_ticks = 9,
        .detail = "private api secret v2 revoked",
    }, &ledger) catch return evidence;
    evidence.explicit_revocation = service.activeHandleCount() == 0 and
        (if (service.exportRaw(&policies, subjects, .{
            .holder = app,
            .task_id = 82,
            .handle_id = rotated_handle.id,
            .now_ticks = 10,
            .detail = "private api secret v2 revoked export",
        }, &ledger)) |_| false else |err| err == error.HandleRevoked);

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.secret_vault_events >= 9 and
        summary.secret_vault_denials >= 4 and
        summary.secret_vault_raw_export_denials >= 1 and
        summary.secret_vault_rotations >= 1 and
        summary.secret_vault_revocations >= 1;
    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.secret_vault_events and
        std.mem.indexOf(u8, exported, "private api secret") == null and
        std.mem.indexOf(u8, exported, "kind=secret_vault") != null;
    return evidence;
}

fn secretVaultBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.secret_vault, .secret_vault, "zigos.secret.vault");
}

fn secretVaultBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.secret_vault, "zigos.system.secret-vault", "userspace-secret-vault.elf", "zigos.secret.vault");
}

const AttentionBrokerEvidence = struct {
    service_model: bool = false,
    brokered_post: bool = false,
    default_task_binding: bool = false,
    quiet_denial: bool = false,
    critical_denial: bool = false,
    visible_budget_denial: bool = false,
    interruption_budget_denial: bool = false,
    dismissal: bool = false,
    task_bound_dismissal: bool = false,
    strict_expiry_boundary: bool = false,
    latest_query: bool = false,
    policy_gate: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryTwentiethContract() TwentiethChecklist {
    var features = [_]bool{false} ** twentieth_feature_count;
    const evidence = attentionBrokerEvidence();

    features[@intFromEnum(TwentiethFeature.attention_broker_service_model)] = evidence.service_model;
    features[@intFromEnum(TwentiethFeature.brokered_notification_post)] = evidence.brokered_post;
    features[@intFromEnum(TwentiethFeature.notification_default_task_binding)] =
        evidence.default_task_binding and
        @hasField(typed_component_abi.AttentionDismissRequest, "expected_source_serial") and
        @hasField(typed_component_abi.AttentionDismissRequest, "expected_source_kind") and
        @hasField(typed_component_abi.AttentionDismissRequest, "expected_notification_task_id");
    features[@intFromEnum(TwentiethFeature.quiet_interrupt_denial)] = evidence.quiet_denial;
    features[@intFromEnum(TwentiethFeature.critical_interrupt_denial)] = evidence.critical_denial;
    features[@intFromEnum(TwentiethFeature.visible_budget_denial)] = evidence.visible_budget_denial;
    features[@intFromEnum(TwentiethFeature.interruption_budget_denial)] = evidence.interruption_budget_denial;
    features[@intFromEnum(TwentiethFeature.notification_dismissal)] = evidence.dismissal;
    features[@intFromEnum(TwentiethFeature.notification_task_bound_dismissal)] = evidence.task_bound_dismissal;
    features[@intFromEnum(TwentiethFeature.notification_strict_expiry_boundary)] = evidence.strict_expiry_boundary;
    features[@intFromEnum(TwentiethFeature.latest_visible_query)] = evidence.latest_query;
    features[@intFromEnum(TwentiethFeature.attention_broker_policy_gate)] = evidence.policy_gate;
    features[@intFromEnum(TwentiethFeature.attention_broker_ledger)] =
        event_ledger.EventKind.attention_policy == .attention_policy and evidence.ledger;
    features[@intFromEnum(TwentiethFeature.attention_broker_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentiethFeature.typed_attention_broker_service)] = contractPresent("zigos.attention.broker");
    features[@intFromEnum(TwentiethFeature.attention_post_operation)] = contractOperationPresent("zigos.attention.broker", .attention_post);
    features[@intFromEnum(TwentiethFeature.attention_dismiss_operation)] = contractOperationPresent("zigos.attention.broker", .attention_dismiss);
    features[@intFromEnum(TwentiethFeature.attention_query_operation)] = contractOperationPresent("zigos.attention.broker", .attention_query);
    features[@intFromEnum(TwentiethFeature.native_registry_attention_discovery)] =
        typed_component_abi.interfaceId(.attention_broker) == .attention_broker;
    features[@intFromEnum(TwentiethFeature.attention_broker_bootstrap_contract)] = attentionBrokerBootstrapContractCheck();
    features[@intFromEnum(TwentiethFeature.attention_broker_boot_image_registry)] = attentionBrokerBootImageRegistryCheck();
    return .{ .satisfied_features = features };
}

fn attentionBrokerEvidence() AttentionBrokerEvidence {
    var evidence = AttentionBrokerEvidence{
        .service_model = @hasDecl(attention_broker_service.Service, "post") and
            @hasDecl(attention_broker_service.Service, "dismiss") and
            @hasDecl(attention_broker_service.Service, "query"),
    };

    const user = principal.PrincipalId{ .kind = .user, .serial = 741 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 742 };
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 741 },
        .label = "attention-broker-contract",
        .quiet_until_tick = 50,
        .max_visible_notifications = 2,
        .max_interruptive_notifications = 1,
        .allow_critical_interruption = false,
    }, .{
        .label = "attention-broker-policy",
        .seed = signing.seedFromByte(0xA7),
    }) catch return evidence;

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = attention_broker_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    var expiry_service = attention_broker_service.Service.init();
    var expiry_ledger = event_ledger.Ledger.init();
    defer expiry_ledger.deinit();
    const expiring = expiry_service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 94,
        .reason = .policy_notice,
        .urgency = .passive,
        .expires_at_ticks = 70,
        .detail = "private expiring attention detail",
        .now_ticks = 68,
    }, &expiry_ledger) catch return evidence;
    const expired_query = expiry_service.query(.{
        .subject = user,
        .task_id = 95,
        .now_ticks = 70,
        .detail = "query expired notification",
    }, &expiry_ledger) catch return evidence;
    evidence.strict_expiry_boundary =
        expiring.isActive(69) and
        !expiring.isActive(70) and
        expiry_service.activeVisible(69) == 1 and
        expiry_service.activeVisible(70) == 0 and
        expired_query.latest == null;

    const missing_task_denied = if (service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 0,
        .reason = .policy_notice,
        .urgency = .passive,
        .detail = "private missing task binding detail",
        .now_ticks = 9,
    }, &ledger)) |_| false else |err| err == error.MissingTaskBinding;

    const passive = service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .policy_notice,
        .urgency = .passive,
        .detail = "private passive attention detail",
        .now_ticks = 10,
    }, &ledger) catch return evidence;
    evidence.brokered_post = passive.id != 0 and service.activeVisible(10) == 1;
    evidence.default_task_binding = missing_task_denied and
        passive.taskId() != null and
        passive.taskId().? == 91;

    evidence.quiet_denial = if (service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .driver_restart,
        .urgency = .high,
        .detail = "private quiet denial detail",
        .now_ticks = 20,
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    evidence.critical_denial = if (service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .driver_restart,
        .urgency = .critical,
        .detail = "private critical denial detail",
        .now_ticks = 21,
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const high = service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .sync_conflict,
        .urgency = .high,
        .notification_task_id = 92,
        .detail = "private conflict attention detail",
        .now_ticks = 60,
    }, &ledger) catch return evidence;

    const query = service.query(.{
        .subject = user,
        .task_id = 93,
        .now_ticks = 61,
        .detail = "query latest visible notification",
    }, &ledger) catch return evidence;
    evidence.latest_query = query.latest != null and
        query.latest.?.id == high.id and
        query.active_visible == 2 and
        query.active_interruptions == 1;

    evidence.visible_budget_denial = if (service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .update_ready,
        .urgency = .normal,
        .detail = "private visible budget denial detail",
        .now_ticks = 62,
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const wrong_task_dismiss_denied = if (service.dismiss(.{
        .subject = app,
        .task_id = 91,
        .notification_id = high.id,
        .now_ticks = 63,
        .detail = "wrong task dismiss denied",
    }, &ledger)) |_| false else |err| err == error.NotificationTaskMismatch;

    const wrong_default_task_dismiss_denied = if (service.dismiss(.{
        .subject = app,
        .task_id = 92,
        .notification_id = passive.id,
        .now_ticks = 64,
        .detail = "wrong default task dismiss denied",
    }, &ledger)) |_| false else |err| err == error.NotificationTaskMismatch;
    evidence.default_task_binding = evidence.default_task_binding and
        wrong_default_task_dismiss_denied and
        service.activeVisible(64) == 2;

    const dismissed = service.dismiss(.{
        .subject = app,
        .task_id = 91,
        .notification_id = passive.id,
        .now_ticks = 65,
        .detail = "dismiss passive notification",
    }, &ledger) catch return evidence;
    evidence.dismissal = dismissed.suppressed and service.activeVisible(65) == 1;

    evidence.interruption_budget_denial = if (service.post(&policies, subjects, .{
        .subject = app,
        .task_id = 91,
        .reason = .update_ready,
        .urgency = .high,
        .detail = "private interruption budget denial detail",
        .now_ticks = 66,
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;
    const task_dismissed = service.dismiss(.{
        .subject = app,
        .task_id = 92,
        .notification_id = high.id,
        .now_ticks = 67,
        .detail = "task-bound dismiss",
    }, &ledger) catch return evidence;
    evidence.task_bound_dismissal = wrong_task_dismiss_denied and task_dismissed.suppressed;
    evidence.policy_gate = evidence.quiet_denial and
        evidence.critical_denial and
        evidence.visible_budget_denial and
        evidence.interruption_budget_denial;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.attention_policy_events >= 8 and
        summary.attention_interruptions_denied >= 3;
    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.attention_policy_events and
        std.mem.indexOf(u8, exported, "private quiet denial detail") == null and
        std.mem.indexOf(u8, exported, "private critical denial detail") == null and
        std.mem.indexOf(u8, exported, "private interruption budget denial detail") == null and
        std.mem.indexOf(u8, exported, "kind=attention_policy") != null;
    return evidence;
}

fn attentionBrokerBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.attention_broker, .attention_broker, "zigos.attention.broker");
}

fn attentionBrokerBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.attention_broker, "zigos.system.attention-broker", "userspace-attention-broker.elf", "zigos.attention.broker");
}

const TaskLifecycleEvidence = struct {
    service_model: bool = false,
    task_suspend: bool = false,
    invalid_task_suspend_denial: bool = false,
    task_resume: bool = false,
    checkpoint_denial: bool = false,
    task_terminate: bool = false,
    target_owner_binding: bool = false,
    policy_gate: bool = false,
    runtime_audit: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
    policy_digest: bool = false,
};

pub fn currentRepositoryTwentyFirstContract() TwentyFirstChecklist {
    var features = [_]bool{false} ** twenty_first_feature_count;
    const evidence = taskLifecycleEvidence();

    features[@intFromEnum(TwentyFirstFeature.task_lifecycle_service_model)] = evidence.service_model;
    features[@intFromEnum(TwentyFirstFeature.brokered_task_suspend)] = evidence.task_suspend;
    features[@intFromEnum(TwentyFirstFeature.invalid_suspend_denial)] = evidence.invalid_task_suspend_denial;
    features[@intFromEnum(TwentyFirstFeature.brokered_task_resume)] = evidence.task_resume;
    features[@intFromEnum(TwentyFirstFeature.terminate_checkpoint_policy_denial)] = evidence.checkpoint_denial;
    features[@intFromEnum(TwentyFirstFeature.brokered_task_terminate)] = evidence.task_terminate;
    features[@intFromEnum(TwentyFirstFeature.lifecycle_target_owner_binding)] =
        evidence.target_owner_binding and
        @hasField(typed_component_abi.LifecycleControlRequest, "target_owner_serial") and
        @hasField(typed_component_abi.LifecycleControlRequest, "target_owner_kind");
    features[@intFromEnum(TwentyFirstFeature.task_lifecycle_policy_gate)] = evidence.policy_gate;
    features[@intFromEnum(TwentyFirstFeature.task_lifecycle_runtime_audit)] = evidence.runtime_audit;
    features[@intFromEnum(TwentyFirstFeature.task_lifecycle_ledger)] =
        event_ledger.EventKind.task_lifecycle == .task_lifecycle and evidence.ledger;
    features[@intFromEnum(TwentyFirstFeature.task_lifecycle_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentyFirstFeature.typed_task_lifecycle_service)] = contractPresent("zigos.task.lifecycle");
    features[@intFromEnum(TwentyFirstFeature.lifecycle_suspend_operation)] = contractOperationPresent("zigos.task.lifecycle", .lifecycle_suspend);
    features[@intFromEnum(TwentyFirstFeature.lifecycle_resume_operation)] = contractOperationPresent("zigos.task.lifecycle", .lifecycle_resume);
    features[@intFromEnum(TwentyFirstFeature.lifecycle_terminate_operation)] = contractOperationPresent("zigos.task.lifecycle", .lifecycle_terminate);
    features[@intFromEnum(TwentyFirstFeature.native_registry_lifecycle_discovery)] =
        typed_component_abi.interfaceId(.task_lifecycle) == .task_lifecycle;
    features[@intFromEnum(TwentyFirstFeature.lifecycle_bootstrap_contract)] = taskLifecycleBootstrapContractCheck();
    features[@intFromEnum(TwentyFirstFeature.lifecycle_boot_image_registry)] = taskLifecycleBootImageRegistryCheck();
    features[@intFromEnum(TwentyFirstFeature.lifecycle_policy_digest)] = evidence.policy_digest;
    return .{ .satisfied_features = features };
}

fn taskLifecycleEvidence() TaskLifecycleEvidence {
    var evidence = TaskLifecycleEvidence{
        .service_model = @hasDecl(task_lifecycle_service.Service, "control") and
            @hasDecl(task_runtime.Runtime, "suspendTask") and
            @hasDecl(task_runtime.Runtime, "resumeTask"),
    };

    var runtime = task_runtime.Runtime.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 751 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 752 };
    const task = runtime.createTask(.{
        .owner = app,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(16),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(4),
            .background_allowed = false,
        },
        .local_only = true,
    }) catch return evidence;

    var policies = policy_object.Directory.init();
    const lifecycle_policy = policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 751 },
        .label = "task-lifecycle-contract",
        .task_lifecycle_allowed = true,
        .require_lifecycle_checkpoint_before_terminate = true,
    }, .{
        .label = "task-lifecycle-policy",
        .seed = signing.seedFromByte(0xB1),
    }) catch return evidence;
    evidence.policy_digest = policies.verify(lifecycle_policy.id);

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = task_lifecycle_service.Service.init(&runtime);
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    evidence.target_owner_binding = if (service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = user,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 19,
        .detail = "private lifecycle wrong-owner detail",
    }, &ledger)) |_| false else |err| err == error.TaskOwnerMismatch;
    if ((runtime.find(task.id) orelse return evidence).state != .active) return evidence;

    const suspended = service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 20,
        .detail = "private lifecycle suspend detail",
    }, &ledger) catch return evidence;
    evidence.task_suspend = suspended.state == .suspended;
    const suspend_audited = (runtime.find(task.id) orelse return evidence).latestAuditEvent().?.kind == .suspended;

    evidence.invalid_task_suspend_denial = if (service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .suspend_task,
        .now_ticks = 21,
        .detail = "private lifecycle duplicate suspend detail",
    }, &ledger)) |_| false else |err| err == error.InvalidLifecycleTransition;

    const resumed = service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .resume_task,
        .now_ticks = 22,
        .detail = "private lifecycle resume detail",
    }, &ledger) catch return evidence;
    evidence.task_resume = resumed.state == .active;
    const resume_audited = (runtime.find(task.id) orelse return evidence).latestAuditEvent().?.kind == .resumed;

    evidence.checkpoint_denial = if (service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .terminate_task,
        .now_ticks = 23,
        .detail = "private lifecycle terminate without checkpoint detail",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;

    const terminated = service.control(&policies, subjects, .{
        .subject = user,
        .target_owner = app,
        .task_id = task.id,
        .operation = .terminate_task,
        .checkpoint_present = true,
        .now_ticks = 24,
        .detail = "private lifecycle terminate after checkpoint detail",
    }, &ledger) catch return evidence;
    evidence.task_terminate = terminated.state == .terminated;
    const terminate_audited = (runtime.find(task.id) orelse return evidence).latestAuditEvent().?.kind == .terminated;
    evidence.policy_gate = evidence.checkpoint_denial and
        !policies.lifecycleDecision(subjects, .{ .operation = .terminate_task }).allowed and
        policies.lifecycleDecision(subjects, .{ .operation = .terminate_task, .checkpoint_present = true }).allowed;

    evidence.runtime_audit = suspend_audited and resume_audited and terminate_audited;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.task_lifecycle_events >= 6 and
        summary.task_lifecycle_denials >= 3 and
        summary.task_lifecycle_terminations == 1;
    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.task_lifecycle_events and
        std.mem.indexOf(u8, exported, "private lifecycle suspend detail") == null and
        std.mem.indexOf(u8, exported, "private lifecycle terminate after checkpoint detail") == null and
        std.mem.indexOf(u8, exported, "kind=task_lifecycle") != null;
    return evidence;
}

fn taskLifecycleBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.task_lifecycle, .task_lifecycle, "zigos.task.lifecycle");
}

fn taskLifecycleBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.task_lifecycle, "zigos.system.task-lifecycle", "userspace-task-lifecycle.elf", "zigos.task.lifecycle");
}

const PackageOffboardingEvidence = struct {
    service_model: bool = false,
    policy_gate: bool = false,
    receipt_required: bool = false,
    denied_preserves_install: bool = false,
    package_removed: bool = false,
    result_receipt: bool = false,
    removed_bundle_digest: bool = false,
    removed_bundle_digest_content_binding: bool = false,
    revision_purge: bool = false,
    unlaunchable: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
    policy_digest: bool = false,
};

pub fn currentRepositoryTwentySecondContract() TwentySecondChecklist {
    var features = [_]bool{false} ** twenty_second_feature_count;
    const evidence = packageOffboardingEvidence();

    features[@intFromEnum(TwentySecondFeature.package_offboarding_service_model)] = evidence.service_model;
    features[@intFromEnum(TwentySecondFeature.package_port_offboarding_authority_path)] =
        @hasDecl(package_service.PackagePort, "offboard");
    features[@intFromEnum(TwentySecondFeature.offboard_policy_delete_gate)] = evidence.policy_gate;
    features[@intFromEnum(TwentySecondFeature.offboard_receipt_required)] = evidence.receipt_required;
    features[@intFromEnum(TwentySecondFeature.denied_offboard_preserves_install)] = evidence.denied_preserves_install;
    features[@intFromEnum(TwentySecondFeature.receipt_backed_package_remove)] = evidence.package_removed;
    features[@intFromEnum(TwentySecondFeature.offboard_result_receipt)] = evidence.result_receipt;
    features[@intFromEnum(TwentySecondFeature.offboard_removed_bundle_digest)] = evidence.removed_bundle_digest;
    features[@intFromEnum(TwentySecondFeature.offboard_removed_bundle_digest_content_binding)] = evidence.removed_bundle_digest_content_binding;
    features[@intFromEnum(TwentySecondFeature.offboard_revision_purge)] = evidence.revision_purge;
    features[@intFromEnum(TwentySecondFeature.removed_bundle_unlaunchable)] = evidence.unlaunchable;
    features[@intFromEnum(TwentySecondFeature.offboard_data_deletion_ledger)] =
        event_ledger.EventKind.data_deletion == .data_deletion and evidence.ledger;
    features[@intFromEnum(TwentySecondFeature.offboard_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentySecondFeature.typed_package_remove_operation)] =
        contractOperationPresent("zigos.package.install", .package_remove);
    features[@intFromEnum(TwentySecondFeature.package_remove_operation_id)] =
        typed_component_abi.OperationId.package_remove == .package_remove and
        @intFromEnum(typed_component_abi.OperationId.package_remove) == 0x0604;
    features[@intFromEnum(TwentySecondFeature.package_remove_wire_validation)] = packageRemoveWireValidationCheck();
    features[@intFromEnum(TwentySecondFeature.package_registry_discovery)] =
        userspace_registry.findByServiceClass(.package_install_update) != null and
        typed_component_abi.interfaceId(.package_install) == .package_install;
    features[@intFromEnum(TwentySecondFeature.package_offboard_policy_digest)] = evidence.policy_digest;
    return .{ .satisfied_features = features };
}

fn packageOffboardingEvidence() PackageOffboardingEvidence {
    var evidence = PackageOffboardingEvidence{
        .service_model = @hasDecl(package_service.Service, "offboard") and
            @hasDecl(package_service, "OffboardRequest") and
            @hasDecl(package_service, "OffboardResult"),
    };

    var service = package_service.Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "contract-offboard-bundle",
        .seed = signing.seedFromByte(0xB2),
    };
    package_service.testingTrustPublisher(&service, signer_identity, "zigos.dev") catch return evidence;

    var bundle = @import("../policy/manifest_fixtures.zig").notesBundle();
    bundle.signature = signing.signWithDefaultRegistry(.ed25519, signer_identity, &package_service.digestBundle(bundle)) catch return evidence;
    const installed = service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null) catch return evidence;
    if (!installed.installed_new) return evidence;

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 761 };
    const policy = policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 761 },
        .label = "package-offboarding-contract",
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = true,
    }, .{
        .label = "package-offboarding-policy",
        .seed = signing.seedFromByte(0xB3),
    }) catch return evidence;
    evidence.policy_digest = policies.verify(policy.id);
    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    evidence.receipt_required = !policies.dataRightsDecision(subjects, .{
        .operation = .delete,
        .sensitivity = .private_user_data,
    }).allowed;

    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    evidence.policy_gate = if (service.offboard(&policies, subjects, .{
        .subject = user,
        .task_id = 7601,
        .bundle_id = "app.notes",
        .sensitivity = .private_user_data,
        .bytes = units.kibibytes(64),
        .now_ticks = 30,
        .detail = "private offboarding denial detail",
    }, &ledger)) |_| false else |err| err == error.PolicyDenied;
    evidence.denied_preserves_install = service.find("app.notes") != null;
    const installed_bundle = service.find("app.notes") orelse return evidence;
    const expected_removed_digest = package_service.offboardRemovedBundleDigest(installed_bundle);
    var altered_bundle = installed_bundle.*;
    const altered_revision = altered_bundle.activeRevisionMut();
    if (altered_revision.component_count != 0 and altered_revision.components[0].entry_len != 0) {
        altered_revision.components[0].entry[0] +%= 1;
    } else {
        altered_revision.data_rights.deletion_supported = !altered_revision.data_rights.deletion_supported;
    }
    const altered_removed_digest = package_service.offboardRemovedBundleDigest(&altered_bundle);
    evidence.removed_bundle_digest_content_binding = !std.mem.eql(u8, &expected_removed_digest, &altered_removed_digest);

    const result = service.offboard(&policies, subjects, .{
        .subject = user,
        .task_id = 7601,
        .bundle_id = "app.notes",
        .sensitivity = .private_user_data,
        .bytes = units.kibibytes(64),
        .deletion_receipt_id = 760_001,
        .now_ticks = 31,
        .detail = "private offboarding receipt detail",
    }, &ledger) catch return evidence;
    evidence.package_removed = result.removed_existing and service.find("app.notes") == null;
    evidence.result_receipt = result.deletion_receipt_id == 760_001;
    evidence.removed_bundle_digest =
        @hasField(package_service.OffboardResult, "removed_bundle_digest") and
        @hasField(typed_component_abi.PackageRemoveResponse, "removed_bundle_digest") and
        !std.mem.eql(u8, &result.removed_bundle_digest, &crypto_hash.zero_digest) and
        std.mem.eql(u8, &result.removed_bundle_digest, &expected_removed_digest);
    evidence.revision_purge = result.removed_revision_count >= 1;
    evidence.unlaunchable = if (service.buildLaunchPlan("app.notes")) |_| false else |err| err == error.BundleNotFound;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.data_deletion_events >= 2 and
        summary.data_deletion_denials >= 1 and
        summary.data_deletion_receipts >= 1;
    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= 2 and
        std.mem.indexOf(u8, exported, "private offboarding") == null and
        std.mem.indexOf(u8, exported, "kind=data_deletion") != null;
    return evidence;
}

fn packageRemoveWireValidationCheck() bool {
    const header = typed_component_abi.WireHeader{
        .operation = @intFromEnum(typed_component_abi.OperationId.package_remove),
        .correlation_id = 2026,
        .subject_task_id = 7601,
    };
    typed_component_abi.validateMessage(
        .package_install,
        .package_remove,
        header,
        @sizeOf(typed_component_abi.PackageRemoveRequest),
        @sizeOf(typed_component_abi.PackageRemoveResponse),
    ) catch return false;
    return true;
}

const ResourceGovernanceEvidence = struct {
    scheduler_model: bool = false,
    telemetry_provider_boundary: bool = false,
    hardware_evidence_required: bool = false,
    foreground_thermal_dispatch: bool = false,
    emergency_pressure_bypass: bool = false,
    background_thermal_delay: bool = false,
    batch_battery_delay: bool = false,
    batch_recovers_after_pressure: bool = false,
    pressure_reason_accounting: bool = false,
    dispatch_budget_accounting: bool = false,
    privacy_mode_degrades_accelerator: bool = false,
    carbon_aware_planner_compat: bool = false,
    ledger: bool = false,
    diagnostics: bool = false,
    redacted_diagnostics: bool = false,
    query_index: bool = false,
};

pub fn currentRepositoryTwentyThirdContract() TwentyThirdChecklist {
    var features = [_]bool{false} ** twenty_third_feature_count;
    const evidence = resourceGovernanceEvidence();

    features[@intFromEnum(TwentyThirdFeature.scheduler_resource_governance_model)] = evidence.scheduler_model;
    features[@intFromEnum(TwentyThirdFeature.hardware_telemetry_provider_boundary)] = evidence.telemetry_provider_boundary;
    features[@intFromEnum(TwentyThirdFeature.hardware_evidence_required_for_accelerator_queues)] = evidence.hardware_evidence_required;
    features[@intFromEnum(TwentyThirdFeature.foreground_thermal_dispatch)] = evidence.foreground_thermal_dispatch;
    features[@intFromEnum(TwentyThirdFeature.emergency_pressure_bypass)] = evidence.emergency_pressure_bypass;
    features[@intFromEnum(TwentyThirdFeature.background_thermal_delay)] = evidence.background_thermal_delay;
    features[@intFromEnum(TwentyThirdFeature.batch_battery_delay)] = evidence.batch_battery_delay;
    features[@intFromEnum(TwentyThirdFeature.batch_recovers_after_pressure)] = evidence.batch_recovers_after_pressure;
    features[@intFromEnum(TwentyThirdFeature.pressure_delay_reason_accounting)] = evidence.pressure_reason_accounting;
    features[@intFromEnum(TwentyThirdFeature.dispatch_budget_accounting)] = evidence.dispatch_budget_accounting;
    features[@intFromEnum(TwentyThirdFeature.privacy_mode_degrades_accelerator)] = evidence.privacy_mode_degrades_accelerator;
    features[@intFromEnum(TwentyThirdFeature.carbon_aware_planner_compat)] = evidence.carbon_aware_planner_compat;
    features[@intFromEnum(TwentyThirdFeature.resource_governance_ledger)] =
        event_ledger.EventKind.resource_governance == .resource_governance and evidence.ledger;
    features[@intFromEnum(TwentyThirdFeature.resource_governance_diagnostics)] = evidence.diagnostics;
    features[@intFromEnum(TwentyThirdFeature.resource_governance_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentyThirdFeature.resource_governance_query_index)] = evidence.query_index;
    return .{ .satisfied_features = features };
}

fn resourceGovernanceEvidence() ResourceGovernanceEvidence {
    var evidence = ResourceGovernanceEvidence{
        .scheduler_model = @hasDecl(userspace_scheduler.Scheduler, "configureResourceTelemetryFromProvider") and
            @hasDecl(userspace_scheduler.Scheduler, "taskDispatchStats") and
            @hasField(event_ledger.DiagnosticSummary, "resource_governance_events"),
        .carbon_aware_planner_compat = carbonAwareSchedulingBackedByPlanner(),
    };

    const incomplete_hardware_sample = accelerator_scheduler.TelemetrySample{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    };
    const complete_hardware_sample = accelerator_scheduler.TelemetrySample{
        .source = .hardware,
        .observed_tick = 2,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = resourceGovernanceHardwareEvidence(),
    };
    evidence.hardware_evidence_required =
        !incomplete_hardware_sample.hardwareReaderEvidenceComplete() and
        complete_hardware_sample.hardwareReaderEvidenceComplete();

    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const emergency = createResourceGovernanceTask(&runtime, 771, .emergency_system_critical, "svc.example.resource-critical", null) catch return evidence;
    const foreground = createResourceGovernanceTask(&runtime, 772, .foreground_interactive, "app.example.resource-foreground", 772) catch return evidence;
    const background = createResourceGovernanceTask(&runtime, 773, .background_light, "app.example.resource-background", null) catch return evidence;
    const batch = createResourceGovernanceTask(&runtime, 774, .batch_compute, "app.example.resource-batch", null) catch return evidence;

    const task_ids = [_]u64{ emergency.id, foreground.id, background.id, batch.id };
    for (task_ids) |task_id| {
        if (!scheduler.registerTask(task_id)) return evidence;
    }
    if (!scheduler.configureTaskDispatchRequest(background.id, .{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
        .shared_memory_bytes = units.kibibytes(8),
    }, false)) return evidence;

    var provider = accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(770, 7701, 10, .{
        .total_cpu_budget_ticks = 50_000,
        .memory_capacity_bytes = units.mebibytes(2),
        .thermal_milli_celsius = 92_000,
        .battery_percent = 90,
        .battery_charging = true,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = resourceGovernanceHardwareEvidence(),
    }) catch return evidence;
    const telemetry_provider = provider.telemetryProvider();
    evidence.telemetry_provider_boundary = !telemetry_provider.testOnly();
    scheduler.configureResourceTelemetryFromProvider(telemetry_provider);
    evidence.telemetry_provider_boundary = evidence.telemetry_provider_boundary and
        scheduler.observedResourceTelemetry() and
        scheduler.resource_telemetry_source == .hardware and
        scheduler.resource_hardware_evidence_complete and
        provider.read_count == 1;

    _ = scheduler.runNext(11);
    const emergency_stats = scheduler.taskDispatchStats(emergency.id) orelse return evidence;
    evidence.emergency_pressure_bypass =
        emergency_stats.dispatch_count == 1 and
        emergency_stats.last_dispatch_reason == .normal;

    _ = scheduler.runNext(12);
    const foreground_stats = scheduler.taskDispatchStats(foreground.id) orelse return evidence;
    evidence.foreground_thermal_dispatch =
        foreground_stats.dispatch_count == 1 and
        foreground_stats.last_dispatch_engine == .gpu and
        foreground_stats.last_dispatch_degraded and
        foreground_stats.last_dispatch_reason == .thermal_throttle;

    _ = scheduler.runNext(13);
    const thermal_background_stats = scheduler.taskDispatchStats(background.id) orelse return evidence;
    const thermal_batch_stats = scheduler.taskDispatchStats(batch.id) orelse return evidence;
    evidence.background_thermal_delay =
        thermal_background_stats.dispatch_count == 0 and
        thermal_background_stats.delayed_dispatch_count == 1 and
        thermal_background_stats.last_dispatch_reason == .thermal_throttle;
    const batch_thermal_delay =
        thermal_batch_stats.dispatch_count == 0 and
        thermal_batch_stats.delayed_dispatch_count == 1 and
        thermal_batch_stats.last_dispatch_reason == .thermal_throttle;

    provider.observeLive(7701, 14, .{
        .total_cpu_budget_ticks = 50_000,
        .memory_capacity_bytes = units.mebibytes(2),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 12,
        .battery_charging = false,
        .privacy_sensitive_task_count = 1,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = resourceGovernanceHardwareEvidence(),
    }) catch return evidence;
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    _ = scheduler.runNext(14);
    const privacy_background_stats = scheduler.taskDispatchStats(background.id) orelse return evidence;
    evidence.privacy_mode_degrades_accelerator =
        privacy_background_stats.dispatch_count == 1 and
        privacy_background_stats.last_dispatch_engine == .cpu and
        privacy_background_stats.last_dispatch_degraded and
        privacy_background_stats.last_dispatch_reason == .privacy_mode;

    _ = scheduler.runNext(15);
    const battery_batch_stats = scheduler.taskDispatchStats(batch.id) orelse return evidence;
    evidence.batch_battery_delay =
        battery_batch_stats.dispatch_count == 0 and
        battery_batch_stats.delayed_dispatch_count == 2 and
        battery_batch_stats.last_dispatch_reason == .battery_preserve;

    provider.observeLive(7701, 16, .{
        .total_cpu_budget_ticks = 50_000,
        .memory_capacity_bytes = units.mebibytes(2),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 80,
        .battery_charging = true,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = resourceGovernanceHardwareEvidence(),
    }) catch return evidence;
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    _ = scheduler.runNext(16);
    const recovered_batch_stats = scheduler.taskDispatchStats(batch.id) orelse return evidence;
    evidence.batch_recovers_after_pressure =
        recovered_batch_stats.dispatch_count == 1 and
        recovered_batch_stats.last_dispatch_engine == .npu;
    evidence.pressure_reason_accounting =
        batch_thermal_delay and
        evidence.background_thermal_delay and
        evidence.batch_battery_delay;
    evidence.dispatch_budget_accounting =
        scheduler.engineDispatchCount(.cpu) >= 2 and
        scheduler.engineDispatchCount(.gpu) == 1 and
        scheduler.engineDispatchCount(.npu) == 1 and
        scheduler.resource_state.cpu_budget_ticks < 50_000;

    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const user = principal.PrincipalId{ .kind = .user, .serial = 770 };
    ledger.recordResourceGovernance(
        user,
        foreground.id,
        foreground_stats.resource_class,
        foreground_stats.last_dispatch_reason,
        false,
        foreground_stats.last_dispatch_degraded,
        scheduler.observedResourceTelemetry(),
        scheduler.resource_hardware_evidence_complete,
        12,
        "private foreground thermal pressure detail",
    ) catch return evidence;
    ledger.recordResourceGovernance(
        user,
        background.id,
        thermal_background_stats.resource_class,
        thermal_background_stats.last_dispatch_reason,
        true,
        thermal_background_stats.last_dispatch_degraded,
        scheduler.observedResourceTelemetry(),
        scheduler.resource_hardware_evidence_complete,
        13,
        "private background thermal pressure detail",
    ) catch return evidence;
    ledger.recordResourceGovernance(
        user,
        background.id,
        privacy_background_stats.resource_class,
        privacy_background_stats.last_dispatch_reason,
        false,
        privacy_background_stats.last_dispatch_degraded,
        scheduler.observedResourceTelemetry(),
        scheduler.resource_hardware_evidence_complete,
        14,
        "private background privacy pressure detail",
    ) catch return evidence;
    ledger.recordResourceGovernance(
        user,
        batch.id,
        battery_batch_stats.resource_class,
        battery_batch_stats.last_dispatch_reason,
        true,
        battery_batch_stats.last_dispatch_degraded,
        scheduler.observedResourceTelemetry(),
        scheduler.resource_hardware_evidence_complete,
        15,
        "private batch battery pressure detail",
    ) catch return evidence;
    ledger.recordResourceGovernance(
        user,
        batch.id,
        recovered_batch_stats.resource_class,
        recovered_batch_stats.last_dispatch_reason,
        false,
        recovered_batch_stats.last_dispatch_degraded,
        scheduler.observedResourceTelemetry(),
        scheduler.resource_hardware_evidence_complete,
        16,
        "private batch recovered pressure detail",
    ) catch return evidence;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.resource_governance_events == 5 and
        summary.resource_governance_delays == 2 and
        summary.resource_governance_thermal_throttles == 2 and
        summary.resource_governance_battery_preserves == 1 and
        summary.resource_governance_hardware_evidence == 5;
    evidence.query_index =
        ledger.countMatching(.{ .kind = .resource_governance }) == 5 and
        ledger.countMatching(.{ .kind = .resource_governance, .task_id = batch.id }) == 2;

    var diagnostics_buffer: [4096]u8 = undefined;
    const diagnostics = ledger.renderUserVisibleDiagnosticsToBuffer(&diagnostics_buffer) catch return evidence;
    evidence.diagnostics =
        summary.evidenceEventCount() >= summary.resource_governance_events and
        std.mem.indexOf(u8, diagnostics, "resource_governance_events=5") != null and
        std.mem.indexOf(u8, diagnostics, "resource_governance_delays=2") != null;

    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.resource_governance_events and
        std.mem.indexOf(u8, exported, "private foreground thermal pressure detail") == null and
        std.mem.indexOf(u8, exported, "private batch battery pressure detail") == null and
        std.mem.indexOf(u8, exported, "kind=resource_governance") != null and
        std.mem.indexOf(u8, exported, "detail=redacted") != null;
    return evidence;
}

fn createResourceGovernanceTask(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    bundle_id: []const u8,
    ui_surface_id: ?u64,
) !*task_runtime.TaskRecord {
    const service_task = class == .emergency_system_critical;
    const image = if (service_task)
        try generated_image_fixtures.serviceImage()
    else
        try generated_image_fixtures.appImage();
    return runtime.createTask(.{
        .owner = .{
            .kind = if (service_task) .service else .app,
            .serial = serial,
        },
        .component_class = if (service_task) .service_component else .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(32),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(8),
            .resource_class = class,
            .background_allowed = class == .background_light or class == .batch_compute,
        },
        .ui_surface_id = ui_surface_id,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = serial,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    });
}

fn resourceGovernanceHardwareEvidence() accelerator_scheduler.HardwareTelemetryEvidence {
    return .{
        .target_id = "contract-resource-governance",
        .reader_generation = 1,
        .acpi_observed = true,
        .thermal_observed = true,
        .battery_observed = true,
        .accelerator_observed = true,
        .grid_carbon_observed = true,
    };
}

const NetworkSessionEvidence = struct {
    service_model: bool = false,
    egress_broker_composed: bool = false,
    destination_gate: bool = false,
    attested_open: bool = false,
    byte_budget: bool = false,
    expiry_boundary_gate: bool = false,
    effective_budget_policy: bool = false,
    over_budget_denied: bool = false,
    mutation_binding: bool = false,
    revocation_gate: bool = false,
    revoked_transfer_denied: bool = false,
    completed_transfer_denied: bool = false,
    ledger: bool = false,
    diagnostics: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryTwentyFourthContract() TwentyFourthChecklist {
    var features = [_]bool{false} ** twenty_fourth_feature_count;
    const evidence = networkSessionEvidence();

    features[@intFromEnum(TwentyFourthFeature.network_session_service_model)] = evidence.service_model;
    features[@intFromEnum(TwentyFourthFeature.existing_egress_broker_composed)] = evidence.egress_broker_composed;
    features[@intFromEnum(TwentyFourthFeature.allow_list_destination_gate)] = evidence.destination_gate;
    features[@intFromEnum(TwentyFourthFeature.attested_session_open)] = evidence.attested_open;
    features[@intFromEnum(TwentyFourthFeature.session_byte_budget)] = evidence.byte_budget;
    features[@intFromEnum(TwentyFourthFeature.session_expiry_boundary_gate)] = evidence.expiry_boundary_gate;
    features[@intFromEnum(TwentyFourthFeature.session_effective_budget_policy)] = evidence.effective_budget_policy;
    features[@intFromEnum(TwentyFourthFeature.transfer_over_budget_denied)] = evidence.over_budget_denied;
    features[@intFromEnum(TwentyFourthFeature.session_mutation_binding)] =
        evidence.mutation_binding and
        @hasField(typed_component_abi.NetworkRecordTransferRequest, "expected_policy_id") and
        @hasField(typed_component_abi.NetworkRecordTransferRequest, "expected_capability_id") and
        @hasField(typed_component_abi.NetworkRevokeSessionRequest, "expected_policy_id") and
        @hasField(typed_component_abi.NetworkRevokeSessionRequest, "expected_capability_id");
    features[@intFromEnum(TwentyFourthFeature.session_revocation_gate)] = evidence.revocation_gate;
    features[@intFromEnum(TwentyFourthFeature.revoked_session_transfer_denied)] = evidence.revoked_transfer_denied;
    features[@intFromEnum(TwentyFourthFeature.completed_session_transfer_denied)] = evidence.completed_transfer_denied;
    features[@intFromEnum(TwentyFourthFeature.network_session_ledger)] =
        event_ledger.EventKind.network_session == .network_session and evidence.ledger;
    features[@intFromEnum(TwentyFourthFeature.network_session_diagnostics)] = evidence.diagnostics;
    features[@intFromEnum(TwentyFourthFeature.network_session_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentyFourthFeature.typed_network_open_session_operation)] =
        contractOperationPresent("zigos.service.network.policy", .network_open_session);
    features[@intFromEnum(TwentyFourthFeature.typed_network_transfer_operation)] =
        contractOperationPresent("zigos.service.network.policy", .network_record_transfer);
    features[@intFromEnum(TwentyFourthFeature.typed_network_revoke_operation)] =
        contractOperationPresent("zigos.service.network.policy", .network_revoke_session);
    features[@intFromEnum(TwentyFourthFeature.network_session_wire_validation)] = networkSessionWireValidationCheck();
    features[@intFromEnum(TwentyFourthFeature.network_stack_catalog_binding)] =
        service_catalog.entryForClass(.network_stack) != null and
        typed_component_abi.interfaceId(.network_policy) == .network_policy;
    return .{ .satisfied_features = features };
}

fn networkSessionEvidence() NetworkSessionEvidence {
    var evidence = NetworkSessionEvidence{
        .service_model = @hasDecl(network_session_service.Service, "open") and
            @hasDecl(network_session_service.Service, "recordTransfer") and
            @hasDecl(network_session_service.Service, "revoke") and
            @hasField(event_ledger.DiagnosticSummary, "network_session_events"),
        .egress_broker_composed = @hasDecl(network_policy, "EgressBroker"),
    };

    var network_policies = network_policy.Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 811 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 812 };
    const relay = network_policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
        .require_remote_attestation = true,
    }) catch return evidence;

    var capabilities = capability.CapabilityTable.init();
    const network_capability = capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 811 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
            .capability_derive = true,
        } },
        .scope = .{
            .task_id = 8812,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 100,
        },
    }) catch return evidence;

    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 810,
        .issuer = .{ .kind = .policy_authority, .serial = 811 },
        .label = "network-session-contract",
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &.{"relay.zigos.dev"},
        .max_remote_private_egress_bytes = 1024,
    }, .{
        .label = "network-session-contract",
        .seed = signing.seedFromByte(0x8B),
    }) catch return evidence;
    const subjects = policy_object.SubjectSet{ .user_id = 810 };

    var service = network_session_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    evidence.destination_gate = if (service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = "other.example" } },
            .sensitivity = .private_user_data,
            .remote_bytes = 128,
            .max_session_bytes = 256,
            .expires_at_ticks = 40,
            .now_ticks = 10,
            .detail = "private denied network destination",
        },
        &ledger,
    )) |_| false else |err| err == error.PolicyDenied;

    const session = service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{
                .destination = .{ .domain = "relay.zigos.dev" },
                .attested = true,
                .verified_remote_attestation = true,
                .attestation_request_digest_present = true,
                .attestation_request_digest = crypto_hash.digestFromByte(0x91),
                .peer_root_digest_present = true,
                .peer_root_digest = crypto_hash.digestFromByte(0x92),
            },
            .sensitivity = .private_user_data,
            .remote_bytes = 512,
            .max_session_bytes = 768,
            .expires_at_ticks = 40,
            .now_ticks = 11,
            .detail = "private relay session opened",
        },
        &ledger,
    ) catch return evidence;
    evidence.attested_open = session.id != 0 and session.attested and
        std.mem.eql(u8, session.destinationSlice(), "relay.zigos.dev");

    const wrong_binding_denied = if (service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = session.id,
        .expected_policy_id = relay.id + 1,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 12,
        .detail = "private relay wrong binding transfer",
    }, &ledger)) |_| false else |err| err == error.SessionBindingMismatch;
    evidence.mutation_binding = wrong_binding_denied and session.bytes_used == 0;

    const transferred = service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 256,
        .now_ticks = 12,
        .detail = "private relay transfer",
    }, &ledger) catch return evidence;
    evidence.byte_budget = transferred.bytes_used == 256 and transferred.remainingBytes() == 512;

    evidence.over_budget_denied = if (service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 600,
        .now_ticks = 13,
        .detail = "private relay transfer over budget",
    }, &ledger)) |_| false else |err| err == error.ByteLimitExceeded;

    const revoked = service.revoke(.{
        .subject = app,
        .task_id = 8812,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .now_ticks = 14,
        .detail = "private relay session revoked",
    }, &ledger) catch return evidence;
    evidence.revocation_gate = revoked.state == .revoked;
    evidence.revoked_transfer_denied = if (service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 15,
        .detail = "private revoked relay transfer",
    }, &ledger)) |_| false else |err| err == error.SessionRevoked;

    const completed_session = service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{
                .destination = .{ .domain = "relay.zigos.dev" },
                .attested = true,
                .verified_remote_attestation = true,
                .attestation_request_digest_present = true,
                .attestation_request_digest = crypto_hash.digestFromByte(0x93),
                .peer_root_digest_present = true,
                .peer_root_digest = crypto_hash.digestFromByte(0x94),
            },
            .sensitivity = .private_user_data,
            .remote_bytes = 256,
            .max_session_bytes = 256,
            .expires_at_ticks = 40,
            .now_ticks = 16,
            .detail = "private completed relay session opened",
        },
        &ledger,
    ) catch return evidence;
    const completed = service.complete(.{
        .subject = app,
        .task_id = 8812,
        .session_id = completed_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .now_ticks = 17,
        .detail = "private relay session completed",
    }, &ledger) catch return evidence;
    const completed_transfer_denied = if (service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = completed_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 18,
        .detail = "private completed relay transfer",
    }, &ledger)) |_| false else |err| err == error.SessionCompleted;
    evidence.completed_transfer_denied = completed.state == .completed and completed_transfer_denied;

    var expiry_service = network_session_service.Service.init();
    var expiry_ledger = event_ledger.Ledger.init();
    defer expiry_ledger.deinit();
    const instant_expiry_rejected = if (expiry_service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{
                .destination = .{ .domain = "relay.zigos.dev" },
                .attested = true,
                .verified_remote_attestation = true,
                .attestation_request_digest_present = true,
                .attestation_request_digest = crypto_hash.digestFromByte(0x95),
                .peer_root_digest_present = true,
                .peer_root_digest = crypto_hash.digestFromByte(0x96),
            },
            .sensitivity = .private_user_data,
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 20,
            .now_ticks = 20,
            .detail = "private instant-expired relay session",
        },
        &expiry_ledger,
    )) |_| false else |err| err == error.PolicyDenied;
    const expiring_session = expiry_service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{
                .destination = .{ .domain = "relay.zigos.dev" },
                .attested = true,
                .verified_remote_attestation = true,
                .attestation_request_digest_present = true,
                .attestation_request_digest = crypto_hash.digestFromByte(0x97),
                .peer_root_digest_present = true,
                .peer_root_digest = crypto_hash.digestFromByte(0x98),
            },
            .sensitivity = .private_user_data,
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 22,
            .now_ticks = 20,
            .detail = "private expiring relay session",
        },
        &expiry_ledger,
    ) catch return evidence;
    const pre_expiry_transfer = expiry_service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = expiring_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 21,
        .detail = "private pre-expiry relay transfer",
    }, &expiry_ledger) catch return evidence;
    const at_expiry_transfer_denied = if (expiry_service.recordTransfer(.{
        .subject = app,
        .task_id = 8812,
        .session_id = expiring_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 22,
        .detail = "private at-expiry relay transfer",
    }, &expiry_ledger)) |_| false else |err| err == error.SessionExpired;
    evidence.expiry_boundary_gate =
        instant_expiry_rejected and
        pre_expiry_transfer.bytes_used == 1 and
        at_expiry_transfer_denied;

    var budget_service = network_session_service.Service.init();
    var budget_ledger = event_ledger.Ledger.init();
    defer budget_ledger.deinit();
    evidence.effective_budget_policy = if (budget_service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8812,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{
                .destination = .{ .domain = "relay.zigos.dev" },
                .attested = true,
                .verified_remote_attestation = true,
                .attestation_request_digest_present = true,
                .attestation_request_digest = crypto_hash.digestFromByte(0x99),
                .peer_root_digest_present = true,
                .peer_root_digest = crypto_hash.digestFromByte(0x9A),
            },
            .sensitivity = .private_user_data,
            .remote_bytes = 128,
            .max_session_bytes = 2048,
            .expires_at_ticks = 40,
            .now_ticks = 19,
            .detail = "private oversized session budget",
        },
        &budget_ledger,
    )) |_| false else |err| err == error.PolicyDenied;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.network_session_events == 10 and
        summary.network_session_denials == 5 and
        summary.network_session_revocations == 1 and
        summary.network_session_byte_denials == 1 and
        summary.network_session_attested >= 7;

    var diagnostics_buffer: [4096]u8 = undefined;
    const diagnostics = ledger.renderUserVisibleDiagnosticsToBuffer(&diagnostics_buffer) catch return evidence;
    evidence.diagnostics =
        summary.evidenceEventCount() >= summary.network_session_events and
        std.mem.indexOf(u8, diagnostics, "network_session_events=10") != null and
        std.mem.indexOf(u8, diagnostics, "network_session_denials=5") != null;

    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.network_session_events and
        std.mem.indexOf(u8, exported, "private relay") == null and
        std.mem.indexOf(u8, exported, "kind=network_session") != null and
        std.mem.indexOf(u8, exported, "detail=redacted") != null;
    return evidence;
}

fn networkSessionWireValidationCheck() bool {
    const header = typed_component_abi.WireHeader{
        .operation = @intFromEnum(typed_component_abi.OperationId.network_open_session),
        .correlation_id = 2026,
        .subject_task_id = 8812,
    };
    typed_component_abi.validateMessage(
        .network_policy,
        .network_open_session,
        header,
        @sizeOf(typed_component_abi.NetworkOpenSessionRequest),
        @sizeOf(typed_component_abi.NetworkSessionResponse),
    ) catch return false;
    return true;
}

const PersonalContextEvidence = struct {
    service_model: bool = false,
    policy_composed: bool = false,
    lease_issue: bool = false,
    query_accounting: bool = false,
    query_canonical_byte_metering: bool = false,
    indexed_retrieval: bool = false,
    pack_redaction: bool = false,
    pack_receipt: bool = false,
    pack_index_generation: bool = false,
    pack_index_staleness_guard: bool = false,
    pack_accounting_snapshot_guard: bool = false,
    pack_envelope_consistency: bool = false,
    pack_request_fingerprint: bool = false,
    pack_sensitivity_envelope: bool = false,
    pack_empty_receipt: bool = false,
    pack_freshness: bool = false,
    pack_revocation_binding: bool = false,
    pack_replay_guard: bool = false,
    pack_live_replay_verifier: bool = false,
    pack_receipt_audit: bool = false,
    pack_invalid_receipt_audit: bool = false,
    pack_malformed_receipt_audit: bool = false,
    pack_policy_reauthorization: bool = false,
    privacy_mode_binding: bool = false,
    expiration_gate: bool = false,
    revocation_gate: bool = false,
    workspace_scope_gate: bool = false,
    budget_gate: bool = false,
    ledger: bool = false,
    diagnostics: bool = false,
    redacted_diagnostics: bool = false,
};

pub fn currentRepositoryTwentyFifthContract() TwentyFifthChecklist {
    var features = [_]bool{false} ** twenty_fifth_feature_count;
    const evidence = personalContextEvidence();

    features[@intFromEnum(TwentyFifthFeature.personal_context_service_model)] = evidence.service_model;
    features[@intFromEnum(TwentyFifthFeature.semantic_policy_composed)] = evidence.policy_composed;
    features[@intFromEnum(TwentyFifthFeature.local_model_gate)] = semanticMemoryPolicyDenies(.semantic_memory_remote_model_denied);
    features[@intFromEnum(TwentyFifthFeature.encrypted_index_gate)] = semanticMemoryPolicyDenies(.semantic_memory_encryption_denied);
    features[@intFromEnum(TwentyFifthFeature.redacted_snippet_gate)] = semanticMemoryPolicyDenies(.semantic_memory_redaction_denied);
    features[@intFromEnum(TwentyFifthFeature.context_query_byte_budget)] =
        semanticMemoryPolicyDenies(.semantic_query_budget_denied) and evidence.budget_gate;
    features[@intFromEnum(TwentyFifthFeature.context_lease_issue)] = evidence.lease_issue;
    features[@intFromEnum(TwentyFifthFeature.context_lease_query_accounting)] = evidence.query_accounting;
    features[@intFromEnum(TwentyFifthFeature.context_query_canonical_byte_metering)] = evidence.query_canonical_byte_metering;
    features[@intFromEnum(TwentyFifthFeature.context_indexed_retrieval)] = evidence.indexed_retrieval;
    features[@intFromEnum(TwentyFifthFeature.context_pack_redaction)] = evidence.pack_redaction;
    features[@intFromEnum(TwentyFifthFeature.context_pack_receipt)] = evidence.pack_receipt;
    features[@intFromEnum(TwentyFifthFeature.context_pack_index_generation)] = evidence.pack_index_generation;
    features[@intFromEnum(TwentyFifthFeature.context_pack_index_staleness_guard)] = evidence.pack_index_staleness_guard;
    features[@intFromEnum(TwentyFifthFeature.context_pack_accounting_snapshot_guard)] = evidence.pack_accounting_snapshot_guard;
    features[@intFromEnum(TwentyFifthFeature.context_pack_envelope_consistency)] = evidence.pack_envelope_consistency;
    features[@intFromEnum(TwentyFifthFeature.context_pack_request_fingerprint)] = evidence.pack_request_fingerprint;
    features[@intFromEnum(TwentyFifthFeature.context_pack_sensitivity_envelope)] = evidence.pack_sensitivity_envelope;
    features[@intFromEnum(TwentyFifthFeature.context_pack_empty_receipt)] = evidence.pack_empty_receipt;
    features[@intFromEnum(TwentyFifthFeature.context_pack_freshness)] = evidence.pack_freshness;
    features[@intFromEnum(TwentyFifthFeature.context_pack_revocation_binding)] = evidence.pack_revocation_binding;
    features[@intFromEnum(TwentyFifthFeature.context_pack_replay_guard)] = evidence.pack_replay_guard;
    features[@intFromEnum(TwentyFifthFeature.context_pack_live_replay_verifier)] = evidence.pack_live_replay_verifier;
    features[@intFromEnum(TwentyFifthFeature.context_pack_receipt_audit)] =
        @hasDecl(event_ledger.Ledger, "recordSemanticMemoryReceipt") and evidence.pack_receipt_audit;
    features[@intFromEnum(TwentyFifthFeature.context_pack_invalid_receipt_audit)] = evidence.pack_invalid_receipt_audit;
    features[@intFromEnum(TwentyFifthFeature.context_pack_malformed_receipt_audit)] = evidence.pack_malformed_receipt_audit;
    features[@intFromEnum(TwentyFifthFeature.context_pack_policy_reauthorization)] = evidence.pack_policy_reauthorization;
    features[@intFromEnum(TwentyFifthFeature.context_lease_privacy_mode_binding)] = evidence.privacy_mode_binding;
    features[@intFromEnum(TwentyFifthFeature.context_lease_expiration_gate)] = evidence.expiration_gate;
    features[@intFromEnum(TwentyFifthFeature.context_lease_revocation_gate)] = evidence.revocation_gate;
    features[@intFromEnum(TwentyFifthFeature.context_workspace_scope_gate)] = evidence.workspace_scope_gate;
    features[@intFromEnum(TwentyFifthFeature.personal_context_ledger)] =
        event_ledger.EventKind.semantic_memory == .semantic_memory and evidence.ledger;
    features[@intFromEnum(TwentyFifthFeature.personal_context_diagnostics)] = evidence.diagnostics;
    features[@intFromEnum(TwentyFifthFeature.personal_context_redaction)] = evidence.redacted_diagnostics;
    features[@intFromEnum(TwentyFifthFeature.typed_context_lease_operation)] =
        contractOperationPresent("zigos.personal.context", .personal_context_lease);
    features[@intFromEnum(TwentyFifthFeature.typed_context_query_operation)] =
        contractOperationPresent("zigos.personal.context", .personal_context_query);
    features[@intFromEnum(TwentyFifthFeature.typed_context_revoke_operation)] =
        contractOperationPresent("zigos.personal.context", .personal_context_revoke);
    features[@intFromEnum(TwentyFifthFeature.context_wire_validation)] = personalContextWireValidationCheck();
    features[@intFromEnum(TwentyFifthFeature.personal_context_catalog_binding)] = personalContextCatalogBindingCheck();
    return .{ .satisfied_features = features };
}

fn personalContextEvidence() PersonalContextEvidence {
    var evidence = PersonalContextEvidence{
        .service_model = @hasDecl(personal_context_service.Service, "issueLease") and
            @hasDecl(personal_context_service.Service, "query") and
            @hasDecl(personal_context_service.Service, "revoke") and
            @hasField(personal_context_service.ContextLease, "workspace_id"),
        .policy_composed = @hasDecl(policy_object.Directory, "semanticMemoryDecision") and
            @hasDecl(event_ledger.Ledger, "recordSemanticMemory"),
        .pack_empty_receipt = personalContextEmptyReceiptCheck(),
        .pack_policy_reauthorization = personalContextReceiptPolicyReauthorizationCheck(),
        .privacy_mode_binding = personalContextPrivacyModeBindingCheck(),
        .pack_sensitivity_envelope = personalContextSensitivityEnvelopeCheck(),
        .pack_index_staleness_guard = personalContextIndexStalenessCheck(),
        .pack_accounting_snapshot_guard = personalContextAccountingSnapshotCheck(),
    };
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2060,
        .issuer = .{ .kind = .policy_authority, .serial = 2060 },
        .label = "personal-context-contract",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-contract-policy",
        .seed = signing.seedFromByte(0xA6),
    }) catch return evidence;
    const subjects = policy_object.SubjectSet{ .user_id = 2060 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2061 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(42, 7062, 1, "Context Notes", "private personal context contract roadmap", .private_user_data) catch return evidence;
    semantic_index.upsertClassified(43, 7063, 1, "Other Context", "private personal context contract roadmap", .private_user_data) catch return evidence;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .workspace_id = 42,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context contract lease",
    }, &ledger) catch return evidence;
    const lease_id = lease.id;
    evidence.lease_issue = lease_id != 0 and lease.workspace_id == 42 and lease.remainingBytes() == 64;

    const query = service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 16,
        .now_ticks = 11,
        .detail = "private personal context contract query",
    }, &ledger) catch return evidence;
    evidence.query_accounting = query.bytes_used == 16 and query.bytes_remaining == 48;

    var metered_service = personal_context_service.Service.init();
    var metered_ledger = event_ledger.Ledger.init();
    defer metered_ledger.deinit();
    const metered_lease = metered_service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 7065,
        .workspace_id = 42,
        .max_query_bytes = 8,
        .expires_at_ticks = 100,
        .now_ticks = 11,
        .detail = "private personal context metered lease",
    }, &metered_ledger) catch return evidence;
    const metered_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 7065,
        .lease_id = metered_lease.id,
        .workspace_id = 42,
        .query_bytes = 1,
        .query = "context",
        .now_ticks = 12,
        .detail = "private personal context metered query",
    };
    const metered_query = metered_service.query(&policies, subjects, metered_request, &metered_ledger) catch return evidence;
    evidence.query_canonical_byte_metering =
        personal_context_service.meteredQueryBytes(metered_request) == 7 and
        metered_query.bytes_used == 7 and
        metered_query.bytes_remaining == 1;

    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const retrieval = service.retrieve(&semantic_index, &policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 0,
        .query = "context",
        .now_ticks = 12,
        .detail = "private personal context indexed query",
    }, &results_buffer, &ledger) catch return evidence;
    evidence.indexed_retrieval = retrieval.results.len == 1 and
        retrieval.results[0].object_id == 7062 and
        retrieval.results[0].workspace_id == 42 and
        retrieval.accounting.bytes_used == 23 and
        retrieval.accounting.bytes_remaining == 41;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 0,
        .query = "context",
        .now_ticks = 13,
        .detail = "private personal context packed query",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return evidence;
    evidence.pack_redaction = packs.packs.len == 1 and
        packs.packs[0].object_id == 7062 and
        packs.packs[0].workspace_id == 42 and
        packs.packs[0].score == 5 and
        packs.packs[0].title_hits == 1 and
        packs.packs[0].body_hits == 1 and
        packs.packs[0].sensitivity == .private_user_data and
        packs.packs[0].title_fingerprint != 0 and
        (packs.packs[0].flags & personal_context_service.PACK_FLAG_REDACTED) != 0 and
        (packs.packs[0].flags & personal_context_service.PACK_FLAG_LOCAL_MODEL) != 0 and
        (packs.packs[0].flags & personal_context_service.PACK_FLAG_ENCRYPTED_INDEX) != 0 and
        !@hasField(personal_context_service.ContextPack, "title") and
        !@hasField(personal_context_service.ContextPack, "body") and
        packs.accounting.bytes_used == 30 and
        packs.accounting.bytes_remaining == 34;
    evidence.pack_index_generation = packs.accounting.index_generation == semantic_index.generation and
        packs.receipt.index_generation == semantic_index.generation and
        packs.packs[0].index_generation == semantic_index.generation and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_index_generation");
    var tampered_pack_buffer = packs_buffer;
    tampered_pack_buffer[0].score +|= 1;
    var wrong_generation_pack_buffer = packs_buffer;
    wrong_generation_pack_buffer[0].index_generation +|= 1;
    var wrong_workspace_pack_buffer = packs_buffer;
    wrong_workspace_pack_buffer[0].workspace_id +|= 1;
    var wrong_flags_pack_buffer = packs_buffer;
    wrong_flags_pack_buffer[0].flags = 0;
    evidence.pack_envelope_consistency =
        !personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, wrong_generation_pack_buffer[0..packs.packs.len]) and
        !personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, wrong_workspace_pack_buffer[0..packs.packs.len]) and
        !personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, wrong_flags_pack_buffer[0..packs.packs.len]);
    var shifted_issue_request = pack_request;
    shifted_issue_request.now_ticks +|= 1;
    evidence.pack_request_fingerprint =
        @hasField(personal_context_service.ContextPackReceipt, "request_fingerprint") and
        @hasField(typed_component_abi.PersonalContextResponse, "request_fingerprint") and
        !std.mem.eql(u8, &packs.receipt.request_fingerprint, &crypto_hash.zero_digest) and
        !personal_context_service.verifyPackReceipt(packs.receipt, shifted_issue_request, packs.accounting, packs.packs);
    evidence.pack_receipt = packs.receipt.complete() and
        packs.receipt.receipt_id != 0 and
        packs.receipt.pack_count == 1 and
        packs.receipt.lease_id == lease_id and
        packs.receipt.workspace_id == 42 and
        packs.receipt.privacy_mode_flags == personal_context_service.privacyFlagsFromRequest(pack_request) and
        packs.receipt.max_pack_sensitivity == manifest.DataSensitivity.private_user_data and
        !std.mem.eql(u8, &packs.receipt.request_fingerprint, &crypto_hash.zero_digest) and
        !std.mem.eql(u8, &packs.receipt.query_fingerprint, &crypto_hash.zero_digest) and
        !std.mem.eql(u8, &packs.receipt.pack_digest, &crypto_hash.zero_digest) and
        !std.mem.eql(u8, &packs.receipt.receipt_digest, &crypto_hash.zero_digest) and
        personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, packs.packs) and
        !personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, tampered_pack_buffer[0..packs.packs.len]);
    evidence.pack_freshness =
        personal_context_service.verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 99) and
        !personal_context_service.verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 100) and
        !personal_context_service.verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 12);
    const receipt_live_before_revoke =
        packs.receipt.lease_revocation_generation == 0 and
        personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16);
    const receipt_consumed_once =
        service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16, &ledger, "private personal context receipt consumption") catch return evidence;
    const receipt_live_after_consumption =
        personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16);
    const receipt_replayed =
        service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16, &ledger, "private personal context receipt replay") catch return evidence;
    const receipt_replay_rejected = !receipt_replayed;
    evidence.pack_replay_guard = receipt_consumed_once and receipt_replay_rejected;
    evidence.pack_live_replay_verifier = receipt_live_before_revoke and receipt_consumed_once and !receipt_live_after_consumption;
    var invalid_receipt = packs.receipt;
    invalid_receipt.receipt_id +|= 1;
    const invalid_receipt_rejected =
        !(service.consumePackReceipt(&policies, subjects, invalid_receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16, &ledger, "private personal context invalid receipt") catch return evidence);
    var malformed_receipt = packs.receipt;
    malformed_receipt.receipt_id = 0;
    const malformed_receipt_rejected =
        !(service.consumePackReceipt(&policies, subjects, malformed_receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 16, &ledger, "private personal context malformed receipt") catch return evidence);

    evidence.workspace_scope_gate = if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 43,
        .query_bytes = 8,
        .now_ticks = 14,
        .detail = "private personal context wrong workspace",
    }, &ledger)) |_| false else |err| err == error.WorkspaceScopeMismatch;

    if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 8,
        .local_model = false,
        .now_ticks = 15,
        .detail = "private personal context remote model",
    }, &ledger)) |_| {
        return evidence;
    } else |err| {
        if (err != error.LeasePrivacyMismatch) return evidence;
    }

    evidence.budget_gate = if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 80,
        .now_ticks = 16,
        .detail = "private personal context budget overflow",
    }, &ledger)) |_| false else |err| err == error.QueryBudgetExceeded;

    service.revoke(.{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .now_ticks = 17,
        .detail = "private personal context revoke",
    }, &ledger) catch return evidence;
    evidence.pack_revocation_binding = receipt_live_before_revoke and
        !personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 18);
    evidence.revocation_gate = if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7060,
        .lease_id = lease_id,
        .workspace_id = 42,
        .query_bytes = 8,
        .now_ticks = 18,
        .detail = "private personal context revoked query",
    }, &ledger)) |_| false else |err| err == error.LeaseRevoked;

    const short_lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 7061,
        .workspace_id = 42,
        .max_query_bytes = 32,
        .expires_at_ticks = 20,
        .now_ticks = 19,
        .detail = "private personal context expiring lease",
    }, &ledger) catch return evidence;
    evidence.expiration_gate = if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 7061,
        .lease_id = short_lease.id,
        .workspace_id = 42,
        .query_bytes = 8,
        .now_ticks = 20,
        .detail = "private personal context expired query",
    }, &ledger)) |_| false else |err| err == error.LeaseExpired;

    const summary = ledger.userVisibleDiagnosticSummary();
    evidence.ledger = summary.semantic_memory_events == 15 and
        summary.semantic_memory_denials == 8 and
        summary.semantic_memory_remote_denials == 1;
    evidence.pack_receipt_audit = summary.semantic_memory_receipt_events == 4 and
        summary.semantic_memory_receipt_denials == 3;
    evidence.pack_invalid_receipt_audit = invalid_receipt_rejected and evidence.pack_receipt_audit;
    evidence.pack_malformed_receipt_audit = malformed_receipt_rejected and evidence.pack_receipt_audit;

    var diagnostics_buffer: [4096]u8 = undefined;
    const diagnostics = ledger.renderUserVisibleDiagnosticsToBuffer(&diagnostics_buffer) catch return evidence;
    evidence.diagnostics =
        summary.evidenceEventCount() >= summary.semantic_memory_events and
        std.mem.indexOf(u8, diagnostics, "semantic_memory_events=15") != null and
        std.mem.indexOf(u8, diagnostics, "semantic_memory_denials=8") != null and
        std.mem.indexOf(u8, diagnostics, "semantic_memory_receipt_events=4") != null and
        std.mem.indexOf(u8, diagnostics, "semantic_memory_receipt_denials=3") != null;

    var export_buffer: [4096]u8 = undefined;
    const exported = ledger.exportText(&export_buffer, .{}) catch return evidence;
    evidence.redacted_diagnostics =
        summary.protected_details_redacted >= summary.semantic_memory_events and
        std.mem.indexOf(u8, exported, "private personal context") == null and
        std.mem.indexOf(u8, exported, "kind=semantic_memory") != null and
        std.mem.indexOf(u8, exported, "detail=redacted") != null;
    return evidence;
}

fn personalContextEmptyReceiptCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2090,
        .issuer = .{ .kind = .policy_authority, .serial = 2090 },
        .label = "personal-context-empty-receipt",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 32,
    }, .{
        .label = "personal-context-empty-receipt",
        .seed = signing.seedFromByte(0xB3),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2090 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2091 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(82, 9082, 1, "Present Context", "private present context only", .private_user_data) catch return false;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8080,
        .workspace_id = 82,
        .max_query_bytes = 32,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context empty lease",
    }, &ledger) catch return false;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8080,
        .lease_id = lease.id,
        .workspace_id = 82,
        .query_bytes = 0,
        .query = "absent",
        .now_ticks = 11,
        .detail = "private personal context empty pack",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return false;
    if (packs.packs.len != 0 or packs.receipt.pack_count != 0) return false;
    if (packs.accounting.index_generation != semantic_index.generation) return false;
    if (packs.receipt.index_generation != semantic_index.generation) return false;
    if (!packs.receipt.complete()) return false;
    if (std.mem.eql(u8, &packs.receipt.pack_digest, &crypto_hash.zero_digest)) return false;
    if (!personal_context_service.verifyPackReceipt(packs.receipt, pack_request, packs.accounting, packs.packs)) return false;
    if (!personal_context_service.verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 12)) return false;
    const consumed = service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12, &ledger, "private personal context empty receipt") catch return false;
    const replayed = service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12, &ledger, "private personal context empty replay") catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return consumed and
        !replayed and
        summary.semantic_memory_events == 4 and
        summary.semantic_memory_denials == 1 and
        summary.semantic_memory_receipt_events == 2 and
        summary.semantic_memory_receipt_denials == 1;
}

fn personalContextSensitivityEnvelopeCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2100,
        .issuer = .{ .kind = .policy_authority, .serial = 2100 },
        .label = "personal-context-sensitivity-envelope",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-sensitivity-envelope",
        .seed = signing.seedFromByte(0xB4),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2100 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2101 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(92, 9092, 1, "Secret Context", "private secret context envelope", .secret_user_data) catch return false;
    if (semantic_index.permittedWorkspaceSensitivity(&[_]u64{92}) != .secret_user_data) return false;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8090,
        .workspace_id = 92,
        .sensitivity = .private_user_data,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context sensitivity lease",
    }, &ledger) catch return false;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8090,
        .lease_id = lease.id,
        .workspace_id = 92,
        .query_bytes = 0,
        .query = "secret",
        .now_ticks = 11,
        .detail = "private personal context sensitivity pack",
    };
    if (service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger)) |_| {
        return false;
    } else |err| {
        if (err != error.LeaseSensitivityMismatch) return false;
    }
    const summary = ledger.userVisibleDiagnosticSummary();
    return @hasField(personal_context_service.ContextPackReceipt, "max_pack_sensitivity") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_max_pack_sensitivity") and
        summary.semantic_memory_events == 2 and
        summary.semantic_memory_denials == 1;
}

fn personalContextIndexStalenessCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2110,
        .issuer = .{ .kind = .policy_authority, .serial = 2110 },
        .label = "personal-context-index-staleness",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-index-staleness",
        .seed = signing.seedFromByte(0xB5),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2110 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2111 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(102, 9102, 1, "Stable Context", "private stable context envelope", .private_user_data) catch return false;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8100,
        .workspace_id = 102,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context stale-index lease",
    }, &ledger) catch return false;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8100,
        .lease_id = lease.id,
        .workspace_id = 102,
        .query_bytes = 0,
        .query = "stable",
        .now_ticks = 11,
        .detail = "private personal context stale-index pack",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return false;
    const issued_generation = semantic_index.generation;
    semantic_index.upsertClassified(102, 9103, 1, "New Context", "private new context envelope", .private_user_data) catch return false;
    if (semantic_index.generation == issued_generation) return false;
    if (!personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, issued_generation, 12)) return false;
    if (personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12)) return false;

    const consumed = service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12, &ledger, "private personal context stale-index receipt") catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return !consumed and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_index_generation") and
        summary.semantic_memory_events == 3 and
        summary.semantic_memory_receipt_events == 1 and
        summary.semantic_memory_receipt_denials == 1;
}

fn personalContextAccountingSnapshotCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2120,
        .issuer = .{ .kind = .policy_authority, .serial = 2120 },
        .label = "personal-context-accounting-snapshot",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-accounting-snapshot",
        .seed = signing.seedFromByte(0xB6),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2120 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2121 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(112, 9112, 1, "Stable Context", "private stable context envelope", .private_user_data) catch return false;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8110,
        .workspace_id = 112,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context accounting lease",
    }, &ledger) catch return false;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8110,
        .lease_id = lease.id,
        .workspace_id = 112,
        .query_bytes = 0,
        .query = "stable",
        .now_ticks = 11,
        .detail = "private personal context accounting pack",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return false;
    if (!personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12)) return false;
    _ = service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 8110,
        .lease_id = lease.id,
        .workspace_id = 112,
        .query_bytes = 8,
        .now_ticks = 12,
        .detail = "private personal context accounting drift",
    }, &ledger) catch return false;
    if (personal_context_service.verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 13)) return false;

    const consumed = service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 13, &ledger, "private personal context stale-accounting receipt") catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return !consumed and
        @hasField(typed_component_abi.PersonalContextResponse, "remaining_bytes") and
        summary.semantic_memory_events == 4 and
        summary.semantic_memory_receipt_events == 1 and
        summary.semantic_memory_receipt_denials == 1;
}

fn personalContextPrivacyModeBindingCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2080,
        .issuer = .{ .kind = .policy_authority, .serial = 2080 },
        .label = "personal-context-privacy-envelope",
        .semantic_memory_allowed = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-privacy-envelope",
        .seed = signing.seedFromByte(0xB2),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2080 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2081 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8070,
        .workspace_id = 72,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .local_model = true,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 10,
        .detail = "private personal context privacy envelope lease",
    }, &ledger) catch return false;

    if (service.query(&policies, subjects, .{
        .subject = subject,
        .task_id = 8070,
        .lease_id = lease.id,
        .workspace_id = 72,
        .query_bytes = 8,
        .local_model = false,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 11,
        .detail = "private personal context lease downgrade",
    }, &ledger)) |_| {
        return false;
    } else |err| {
        if (err != error.LeasePrivacyMismatch) return false;
    }

    semantic_index.upsertClassified(72, 8072, 1, "Privacy Envelope", "private personal context privacy envelope", .private_user_data) catch return false;
    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8070,
        .lease_id = lease.id,
        .workspace_id = 72,
        .query_bytes = 0,
        .query = "privacy",
        .local_model = true,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 12,
        .detail = "private personal context privacy pack",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return false;
    if (packs.receipt.privacy_mode_flags != personal_context_service.privacyFlagsFromRequest(pack_request)) return false;

    var downgraded_request = pack_request;
    downgraded_request.local_model = false;
    if (personal_context_service.verifyPackReceipt(packs.receipt, downgraded_request, packs.accounting, packs.packs)) return false;
    const consumed = service.consumePackReceipt(&policies, subjects, packs.receipt, downgraded_request, packs.accounting, packs.packs, semantic_index.generation, 13, &ledger, "private personal context receipt downgrade") catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return !consumed and
        summary.semantic_memory_events == 4 and
        summary.semantic_memory_denials == 2 and
        summary.semantic_memory_remote_denials == 2 and
        summary.semantic_memory_receipt_events == 1 and
        summary.semantic_memory_receipt_denials == 1;
}

fn personalContextReceiptPolicyReauthorizationCheck() bool {
    var policies = policy_object.Directory.init();
    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2070,
        .issuer = .{ .kind = .policy_authority, .serial = 2070 },
        .label = "personal-context-policy-reauth-allow",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "personal-context-policy-reauth-allow",
        .seed = signing.seedFromByte(0xB0),
    }) catch return false;
    const subjects = policy_object.SubjectSet{ .user_id = 2070 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 2071 };
    var service = personal_context_service.Service.init();
    var semantic_index = indexing_service.Service.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    semantic_index.upsertClassified(62, 8062, 1, "Policy Drift", "private receipt policy reauthorization", .private_user_data) catch return false;

    const lease = service.issueLease(&policies, subjects, .{
        .subject = subject,
        .task_id = 8060,
        .workspace_id = 62,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context policy-bound lease",
    }, &ledger) catch return false;

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]personal_context_service.ContextPack = undefined;
    const pack_request = personal_context_service.QueryRequest{
        .subject = subject,
        .task_id = 8060,
        .lease_id = lease.id,
        .workspace_id = 62,
        .query_bytes = 0,
        .query = "policy",
        .now_ticks = 11,
        .detail = "private personal context policy-bound pack",
    };
    const packs = service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger) catch return false;

    _ = policies.create(.{
        .scope = .user,
        .subject_id = 2070,
        .issuer = .{ .kind = .policy_authority, .serial = 2072 },
        .label = "personal-context-policy-reauth-deny",
        .semantic_memory_allowed = false,
    }, .{
        .label = "personal-context-policy-reauth-deny",
        .seed = signing.seedFromByte(0xB1),
    }) catch return false;

    const consumed = service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 12, &ledger, "private personal context policy reauthorization") catch return false;
    const summary = ledger.userVisibleDiagnosticSummary();
    return !consumed and
        summary.semantic_memory_events == 3 and
        summary.semantic_memory_denials == 1 and
        summary.semantic_memory_receipt_events == 1 and
        summary.semantic_memory_receipt_denials == 1;
}

fn personalContextWireValidationCheck() bool {
    const header = typed_component_abi.WireHeader{
        .operation = @intFromEnum(typed_component_abi.OperationId.personal_context_query),
        .correlation_id = 2027,
        .subject_task_id = 7060,
    };
    typed_component_abi.validateMessage(
        .personal_context,
        .personal_context_query,
        header,
        @sizeOf(typed_component_abi.PersonalContextQueryRequest),
        @sizeOf(typed_component_abi.PersonalContextResponse),
    ) catch return false;
    return @hasField(typed_component_abi.PersonalContextResponse, "result_count") and
        @hasField(typed_component_abi.PersonalContextResponse, "lease_revocation_generation") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_score") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_title_hits") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_body_hits") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_sensitivity") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_id") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_index_generation") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_privacy_flags") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_max_pack_sensitivity") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_object_id") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_version_id") and
        @hasField(typed_component_abi.PersonalContextResponse, "top_title_fingerprint") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_issued_at_tick") and
        @hasField(typed_component_abi.PersonalContextResponse, "request_fingerprint") and
        @hasField(typed_component_abi.PersonalContextResponse, "query_fingerprint") and
        @hasField(typed_component_abi.PersonalContextResponse, "pack_digest") and
        @hasField(typed_component_abi.PersonalContextResponse, "receipt_digest");
}

fn personalContextCatalogBindingCheck() bool {
    const entry = service_catalog.entryForClass(.personal_context) orelse return false;
    const launch = entry.service_bootstrap orelse return false;
    const contract = service_catalog.serviceContractForClass(.personal_context) orelse return false;
    const image = userspace_registry.findByServiceClass(.personal_context) orelse return false;
    const provided_interfaces = image.providedInterfaces();
    return entry.published_native_service and
        entry.userspace_image != null and
        launch.mode == .kernel_contract and
        launch.grants.len != 0 and
        launch.grants[0] == .service_task_authority and
        contract.interface_id == .personal_context and
        typed_component_abi.interfaceId(.personal_context) == .personal_context and
        provided_interfaces.len == 1 and
        std.mem.eql(u8, image.bundleId(), "zigos.system.personal-context") and
        std.mem.eql(u8, provided_interfaces[0].name, "zigos.personal.context");
}

test "OS contract keeps sixteen modernization features satisfied" {
    const checklist = currentRepositoryContract();
    try std.testing.expectEqual(@as(usize, 16), feature_count);
    try std.testing.expectEqual(feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.no_compatibility_namespace));
    try std.testing.expect(checklist.satisfied(.typed_ai_inference_service));
}

test "OS contract keeps thirty four additional modernization passes satisfied" {
    const checklist = currentRepositoryExtraContract();
    try std.testing.expectEqual(@as(usize, 34), extra_feature_count);
    try std.testing.expectEqual(extra_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_privacy_budget_service));
    try std.testing.expect(checklist.satisfied(.typed_diagnostics_export_service));
    try std.testing.expect(checklist.satisfied(.private_egress_budget_policy));
    try std.testing.expect(checklist.satisfied(.process_hidden_observability_denied));
    try std.testing.expect(checklist.satisfied(.process_continuous_observability_scope));
}

test "OS contract keeps thirty two third-loop lifecycle passes satisfied" {
    const checklist = currentRepositoryThirdContract();
    try std.testing.expectEqual(@as(usize, 32), third_feature_count);
    try std.testing.expectEqual(third_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_consent_receipts_service));
    try std.testing.expect(checklist.satisfied(.typed_permission_lease_service));
    try std.testing.expect(checklist.satisfied(.permission_use_policy_request));
}

test "OS contract keeps twenty fourth-loop data-rights passes satisfied" {
    const checklist = currentRepositoryFourthContract();
    try std.testing.expectEqual(@as(usize, 20), fourth_feature_count);
    try std.testing.expectEqual(fourth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_data_rights_service));
    try std.testing.expect(checklist.satisfied(.policy_deletion_receipt_required));
    try std.testing.expect(checklist.satisfied(.data_deletion_receipt_summary));
}

test "OS contract keeps twenty fifth-loop AI model provenance passes satisfied" {
    const checklist = currentRepositoryFifthContract();
    try std.testing.expectEqual(@as(usize, 20), fifth_feature_count);
    try std.testing.expectEqual(fifth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_ai_model_registry_service));
    try std.testing.expect(checklist.satisfied(.policy_ai_model_measurement_gate));
    try std.testing.expect(checklist.satisfied(.ai_model_rejection_summary));
}

test "OS contract keeps twenty sixth-loop trusted session passes satisfied" {
    const checklist = currentRepositorySixthContract();
    try std.testing.expectEqual(@as(usize, 20), sixth_feature_count);
    try std.testing.expectEqual(sixth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_identity_session_service));
    try std.testing.expect(checklist.satisfied(.policy_unlock_age_gate));
    try std.testing.expect(checklist.satisfied(.identity_session_redaction));
}

test "OS contract keeps twenty one seventh-loop supply chain passes satisfied" {
    const checklist = currentRepositorySeventhContract();
    try std.testing.expectEqual(@as(usize, 21), seventh_feature_count);
    try std.testing.expectEqual(seventh_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.supply_chain_manifest));
    try std.testing.expect(checklist.satisfied(.policy_package_sbom_gate));
    try std.testing.expect(checklist.satisfied(.package_install_provenance_error));
    try std.testing.expect(checklist.satisfied(.package_active_revision_mutation_gate));
}

test "OS contract keeps twenty eighth-loop agent delegation passes satisfied" {
    const checklist = currentRepositoryEighthContract();
    try std.testing.expectEqual(@as(usize, 20), eighth_feature_count);
    try std.testing.expectEqual(eighth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.agent_delegation_manifest));
    try std.testing.expect(checklist.satisfied(.typed_agent_delegation_service));
    try std.testing.expect(checklist.satisfied(.agent_delegation_diagnostics));
}

test "OS contract keeps sixteen ninth-loop attention sovereignty passes satisfied" {
    const checklist = currentRepositoryNinthContract();
    try std.testing.expectEqual(@as(usize, 16), ninth_feature_count);
    try std.testing.expectEqual(ninth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.notification_center_quiet_mode));
    try std.testing.expect(checklist.satisfied(.attention_policy_redaction));
    try std.testing.expect(checklist.satisfied(.policy_digest_covers_attention));
}

test "OS contract keeps twenty tenth-loop accessibility profile passes satisfied" {
    const checklist = currentRepositoryTenthContract();
    try std.testing.expectEqual(@as(usize, 20), tenth_feature_count);
    try std.testing.expectEqual(tenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_accessibility_profile_service));
    try std.testing.expect(checklist.satisfied(.policy_keyboard_navigation_gate));
    try std.testing.expect(checklist.satisfied(.accessibility_redaction));
}

test "OS contract keeps twenty five eleventh-loop agent session passes satisfied" {
    const checklist = currentRepositoryEleventhContract();
    try std.testing.expectEqual(@as(usize, 25), eleventh_feature_count);
    try std.testing.expectEqual(eleventh_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.agent_manifest_session_binding));
    try std.testing.expect(checklist.satisfied(.agent_session_service_model));
    try std.testing.expect(checklist.satisfied(.agent_action_binding_gate));
    try std.testing.expect(checklist.satisfied(.policy_agent_kill_switch_gate));
    try std.testing.expect(checklist.satisfied(.agent_session_cumulative_context_budget));
    try std.testing.expect(checklist.satisfied(.agent_action_denial_audit));
    try std.testing.expect(checklist.satisfied(.agent_session_redaction));
}

test "OS contract keeps twenty two twelfth-loop background activity passes satisfied" {
    const checklist = currentRepositoryTwelfthContract();
    try std.testing.expectEqual(@as(usize, 22), twelfth_feature_count);
    try std.testing.expectEqual(twelfth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.background_manifest_decl));
    try std.testing.expect(checklist.satisfied(.policy_background_network_gate));
    try std.testing.expect(checklist.satisfied(.typed_background_activity_service));
    try std.testing.expect(checklist.satisfied(.background_completion_binding_gate));
    try std.testing.expect(checklist.satisfied(.background_dispatch_runtime_gate));
    try std.testing.expect(checklist.satisfied(.background_expiration_watchdog));
    try std.testing.expect(checklist.satisfied(.background_activity_redaction));
}

test "OS contract keeps sixteen thirteenth-loop secure pasteboard passes satisfied" {
    const checklist = currentRepositoryThirteenthContract();
    try std.testing.expectEqual(@as(usize, 16), thirteenth_feature_count);
    try std.testing.expectEqual(thirteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.secure_pasteboard_service_model));
    try std.testing.expect(checklist.satisfied(.pasteboard_foreground_gesture_gate));
    try std.testing.expect(checklist.satisfied(.pasteboard_read_once_token));
    try std.testing.expect(checklist.satisfied(.pasteboard_destination_principal_bound_grant));
    try std.testing.expect(checklist.satisfied(.pasteboard_redacted_diagnostics));
    try std.testing.expect(checklist.satisfied(.pasteboard_bootstrap_service_contract));
    try std.testing.expect(checklist.satisfied(.pasteboard_boot_image_registry));
}

test "OS contract keeps twenty six fourteenth-loop object resilience passes satisfied" {
    const checklist = currentRepositoryFourteenthContract();
    try std.testing.expectEqual(@as(usize, 26), fourteenth_feature_count);
    try std.testing.expectEqual(fourteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.object_resilience_manifest));
    try std.testing.expect(checklist.satisfied(.typed_object_resilience_service));
    try std.testing.expect(checklist.satisfied(.restore_token_device_bound));
    try std.testing.expect(checklist.satisfied(.restore_snapshot_subject_bound));
    try std.testing.expect(checklist.satisfied(.revoke_snapshot_source_task_bound));
    try std.testing.expect(checklist.satisfied(.backup_revocation_gate));
    try std.testing.expect(checklist.satisfied(.object_resilience_redaction));
    try std.testing.expect(checklist.satisfied(.object_resilience_bootstrap_contract));
    try std.testing.expect(checklist.satisfied(.object_resilience_boot_image_registry));
}

test "OS contract keeps twenty six fifteenth-loop semantic memory passes satisfied" {
    const checklist = currentRepositoryFifteenthContract();
    try std.testing.expectEqual(@as(usize, 26), fifteenth_feature_count);
    try std.testing.expectEqual(fifteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.semantic_index_manifest));
    try std.testing.expect(checklist.satisfied(.typed_index_search_service));
    try std.testing.expect(checklist.satisfied(.semantic_query_operation));
    try std.testing.expect(checklist.satisfied(.semantic_query_index_generation));
    try std.testing.expect(checklist.satisfied(.semantic_query_top_k_ranking));
    try std.testing.expect(checklist.satisfied(.semantic_query_result_redaction));
    try std.testing.expect(checklist.satisfied(.semantic_query_workspace_scope));
    try std.testing.expect(checklist.satisfied(.semantic_memory_ledger));
    try std.testing.expect(checklist.satisfied(.semantic_memory_redaction));
}

test "OS contract keeps twenty two sixteenth-loop passwordless identity passes satisfied" {
    const checklist = currentRepositorySixteenthContract();
    try std.testing.expectEqual(@as(usize, 22), sixteenth_feature_count);
    try std.testing.expectEqual(sixteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.passwordless_unlock_methods));
    try std.testing.expect(checklist.satisfied(.credential_phishing_origin_rejection));
    try std.testing.expect(checklist.satisfied(.synced_credential_recovery_device_graph));
    try std.testing.expect(checklist.satisfied(.identity_credential_assert_operation));
    try std.testing.expect(checklist.satisfied(.credential_ledger));
    try std.testing.expect(checklist.satisfied(.credential_redaction));
}

test "OS contract keeps twenty three seventeenth-loop private sync passes satisfied" {
    const checklist = currentRepositorySeventeenthContract();
    try std.testing.expectEqual(@as(usize, 23), seventeenth_feature_count);
    try std.testing.expectEqual(seventeenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.deterministic_document_merge));
    try std.testing.expect(checklist.satisfied(.encrypted_transport_queue));
    try std.testing.expect(checklist.satisfied(.sync_destination_policy_gate));
    try std.testing.expect(checklist.satisfied(.sync_workspace_replicate_operation));
    try std.testing.expect(checklist.satisfied(.sync_conflict_redaction));
    try std.testing.expect(checklist.satisfied(.sync_boot_image_registry));
}

test "OS contract keeps twenty two eighteenth-loop sensitive capture passes satisfied" {
    const checklist = currentRepositoryEighteenthContract();
    try std.testing.expectEqual(@as(usize, 22), eighteenth_feature_count);
    try std.testing.expect(checklist.satisfied(.sensitive_capture_service_model));
    try std.testing.expect(checklist.satisfied(.capture_foreground_session_gate));
    try std.testing.expect(checklist.satisfied(.capture_privacy_indicator_gate));
    try std.testing.expect(checklist.satisfied(.capture_background_denial));
    try std.testing.expect(checklist.satisfied(.capture_lease_policy_gate));
    try std.testing.expect(checklist.satisfied(.capture_indicator_expiry_boundary));
    try std.testing.expect(checklist.satisfied(.capture_session_binding_gate));
    try std.testing.expect(checklist.satisfied(.capture_sample_budget_gate));
    try std.testing.expect(checklist.satisfied(.capture_permission_kind_policy_gate));
    try std.testing.expect(checklist.satisfied(.capture_revocation_gate));
    try std.testing.expect(checklist.satisfied(.sensitive_capture_ledger));
    try std.testing.expect(checklist.satisfied(.sensitive_capture_redaction));
    try std.testing.expect(checklist.satisfied(.typed_sensitive_capture_service));
    try std.testing.expect(checklist.satisfied(.capture_start_operation));
    try std.testing.expect(checklist.satisfied(.capture_sample_operation));
    try std.testing.expect(checklist.satisfied(.capture_stop_operation));
    try std.testing.expect(checklist.satisfied(.native_registry_capture_discovery));
    try std.testing.expect(checklist.satisfied(.capture_bootstrap_service_contract));
    try std.testing.expect(checklist.satisfied(.capture_boot_image_registry));
    try std.testing.expect(checklist.satisfied(.camera_permission_manifest_lease));
    try std.testing.expect(checklist.satisfied(.microphone_permission_manifest_lease));
    try std.testing.expect(checklist.satisfied(.screen_capture_permission_manifest_lease));
    try std.testing.expectEqual(eighteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps twenty five nineteenth-loop secret vault passes satisfied" {
    const checklist = currentRepositoryNineteenthContract();
    try std.testing.expectEqual(@as(usize, 25), nineteenth_feature_count);
    try std.testing.expect(checklist.satisfied(.secret_vault_service_model));
    try std.testing.expect(checklist.satisfied(.hardware_sealed_import));
    try std.testing.expect(checklist.satisfied(.nonresident_secret_material));
    try std.testing.expect(checklist.satisfied(.secret_owner_binding));
    try std.testing.expect(checklist.satisfied(.leased_handle_lending));
    try std.testing.expect(checklist.satisfied(.secret_handle_expiry_boundary));
    try std.testing.expect(checklist.satisfied(.raw_export_policy_denial));
    try std.testing.expect(checklist.satisfied(.raw_export_handle_capability_gate));
    try std.testing.expect(checklist.satisfied(.raw_export_success_audit));
    try std.testing.expect(checklist.satisfied(.store_handle_identity_binding));
    try std.testing.expect(checklist.satisfied(.secret_rotation_revokes_old_handles));
    try std.testing.expect(checklist.satisfied(.explicit_handle_revocation));
    try std.testing.expect(checklist.satisfied(.secret_revoke_binding_gate));
    try std.testing.expect(checklist.satisfied(.secret_hardware_policy_gate));
    try std.testing.expect(checklist.satisfied(.secret_lease_policy_gate));
    try std.testing.expect(checklist.satisfied(.secret_vault_ledger));
    try std.testing.expect(checklist.satisfied(.secret_vault_redaction));
    try std.testing.expect(checklist.satisfied(.typed_secret_vault_service));
    try std.testing.expect(checklist.satisfied(.secret_import_operation));
    try std.testing.expect(checklist.satisfied(.secret_lend_operation));
    try std.testing.expect(checklist.satisfied(.secret_rotate_operation));
    try std.testing.expect(checklist.satisfied(.secret_revoke_operation));
    try std.testing.expect(checklist.satisfied(.native_registry_secret_discovery));
    try std.testing.expect(checklist.satisfied(.secret_vault_bootstrap_contract));
    try std.testing.expect(checklist.satisfied(.secret_vault_boot_image_registry));
    try std.testing.expectEqual(nineteenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps twenty one twentieth-loop attention broker passes satisfied" {
    const checklist = currentRepositoryTwentiethContract();
    try std.testing.expectEqual(@as(usize, 21), twentieth_feature_count);
    try std.testing.expect(checklist.satisfied(.attention_broker_service_model));
    try std.testing.expect(checklist.satisfied(.brokered_notification_post));
    try std.testing.expect(checklist.satisfied(.notification_default_task_binding));
    try std.testing.expect(checklist.satisfied(.quiet_interrupt_denial));
    try std.testing.expect(checklist.satisfied(.critical_interrupt_denial));
    try std.testing.expect(checklist.satisfied(.visible_budget_denial));
    try std.testing.expect(checklist.satisfied(.interruption_budget_denial));
    try std.testing.expect(checklist.satisfied(.notification_dismissal));
    try std.testing.expect(checklist.satisfied(.notification_task_bound_dismissal));
    try std.testing.expect(checklist.satisfied(.notification_strict_expiry_boundary));
    try std.testing.expect(checklist.satisfied(.latest_visible_query));
    try std.testing.expect(checklist.satisfied(.attention_broker_policy_gate));
    try std.testing.expect(checklist.satisfied(.attention_broker_ledger));
    try std.testing.expect(checklist.satisfied(.attention_broker_redaction));
    try std.testing.expect(checklist.satisfied(.typed_attention_broker_service));
    try std.testing.expect(checklist.satisfied(.attention_post_operation));
    try std.testing.expect(checklist.satisfied(.attention_dismiss_operation));
    try std.testing.expect(checklist.satisfied(.attention_query_operation));
    try std.testing.expect(checklist.satisfied(.native_registry_attention_discovery));
    try std.testing.expect(checklist.satisfied(.attention_broker_bootstrap_contract));
    try std.testing.expect(checklist.satisfied(.attention_broker_boot_image_registry));
    try std.testing.expectEqual(twentieth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps nineteen twenty-first-loop task lifecycle passes satisfied" {
    const checklist = currentRepositoryTwentyFirstContract();
    try std.testing.expectEqual(@as(usize, 19), twenty_first_feature_count);
    try std.testing.expect(checklist.satisfied(.task_lifecycle_service_model));
    try std.testing.expect(checklist.satisfied(.brokered_task_suspend));
    try std.testing.expect(checklist.satisfied(.invalid_suspend_denial));
    try std.testing.expect(checklist.satisfied(.brokered_task_resume));
    try std.testing.expect(checklist.satisfied(.terminate_checkpoint_policy_denial));
    try std.testing.expect(checklist.satisfied(.brokered_task_terminate));
    try std.testing.expect(checklist.satisfied(.lifecycle_target_owner_binding));
    try std.testing.expect(checklist.satisfied(.task_lifecycle_policy_gate));
    try std.testing.expect(checklist.satisfied(.task_lifecycle_runtime_audit));
    try std.testing.expect(checklist.satisfied(.task_lifecycle_ledger));
    try std.testing.expect(checklist.satisfied(.task_lifecycle_redaction));
    try std.testing.expect(checklist.satisfied(.typed_task_lifecycle_service));
    try std.testing.expect(checklist.satisfied(.lifecycle_suspend_operation));
    try std.testing.expect(checklist.satisfied(.lifecycle_resume_operation));
    try std.testing.expect(checklist.satisfied(.lifecycle_terminate_operation));
    try std.testing.expect(checklist.satisfied(.native_registry_lifecycle_discovery));
    try std.testing.expect(checklist.satisfied(.lifecycle_bootstrap_contract));
    try std.testing.expect(checklist.satisfied(.lifecycle_boot_image_registry));
    try std.testing.expect(checklist.satisfied(.lifecycle_policy_digest));
    try std.testing.expectEqual(twenty_first_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps eighteen twenty-second-loop package offboarding passes satisfied" {
    const checklist = currentRepositoryTwentySecondContract();
    try std.testing.expectEqual(@as(usize, 18), twenty_second_feature_count);
    try std.testing.expect(checklist.satisfied(.package_offboarding_service_model));
    try std.testing.expect(checklist.satisfied(.package_port_offboarding_authority_path));
    try std.testing.expect(checklist.satisfied(.offboard_policy_delete_gate));
    try std.testing.expect(checklist.satisfied(.offboard_receipt_required));
    try std.testing.expect(checklist.satisfied(.denied_offboard_preserves_install));
    try std.testing.expect(checklist.satisfied(.receipt_backed_package_remove));
    try std.testing.expect(checklist.satisfied(.offboard_result_receipt));
    try std.testing.expect(checklist.satisfied(.offboard_removed_bundle_digest));
    try std.testing.expect(checklist.satisfied(.offboard_removed_bundle_digest_content_binding));
    try std.testing.expect(checklist.satisfied(.offboard_revision_purge));
    try std.testing.expect(checklist.satisfied(.removed_bundle_unlaunchable));
    try std.testing.expect(checklist.satisfied(.offboard_data_deletion_ledger));
    try std.testing.expect(checklist.satisfied(.offboard_redaction));
    try std.testing.expect(checklist.satisfied(.typed_package_remove_operation));
    try std.testing.expect(checklist.satisfied(.package_remove_operation_id));
    try std.testing.expect(checklist.satisfied(.package_remove_wire_validation));
    try std.testing.expect(checklist.satisfied(.package_registry_discovery));
    try std.testing.expect(checklist.satisfied(.package_offboard_policy_digest));
    try std.testing.expectEqual(twenty_second_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps sixteen twenty-third-loop resource governance passes satisfied" {
    const checklist = currentRepositoryTwentyThirdContract();
    try std.testing.expectEqual(@as(usize, 16), twenty_third_feature_count);
    try std.testing.expect(checklist.satisfied(.scheduler_resource_governance_model));
    try std.testing.expect(checklist.satisfied(.hardware_telemetry_provider_boundary));
    try std.testing.expect(checklist.satisfied(.hardware_evidence_required_for_accelerator_queues));
    try std.testing.expect(checklist.satisfied(.foreground_thermal_dispatch));
    try std.testing.expect(checklist.satisfied(.emergency_pressure_bypass));
    try std.testing.expect(checklist.satisfied(.background_thermal_delay));
    try std.testing.expect(checklist.satisfied(.batch_battery_delay));
    try std.testing.expect(checklist.satisfied(.batch_recovers_after_pressure));
    try std.testing.expect(checklist.satisfied(.pressure_delay_reason_accounting));
    try std.testing.expect(checklist.satisfied(.dispatch_budget_accounting));
    try std.testing.expect(checklist.satisfied(.privacy_mode_degrades_accelerator));
    try std.testing.expect(checklist.satisfied(.carbon_aware_planner_compat));
    try std.testing.expect(checklist.satisfied(.resource_governance_ledger));
    try std.testing.expect(checklist.satisfied(.resource_governance_diagnostics));
    try std.testing.expect(checklist.satisfied(.resource_governance_redaction));
    try std.testing.expect(checklist.satisfied(.resource_governance_query_index));
    try std.testing.expectEqual(twenty_third_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps twenty twenty-fourth-loop network session passes satisfied" {
    const checklist = currentRepositoryTwentyFourthContract();
    try std.testing.expectEqual(@as(usize, 20), twenty_fourth_feature_count);
    try std.testing.expect(checklist.satisfied(.network_session_service_model));
    try std.testing.expect(checklist.satisfied(.existing_egress_broker_composed));
    try std.testing.expect(checklist.satisfied(.allow_list_destination_gate));
    try std.testing.expect(checklist.satisfied(.attested_session_open));
    try std.testing.expect(checklist.satisfied(.session_byte_budget));
    try std.testing.expect(checklist.satisfied(.session_expiry_boundary_gate));
    try std.testing.expect(checklist.satisfied(.session_effective_budget_policy));
    try std.testing.expect(checklist.satisfied(.transfer_over_budget_denied));
    try std.testing.expect(checklist.satisfied(.session_mutation_binding));
    try std.testing.expect(checklist.satisfied(.session_revocation_gate));
    try std.testing.expect(checklist.satisfied(.revoked_session_transfer_denied));
    try std.testing.expect(checklist.satisfied(.completed_session_transfer_denied));
    try std.testing.expect(checklist.satisfied(.network_session_ledger));
    try std.testing.expect(checklist.satisfied(.network_session_diagnostics));
    try std.testing.expect(checklist.satisfied(.network_session_redaction));
    try std.testing.expect(checklist.satisfied(.typed_network_open_session_operation));
    try std.testing.expect(checklist.satisfied(.typed_network_transfer_operation));
    try std.testing.expect(checklist.satisfied(.typed_network_revoke_operation));
    try std.testing.expect(checklist.satisfied(.network_session_wire_validation));
    try std.testing.expect(checklist.satisfied(.network_stack_catalog_binding));
    try std.testing.expectEqual(twenty_fourth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract keeps thirty nine twenty-fifth-loop personal context passes satisfied" {
    const checklist = currentRepositoryTwentyFifthContract();
    try std.testing.expectEqual(@as(usize, 39), twenty_fifth_feature_count);
    try std.testing.expect(checklist.satisfied(.personal_context_service_model));
    try std.testing.expect(checklist.satisfied(.semantic_policy_composed));
    try std.testing.expect(checklist.satisfied(.local_model_gate));
    try std.testing.expect(checklist.satisfied(.encrypted_index_gate));
    try std.testing.expect(checklist.satisfied(.redacted_snippet_gate));
    try std.testing.expect(checklist.satisfied(.context_query_byte_budget));
    try std.testing.expect(checklist.satisfied(.context_lease_issue));
    try std.testing.expect(checklist.satisfied(.context_lease_query_accounting));
    try std.testing.expect(checklist.satisfied(.context_query_canonical_byte_metering));
    try std.testing.expect(checklist.satisfied(.context_indexed_retrieval));
    try std.testing.expect(checklist.satisfied(.context_pack_redaction));
    try std.testing.expect(checklist.satisfied(.context_pack_receipt));
    try std.testing.expect(checklist.satisfied(.context_pack_index_generation));
    try std.testing.expect(checklist.satisfied(.context_pack_index_staleness_guard));
    try std.testing.expect(checklist.satisfied(.context_pack_accounting_snapshot_guard));
    try std.testing.expect(checklist.satisfied(.context_pack_envelope_consistency));
    try std.testing.expect(checklist.satisfied(.context_pack_request_fingerprint));
    try std.testing.expect(checklist.satisfied(.context_pack_sensitivity_envelope));
    try std.testing.expect(checklist.satisfied(.context_pack_empty_receipt));
    try std.testing.expect(checklist.satisfied(.context_pack_freshness));
    try std.testing.expect(checklist.satisfied(.context_pack_revocation_binding));
    try std.testing.expect(checklist.satisfied(.context_pack_replay_guard));
    try std.testing.expect(checklist.satisfied(.context_pack_live_replay_verifier));
    try std.testing.expect(checklist.satisfied(.context_pack_receipt_audit));
    try std.testing.expect(checklist.satisfied(.context_pack_invalid_receipt_audit));
    try std.testing.expect(checklist.satisfied(.context_pack_malformed_receipt_audit));
    try std.testing.expect(checklist.satisfied(.context_pack_policy_reauthorization));
    try std.testing.expect(checklist.satisfied(.context_lease_privacy_mode_binding));
    try std.testing.expect(checklist.satisfied(.context_lease_expiration_gate));
    try std.testing.expect(checklist.satisfied(.context_lease_revocation_gate));
    try std.testing.expect(checklist.satisfied(.context_workspace_scope_gate));
    try std.testing.expect(checklist.satisfied(.personal_context_ledger));
    try std.testing.expect(checklist.satisfied(.personal_context_diagnostics));
    try std.testing.expect(checklist.satisfied(.personal_context_redaction));
    try std.testing.expect(checklist.satisfied(.typed_context_lease_operation));
    try std.testing.expect(checklist.satisfied(.typed_context_query_operation));
    try std.testing.expect(checklist.satisfied(.typed_context_revoke_operation));
    try std.testing.expect(checklist.satisfied(.context_wire_validation));
    try std.testing.expect(checklist.satisfied(.personal_context_catalog_binding));
    try std.testing.expectEqual(twenty_fifth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
}

test "OS contract proves AI policy and diagnostics stay private by default" {
    var policies = policy_object.Directory.init();
    const signer = signing.SignerIdentity{
        .label = "os-contract-policy",
        .seed = signing.seedFromByte(0xCE),
    };
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2026,
        .issuer = .{ .kind = .policy_authority, .serial = 2026 },
        .label = "private-local-ai",
        .network_egress_mode = .local_only,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 2048,
    }, signer);
    const subjects = policy_object.SubjectSet{
        .organization_id = 2026,
    };

    try std.testing.expect(!policies.aiUseDecision(subjects, .{
        .remote_model = true,
        .context_bytes = 512,
    }).allowed);
    try std.testing.expect(!policies.aiUseDecision(subjects, .{
        .training_user_content = true,
        .context_bytes = 512,
    }).allowed);
    try std.testing.expect(!policies.aiUseDecision(subjects, .{
        .context_bytes = 4096,
    }).allowed);
    try std.testing.expect(policies.aiUseDecision(subjects, .{
        .context_bytes = 1024,
    }).allowed);

    var ledger = event_ledger.Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 26 };
    try ledger.recordAiInference(user, 2601, false, true, false, 12, "private prompt");
    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 1), summary.ai_inference_events);
    try std.testing.expectEqual(@as(usize, 1), summary.ai_remote_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.protected_details_redacted);
}
