const std = @import("std");
const boot_markers = @import("kernel/boot/markers.zig");

pub const ready = boot_markers.native_ready;

pub const production_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_production,
    boot_markers.cpu_baseline_ready,
    boot_markers.cpu_nx_enabled,
    boot_markers.boot_core_ready,
    boot_markers.kernel_network_deferred,
    boot_markers.native_bootstrap,
    boot_markers.tcb_defined,
    boot_markers.userspace_scheduler_ready,
    boot_markers.userspace_artifacts_ready,
    boot_markers.userspace_exec_probe_ok,
    boot_markers.userspace_resume_ok,
    boot_markers.transport_native_kernel_ready,
    boot_markers.transport_no_root,
    boot_markers.transport_component_abi_ready,
    boot_markers.supervisor_ready,
    boot_markers.service_contract_map_ready,
    boot_markers.policy_ready,
    boot_markers.service_boot_driver_service_network_ready,
    boot_markers.service_boot_driver_service_storage_ready,
    boot_markers.service_boot_service_contracts_ready,
    boot_markers.platform_bootloader_measurement_provided,
    boot_markers.platform_build_artifact_manifest_verified,
    boot_markers.platform_bootloader_handoff_verified,
    boot_markers.platform_artifact_manifest_verified,
    boot_markers.platform_measured_boot_recorded,
    boot_markers.platform_measured_boot_verified_root,
    boot_markers.storage_checkpoint_final_clean,
    boot_markers.task_session_ready,
    boot_markers.native_ready,
};

pub const production_forbidden = [_][]const u8{
    boot_markers.kernel_role_verification,
    boot_markers.runtime_proof_process_isolation,
    boot_markers.service_boot_ipc_connect_all_ok,
    boot_markers.service_boot_supervisor_crash_recorded,
    boot_markers.service_boot_driver_rehost_ok,
    boot_markers.platform_activation_rollback_ok,
    boot_markers.platform_health_checks_boot_rollback,
    boot_markers.permission_review_port_ready,
    boot_markers.notes_daily_driver_complete,
    "app.notes.daily",
    "userspace-notes-daily.elf",
    "zigos.system.transport-probe",
    "userspace-transport-probe.elf",
    "zigos.system.termination-probe",
    "userspace-termination-probe.elf",
    "zigos.system.service-client",
    "userspace-service-client.elf",
    "zigos.proof.mmu-isolation",
    "userspace-mmu-isolation-proof.elf",
};

pub const production_first_boot_required = [_][]const u8{
    boot_markers.platform_measured_boot_first,
};

pub const production_reboot_required = [_][]const u8{
    boot_markers.platform_measured_boot_same_root,
    boot_markers.platform_measured_boot_same_shape,
};

pub const cold_boot_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.cpu_baseline_ready,
    boot_markers.cpu_nx_enabled,
    boot_markers.boot_core_ready,
    boot_markers.kernel_network_deferred,
    boot_markers.native_bootstrap,
    boot_markers.tcb_defined,
    boot_markers.userspace_scheduler_ready,
    boot_markers.userspace_artifacts_ready,
    boot_markers.userspace_exec_probe_ok,
    boot_markers.userspace_resume_ok,
    boot_markers.transport_native_kernel_ready,
    boot_markers.transport_no_root,
    boot_markers.transport_component_abi_ready,
    boot_markers.runtime_proof_process_isolation,
    boot_markers.runtime_proof_syscall_pointer_isolation,
    boot_markers.runtime_proof_user_nx_fault,
    boot_markers.runtime_proof_mmu_user_fault,
    boot_markers.runtime_proof_address_space_reclamation,
    boot_markers.runtime_proof_syscall_subject_spoof,
    boot_markers.runtime_proof_raw_network_bypass,
    boot_markers.runtime_proof_driver_authority_escape,
    boot_markers.runtime_proof_reboot_grant_revocation,
    boot_markers.supervisor_ready,
    boot_markers.service_contract_map_ready,
    boot_markers.policy_ready,
    boot_markers.permission_ui_service_ready,
    boot_markers.permission_ui_service_task_ready,
    boot_markers.service_boot_driver_service_network_ready,
    boot_markers.service_boot_driver_service_storage_ready,
    boot_markers.service_boot_service_contracts_ready,
    boot_markers.service_boot_supervisor_crash_recorded,
    boot_markers.service_boot_driver_rehost_ok,
    boot_markers.service_boot_supervisor_restart_ok,
    boot_markers.service_boot_supervisor_restart_without_reboot,
    boot_markers.service_boot_storage_io_before_restart_ok,
    boot_markers.service_boot_storage_dma_domain_programmed,
    boot_markers.service_boot_storage_brokered_dma_buffer_ok,
    boot_markers.service_boot_storage_timeout_propagated,
    boot_markers.service_boot_storage_partial_transfer_rejected,
    boot_markers.service_boot_storage_stale_authority_rejected,
    boot_markers.service_boot_storage_stale_dma_port_rejected,
    boot_markers.service_boot_storage_stale_access_rejected,
    boot_markers.service_boot_storage_rebind_ok,
    boot_markers.service_boot_storage_broker_revoke_rejected,
    boot_markers.service_boot_storage_republish_after_revoke_ok,
    boot_markers.service_boot_storage_io_after_restart_ok,
    boot_markers.service_boot_accelerator_queue_owned,
    boot_markers.service_boot_accelerator_completion_interrupt,
    boot_markers.service_boot_ipc_connect_all_ok,
    boot_markers.permission_review_port_ready,
    boot_markers.permission_policy_port_ready,
    boot_markers.permission_manifest_valid,
    boot_markers.permission_zero_authority_deny_network,
    boot_markers.permission_zero_authority_deny_clipboard,
    boot_markers.permission_grant_object_local,
    boot_markers.permission_grant_network_local,
    boot_markers.permission_deny_clipboard,
    boot_markers.permission_elf_substrate_ok,
    boot_markers.permission_grant_device_local,
    boot_markers.permission_grant_camera,
    boot_markers.permission_deny_mic,
    boot_markers.permission_grant_sensor_local,
    boot_markers.permission_grant_peer_ipc_local,
    boot_markers.permission_lease_expired,
    boot_markers.permission_ui_review_rendered,
    boot_markers.permission_xhci_keyboard_report,
    boot_markers.permission_xhci_review_command,
    boot_markers.permission_xhci_boot_flow_commands,
    boot_markers.platform_bootloader_measurement_provided,
    boot_markers.platform_build_artifact_manifest_verified,
    boot_markers.platform_bootloader_handoff_verified,
    boot_markers.platform_artifact_manifest_verified,
    boot_markers.platform_health_checks_boot_rollback,
    boot_markers.platform_health_checks_core_rollback,
    boot_markers.platform_health_checks_storage_rollback,
    boot_markers.platform_health_checks_network_rollback,
    boot_markers.platform_health_checks_ui_rollback,
    boot_markers.platform_health_checks_promote_ok,
    boot_markers.platform_measured_boot_recorded,
    boot_markers.platform_measured_boot_verified_root,
    boot_markers.notes_daily_driver_install_open_ok,
    boot_markers.notes_daily_driver_edit_saved_ok,
    boot_markers.notes_daily_driver_share_sync_ok,
    boot_markers.notes_daily_driver_update_rollback_ok,
    boot_markers.notes_daily_driver_recovery_remove_ok,
    boot_markers.notes_daily_driver_authority_revoked_ok,
    boot_markers.notes_daily_driver_typed_edit_ok,
    boot_markers.notes_daily_driver_typed_sync_ok,
    boot_markers.notes_daily_driver_typed_recovery_ok,
    boot_markers.notes_daily_driver_typed_loop_complete,
    boot_markers.notes_daily_driver_complete,
    boot_markers.task_session_ready,
    boot_markers.native_ready,
};

pub const cold_reboot_required = [_][]const u8{
    boot_markers.platform_measured_boot_same_root,
    boot_markers.platform_measured_boot_same_shape,
    boot_markers.platform_base_selector_cold_reboot_slot_verified,
};

pub const first_boot_required = [_][]const u8{
    boot_markers.platform_measured_boot_first,
};

pub const driver_restart_required = [_][]const u8{
    boot_markers.kernel_role_verification,
    boot_markers.service_boot_supervisor_crash_recorded,
    boot_markers.service_boot_driver_rehost_ok,
    boot_markers.service_boot_supervisor_restart_ok,
    boot_markers.service_boot_supervisor_restart_without_reboot,
    boot_markers.service_boot_storage_io_before_restart_ok,
    boot_markers.service_boot_storage_dma_domain_programmed,
    boot_markers.service_boot_storage_brokered_dma_buffer_ok,
    boot_markers.service_boot_storage_timeout_propagated,
    boot_markers.service_boot_storage_partial_transfer_rejected,
    boot_markers.service_boot_storage_stale_authority_rejected,
    boot_markers.service_boot_storage_stale_dma_port_rejected,
    boot_markers.service_boot_storage_stale_access_rejected,
    boot_markers.service_boot_storage_rebind_ok,
    boot_markers.service_boot_storage_broker_revoke_rejected,
    boot_markers.service_boot_storage_republish_after_revoke_ok,
    boot_markers.service_boot_storage_io_after_restart_ok,
    boot_markers.service_boot_accelerator_queue_owned,
    boot_markers.service_boot_accelerator_completion_interrupt,
};

pub const service_startup_required = [_][]const u8{
    boot_markers.userspace_artifacts_ready,
    boot_markers.userspace_scheduler_ready,
    boot_markers.userspace_exec_probe_ok,
    boot_markers.userspace_resume_ok,
    boot_markers.transport_native_kernel_ready,
    boot_markers.transport_component_abi_ready,
    boot_markers.service_boot_driver_service_network_ready,
    boot_markers.service_boot_driver_service_storage_ready,
    boot_markers.service_boot_service_contracts_ready,
    boot_markers.service_boot_ipc_connect_all_ok,
};

pub const permission_review_required = [_][]const u8{
    boot_markers.permission_ui_service_ready,
    boot_markers.permission_ui_service_task_ready,
    boot_markers.permission_review_port_ready,
    boot_markers.permission_policy_port_ready,
    boot_markers.permission_manifest_valid,
    boot_markers.permission_zero_authority_deny_network,
    boot_markers.permission_zero_authority_deny_clipboard,
    boot_markers.permission_grant_object_local,
    boot_markers.permission_grant_network_local,
    boot_markers.permission_deny_clipboard,
    boot_markers.permission_elf_substrate_ok,
    boot_markers.permission_grant_device_local,
    boot_markers.permission_grant_camera,
    boot_markers.permission_deny_mic,
    boot_markers.permission_grant_sensor_local,
    boot_markers.permission_grant_peer_ipc_local,
    boot_markers.permission_lease_expired,
    boot_markers.permission_ui_review_rendered,
    boot_markers.permission_xhci_keyboard_report,
    boot_markers.permission_xhci_review_command,
    boot_markers.permission_xhci_boot_flow_commands,
};

pub const ab_rollback_required = [_][]const u8{
    boot_markers.platform_immutable_base_active,
    boot_markers.platform_immutable_base_boot_selection,
    boot_markers.platform_activation_rollback_ok,
    boot_markers.platform_ab_image_rollback_ok,
    boot_markers.platform_base_selector_active_slot_verified,
    boot_markers.platform_base_selector_rollback_before_service,
};

pub const update_rollback_required = [_][]const u8{
    boot_markers.platform_immutable_base_active,
    boot_markers.platform_immutable_base_boot_selection,
    boot_markers.platform_activation_rollback_ok,
    boot_markers.platform_ab_image_rollback_ok,
    boot_markers.platform_base_selector_active_slot_verified,
    boot_markers.platform_base_selector_rollback_before_service,
    boot_markers.platform_health_checks_boot_rollback,
    boot_markers.platform_health_checks_core_rollback,
    boot_markers.platform_health_checks_storage_rollback,
    boot_markers.platform_health_checks_network_rollback,
    boot_markers.platform_health_checks_ui_rollback,
    boot_markers.platform_health_checks_promote_ok,
};

pub const tampered_artifact_manifest_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_artifact_manifest_tamper_rejected,
};

pub const tampered_bootloader_measurement_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_bootloader_measurement_tamper_rejected,
};

pub const tampered_kernel_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_artifact_kernel_tamper_rejected,
};

pub const tampered_userspace_image_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_artifact_userspace_image_tamper_rejected,
};

pub const tampered_policy_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_artifact_policy_tamper_rejected,
};

pub const tampered_driver_set_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_artifact_driver_set_tamper_rejected,
};

pub const rollback_slot_failure_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.platform_base_selector_rollback_slot_failure_rejected,
};

pub const storage_durability_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.boot_core_ready,
    boot_markers.storage_durability_start,
    boot_markers.storage_durability_baseline_checkpointed,
    boot_markers.storage_durability_interrupted_write_staged,
    boot_markers.storage_durability_interrupted_boot_recovered,
    boot_markers.storage_durability_final_checkpointed,
    boot_markers.storage_durability_bad_root_slot_fallback,
    boot_markers.storage_durability_deterministic_recovery,
};

pub const sync_two_node_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.kernel_role_verification,
    boot_markers.transport_native_kernel_ready,
    boot_markers.sync_device_graph_rooted,
    "ZIGOS:SYNC:DEVICE_ENROLL:OK",
    "ZIGOS:SYNC:KEY_ROTATION:OK",
    "ZIGOS:SYNC:DEVICE_REVOKE:OK",
    "ZIGOS:SYNC:NETWORK_POLICY:LOCAL",
    "ZIGOS:SYNC:SYNC_POLICY:OFFLINE_FIRST",
    "ZIGOS:SYNC:SYNC_POLICY:E2EE_PERSONAL",
    "ZIGOS:SYNC:SYNC_POLICY:SELECTIVE",
    "ZIGOS:SYNC:SYNC:DEVICE_TO_DEVICE",
    "ZIGOS:SYNC:SYNC:RELAY",
    boot_markers.sync_native_driver_packet_captured,
    boot_markers.sync_native_driver_frame_sent,
    boot_markers.sync_native_driver_malformed_packet_rejected,
    boot_markers.sync_native_driver_reconnect_ok,
    boot_markers.sync_native_driver_replay_rejected,
    boot_markers.sync_native_driver_congestion_backpressure,
    "ZIGOS:SYNC:DEVICE_REVOKE:ENFORCED",
    "ZIGOS:SYNC:SYNC_SERVICE:RECOVERED",
    boot_markers.native_ready,
};

pub const notes_daily_driver_required = [_][]const u8{
    boot_markers.notes_daily_driver_install_open_ok,
    boot_markers.notes_daily_driver_edit_saved_ok,
    boot_markers.notes_daily_driver_share_sync_ok,
    boot_markers.notes_daily_driver_update_rollback_ok,
    boot_markers.notes_daily_driver_recovery_remove_ok,
    boot_markers.notes_daily_driver_authority_revoked_ok,
    boot_markers.notes_daily_driver_typed_edit_ok,
    boot_markers.notes_daily_driver_typed_sync_ok,
    boot_markers.notes_daily_driver_typed_recovery_ok,
    boot_markers.notes_daily_driver_typed_loop_complete,
    boot_markers.notes_daily_driver_complete,
};

pub const recovery_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_recovery,
    boot_markers.kernel_role_verification,
    boot_markers.cpu_baseline_ready,
    boot_markers.cpu_nx_enabled,
    boot_markers.boot_core_ready,
    boot_markers.recovery_start,
    boot_markers.recovery_break_glass_audited,
    boot_markers.recovery_no_normal_session_authority,
    boot_markers.recovery_reinstall_ok,
    boot_markers.recovery_restore_ok,
    boot_markers.recovery_repair_sync_ok,
    boot_markers.recovery_rotate_keys_ok,
    boot_markers.recovery_revoke_trust_ok,
    boot_markers.recovery_pass,
};

fn contains(group: []const []const u8, marker: []const u8) bool {
    for (group) |candidate| {
        if (std.mem.eql(u8, candidate, marker)) return true;
    }
    return false;
}

test "production smoke gate requires core readiness and excludes verification evidence" {
    const required = [_][]const u8{
        boot_markers.boot_start,
        boot_markers.boot_profile_zigos_native,
        boot_markers.kernel_role_production,
        boot_markers.cpu_baseline_ready,
        boot_markers.cpu_nx_enabled,
        boot_markers.boot_core_ready,
        boot_markers.userspace_artifacts_ready,
        boot_markers.service_boot_service_contracts_ready,
        boot_markers.platform_artifact_manifest_verified,
        boot_markers.platform_measured_boot_verified_root,
        boot_markers.native_ready,
    };
    for (required) |marker| {
        try std.testing.expect(contains(&production_required, marker));
    }
    for (production_forbidden) |marker| {
        try std.testing.expect(!contains(&production_required, marker));
    }
    try std.testing.expect(contains(&production_first_boot_required, boot_markers.platform_measured_boot_first));
    try std.testing.expect(contains(&production_reboot_required, boot_markers.platform_measured_boot_same_root));
    try std.testing.expect(contains(&production_reboot_required, boot_markers.platform_measured_boot_same_shape));
}

test "verification smoke groups require the verification kernel role" {
    try std.testing.expect(contains(&cold_boot_required, boot_markers.cpu_baseline_ready));
    try std.testing.expect(contains(&recovery_required, boot_markers.cpu_baseline_ready));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.cpu_nx_enabled));
    try std.testing.expect(contains(&recovery_required, boot_markers.cpu_nx_enabled));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&driver_restart_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_artifact_manifest_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_bootloader_measurement_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_kernel_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_userspace_image_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_policy_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&tampered_driver_set_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&rollback_slot_failure_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&storage_durability_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.kernel_role_verification));
    try std.testing.expect(contains(&recovery_required, boot_markers.kernel_role_verification));
    try std.testing.expect(!contains(&cold_boot_required, boot_markers.kernel_role_production));
}

test "native smoke gate requires runtime isolation proof markers" {
    const required = [_][]const u8{
        boot_markers.transport_no_root,
        boot_markers.runtime_proof_process_isolation,
        boot_markers.runtime_proof_syscall_pointer_isolation,
        boot_markers.runtime_proof_user_nx_fault,
        boot_markers.runtime_proof_mmu_user_fault,
        boot_markers.runtime_proof_address_space_reclamation,
        boot_markers.runtime_proof_syscall_subject_spoof,
        boot_markers.runtime_proof_raw_network_bypass,
        boot_markers.runtime_proof_driver_authority_escape,
        boot_markers.runtime_proof_reboot_grant_revocation,
    };

    for (required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
}

test "native smoke gate requires measured boot reboot comparison markers" {
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_bootloader_measurement_provided));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_build_artifact_manifest_verified));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_bootloader_handoff_verified));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_measured_boot_recorded));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_measured_boot_verified_root));
    try std.testing.expect(contains(&first_boot_required, boot_markers.platform_measured_boot_first));
    try std.testing.expect(contains(&cold_reboot_required, boot_markers.platform_measured_boot_same_root));
    try std.testing.expect(contains(&cold_reboot_required, boot_markers.platform_measured_boot_same_shape));
    try std.testing.expect(contains(&cold_reboot_required, boot_markers.platform_base_selector_cold_reboot_slot_verified));
}

test "native smoke gate requires in-boot driver crash restart proof markers" {
    for (driver_restart_required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
    try std.testing.expect(contains(&driver_restart_required, boot_markers.service_boot_accelerator_queue_owned));
    try std.testing.expect(contains(&driver_restart_required, boot_markers.service_boot_accelerator_completion_interrupt));
}

test "native smoke gate requires booted service startup proof markers" {
    for (service_startup_required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
}

test "native smoke gate requires booted permission review proof markers" {
    for (permission_review_required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
}

test "native smoke gate requires A/B image rollback proof markers" {
    try std.testing.expect(contains(&ab_rollback_required, boot_markers.platform_immutable_base_active));
    try std.testing.expect(contains(&ab_rollback_required, boot_markers.platform_activation_rollback_ok));
    try std.testing.expect(contains(&ab_rollback_required, boot_markers.platform_ab_image_rollback_ok));
    try std.testing.expect(contains(&ab_rollback_required, boot_markers.platform_base_selector_rollback_before_service));
}

test "native smoke gate requires update rollback proof markers" {
    for (update_rollback_required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker) or contains(&ab_rollback_required, marker));
    }
}

test "native smoke gate requires boot attestation negative proof markers" {
    try std.testing.expect(contains(&tampered_artifact_manifest_required, boot_markers.platform_artifact_manifest_tamper_rejected));
    try std.testing.expect(contains(&tampered_bootloader_measurement_required, boot_markers.platform_bootloader_measurement_tamper_rejected));
    try std.testing.expect(contains(&tampered_kernel_required, boot_markers.platform_artifact_kernel_tamper_rejected));
    try std.testing.expect(contains(&tampered_userspace_image_required, boot_markers.platform_artifact_userspace_image_tamper_rejected));
    try std.testing.expect(contains(&tampered_policy_required, boot_markers.platform_artifact_policy_tamper_rejected));
    try std.testing.expect(contains(&tampered_driver_set_required, boot_markers.platform_artifact_driver_set_tamper_rejected));
    try std.testing.expect(contains(&rollback_slot_failure_required, boot_markers.platform_base_selector_rollback_slot_failure_rejected));
}

test "native smoke gate requires focused storage durability proof markers" {
    try std.testing.expect(contains(&storage_durability_required, boot_markers.storage_durability_start));
    try std.testing.expect(contains(&storage_durability_required, boot_markers.storage_durability_baseline_checkpointed));
    try std.testing.expect(contains(&storage_durability_required, boot_markers.storage_durability_interrupted_write_staged));
    try std.testing.expect(contains(&storage_durability_required, boot_markers.storage_durability_bad_root_slot_fallback));
    try std.testing.expect(contains(&storage_durability_required, boot_markers.storage_durability_deterministic_recovery));
}

test "native smoke gate requires two-node sync transport proof markers" {
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.transport_native_kernel_ready));
    try std.testing.expect(contains(&sync_two_node_required, "ZIGOS:SYNC:SYNC:DEVICE_TO_DEVICE"));
    try std.testing.expect(contains(&sync_two_node_required, "ZIGOS:SYNC:SYNC:RELAY"));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_packet_captured));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_frame_sent));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_malformed_packet_rejected));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_reconnect_ok));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_replay_rejected));
    try std.testing.expect(contains(&sync_two_node_required, boot_markers.sync_native_driver_congestion_backpressure));
    try std.testing.expect(contains(&sync_two_node_required, "ZIGOS:SYNC:SYNC_SERVICE:RECOVERED"));
}

test "native smoke marker contract includes the Notes daily-driver proof path" {
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_install_open_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_edit_saved_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_share_sync_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_update_rollback_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_recovery_remove_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_authority_revoked_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_typed_edit_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_typed_sync_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_typed_recovery_ok));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_typed_loop_complete));
    try std.testing.expect(contains(&notes_daily_driver_required, boot_markers.notes_daily_driver_complete));
}

test "native smoke gate requires production post-activation health proof markers" {
    const required = [_][]const u8{
        boot_markers.platform_health_checks_boot_rollback,
        boot_markers.platform_health_checks_core_rollback,
        boot_markers.platform_health_checks_storage_rollback,
        boot_markers.platform_health_checks_network_rollback,
        boot_markers.platform_health_checks_ui_rollback,
        boot_markers.platform_health_checks_promote_ok,
    };

    for (required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
}

test "native smoke gate requires freestanding recovery proof markers" {
    for (recovery_required) |marker| {
        try std.testing.expect(contains(&recovery_required, marker));
    }
}
