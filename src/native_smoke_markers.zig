const std = @import("std");
const boot_markers = @import("kernel/boot/markers.zig");

pub const ready = boot_markers.native_ready;

pub const cold_boot_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_zigos_native,
    boot_markers.boot_core_ready,
    boot_markers.kernel_network_deferred,
    boot_markers.native_bootstrap,
    boot_markers.tcb_defined,
    boot_markers.userspace_scheduler_ready,
    boot_markers.userspace_artifacts_ready,
    boot_markers.transport_native_kernel_ready,
    boot_markers.transport_no_root,
    boot_markers.transport_component_abi_ready,
    boot_markers.runtime_proof_process_isolation,
    boot_markers.runtime_proof_syscall_pointer_isolation,
    boot_markers.runtime_proof_mmu_user_fault,
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
    boot_markers.service_boot_service_contracts_ready,
    boot_markers.service_boot_supervisor_crash_recorded,
    boot_markers.service_boot_driver_rehost_ok,
    boot_markers.service_boot_supervisor_restart_ok,
    boot_markers.service_boot_supervisor_restart_without_reboot,
    "ZIGOS:SERVICE_BOOT:COMPAT_PORTAL:READY",
    boot_markers.platform_bootloader_measurement_provided,
    boot_markers.platform_build_artifact_manifest_verified,
    boot_markers.platform_artifact_manifest_verified,
    boot_markers.platform_measured_boot_recorded,
    boot_markers.platform_measured_boot_verified_root,
    boot_markers.task_session_ready,
    boot_markers.native_ready,
};

pub const cold_reboot_required = [_][]const u8{
    boot_markers.platform_measured_boot_same_root,
    boot_markers.platform_measured_boot_same_shape,
};

pub const first_boot_required = [_][]const u8{
    boot_markers.platform_measured_boot_first,
};

pub const driver_restart_required = [_][]const u8{
    boot_markers.service_boot_supervisor_crash_recorded,
    boot_markers.service_boot_driver_rehost_ok,
    boot_markers.service_boot_supervisor_restart_ok,
    boot_markers.service_boot_supervisor_restart_without_reboot,
};

pub const ab_rollback_required = [_][]const u8{
    boot_markers.platform_immutable_base_active,
    boot_markers.platform_immutable_base_boot_selection,
    boot_markers.platform_activation_rollback_ok,
    boot_markers.platform_ab_image_rollback_ok,
};

pub const recovery_required = [_][]const u8{
    boot_markers.boot_start,
    boot_markers.boot_profile_recovery,
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

test "native smoke gate requires runtime isolation proof markers" {
    const required = [_][]const u8{
        boot_markers.transport_no_root,
        boot_markers.runtime_proof_process_isolation,
        boot_markers.runtime_proof_syscall_pointer_isolation,
        boot_markers.runtime_proof_mmu_user_fault,
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
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_measured_boot_recorded));
    try std.testing.expect(contains(&cold_boot_required, boot_markers.platform_measured_boot_verified_root));
    try std.testing.expect(contains(&first_boot_required, boot_markers.platform_measured_boot_first));
    try std.testing.expect(contains(&cold_reboot_required, boot_markers.platform_measured_boot_same_root));
    try std.testing.expect(contains(&cold_reboot_required, boot_markers.platform_measured_boot_same_shape));
}

test "native smoke gate requires in-boot driver crash restart proof markers" {
    for (driver_restart_required) |marker| {
        try std.testing.expect(contains(&cold_boot_required, marker));
    }
}

test "native smoke gate requires A/B image rollback proof markers" {
    for (ab_rollback_required) |marker| {
        try std.testing.expect(contains(&ab_rollback_required, marker));
    }
}

test "native smoke gate requires freestanding recovery proof markers" {
    for (recovery_required) |marker| {
        try std.testing.expect(contains(&recovery_required, marker));
    }
}
