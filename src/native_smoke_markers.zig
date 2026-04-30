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
    "ZIGOS:SERVICE_BOOT:COMPAT_PORTAL:READY",
    boot_markers.platform_measured_boot_recorded,
    boot_markers.task_session_ready,
    boot_markers.native_ready,
};
