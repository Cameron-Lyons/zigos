pub const boot_start = "BOOT:START";
pub const boot_profile_zigos_native = "BOOT:PROFILE:zigos_native";
pub const boot_core_ready = "BOOT:CORE_READY";

pub const phase3_kernel_network_deferred = "ZIGOS:PHASE3:KERNEL_NETWORK:DEFERRED";

pub const native_bootstrap = "ZIGOS:NATIVE:BOOTSTRAP";
pub const tcb_defined = "ZIGOS:TCB:DEFINED";
pub const userspace_artifacts_ready = "ZIGOS:USERSPACE:ARTIFACTS:READY";
pub const userspace_scheduler_ready = "ZIGOS:USERSPACE:SCHEDULER:READY";
pub const userspace_exec_probe_ok = "ZIGOS:USERSPACE:EXEC_PROBE:OK";
pub const userspace_resume_ok = "ZIGOS:USERSPACE:RESUME:OK";
pub const userspace_scheduler_active = "ZIGOS:USERSPACE:SCHEDULER:ACTIVE";

pub const supervisor_ready = "ZIGOS:SUPERVISOR:READY";
pub const phase3_contract_map_ready = "ZIGOS:PHASE3:CONTRACT_MAP:READY";
pub const policy_ready = "ZIGOS:POLICY:READY";

pub const phase2_ui_service_ready = "ZIGOS:PHASE2:UI:SERVICE_READY";
pub const phase2_ui_service_task_ready = "ZIGOS:PHASE2:UI:SERVICE_TASK_READY";
pub const phase2_review_port_ready = "ZIGOS:PHASE2:REVIEW_PORT:READY";
pub const phase2_policy_port_ready = "ZIGOS:PHASE2:POLICY_PORT:READY";
pub const phase2_ui_review_rendered = "ZIGOS:PHASE2:UI:REVIEW_RENDERED";

pub const phase1_native_kernel_ready = "ZIGOS:PHASE1:NATIVE_KERNEL:READY";
pub const phase1_no_root = "ZIGOS:PHASE1:NO_ROOT";
pub const phase1_component_abi_ready = "ZIGOS:PHASE1:COMPONENT_ABI:READY";
pub const phase1_task_create_ok = "ZIGOS:PHASE1:TASK_CREATE:OK";
pub const phase1_service_connect_ok = "ZIGOS:PHASE1:SERVICE_CONNECT:OK";
pub const phase1_cap_pass_ok = "ZIGOS:PHASE1:CAP_PASS:OK";

pub const phase2_manifest_valid = "ZIGOS:PHASE2:MANIFEST:VALID";
pub const phase2_zero_authority_deny_network = "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_NETWORK";
pub const phase2_zero_authority_deny_clipboard = "ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_CLIPBOARD";
pub const phase2_grant_object_local = "ZIGOS:PHASE2:GRANT:OBJECT_LOCAL";
pub const phase2_grant_network_local = "ZIGOS:PHASE2:GRANT:NETWORK_LOCAL";
pub const phase2_deny_clipboard = "ZIGOS:PHASE2:DENY:CLIPBOARD";
pub const phase2_elf_substrate_ok = "ZIGOS:PHASE2:ELF_SUBSTRATE:OK";
pub const phase2_grant_device_local = "ZIGOS:PHASE2:GRANT:DEVICE_LOCAL";
pub const phase2_grant_camera = "ZIGOS:PHASE2:GRANT:CAMERA";
pub const phase2_deny_mic = "ZIGOS:PHASE2:DENY:MIC";
pub const phase2_grant_sensor_local = "ZIGOS:PHASE2:GRANT:SENSOR_LOCAL";
pub const phase2_grant_peer_ipc_local = "ZIGOS:PHASE2:GRANT:PEER_IPC_LOCAL";
pub const phase2_lease_expired = "ZIGOS:PHASE2:LEASE:EXPIRED";

pub const phase3_driver_service_nic_ready = "ZIGOS:PHASE3:DRIVER_SERVICE:NIC_READY";
pub const phase3_service_contracts_ready = "ZIGOS:PHASE3:SERVICE_CONTRACTS:READY";
pub const phase3_ipc_connect_all_ok = "ZIGOS:PHASE3:IPC_CONNECT:ALL_OK";
pub const phase3_supervisor_restart_ok = "ZIGOS:PHASE3:SUPERVISOR:RESTART_OK";

pub const phase4_object_store_ready = "ZIGOS:PHASE4:OBJECT_STORE:READY";
pub const phase4_workspace_transaction_ok = "ZIGOS:PHASE4:WORKSPACE:TRANSACTION_OK";
pub const phase4_persistence_reloaded = "ZIGOS:PHASE4:PERSISTENCE:RELOADED";
pub const phase4_reload_notes_workspace_done = "ZIGOS:PHASE4:RELOAD:NOTES_WORKSPACE:DONE";
pub const phase4_reload_imported_workspace_done = "ZIGOS:PHASE4:RELOAD:IMPORTED_WORKSPACE:DONE";
pub const phase4_reload_latest_version_done = "ZIGOS:PHASE4:RELOAD:LATEST_VERSION:DONE";
pub const phase4_storage_service_recovered = "ZIGOS:PHASE4:STORAGE_SERVICE:RECOVERED";
pub const phase4_file_bridge_derived = "ZIGOS:PHASE4:FILE_BRIDGE:DERIVED";
pub const phase4_path_authority_deprecated = "ZIGOS:PHASE4:PATH_AUTHORITY:DEPRECATED";

pub const phase5_device_graph_rooted = "ZIGOS:PHASE5:DEVICE_GRAPH:ROOTED";

pub const phase6_immutable_base_active = "ZIGOS:PHASE6:IMMUTABLE_BASE:ACTIVE";
pub const phase6_activation_rollback_ok = "ZIGOS:PHASE6:ACTIVATION:ROLLBACK_OK";
pub const phase6_measured_boot_recorded = "ZIGOS:PHASE6:MEASURED_BOOT:RECORDED";
pub const phase6_recovery_verify_reinstall = "ZIGOS:PHASE6:RECOVERY:VERIFY_REINSTALL";
pub const phase6_ux_recover_system = "ZIGOS:PHASE6:UX:RECOVER_SYSTEM";

pub const task_session_ready = "ZIGOS:TASK:SESSION_READY";
pub const native_ready = "ZIGOS:NATIVE:READY";

pub const smoke = struct {
    pub const ready = native_ready;

    pub const cold_boot_required = [_][]const u8{
        boot_start,
        boot_profile_zigos_native,
        boot_core_ready,
        phase3_kernel_network_deferred,
        native_bootstrap,
        tcb_defined,
        userspace_scheduler_ready,
        userspace_exec_probe_ok,
        userspace_resume_ok,
        userspace_scheduler_active,
        phase1_native_kernel_ready,
        phase1_no_root,
        phase1_component_abi_ready,
        phase1_task_create_ok,
        phase1_service_connect_ok,
        phase1_cap_pass_ok,
        supervisor_ready,
        policy_ready,
        phase2_manifest_valid,
        phase2_ui_review_rendered,
        phase2_zero_authority_deny_network,
        phase2_zero_authority_deny_clipboard,
        phase2_grant_object_local,
        phase2_grant_network_local,
        phase2_deny_clipboard,
        phase2_elf_substrate_ok,
        phase2_grant_device_local,
        phase2_grant_camera,
        phase2_deny_mic,
        phase2_grant_sensor_local,
        phase2_grant_peer_ipc_local,
        phase2_lease_expired,
        phase3_driver_service_nic_ready,
        phase3_service_contracts_ready,
        phase3_ipc_connect_all_ok,
        phase3_supervisor_restart_ok,
        phase4_object_store_ready,
        phase4_workspace_transaction_ok,
        phase5_device_graph_rooted,
        phase6_immutable_base_active,
        phase6_activation_rollback_ok,
        phase6_measured_boot_recorded,
        phase6_recovery_verify_reinstall,
        phase6_ux_recover_system,
        task_session_ready,
        native_ready,
    };

    pub const boot2_reloaded_phase4_required = [_][]const u8{
        phase4_persistence_reloaded,
        phase4_reload_notes_workspace_done,
        phase4_reload_imported_workspace_done,
        phase4_reload_latest_version_done,
    };

    pub const boot2_fresh_phase4_required = [_][]const u8{
        phase4_storage_service_recovered,
        phase4_file_bridge_derived,
        phase4_path_authority_deprecated,
    };
};
