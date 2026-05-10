pub const boot_start = "BOOT:START";
pub const boot_profile_zigos_native = "BOOT:PROFILE:zigos_native";
pub const boot_profile_recovery = "BOOT:PROFILE:recovery";
pub const boot_profile_benchmark = "BOOT:PROFILE:benchmark";
pub const boot_core_ready = "BOOT:CORE_READY";

pub const bench_start = "BENCH:START";
pub const bench_summary_prefix = "BENCH:SUMMARY";
pub const bench_pass = "BENCH:PASS";
pub const bench_fail = "BENCH:FAIL";

pub const recovery_start = "RECOVERY:START";
pub const recovery_break_glass_audited = "RECOVERY:BREAK_GLASS:AUDITED";
pub const recovery_no_normal_session_authority = "RECOVERY:NO_NORMAL_SESSION_AUTHORITY";
pub const recovery_reinstall_ok = "RECOVERY:REINSTALL:OK";
pub const recovery_restore_ok = "RECOVERY:RESTORE:OK";
pub const recovery_repair_sync_ok = "RECOVERY:REPAIR_SYNC:OK";
pub const recovery_rotate_keys_ok = "RECOVERY:ROTATE_KEYS:OK";
pub const recovery_revoke_trust_ok = "RECOVERY:REVOKE_TRUST:OK";
pub const recovery_pass = "RECOVERY:PASS";
pub const recovery_fail = "RECOVERY:FAIL";

pub const kernel_network_deferred = "ZIGOS:KERNEL_NETWORK:DEFERRED";

pub const native_bootstrap = "ZIGOS:NATIVE:BOOTSTRAP";
pub const tcb_defined = "ZIGOS:TCB:DEFINED";
pub const userspace_artifacts_ready = "ZIGOS:USERSPACE:ARTIFACTS:READY";
pub const userspace_scheduler_ready = "ZIGOS:USERSPACE:SCHEDULER:READY";
pub const userspace_exec_probe_ok = "ZIGOS:USERSPACE:EXEC_PROBE:OK";
pub const userspace_resume_ok = "ZIGOS:USERSPACE:RESUME:OK";
pub const userspace_scheduler_active = "ZIGOS:USERSPACE:SCHEDULER:ACTIVE";

pub const supervisor_ready = "ZIGOS:SUPERVISOR:READY";
pub const service_contract_map_ready = "ZIGOS:SERVICE_BOOT:CONTRACT_MAP:READY";
pub const policy_ready = "ZIGOS:POLICY:READY";

pub const permission_ui_service_ready = "ZIGOS:PERMISSION:UI:SERVICE_READY";
pub const permission_ui_service_task_ready = "ZIGOS:PERMISSION:UI:SERVICE_TASK_READY";
pub const permission_review_port_ready = "ZIGOS:PERMISSION:REVIEW_PORT:READY";
pub const permission_policy_port_ready = "ZIGOS:PERMISSION:POLICY_PORT:READY";
pub const permission_ui_review_rendered = "ZIGOS:PERMISSION:UI:REVIEW_RENDERED";

pub const transport_native_kernel_ready = "ZIGOS:TRANSPORT:NATIVE_KERNEL:READY";
pub const transport_no_root = "ZIGOS:TRANSPORT:NO_ROOT";
pub const transport_component_abi_ready = "ZIGOS:TRANSPORT:COMPONENT_ABI:READY";
pub const transport_task_create_ok = "ZIGOS:TRANSPORT:TASK_CREATE:OK";
pub const transport_service_connect_ok = "ZIGOS:TRANSPORT:SERVICE_CONNECT:OK";
pub const transport_cap_pass_ok = "ZIGOS:TRANSPORT:CAP_PASS:OK";
pub const runtime_proof_process_isolation = "ZIGOS:RUNTIME_PROOF:PROCESS_ISOLATION:PASS";
pub const runtime_proof_syscall_pointer_isolation = "ZIGOS:RUNTIME_PROOF:SYSCALL_POINTER_ISOLATION:PASS";
pub const runtime_proof_mmu_user_fault = "ZIGOS:RUNTIME_PROOF:MMU_USER_FAULT:PASS";
pub const runtime_proof_syscall_subject_spoof = "ZIGOS:RUNTIME_PROOF:SYSCALL_SUBJECT_SPOOF:PASS";
pub const runtime_proof_raw_network_bypass = "ZIGOS:RUNTIME_PROOF:RAW_NETWORK_BYPASS:PASS";
pub const runtime_proof_driver_authority_escape = "ZIGOS:RUNTIME_PROOF:DRIVER_AUTHORITY_ESCAPE:PASS";
pub const runtime_proof_reboot_grant_revocation = "ZIGOS:RUNTIME_PROOF:REBOOT_GRANT_REVOCATION:PASS";

pub const permission_manifest_valid = "ZIGOS:PERMISSION:MANIFEST:VALID";
pub const permission_zero_authority_deny_network = "ZIGOS:PERMISSION:ZERO_AUTHORITY:DENY_NETWORK";
pub const permission_zero_authority_deny_clipboard = "ZIGOS:PERMISSION:ZERO_AUTHORITY:DENY_CLIPBOARD";
pub const permission_grant_object_local = "ZIGOS:PERMISSION:GRANT:OBJECT_LOCAL";
pub const permission_grant_network_local = "ZIGOS:PERMISSION:GRANT:NETWORK_LOCAL";
pub const permission_deny_clipboard = "ZIGOS:PERMISSION:DENY:CLIPBOARD";
pub const permission_elf_substrate_ok = "ZIGOS:PERMISSION:ELF_SUBSTRATE:OK";
pub const permission_grant_device_local = "ZIGOS:PERMISSION:GRANT:DEVICE_LOCAL";
pub const permission_grant_camera = "ZIGOS:PERMISSION:GRANT:CAMERA";
pub const permission_deny_mic = "ZIGOS:PERMISSION:DENY:MIC";
pub const permission_grant_sensor_local = "ZIGOS:PERMISSION:GRANT:SENSOR_LOCAL";
pub const permission_grant_peer_ipc_local = "ZIGOS:PERMISSION:GRANT:PEER_IPC_LOCAL";
pub const permission_lease_expired = "ZIGOS:PERMISSION:LEASE:EXPIRED";

pub const service_boot_driver_service_network_ready = "ZIGOS:SERVICE_BOOT:DRIVER_SERVICE:NETWORK_READY";
pub const service_boot_service_contracts_ready = "ZIGOS:SERVICE_BOOT:SERVICE_CONTRACTS:READY";
pub const service_boot_ipc_connect_all_ok = "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK";
pub const service_boot_supervisor_crash_recorded = "ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED";
pub const service_boot_driver_rehost_ok = "ZIGOS:SERVICE_BOOT:DRIVER:REHOST_OK";
pub const service_boot_supervisor_restart_ok = "ZIGOS:SERVICE_BOOT:SUPERVISOR:RESTART_OK";
pub const service_boot_supervisor_restart_without_reboot = "ZIGOS:SERVICE_BOOT:SUPERVISOR:RESTART_WITHOUT_REBOOT";

pub const storage_object_store_ready = "ZIGOS:STORAGE:OBJECT_STORE:READY";
pub const storage_workspace_transaction_ok = "ZIGOS:STORAGE:WORKSPACE:TRANSACTION_OK";
pub const storage_persistence_reloaded = "ZIGOS:STORAGE:PERSISTENCE:RELOADED";
pub const storage_reload_notes_workspace_done = "ZIGOS:STORAGE:RELOAD:NOTES_WORKSPACE:DONE";
pub const storage_reload_imported_workspace_done = "ZIGOS:STORAGE:RELOAD:IMPORTED_WORKSPACE:DONE";
pub const storage_reload_latest_version_done = "ZIGOS:STORAGE:RELOAD:LATEST_VERSION:DONE";
pub const storage_service_recovered = "ZIGOS:STORAGE:STORAGE_SERVICE:RECOVERED";
pub const storage_file_bridge_derived = "ZIGOS:STORAGE:FILE_BRIDGE:DERIVED";
pub const storage_path_authority_deprecated = "ZIGOS:STORAGE:PATH_AUTHORITY:DEPRECATED";

pub const sync_device_graph_rooted = "ZIGOS:SYNC:DEVICE_GRAPH:ROOTED";

pub const platform_immutable_base_active = "ZIGOS:PLATFORM:IMMUTABLE_BASE:ACTIVE";
pub const platform_immutable_base_boot_selection = "ZIGOS:PLATFORM:IMMUTABLE_BASE:BOOT_SELECTION_VERIFIED";
pub const platform_activation_rollback_ok = "ZIGOS:PLATFORM:ACTIVATION:ROLLBACK_OK";
pub const platform_ab_image_rollback_ok = "ZIGOS:PLATFORM:AB_IMAGE:ROLLBACK_OK";
pub const platform_build_artifact_manifest_verified = "ZIGOS:PLATFORM:BUILD_ARTIFACT_MANIFEST:VERIFIED";
pub const platform_bootloader_measurement_provided = "ZIGOS:PLATFORM:BOOTLOADER_MEASUREMENT:PROVIDED";
pub const platform_artifact_manifest_verified = "ZIGOS:PLATFORM:ARTIFACT_MANIFEST:VERIFIED";
pub const platform_measured_boot_recorded = "ZIGOS:PLATFORM:MEASURED_BOOT:RECORDED";
pub const platform_measured_boot_verified_root = "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT";
pub const platform_measured_boot_first = "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:FIRST_BOOT";
pub const platform_measured_boot_same_root = "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_ROOT";
pub const platform_measured_boot_same_shape = "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_SHAPE";
pub const platform_recovery_verify_reinstall = "ZIGOS:PLATFORM:RECOVERY:VERIFY_REINSTALL";
pub const platform_ux_recover_system = "ZIGOS:PLATFORM:UX:RECOVER_SYSTEM";

pub const task_session_ready = "ZIGOS:TASK:SESSION_READY";
pub const native_ready = "ZIGOS:NATIVE:READY";
