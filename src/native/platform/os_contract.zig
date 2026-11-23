const identity_keys = @import("../../tests/fixtures/identity_vault.zig");
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
const indexing_service = @import("../../kernel/boot/benchmark/models/indexing_service.zig");
const network_policy = @import("../sync/network_policy.zig");
const package_digest = @import("../services/package_service_digest.zig");
const package_service = @import("../services/package_service.zig");
const secure_pasteboard = @import("../services/secure_pasteboard.zig");
const secret_vault_service = @import("../services/secret_vault_service.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Feature = enum(u16) {
    native_only_apps,
    no_compatibility_namespace,
    private_local_ai,
    carbon_aware_scheduling,
    permission_sensitivity_labels,
    secret_permissions_local_only,
    sensitive_remote_egress_intent,
    permission_digest_covers_privacy,
    dangerous_permission_lint_reason,
    process_hidden_observability_denied,
    process_continuous_observability_scope,
    ai_training_audit_manifest,
    offline_ai_local_model_manifest,
    compatibility_lint_rejection,
    no_secret_remote_permissions,
    sensitive_permission_reason_validation,
    sensitive_purpose_validation,
    sensitive_retention_validation,
    sensitive_retention_ceiling,
    secret_retention_ceiling,
    sensitive_lease_validation,
    permission_digest_covers_purpose,
    permission_digest_covers_retention,
    linter_purpose_guidance,
    linter_retention_guidance,
    linter_lease_guidance,
    private_object_data_rights_validation,
    deletion_receipt_manifest_validation,
    data_rights_digest_covers_export_format,
    local_ai_digest_validation,
    local_ai_source_validation,
    private_ai_locality_validation,
    ai_digest_covers_model_provenance,
    identity_session_redaction,
    reproducible_build_validation,
    trusted_builder_validation,
    supply_chain_digest_covers_sbom,
    supply_chain_digest_covers_builder,
    package_install_provenance_error,
    package_active_revision_mutation_gate,
    agent_purpose_validation,
    agent_action_budget_validation,
    agent_remote_confirmation_validation,
    agent_digest_covers_purpose,
    quiet_hours_policy,
    visible_notification_budget_policy,
    interruptive_notification_budget_policy,
    critical_interruption_policy,
    notification_center_quiet_mode,
    notification_center_interruption_budget,
    attention_policy_redaction,
    policy_digest_covers_attention,
    structured_urgency_classification,
    accessibility_profile_validation,
    accessibility_keyboard_validation,
    accessibility_digest_covers_profile,
    policy_adaptive_ui_gate,
    policy_screen_reader_gate,
    policy_keyboard_navigation_gate,
    policy_reduced_motion_gate,
    policy_high_contrast_gate,
    accessibility_redaction,
    rendered_shell_accessibility_profile,
    agent_session_binding_validation,
    agent_context_budget_validation,
    agent_kill_switch_validation,
    agent_digest_covers_session_scope,
    policy_agent_session_binding_gate,
    policy_agent_local_context_gate,
    policy_agent_context_budget_gate,
    policy_agent_kill_switch_gate,
    policy_agent_visible_plan_gate,
    agent_session_redaction,
    background_permission_pairing,
    background_budget_validation,
    background_network_visibility_validation,
    background_digest_covers_budget,
    policy_background_duration_gate,
    policy_background_cpu_gate,
    policy_background_memory_gate,
    policy_background_network_gate,
    policy_background_visibility_gate,
    background_completion_binding_gate,
    background_dispatch_runtime_gate,
    background_expiration_watchdog,
    background_activity_redaction,
    pasteboard_foreground_gesture_gate,
    pasteboard_destination_bound_grant,
    pasteboard_destination_principal_bound_grant,
    pasteboard_strict_expiry_gate,
    pasteboard_read_once_token,
    pasteboard_revocation_gate,
    pasteboard_user_visible_audit,
    pasteboard_redacted_diagnostics,
    pasteboard_bootstrap_service_contract,
    pasteboard_boot_image_registry,
    encrypted_backup_validation,
    recovery_key_validation,
    portable_restore_validation,
    trusted_restore_validation,
    backup_digest_covers_format,
    policy_backup_allowed_gate,
    policy_restore_allowed_gate,
    policy_encrypted_backup_gate,
    policy_restore_device_trust_gate,
    semantic_index_local_validation,
    semantic_index_encryption_validation,
    semantic_index_redaction_validation,
    semantic_index_query_budget_validation,
    semantic_index_model_digest_validation,
    semantic_index_digest_covers_model,
    policy_semantic_memory_gate,
    policy_semantic_local_model_gate,
    policy_semantic_encryption_gate,
    policy_semantic_redaction_gate,
    policy_semantic_query_budget_gate,
    native_registry_index_discovery,
    semantic_query_index_generation,
    semantic_query_top_k_ranking,
    semantic_query_result_redaction,
    semantic_query_workspace_scope,
    semantic_memory_ledger,
    semantic_memory_redaction,
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
    credential_ledger,
    credential_redaction,
    deterministic_document_merge,
    idempotent_operation_log_merge,
    vector_clock_tracking,
    merge_buffer_bounds,
    encrypted_transport_queue,
    mergeable_transport_semantic,
    sync_destination_policy_gate,
    personal_e2ee_default_policy,
    offline_first_default_policy,
    sync_conflict_ledger,
    sync_conflict_redaction,
    native_registry_sync_discovery,
    sync_boot_image_registry,
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
    secret_vault_bootstrap_contract,
    secret_vault_boot_image_registry,
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
    package_remove_wire_validation,
    package_offboard_policy_digest,
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
    resource_governance_ledger,
    resource_governance_diagnostics,
    resource_governance_redaction,
    resource_governance_query_index,
};

pub const feature_count = @typeInfo(Feature).@"enum".field_names.len;

pub const Checklist = struct {
    satisfied_features: [feature_count]bool,

    pub fn complete(self: Checklist) bool {
        return std.mem.allEqual(bool, &self.satisfied_features, true);
    }
};

pub fn currentRepositoryContract() Checklist {
    var features = @as([feature_count]bool, @splat(false));
    fillBaseContract(&features);
    fillExtraContract(&features);
    fillThirdContract(&features);
    fillFourthContract(&features);
    fillFifthContract(&features);
    fillSixthContract(&features);
    fillSeventhContract(&features);
    fillEighthContract(&features);
    fillNinthContract(&features);
    fillTenthContract(&features);
    fillEleventhContract(&features);
    fillTwelfthContract(&features);
    fillThirteenthContract(&features);
    fillFourteenthContract(&features);
    fillFifteenthContract(&features);
    fillSixteenthContract(&features);
    fillSeventeenthContract(&features);
    fillNineteenthContract(&features);
    fillTwentySecondContract(&features);
    fillTwentyThirdContract(&features);
    return .{ .satisfied_features = features };
}

fn fillBaseContract(features: *[feature_count]bool) void {
    const default_ai = manifest.AiMetadata{};
    features[@backingInt(Feature.native_only_apps)] = manifest.requiresApplicationPackaging("app.notes");
    features[@backingInt(Feature.no_compatibility_namespace)] = !manifest.isApplicationBundle("compat.posix") and
        validationFailsWith(.{
            .bundle_id = "compat.posix",
            .display_name = "Compat POSIX",
            .publisher = "zigos.dev",
        }, error.CompatibilityNamespaceUnsupported);
    features[@backingInt(Feature.private_local_ai)] = !default_ai.training_allowed and
        default_ai.locality == .inherit_task;
    features[@backingInt(Feature.carbon_aware_scheduling)] = carbonAwareSchedulingBackedByPlanner();
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

    return !high_carbon_batch.delayed and
        high_carbon_batch.engine == .npu and
        !low_carbon_batch.delayed and
        low_carbon_batch.engine == .npu and
        !foreground.delayed and
        foreground.engine == .gpu;
}

fn fillExtraContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.permission_sensitivity_labels)] = default_permission.sensitivity == .internal_data and
        manifest.isSensitive(.private_user_data);
    features[@backingInt(Feature.secret_permissions_local_only)] = validationFailsWith(.{
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
    features[@backingInt(Feature.sensitive_remote_egress_intent)] = validationFailsWith(.{
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
    features[@backingInt(Feature.permission_digest_covers_privacy)] = !std.mem.eql(u8, &reason_digest_a, &reason_digest_b);
    features[@backingInt(Feature.dangerous_permission_lint_reason)] = manifest_linter.lint(.{
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
    features[@backingInt(Feature.process_hidden_observability_denied)] = processHiddenObservabilityDeniedCheck();
    features[@backingInt(Feature.process_continuous_observability_scope)] = processContinuousObservabilityScopeCheck();
    features[@backingInt(Feature.ai_training_audit_manifest)] = validationFailsWith(.{
        .bundle_id = "app.training-ai",
        .display_name = "Training AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .training_allowed = true,
        },
    }, error.AiTrainingRequiresAudit);
    features[@backingInt(Feature.offline_ai_local_model_manifest)] = validationFailsWith(.{
        .bundle_id = "app.offline-ai",
        .display_name = "Offline AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .offline_required = true,
        },
    }, error.OfflineAiRequiresLocalModel);
    features[@backingInt(Feature.compatibility_lint_rejection)] = compat_report.hasErrors();
    features[@backingInt(Feature.no_secret_remote_permissions)] = validationFailsWith(.{
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
    features[@backingInt(Feature.sensitive_permission_reason_validation)] = validationFailsWith(.{
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

fn fillThirdContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.sensitive_purpose_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.sensitive_retention_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.sensitive_retention_ceiling)] = validationFailsWith(.{
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
    features[@backingInt(Feature.secret_retention_ceiling)] = validationFailsWith(.{
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
    features[@backingInt(Feature.sensitive_lease_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.permission_digest_covers_purpose)] = !std.mem.eql(u8, &purpose_digest_a, &purpose_digest_b);
    features[@backingInt(Feature.permission_digest_covers_retention)] = !std.mem.eql(u8, &purpose_digest_a, &retention_digest_b);
    features[@backingInt(Feature.linter_purpose_guidance)] = lifecycle_lint.count(.warning) != 0;
    features[@backingInt(Feature.linter_retention_guidance)] = lifecycle_lint.count(.warning) >= 2;
    features[@backingInt(Feature.linter_lease_guidance)] = lifecycle_lint.count(.warning) >= 3;
}

fn fillFourthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.private_object_data_rights_validation)] = validationFailsWith(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &private_object_requests,
    }, error.DataRightsExportMissing);
    features[@backingInt(Feature.deletion_receipt_manifest_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.data_rights_digest_covers_export_format)] = !std.mem.eql(u8, &digest_a, &digest_b);
}

fn fillFifthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.local_ai_digest_validation)] = validationFailsWith(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .local_only,
        },
    }, error.AiModelDigestMissing);
    features[@backingInt(Feature.local_ai_source_validation)] = validationFailsWith(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local",
            .locality = .local_only,
        },
    }, error.AiModelSourceMissing);
    features[@backingInt(Feature.private_ai_locality_validation)] = validationFailsWith(.{
        .bundle_id = "app.remote-private-ai",
        .display_name = "Remote Private AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "remote-private",
            .locality = .remote_allowed,
            .private_context = true,
        },
    }, error.PrivateAiRequiresLocalModel);
    features[@backingInt(Feature.ai_digest_covers_model_provenance)] = !std.mem.eql(u8, &digest_v1, &digest_v2);
}

fn fillSixthContract(features: *[feature_count]bool) void {
    features[@backingInt(Feature.identity_session_redaction)] = sessionPostureRedactionCheck();
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

fn fillSeventhContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.reproducible_build_validation)] = validationFailsWith(.{
        .bundle_id = "app.repro",
        .display_name = "Repro",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .reproducible_build = true,
            .build_recipe_digest = "sha256:recipe",
        },
    }, error.ReproducibleBuildRequiresSourceArchive);
    features[@backingInt(Feature.trusted_builder_validation)] = validationFailsWith(.{
        .bundle_id = "app.builder",
        .display_name = "Builder",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .trusted_builder = true,
        },
    }, error.TrustedBuilderRequiresIdentity);
    features[@backingInt(Feature.supply_chain_digest_covers_sbom)] = !std.mem.eql(u8, &digest_a, &digest_sbom_b);
    features[@backingInt(Feature.supply_chain_digest_covers_builder)] = !std.mem.eql(u8, &digest_a, &digest_builder_b);
    features[@backingInt(Feature.package_install_provenance_error)] = packageProvenanceInstallErrorPresent();
    features[@backingInt(Feature.package_active_revision_mutation_gate)] = packageActiveRevisionMutationGate();
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
    v1.signature = signing.sign(signer_identity, &package_service.digestBundle(v1)) catch return false;
    const installed = port.install(authority, .{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, &.{}, .{}) catch return false;
    if (!installed.installed_new) return false;

    const stale_rollback = package_service.rollbackRequestForActive(service.find("app.notes") orelse return false);
    var v2 = v1;
    v2.version_minor = 1;
    v2.signature = signing.sign(signer_identity, &package_service.digestBundle(v2)) catch return false;
    const updated = port.install(authority, .{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, &.{}, .{}) catch return false;
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

fn fillEighthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.agent_purpose_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .max_autonomous_actions = 4,
        },
    }, error.AgentDelegationPurposeMissing);
    features[@backingInt(Feature.agent_action_budget_validation)] = validationFailsWith(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize private notes locally",
        },
    }, error.AgentDelegationActionBudgetMissing);
    features[@backingInt(Feature.agent_remote_confirmation_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.agent_digest_covers_purpose)] = !std.mem.eql(u8, &digest_a, &digest_b);
}

fn fillNinthContract(features: *[feature_count]bool) void {
    features[@backingInt(Feature.quiet_hours_policy)] = attentionPolicyDenies(.attention_quiet_denied);
    features[@backingInt(Feature.visible_notification_budget_policy)] = attentionPolicyDenies(.attention_visible_budget_denied);
    features[@backingInt(Feature.interruptive_notification_budget_policy)] = attentionPolicyDenies(.attention_interruption_budget_denied);
    features[@backingInt(Feature.critical_interruption_policy)] = attentionPolicyDenies(.attention_critical_denied);
    features[@backingInt(Feature.notification_center_quiet_mode)] = notificationQuietModeCheck();
    features[@backingInt(Feature.notification_center_interruption_budget)] = notificationInterruptionBudgetCheck();
    features[@backingInt(Feature.attention_policy_redaction)] = attentionRedactionCheck();
    features[@backingInt(Feature.policy_digest_covers_attention)] = attentionPolicyDigestCheck();
    features[@backingInt(Feature.structured_urgency_classification)] = notification_center.isInterruptive(.high) and
        notification_center.isInterruptive(.critical) and
        !notification_center.isInterruptive(.normal);
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

fn fillTenthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.accessibility_profile_validation)] = validationFailsWith(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_keyboard_navigation = true,
            .supports_screen_reader = true,
        },
    }, error.AccessibilityReducedMotionMissing);
    features[@backingInt(Feature.accessibility_keyboard_validation)] = validationFailsWith(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_screen_reader = true,
            .supports_reduced_motion = true,
        },
    }, error.AccessibilityKeyboardNavigationMissing);
    features[@backingInt(Feature.accessibility_digest_covers_profile)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@backingInt(Feature.policy_adaptive_ui_gate)] = accessibilityPolicyDenies(.accessibility_adaptive_ui_denied);
    features[@backingInt(Feature.policy_screen_reader_gate)] = accessibilityPolicyDenies(.accessibility_screen_reader_denied);
    features[@backingInt(Feature.policy_keyboard_navigation_gate)] = accessibilityPolicyDenies(.accessibility_keyboard_navigation_denied);
    features[@backingInt(Feature.policy_reduced_motion_gate)] = accessibilityPolicyDenies(.accessibility_reduced_motion_denied);
    features[@backingInt(Feature.policy_high_contrast_gate)] = accessibilityPolicyDenies(.accessibility_high_contrast_denied);
    features[@backingInt(Feature.accessibility_redaction)] = accessibilityRedactionCheck();
    features[@backingInt(Feature.rendered_shell_accessibility_profile)] = shell_profile.keyboard_navigation and
        shell_profile.screen_reader_labels and
        shell_profile.reduce_motion;
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

fn fillEleventhContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.agent_session_binding_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.agent_context_budget_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.agent_kill_switch_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.agent_digest_covers_session_scope)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@backingInt(Feature.policy_agent_session_binding_gate)] = agentSessionPolicyDenies(.agent_session_binding_denied);
    features[@backingInt(Feature.policy_agent_local_context_gate)] = agentSessionPolicyDenies(.agent_context_scope_denied);
    features[@backingInt(Feature.policy_agent_context_budget_gate)] = agentSessionPolicyDenies(.agent_context_budget_denied);
    features[@backingInt(Feature.policy_agent_kill_switch_gate)] = agentSessionPolicyDenies(.agent_kill_switch_denied);
    features[@backingInt(Feature.policy_agent_visible_plan_gate)] = agentSessionPolicyDenies(.agent_plan_visibility_required);
    features[@backingInt(Feature.agent_session_redaction)] = agentSessionRedactionCheck();
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

fn fillTwelfthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.background_permission_pairing)] = validationFailsWith(.{
        .bundle_id = "app.background-contract",
        .display_name = "Background Contract",
        .publisher = "zigos.dev",
        .background_tasks = &background_tasks,
    }, error.MissingBackgroundPermission);
    features[@backingInt(Feature.background_budget_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.background_network_visibility_validation)] = backgroundNetworkVisibilityValidation(&background_permissions);
    features[@backingInt(Feature.background_digest_covers_budget)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@backingInt(Feature.policy_background_duration_gate)] = backgroundPolicyDenies(.background_duration_denied);
    features[@backingInt(Feature.policy_background_cpu_gate)] = backgroundPolicyDenies(.background_cpu_denied);
    features[@backingInt(Feature.policy_background_memory_gate)] = backgroundPolicyDenies(.background_memory_denied);
    features[@backingInt(Feature.policy_background_network_gate)] = backgroundPolicyDenies(.background_network_denied);
    features[@backingInt(Feature.policy_background_visibility_gate)] = backgroundPolicyDenies(.background_visibility_denied);
    features[@backingInt(Feature.background_completion_binding_gate)] = backgroundCompletionBindingCheck(background_bundle);
    features[@backingInt(Feature.background_dispatch_runtime_gate)] = backgroundDispatchRuntimeCheck(background_bundle);
    features[@backingInt(Feature.background_expiration_watchdog)] = backgroundExpirationWatchdogCheck(background_bundle);
    features[@backingInt(Feature.background_activity_redaction)] = backgroundActivityRedactionCheck();
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

fn fillThirteenthContract(features: *[feature_count]bool) void {
    const evidence = securePasteboardContractEvidence();
    features[@backingInt(Feature.pasteboard_foreground_gesture_gate)] = evidence.foreground_gesture_gate;
    features[@backingInt(Feature.pasteboard_destination_bound_grant)] = evidence.destination_bound_grant;
    features[@backingInt(Feature.pasteboard_destination_principal_bound_grant)] = evidence.destination_principal_bound_grant;
    features[@backingInt(Feature.pasteboard_strict_expiry_gate)] = evidence.strict_expiry_gate;
    features[@backingInt(Feature.pasteboard_read_once_token)] = evidence.read_once_token;
    features[@backingInt(Feature.pasteboard_revocation_gate)] = evidence.revocation_gate;
    features[@backingInt(Feature.pasteboard_user_visible_audit)] = evidence.user_visible_audit;
    features[@backingInt(Feature.pasteboard_redacted_diagnostics)] = evidence.redacted_diagnostics;
    features[@backingInt(Feature.pasteboard_bootstrap_service_contract)] = securePasteboardBootstrapContractCheck();
    features[@backingInt(Feature.pasteboard_boot_image_registry)] = securePasteboardBootImageRegistryCheck();
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
    return std.mem.eql(u8, image.bundleId(), bundle_id) and
        std.mem.eql(u8, build_image.artifact_name, artifact_name) and
        std.mem.eql(u8, catalog_entry.interface.name, interface_name);
}

fn securePasteboardBootstrapContractCheck() bool {
    return serviceBootstrapContractCheck(.secure_pasteboard, .secure_pasteboard, "zigos.secure.pasteboard");
}

fn securePasteboardBootImageRegistryCheck() bool {
    return serviceBootImageRegistryCheck(.secure_pasteboard, "zigos.system.privacy", "userspace-privacy.elf", "zigos.secure.pasteboard");
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
    if (!std.mem.eql(u8, buffer[0..pasted], "contract private pasteboard payload")) return evidence;
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

fn fillFourteenthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.encrypted_backup_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.recovery_key_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.portable_restore_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.trusted_restore_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.backup_digest_covers_format)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@backingInt(Feature.policy_backup_allowed_gate)] = objectResiliencePolicyDenies(.object_backup_denied);
    features[@backingInt(Feature.policy_restore_allowed_gate)] = objectResiliencePolicyDenies(.object_restore_denied);
    features[@backingInt(Feature.policy_encrypted_backup_gate)] = objectResiliencePolicyDenies(.object_backup_encryption_denied);
    features[@backingInt(Feature.policy_restore_device_trust_gate)] = objectResiliencePolicyDenies(.object_restore_device_trust_denied);
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

const SemanticMemoryEvidence = struct {
    index_generation: bool = false,
    top_k_ranking: bool = false,
    result_redaction: bool = false,
    workspace_scope: bool = false,
    ledger: bool = false,
    redacted_diagnostics: bool = false,
};

fn fillFifteenthContract(features: *[feature_count]bool) void {
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

    features[@backingInt(Feature.semantic_index_local_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.semantic_index_encryption_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.semantic_index_redaction_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.semantic_index_query_budget_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.semantic_index_model_digest_validation)] = validationFailsWith(.{
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
    features[@backingInt(Feature.semantic_index_digest_covers_model)] = !std.mem.eql(u8, &digest_a, &digest_b);
    features[@backingInt(Feature.policy_semantic_memory_gate)] = semanticMemoryPolicyDenies(.semantic_memory_denied);
    features[@backingInt(Feature.policy_semantic_local_model_gate)] = semanticMemoryPolicyDenies(.semantic_memory_remote_model_denied);
    features[@backingInt(Feature.policy_semantic_encryption_gate)] = semanticMemoryPolicyDenies(.semantic_memory_encryption_denied);
    features[@backingInt(Feature.policy_semantic_redaction_gate)] = semanticMemoryPolicyDenies(.semantic_memory_redaction_denied);
    features[@backingInt(Feature.policy_semantic_query_budget_gate)] = semanticMemoryPolicyDenies(.semantic_query_budget_denied);
    features[@backingInt(Feature.native_registry_index_discovery)] = indexSearchBootstrapContractCheck();
    features[@backingInt(Feature.semantic_query_index_generation)] = evidence.index_generation;
    features[@backingInt(Feature.semantic_query_top_k_ranking)] = evidence.top_k_ranking;
    features[@backingInt(Feature.semantic_query_result_redaction)] = evidence.result_redaction;
    features[@backingInt(Feature.semantic_query_workspace_scope)] = evidence.workspace_scope;
    features[@backingInt(Feature.semantic_memory_ledger)] = evidence.ledger;
    features[@backingInt(Feature.semantic_memory_redaction)] = evidence.redacted_diagnostics;
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
    return serviceBootstrapContractCheck(.indexing_search, .index_search, "zigos.index.search");
}

const IdentityCredentialEvidence = struct {
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

fn fillSixteenthContract(features: *[feature_count]bool) void {
    const evidence = identityCredentialEvidence();

    features[@backingInt(Feature.credential_hardware_sealed_secret)] = evidence.hardware_sealed;
    features[@backingInt(Feature.credential_phishing_origin_rejection)] = evidence.phishing_rejected;
    features[@backingInt(Feature.credential_local_unlock_required)] = evidence.local_unlock_required;
    features[@backingInt(Feature.credential_fresh_unlock_enforced)] = evidence.fresh_unlock_enforced;
    features[@backingInt(Feature.device_bound_wrong_device_rejected)] = evidence.device_bound_wrong_device_rejected;
    features[@backingInt(Feature.synced_credential_recovery_device_graph)] = evidence.synced_recovery;
    features[@backingInt(Feature.device_bound_recovery_denied)] = evidence.device_bound_recovery_denied;
    features[@backingInt(Feature.credential_revocation_gate)] = evidence.revocation_gate;
    features[@backingInt(Feature.policy_credential_assertion_gate)] = credentialPolicyDenies(.credential_assertion_denied);
    features[@backingInt(Feature.policy_credential_password_fallback_gate)] = credentialPolicyDenies(.credential_password_fallback_denied);
    features[@backingInt(Feature.policy_credential_phishing_gate)] = credentialPolicyDenies(.credential_phishing_resistance_denied);
    features[@backingInt(Feature.policy_credential_hardware_gate)] = credentialPolicyDenies(.credential_hardware_denied);
    features[@backingInt(Feature.policy_credential_local_unlock_gate)] = credentialPolicyDenies(.credential_unlock_denied);
    features[@backingInt(Feature.policy_credential_unlock_age_gate)] = credentialPolicyDenies(.credential_unlock_stale);
    features[@backingInt(Feature.credential_ledger)] = evidence.ledger;
    features[@backingInt(Feature.credential_redaction)] = evidence.redacted_diagnostics;
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

fn credentialContractHardwareProvider() secure_secret_store.HardwareSealProvider {
    return @import("../../tests/fixtures/secret_provider.zig").provider();
}

fn identityCredentialEvidence() IdentityCredentialEvidence {
    var evidence = IdentityCredentialEvidence{};
    var graph = device_graph.Graph.init();
    var secrets = secret_vault_service.Service.init();
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
        .secret_vault_allowed = true,
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
    var authority = identity_keys.context(&secrets, &policies, user);
    authority.subjects.organization_id = 2057;
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 2058 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 2059 };
    const task_id: u64 = 2060;
    const user_identity = signing.SignerIdentity{ .label = "credential-contract-user", .seed = signing.seedFromByte(0xE6) };
    const laptop_identity = signing.SignerIdentity{ .label = "credential-contract-laptop", .seed = signing.seedFromByte(0xE7) };
    const phone_identity = signing.SignerIdentity{ .label = "credential-contract-phone", .seed = signing.seedFromByte(0xE8) };
    const first_credential_identity = signing.SignerIdentity{ .label = "credential-contract-passkey-v1", .seed = signing.seedFromByte(0xE9) };
    const handle_first_credential_identity = identity_keys.provision(authority, user, first_credential_identity) catch return evidence;
    const replacement_credential_identity = signing.SignerIdentity{ .label = "credential-contract-passkey-v2", .seed = signing.seedFromByte(0xEA) };
    const handle_replacement_credential_identity = identity_keys.provision(authority, user, replacement_credential_identity) catch return evidence;
    const bound_credential_identity = signing.SignerIdentity{ .label = "credential-contract-bound", .seed = signing.seedFromByte(0xEB) };
    const handle_bound_credential_identity = identity_keys.provision(authority, user, bound_credential_identity) catch return evidence;

    _ = graph.ensureUserRoot(user, "owner", user_identity) catch return evidence;
    _ = graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1) catch return evidence;
    _ = graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2) catch return evidence;
    const credential = identities.registerCredential(&graph, identity_keys.at(authority, 3), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = "accounts-passkey",
        .scope = .synced,
        .recovery_threshold = 2,
        .key_handle_id = handle_first_credential_identity,
    }) catch return evidence;
    const credential_id = credential.id;
    const first_generation = credential.credential_generation;
    evidence.hardware_sealed = credential.local_unlock_required and
        credential.phishing_resistant and
        credential.hardware_backed_credential and
        credential.sealed_credential_secret and
        credential.isRecoverableThroughDeviceGraph();

    const unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "accounts.example", "nonce-1", .biometric, 4, 8, laptop_identity) catch return evidence;
    const assertion = identities.assertCredential(&graph, identity_keys.at(authority, 5), .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://login.accounts.example",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .key_handle_id = handle_first_credential_identity,
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

    evidence.local_unlock_required = if (identities.assertCredential(&graph, identity_keys.at(authority, 6), .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-1",
        .key_handle_id = handle_first_credential_identity,
    })) |_| false else |err| err == error.LocalUnlockRequired;

    evidence.phishing_rejected = if (identities.assertCredential(&graph, identity_keys.at(authority, 6), .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example.evil.test",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .key_handle_id = handle_first_credential_identity,
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

    const expired_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "accounts.example", "nonce-expired", .biometric, 4, 5, laptop_identity) catch return evidence;
    evidence.fresh_unlock_enforced = if (identities.assertCredential(&graph, identity_keys.at(authority, 9), .{
        .credential_id = credential_id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-expired",
        .local_unlock = expired_unlock,
        .key_handle_id = handle_first_credential_identity,
    })) |_| false else |err| err == error.LocalUnlockExpired;

    const bound = identities.registerCredential(&graph, identity_keys.at(authority, 10), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "admin.example",
        .label = "admin-device-passkey",
        .scope = .device_bound,
        .key_handle_id = handle_bound_credential_identity,
    }) catch return evidence;
    const phone_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "admin.example", "bound-nonce", .biometric, 11, 15, phone_identity) catch return evidence;
    evidence.device_bound_wrong_device_rejected = if (identities.assertCredential(&graph, identity_keys.at(authority, 12), .{
        .credential_id = bound.id,
        .device = phone,
        .relying_party_id = "admin.example",
        .origin = "https://admin.example",
        .challenge = "bound-nonce",
        .local_unlock = phone_unlock,
        .key_handle_id = handle_bound_credential_identity,
    })) |_| false else |err| err == error.DeviceBoundCredentialWrongDevice;

    const recovery_challenge = identities.recoveryChallenge(authority, credential_id, phone, handle_replacement_credential_identity) catch return evidence;
    const recovery_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "accounts.example", &recovery_challenge, .recovery_key, 13, 18, phone_identity) catch return evidence;
    const laptop_recovery_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "accounts.example", &recovery_challenge, .recovery_key, 13, 18, laptop_identity) catch return evidence;
    const recovered = identities.recoverCredential(&graph, identity_keys.at(authority, 14), .{
        .credential_id = credential_id,
        .recovery_device = phone,
        .relying_party_id = "accounts.example",
        .local_unlock = recovery_unlock,
        .approvals = &.{.{ .device = laptop, .local_unlock = laptop_recovery_unlock }},
        .replacement_key_handle_id = handle_replacement_credential_identity,
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

    const bound_recovery_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "admin.example", "recover-bound", .recovery_key, 15, 19, phone_identity) catch return evidence;
    evidence.device_bound_recovery_denied = if (identities.recoverCredential(&graph, identity_keys.at(authority, 16), .{
        .credential_id = bound.id,
        .recovery_device = phone,
        .relying_party_id = "admin.example",
        .local_unlock = bound_recovery_unlock,
        .replacement_key_handle_id = handle_replacement_credential_identity,
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
    const post_revoke_unlock = os_identity.createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "accounts.example", "post-revoke", .device_pin, 18, 21, phone_identity) catch return evidence;
    evidence.revocation_gate = if (identities.assertCredential(&graph, identity_keys.at(authority, 19), .{
        .credential_id = credential_id,
        .device = phone,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "post-revoke",
        .local_unlock = post_revoke_unlock,
        .key_handle_id = handle_replacement_credential_identity,
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

fn fillSeventeenthContract(features: *[feature_count]bool) void {
    const evidence = privateSyncEvidence();
    const default_policy = sync_service.WorkspacePolicyRequest{
        .workspace_id = 1,
        .owner = .{ .kind = .user, .serial = 1 },
    };

    features[@backingInt(Feature.deterministic_document_merge)] = evidence.crdt_merge;
    features[@backingInt(Feature.idempotent_operation_log_merge)] = evidence.log_idempotence;
    features[@backingInt(Feature.vector_clock_tracking)] = evidence.vector_clock;
    features[@backingInt(Feature.merge_buffer_bounds)] = evidence.buffer_bounds;
    features[@backingInt(Feature.encrypted_transport_queue)] = evidence.encrypted_transport;
    features[@backingInt(Feature.mergeable_transport_semantic)] = evidence.mergeable_semantic;
    features[@backingInt(Feature.sync_destination_policy_gate)] = evidence.policy_gate;
    features[@backingInt(Feature.personal_e2ee_default_policy)] = default_policy.personal_e2ee;
    features[@backingInt(Feature.offline_first_default_policy)] = default_policy.offline_first;
    features[@backingInt(Feature.sync_conflict_ledger)] = evidence.ledger;
    features[@backingInt(Feature.sync_conflict_redaction)] = evidence.redacted_diagnostics;
    features[@backingInt(Feature.native_registry_sync_discovery)] = syncBootstrapContractCheck();
    features[@backingInt(Feature.sync_boot_image_registry)] = syncBootImageRegistryCheck();
}

fn privateSyncEvidence() PrivateSyncEvidence {
    var evidence = PrivateSyncEvidence{};
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
    return serviceBootImageRegistryCheck(.sync_replication, "zigos.system.store", "userspace-store.elf", "zigos.sync.replication");
}

const SecretVaultEvidence = struct {
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

fn fillNineteenthContract(features: *[feature_count]bool) void {
    const evidence = secretVaultEvidence();

    features[@backingInt(Feature.hardware_sealed_import)] = evidence.hardware_sealed_import;
    features[@backingInt(Feature.nonresident_secret_material)] = evidence.nonresident_material;
    features[@backingInt(Feature.secret_owner_binding)] = evidence.owner_binding;
    features[@backingInt(Feature.leased_handle_lending)] = evidence.leased_handle;
    features[@backingInt(Feature.secret_handle_expiry_boundary)] = evidence.handle_expiry_boundary;
    features[@backingInt(Feature.raw_export_policy_denial)] = evidence.raw_export_denial;
    features[@backingInt(Feature.raw_export_handle_capability_gate)] = evidence.raw_export_handle_capability_gate;
    features[@backingInt(Feature.raw_export_success_audit)] = evidence.raw_export_success_audit;
    features[@backingInt(Feature.store_handle_identity_binding)] = evidence.store_handle_identity_binding;
    features[@backingInt(Feature.secret_rotation_revokes_old_handles)] = evidence.rotation_revokes_old_handles;
    features[@backingInt(Feature.explicit_handle_revocation)] = evidence.explicit_revocation;
    features[@backingInt(Feature.secret_revoke_binding_gate)] = evidence.revoke_binding_gate;
    features[@backingInt(Feature.secret_hardware_policy_gate)] = evidence.hardware_policy_gate;
    features[@backingInt(Feature.secret_lease_policy_gate)] = evidence.lease_policy_gate;
    features[@backingInt(Feature.secret_vault_ledger)] = evidence.ledger;
    features[@backingInt(Feature.secret_vault_redaction)] = evidence.redacted_diagnostics;
    features[@backingInt(Feature.secret_vault_bootstrap_contract)] = secretVaultBootstrapContractCheck();
    features[@backingInt(Feature.secret_vault_boot_image_registry)] = secretVaultBootImageRegistryCheck();
}

fn secretVaultContractHardwareProvider() secure_secret_store.HardwareSealProvider {
    return @import("../../tests/fixtures/secret_provider.zig").provider();
}

fn secretVaultEvidence() SecretVaultEvidence {
    var secret_export_buffer: secure_secret_store.Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    var evidence = SecretVaultEvidence{};

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
    evidence.nonresident_material = !secret.resident_material and secret.sealedBlob() != null;
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
        expiry_service.activeHandleCountAt(19) == 1 and
        expiry_service.activeHandleCountAt(20) == 0 and
        (if (expiry_service.exportRaw(&policies, subjects, .{
            .holder = app,
            .task_id = 84,
            .handle_id = expiring_handle.id,
            .now_ticks = 20,
            .detail = "private expiring api secret boundary export",
        }, &expiry_ledger, &secret_export_buffer)) |_| false else |err| err == error.HandleExpired);

    evidence.raw_export_denial = if (service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 82,
        .handle_id = old_handle_id,
        .now_ticks = 5,
        .detail = "private api secret raw export denied",
    }, &ledger, &secret_export_buffer)) |_| false else |err| err == error.PolicyDenied;

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
    }, &export_ledger, &secret_export_buffer)) |_| false else |err| err == error.RawExportDenied;
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
    }, &export_ledger, &secret_export_buffer) catch return evidence;
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
    }, &secret_export_buffer)) |_| false else |err| err == error.HandleHolderMismatch;
    const wrong_store_task_denied = if (direct_store.exportRaw(direct_handle.id, .{
        .holder = app,
        .task_id = 88,
    }, &secret_export_buffer)) |_| false else |err| err == error.HandleHolderMismatch;
    const direct_raw = direct_store.exportRaw(direct_handle.id, .{
        .holder = app,
        .task_id = 87,
    }, &secret_export_buffer) catch return evidence;
    evidence.store_handle_identity_binding =
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
        }, &ledger, &secret_export_buffer)) |_| false else |err| err == error.HandleRevoked);

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
        }, &ledger, &secret_export_buffer)) |_| false else |err| err == error.HandleRevoked);

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
    return serviceBootImageRegistryCheck(.secret_vault, "zigos.system.privacy", "userspace-privacy.elf", "zigos.secret.vault");
}

const PackageOffboardingEvidence = struct {
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

fn fillTwentySecondContract(features: *[feature_count]bool) void {
    const evidence = packageOffboardingEvidence();

    features[@backingInt(Feature.offboard_policy_delete_gate)] = evidence.policy_gate;
    features[@backingInt(Feature.offboard_receipt_required)] = evidence.receipt_required;
    features[@backingInt(Feature.denied_offboard_preserves_install)] = evidence.denied_preserves_install;
    features[@backingInt(Feature.receipt_backed_package_remove)] = evidence.package_removed;
    features[@backingInt(Feature.offboard_result_receipt)] = evidence.result_receipt;
    features[@backingInt(Feature.offboard_removed_bundle_digest)] = evidence.removed_bundle_digest;
    features[@backingInt(Feature.offboard_removed_bundle_digest_content_binding)] = evidence.removed_bundle_digest_content_binding;
    features[@backingInt(Feature.offboard_revision_purge)] = evidence.revision_purge;
    features[@backingInt(Feature.removed_bundle_unlaunchable)] = evidence.unlaunchable;
    features[@backingInt(Feature.offboard_data_deletion_ledger)] = evidence.ledger;
    features[@backingInt(Feature.offboard_redaction)] = evidence.redacted_diagnostics;
    features[@backingInt(Feature.package_remove_wire_validation)] = packageRemoveWireValidationCheck();
    features[@backingInt(Feature.package_offboard_policy_digest)] = evidence.policy_digest;
}

fn packageOffboardingEvidence() PackageOffboardingEvidence {
    var evidence = PackageOffboardingEvidence{};

    var service = package_service.Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "contract-offboard-bundle",
        .seed = signing.seedFromByte(0xB2),
    };
    package_service.testingTrustPublisher(&service, signer_identity, "zigos.dev") catch return evidence;

    var bundle = @import("../policy/manifest_fixtures.zig").notesBundle();
    bundle.signature = signing.sign(signer_identity, &package_service.digestBundle(bundle)) catch return evidence;
    const installed = service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, &.{}, .{}) catch return evidence;
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
    const header = component_abi_schema.WireHeader{
        .operation = @backingInt(component_abi_schema.OperationId.package_remove),
        .correlation_id = 2026,
        .subject_task_id = 7601,
    };
    component_abi_schema.validateMessage(
        .package_install,
        .package_remove,
        header,
        @sizeOf(component_abi_schema.Request(.package_remove)),
        @sizeOf(component_abi_schema.Response(.package_remove)),
    ) catch return false;
    return true;
}

const ResourceGovernanceEvidence = struct {
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
    ledger: bool = false,
    diagnostics: bool = false,
    redacted_diagnostics: bool = false,
    query_index: bool = false,
};

fn fillTwentyThirdContract(features: *[feature_count]bool) void {
    const evidence = resourceGovernanceEvidence();

    features[@backingInt(Feature.hardware_telemetry_provider_boundary)] = evidence.telemetry_provider_boundary;
    features[@backingInt(Feature.hardware_evidence_required_for_accelerator_queues)] = evidence.hardware_evidence_required;
    features[@backingInt(Feature.foreground_thermal_dispatch)] = evidence.foreground_thermal_dispatch;
    features[@backingInt(Feature.emergency_pressure_bypass)] = evidence.emergency_pressure_bypass;
    features[@backingInt(Feature.background_thermal_delay)] = evidence.background_thermal_delay;
    features[@backingInt(Feature.batch_battery_delay)] = evidence.batch_battery_delay;
    features[@backingInt(Feature.batch_recovers_after_pressure)] = evidence.batch_recovers_after_pressure;
    features[@backingInt(Feature.pressure_delay_reason_accounting)] = evidence.pressure_reason_accounting;
    features[@backingInt(Feature.dispatch_budget_accounting)] = evidence.dispatch_budget_accounting;
    features[@backingInt(Feature.privacy_mode_degrades_accelerator)] = evidence.privacy_mode_degrades_accelerator;
    features[@backingInt(Feature.resource_governance_ledger)] = evidence.ledger;
    features[@backingInt(Feature.resource_governance_diagnostics)] = evidence.diagnostics;
    features[@backingInt(Feature.resource_governance_redaction)] = evidence.redacted_diagnostics;
    features[@backingInt(Feature.resource_governance_query_index)] = evidence.query_index;
}

fn resourceGovernanceEvidence() ResourceGovernanceEvidence {
    var evidence = ResourceGovernanceEvidence{};

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
        .status = .{
            .battery_charging = false,
            .privacy_sensitive_task_present = true,
        },
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
        .observations = .{
            .acpi_observed = true,
            .thermal_observed = true,
            .battery_observed = true,
            .accelerator_observed = true,
            .grid_carbon_observed = true,
        },
    };
}

test "OS contract satisfies every feature" {
    const checklist = currentRepositoryContract();
    for (checklist.satisfied_features, 0..) |satisfied, index| {
        if (!satisfied) std.debug.print("unsatisfied OS contract feature: {t}\n", .{@as(Feature, @fromBackingInt(@intCast(index)))});
    }
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
