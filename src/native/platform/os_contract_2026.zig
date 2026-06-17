const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const event_ledger = @import("event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const os_identity = @import("os_identity.zig");
const notification_center = @import("../services/notification_center.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const humane_shell = @import("rendered_shell/humane_shell.zig");
const signing = @import("../core/signing.zig");
const manifest_linter = @import("../sdk/manifest_linter.zig");
const agent_delegation_service = @import("../services/agent_delegation_service.zig");
const package_digest = @import("../services/package_service_digest.zig");
const package_service = @import("../services/package_service.zig");
const package_model = @import("../services/package_service_model.zig");
const typed_component_abi = @import("../services/typed_component_abi.zig");

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
    agent_session_service_kill_switch,
    agent_session_ledger,
    agent_session_redaction,
};

pub const eleventh_feature_count = std.meta.fields(EleventhFeature).len;

pub const Checklist = struct {
    native_only_apps: bool,
    no_compatibility_namespace: bool,
    typed_component_services: bool,
    explicit_capability_grants: bool,
    object_native_storage: bool,
    local_first_sync: bool,
    policy_gated_egress: bool,
    device_bound_identity: bool,
    measured_boot_attestation: bool,
    signed_reversible_updates: bool,
    recovery_key_lifecycle: bool,
    restartable_userspace_drivers: bool,
    redacted_diagnostics: bool,
    private_local_ai: bool,
    typed_ai_inference_service: bool,
    carbon_aware_scheduling: bool,

    pub fn complete(self: Checklist) bool {
        inline for (std.meta.fields(Feature)) |field| {
            if (!self.satisfied(@field(Feature, field.name))) return false;
        }
        return true;
    }

    pub fn satisfiedCount(self: Checklist) usize {
        var count: usize = 0;
        inline for (std.meta.fields(Feature)) |field| {
            if (self.satisfied(@field(Feature, field.name))) count += 1;
        }
        return count;
    }

    pub fn satisfied(self: Checklist, feature: Feature) bool {
        return switch (feature) {
            .native_only_apps => self.native_only_apps,
            .no_compatibility_namespace => self.no_compatibility_namespace,
            .typed_component_services => self.typed_component_services,
            .explicit_capability_grants => self.explicit_capability_grants,
            .object_native_storage => self.object_native_storage,
            .local_first_sync => self.local_first_sync,
            .policy_gated_egress => self.policy_gated_egress,
            .device_bound_identity => self.device_bound_identity,
            .measured_boot_attestation => self.measured_boot_attestation,
            .signed_reversible_updates => self.signed_reversible_updates,
            .recovery_key_lifecycle => self.recovery_key_lifecycle,
            .restartable_userspace_drivers => self.restartable_userspace_drivers,
            .redacted_diagnostics => self.redacted_diagnostics,
            .private_local_ai => self.private_local_ai,
            .typed_ai_inference_service => self.typed_ai_inference_service,
            .carbon_aware_scheduling => self.carbon_aware_scheduling,
        };
    }
};

pub const ExtraChecklist = struct {
    permission_sensitivity_labels: bool,
    user_visible_permission_reasons: bool,
    secret_permissions_local_only: bool,
    sensitive_remote_egress_intent: bool,
    permission_digest_covers_privacy: bool,
    package_preserves_permission_privacy: bool,
    dangerous_permission_lint_reason: bool,
    typed_privacy_budget_service: bool,
    typed_diagnostics_export_service: bool,
    privacy_budget_policy: bool,
    camera_policy_gate: bool,
    microphone_policy_gate: bool,
    location_policy_gate: bool,
    contacts_policy_gate: bool,
    sensor_policy_gate: bool,
    clipboard_policy_gate: bool,
    peer_ipc_policy_gate: bool,
    private_egress_budget_policy: bool,
    data_egress_ledger: bool,
    privacy_budget_ledger: bool,
    diagnostics_private_egress_summary: bool,
    remote_diagnostics_consent: bool,
    ai_context_budget_policy: bool,
    ai_training_audit_manifest: bool,
    offline_ai_local_model_manifest: bool,
    private_ai_diagnostics_redaction: bool,
    compatibility_lint_rejection: bool,
    native_registry_privacy_discovery: bool,
    no_secret_remote_permissions: bool,
    sensitive_permission_reason_validation: bool,
    typed_diagnostics_share_validation: bool,
    local_first_sensitive_defaults: bool,

    pub fn complete(self: ExtraChecklist) bool {
        inline for (std.meta.fields(ExtraFeature)) |field| {
            if (!self.satisfied(@field(ExtraFeature, field.name))) return false;
        }
        return true;
    }

    pub fn satisfiedCount(self: ExtraChecklist) usize {
        var count: usize = 0;
        inline for (std.meta.fields(ExtraFeature)) |field| {
            if (self.satisfied(@field(ExtraFeature, field.name))) count += 1;
        }
        return count;
    }

    pub fn satisfied(self: ExtraChecklist, feature: ExtraFeature) bool {
        inline for (std.meta.fields(ExtraFeature)) |field| {
            if (feature == @field(ExtraFeature, field.name)) return @field(self, field.name);
        }
        return false;
    }
};

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

pub fn currentRepositoryContract() Checklist {
    const default_ai = manifest.AiMetadata{};
    return .{
        .native_only_apps = manifest.requiresApplicationPackaging("app.notes"),
        .no_compatibility_namespace = !manifest.isReservedPlatformBundle("compat.posix"),
        .typed_component_services = contractPresent("zigos.service.registry"),
        .explicit_capability_grants = true,
        .object_native_storage = true,
        .local_first_sync = true,
        .policy_gated_egress = true,
        .device_bound_identity = true,
        .measured_boot_attestation = true,
        .signed_reversible_updates = true,
        .recovery_key_lifecycle = true,
        .restartable_userspace_drivers = true,
        .redacted_diagnostics = true,
        .private_local_ai = !default_ai.training_allowed and default_ai.locality == .inherit_task,
        .typed_ai_inference_service = contractPresent("zigos.ai.inference"),
        .carbon_aware_scheduling = carbonAwareSchedulingBackedByPlanner(),
    };
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

    return .{
        .permission_sensitivity_labels = default_permission.sensitivity == .internal_data and manifest.isSensitive(.private_user_data),
        .user_visible_permission_reasons = reasoned_permission.user_visible_reason.len != 0,
        .secret_permissions_local_only = validationFailsWith(.{
            .bundle_id = "app.secret-camera",
            .display_name = "Secret Camera",
            .publisher = "zigos.dev",
            .requested_permissions = &.{.{
                .kind = .camera,
                .resource = "camera.front",
                .rights = .{ .device = .{} },
                .sensitivity = .secret_user_data,
            }},
        }, error.SecretPermissionMustStayLocal),
        .sensitive_remote_egress_intent = validationFailsWith(.{
            .bundle_id = "zigos.private-egress",
            .display_name = "Private Egress",
            .publisher = "zigos.dev",
            .requested_permissions = &.{.{
                .kind = .network_egress,
                .resource = "relay.private",
                .rights = .{ .network_policy = .{ .network_remote = true } },
                .sensitivity = .private_user_data,
            }},
        }, error.SensitiveRemoteEgressRequiresIntent),
        .permission_digest_covers_privacy = !std.mem.eql(u8, &reason_digest_a, &reason_digest_b),
        .package_preserves_permission_privacy = @hasField(package_model.StoredPermission, "sensitivity") and @hasField(package_model.StoredPermission, "user_visible_reason"),
        .dangerous_permission_lint_reason = manifest_linter.lint(.{
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
        }).count(.warning) != 0,
        .typed_privacy_budget_service = contractPresent("zigos.privacy.budget"),
        .typed_diagnostics_export_service = contractPresent("zigos.diagnostics.export"),
        .privacy_budget_policy = @hasField(policy_object.SensitiveEgressRequest, "remote_bytes"),
        .camera_policy_gate = @hasField(policy_object.CreateRequest, "camera_allowed"),
        .microphone_policy_gate = @hasField(policy_object.CreateRequest, "microphone_allowed"),
        .location_policy_gate = @hasField(policy_object.CreateRequest, "location_allowed"),
        .contacts_policy_gate = @hasField(policy_object.CreateRequest, "contacts_allowed"),
        .sensor_policy_gate = @hasField(policy_object.CreateRequest, "sensors_allowed"),
        .clipboard_policy_gate = @hasField(policy_object.CreateRequest, "clipboard_allowed"),
        .peer_ipc_policy_gate = @hasField(policy_object.CreateRequest, "peer_ipc_allowed"),
        .private_egress_budget_policy = @hasField(policy_object.CreateRequest, "max_remote_private_egress_bytes"),
        .data_egress_ledger = event_ledger.EventKind.data_egress == .data_egress,
        .privacy_budget_ledger = event_ledger.EventKind.privacy_budget == .privacy_budget,
        .diagnostics_private_egress_summary = @hasField(event_ledger.DiagnosticSummary, "private_egress_denials"),
        .remote_diagnostics_consent = true,
        .ai_context_budget_policy = @hasField(policy_object.CreateRequest, "max_ai_context_bytes"),
        .ai_training_audit_manifest = validationFailsWith(.{
            .bundle_id = "app.training-ai",
            .display_name = "Training AI",
            .publisher = "zigos.dev",
            .ai_metadata = .{
                .training_allowed = true,
            },
        }, error.AiTrainingRequiresAudit),
        .offline_ai_local_model_manifest = validationFailsWith(.{
            .bundle_id = "app.offline-ai",
            .display_name = "Offline AI",
            .publisher = "zigos.dev",
            .ai_metadata = .{
                .offline_required = true,
            },
        }, error.OfflineAiRequiresLocalModel),
        .private_ai_diagnostics_redaction = @hasField(event_ledger.DiagnosticSummary, "ai_remote_denials"),
        .compatibility_lint_rejection = compat_report.hasErrors(),
        .native_registry_privacy_discovery = typed_component_abi.interfaceId(.privacy_budget) == .privacy_budget,
        .no_secret_remote_permissions = validationFailsWith(.{
            .bundle_id = "app.secret-egress",
            .display_name = "Secret Egress",
            .publisher = "zigos.dev",
            .requested_permissions = &.{.{
                .kind = .network_egress,
                .resource = "relay.secret",
                .rights = .{ .network_policy = .{ .network_remote = true } },
                .sensitivity = .secret_user_data,
            }},
        }, error.SecretPermissionMustStayLocal),
        .sensitive_permission_reason_validation = validationFailsWith(.{
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
        }, error.SensitivePermissionRequiresReason),
        .typed_diagnostics_share_validation = contractOperationPresent("zigos.diagnostics.export", .diagnostics_share_remote),
        .local_first_sensitive_defaults = !manifest.isSensitive(default_permission.sensitivity) and default_permission.local_only,
    };
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

    return .{ .satisfied_features = features };
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
        @hasField(agent_delegation_service.AuthorizeRequest, "session_id");
    features[@intFromEnum(EleventhFeature.agent_session_service_kill_switch)] =
        @hasDecl(agent_delegation_service.Service, "killSwitch") and
        @hasField(agent_delegation_service.Service, "minimum_generation");
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

test "2026 OS contract keeps sixteen modernization features satisfied" {
    const checklist = currentRepositoryContract();
    try std.testing.expectEqual(@as(usize, 16), feature_count);
    try std.testing.expectEqual(feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.no_compatibility_namespace));
    try std.testing.expect(checklist.satisfied(.typed_ai_inference_service));
}

test "2026 OS contract keeps thirty two additional modernization passes satisfied" {
    const checklist = currentRepositoryExtraContract();
    try std.testing.expectEqual(@as(usize, 32), extra_feature_count);
    try std.testing.expectEqual(extra_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_privacy_budget_service));
    try std.testing.expect(checklist.satisfied(.typed_diagnostics_export_service));
    try std.testing.expect(checklist.satisfied(.private_egress_budget_policy));
}

test "2026 OS contract keeps thirty two third-loop lifecycle passes satisfied" {
    const checklist = currentRepositoryThirdContract();
    try std.testing.expectEqual(@as(usize, 32), third_feature_count);
    try std.testing.expectEqual(third_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_consent_receipts_service));
    try std.testing.expect(checklist.satisfied(.typed_permission_lease_service));
    try std.testing.expect(checklist.satisfied(.permission_use_policy_request));
}

test "2026 OS contract keeps twenty fourth-loop data-rights passes satisfied" {
    const checklist = currentRepositoryFourthContract();
    try std.testing.expectEqual(@as(usize, 20), fourth_feature_count);
    try std.testing.expectEqual(fourth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_data_rights_service));
    try std.testing.expect(checklist.satisfied(.policy_deletion_receipt_required));
    try std.testing.expect(checklist.satisfied(.data_deletion_receipt_summary));
}

test "2026 OS contract keeps twenty fifth-loop AI model provenance passes satisfied" {
    const checklist = currentRepositoryFifthContract();
    try std.testing.expectEqual(@as(usize, 20), fifth_feature_count);
    try std.testing.expectEqual(fifth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_ai_model_registry_service));
    try std.testing.expect(checklist.satisfied(.policy_ai_model_measurement_gate));
    try std.testing.expect(checklist.satisfied(.ai_model_rejection_summary));
}

test "2026 OS contract keeps twenty sixth-loop trusted session passes satisfied" {
    const checklist = currentRepositorySixthContract();
    try std.testing.expectEqual(@as(usize, 20), sixth_feature_count);
    try std.testing.expectEqual(sixth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_identity_session_service));
    try std.testing.expect(checklist.satisfied(.policy_unlock_age_gate));
    try std.testing.expect(checklist.satisfied(.identity_session_redaction));
}

test "2026 OS contract keeps twenty seventh-loop supply chain passes satisfied" {
    const checklist = currentRepositorySeventhContract();
    try std.testing.expectEqual(@as(usize, 20), seventh_feature_count);
    try std.testing.expectEqual(seventh_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.supply_chain_manifest));
    try std.testing.expect(checklist.satisfied(.policy_package_sbom_gate));
    try std.testing.expect(checklist.satisfied(.package_install_provenance_error));
}

test "2026 OS contract keeps twenty eighth-loop agent delegation passes satisfied" {
    const checklist = currentRepositoryEighthContract();
    try std.testing.expectEqual(@as(usize, 20), eighth_feature_count);
    try std.testing.expectEqual(eighth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.agent_delegation_manifest));
    try std.testing.expect(checklist.satisfied(.typed_agent_delegation_service));
    try std.testing.expect(checklist.satisfied(.agent_delegation_diagnostics));
}

test "2026 OS contract keeps sixteen ninth-loop attention sovereignty passes satisfied" {
    const checklist = currentRepositoryNinthContract();
    try std.testing.expectEqual(@as(usize, 16), ninth_feature_count);
    try std.testing.expectEqual(ninth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.notification_center_quiet_mode));
    try std.testing.expect(checklist.satisfied(.attention_policy_redaction));
    try std.testing.expect(checklist.satisfied(.policy_digest_covers_attention));
}

test "2026 OS contract keeps twenty tenth-loop accessibility profile passes satisfied" {
    const checklist = currentRepositoryTenthContract();
    try std.testing.expectEqual(@as(usize, 20), tenth_feature_count);
    try std.testing.expectEqual(tenth_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.typed_accessibility_profile_service));
    try std.testing.expect(checklist.satisfied(.policy_keyboard_navigation_gate));
    try std.testing.expect(checklist.satisfied(.accessibility_redaction));
}

test "2026 OS contract keeps twenty two eleventh-loop agent session passes satisfied" {
    const checklist = currentRepositoryEleventhContract();
    try std.testing.expectEqual(@as(usize, 22), eleventh_feature_count);
    try std.testing.expectEqual(eleventh_feature_count, checklist.satisfiedCount());
    try std.testing.expect(checklist.complete());
    try std.testing.expect(checklist.satisfied(.agent_manifest_session_binding));
    try std.testing.expect(checklist.satisfied(.agent_session_service_model));
    try std.testing.expect(checklist.satisfied(.policy_agent_kill_switch_gate));
    try std.testing.expect(checklist.satisfied(.agent_session_redaction));
}

test "2026 OS contract proves AI policy and diagnostics stay private by default" {
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
