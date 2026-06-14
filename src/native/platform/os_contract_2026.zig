const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const event_ledger = @import("event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const manifest_linter = @import("../sdk/manifest_linter.zig");
const package_digest = @import("../services/package_service_digest.zig");
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

pub const ThirdChecklist = struct {
    satisfied_features: [third_feature_count]bool,

    pub fn complete(self: ThirdChecklist) bool {
        return self.satisfiedCount() == third_feature_count;
    }

    pub fn satisfiedCount(self: ThirdChecklist) usize {
        var count: usize = 0;
        for (self.satisfied_features) |satisfied_feature| {
            if (satisfied_feature) count += 1;
        }
        return count;
    }

    pub fn satisfied(self: ThirdChecklist, feature: ThirdFeature) bool {
        return self.satisfied_features[@intFromEnum(feature)];
    }
};

pub fn currentRepositoryContract() Checklist {
    const default_ai = manifest.AiMetadata{};
    return .{
        .native_only_apps = manifest.requiresApplicationPackaging("app.notes"),
        .no_compatibility_namespace = !manifest.isReservedPlatformBundle("compat.posix"),
        .typed_component_services = typed_component_abi.contractFor("zigos.service.registry") != null,
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
        .typed_ai_inference_service = typed_component_abi.contractFor("zigos.ai.inference") != null,
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
        .typed_privacy_budget_service = typed_component_abi.contractFor("zigos.privacy.budget") != null,
        .typed_diagnostics_export_service = typed_component_abi.contractFor("zigos.diagnostics.export") != null,
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
        .typed_diagnostics_share_validation = typed_component_abi.contractFor("zigos.diagnostics.export").?.operation(.diagnostics_share_remote) != null,
        .local_first_sensitive_defaults = !manifest.isSensitive(default_permission.sensitivity) and default_permission.local_only,
    };
}

fn validationFailsWith(bundle: manifest.BundleManifest, expected: anyerror) bool {
    manifest.validate(bundle) catch |err| return err == expected;
    return false;
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
    features[@intFromEnum(ThirdFeature.typed_consent_receipts_service)] = typed_component_abi.contractFor("zigos.consent.receipts") != null;
    features[@intFromEnum(ThirdFeature.typed_permission_lease_service)] = typed_component_abi.contractFor("zigos.permission.lease") != null;
    features[@intFromEnum(ThirdFeature.consent_record_wire_validation)] = typed_component_abi.contractFor("zigos.consent.receipts").?.operation(.consent_record) != null;
    features[@intFromEnum(ThirdFeature.permission_lease_expire_wire_validation)] = typed_component_abi.contractFor("zigos.permission.lease").?.operation(.permission_lease_expire) != null;
    features[@intFromEnum(ThirdFeature.native_registry_consent_discovery)] = typed_component_abi.interfaceId(.consent_receipts) == .consent_receipts;
    features[@intFromEnum(ThirdFeature.native_registry_lease_discovery)] = typed_component_abi.interfaceId(.permission_lease) == .permission_lease;
    features[@intFromEnum(ThirdFeature.retention_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "retention_policy_events");
    features[@intFromEnum(ThirdFeature.lease_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "permission_lease_events");
    features[@intFromEnum(ThirdFeature.consent_diagnostics_redacted)] = @hasField(event_ledger.DiagnosticSummary, "consent_receipt_events");

    return .{ .satisfied_features = features };
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
