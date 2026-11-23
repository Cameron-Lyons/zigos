const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const signing = @import("../core/signing.zig");
const model = @import("policy_object_model.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_ALLOW_LIST = model.MAX_ALLOW_LIST;
pub const MAX_LABEL_BYTES = model.MAX_LABEL_BYTES;
pub const POLICY_OBJECT_SIZE_CEILING_BYTES = model.POLICY_OBJECT_SIZE_CEILING_BYTES;
pub const DIRECTORY_SIZE_CEILING_BYTES: usize = 32_520;

pub const Scope = model.Scope;
pub const InstallSourceMode = model.InstallSourceMode;
pub const NetworkEgressMode = model.NetworkEgressMode;
pub const SubjectSet = model.SubjectSet;
pub const DecisionReason = model.DecisionReason;
pub const PolicyDecision = model.PolicyDecision;
pub const CreateRequest = model.CreateRequest;
pub const AiUseRequest = model.AiUseRequest;
pub const SessionTrustRequest = model.SessionTrustRequest;
pub const SensitiveEgressRequest = model.SensitiveEgressRequest;
pub const DataRightsOperation = model.DataRightsOperation;
pub const PackageProvenanceRequest = model.PackageProvenanceRequest;
pub const DataRightsRequest = model.DataRightsRequest;
pub const ObjectResilienceOperation = model.ObjectResilienceOperation;
pub const ObjectResilienceRequest = model.ObjectResilienceRequest;
pub const SemanticMemoryRequest = model.SemanticMemoryRequest;
pub const CredentialAssertionRequest = model.CredentialAssertionRequest;
pub const SecretVaultOperation = model.SecretVaultOperation;
pub const SecretVaultRequest = model.SecretVaultRequest;
pub const AttentionRequest = model.AttentionRequest;
pub const LifecycleOperation = model.LifecycleOperation;
pub const LifecycleRequest = model.LifecycleRequest;
pub const AccessibilityRequest = model.AccessibilityRequest;
pub const BackgroundActivityRequest = model.BackgroundActivityRequest;
pub const AgentDelegationRequest = model.AgentDelegationRequest;
pub const PermissionUseRequest = model.PermissionUseRequest;
pub const SensitiveCaptureRequest = model.SensitiveCaptureRequest;
pub const PolicyObject = model.PolicyObject;
pub const Error = model.Error;

// A slot is authentic while its policy still hashes to the binding recorded
// when the Directory accepted the signature. Decisions compare that binding
// instead of re-running Ed25519, so any later change to a signed control or
// to the signature bytes makes the policy fail closed as unsigned.
const PolicySlot = struct {
    policy: PolicyObject = .{},
    verified_binding: crypto_hash.Digest = crypto_hash.zero_digest,

    fn authenticDigest(self: *const PolicySlot) ?crypto_hash.Digest {
        const digest = policyDigest(&self.policy);
        const binding = verifiedBinding(&digest, &self.policy.signature);
        return if (std.crypto.timing_safe.eql(crypto_hash.Digest, binding, self.verified_binding)) digest else null;
    }
};

// Policies are append-only: ids are slot index + 1, revocation only marks a
// slot, and each insert takes the next generation for its scope, so the last
// live slot matching a scope is that scope's newest policy.
pub const Directory = struct {
    slots: [MAX_POLICIES]PolicySlot = @splat(.{}),
    len: usize = 0,

    pub fn init() Directory {
        return .{};
    }

    pub fn initializeAllocated(self: *Directory) void {
        self.len = 0;
    }

    pub fn count(self: *const Directory) usize {
        return self.len;
    }

    pub fn create(
        self: *Directory,
        request: CreateRequest,
        signer: signing.SignerIdentity,
    ) (Error || anyerror)!*PolicyObject {
        if (self.len >= MAX_POLICIES) return error.PolicyTableFull;
        var policy: PolicyObject = undefined;
        try policyFromRequestInto(&policy, request);
        const digest = policyDigest(&policy);
        policy.signature = try signing.sign(signer, &digest);
        return self.insert(policy, &digest);
    }

    // Initial native attachment requires an independently authenticated issuer
    // key and an empty directory. Detached request signatures do not authorize
    // updates: replay must never acquire a newer local generation. Signer labels
    // are not authenticated and are never retained from a borrowed caller buffer.
    pub fn attachInitialAuthenticated(self: *Directory, request: CreateRequest, signature: manifest.Signature, issuer_key: signing.PublicKey) !*PolicyObject {
        if (self.len != 0) return error.PolicyAlreadyAttached;
        var policy: PolicyObject = undefined;
        try policyFromRequestInto(&policy, request);
        const digest = policyDigest(&policy);
        if (!issuerSigned(&digest, signature, issuer_key)) return error.UntrustedPolicy;
        policy.signature = signature;
        policy.signature.signer = "";
        return self.insert(policy, &digest);
    }

    fn insert(self: *Directory, candidate: PolicyObject, digest: *const crypto_hash.Digest) Error!*PolicyObject {
        if (self.len >= MAX_POLICIES) return error.PolicyTableFull;
        const generation = self.latestGeneration(candidate.scope, candidate.subject_id) + 1;
        const slot = &self.slots[self.len];
        slot.policy = candidate;
        slot.policy.id = self.len + 1;
        slot.policy.generation = generation;
        slot.policy.revoked = false;
        slot.verified_binding = verifiedBinding(digest, &slot.policy.signature);
        self.len += 1;
        return &slot.policy;
    }

    // Mutable access exists for in-memory tamper tests; production callers
    // only read the returned policy.
    pub fn activeForScope(self: *Directory, scope: Scope, subject_id: u64) ?*PolicyObject {
        const slot = self.activeSlot(scope, subject_id) orelse return null;
        return &@constCast(slot).policy;
    }

    // Full re-verification: the slot binding must hold and the stored
    // signature must still verify over the recomputed digest.
    pub fn verify(self: *const Directory, policy_id: u64) bool {
        const slot = self.slotForId(policy_id) orelse return false;
        const digest = slot.authenticDigest() orelse return false;
        return signing.verify(slot.policy.signature, &digest);
    }

    pub fn revokePolicy(self: *Directory, policy_id: u64) Error!void {
        const slot = self.slotForId(policy_id) orelse return error.PolicyNotFound;
        const policy = &@constCast(slot).policy;
        if (policy.revoked) return error.PolicyAlreadyRevoked;
        policy.revoked = true;
    }

    pub fn revokePoliciesForScope(self: *Directory, scope: Scope, subject_id: u64) usize {
        var revoked_count: usize = 0;
        for (self.slots[0..self.len]) |*slot| {
            if (slot.policy.revoked or slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            slot.policy.revoked = true;
            revoked_count += 1;
        }
        return revoked_count;
    }

    pub fn installSourceDecision(self: *const Directory, subjects: SubjectSet, source_identity: []const u8) PolicyDecision {
        return self.decide(subjects, source_identity, installSourceDenial);
    }

    pub fn packageProvenanceDecision(self: *const Directory, subjects: SubjectSet, request: PackageProvenanceRequest) PolicyDecision {
        return self.decide(subjects, request, packageProvenanceDenial);
    }

    pub fn agentDelegationDecision(self: *const Directory, subjects: SubjectSet, request: AgentDelegationRequest) PolicyDecision {
        if (!request.enabled) return allow();
        return self.decide(subjects, request, agentDelegationDenial);
    }

    pub fn syncDestinationDecision(self: *const Directory, subjects: SubjectSet, destination: []const u8) PolicyDecision {
        return self.decide(subjects, destination, syncDestinationDenial);
    }

    pub fn networkEgressDecision(self: *const Directory, subjects: SubjectSet, destination: []const u8) PolicyDecision {
        return self.decide(subjects, destination, networkEgressDenial);
    }

    pub fn permissionKindDecision(self: *const Directory, subjects: SubjectSet, kind: manifest.PermissionKind) PolicyDecision {
        return self.decide(subjects, kind, permissionKindDenial);
    }

    pub fn aiUseDecision(self: *const Directory, subjects: SubjectSet, request: AiUseRequest) PolicyDecision {
        return self.decide(subjects, request, aiUseDenial);
    }

    // Reject excessive requested authority before PIN/recovery hardware work.
    // Device posture is checked separately once authenticated keys are restored.
    pub fn sessionLifetimeDecision(self: *const Directory, subjects: SubjectSet, lifetime_ticks: u64) PolicyDecision {
        return self.decide(subjects, lifetime_ticks, sessionLifetimeDenial);
    }

    pub fn sessionTrustDecision(self: *const Directory, subjects: SubjectSet, request: SessionTrustRequest) PolicyDecision {
        return self.decide(subjects, request, sessionTrustDenial);
    }

    pub fn sensitiveEgressDecision(self: *const Directory, subjects: SubjectSet, request: SensitiveEgressRequest) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        return self.decide(subjects, request, sensitiveEgressDenial);
    }

    pub fn dataRightsDecision(self: *const Directory, subjects: SubjectSet, request: DataRightsRequest) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        return self.decide(subjects, request, dataRightsDenial);
    }

    pub fn objectResilienceDecision(self: *const Directory, subjects: SubjectSet, request: ObjectResilienceRequest) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        return self.decide(subjects, request, objectResilienceDenial);
    }

    pub fn semanticMemoryDecision(self: *const Directory, subjects: SubjectSet, request: SemanticMemoryRequest) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        return self.decide(subjects, request, semanticMemoryDenial);
    }

    pub fn credentialAssertionDecision(self: *const Directory, subjects: SubjectSet, request: CredentialAssertionRequest) PolicyDecision {
        return self.decide(subjects, request, credentialAssertionDenial);
    }

    pub fn secretVaultDecision(self: *const Directory, subjects: SubjectSet, request: SecretVaultRequest) PolicyDecision {
        if (request.operation == .revoke) return allow();
        return self.decide(subjects, request, secretVaultDenial);
    }

    pub fn lifecycleDecision(self: *const Directory, subjects: SubjectSet, request: LifecycleRequest) PolicyDecision {
        return self.decide(subjects, request, lifecycleDenial);
    }

    pub fn attentionDecision(self: *const Directory, subjects: SubjectSet, request: AttentionRequest) PolicyDecision {
        return self.decide(subjects, request, attentionDenial);
    }

    pub fn accessibilityDecision(self: *const Directory, subjects: SubjectSet, request: AccessibilityRequest) PolicyDecision {
        return self.decide(subjects, request, accessibilityDenial);
    }

    pub fn backgroundActivityDecision(self: *const Directory, subjects: SubjectSet, request: BackgroundActivityRequest) PolicyDecision {
        return self.decide(subjects, request, backgroundActivityDenial);
    }

    pub fn permissionUseDecision(self: *const Directory, subjects: SubjectSet, request: PermissionUseRequest) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        return self.decide(subjects, request, permissionUseDenial);
    }

    pub fn sensitiveCaptureDecision(self: *const Directory, subjects: SubjectSet, request: SensitiveCaptureRequest) PolicyDecision {
        return self.decide(subjects, request, sensitiveCaptureDenial);
    }

    // Every active policy for the subjects must be authentic and must not
    // deny the request. Organization policy is consulted first, then user,
    // device and workspace policy; the first denial names its blocking scope.
    fn decide(
        self: *const Directory,
        subjects: SubjectSet,
        request: anytype,
        comptime denial: fn (*const PolicyObject, @TypeOf(request)) ?DecisionReason,
    ) PolicyDecision {
        const active = self.activeSlots(subjects);
        for (decision_order) |scope| {
            const slot = active[@backingInt(scope)] orelse continue;
            if (slot.authenticDigest() == null) return block(&slot.policy, .unsigned_policy);
            if (denial(&slot.policy, request)) |reason| return block(&slot.policy, reason);
        }
        return allow();
    }

    fn slotForId(self: *const Directory, policy_id: u64) ?*const PolicySlot {
        if (policy_id == 0 or policy_id > self.len) return null;
        return &self.slots[@intCast(policy_id - 1)];
    }

    fn activeSlot(self: *const Directory, scope: Scope, subject_id: u64) ?*const PolicySlot {
        var active: ?*const PolicySlot = null;
        for (self.slots[0..self.len]) |*slot| {
            if (!slot.policy.revoked and slot.policy.scope == scope and slot.policy.subject_id == subject_id) active = slot;
        }
        return active;
    }

    fn activeSlots(self: *const Directory, subjects: SubjectSet) [scope_count]?*const PolicySlot {
        var active: [scope_count]?*const PolicySlot = @splat(null);
        for (self.slots[0..self.len]) |*slot| {
            if (slot.policy.revoked) continue;
            const subject_id = subjectFor(subjects, slot.policy.scope) orelse continue;
            if (slot.policy.subject_id == subject_id) active[@backingInt(slot.policy.scope)] = slot;
        }
        return active;
    }

    fn latestGeneration(self: *const Directory, scope: Scope, subject_id: u64) u32 {
        var generation: u32 = 0;
        for (self.slots[0..self.len]) |*slot| {
            if (slot.policy.scope == scope and slot.policy.subject_id == subject_id) generation = slot.policy.generation;
        }
        return generation;
    }

    comptime {
        if (@sizeOf(@This()) > DIRECTORY_SIZE_CEILING_BYTES) {
            @compileError("policy directory exceeds its compact size ceiling");
        }
    }
};

// The policy state of a device before any policy is attached: every decision
// is allowed. Boot seeding and verification flows that run ahead of policy
// enrollment name it explicitly instead of skipping policy.
pub const unattached: Directory = .{};

const scope_count = @typeInfo(Scope).@"enum".field_names.len;
const decision_order = [scope_count]Scope{ .organization, .user, .device, .workspace };

fn subjectFor(subjects: SubjectSet, scope: Scope) ?u64 {
    return switch (scope) {
        .user => subjects.user_id,
        .device => subjects.device_id,
        .workspace => subjects.workspace_id,
        .organization => subjects.organization_id,
    };
}

fn allow() PolicyDecision {
    return .{ .allowed = true };
}

fn block(policy: *const PolicyObject, reason: DecisionReason) PolicyDecision {
    return .{
        .allowed = false,
        .reason = reason,
        .blocking_scope = policy.scope,
        .blocking_policy_id = policy.id,
        .blocking_generation = policy.generation,
    };
}

fn installSourceDenial(policy: *const PolicyObject, source_identity: []const u8) ?DecisionReason {
    return if (policy.allowsInstallSource(source_identity)) null else .install_source_denied;
}

fn packageProvenanceDenial(policy: *const PolicyObject, request: PackageProvenanceRequest) ?DecisionReason {
    if (policy.require_package_sbom and !request.sbom_present) return .package_sbom_denied;
    if (policy.require_reproducible_package_build and
        (!request.reproducible_build or !request.source_archive_present or !request.build_recipe_present))
    {
        return .package_reproducibility_denied;
    }
    if (policy.require_trusted_package_builder and !request.trusted_builder) return .package_builder_denied;
    if (policy.require_vulnerability_scan and !request.vulnerability_scan_present) return .package_vulnerability_scan_denied;
    return null;
}

fn agentDelegationDenial(policy: *const PolicyObject, request: AgentDelegationRequest) ?DecisionReason {
    if (!policy.agent_delegation_allowed) return .agent_delegation_denied;
    if (policy.max_agent_actions_per_session != 0 and request.autonomous_actions > policy.max_agent_actions_per_session) {
        return .agent_action_budget_denied;
    }
    if (policy.max_agent_remote_calls_per_session != 0 and request.remote_calls > policy.max_agent_remote_calls_per_session) {
        return .agent_remote_call_denied;
    }
    if (request.remote_calls != 0 and policy.require_agent_user_confirmation and !request.user_confirmed) {
        return .agent_confirmation_required;
    }
    if (policy.require_agent_audit and !request.audit_enabled) return .agent_audit_required;
    if (policy.require_agent_session_binding and !request.session_bound) return .agent_session_binding_denied;
    if (policy.require_agent_local_context and !request.local_context_only) return .agent_context_scope_denied;
    if (policy.max_agent_context_bytes != 0 and request.context_bytes > policy.max_agent_context_bytes) {
        return .agent_context_budget_denied;
    }
    if (request.delegation_generation < policy.min_agent_delegation_generation) return .agent_kill_switch_denied;
    if (policy.require_agent_visible_plan and !request.user_visible_plan) return .agent_plan_visibility_required;
    return null;
}

fn syncDestinationDenial(policy: *const PolicyObject, destination: []const u8) ?DecisionReason {
    return if (policy.allowsSyncDestination(destination)) null else .sync_destination_denied;
}

fn networkEgressDenial(policy: *const PolicyObject, destination: []const u8) ?DecisionReason {
    return if (policy.allowsNetworkDestination(destination)) null else .network_egress_denied;
}

fn permissionKindDenial(policy: *const PolicyObject, kind: manifest.PermissionKind) ?DecisionReason {
    const allowed, const reason: DecisionReason = switch (kind) {
        .clipboard => .{ policy.clipboard_allowed, .clipboard_denied },
        .camera => .{ policy.camera_allowed, .camera_denied },
        .mic => .{ policy.microphone_allowed, .microphone_denied },
        .location => .{ policy.location_allowed, .location_denied },
        .contacts => .{ policy.contacts_allowed, .contacts_denied },
        .sensor => .{ policy.sensors_allowed, .sensor_denied },
        .screen_capture => .{ policy.screen_capture_allowed, .screen_capture_denied },
        .peer_ipc => .{ policy.peer_ipc_allowed, .peer_ipc_denied },
        else => return null,
    };
    return if (allowed) null else reason;
}

fn aiUseDenial(policy: *const PolicyObject, request: AiUseRequest) ?DecisionReason {
    if (request.remote_model and !policy.remote_ai_allowed) return .remote_ai_denied;
    if (request.training_user_content and !policy.ai_training_allowed) return .ai_training_denied;
    if (policy.max_ai_context_bytes != 0 and request.context_bytes > policy.max_ai_context_bytes) return .ai_context_denied;
    if (request.remote_model) return null;
    if (policy.require_ai_model_measurement and !request.local_model_measured) return .ai_model_measurement_denied;
    if (policy.require_trusted_ai_model_source and !request.model_source_trusted) return .ai_model_source_denied;
    if (policy.max_ai_model_age_days != 0 and request.model_age_days > policy.max_ai_model_age_days) return .ai_model_staleness_denied;
    return null;
}

fn sessionLifetimeDenial(policy: *const PolicyObject, lifetime_ticks: u64) ?DecisionReason {
    if (policy.max_session_unlock_age_ticks != 0 and lifetime_ticks > policy.max_session_unlock_age_ticks) return .session_unlock_stale;
    return null;
}

fn sessionTrustDenial(policy: *const PolicyObject, request: SessionTrustRequest) ?DecisionReason {
    if (policy.require_hardware_backed_session and !request.hardware_backed_credential) return .session_hardware_denied;
    if (policy.require_platform_backed_device_session and !request.device_platform_backed) return .session_device_posture_denied;
    if (policy.require_primary_device_session and !request.primary_device_assertion) return .session_primary_device_denied;
    return sessionLifetimeDenial(policy, request.unlock_age_ticks);
}

fn sensitiveEgressDenial(policy: *const PolicyObject, request: SensitiveEgressRequest) ?DecisionReason {
    if (policy.max_remote_private_egress_bytes != 0 and request.remote_bytes > policy.max_remote_private_egress_bytes) {
        return .private_egress_budget_denied;
    }
    return null;
}

fn dataRightsDenial(policy: *const PolicyObject, request: DataRightsRequest) ?DecisionReason {
    switch (request.operation) {
        .portable_export => {
            if (!policy.data_export_allowed) return .data_export_denied;
            if (policy.max_data_export_bytes != 0 and request.bytes > policy.max_data_export_bytes) return .data_export_denied;
        },
        .delete => {
            if (!policy.data_deletion_allowed) return .data_deletion_denied;
            if (policy.require_data_deletion_receipt and !request.deletion_receipt_present) return .data_deletion_receipt_denied;
        },
    }
    return null;
}

fn objectResilienceDenial(policy: *const PolicyObject, request: ObjectResilienceRequest) ?DecisionReason {
    switch (request.operation) {
        .backup => {
            if (!policy.object_backup_allowed) return .object_backup_denied;
            if (policy.require_encrypted_object_backup and !request.encrypted) return .object_backup_encryption_denied;
            if (policy.require_backup_recovery_key and !request.recovery_key_present) return .object_backup_recovery_key_denied;
            if (policy.max_object_backup_bytes != 0 and request.bytes > policy.max_object_backup_bytes) return .object_backup_size_denied;
        },
        .restore, .migrate => {
            if (!policy.object_restore_allowed) return .object_restore_denied;
            if (policy.require_restore_device_trust and !request.device_trust_verified) return .object_restore_device_trust_denied;
            if (policy.max_object_restore_age_days != 0 and request.restore_age_days > policy.max_object_restore_age_days) {
                return .object_restore_staleness_denied;
            }
        },
    }
    return null;
}

fn semanticMemoryDenial(policy: *const PolicyObject, request: SemanticMemoryRequest) ?DecisionReason {
    if (!policy.semantic_memory_allowed) return .semantic_memory_denied;
    if (policy.require_local_semantic_model and !request.local_model) return .semantic_memory_remote_model_denied;
    if (policy.require_encrypted_semantic_index and !request.encrypted_index) return .semantic_memory_encryption_denied;
    if (policy.require_redacted_semantic_snippets and !request.redacted_snippets) return .semantic_memory_redaction_denied;
    if (policy.max_semantic_query_bytes != 0 and request.query_bytes > policy.max_semantic_query_bytes) return .semantic_query_budget_denied;
    return null;
}

fn credentialAssertionDenial(policy: *const PolicyObject, request: CredentialAssertionRequest) ?DecisionReason {
    if (!policy.credential_assertions_allowed) return .credential_assertion_denied;
    if (policy.deny_credential_password_fallback and request.password_fallback) return .credential_password_fallback_denied;
    if (policy.require_phishing_resistant_credential and !request.phishing_resistant) return .credential_phishing_resistance_denied;
    if (policy.require_hardware_backed_credential and !request.hardware_backed) return .credential_hardware_denied;
    if (policy.require_local_credential_unlock and !request.local_unlock_verified) return .credential_unlock_denied;
    if (policy.max_credential_unlock_age_ticks != 0 and request.unlock_age_ticks > policy.max_credential_unlock_age_ticks) {
        return .credential_unlock_stale;
    }
    return null;
}

fn secretVaultDenial(policy: *const PolicyObject, request: SecretVaultRequest) ?DecisionReason {
    if (!policy.secret_vault_allowed) return .secret_vault_denied;
    if (policy.require_hardware_backed_secrets and !request.hardware_backed) return .secret_hardware_denied;
    if (policy.deny_secret_raw_export and request.raw_export) return .secret_raw_export_denied;
    if (policy.max_secret_handle_lease_ticks != 0 and request.lease_ticks > policy.max_secret_handle_lease_ticks) return .secret_lease_denied;
    return null;
}

fn lifecycleDenial(policy: *const PolicyObject, request: LifecycleRequest) ?DecisionReason {
    if (!policy.task_lifecycle_allowed) return .task_lifecycle_denied;
    if (request.operation == .terminate_task and policy.require_lifecycle_checkpoint_before_terminate and !request.checkpoint_present) {
        return .task_lifecycle_checkpoint_required;
    }
    return null;
}

fn attentionDenial(policy: *const PolicyObject, request: AttentionRequest) ?DecisionReason {
    if (request.critical and !policy.allow_critical_interruption) return .attention_critical_denied;
    if (request.requests_interruption and !request.critical and policy.quiet_until_tick != 0 and request.now_tick < policy.quiet_until_tick) {
        return .attention_quiet_denied;
    }
    if (policy.max_visible_notifications != 0 and request.visible_notifications >= policy.max_visible_notifications) {
        return .attention_visible_budget_denied;
    }
    if (request.requests_interruption and policy.max_interruptive_notifications != 0 and
        request.interruptive_notifications >= policy.max_interruptive_notifications)
    {
        return .attention_interruption_budget_denied;
    }
    return null;
}

fn accessibilityDenial(policy: *const PolicyObject, request: AccessibilityRequest) ?DecisionReason {
    if (policy.require_adaptive_ui and !request.adaptive_ui) return .accessibility_adaptive_ui_denied;
    if (policy.require_screen_reader_support and !request.screen_reader_supported) return .accessibility_screen_reader_denied;
    if (policy.require_keyboard_navigation and !request.keyboard_navigation) return .accessibility_keyboard_navigation_denied;
    if (policy.require_reduced_motion_support and !request.reduced_motion_supported) return .accessibility_reduced_motion_denied;
    if (policy.require_high_contrast_support and !request.high_contrast_supported) return .accessibility_high_contrast_denied;
    return null;
}

fn backgroundActivityDenial(policy: *const PolicyObject, request: BackgroundActivityRequest) ?DecisionReason {
    if (policy.max_background_duration_seconds != 0 and request.expected_duration_seconds > policy.max_background_duration_seconds) {
        return .background_duration_denied;
    }
    if (policy.max_background_cpu_time_ticks != 0 and request.cpu_time_ticks > policy.max_background_cpu_time_ticks) {
        return .background_cpu_denied;
    }
    if ((policy.max_background_memory_bytes != 0 and request.memory_bytes > policy.max_background_memory_bytes) or
        (policy.max_background_shared_memory_bytes != 0 and request.shared_memory_bytes > policy.max_background_shared_memory_bytes))
    {
        return .background_memory_denied;
    }
    if (!policy.allow_remote_background_network and backgroundNetworkIsRemote(request.network)) return .background_network_denied;
    if (policy.require_visible_background_activity and !backgroundActivityIsVisible(request.visibility)) {
        return .background_visibility_denied;
    }
    return null;
}

fn permissionUseDenial(policy: *const PolicyObject, request: PermissionUseRequest) ?DecisionReason {
    if (policy.max_sensitive_retention_days != 0 and request.retention_days > policy.max_sensitive_retention_days) {
        return .permission_retention_denied;
    }
    if (!manifest.dangerousPermissionKind(request.kind)) return null;
    if (policy.require_sensitive_permission_lease and request.lease_ticks == 0) return .permission_lease_denied;
    if (policy.max_permission_lease_ticks != 0 and request.lease_ticks > policy.max_permission_lease_ticks) return .permission_lease_denied;
    return null;
}

fn sensitiveCaptureDenial(policy: *const PolicyObject, request: SensitiveCaptureRequest) ?DecisionReason {
    if (permissionKindDenial(policy, request.kind)) |reason| return reason;
    if (policy.require_sensitive_capture_foreground and !request.foreground_session) return .capture_foreground_denied;
    if (policy.require_capture_indicator and !request.visible_indicator) return .capture_indicator_denied;
    if (!policy.allow_background_capture and request.background) return .capture_background_denied;
    if (policy.max_sensitive_capture_lease_ticks != 0 and request.lease_ticks > policy.max_sensitive_capture_lease_ticks) {
        return .capture_lease_denied;
    }
    if (policy.max_sensitive_capture_samples != 0 and request.sample_budget > policy.max_sensitive_capture_samples) {
        return .capture_sample_budget_denied;
    }
    return null;
}

fn backgroundNetworkIsRemote(network: manifest.BackgroundNetworkMode) bool {
    return switch (network) {
        .named_service_identities, .named_domains, .unrestricted_internet => true,
        .unspecified, .none, .local_network_only => false,
    };
}

fn backgroundActivityIsVisible(visibility: manifest.BackgroundVisibility) bool {
    return switch (visibility) {
        .status_only, .user_visible => true,
        .unspecified, .hidden, .audit_only => false,
    };
}

// Local IDs, generations and revocation state belong to the directory. Detached
// signatures cover the complete canonical request, shared with native creation.
pub fn requestDigest(request: CreateRequest) !crypto_hash.Digest {
    var candidate: PolicyObject = undefined;
    try policyFromRequestInto(&candidate, request);
    return policyDigest(&candidate);
}

pub fn verifyRequest(request: CreateRequest, signature: manifest.Signature, issuer_key: signing.PublicKey) !void {
    if (!issuerSigned(&(try requestDigest(request)), signature, issuer_key)) return error.UntrustedPolicy;
}

fn issuerSigned(digest: *const crypto_hash.Digest, signature: manifest.Signature, issuer_key: signing.PublicKey) bool {
    return std.mem.eql(u8, signature.publicKeySlice(), &issuer_key) and signing.verify(signature, digest);
}

// Binds the signed policy digest to the exact signature bytes the Directory
// accepted. The unauthenticated signer label is deliberately excluded.
fn verifiedBinding(digest: *const crypto_hash.Digest, signature: *const manifest.Signature) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "policy-digest", digest);
    crypto_hash.updateEnum(&hasher, "signature-format", signature.format);
    crypto_hash.updateInt(&hasher, "public-key-len", signature.public_key_len);
    crypto_hash.updateBytes(&hasher, "public-key", &signature.public_key);
    crypto_hash.updateInt(&hasher, "value-len", signature.value_len);
    crypto_hash.updateBytes(&hasher, "value", &signature.value);
    return crypto_hash.finalize(&hasher);
}

// Only a successful construction may be consumed or published. The caller
// owns this private candidate, including partial state on validation failure.
fn policyFromRequestInto(policy: *PolicyObject, request: CreateRequest) Error!void {
    if (request.allowed_install_sources.len > MAX_ALLOW_LIST) return error.TooManyInstallSources;
    if (request.allowed_network_destinations.len > MAX_ALLOW_LIST) return error.TooManyNetworkDestinations;
    if (request.allowed_sync_destinations.len > MAX_ALLOW_LIST) return error.TooManySyncDestinations;

    policy.* = .{
        .scope = request.scope,
        .subject_id = request.subject_id,
        .issuer = request.issuer,
    };
    policy.label_len = @intCast(native_util.copyTextExact(&policy.label, request.label) catch return error.LabelTooLong);
    inline for (model.signed_controls) |name| @field(policy, name) = @field(request, name);

    for (request.allowed_install_sources, 0..) |source_identity, index| {
        policy.allowed_install_source_lens[index] = @intCast(native_util.copyTextExact(&policy.allowed_install_sources[index], source_identity) catch return error.InstallSourceTooLong);
        policy.allowed_install_source_count += 1;
    }
    for (request.allowed_network_destinations, 0..) |destination, index| {
        policy.allowed_network_destination_lens[index] = @intCast(native_util.copyTextExact(&policy.allowed_network_destinations[index], destination) catch return error.NetworkDestinationTooLong);
        policy.allowed_network_destination_count += 1;
    }
    for (request.allowed_sync_destinations, 0..) |destination, index| {
        policy.allowed_sync_destination_lens[index] = @intCast(native_util.copyTextExact(&policy.allowed_sync_destinations[index], destination) catch return error.SyncDestinationTooLong);
        policy.allowed_sync_destination_count += 1;
    }
}

fn policyDigest(policy: *const PolicyObject) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "scope", policy.scope);
    crypto_hash.updateEnum(&hasher, "issuer-kind", policy.issuer.kind);
    crypto_hash.updateInt(&hasher, "subject-id", policy.subject_id);
    crypto_hash.updateInt(&hasher, "issuer-serial", policy.issuer.serial);
    crypto_hash.updateBytes(&hasher, "label", policy.labelSlice());
    inline for (model.signed_controls, control_digest_tags) |name, tag| {
        const value = @field(policy, name);
        switch (@typeInfo(@TypeOf(value))) {
            .bool => crypto_hash.updateBool(&hasher, tag, value),
            .@"enum" => crypto_hash.updateEnum(&hasher, tag, value),
            .int => crypto_hash.updateInt(&hasher, tag, value),
            else => comptime unreachable,
        }
    }
    for (0..policy.allowed_install_source_count) |index| {
        crypto_hash.updateInt(&hasher, "install-source-index", index);
        crypto_hash.updateBytes(&hasher, "install-source", policy.allowed_install_sources[index][0..policy.allowed_install_source_lens[index]]);
    }
    for (0..policy.allowed_network_destination_count) |index| {
        crypto_hash.updateInt(&hasher, "network-destination-index", index);
        crypto_hash.updateBytes(&hasher, "network-destination", policy.allowed_network_destinations[index][0..policy.allowed_network_destination_lens[index]]);
    }
    for (0..policy.allowed_sync_destination_count) |index| {
        crypto_hash.updateInt(&hasher, "sync-destination-index", index);
        crypto_hash.updateBytes(&hasher, "sync-destination", policy.allowed_sync_destinations[index][0..policy.allowed_sync_destination_lens[index]]);
    }
    return crypto_hash.finalize(&hasher);
}

// Each control is signed under its field name with '_' spelled as '-'.
const control_digest_tags: [model.signed_controls.len][]const u8 = blk: {
    @setEvalBranchQuota(50_000);
    var tags: [model.signed_controls.len][]const u8 = undefined;
    for (model.signed_controls, &tags) |name, *tag| {
        var spelled: [name.len]u8 = name[0..name.len].*;
        std.mem.replaceScalar(u8, &spelled, '_', '-');
        const final = spelled;
        tag.* = &final;
    }
    break :blk tags;
};

test "policy objects remain signed scoped and enforce enterprise controls" {
    var directory: Directory = undefined;
    @memset(std.mem.asBytes(&directory), 0xa5);
    directory.initializeAllocated();
    const policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp-apps" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.corp.example" },
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 4096,
        .retention_days = 365,
        .audit_export_required = true,
    }, .{
        .label = "corp-policy-key",
        .seed = signing.seedFromByte(0x81),
    });

    try std.testing.expectEqual(@as(u32, 1), policy.generation);
    try std.testing.expectEqualStrings("corp-defaults", policy.labelSlice());
    try std.testing.expect(directory.verify(policy.id));
    const organization = SubjectSet{ .organization_id = 77 };
    try std.testing.expect(directory.installSourceDecision(organization, "store:zigos").allowed);
    try std.testing.expect(!directory.installSourceDecision(organization, "repo:unknown").allowed);
    try std.testing.expect(directory.syncDestinationDecision(organization, "relay.corp.example").allowed);
    try std.testing.expect(!directory.syncDestinationDecision(organization, "relay.personal.example").allowed);
    try std.testing.expect(!policy.removable_storage_allowed);
    try std.testing.expect(policy.screen_capture_allowed);
    try std.testing.expect(!policy.remote_ai_allowed);
    try std.testing.expect(!policy.ai_training_allowed);
    try std.testing.expectEqual(@as(usize, 4096), policy.max_ai_context_bytes);
    try std.testing.expect(policy.audit_export_required);
    try std.testing.expectEqual(@as(u16, 365), policy.retention_days);

    _ = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-tightened",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "corp-policy-key",
        .seed = signing.seedFromByte(0x81),
    });
    const latest = directory.activeForScope(.organization, 77).?;
    try std.testing.expectEqual(@as(u32, 2), latest.generation);
    try std.testing.expect(latest.allowsInstallSource("store:zigos"));
    try std.testing.expect(!latest.allowsInstallSource("repo:corp-apps"));
}

test "policy directory composes active user device workspace and organization policy" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "policy-compose-key",
        .seed = signing.seedFromByte(0x83),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-baseline",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .screen_capture_allowed = false,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 4096,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 70,
        .issuer = .{ .kind = .policy_authority, .serial = 8 },
        .label = "user-preferences",
        .install_source_mode = .any_signed,
        .network_egress_mode = .inherit,
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 2048,
    }, signer);
    const device_policy = try directory.create(.{
        .scope = .device,
        .subject_id = 701,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "device-hardening",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = true,
    }, signer);
    _ = try directory.create(.{
        .scope = .workspace,
        .subject_id = 9_001,
        .issuer = .{ .kind = .policy_authority, .serial = 10 },
        .label = "workspace-sync",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.project.example" },
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = true,
        .max_ai_context_bytes = 1024,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 70,
        .device_id = 701,
        .workspace_id = 9_001,
        .organization_id = 7,
    };
    const store_decision = directory.installSourceDecision(subjects, "store:zigos");
    try std.testing.expect(store_decision.allowed);

    const corp_repo_decision = directory.installSourceDecision(subjects, "repo:corp");
    try std.testing.expect(!corp_repo_decision.allowed);
    try std.testing.expectEqual(DecisionReason.install_source_denied, corp_repo_decision.reason);
    try std.testing.expectEqual(Scope.device, corp_repo_decision.blocking_scope.?);
    try std.testing.expectEqual(device_policy.id, corp_repo_decision.blocking_policy_id);

    const relay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(relay_decision.allowed);
    const overlay_decision = directory.syncDestinationDecision(subjects, "overlay.project.example");
    try std.testing.expect(!overlay_decision.allowed);
    try std.testing.expectEqual(DecisionReason.sync_destination_denied, overlay_decision.reason);
    try std.testing.expectEqual(Scope.organization, overlay_decision.blocking_scope.?);

    const screen_decision = directory.permissionKindDecision(subjects, .screen_capture);
    try std.testing.expect(!screen_decision.allowed);
    try std.testing.expectEqual(DecisionReason.screen_capture_denied, screen_decision.reason);
    try std.testing.expectEqual(org_policy.id, screen_decision.blocking_policy_id);

    const remote_ai_decision = directory.aiUseDecision(subjects, .{
        .remote_model = true,
        .context_bytes = 512,
    });
    try std.testing.expect(!remote_ai_decision.allowed);
    try std.testing.expectEqual(DecisionReason.remote_ai_denied, remote_ai_decision.reason);
    try std.testing.expectEqual(Scope.organization, remote_ai_decision.blocking_scope.?);

    const training_decision = directory.aiUseDecision(subjects, .{
        .training_user_content = true,
        .context_bytes = 512,
    });
    try std.testing.expect(!training_decision.allowed);
    try std.testing.expectEqual(DecisionReason.ai_training_denied, training_decision.reason);
    try std.testing.expectEqual(Scope.organization, training_decision.blocking_scope.?);

    const context_decision = directory.aiUseDecision(subjects, .{
        .context_bytes = 2_048,
    });
    try std.testing.expect(!context_decision.allowed);
    try std.testing.expectEqual(DecisionReason.ai_context_denied, context_decision.reason);
    try std.testing.expectEqual(Scope.workspace, context_decision.blocking_scope.?);

    const local_small_ai_decision = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
    });
    try std.testing.expect(local_small_ai_decision.allowed);

    const tightened_org = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-store-only",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .none,
    }, signer);
    const next_overlay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(!next_overlay_decision.allowed);
    try std.testing.expectEqual(tightened_org.id, next_overlay_decision.blocking_policy_id);
    try std.testing.expectEqual(@as(u32, 2), next_overlay_decision.blocking_generation);
}

test "policy directory gates sensitive device permissions and private egress budgets" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "privacy-policy-key",
        .seed = signing.seedFromByte(0x84),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 88,
        .issuer = .{ .kind = .policy_authority, .serial = 88 },
        .label = "privacy-baseline",
        .camera_allowed = false,
        .microphone_allowed = false,
        .location_allowed = false,
        .contacts_allowed = false,
        .sensors_allowed = false,
        .clipboard_allowed = false,
        .peer_ipc_allowed = false,
        .max_remote_private_egress_bytes = 1024,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 880,
        .issuer = .{ .kind = .policy_authority, .serial = 89 },
        .label = "user-local-tools",
        .camera_allowed = true,
        .microphone_allowed = true,
        .location_allowed = true,
        .contacts_allowed = true,
        .sensors_allowed = true,
        .clipboard_allowed = true,
        .peer_ipc_allowed = true,
        .max_remote_private_egress_bytes = 4096,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 880,
        .organization_id = 88,
    };
    const camera_decision = directory.permissionKindDecision(subjects, .camera);
    try std.testing.expect(!camera_decision.allowed);
    try std.testing.expectEqual(DecisionReason.camera_denied, camera_decision.reason);
    try std.testing.expectEqual(org_policy.id, camera_decision.blocking_policy_id);

    const clipboard_decision = directory.permissionKindDecision(subjects, .clipboard);
    try std.testing.expect(!clipboard_decision.allowed);
    try std.testing.expectEqual(DecisionReason.clipboard_denied, clipboard_decision.reason);

    const object_decision = directory.permissionKindDecision(subjects, .object_access);
    try std.testing.expect(object_decision.allowed);

    const small_private = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .private_user_data,
        .remote_bytes = 512,
    });
    try std.testing.expect(small_private.allowed);

    const large_private = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .private_user_data,
        .remote_bytes = 2048,
    });
    try std.testing.expect(!large_private.allowed);
    try std.testing.expectEqual(DecisionReason.private_egress_budget_denied, large_private.reason);
    try std.testing.expectEqual(Scope.organization, large_private.blocking_scope.?);

    const large_internal = directory.sensitiveEgressDecision(subjects, .{
        .sensitivity = .internal_data,
        .remote_bytes = 65_536,
    });
    try std.testing.expect(large_internal.allowed);
}

test "policy directory gates local AI model provenance" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "ai-model-policy-key",
        .seed = signing.seedFromByte(0x87),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 91,
        .issuer = .{ .kind = .policy_authority, .serial = 94 },
        .label = "ai-model-provenance",
        .remote_ai_allowed = false,
        .require_ai_model_measurement = true,
        .require_trusted_ai_model_source = true,
        .max_ai_model_age_days = 30,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 91,
    };
    const measured = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = true,
        .model_age_days = 7,
    });
    try std.testing.expect(measured.allowed);

    const unmeasured = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = false,
        .model_source_trusted = true,
        .model_age_days = 7,
    });
    try std.testing.expect(!unmeasured.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_measurement_denied, unmeasured.reason);
    try std.testing.expectEqual(org_policy.id, unmeasured.blocking_policy_id);

    const untrusted_source = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = false,
        .model_age_days = 7,
    });
    try std.testing.expect(!untrusted_source.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_source_denied, untrusted_source.reason);

    const stale = directory.aiUseDecision(subjects, .{
        .context_bytes = 512,
        .local_model_measured = true,
        .model_source_trusted = true,
        .model_age_days = 45,
    });
    try std.testing.expect(!stale.allowed);
    try std.testing.expectEqual(DecisionReason.ai_model_staleness_denied, stale.reason);

    const remote = directory.aiUseDecision(subjects, .{
        .remote_model = true,
        .context_bytes = 512,
        .local_model_measured = false,
        .model_source_trusted = false,
        .model_age_days = 365,
    });
    try std.testing.expect(!remote.allowed);
    try std.testing.expectEqual(DecisionReason.remote_ai_denied, remote.reason);
}

test "policy directory gates trusted session posture" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "session-trust-policy-key",
        .seed = signing.seedFromByte(0x88),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 92,
        .issuer = .{ .kind = .policy_authority, .serial = 95 },
        .label = "trusted-session",
        .require_hardware_backed_session = true,
        .require_platform_backed_device_session = true,
        .require_primary_device_session = true,
        .max_session_unlock_age_ticks = 5,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 92,
    };
    const trusted = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(trusted.allowed);

    const software_secret = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = false,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!software_secret.allowed);
    try std.testing.expectEqual(DecisionReason.session_hardware_denied, software_secret.reason);
    try std.testing.expectEqual(org_policy.id, software_secret.blocking_policy_id);

    const software_device = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = false,
        .primary_device_assertion = true,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!software_device.allowed);
    try std.testing.expectEqual(DecisionReason.session_device_posture_denied, software_device.reason);

    const stale_unlock = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = true,
        .unlock_age_ticks = 9,
    });
    try std.testing.expect(!stale_unlock.allowed);
    try std.testing.expectEqual(DecisionReason.session_unlock_stale, stale_unlock.reason);

    const secondary_device = directory.sessionTrustDecision(subjects, .{
        .hardware_backed_credential = true,
        .device_platform_backed = true,
        .primary_device_assertion = false,
        .unlock_age_ticks = 2,
    });
    try std.testing.expect(!secondary_device.allowed);
    try std.testing.expectEqual(DecisionReason.session_primary_device_denied, secondary_device.reason);
}

test "policy directory gates package supply chain posture" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "package-provenance-policy-key",
        .seed = signing.seedFromByte(0x89),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 93,
        .issuer = .{ .kind = .policy_authority, .serial = 96 },
        .label = "package-provenance",
        .require_package_sbom = true,
        .require_reproducible_package_build = true,
        .require_trusted_package_builder = true,
        .require_vulnerability_scan = true,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 93,
    };
    const trusted = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(trusted.allowed);

    const missing_sbom = directory.packageProvenanceDecision(subjects, .{
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!missing_sbom.allowed);
    try std.testing.expectEqual(DecisionReason.package_sbom_denied, missing_sbom.reason);
    try std.testing.expectEqual(org_policy.id, missing_sbom.blocking_policy_id);

    const missing_recipe = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!missing_recipe.allowed);
    try std.testing.expectEqual(DecisionReason.package_reproducibility_denied, missing_recipe.reason);

    const untrusted_builder = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .vulnerability_scan_present = true,
    });
    try std.testing.expect(!untrusted_builder.allowed);
    try std.testing.expectEqual(DecisionReason.package_builder_denied, untrusted_builder.reason);

    const missing_scan = directory.packageProvenanceDecision(subjects, .{
        .sbom_present = true,
        .source_archive_present = true,
        .build_recipe_present = true,
        .reproducible_build = true,
        .trusted_builder = true,
    });
    try std.testing.expect(!missing_scan.allowed);
    try std.testing.expectEqual(DecisionReason.package_vulnerability_scan_denied, missing_scan.reason);
}

test "policy directory gates agent delegation budgets confirmation and audit" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "agent-policy-key",
        .seed = signing.seedFromByte(0x8B),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 95,
        .issuer = .{ .kind = .policy_authority, .serial = 98 },
        .label = "bounded-agent-delegation",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 8,
        .max_agent_remote_calls_per_session = 1,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 4096,
        .min_agent_delegation_generation = 4,
        .require_agent_visible_plan = true,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 95,
    };
    const allowed = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(allowed.allowed);

    const too_many_actions = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 9,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(!too_many_actions.allowed);
    try std.testing.expectEqual(DecisionReason.agent_action_budget_denied, too_many_actions.reason);
    try std.testing.expectEqual(org_policy.id, too_many_actions.blocking_policy_id);

    const too_many_remote_calls = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 2,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(!too_many_remote_calls.allowed);
    try std.testing.expectEqual(DecisionReason.agent_remote_call_denied, too_many_remote_calls.reason);

    const missing_confirmation = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 1,
        .audit_enabled = true,
    });
    try std.testing.expect(!missing_confirmation.allowed);
    try std.testing.expectEqual(DecisionReason.agent_confirmation_required, missing_confirmation.reason);

    const missing_audit = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
    });
    try std.testing.expect(!missing_audit.allowed);
    try std.testing.expectEqual(DecisionReason.agent_audit_required, missing_audit.reason);

    const missing_session_binding = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(!missing_session_binding.allowed);
    try std.testing.expectEqual(DecisionReason.agent_session_binding_denied, missing_session_binding.reason);

    const remote_context = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = false,
        .context_bytes = 2048,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(!remote_context.allowed);
    try std.testing.expectEqual(DecisionReason.agent_context_scope_denied, remote_context.reason);

    const oversized_context = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 8192,
        .delegation_generation = 4,
        .user_visible_plan = true,
    });
    try std.testing.expect(!oversized_context.allowed);
    try std.testing.expectEqual(DecisionReason.agent_context_budget_denied, oversized_context.reason);

    const stale_generation = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 3,
        .user_visible_plan = true,
    });
    try std.testing.expect(!stale_generation.allowed);
    try std.testing.expectEqual(DecisionReason.agent_kill_switch_denied, stale_generation.reason);

    const hidden_plan = directory.agentDelegationDecision(subjects, .{
        .enabled = true,
        .autonomous_actions = 4,
        .remote_calls = 0,
        .user_confirmed = true,
        .audit_enabled = true,
        .session_bound = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 4,
    });
    try std.testing.expect(!hidden_plan.allowed);
    try std.testing.expectEqual(DecisionReason.agent_plan_visibility_required, hidden_plan.reason);

    var locked_directory = Directory.init();
    _ = try locked_directory.create(.{
        .scope = .organization,
        .subject_id = 96,
        .issuer = .{ .kind = .policy_authority, .serial = 99 },
        .label = "no-agent-delegation",
        .agent_delegation_allowed = false,
    }, signer);
    const locked = locked_directory.agentDelegationDecision(.{ .organization_id = 96 }, .{
        .enabled = true,
        .autonomous_actions = 1,
        .audit_enabled = true,
    });
    try std.testing.expect(!locked.allowed);
    try std.testing.expectEqual(DecisionReason.agent_delegation_denied, locked.reason);
}

test "policy directory gates user attention budgets and quiet hours" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "attention-policy-key",
        .seed = signing.seedFromByte(0x8C),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 97,
        .issuer = .{ .kind = .policy_authority, .serial = 100 },
        .label = "attention-baseline",
        .quiet_until_tick = 500,
        .max_visible_notifications = 3,
        .max_interruptive_notifications = 1,
        .allow_critical_interruption = false,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 970,
        .issuer = .{ .kind = .policy_authority, .serial = 101 },
        .label = "user-attention",
        .quiet_until_tick = 0,
        .max_visible_notifications = 6,
        .max_interruptive_notifications = 2,
        .allow_critical_interruption = true,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 970,
        .organization_id = 97,
    };
    const passive = directory.attentionDecision(subjects, .{
        .now_tick = 300,
        .visible_notifications = 1,
    });
    try std.testing.expect(passive.allowed);

    const quiet = directory.attentionDecision(subjects, .{
        .now_tick = 300,
        .visible_notifications = 1,
        .requests_interruption = true,
    });
    try std.testing.expect(!quiet.allowed);
    try std.testing.expectEqual(DecisionReason.attention_quiet_denied, quiet.reason);
    try std.testing.expectEqual(org_policy.id, quiet.blocking_policy_id);

    const visible_budget = directory.attentionDecision(subjects, .{
        .now_tick = 600,
        .visible_notifications = 3,
    });
    try std.testing.expect(!visible_budget.allowed);
    try std.testing.expectEqual(DecisionReason.attention_visible_budget_denied, visible_budget.reason);

    const interruption_budget = directory.attentionDecision(subjects, .{
        .now_tick = 600,
        .visible_notifications = 1,
        .interruptive_notifications = 1,
        .requests_interruption = true,
    });
    try std.testing.expect(!interruption_budget.allowed);
    try std.testing.expectEqual(DecisionReason.attention_interruption_budget_denied, interruption_budget.reason);

    const critical = directory.attentionDecision(subjects, .{
        .now_tick = 600,
        .visible_notifications = 1,
        .requests_interruption = true,
        .critical = true,
    });
    try std.testing.expect(!critical.allowed);
    try std.testing.expectEqual(DecisionReason.attention_critical_denied, critical.reason);
}

test "policy directory gates accessibility profile requirements" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "accessibility-policy-key",
        .seed = signing.seedFromByte(0x8D),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 98,
        .issuer = .{ .kind = .policy_authority, .serial = 102 },
        .label = "accessible-ui-baseline",
        .require_adaptive_ui = true,
        .require_screen_reader_support = true,
        .require_keyboard_navigation = true,
        .require_reduced_motion_support = true,
        .require_high_contrast_support = true,
    }, signer);

    const subjects = SubjectSet{
        .organization_id = 98,
    };
    const allowed = directory.accessibilityDecision(subjects, .{
        .adaptive_ui = true,
        .screen_reader_supported = true,
        .keyboard_navigation = true,
        .reduced_motion_supported = true,
        .high_contrast_supported = true,
    });
    try std.testing.expect(allowed.allowed);

    const missing_adaptive = directory.accessibilityDecision(subjects, .{
        .screen_reader_supported = true,
        .keyboard_navigation = true,
        .reduced_motion_supported = true,
        .high_contrast_supported = true,
    });
    try std.testing.expect(!missing_adaptive.allowed);
    try std.testing.expectEqual(DecisionReason.accessibility_adaptive_ui_denied, missing_adaptive.reason);
    try std.testing.expectEqual(org_policy.id, missing_adaptive.blocking_policy_id);

    const missing_screen_reader = directory.accessibilityDecision(subjects, .{
        .adaptive_ui = true,
        .keyboard_navigation = true,
        .reduced_motion_supported = true,
        .high_contrast_supported = true,
    });
    try std.testing.expect(!missing_screen_reader.allowed);
    try std.testing.expectEqual(DecisionReason.accessibility_screen_reader_denied, missing_screen_reader.reason);

    const missing_keyboard = directory.accessibilityDecision(subjects, .{
        .adaptive_ui = true,
        .screen_reader_supported = true,
        .reduced_motion_supported = true,
        .high_contrast_supported = true,
    });
    try std.testing.expect(!missing_keyboard.allowed);
    try std.testing.expectEqual(DecisionReason.accessibility_keyboard_navigation_denied, missing_keyboard.reason);

    const missing_reduced_motion = directory.accessibilityDecision(subjects, .{
        .adaptive_ui = true,
        .screen_reader_supported = true,
        .keyboard_navigation = true,
        .high_contrast_supported = true,
    });
    try std.testing.expect(!missing_reduced_motion.allowed);
    try std.testing.expectEqual(DecisionReason.accessibility_reduced_motion_denied, missing_reduced_motion.reason);

    const missing_high_contrast = directory.accessibilityDecision(subjects, .{
        .adaptive_ui = true,
        .screen_reader_supported = true,
        .keyboard_navigation = true,
        .reduced_motion_supported = true,
    });
    try std.testing.expect(!missing_high_contrast.allowed);
    try std.testing.expectEqual(DecisionReason.accessibility_high_contrast_denied, missing_high_contrast.reason);
}

test "policy directory gates sensitive data export deletion and receipts" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "data-rights-policy-key",
        .seed = signing.seedFromByte(0x86),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 90,
        .issuer = .{ .kind = .policy_authority, .serial = 92 },
        .label = "data-rights-baseline",
        .data_export_allowed = true,
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = true,
        .max_data_export_bytes = 4096,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 901,
        .issuer = .{ .kind = .policy_authority, .serial = 93 },
        .label = "user-data-rights",
        .data_export_allowed = true,
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = false,
        .max_data_export_bytes = 8192,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 901,
        .organization_id = 90,
    };
    const small_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .private_user_data,
        .bytes = 2048,
    });
    try std.testing.expect(small_export.allowed);

    const large_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .private_user_data,
        .bytes = 8192,
    });
    try std.testing.expect(!large_export.allowed);
    try std.testing.expectEqual(DecisionReason.data_export_denied, large_export.reason);
    try std.testing.expectEqual(org_policy.id, large_export.blocking_policy_id);

    const delete_without_receipt = directory.dataRightsDecision(subjects, .{
        .operation = .delete,
        .sensitivity = .private_user_data,
    });
    try std.testing.expect(!delete_without_receipt.allowed);
    try std.testing.expectEqual(DecisionReason.data_deletion_receipt_denied, delete_without_receipt.reason);

    const delete_with_receipt = directory.dataRightsDecision(subjects, .{
        .operation = .delete,
        .sensitivity = .private_user_data,
        .deletion_receipt_present = true,
    });
    try std.testing.expect(delete_with_receipt.allowed);

    const public_export = directory.dataRightsDecision(subjects, .{
        .operation = .portable_export,
        .sensitivity = .public_data,
        .bytes = 1_000_000,
    });
    try std.testing.expect(public_export.allowed);
}

test "policy directory gates sensitive permission retention and leases" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "permission-lifecycle-key",
        .seed = signing.seedFromByte(0x85),
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 89,
        .issuer = .{ .kind = .policy_authority, .serial = 90 },
        .label = "sensitive-lifecycle",
        .max_sensitive_retention_days = 30,
        .max_permission_lease_ticks = 600,
        .require_sensitive_permission_lease = true,
        .camera_allowed = true,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 891,
        .issuer = .{ .kind = .policy_authority, .serial = 91 },
        .label = "user-lifecycle",
        .max_sensitive_retention_days = 90,
        .max_permission_lease_ticks = 1200,
        .require_sensitive_permission_lease = false,
        .camera_allowed = true,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 891,
        .organization_id = 89,
    };
    const allowed = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
        .lease_ticks = 300,
    });
    try std.testing.expect(allowed.allowed);

    const retention_denied = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 45,
        .lease_ticks = 300,
    });
    try std.testing.expect(!retention_denied.allowed);
    try std.testing.expectEqual(DecisionReason.permission_retention_denied, retention_denied.reason);
    try std.testing.expectEqual(org_policy.id, retention_denied.blocking_policy_id);

    const missing_lease = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
    });
    try std.testing.expect(!missing_lease.allowed);
    try std.testing.expectEqual(DecisionReason.permission_lease_denied, missing_lease.reason);

    const long_lease = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .private_user_data,
        .retention_days = 7,
        .lease_ticks = 900,
    });
    try std.testing.expect(!long_lease.allowed);
    try std.testing.expectEqual(DecisionReason.permission_lease_denied, long_lease.reason);

    const public_unbounded = directory.permissionUseDecision(subjects, .{
        .kind = .camera,
        .sensitivity = .public_data,
        .retention_days = 365,
    });
    try std.testing.expect(public_unbounded.allowed);
}

test "policy objects reject oversized lists and refuse authorization after tampering" {
    var directory = Directory.init();
    const oversized_label = @as([MAX_LABEL_BYTES + 1]u8, @splat('x'));
    try std.testing.expectError(error.LabelTooLong, directory.create(.{
        .scope = .user,
        .subject_id = 5,
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .label = oversized_label[0..],
    }, .{
        .label = "policy-key",
        .seed = signing.seedFromByte(0x51),
    }));
    try std.testing.expect(directory.activeForScope(.user, 5) == null);

    const too_many = [_][]const u8{
        "a", "b", "c", "d", "e", "f", "g", "h", "i",
    };
    try std.testing.expectError(error.TooManyInstallSources, directory.create(.{
        .scope = .user,
        .subject_id = 5,
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .label = "overflow",
        .allowed_install_sources = &too_many,
    }, .{
        .label = "policy-key",
        .seed = signing.seedFromByte(0x52),
    }));

    const policy = try directory.create(.{
        .scope = .device,
        .subject_id = 8,
        .issuer = .{ .kind = .policy_authority, .serial = 3 },
        .label = "signed-device-policy",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "device-policy-key",
        .seed = signing.seedFromByte(0x53),
    });
    try std.testing.expectEqual(@as(u64, 1), policy.id);
    try std.testing.expect(directory.verify(policy.id));

    const device = SubjectSet{ .device_id = 8 };
    try std.testing.expect(directory.installSourceDecision(device, "store:zigos").allowed);

    policy.signature.value[0] ^= 0x5A;
    try std.testing.expect(!directory.verify(policy.id));
    const forged_signature = directory.installSourceDecision(device, "store:zigos");
    try std.testing.expect(!forged_signature.allowed);
    try std.testing.expectEqual(DecisionReason.unsigned_policy, forged_signature.reason);
    policy.signature.value[0] ^= 0x5A;
    try std.testing.expect(directory.verify(policy.id));
    try std.testing.expect(directory.installSourceDecision(device, "store:zigos").allowed);

    policy.install_source_mode = .any_signed;
    try std.testing.expect(!directory.verify(policy.id));
    const widened = directory.installSourceDecision(device, "repo:unknown");
    try std.testing.expect(!widened.allowed);
    try std.testing.expectEqual(DecisionReason.unsigned_policy, widened.reason);
    try std.testing.expectEqual(policy.id, widened.blocking_policy_id);

    // Re-signing the widened policy in place with an arbitrary key verifies
    // under its embedded key but is not the signature the Directory accepted.
    policy.signature = try signing.sign(.{
        .label = "in-memory-forger",
        .seed = signing.seedFromByte(0x54),
    }, &policyDigest(policy));
    try std.testing.expect(signing.verify(policy.signature, &policyDigest(policy)));
    try std.testing.expect(!directory.verify(policy.id));
    try std.testing.expectEqual(DecisionReason.unsigned_policy, directory.installSourceDecision(device, "repo:unknown").reason);
}

test "compact policy metadata preserves exact label and allow-list capacities" {
    const full_label = @as([MAX_LABEL_BYTES]u8, @splat('p'));
    const full_allow_list = @as([MAX_ALLOW_LIST][]const u8, @splat(&full_label));
    var directory = Directory.init();
    const policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 88 },
        .label = &full_label,
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &full_allow_list,
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &full_allow_list,
        .allowed_sync_destinations = &full_allow_list,
    }, .{
        .label = "compact-policy-key",
        .seed = signing.seedFromByte(0x68),
    });

    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), policy.label_len);
    try std.testing.expectEqual(@as(u8, MAX_ALLOW_LIST), policy.allowed_install_source_count);
    try std.testing.expectEqual(@as(u8, MAX_ALLOW_LIST), policy.allowed_network_destination_count);
    try std.testing.expectEqual(@as(u8, MAX_ALLOW_LIST), policy.allowed_sync_destination_count);
    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), policy.allowed_install_source_lens[MAX_ALLOW_LIST - 1]);
    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), policy.allowed_network_destination_lens[MAX_ALLOW_LIST - 1]);
    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), policy.allowed_sync_destination_lens[MAX_ALLOW_LIST - 1]);
    try std.testing.expectEqualSlices(u8, &full_label, policy.labelSlice());
    try std.testing.expect(policy.allowsInstallSource(&full_label));
    try std.testing.expect(policy.allowsNetworkDestination(&full_label));
    try std.testing.expect(policy.allowsSyncDestination(&full_label));
    try std.testing.expect(directory.verify(policy.id));
}

test "authenticated policy attachment validates the complete candidate before publication" {
    const signer = signing.SignerIdentity{
        .label = "detached-policy-issuer",
        .seed = signing.seedFromByte(0x69),
    };
    const issuer_key = try signing.publicKey(signer);
    const request = CreateRequest{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 88 },
        .label = "authenticated-policy",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "store:organization" },
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &.{ "local:organization", "lan.example" },
        .allowed_sync_destinations = &.{"local:archive"},
        .max_remote_private_egress_bytes = 1024,
        .require_hardware_backed_session = true,
    };
    const signature = try signing.sign(signer, &(try requestDigest(request)));
    try verifyRequest(request, signature, issuer_key);
    var directory = Directory.init();

    try std.testing.expectError(error.UntrustedPolicy, directory.attachInitialAuthenticated(request, signature, @splat(0)));
    var bad_signature = signature;
    bad_signature.value[0] ^= 1;
    try std.testing.expectError(error.UntrustedPolicy, directory.attachInitialAuthenticated(request, bad_signature, issuer_key));
    for (0..4) |field| {
        var changed = request;
        switch (field) {
            0 => changed.allowed_install_sources = &.{"store:other"},
            1 => changed.allowed_network_destinations = &.{"local:other"},
            2 => changed.allowed_sync_destinations = &.{"local:other"},
            3 => changed.max_remote_private_egress_bytes += 1,
            else => unreachable,
        }
        try std.testing.expectError(error.UntrustedPolicy, directory.attachInitialAuthenticated(changed, signature, issuer_key));
    }
    const too_long: [MAX_LABEL_BYTES + 1]u8 = @splat('s');
    var malformed = request;
    malformed.allowed_sync_destinations = &.{ "local:archive", &too_long };
    try std.testing.expectError(error.SyncDestinationTooLong, directory.attachInitialAuthenticated(malformed, signature, issuer_key));
    try std.testing.expectEqual(@as(usize, 0), directory.count());
    try std.testing.expect(directory.activeForScope(request.scope, request.subject_id) == null);

    const policy = try directory.attachInitialAuthenticated(request, signature, issuer_key);
    try std.testing.expectEqual(@as(u64, 1), policy.id);
    try std.testing.expectEqual(@as(u32, 1), policy.generation);
    try std.testing.expectEqualStrings(request.label, policy.labelSlice());
    try std.testing.expectEqualStrings("", policy.signature.signer);
    try std.testing.expect(policy.allowsInstallSource("store:organization"));
    try std.testing.expect(policy.allowsNetworkDestination("lan.example"));
    try std.testing.expect(policy.allowsSyncDestination("local:archive"));
    try std.testing.expect(directory.verify(policy.id));
    try std.testing.expectError(error.PolicyAlreadyAttached, directory.attachInitialAuthenticated(request, signature, issuer_key));
    try std.testing.expectEqual(@as(usize, 1), directory.count());
}

test "policy directory resolves policy slots by id and scope through a full table" {
    var directory = Directory.init();
    const subject_id: u64 = 0xCAFE;
    const signer = signing.SignerIdentity{
        .label = "full-policy-table-key",
        .seed = signing.seedFromByte(0x64),
    };

    var first_policy_id: u64 = 0;
    var policy_index: usize = 0;
    while (policy_index < MAX_POLICIES) : (policy_index += 1) {
        var label_buffer: [32]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buffer, "indexed-policy-{d}", .{policy_index});
        const policy = try directory.create(.{
            .scope = .workspace,
            .subject_id = subject_id,
            .issuer = .{ .kind = .policy_authority, .serial = 44 },
            .label = label,
            .screen_capture_allowed = policy_index % 2 == 0,
        }, signer);
        if (policy_index == 0) first_policy_id = policy.id;
        try std.testing.expectEqual(@as(u64, @intCast(policy_index + 1)), policy.id);
        try std.testing.expect(directory.verify(policy.id));
    }

    const active = directory.activeForScope(.workspace, subject_id) orelse return error.TestExpectedPolicy;
    try std.testing.expectEqual(@as(u32, @intCast(MAX_POLICIES)), active.generation);

    try std.testing.expectError(error.PolicyTableFull, directory.create(.{
        .scope = .workspace,
        .subject_id = subject_id + 1,
        .issuer = .{ .kind = .policy_authority, .serial = 45 },
        .label = "overflow-policy",
    }, signer));

    try directory.revokePolicy(first_policy_id);
    try std.testing.expectError(error.PolicyAlreadyRevoked, directory.revokePolicy(first_policy_id));
    const revoked_count = directory.revokePoliciesForScope(.workspace, subject_id);
    try std.testing.expectEqual(@as(usize, MAX_POLICIES - 1), revoked_count);
    try std.testing.expect(directory.activeForScope(.workspace, subject_id) == null);
    try std.testing.expectEqual(@as(usize, DIRECTORY_SIZE_CEILING_BYTES), @sizeOf(Directory));
}

test "policy digest golden vector pins the signed control encoding" {
    const request = CreateRequest{
        .scope = .workspace,
        .subject_id = 0x5157_4F52_4B53_5041,
        .issuer = .{ .kind = .policy_authority, .serial = 0x4F52_4741 },
        .label = "golden-policy",
        .allowed_install_sources = &.{ "store:zigos", "repo:golden" },
        .allowed_network_destinations = &.{"lan.golden"},
        .allowed_sync_destinations = &.{ "relay.golden", "local:archive", "overlay.golden" },
        .install_source_mode = .trusted_sources,
        .network_egress_mode = .allow_list,
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
        .clipboard_allowed = true,
        .camera_allowed = true,
        .microphone_allowed = true,
        .location_allowed = true,
        .contacts_allowed = true,
        .sensors_allowed = true,
        .peer_ipc_allowed = true,
        .remote_ai_allowed = true,
        .ai_training_allowed = true,
        .max_ai_context_bytes = 1014,
        .require_ai_model_measurement = true,
        .require_trusted_ai_model_source = true,
        .max_ai_model_age_days = 1017,
        .require_hardware_backed_session = true,
        .require_platform_backed_device_session = true,
        .require_primary_device_session = true,
        .max_session_unlock_age_ticks = 1021,
        .require_package_sbom = true,
        .require_reproducible_package_build = true,
        .require_trusted_package_builder = true,
        .require_vulnerability_scan = true,
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 1027,
        .max_agent_remote_calls_per_session = 1028,
        .require_agent_user_confirmation = false,
        .require_agent_audit = false,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 1033,
        .min_agent_delegation_generation = 1034,
        .require_agent_visible_plan = true,
        .max_remote_private_egress_bytes = 1036,
        .data_export_allowed = true,
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = true,
        .max_data_export_bytes = 1040,
        .object_backup_allowed = true,
        .object_restore_allowed = true,
        .require_encrypted_object_backup = false,
        .require_backup_recovery_key = false,
        .require_restore_device_trust = false,
        .max_object_backup_bytes = 1046,
        .max_object_restore_age_days = 1047,
        .semantic_memory_allowed = true,
        .require_local_semantic_model = false,
        .require_encrypted_semantic_index = false,
        .require_redacted_semantic_snippets = false,
        .max_semantic_query_bytes = 1052,
        .credential_assertions_allowed = true,
        .deny_credential_password_fallback = false,
        .require_phishing_resistant_credential = false,
        .require_hardware_backed_credential = true,
        .require_local_credential_unlock = false,
        .max_credential_unlock_age_ticks = 1058,
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = false,
        .deny_secret_raw_export = false,
        .max_secret_handle_lease_ticks = 1062,
        .task_lifecycle_allowed = true,
        .require_lifecycle_checkpoint_before_terminate = false,
        .quiet_until_tick = 1065,
        .max_visible_notifications = 1066,
        .max_interruptive_notifications = 1067,
        .allow_critical_interruption = false,
        .require_adaptive_ui = true,
        .require_screen_reader_support = true,
        .require_keyboard_navigation = true,
        .require_reduced_motion_support = true,
        .require_high_contrast_support = true,
        .max_background_duration_seconds = 1074,
        .max_background_cpu_time_ticks = 1075,
        .max_background_memory_bytes = 1076,
        .max_background_shared_memory_bytes = 1077,
        .allow_remote_background_network = true,
        .require_visible_background_activity = true,
        .max_sensitive_retention_days = 1080,
        .max_permission_lease_ticks = 1081,
        .require_sensitive_permission_lease = true,
        .require_sensitive_capture_foreground = false,
        .require_capture_indicator = false,
        .allow_background_capture = true,
        .max_sensitive_capture_lease_ticks = 1086,
        .max_sensitive_capture_samples = 1087,
        .retention_days = 1088,
        .audit_export_required = true,
    };
    const golden = [_]u8{
        0x8f, 0x43, 0x26, 0x0c, 0x36, 0xa6, 0x89, 0x8b, 0x64, 0xad, 0x7e, 0xfd, 0x19, 0x57, 0x5d, 0x8f,
        0x4e, 0x52, 0x83, 0x9f, 0x0e, 0xfe, 0x5c, 0x10, 0x01, 0x70, 0xa9, 0x37, 0x43, 0xc3, 0xc8, 0x7d,
    };
    try std.testing.expectEqualSlices(u8, &golden, &(try requestDigest(request)));
}
