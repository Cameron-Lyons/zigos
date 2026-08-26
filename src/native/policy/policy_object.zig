const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const model = @import("policy_object_model.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_ALLOW_LIST = model.MAX_ALLOW_LIST;
pub const MAX_LABEL_BYTES = model.MAX_LABEL_BYTES;
pub const COMPACT_POLICY_METADATA = model.COMPACT_POLICY_METADATA;
pub const DERIVES_POLICY_IDS_FROM_ARENA_COUNT = true;
pub const POLICY_OBJECT_SIZE_CEILING_BYTES = model.POLICY_OBJECT_SIZE_CEILING_BYTES;
pub const DIRECTORY_SIZE_CEILING_BYTES: usize = 33_232;
const POLICY_INDEX_CAPACITY: usize = MAX_POLICIES * 2;

pub const Scope = model.Scope;
pub const InstallSourceMode = model.InstallSourceMode;
pub const NetworkEgressMode = model.NetworkEgressMode;
pub const SubjectSet = model.SubjectSet;
pub const DecisionReason = model.DecisionReason;
pub const PolicyDecision = model.PolicyDecision;
pub const CreateRequest = model.CreateRequest;
pub const RetentionAuditRequest = model.RetentionAuditRequest;
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

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyObject = zeroPolicy(),
};

fn policySlotId(slot: *const PolicySlot) u64 {
    return slot.policy.id;
}

const PolicyArena = indexed_arena.IndexedArena(PolicySlot, MAX_POLICIES, POLICY_INDEX_CAPACITY, policySlotId);
const PolicyScopeIndex = indexed_arena.MultimapIndex(MAX_POLICIES, MAX_POLICIES, POLICY_INDEX_CAPACITY);

pub const Directory = struct {
    policies: PolicyArena = PolicyArena.init(),
    scope_index: PolicyScopeIndex = PolicyScopeIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn create(
        self: *Directory,
        request: CreateRequest,
        signer: signing.SignerIdentity,
    ) (Error || anyerror)!*PolicyObject {
        if (request.allowed_install_sources.len > MAX_ALLOW_LIST) return error.TooManyInstallSources;
        if (request.allowed_network_destinations.len > MAX_ALLOW_LIST) return error.TooManyNetworkDestinations;
        if (request.allowed_sync_destinations.len > MAX_ALLOW_LIST) return error.TooManySyncDestinations;

        const policy_count = self.policies.countInUse();
        if (policy_count >= MAX_POLICIES) return error.PolicyTableFull;

        const policy_id: u64 = @intCast(policy_count + 1);
        var policy = zeroPolicy();
        policy.id = policy_id;
        policy.generation = nextGeneration(self, request.scope, request.subject_id);
        policy.scope = request.scope;
        policy.subject_id = request.subject_id;
        policy.issuer = request.issuer;
        policy.label_len = @intCast(native_util.copyTextExact(&policy.label, request.label) catch return error.LabelTooLong);
        policy.install_source_mode = request.install_source_mode;
        policy.network_egress_mode = request.network_egress_mode;
        policy.removable_storage_allowed = request.removable_storage_allowed;
        policy.screen_capture_allowed = request.screen_capture_allowed;
        policy.clipboard_allowed = request.clipboard_allowed;
        policy.camera_allowed = request.camera_allowed;
        policy.microphone_allowed = request.microphone_allowed;
        policy.location_allowed = request.location_allowed;
        policy.contacts_allowed = request.contacts_allowed;
        policy.sensors_allowed = request.sensors_allowed;
        policy.peer_ipc_allowed = request.peer_ipc_allowed;
        policy.remote_ai_allowed = request.remote_ai_allowed;
        policy.ai_training_allowed = request.ai_training_allowed;
        policy.max_ai_context_bytes = request.max_ai_context_bytes;
        policy.require_ai_model_measurement = request.require_ai_model_measurement;
        policy.require_trusted_ai_model_source = request.require_trusted_ai_model_source;
        policy.max_ai_model_age_days = request.max_ai_model_age_days;
        policy.require_hardware_backed_session = request.require_hardware_backed_session;
        policy.require_platform_backed_device_session = request.require_platform_backed_device_session;
        policy.require_primary_device_session = request.require_primary_device_session;
        policy.max_session_unlock_age_ticks = request.max_session_unlock_age_ticks;
        policy.require_package_sbom = request.require_package_sbom;
        policy.require_reproducible_package_build = request.require_reproducible_package_build;
        policy.require_trusted_package_builder = request.require_trusted_package_builder;
        policy.require_vulnerability_scan = request.require_vulnerability_scan;
        policy.agent_delegation_allowed = request.agent_delegation_allowed;
        policy.max_agent_actions_per_session = request.max_agent_actions_per_session;
        policy.max_agent_remote_calls_per_session = request.max_agent_remote_calls_per_session;
        policy.require_agent_user_confirmation = request.require_agent_user_confirmation;
        policy.require_agent_audit = request.require_agent_audit;
        policy.require_agent_session_binding = request.require_agent_session_binding;
        policy.require_agent_local_context = request.require_agent_local_context;
        policy.max_agent_context_bytes = request.max_agent_context_bytes;
        policy.min_agent_delegation_generation = request.min_agent_delegation_generation;
        policy.require_agent_visible_plan = request.require_agent_visible_plan;
        policy.max_remote_private_egress_bytes = request.max_remote_private_egress_bytes;
        policy.data_export_allowed = request.data_export_allowed;
        policy.data_deletion_allowed = request.data_deletion_allowed;
        policy.require_data_deletion_receipt = request.require_data_deletion_receipt;
        policy.max_data_export_bytes = request.max_data_export_bytes;
        policy.object_backup_allowed = request.object_backup_allowed;
        policy.object_restore_allowed = request.object_restore_allowed;
        policy.require_encrypted_object_backup = request.require_encrypted_object_backup;
        policy.require_backup_recovery_key = request.require_backup_recovery_key;
        policy.require_restore_device_trust = request.require_restore_device_trust;
        policy.max_object_backup_bytes = request.max_object_backup_bytes;
        policy.max_object_restore_age_days = request.max_object_restore_age_days;
        policy.semantic_memory_allowed = request.semantic_memory_allowed;
        policy.require_local_semantic_model = request.require_local_semantic_model;
        policy.require_encrypted_semantic_index = request.require_encrypted_semantic_index;
        policy.require_redacted_semantic_snippets = request.require_redacted_semantic_snippets;
        policy.max_semantic_query_bytes = request.max_semantic_query_bytes;
        policy.credential_assertions_allowed = request.credential_assertions_allowed;
        policy.deny_credential_password_fallback = request.deny_credential_password_fallback;
        policy.require_phishing_resistant_credential = request.require_phishing_resistant_credential;
        policy.require_hardware_backed_credential = request.require_hardware_backed_credential;
        policy.require_local_credential_unlock = request.require_local_credential_unlock;
        policy.max_credential_unlock_age_ticks = request.max_credential_unlock_age_ticks;
        policy.secret_vault_allowed = request.secret_vault_allowed;
        policy.require_hardware_backed_secrets = request.require_hardware_backed_secrets;
        policy.deny_secret_raw_export = request.deny_secret_raw_export;
        policy.max_secret_handle_lease_ticks = request.max_secret_handle_lease_ticks;
        policy.task_lifecycle_allowed = request.task_lifecycle_allowed;
        policy.require_lifecycle_checkpoint_before_terminate = request.require_lifecycle_checkpoint_before_terminate;
        policy.quiet_until_tick = request.quiet_until_tick;
        policy.max_visible_notifications = request.max_visible_notifications;
        policy.max_interruptive_notifications = request.max_interruptive_notifications;
        policy.allow_critical_interruption = request.allow_critical_interruption;
        policy.require_adaptive_ui = request.require_adaptive_ui;
        policy.require_screen_reader_support = request.require_screen_reader_support;
        policy.require_keyboard_navigation = request.require_keyboard_navigation;
        policy.require_reduced_motion_support = request.require_reduced_motion_support;
        policy.require_high_contrast_support = request.require_high_contrast_support;
        policy.max_background_duration_seconds = request.max_background_duration_seconds;
        policy.max_background_cpu_time_ticks = request.max_background_cpu_time_ticks;
        policy.max_background_memory_bytes = request.max_background_memory_bytes;
        policy.max_background_shared_memory_bytes = request.max_background_shared_memory_bytes;
        policy.allow_remote_background_network = request.allow_remote_background_network;
        policy.require_visible_background_activity = request.require_visible_background_activity;
        policy.max_sensitive_retention_days = request.max_sensitive_retention_days;
        policy.max_permission_lease_ticks = request.max_permission_lease_ticks;
        policy.require_sensitive_permission_lease = request.require_sensitive_permission_lease;
        policy.require_sensitive_capture_foreground = request.require_sensitive_capture_foreground;
        policy.require_capture_indicator = request.require_capture_indicator;
        policy.allow_background_capture = request.allow_background_capture;
        policy.max_sensitive_capture_lease_ticks = request.max_sensitive_capture_lease_ticks;
        policy.max_sensitive_capture_samples = request.max_sensitive_capture_samples;
        policy.retention_days = request.retention_days;
        policy.audit_export_required = request.audit_export_required;

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

        const digest = policyDigest(&policy);
        policy.signature = try signing.sign(signer, &digest);
        const slot_index = self.policies.reserveIndex(policy_id) orelse
            native_util.impossibleByInvariant("prechecked policy slot reservation must succeed");
        const slot = &self.policies.slots[slot_index];
        slot.policy = policy;
        self.indexPolicy(slot_index);
        return &slot.policy;
    }

    pub fn activeForScope(self: *Directory, scope: Scope, subject_id: u64) ?*PolicyObject {
        var candidate: ?*PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.policies.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    pub fn verify(self: *const Directory, policy_id: u64) bool {
        const policy = self.findConst(policy_id) orelse return false;
        const digest = policyDigest(policy);
        return signing.verify(policy.signature, &digest);
    }

    pub fn revokePolicy(self: *Directory, policy_id: u64) Error!void {
        const slot = self.policies.get(policy_id) orelse return error.PolicyNotFound;
        if (slot.policy.id != policy_id) native_util.impossibleByInvariant("policy id index points at the wrong policy");
        if (slot.policy.revoked) return error.PolicyAlreadyRevoked;
        slot.policy.revoked = true;
    }

    pub fn revokePoliciesForScope(self: *Directory, scope: Scope, subject_id: u64) usize {
        var revoked_count: usize = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.policies.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            slot.policy.revoked = true;
            revoked_count += 1;
        }
        return revoked_count;
    }

    pub fn installSourceAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        source_identity: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsInstallSource(source_identity);
    }

    pub fn syncDestinationAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        destination: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsSyncDestination(destination);
    }

    pub fn installSourceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        source_identity: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsInstallSource(source_identity)) {
                return block(policy, .install_source_denied);
            }
        }
        return allow();
    }

    pub fn packageProvenanceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: PackageProvenanceRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.packageProvenanceDenial(request)) |reason| return block(policy, reason);
        }
        return allow();
    }

    pub fn agentDelegationDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: AgentDelegationRequest,
    ) PolicyDecision {
        if (!request.enabled) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.agent_delegation_allowed) return block(policy, .agent_delegation_denied);
            if (policy.max_agent_actions_per_session != 0 and request.autonomous_actions > policy.max_agent_actions_per_session) {
                return block(policy, .agent_action_budget_denied);
            }
            if (policy.max_agent_remote_calls_per_session != 0 and request.remote_calls > policy.max_agent_remote_calls_per_session) {
                return block(policy, .agent_remote_call_denied);
            }
            if (request.remote_calls != 0 and policy.require_agent_user_confirmation and !request.user_confirmed) {
                return block(policy, .agent_confirmation_required);
            }
            if (policy.require_agent_audit and !request.audit_enabled) {
                return block(policy, .agent_audit_required);
            }
            if (policy.require_agent_session_binding and !request.session_bound) {
                return block(policy, .agent_session_binding_denied);
            }
            if (policy.require_agent_local_context and !request.local_context_only) {
                return block(policy, .agent_context_scope_denied);
            }
            if (policy.max_agent_context_bytes != 0 and request.context_bytes > policy.max_agent_context_bytes) {
                return block(policy, .agent_context_budget_denied);
            }
            if (request.delegation_generation < policy.min_agent_delegation_generation) {
                return block(policy, .agent_kill_switch_denied);
            }
            if (policy.require_agent_visible_plan and !request.user_visible_plan) {
                return block(policy, .agent_plan_visibility_required);
            }
        }
        return allow();
    }

    pub fn syncDestinationDecision(
        self: *const Directory,
        subjects: SubjectSet,
        destination: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsSyncDestination(destination)) {
                return block(policy, .sync_destination_denied);
            }
        }
        return allow();
    }

    pub fn networkEgressDecision(
        self: *const Directory,
        subjects: SubjectSet,
        destination: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsNetworkDestination(destination)) {
                return block(policy, .network_egress_denied);
            }
        }
        return allow();
    }

    pub fn removableStorageDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.removable_storage_allowed) return block(policy, .removable_storage_denied);
        }
        return allow();
    }

    pub fn screenCaptureDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.screen_capture_allowed) return block(policy, .screen_capture_denied);
        }
        return allow();
    }

    pub fn permissionKindDecision(
        self: *const Directory,
        subjects: SubjectSet,
        kind: manifest.PermissionKind,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policyAllowsPermissionKind(policy, kind)) {
                return block(policy, permissionKindDenialReason(kind));
            }
        }
        return allow();
    }

    pub fn aiUseDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: AiUseRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (request.remote_model and !policy.remote_ai_allowed) return block(policy, .remote_ai_denied);
            if (request.training_user_content and !policy.ai_training_allowed) return block(policy, .ai_training_denied);
            if (policy.max_ai_context_bytes != 0 and request.context_bytes > policy.max_ai_context_bytes) {
                return block(policy, .ai_context_denied);
            }
            if (!request.remote_model and policy.require_ai_model_measurement and !request.local_model_measured) {
                return block(policy, .ai_model_measurement_denied);
            }
            if (!request.remote_model and policy.require_trusted_ai_model_source and !request.model_source_trusted) {
                return block(policy, .ai_model_source_denied);
            }
            if (!request.remote_model and policy.max_ai_model_age_days != 0 and request.model_age_days > policy.max_ai_model_age_days) {
                return block(policy, .ai_model_staleness_denied);
            }
        }
        return allow();
    }

    pub fn sessionTrustDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SessionTrustRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.require_hardware_backed_session and !request.hardware_backed_credential) {
                return block(policy, .session_hardware_denied);
            }
            if (policy.require_platform_backed_device_session and !request.device_platform_backed) {
                return block(policy, .session_device_posture_denied);
            }
            if (policy.require_primary_device_session and !request.primary_device_assertion) {
                return block(policy, .session_primary_device_denied);
            }
            if (policy.max_session_unlock_age_ticks != 0 and request.unlock_age_ticks > policy.max_session_unlock_age_ticks) {
                return block(policy, .session_unlock_stale);
            }
        }
        return allow();
    }

    pub fn sensitiveEgressDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SensitiveEgressRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.max_remote_private_egress_bytes != 0 and request.remote_bytes > policy.max_remote_private_egress_bytes) {
                return block(policy, .private_egress_budget_denied);
            }
        }
        return allow();
    }

    pub fn dataRightsDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: DataRightsRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            switch (request.operation) {
                .portable_export => {
                    if (!policy.data_export_allowed) return block(policy, .data_export_denied);
                    if (policy.max_data_export_bytes != 0 and request.bytes > policy.max_data_export_bytes) {
                        return block(policy, .data_export_denied);
                    }
                },
                .delete => {
                    if (!policy.data_deletion_allowed) return block(policy, .data_deletion_denied);
                    if (policy.require_data_deletion_receipt and !request.deletion_receipt_present) {
                        return block(policy, .data_deletion_receipt_denied);
                    }
                },
            }
        }
        return allow();
    }

    pub fn objectResilienceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: ObjectResilienceRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            switch (request.operation) {
                .backup => {
                    if (!policy.object_backup_allowed) return block(policy, .object_backup_denied);
                    if (policy.require_encrypted_object_backup and !request.encrypted) {
                        return block(policy, .object_backup_encryption_denied);
                    }
                    if (policy.require_backup_recovery_key and !request.recovery_key_present) {
                        return block(policy, .object_backup_recovery_key_denied);
                    }
                    if (policy.max_object_backup_bytes != 0 and request.bytes > policy.max_object_backup_bytes) {
                        return block(policy, .object_backup_size_denied);
                    }
                },
                .restore, .migrate => {
                    if (!policy.object_restore_allowed) return block(policy, .object_restore_denied);
                    if (policy.require_restore_device_trust and !request.device_trust_verified) {
                        return block(policy, .object_restore_device_trust_denied);
                    }
                    if (policy.max_object_restore_age_days != 0 and request.restore_age_days > policy.max_object_restore_age_days) {
                        return block(policy, .object_restore_staleness_denied);
                    }
                },
            }
        }
        return allow();
    }

    pub fn semanticMemoryDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SemanticMemoryRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.semantic_memory_allowed) return block(policy, .semantic_memory_denied);
            if (policy.require_local_semantic_model and !request.local_model) {
                return block(policy, .semantic_memory_remote_model_denied);
            }
            if (policy.require_encrypted_semantic_index and !request.encrypted_index) {
                return block(policy, .semantic_memory_encryption_denied);
            }
            if (policy.require_redacted_semantic_snippets and !request.redacted_snippets) {
                return block(policy, .semantic_memory_redaction_denied);
            }
            if (policy.max_semantic_query_bytes != 0 and request.query_bytes > policy.max_semantic_query_bytes) {
                return block(policy, .semantic_query_budget_denied);
            }
        }
        return allow();
    }

    pub fn credentialAssertionDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: CredentialAssertionRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.credential_assertions_allowed) return block(policy, .credential_assertion_denied);
            if (policy.deny_credential_password_fallback and request.password_fallback) {
                return block(policy, .credential_password_fallback_denied);
            }
            if (policy.require_phishing_resistant_credential and !request.phishing_resistant) {
                return block(policy, .credential_phishing_resistance_denied);
            }
            if (policy.require_hardware_backed_credential and !request.hardware_backed) {
                return block(policy, .credential_hardware_denied);
            }
            if (policy.require_local_credential_unlock and !request.local_unlock_verified) {
                return block(policy, .credential_unlock_denied);
            }
            if (policy.max_credential_unlock_age_ticks != 0 and request.unlock_age_ticks > policy.max_credential_unlock_age_ticks) {
                return block(policy, .credential_unlock_stale);
            }
        }
        return allow();
    }

    pub fn secretVaultDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SecretVaultRequest,
    ) PolicyDecision {
        if (request.operation == .revoke) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.secret_vault_allowed) return block(policy, .secret_vault_denied);
            if (policy.require_hardware_backed_secrets and !request.hardware_backed) {
                return block(policy, .secret_hardware_denied);
            }
            if (policy.deny_secret_raw_export and request.raw_export) {
                return block(policy, .secret_raw_export_denied);
            }
            if (policy.max_secret_handle_lease_ticks != 0 and request.lease_ticks > policy.max_secret_handle_lease_ticks) {
                return block(policy, .secret_lease_denied);
            }
        }
        return allow();
    }

    pub fn lifecycleDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: LifecycleRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.task_lifecycle_allowed) return block(policy, .task_lifecycle_denied);
            if (request.operation == .terminate_task and
                policy.require_lifecycle_checkpoint_before_terminate and
                !request.checkpoint_present)
            {
                return block(policy, .task_lifecycle_checkpoint_required);
            }
        }
        return allow();
    }

    pub fn attentionDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: AttentionRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (request.critical and !policy.allow_critical_interruption) {
                return block(policy, .attention_critical_denied);
            }
            if (request.requests_interruption and
                !request.critical and
                policy.quiet_until_tick != 0 and
                request.now_tick < policy.quiet_until_tick)
            {
                return block(policy, .attention_quiet_denied);
            }
            if (policy.max_visible_notifications != 0 and
                request.visible_notifications >= policy.max_visible_notifications)
            {
                return block(policy, .attention_visible_budget_denied);
            }
            if (request.requests_interruption and
                policy.max_interruptive_notifications != 0 and
                request.interruptive_notifications >= policy.max_interruptive_notifications)
            {
                return block(policy, .attention_interruption_budget_denied);
            }
        }
        return allow();
    }

    pub fn accessibilityDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: AccessibilityRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.require_adaptive_ui and !request.adaptive_ui) return block(policy, .accessibility_adaptive_ui_denied);
            if (policy.require_screen_reader_support and !request.screen_reader_supported) return block(policy, .accessibility_screen_reader_denied);
            if (policy.require_keyboard_navigation and !request.keyboard_navigation) return block(policy, .accessibility_keyboard_navigation_denied);
            if (policy.require_reduced_motion_support and !request.reduced_motion_supported) return block(policy, .accessibility_reduced_motion_denied);
            if (policy.require_high_contrast_support and !request.high_contrast_supported) return block(policy, .accessibility_high_contrast_denied);
        }
        return allow();
    }

    pub fn backgroundActivityDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: BackgroundActivityRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.max_background_duration_seconds != 0 and
                request.expected_duration_seconds > policy.max_background_duration_seconds)
            {
                return block(policy, .background_duration_denied);
            }
            if (policy.max_background_cpu_time_ticks != 0 and
                request.cpu_time_ticks > policy.max_background_cpu_time_ticks)
            {
                return block(policy, .background_cpu_denied);
            }
            if ((policy.max_background_memory_bytes != 0 and request.memory_bytes > policy.max_background_memory_bytes) or
                (policy.max_background_shared_memory_bytes != 0 and request.shared_memory_bytes > policy.max_background_shared_memory_bytes))
            {
                return block(policy, .background_memory_denied);
            }
            if (!policy.allow_remote_background_network and backgroundNetworkIsRemote(request.network)) {
                return block(policy, .background_network_denied);
            }
            if (policy.require_visible_background_activity and !backgroundActivityIsVisible(request.visibility)) {
                return block(policy, .background_visibility_denied);
            }
        }
        return allow();
    }

    pub fn permissionUseDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: PermissionUseRequest,
    ) PolicyDecision {
        if (!manifest.isSensitive(request.sensitivity)) return allow();
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.max_sensitive_retention_days != 0 and request.retention_days > policy.max_sensitive_retention_days) {
                return block(policy, .permission_retention_denied);
            }
            if (manifest.dangerousPermissionKind(request.kind) and
                policy.require_sensitive_permission_lease and
                request.lease_ticks == 0)
            {
                return block(policy, .permission_lease_denied);
            }
            if (manifest.dangerousPermissionKind(request.kind) and
                policy.max_permission_lease_ticks != 0 and
                request.lease_ticks > policy.max_permission_lease_ticks)
            {
                return block(policy, .permission_lease_denied);
            }
        }
        return allow();
    }

    pub fn sensitiveCaptureDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: SensitiveCaptureRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policyAllowsPermissionKind(policy, request.kind)) {
                return block(policy, permissionKindDenialReason(request.kind));
            }
            if (policy.require_sensitive_capture_foreground and !request.foreground_session) {
                return block(policy, .capture_foreground_denied);
            }
            if (policy.require_capture_indicator and !request.visible_indicator) {
                return block(policy, .capture_indicator_denied);
            }
            if (!policy.allow_background_capture and request.background) {
                return block(policy, .capture_background_denied);
            }
            if (policy.max_sensitive_capture_lease_ticks != 0 and request.lease_ticks > policy.max_sensitive_capture_lease_ticks) {
                return block(policy, .capture_lease_denied);
            }
            if (policy.max_sensitive_capture_samples != 0 and request.sample_budget > policy.max_sensitive_capture_samples) {
                return block(policy, .capture_sample_budget_denied);
            }
        }
        return allow();
    }

    pub fn retentionAuditDecision(
        self: *const Directory,
        subjects: SubjectSet,
        request: RetentionAuditRequest,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (policy.retention_days != 0 and request.retention_days > policy.retention_days) {
                return block(policy, .retention_denied);
            }
            if (policy.audit_export_required and !request.audit_export_present) {
                return block(policy, .audit_export_required);
            }
        }
        return allow();
    }

    fn findConst(self: *const Directory, policy_id: u64) ?*const PolicyObject {
        if (policy_id == 0) return null;
        const slot = self.policies.getConst(policy_id) orelse return null;
        if (slot.policy.id != policy_id) native_util.impossibleByInvariant("policy id index points at the wrong policy");
        return &slot.policy;
    }

    fn activeForScopeConst(self: *const Directory, scope: Scope, subject_id: u64) ?*const PolicyObject {
        var candidate: ?*const PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.policies.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.revoked) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    fn activePolicyIterator(self: *const Directory, subjects: SubjectSet) ActivePolicyIterator {
        return .{
            .directory = self,
            .subjects = subjects,
        };
    }

    fn requireVerified(self: *const Directory, policy: *const PolicyObject) PolicyDecision {
        if (self.verify(policy.id)) return allow();
        return block(policy, .unsigned_policy);
    }

    fn indexPolicy(self: *Directory, slot_index: usize) void {
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy index update points outside slots");
        const slot = &self.policies.slots[slot_index];
        const policy = &slot.policy;
        if (!slot.in_use or policy.id == 0) native_util.impossibleByInvariant("policy index update requires a live policy");
        if (!self.scope_index.append(policyScopeKey(policy.scope, policy.subject_id), slot_index)) {
            native_util.impossibleByInvariant("policy scope index capacity covers policy slots");
        }
    }

    comptime {
        if (@sizeOf(@This()) > DIRECTORY_SIZE_CEILING_BYTES) {
            @compileError("policy directory exceeds its compact size ceiling");
        }
    }
};

const ActivePolicyIterator = struct {
    directory: *const Directory,
    subjects: SubjectSet,
    index: usize = 0,

    fn next(self: *ActivePolicyIterator) ?*const PolicyObject {
        while (self.index < 4) {
            const index = self.index;
            self.index += 1;
            switch (index) {
                0 => if (self.subjects.organization_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.organization, subject_id)) |policy| return policy;
                },
                1 => if (self.subjects.user_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.user, subject_id)) |policy| return policy;
                },
                2 => if (self.subjects.device_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.device, subject_id)) |policy| return policy;
                },
                3 => if (self.subjects.workspace_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.workspace, subject_id)) |policy| return policy;
                },
                else => {},
            }
        }
        return null;
    }
};

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

fn policyAllowsPermissionKind(policy: *const PolicyObject, kind: manifest.PermissionKind) bool {
    return switch (kind) {
        .clipboard => policy.clipboard_allowed,
        .camera => policy.camera_allowed,
        .mic => policy.microphone_allowed,
        .location => policy.location_allowed,
        .contacts => policy.contacts_allowed,
        .sensor => policy.sensors_allowed,
        .screen_capture => policy.screen_capture_allowed,
        .peer_ipc => policy.peer_ipc_allowed,
        else => true,
    };
}

fn permissionKindDenialReason(kind: manifest.PermissionKind) DecisionReason {
    return switch (kind) {
        .clipboard => .clipboard_denied,
        .camera => .camera_denied,
        .mic => .microphone_denied,
        .location => .location_denied,
        .contacts => .contacts_denied,
        .sensor => .sensor_denied,
        .screen_capture => .screen_capture_denied,
        .peer_ipc => .peer_ipc_denied,
        else => .none,
    };
}

fn zeroPolicy() PolicyObject {
    return .{
        .id = 0,
        .generation = 0,
        .revoked = false,
        .scope = .user,
        .subject_id = 0,
        .issuer = .{ .kind = .policy_authority, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .install_source_mode = .any_signed,
        .allowed_install_source_count = 0,
        .allowed_install_sources = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_install_source_lens = [_]u8{0} ** MAX_ALLOW_LIST,
        .network_egress_mode = .inherit,
        .allowed_network_destination_count = 0,
        .allowed_network_destinations = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_network_destination_lens = [_]u8{0} ** MAX_ALLOW_LIST,
        .allowed_sync_destination_count = 0,
        .allowed_sync_destinations = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_sync_destination_lens = [_]u8{0} ** MAX_ALLOW_LIST,
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .clipboard_allowed = false,
        .camera_allowed = false,
        .microphone_allowed = false,
        .location_allowed = false,
        .contacts_allowed = false,
        .sensors_allowed = false,
        .peer_ipc_allowed = false,
        .remote_ai_allowed = false,
        .ai_training_allowed = false,
        .max_ai_context_bytes = 0,
        .require_ai_model_measurement = false,
        .require_trusted_ai_model_source = false,
        .max_ai_model_age_days = 0,
        .require_hardware_backed_session = false,
        .require_platform_backed_device_session = false,
        .require_primary_device_session = false,
        .max_session_unlock_age_ticks = 0,
        .require_package_sbom = false,
        .require_reproducible_package_build = false,
        .require_trusted_package_builder = false,
        .require_vulnerability_scan = false,
        .agent_delegation_allowed = false,
        .max_agent_actions_per_session = 0,
        .max_agent_remote_calls_per_session = 0,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = false,
        .require_agent_local_context = false,
        .max_agent_context_bytes = 0,
        .min_agent_delegation_generation = 0,
        .require_agent_visible_plan = false,
        .max_remote_private_egress_bytes = 0,
        .data_export_allowed = false,
        .data_deletion_allowed = false,
        .require_data_deletion_receipt = false,
        .max_data_export_bytes = 0,
        .object_backup_allowed = false,
        .object_restore_allowed = false,
        .require_encrypted_object_backup = true,
        .require_backup_recovery_key = true,
        .require_restore_device_trust = true,
        .max_object_backup_bytes = 0,
        .max_object_restore_age_days = 0,
        .semantic_memory_allowed = false,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 0,
        .credential_assertions_allowed = false,
        .deny_credential_password_fallback = true,
        .require_phishing_resistant_credential = true,
        .require_hardware_backed_credential = false,
        .require_local_credential_unlock = true,
        .max_credential_unlock_age_ticks = 0,
        .secret_vault_allowed = false,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = true,
        .max_secret_handle_lease_ticks = 0,
        .task_lifecycle_allowed = false,
        .require_lifecycle_checkpoint_before_terminate = true,
        .quiet_until_tick = 0,
        .max_visible_notifications = 0,
        .max_interruptive_notifications = 0,
        .allow_critical_interruption = true,
        .require_adaptive_ui = false,
        .require_screen_reader_support = false,
        .require_keyboard_navigation = false,
        .require_reduced_motion_support = false,
        .require_high_contrast_support = false,
        .max_background_duration_seconds = 0,
        .max_background_cpu_time_ticks = 0,
        .max_background_memory_bytes = 0,
        .max_background_shared_memory_bytes = 0,
        .allow_remote_background_network = false,
        .require_visible_background_activity = false,
        .max_sensitive_retention_days = 0,
        .max_permission_lease_ticks = 0,
        .require_sensitive_permission_lease = false,
        .require_sensitive_capture_foreground = true,
        .require_capture_indicator = true,
        .allow_background_capture = false,
        .max_sensitive_capture_lease_ticks = 0,
        .max_sensitive_capture_samples = 0,
        .retention_days = 0,
        .audit_export_required = false,
        .signature = .{},
    };
}

fn nextGeneration(self: *const Directory, scope: Scope, subject_id: u64) u32 {
    return latestGenerationForScope(self, scope, subject_id) + 1;
}

fn latestGenerationForScope(self: *const Directory, scope: Scope, subject_id: u64) u32 {
    var best_generation: u32 = 0;
    var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
    while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
        if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
        const slot = &self.policies.slots[cursor];
        if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
        if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
        if (slot.policy.generation > best_generation) best_generation = slot.policy.generation;
    }
    return best_generation;
}

fn policyScopeKey(scope: Scope, subject_id: u64) u64 {
    const subject_id_offset = @sizeOf(Scope);
    const policy_scope_key_bytes = subject_id_offset + @sizeOf(u64);
    var bytes: [policy_scope_key_bytes]u8 = undefined;
    bytes[0] = @intFromEnum(scope);
    std.mem.writeInt(u64, bytes[subject_id_offset..][0..@sizeOf(u64)], subject_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.policy_scope_key, &bytes));
}

fn policyDigest(policy: *const PolicyObject) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "scope", policy.scope);
    crypto_hash.updateEnum(&hasher, "issuer-kind", policy.issuer.kind);
    crypto_hash.updateInt(&hasher, "subject-id", policy.subject_id);
    crypto_hash.updateInt(&hasher, "issuer-serial", policy.issuer.serial);
    crypto_hash.updateBytes(&hasher, "label", policy.labelSlice());
    crypto_hash.updateEnum(&hasher, "install-source-mode", policy.install_source_mode);
    crypto_hash.updateEnum(&hasher, "network-egress-mode", policy.network_egress_mode);
    crypto_hash.updateBool(&hasher, "removable-storage-allowed", policy.removable_storage_allowed);
    crypto_hash.updateBool(&hasher, "screen-capture-allowed", policy.screen_capture_allowed);
    crypto_hash.updateBool(&hasher, "clipboard-allowed", policy.clipboard_allowed);
    crypto_hash.updateBool(&hasher, "camera-allowed", policy.camera_allowed);
    crypto_hash.updateBool(&hasher, "microphone-allowed", policy.microphone_allowed);
    crypto_hash.updateBool(&hasher, "location-allowed", policy.location_allowed);
    crypto_hash.updateBool(&hasher, "contacts-allowed", policy.contacts_allowed);
    crypto_hash.updateBool(&hasher, "sensors-allowed", policy.sensors_allowed);
    crypto_hash.updateBool(&hasher, "peer-ipc-allowed", policy.peer_ipc_allowed);
    crypto_hash.updateBool(&hasher, "remote-ai-allowed", policy.remote_ai_allowed);
    crypto_hash.updateBool(&hasher, "ai-training-allowed", policy.ai_training_allowed);
    crypto_hash.updateInt(&hasher, "max-ai-context-bytes", policy.max_ai_context_bytes);
    crypto_hash.updateBool(&hasher, "require-ai-model-measurement", policy.require_ai_model_measurement);
    crypto_hash.updateBool(&hasher, "require-trusted-ai-model-source", policy.require_trusted_ai_model_source);
    crypto_hash.updateInt(&hasher, "max-ai-model-age-days", policy.max_ai_model_age_days);
    crypto_hash.updateBool(&hasher, "require-hardware-backed-session", policy.require_hardware_backed_session);
    crypto_hash.updateBool(&hasher, "require-platform-backed-device-session", policy.require_platform_backed_device_session);
    crypto_hash.updateBool(&hasher, "require-primary-device-session", policy.require_primary_device_session);
    crypto_hash.updateInt(&hasher, "max-session-unlock-age-ticks", policy.max_session_unlock_age_ticks);
    crypto_hash.updateBool(&hasher, "require-package-sbom", policy.require_package_sbom);
    crypto_hash.updateBool(&hasher, "require-reproducible-package-build", policy.require_reproducible_package_build);
    crypto_hash.updateBool(&hasher, "require-trusted-package-builder", policy.require_trusted_package_builder);
    crypto_hash.updateBool(&hasher, "require-vulnerability-scan", policy.require_vulnerability_scan);
    crypto_hash.updateBool(&hasher, "agent-delegation-allowed", policy.agent_delegation_allowed);
    crypto_hash.updateInt(&hasher, "max-agent-actions-per-session", policy.max_agent_actions_per_session);
    crypto_hash.updateInt(&hasher, "max-agent-remote-calls-per-session", policy.max_agent_remote_calls_per_session);
    crypto_hash.updateBool(&hasher, "require-agent-user-confirmation", policy.require_agent_user_confirmation);
    crypto_hash.updateBool(&hasher, "require-agent-audit", policy.require_agent_audit);
    crypto_hash.updateBool(&hasher, "require-agent-session-binding", policy.require_agent_session_binding);
    crypto_hash.updateBool(&hasher, "require-agent-local-context", policy.require_agent_local_context);
    crypto_hash.updateInt(&hasher, "max-agent-context-bytes", policy.max_agent_context_bytes);
    crypto_hash.updateInt(&hasher, "min-agent-delegation-generation", policy.min_agent_delegation_generation);
    crypto_hash.updateBool(&hasher, "require-agent-visible-plan", policy.require_agent_visible_plan);
    crypto_hash.updateInt(&hasher, "max-remote-private-egress-bytes", policy.max_remote_private_egress_bytes);
    crypto_hash.updateBool(&hasher, "data-export-allowed", policy.data_export_allowed);
    crypto_hash.updateBool(&hasher, "data-deletion-allowed", policy.data_deletion_allowed);
    crypto_hash.updateBool(&hasher, "require-data-deletion-receipt", policy.require_data_deletion_receipt);
    crypto_hash.updateInt(&hasher, "max-data-export-bytes", policy.max_data_export_bytes);
    crypto_hash.updateBool(&hasher, "object-backup-allowed", policy.object_backup_allowed);
    crypto_hash.updateBool(&hasher, "object-restore-allowed", policy.object_restore_allowed);
    crypto_hash.updateBool(&hasher, "require-encrypted-object-backup", policy.require_encrypted_object_backup);
    crypto_hash.updateBool(&hasher, "require-backup-recovery-key", policy.require_backup_recovery_key);
    crypto_hash.updateBool(&hasher, "require-restore-device-trust", policy.require_restore_device_trust);
    crypto_hash.updateInt(&hasher, "max-object-backup-bytes", policy.max_object_backup_bytes);
    crypto_hash.updateInt(&hasher, "max-object-restore-age-days", policy.max_object_restore_age_days);
    crypto_hash.updateBool(&hasher, "semantic-memory-allowed", policy.semantic_memory_allowed);
    crypto_hash.updateBool(&hasher, "require-local-semantic-model", policy.require_local_semantic_model);
    crypto_hash.updateBool(&hasher, "require-encrypted-semantic-index", policy.require_encrypted_semantic_index);
    crypto_hash.updateBool(&hasher, "require-redacted-semantic-snippets", policy.require_redacted_semantic_snippets);
    crypto_hash.updateInt(&hasher, "max-semantic-query-bytes", policy.max_semantic_query_bytes);
    crypto_hash.updateBool(&hasher, "credential-assertions-allowed", policy.credential_assertions_allowed);
    crypto_hash.updateBool(&hasher, "deny-credential-password-fallback", policy.deny_credential_password_fallback);
    crypto_hash.updateBool(&hasher, "require-phishing-resistant-credential", policy.require_phishing_resistant_credential);
    crypto_hash.updateBool(&hasher, "require-hardware-backed-credential", policy.require_hardware_backed_credential);
    crypto_hash.updateBool(&hasher, "require-local-credential-unlock", policy.require_local_credential_unlock);
    crypto_hash.updateInt(&hasher, "max-credential-unlock-age-ticks", policy.max_credential_unlock_age_ticks);
    crypto_hash.updateBool(&hasher, "secret-vault-allowed", policy.secret_vault_allowed);
    crypto_hash.updateBool(&hasher, "require-hardware-backed-secrets", policy.require_hardware_backed_secrets);
    crypto_hash.updateBool(&hasher, "deny-secret-raw-export", policy.deny_secret_raw_export);
    crypto_hash.updateInt(&hasher, "max-secret-handle-lease-ticks", policy.max_secret_handle_lease_ticks);
    crypto_hash.updateBool(&hasher, "task-lifecycle-allowed", policy.task_lifecycle_allowed);
    crypto_hash.updateBool(&hasher, "require-lifecycle-checkpoint-before-terminate", policy.require_lifecycle_checkpoint_before_terminate);
    crypto_hash.updateInt(&hasher, "quiet-until-tick", policy.quiet_until_tick);
    crypto_hash.updateInt(&hasher, "max-visible-notifications", policy.max_visible_notifications);
    crypto_hash.updateInt(&hasher, "max-interruptive-notifications", policy.max_interruptive_notifications);
    crypto_hash.updateBool(&hasher, "allow-critical-interruption", policy.allow_critical_interruption);
    crypto_hash.updateBool(&hasher, "require-adaptive-ui", policy.require_adaptive_ui);
    crypto_hash.updateBool(&hasher, "require-screen-reader-support", policy.require_screen_reader_support);
    crypto_hash.updateBool(&hasher, "require-keyboard-navigation", policy.require_keyboard_navigation);
    crypto_hash.updateBool(&hasher, "require-reduced-motion-support", policy.require_reduced_motion_support);
    crypto_hash.updateBool(&hasher, "require-high-contrast-support", policy.require_high_contrast_support);
    crypto_hash.updateInt(&hasher, "max-background-duration-seconds", policy.max_background_duration_seconds);
    crypto_hash.updateInt(&hasher, "max-background-cpu-time-ticks", policy.max_background_cpu_time_ticks);
    crypto_hash.updateInt(&hasher, "max-background-memory-bytes", policy.max_background_memory_bytes);
    crypto_hash.updateInt(&hasher, "max-background-shared-memory-bytes", policy.max_background_shared_memory_bytes);
    crypto_hash.updateBool(&hasher, "allow-remote-background-network", policy.allow_remote_background_network);
    crypto_hash.updateBool(&hasher, "require-visible-background-activity", policy.require_visible_background_activity);
    crypto_hash.updateInt(&hasher, "max-sensitive-retention-days", policy.max_sensitive_retention_days);
    crypto_hash.updateInt(&hasher, "max-permission-lease-ticks", policy.max_permission_lease_ticks);
    crypto_hash.updateBool(&hasher, "require-sensitive-permission-lease", policy.require_sensitive_permission_lease);
    crypto_hash.updateBool(&hasher, "require-sensitive-capture-foreground", policy.require_sensitive_capture_foreground);
    crypto_hash.updateBool(&hasher, "require-capture-indicator", policy.require_capture_indicator);
    crypto_hash.updateBool(&hasher, "allow-background-capture", policy.allow_background_capture);
    crypto_hash.updateInt(&hasher, "max-sensitive-capture-lease-ticks", policy.max_sensitive_capture_lease_ticks);
    crypto_hash.updateInt(&hasher, "max-sensitive-capture-samples", policy.max_sensitive_capture_samples);
    crypto_hash.updateInt(&hasher, "retention-days", policy.retention_days);
    crypto_hash.updateBool(&hasher, "audit-export-required", policy.audit_export_required);

    var allow_index: usize = 0;
    while (allow_index < @as(usize, policy.allowed_install_source_count)) : (allow_index += 1) {
        crypto_hash.updateInt(&hasher, "install-source-index", allow_index);
        crypto_hash.updateBytes(&hasher, "install-source", policy.allowed_install_sources[allow_index][0..@as(usize, policy.allowed_install_source_lens[allow_index])]);
    }
    var network_index: usize = 0;
    while (network_index < @as(usize, policy.allowed_network_destination_count)) : (network_index += 1) {
        crypto_hash.updateInt(&hasher, "network-destination-index", network_index);
        crypto_hash.updateBytes(&hasher, "network-destination", policy.allowed_network_destinations[network_index][0..@as(usize, policy.allowed_network_destination_lens[network_index])]);
    }
    var sync_index: usize = 0;
    while (sync_index < @as(usize, policy.allowed_sync_destination_count)) : (sync_index += 1) {
        crypto_hash.updateInt(&hasher, "sync-destination-index", sync_index);
        crypto_hash.updateBytes(&hasher, "sync-destination", policy.allowed_sync_destinations[sync_index][0..@as(usize, policy.allowed_sync_destination_lens[sync_index])]);
    }
    return crypto_hash.finalize(&hasher);
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

test "policy objects remain signed scoped and enforce enterprise controls" {
    var directory = Directory.init();
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
    try std.testing.expect(directory.installSourceAllowed(.organization, 77, "store:zigos"));
    try std.testing.expect(!directory.installSourceAllowed(.organization, 77, "repo:unknown"));
    try std.testing.expect(directory.syncDestinationAllowed(.organization, 77, "relay.corp.example"));
    try std.testing.expect(!directory.syncDestinationAllowed(.organization, 77, "relay.personal.example"));
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

    const removable_decision = directory.removableStorageDecision(subjects);
    try std.testing.expect(!removable_decision.allowed);
    try std.testing.expectEqual(Scope.organization, removable_decision.blocking_scope.?);

    const screen_decision = directory.screenCaptureDecision(subjects);
    try std.testing.expect(!screen_decision.allowed);
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
    const oversized_label = [_]u8{'x'} ** (MAX_LABEL_BYTES + 1);
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

    policy.signature.value[0] ^=
        0x5A;
    try std.testing.expect(!directory.verify(policy.id));
    try std.testing.expect(!directory.installSourceAllowed(.device, 8, "store:zigos"));
}

test "compact policy metadata preserves exact label and allow-list capacities" {
    const full_label = [_]u8{'p'} ** MAX_LABEL_BYTES;
    const full_allow_list = [_][]const u8{&full_label} ** MAX_ALLOW_LIST;
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

test "policy directory indexes policy slots by id and scope through a full table" {
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
    try std.testing.expect(DERIVES_POLICY_IDS_FROM_ARENA_COUNT);
    try std.testing.expect(!@hasField(Directory, "next_policy_id"));
    try std.testing.expectEqual(@as(usize, DIRECTORY_SIZE_CEILING_BYTES), @sizeOf(Directory));
}
