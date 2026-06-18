const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");

pub const Digest = crypto_hash.Digest;

pub fn digestBundle(bundle: manifest.BundleManifest) Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bundle-id", bundle.bundle_id);
    crypto_hash.updateBytes(&hasher, "display-name", bundle.display_name);
    crypto_hash.updateBytes(&hasher, "publisher", bundle.publisher);
    crypto_hash.updateInt(&hasher, "version-major", bundle.version_major);
    crypto_hash.updateInt(&hasher, "version-minor", bundle.version_minor);
    crypto_hash.updateEnum(&hasher, "update-channel", bundle.update_channel);
    crypto_hash.updateBytes(&hasher, "ai-model-family", bundle.ai_metadata.model_family);
    crypto_hash.updateBytes(&hasher, "ai-model-digest", bundle.ai_metadata.model_digest);
    crypto_hash.updateBytes(&hasher, "ai-model-source-identity", bundle.ai_metadata.model_source_identity);
    crypto_hash.updateEnum(&hasher, "ai-locality", bundle.ai_metadata.locality);
    crypto_hash.updateBool(&hasher, "ai-offline-required", bundle.ai_metadata.offline_required);
    crypto_hash.updateBool(&hasher, "ai-private-context", bundle.ai_metadata.private_context);
    crypto_hash.updateBool(&hasher, "ai-training-allowed", bundle.ai_metadata.training_allowed);
    crypto_hash.updateInt(&hasher, "ai-max-context-bytes", bundle.ai_metadata.max_context_bytes);
    crypto_hash.updateBool(&hasher, "ai-audit-prompt-use", bundle.ai_metadata.audit_prompt_use);
    crypto_hash.updateBool(&hasher, "data-rights-user-data-present", bundle.data_rights.user_data_present);
    crypto_hash.updateBool(&hasher, "data-rights-portable-export", bundle.data_rights.portable_export);
    crypto_hash.updateBool(&hasher, "data-rights-deletion-supported", bundle.data_rights.deletion_supported);
    crypto_hash.updateBool(&hasher, "data-rights-deletion-receipt-required", bundle.data_rights.deletion_receipt_required);
    crypto_hash.updateBytes(&hasher, "data-rights-export-format", bundle.data_rights.export_format);
    crypto_hash.updateBytes(&hasher, "supply-chain-sbom-digest", bundle.supply_chain.sbom_digest);
    crypto_hash.updateBytes(&hasher, "supply-chain-source-archive-digest", bundle.supply_chain.source_archive_digest);
    crypto_hash.updateBytes(&hasher, "supply-chain-build-recipe-digest", bundle.supply_chain.build_recipe_digest);
    crypto_hash.updateBytes(&hasher, "supply-chain-vulnerability-scan-digest", bundle.supply_chain.vulnerability_scan_digest);
    crypto_hash.updateBytes(&hasher, "supply-chain-build-provenance-identity", bundle.supply_chain.build_provenance_identity);
    crypto_hash.updateBool(&hasher, "supply-chain-reproducible-build", bundle.supply_chain.reproducible_build);
    crypto_hash.updateBool(&hasher, "supply-chain-trusted-builder", bundle.supply_chain.trusted_builder);
    crypto_hash.updateBool(&hasher, "agent-delegation-enabled", bundle.agent_delegation.enabled);
    crypto_hash.updateBytes(&hasher, "agent-delegation-purpose", bundle.agent_delegation.purpose);
    crypto_hash.updateInt(&hasher, "agent-delegation-max-actions", bundle.agent_delegation.max_autonomous_actions);
    crypto_hash.updateInt(&hasher, "agent-delegation-max-remote-calls", bundle.agent_delegation.max_remote_calls);
    crypto_hash.updateBool(&hasher, "agent-delegation-user-confirmation", bundle.agent_delegation.user_confirmation_required);
    crypto_hash.updateBool(&hasher, "agent-delegation-audit-required", bundle.agent_delegation.audit_required);
    crypto_hash.updateBool(&hasher, "agent-delegation-session-bound", bundle.agent_delegation.session_bound);
    crypto_hash.updateBool(&hasher, "agent-delegation-local-context-only", bundle.agent_delegation.local_context_only);
    crypto_hash.updateInt(&hasher, "agent-delegation-max-context-bytes", bundle.agent_delegation.max_context_bytes);
    crypto_hash.updateBool(&hasher, "agent-delegation-kill-switch-supported", bundle.agent_delegation.kill_switch_supported);
    crypto_hash.updateBool(&hasher, "accessibility-adaptive-ui", bundle.accessibility.adaptive_ui);
    crypto_hash.updateBool(&hasher, "accessibility-screen-reader", bundle.accessibility.supports_screen_reader);
    crypto_hash.updateBool(&hasher, "accessibility-keyboard-navigation", bundle.accessibility.supports_keyboard_navigation);
    crypto_hash.updateBool(&hasher, "accessibility-reduced-motion", bundle.accessibility.supports_reduced_motion);
    crypto_hash.updateBool(&hasher, "accessibility-high-contrast", bundle.accessibility.supports_high_contrast);
    crypto_hash.updateBytes(&hasher, "accessibility-profile-notes", bundle.accessibility.profile_notes);
    crypto_hash.updateBool(&hasher, "object-resilience-backup-enabled", bundle.object_resilience.backup_enabled);
    crypto_hash.updateBool(&hasher, "object-resilience-encrypted-snapshots", bundle.object_resilience.encrypted_snapshots);
    crypto_hash.updateBool(&hasher, "object-resilience-recovery-key-required", bundle.object_resilience.recovery_key_required);
    crypto_hash.updateBool(&hasher, "object-resilience-portable-restore", bundle.object_resilience.portable_restore);
    crypto_hash.updateBool(&hasher, "object-resilience-device-trust-required", bundle.object_resilience.device_trust_required);
    crypto_hash.updateInt(&hasher, "object-resilience-max-restore-age-days", bundle.object_resilience.max_restore_age_days);
    crypto_hash.updateBytes(&hasher, "object-resilience-backup-format", bundle.object_resilience.backup_format);
    crypto_hash.updateBool(&hasher, "semantic-index-enabled", bundle.semantic_index.enabled);
    crypto_hash.updateBool(&hasher, "semantic-index-local-only", bundle.semantic_index.local_only);
    crypto_hash.updateBool(&hasher, "semantic-index-encrypted-index", bundle.semantic_index.encrypted_index);
    crypto_hash.updateBool(&hasher, "semantic-index-redacted-snippets", bundle.semantic_index.redacted_snippets);
    crypto_hash.updateInt(&hasher, "semantic-index-max-query-bytes", bundle.semantic_index.max_query_bytes);
    crypto_hash.updateBytes(&hasher, "semantic-index-model-digest", bundle.semantic_index.model_digest);

    for (bundle.provided_interfaces, 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "provided-index", index);
        crypto_hash.updateBytes(&hasher, "provided-name", interface.name);
        crypto_hash.updateInt(&hasher, "provided-version-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "provided-version-minor", interface.version_minor);
    }
    for (bundle.consumed_interfaces, 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "consumed-index", index);
        crypto_hash.updateBytes(&hasher, "consumed-name", interface.name);
        crypto_hash.updateInt(&hasher, "consumed-version-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "consumed-version-minor", interface.version_minor);
    }
    for (bundle.components, 0..) |component, index| {
        crypto_hash.updateInt(&hasher, "component-index", index);
        crypto_hash.updateBytes(&hasher, "component-id", component.id);
        crypto_hash.updateBytes(&hasher, "component-entry", component.entry);
        crypto_hash.updateEnum(&hasher, "component-abi", component.abi);
    }
    for (bundle.assets, 0..) |asset, index| {
        crypto_hash.updateInt(&hasher, "asset-index", index);
        crypto_hash.updateBytes(&hasher, "asset-path", asset.path);
        crypto_hash.updateBytes(&hasher, "asset-content-type", asset.content_type);
    }
    for (bundle.requested_permissions, 0..) |permission, index| {
        const rights_bits = permission.rights.toBits();
        crypto_hash.updateInt(&hasher, "permission-index", index);
        crypto_hash.updateEnum(&hasher, "permission-kind", permission.kind);
        crypto_hash.updateBytes(&hasher, "permission-resource", permission.resource);
        crypto_hash.updateInt(&hasher, "permission-rights", rights_bits);
        crypto_hash.updateBool(&hasher, "permission-required", permission.required);
        crypto_hash.updateBool(&hasher, "permission-local-only", permission.local_only);
        crypto_hash.updateInt(&hasher, "permission-max-lease", permission.max_lease_ticks);
        crypto_hash.updateInt(&hasher, "permission-target-id", permission.target_id);
        crypto_hash.updateEnum(&hasher, "permission-sensitivity", permission.sensitivity);
        crypto_hash.updateEnum(&hasher, "permission-purpose", permission.purpose);
        crypto_hash.updateInt(&hasher, "permission-retention-days", permission.retention_days);
        crypto_hash.updateBytes(&hasher, "permission-user-visible-reason", permission.user_visible_reason);
        crypto_hash.updateEnum(&hasher, "permission-egress-intent-kind", permission.egress_intent.kind);
        crypto_hash.updateBytes(&hasher, "permission-egress-object", permission.egress_intent.object);
        crypto_hash.updateBytes(&hasher, "permission-egress-principal", permission.egress_intent.principal);
        crypto_hash.updateBytes(&hasher, "permission-egress-service", permission.egress_intent.service);
        crypto_hash.updateBytes(&hasher, "permission-egress-event-type", permission.egress_intent.event_type);
    }
    for (bundle.background_tasks, 0..) |task, index| {
        crypto_hash.updateInt(&hasher, "background-index", index);
        crypto_hash.updateBytes(&hasher, "background-id", task.id);
        crypto_hash.updateEnum(&hasher, "background-trigger", task.trigger);
        crypto_hash.updateInt(&hasher, "background-duration", task.expected_duration_seconds);
        crypto_hash.updateInt(&hasher, "background-budget-cpu", task.budget.cpu_time_ticks);
        crypto_hash.updateInt(&hasher, "background-budget-memory", task.budget.memory_bytes);
        crypto_hash.updateInt(&hasher, "background-budget-shared-memory", task.budget.shared_memory_bytes);
        crypto_hash.updateEnum(&hasher, "background-network", task.network);
        crypto_hash.updateEnum(&hasher, "background-visibility", task.visibility);
    }

    return crypto_hash.finalize(&hasher);
}

pub fn permissionDigest(requests: []const manifest.PermissionRequest) Digest {
    var hasher = crypto_hash.init();
    for (requests, 0..) |request, index| {
        const rights_bits = request.rights.toBits();
        crypto_hash.updateInt(&hasher, "permission-index", index);
        crypto_hash.updateEnum(&hasher, "permission-kind", request.kind);
        crypto_hash.updateBytes(&hasher, "permission-resource", request.resource);
        crypto_hash.updateInt(&hasher, "permission-rights", rights_bits);
        crypto_hash.updateBool(&hasher, "permission-required", request.required);
        crypto_hash.updateBool(&hasher, "permission-local-only", request.local_only);
        crypto_hash.updateInt(&hasher, "permission-max-lease", request.max_lease_ticks);
        crypto_hash.updateInt(&hasher, "permission-target-id", request.target_id);
        crypto_hash.updateEnum(&hasher, "permission-sensitivity", request.sensitivity);
        crypto_hash.updateEnum(&hasher, "permission-purpose", request.purpose);
        crypto_hash.updateInt(&hasher, "permission-retention-days", request.retention_days);
        crypto_hash.updateBytes(&hasher, "permission-user-visible-reason", request.user_visible_reason);
        crypto_hash.updateEnum(&hasher, "permission-egress-intent-kind", request.egress_intent.kind);
        crypto_hash.updateBytes(&hasher, "permission-egress-object", request.egress_intent.object);
        crypto_hash.updateBytes(&hasher, "permission-egress-principal", request.egress_intent.principal);
        crypto_hash.updateBytes(&hasher, "permission-egress-service", request.egress_intent.service);
        crypto_hash.updateBytes(&hasher, "permission-egress-event-type", request.egress_intent.event_type);
    }
    return crypto_hash.finalize(&hasher);
}
