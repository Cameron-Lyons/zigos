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
    crypto_hash.updateEnum(&hasher, "ai-locality", bundle.ai_metadata.locality);
    crypto_hash.updateBool(&hasher, "ai-offline-required", bundle.ai_metadata.offline_required);

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
        crypto_hash.updateEnum(&hasher, "permission-egress-intent-kind", request.egress_intent.kind);
        crypto_hash.updateBytes(&hasher, "permission-egress-object", request.egress_intent.object);
        crypto_hash.updateBytes(&hasher, "permission-egress-principal", request.egress_intent.principal);
        crypto_hash.updateBytes(&hasher, "permission-egress-service", request.egress_intent.service);
        crypto_hash.updateBytes(&hasher, "permission-egress-event-type", request.egress_intent.event_type);
    }
    return crypto_hash.finalize(&hasher);
}
