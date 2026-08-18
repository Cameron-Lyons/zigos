const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

const copyTextExact = native_util.copyTextExact;

pub const Error = manifest.ValidationError || error{
    InstallSourceTooLong,
    PermissionTextBudgetExceeded,
    RevisionIdExhausted,
};

pub fn validateInstallTarget(
    comptime InstalledBundleType: type,
    bundle: manifest.BundleManifest,
) Error!void {
    try manifest.validate(bundle);
    try validateInstallStorageShape(InstalledBundleType, bundle);
}

pub fn validateInstallStorageShape(
    comptime InstalledBundleType: type,
    bundle: manifest.BundleManifest,
) Error!void {
    const RevisionType = arrayFieldChildType(InstalledBundleType, "revisions");
    const StoredComponentType = arrayFieldChildType(RevisionType, "components");
    const StoredAssetType = arrayFieldChildType(RevisionType, "assets");
    const StoredInterfaceType = arrayFieldChildType(RevisionType, "provided_interfaces");
    const StoredPermissionType = arrayFieldChildType(RevisionType, "requested_permissions");
    const StoredBackgroundTaskType = arrayFieldChildType(RevisionType, "background_tasks");
    const StoredAiMetadataType = @FieldType(RevisionType, "ai_metadata");
    const StoredDataRightsType = @FieldType(RevisionType, "data_rights");
    const StoredSupplyChainType = @FieldType(RevisionType, "supply_chain");
    const StoredAgentDelegationType = @FieldType(RevisionType, "agent_delegation");
    const StoredAccessibilityType = @FieldType(RevisionType, "accessibility");
    const StoredObjectResilienceType = @FieldType(RevisionType, "object_resilience");
    const StoredSemanticIndexType = @FieldType(RevisionType, "semantic_index");
    const StoredSignatureType = @FieldType(RevisionType, "signature");

    try validateTextLen(bundle.bundle_id, arrayFieldLen(InstalledBundleType, "bundle_id"), error.BundleIdTooLong);
    try validateTextLen(bundle.display_name, arrayFieldLen(RevisionType, "display_name"), error.DisplayNameTooLong);
    try validateTextLen(bundle.publisher, arrayFieldLen(RevisionType, "publisher"), error.PublisherTooLong);
    try validateCount(bundle.provided_interfaces.len, arrayFieldLen(RevisionType, "provided_interfaces"), error.TooManyProvidedInterfaces);
    try validateCount(bundle.consumed_interfaces.len, arrayFieldLen(RevisionType, "consumed_interfaces"), error.TooManyConsumedInterfaces);
    try validateCount(bundle.components.len, arrayFieldLen(RevisionType, "components"), error.TooManyComponents);
    try validateCount(bundle.assets.len, arrayFieldLen(RevisionType, "assets"), error.TooManyAssets);
    try validateCount(bundle.requested_permissions.len, arrayFieldLen(RevisionType, "requested_permissions"), error.TooManyPermissions);
    try validateCount(bundle.background_tasks.len, arrayFieldLen(RevisionType, "background_tasks"), error.TooManyBackgroundTasks);
    try validateTextLen(bundle.ai_metadata.model_family, arrayFieldLen(StoredAiMetadataType, "model_family"), error.AiModelFamilyTooLong);
    try validateTextLen(bundle.ai_metadata.model_digest, arrayFieldLen(StoredAiMetadataType, "model_digest"), error.AiModelDigestTooLong);
    try validateTextLen(bundle.ai_metadata.model_source_identity, arrayFieldLen(StoredAiMetadataType, "model_source_identity"), error.AiModelSourceTooLong);
    try validateTextLen(bundle.data_rights.export_format, arrayFieldLen(StoredDataRightsType, "export_format"), error.DataRightsExportFormatTooLong);
    try validateTextLen(bundle.supply_chain.sbom_digest, arrayFieldLen(StoredSupplyChainType, "sbom_digest"), error.SupplyChainDigestTooLong);
    try validateTextLen(bundle.supply_chain.source_archive_digest, arrayFieldLen(StoredSupplyChainType, "source_archive_digest"), error.SupplyChainDigestTooLong);
    try validateTextLen(bundle.supply_chain.build_recipe_digest, arrayFieldLen(StoredSupplyChainType, "build_recipe_digest"), error.SupplyChainDigestTooLong);
    try validateTextLen(bundle.supply_chain.vulnerability_scan_digest, arrayFieldLen(StoredSupplyChainType, "vulnerability_scan_digest"), error.SupplyChainDigestTooLong);
    try validateTextLen(bundle.supply_chain.build_provenance_identity, arrayFieldLen(StoredSupplyChainType, "build_provenance_identity"), error.BuildProvenanceIdentityTooLong);
    try validateTextLen(bundle.agent_delegation.purpose, arrayFieldLen(StoredAgentDelegationType, "purpose"), error.AgentDelegationPurposeTooLong);
    try validateTextLen(bundle.accessibility.profile_notes, arrayFieldLen(StoredAccessibilityType, "profile_notes"), error.AccessibilityProfileTooLong);
    try validateTextLen(bundle.object_resilience.backup_format, arrayFieldLen(StoredObjectResilienceType, "backup_format"), error.ObjectBackupFormatTooLong);
    try validateTextLen(bundle.semantic_index.model_digest, arrayFieldLen(StoredSemanticIndexType, "model_digest"), error.SemanticIndexModelDigestTooLong);
    try validateTextLen(bundle.signature.format, arrayFieldLen(StoredSignatureType, "format"), error.SignatureFormatTooLong);
    try validateTextLen(bundle.signature.signer, arrayFieldLen(StoredSignatureType, "signer"), error.SignatureSignerTooLong);

    for (bundle.provided_interfaces) |interface| {
        try validateTextLen(interface.name, arrayFieldLen(StoredInterfaceType, "name"), error.InterfaceNameTooLong);
    }
    for (bundle.consumed_interfaces) |interface| {
        try validateTextLen(interface.name, arrayFieldLen(StoredInterfaceType, "name"), error.InterfaceNameTooLong);
    }
    for (bundle.components) |component| {
        try validateTextLen(component.id, arrayFieldLen(StoredComponentType, "id"), error.ComponentIdTooLong);
        try validateTextLen(component.entry, arrayFieldLen(StoredComponentType, "entry"), error.ComponentEntryTooLong);
    }
    for (bundle.assets) |asset| {
        try validateTextLen(asset.path, arrayFieldLen(StoredAssetType, "path"), error.AssetPathTooLong);
        try validateTextLen(asset.content_type, arrayFieldLen(StoredAssetType, "content_type"), error.AssetContentTypeTooLong);
    }
    var permission_text_len: usize = 0;
    for (bundle.requested_permissions) |permission| {
        try validateTextLen(permission.resource, StoredPermissionType.max_resource_bytes, error.PermissionResourceTooLong);
        try validateTextLen(permission.user_visible_reason, StoredPermissionType.max_reason_bytes, error.PermissionReasonTooLong);
        try validateTextLen(permission.egress_intent.object, StoredPermissionType.max_resource_bytes, error.PermissionResourceTooLong);
        try validateTextLen(permission.egress_intent.principal, StoredPermissionType.max_resource_bytes, error.PermissionResourceTooLong);
        try validateTextLen(permission.egress_intent.service, StoredPermissionType.max_resource_bytes, error.PermissionResourceTooLong);
        try validateTextLen(permission.egress_intent.event_type, StoredPermissionType.max_resource_bytes, error.PermissionResourceTooLong);

        permission_text_len = std.math.add(usize, permission_text_len, permission.resource.len) catch return error.PermissionTextBudgetExceeded;
        permission_text_len = std.math.add(usize, permission_text_len, permission.user_visible_reason.len) catch return error.PermissionTextBudgetExceeded;
        permission_text_len = std.math.add(usize, permission_text_len, permission.egress_intent.object.len) catch return error.PermissionTextBudgetExceeded;
        permission_text_len = std.math.add(usize, permission_text_len, permission.egress_intent.principal.len) catch return error.PermissionTextBudgetExceeded;
        permission_text_len = std.math.add(usize, permission_text_len, permission.egress_intent.service.len) catch return error.PermissionTextBudgetExceeded;
        permission_text_len = std.math.add(usize, permission_text_len, permission.egress_intent.event_type.len) catch return error.PermissionTextBudgetExceeded;
    }
    if (permission_text_len > arrayFieldLen(RevisionType, "permission_text")) return error.PermissionTextBudgetExceeded;
    for (bundle.background_tasks) |task| {
        try validateTextLen(task.id, arrayFieldLen(StoredBackgroundTaskType, "id"), error.BackgroundTaskIdTooLong);
    }
}

pub fn installNew(
    bundle: anytype,
    source: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    permission_digest: crypto_hash.Digest,
) Error!void {
    const BundleType = storageType(@TypeOf(bundle));
    try validateInstallTarget(BundleType, source);
    try installNewValidated(bundle, source, source_identity, data_schema_version, permission_digest);
}

pub fn installNewValidated(
    bundle: anytype,
    source: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    permission_digest: crypto_hash.Digest,
) Error!void {
    bundle.bundle_id_len = copyValidatedText(&bundle.bundle_id, source.bundle_id);
    bundle.revision_count = 1;
    bundle.next_revision_id = 2;
    bundle.active_revision_slot = 0;
    bundle.rollback_revision_slot = null;
    try writeRevision(&bundle.revisions[0], source, source_identity, data_schema_version, permission_digest, 1);
}

pub fn installRevision(
    bundle: anytype,
    source: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    permission_digest: crypto_hash.Digest,
) Error!void {
    const BundleType = storageType(@TypeOf(bundle));
    try validateInstallTarget(BundleType, source);
    try installRevisionValidated(bundle, source, source_identity, data_schema_version, permission_digest);
}

pub fn installRevisionValidated(
    bundle: anytype,
    source: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    permission_digest: crypto_hash.Digest,
) Error!void {
    const revision_id = bundle.next_revision_id;
    if (revision_id == 0) return error.RevisionIdExhausted;

    const target_slot = bundle.inactiveRevisionSlot();
    try writeRevision(&bundle.revisions[target_slot], source, source_identity, data_schema_version, permission_digest, revision_id);
    bundle.next_revision_id = if (revision_id == std.math.maxInt(@TypeOf(revision_id))) 0 else revision_id + 1;
    if (bundle.revision_count == 0) {
        bundle.revision_count = 1;
    } else if (bundle.revision_count < bundle.revisions.len) {
        bundle.revision_count += 1;
    }
    bundle.rollback_revision_slot = bundle.active_revision_slot;
    bundle.active_revision_slot = target_slot;
}

pub fn rollback(bundle: anytype) void {
    const rollback_slot = bundle.rollback_revision_slot orelse return;
    const previous_active_slot = bundle.active_revision_slot;
    bundle.active_revision_slot = rollback_slot;
    bundle.rollback_revision_slot = previous_active_slot;
}

pub fn resolveActiveManifest(bundle: anytype, resolved: anytype) manifest.BundleManifest {
    const revision = bundle.activeRevision();
    const permission_text = revision.permissionTextSlice();

    var index: usize = 0;
    while (index < revision.provided_interface_count) : (index += 1) {
        const stored = &revision.provided_interfaces[index];
        resolved.provided_interfaces[index] = .{
            .name = stored.nameSlice(),
            .version_major = stored.version_major,
            .version_minor = stored.version_minor,
        };
    }

    index = 0;
    while (index < revision.consumed_interface_count) : (index += 1) {
        const stored = &revision.consumed_interfaces[index];
        resolved.consumed_interfaces[index] = .{
            .name = stored.nameSlice(),
            .version_major = stored.version_major,
            .version_minor = stored.version_minor,
        };
    }

    index = 0;
    while (index < revision.component_count) : (index += 1) {
        const stored = &revision.components[index];
        resolved.components[index] = .{
            .id = stored.idSlice(),
            .entry = stored.entrySlice(),
            .abi = stored.abi,
        };
    }

    index = 0;
    while (index < revision.asset_count) : (index += 1) {
        const stored = &revision.assets[index];
        resolved.assets[index] = .{
            .path = stored.pathSlice(),
            .content_type = stored.contentTypeSlice(),
        };
    }

    index = 0;
    while (index < revision.requested_permission_count) : (index += 1) {
        const stored = &revision.requested_permissions[index];
        resolved.requested_permissions[index] = .{
            .kind = stored.kind,
            .resource = stored.resourceSlice(permission_text),
            .rights = stored.rights,
            .required = stored.required,
            .local_only = stored.local_only,
            .max_lease_ticks = stored.max_lease_ticks,
            .target_id = stored.target_id,
            .sensitivity = stored.sensitivity,
            .purpose = stored.purpose,
            .retention_days = stored.retention_days,
            .user_visible_reason = stored.userVisibleReasonSlice(permission_text),
            .egress_intent = .{
                .kind = stored.egress_intent_kind,
                .object = stored.egressObjectSlice(permission_text),
                .principal = stored.egressPrincipalSlice(permission_text),
                .service = stored.egressServiceSlice(permission_text),
                .event_type = stored.egressEventTypeSlice(permission_text),
            },
        };
    }

    index = 0;
    while (index < revision.background_task_count) : (index += 1) {
        const stored = &revision.background_tasks[index];
        resolved.background_tasks[index] = .{
            .id = stored.idSlice(),
            .trigger = stored.trigger,
            .expected_duration_seconds = stored.expected_duration_seconds,
            .budget = stored.budget,
            .network = stored.network,
            .visibility = stored.visibility,
        };
    }

    resolved.ai_metadata = .{
        .model_family = revision.ai_metadata.modelFamilySlice(),
        .model_digest = revision.ai_metadata.modelDigestSlice(),
        .model_source_identity = revision.ai_metadata.modelSourceIdentitySlice(),
        .locality = revision.ai_metadata.locality,
        .offline_required = revision.ai_metadata.offline_required,
        .private_context = revision.ai_metadata.private_context,
        .training_allowed = revision.ai_metadata.training_allowed,
        .max_context_bytes = revision.ai_metadata.max_context_bytes,
        .audit_prompt_use = revision.ai_metadata.audit_prompt_use,
    };
    resolved.data_rights = .{
        .user_data_present = revision.data_rights.user_data_present,
        .portable_export = revision.data_rights.portable_export,
        .deletion_supported = revision.data_rights.deletion_supported,
        .deletion_receipt_required = revision.data_rights.deletion_receipt_required,
        .export_format = revision.data_rights.exportFormatSlice(),
    };
    resolved.supply_chain = .{
        .sbom_digest = revision.supply_chain.sbomDigestSlice(),
        .source_archive_digest = revision.supply_chain.sourceArchiveDigestSlice(),
        .build_recipe_digest = revision.supply_chain.buildRecipeDigestSlice(),
        .vulnerability_scan_digest = revision.supply_chain.vulnerabilityScanDigestSlice(),
        .build_provenance_identity = revision.supply_chain.buildProvenanceIdentitySlice(),
        .reproducible_build = revision.supply_chain.reproducible_build,
        .trusted_builder = revision.supply_chain.trusted_builder,
    };
    resolved.agent_delegation = .{
        .enabled = revision.agent_delegation.enabled,
        .purpose = revision.agent_delegation.purposeSlice(),
        .max_autonomous_actions = revision.agent_delegation.max_autonomous_actions,
        .max_remote_calls = revision.agent_delegation.max_remote_calls,
        .user_confirmation_required = revision.agent_delegation.user_confirmation_required,
        .audit_required = revision.agent_delegation.audit_required,
        .session_bound = revision.agent_delegation.session_bound,
        .local_context_only = revision.agent_delegation.local_context_only,
        .max_context_bytes = revision.agent_delegation.max_context_bytes,
        .kill_switch_supported = revision.agent_delegation.kill_switch_supported,
    };
    resolved.accessibility = .{
        .adaptive_ui = revision.accessibility.adaptive_ui,
        .supports_screen_reader = revision.accessibility.supports_screen_reader,
        .supports_keyboard_navigation = revision.accessibility.supports_keyboard_navigation,
        .supports_reduced_motion = revision.accessibility.supports_reduced_motion,
        .supports_high_contrast = revision.accessibility.supports_high_contrast,
        .profile_notes = revision.accessibility.profileNotesSlice(),
    };
    resolved.object_resilience = .{
        .backup_enabled = revision.object_resilience.backup_enabled,
        .encrypted_snapshots = revision.object_resilience.encrypted_snapshots,
        .recovery_key_required = revision.object_resilience.recovery_key_required,
        .portable_restore = revision.object_resilience.portable_restore,
        .device_trust_required = revision.object_resilience.device_trust_required,
        .max_restore_age_days = revision.object_resilience.max_restore_age_days,
        .backup_format = revision.object_resilience.backupFormatSlice(),
    };
    resolved.semantic_index = .{
        .enabled = revision.semantic_index.enabled,
        .local_only = revision.semantic_index.local_only,
        .encrypted_index = revision.semantic_index.encrypted_index,
        .redacted_snippets = revision.semantic_index.redacted_snippets,
        .max_query_bytes = revision.semantic_index.max_query_bytes,
        .model_digest = revision.semantic_index.modelDigestSlice(),
    };
    resolved.signature = .{
        .format = revision.signature.formatSlice(),
        .signer = revision.signature.signerSlice(),
        .public_key_len = revision.signature.public_key_len,
        .public_key = revision.signature.public_key,
        .value_len = revision.signature.value_len,
        .value = revision.signature.value,
    };

    return .{
        .bundle_id = bundle.bundleIdSlice(),
        .display_name = revision.displayNameSlice(),
        .publisher = revision.publisherSlice(),
        .version_major = revision.version_major,
        .version_minor = revision.version_minor,
        .provided_interfaces = resolved.provided_interfaces[0..revision.provided_interface_count],
        .consumed_interfaces = resolved.consumed_interfaces[0..revision.consumed_interface_count],
        .components = resolved.components[0..revision.component_count],
        .assets = resolved.assets[0..revision.asset_count],
        .requested_permissions = resolved.requested_permissions[0..revision.requested_permission_count],
        .background_tasks = resolved.background_tasks[0..revision.background_task_count],
        .ai_metadata = resolved.ai_metadata,
        .data_rights = resolved.data_rights,
        .supply_chain = resolved.supply_chain,
        .agent_delegation = resolved.agent_delegation,
        .accessibility = resolved.accessibility,
        .object_resilience = resolved.object_resilience,
        .semantic_index = resolved.semantic_index,
        .update_channel = revision.channel,
        .signature = resolved.signature,
    };
}

fn writeRevision(
    revision: anytype,
    source: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32,
    permission_digest: crypto_hash.Digest,
    revision_id: u64,
) Error!void {
    revision.revision_id = revision_id;
    revision.display_name_len = copyValidatedText(&revision.display_name, source.display_name);
    revision.publisher_len = copyValidatedText(&revision.publisher, source.publisher);
    revision.source_identity_len = copyTextExact(&revision.source_identity, source_identity) catch return error.InstallSourceTooLong;
    revision.version_major = source.version_major;
    revision.version_minor = source.version_minor;
    revision.channel = source.update_channel;
    revision.permission_digest = permission_digest;
    if (@hasField(@TypeOf(revision.*), "release_transparency")) {
        revision.release_transparency = .{};
    }
    revision.schema_version = data_schema_version;
    try writeLaunchMetadata(revision, source);
    try writeManifestMetadata(revision, source);
}

fn writeLaunchMetadata(revision: anytype, source: manifest.BundleManifest) Error!void {
    revision.component_count = source.components.len;
    for (source.components, 0..) |component, component_index| {
        revision.components[component_index].id_len = copyValidatedText(&revision.components[component_index].id, component.id);
        revision.components[component_index].entry_len = copyValidatedText(&revision.components[component_index].entry, component.entry);
        revision.components[component_index].abi = component.abi;
    }

    revision.asset_count = source.assets.len;
    for (source.assets, 0..) |asset, asset_index| {
        revision.assets[asset_index].path_len = copyValidatedText(&revision.assets[asset_index].path, asset.path);
        revision.assets[asset_index].content_type_len = copyValidatedText(&revision.assets[asset_index].content_type, asset.content_type);
    }
}

fn writeManifestMetadata(revision: anytype, source: manifest.BundleManifest) Error!void {
    revision.provided_interface_count = source.provided_interfaces.len;
    for (source.provided_interfaces, 0..) |interface, interface_index| {
        revision.provided_interfaces[interface_index].name_len = copyValidatedText(&revision.provided_interfaces[interface_index].name, interface.name);
        revision.provided_interfaces[interface_index].version_major = interface.version_major;
        revision.provided_interfaces[interface_index].version_minor = interface.version_minor;
    }

    revision.consumed_interface_count = source.consumed_interfaces.len;
    for (source.consumed_interfaces, 0..) |interface, interface_index| {
        revision.consumed_interfaces[interface_index].name_len = copyValidatedText(&revision.consumed_interfaces[interface_index].name, interface.name);
        revision.consumed_interfaces[interface_index].version_major = interface.version_major;
        revision.consumed_interfaces[interface_index].version_minor = interface.version_minor;
    }

    revision.requested_permission_count = source.requested_permissions.len;
    const previous_permission_text_len = @min(
        @as(usize, @intCast(revision.permission_text_len)),
        revision.permission_text.len,
    );
    revision.permission_text_len = 0;
    for (source.requested_permissions, 0..) |permission, permission_index| {
        revision.requested_permissions[permission_index] = .{};
        const stored = &revision.requested_permissions[permission_index];
        stored.kind = permission.kind;
        try writePermissionText(revision, &stored.resource, permission.resource);
        stored.rights = permission.rights;
        stored.required = permission.required;
        stored.local_only = permission.local_only;
        stored.max_lease_ticks = permission.max_lease_ticks;
        stored.target_id = permission.target_id;
        stored.sensitivity = permission.sensitivity;
        stored.purpose = permission.purpose;
        stored.retention_days = permission.retention_days;
        try writePermissionText(revision, &stored.user_visible_reason, permission.user_visible_reason);
        stored.egress_intent_kind = permission.egress_intent.kind;
        try writePermissionText(revision, &stored.egress_object, permission.egress_intent.object);
        try writePermissionText(revision, &stored.egress_principal, permission.egress_intent.principal);
        try writePermissionText(revision, &stored.egress_service, permission.egress_intent.service);
        try writePermissionText(revision, &stored.egress_event_type, permission.egress_intent.event_type);
    }
    const permission_text_len: usize = @intCast(revision.permission_text_len);
    if (permission_text_len < previous_permission_text_len) {
        @memset(revision.permission_text[permission_text_len..previous_permission_text_len], 0);
    }

    revision.background_task_count = source.background_tasks.len;
    for (source.background_tasks, 0..) |task, background_index| {
        revision.background_tasks[background_index].id_len = copyValidatedText(&revision.background_tasks[background_index].id, task.id);
        revision.background_tasks[background_index].trigger = task.trigger;
        revision.background_tasks[background_index].expected_duration_seconds = task.expected_duration_seconds;
        revision.background_tasks[background_index].budget = task.budget;
        revision.background_tasks[background_index].network = task.network;
        revision.background_tasks[background_index].visibility = task.visibility;
    }

    revision.ai_metadata = .{};
    revision.ai_metadata.model_family_len = copyValidatedText(&revision.ai_metadata.model_family, source.ai_metadata.model_family);
    revision.ai_metadata.model_digest_len = copyValidatedText(&revision.ai_metadata.model_digest, source.ai_metadata.model_digest);
    revision.ai_metadata.model_source_identity_len = copyValidatedText(&revision.ai_metadata.model_source_identity, source.ai_metadata.model_source_identity);
    revision.ai_metadata.locality = source.ai_metadata.locality;
    revision.ai_metadata.offline_required = source.ai_metadata.offline_required;
    revision.ai_metadata.private_context = source.ai_metadata.private_context;
    revision.ai_metadata.training_allowed = source.ai_metadata.training_allowed;
    revision.ai_metadata.max_context_bytes = source.ai_metadata.max_context_bytes;
    revision.ai_metadata.audit_prompt_use = source.ai_metadata.audit_prompt_use;

    revision.data_rights = .{};
    revision.data_rights.user_data_present = source.data_rights.user_data_present;
    revision.data_rights.portable_export = source.data_rights.portable_export;
    revision.data_rights.deletion_supported = source.data_rights.deletion_supported;
    revision.data_rights.deletion_receipt_required = source.data_rights.deletion_receipt_required;
    revision.data_rights.export_format_len = copyValidatedText(&revision.data_rights.export_format, source.data_rights.export_format);

    revision.supply_chain = .{};
    revision.supply_chain.sbom_digest_len = copyValidatedText(&revision.supply_chain.sbom_digest, source.supply_chain.sbom_digest);
    revision.supply_chain.source_archive_digest_len = copyValidatedText(&revision.supply_chain.source_archive_digest, source.supply_chain.source_archive_digest);
    revision.supply_chain.build_recipe_digest_len = copyValidatedText(&revision.supply_chain.build_recipe_digest, source.supply_chain.build_recipe_digest);
    revision.supply_chain.vulnerability_scan_digest_len = copyValidatedText(&revision.supply_chain.vulnerability_scan_digest, source.supply_chain.vulnerability_scan_digest);
    revision.supply_chain.build_provenance_identity_len = copyValidatedText(&revision.supply_chain.build_provenance_identity, source.supply_chain.build_provenance_identity);
    revision.supply_chain.reproducible_build = source.supply_chain.reproducible_build;
    revision.supply_chain.trusted_builder = source.supply_chain.trusted_builder;

    revision.agent_delegation = .{};
    revision.agent_delegation.enabled = source.agent_delegation.enabled;
    revision.agent_delegation.purpose_len = copyValidatedText(&revision.agent_delegation.purpose, source.agent_delegation.purpose);
    revision.agent_delegation.max_autonomous_actions = source.agent_delegation.max_autonomous_actions;
    revision.agent_delegation.max_remote_calls = source.agent_delegation.max_remote_calls;
    revision.agent_delegation.user_confirmation_required = source.agent_delegation.user_confirmation_required;
    revision.agent_delegation.audit_required = source.agent_delegation.audit_required;
    revision.agent_delegation.session_bound = source.agent_delegation.session_bound;
    revision.agent_delegation.local_context_only = source.agent_delegation.local_context_only;
    revision.agent_delegation.max_context_bytes = source.agent_delegation.max_context_bytes;
    revision.agent_delegation.kill_switch_supported = source.agent_delegation.kill_switch_supported;

    revision.accessibility = .{};
    revision.accessibility.adaptive_ui = source.accessibility.adaptive_ui;
    revision.accessibility.supports_screen_reader = source.accessibility.supports_screen_reader;
    revision.accessibility.supports_keyboard_navigation = source.accessibility.supports_keyboard_navigation;
    revision.accessibility.supports_reduced_motion = source.accessibility.supports_reduced_motion;
    revision.accessibility.supports_high_contrast = source.accessibility.supports_high_contrast;
    revision.accessibility.profile_notes_len = copyValidatedText(&revision.accessibility.profile_notes, source.accessibility.profile_notes);

    revision.object_resilience = .{};
    revision.object_resilience.backup_enabled = source.object_resilience.backup_enabled;
    revision.object_resilience.encrypted_snapshots = source.object_resilience.encrypted_snapshots;
    revision.object_resilience.recovery_key_required = source.object_resilience.recovery_key_required;
    revision.object_resilience.portable_restore = source.object_resilience.portable_restore;
    revision.object_resilience.device_trust_required = source.object_resilience.device_trust_required;
    revision.object_resilience.max_restore_age_days = source.object_resilience.max_restore_age_days;
    revision.object_resilience.backup_format_len = copyValidatedText(&revision.object_resilience.backup_format, source.object_resilience.backup_format);

    revision.semantic_index = .{};
    revision.semantic_index.enabled = source.semantic_index.enabled;
    revision.semantic_index.local_only = source.semantic_index.local_only;
    revision.semantic_index.encrypted_index = source.semantic_index.encrypted_index;
    revision.semantic_index.redacted_snippets = source.semantic_index.redacted_snippets;
    revision.semantic_index.max_query_bytes = source.semantic_index.max_query_bytes;
    revision.semantic_index.model_digest_len = copyValidatedText(&revision.semantic_index.model_digest, source.semantic_index.model_digest);

    revision.signature = .{};
    revision.signature.format_len = copyValidatedText(&revision.signature.format, source.signature.format);
    revision.signature.signer_len = copyValidatedText(&revision.signature.signer, source.signature.signer);
    revision.signature.public_key_len = source.signature.public_key_len;
    revision.signature.public_key = source.signature.public_key;
    revision.signature.value_len = source.signature.value_len;
    revision.signature.value = source.signature.value;
}

fn copyValidatedText(dest: []u8, src: []const u8) usize {
    @memcpy(dest[0..src.len], src);
    return src.len;
}

fn writePermissionText(revision: anytype, destination: anytype, text: []const u8) Error!void {
    const start: usize = revision.permission_text_len;
    const end = std.math.add(usize, start, text.len) catch return error.PermissionTextBudgetExceeded;
    if (end > revision.permission_text.len) return error.PermissionTextBudgetExceeded;
    @memcpy(revision.permission_text[start..end], text);
    destination.* = .{
        .offset = @intCast(start),
        .len = @intCast(text.len),
    };
    revision.permission_text_len = @intCast(end);
}

fn storageType(comptime PtrType: type) type {
    return switch (@typeInfo(PtrType)) {
        .pointer => |pointer| pointer.child,
        else => @compileError("package_service_bundle_ops expects a pointer destination"),
    };
}

fn arrayFieldLen(comptime T: type, comptime field_name: []const u8) usize {
    return switch (@typeInfo(@FieldType(T, field_name))) {
        .array => |array| array.len,
        else => @compileError("field '" ++ field_name ++ "' must be a fixed-size array"),
    };
}

fn arrayFieldChildType(comptime T: type, comptime field_name: []const u8) type {
    return switch (@typeInfo(@FieldType(T, field_name))) {
        .array => |array| array.child,
        else => @compileError("field '" ++ field_name ++ "' must be a fixed-size array"),
    };
}

fn validateCount(len: usize, max: usize, comptime too_many: Error) Error!void {
    if (len > max) return too_many;
}

fn validateTextLen(text: []const u8, max: usize, comptime too_long: Error) Error!void {
    if (text.len > max) return too_long;
}
