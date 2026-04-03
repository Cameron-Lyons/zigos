const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

const copyText = native_util.copyText;

pub fn installNew(
    bundle: anytype,
    source: manifest.BundleManifest,
    data_schema_version: u32,
    permission_digest: [32]u8,
    migration_manifest: []const u8,
) void {
    bundle.bundle_id_len = copyText(&bundle.bundle_id, source.bundle_id);
    bundle.revision_count = 1;
    bundle.next_revision_id = 2;
    bundle.active_revision_slot = 0;
    bundle.rollback_revision_slot = null;
    bundle.revisions[0] = .{};
    bundle.revisions[1] = .{};
    writeRevision(&bundle.revisions[0], source, data_schema_version, permission_digest, 1);
    bundle.last_migration_manifest_len = copyText(&bundle.last_migration_manifest, migration_manifest);
}

pub fn installRevision(
    bundle: anytype,
    source: manifest.BundleManifest,
    data_schema_version: u32,
    permission_digest: [32]u8,
    migration_manifest: []const u8,
) void {
    const target_slot = bundle.inactiveRevisionSlot();
    bundle.revisions[target_slot] = .{};
    writeRevision(&bundle.revisions[target_slot], source, data_schema_version, permission_digest, bundle.next_revision_id);
    bundle.next_revision_id += 1;
    if (bundle.revision_count == 0) {
        bundle.revision_count = 1;
    } else if (bundle.revision_count < bundle.revisions.len) {
        bundle.revision_count += 1;
    }
    bundle.rollback_revision_slot = bundle.active_revision_slot;
    bundle.active_revision_slot = target_slot;
    bundle.last_migration_manifest_len = copyText(&bundle.last_migration_manifest, migration_manifest);
}

pub fn rollback(bundle: anytype) void {
    const rollback_slot = bundle.rollback_revision_slot orelse return;
    const previous_active_slot = bundle.active_revision_slot;
    bundle.active_revision_slot = rollback_slot;
    bundle.rollback_revision_slot = previous_active_slot;
}

pub fn resolveActiveManifest(bundle: anytype, resolved: anytype) manifest.BundleManifest {
    const revision = bundle.activeRevision();

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
            .resource = stored.resourceSlice(),
            .rights = stored.rights,
            .required = stored.required,
            .local_only = stored.local_only,
            .max_lease_ticks = stored.max_lease_ticks,
            .target_id = stored.target_id,
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
        .locality = revision.ai_metadata.locality,
        .offline_required = revision.ai_metadata.offline_required,
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
        .update_channel = revision.channel,
        .signature = resolved.signature,
    };
}

fn writeRevision(
    revision: anytype,
    source: manifest.BundleManifest,
    data_schema_version: u32,
    permission_digest: [32]u8,
    revision_id: u32,
) void {
    revision.revision_id = revision_id;
    revision.display_name_len = copyText(&revision.display_name, source.display_name);
    revision.publisher_len = copyText(&revision.publisher, source.publisher);
    revision.version_major = source.version_major;
    revision.version_minor = source.version_minor;
    revision.channel = source.update_channel;
    revision.permission_digest = permission_digest;
    revision.schema_version = data_schema_version;
    writeLaunchMetadata(revision, source);
    writeManifestMetadata(revision, source);
}

fn writeLaunchMetadata(revision: anytype, source: manifest.BundleManifest) void {
    revision.component_count = @min(source.components.len, revision.components.len);
    var component_index: usize = 0;
    while (component_index < revision.components.len) : (component_index += 1) {
        revision.components[component_index] = .{};
        if (component_index >= revision.component_count) continue;
        const component = source.components[component_index];
        revision.components[component_index].id_len = copyText(&revision.components[component_index].id, component.id);
        revision.components[component_index].entry_len = copyText(&revision.components[component_index].entry, component.entry);
        revision.components[component_index].abi = component.abi;
    }

    revision.asset_count = @min(source.assets.len, revision.assets.len);
    var asset_index: usize = 0;
    while (asset_index < revision.assets.len) : (asset_index += 1) {
        revision.assets[asset_index] = .{};
        if (asset_index >= revision.asset_count) continue;
        const asset = source.assets[asset_index];
        revision.assets[asset_index].path_len = copyText(&revision.assets[asset_index].path, asset.path);
        revision.assets[asset_index].content_type_len = copyText(&revision.assets[asset_index].content_type, asset.content_type);
    }
}

fn writeManifestMetadata(revision: anytype, source: manifest.BundleManifest) void {
    revision.provided_interface_count = @min(source.provided_interfaces.len, revision.provided_interfaces.len);
    var interface_index: usize = 0;
    while (interface_index < revision.provided_interfaces.len) : (interface_index += 1) {
        revision.provided_interfaces[interface_index] = .{};
        if (interface_index >= revision.provided_interface_count) continue;
        const interface = source.provided_interfaces[interface_index];
        revision.provided_interfaces[interface_index].name_len = copyText(&revision.provided_interfaces[interface_index].name, interface.name);
        revision.provided_interfaces[interface_index].version_major = interface.version_major;
        revision.provided_interfaces[interface_index].version_minor = interface.version_minor;
    }

    revision.consumed_interface_count = @min(source.consumed_interfaces.len, revision.consumed_interfaces.len);
    interface_index = 0;
    while (interface_index < revision.consumed_interfaces.len) : (interface_index += 1) {
        revision.consumed_interfaces[interface_index] = .{};
        if (interface_index >= revision.consumed_interface_count) continue;
        const interface = source.consumed_interfaces[interface_index];
        revision.consumed_interfaces[interface_index].name_len = copyText(&revision.consumed_interfaces[interface_index].name, interface.name);
        revision.consumed_interfaces[interface_index].version_major = interface.version_major;
        revision.consumed_interfaces[interface_index].version_minor = interface.version_minor;
    }

    revision.requested_permission_count = @min(source.requested_permissions.len, revision.requested_permissions.len);
    var permission_index: usize = 0;
    while (permission_index < revision.requested_permissions.len) : (permission_index += 1) {
        revision.requested_permissions[permission_index] = .{};
        if (permission_index >= revision.requested_permission_count) continue;
        const permission = source.requested_permissions[permission_index];
        revision.requested_permissions[permission_index].kind = permission.kind;
        revision.requested_permissions[permission_index].resource_len = copyText(&revision.requested_permissions[permission_index].resource, permission.resource);
        revision.requested_permissions[permission_index].rights = permission.rights;
        revision.requested_permissions[permission_index].required = permission.required;
        revision.requested_permissions[permission_index].local_only = permission.local_only;
        revision.requested_permissions[permission_index].max_lease_ticks = permission.max_lease_ticks;
        revision.requested_permissions[permission_index].target_id = permission.target_id;
    }

    revision.background_task_count = @min(source.background_tasks.len, revision.background_tasks.len);
    var background_index: usize = 0;
    while (background_index < revision.background_tasks.len) : (background_index += 1) {
        revision.background_tasks[background_index] = .{};
        if (background_index >= revision.background_task_count) continue;
        const task = source.background_tasks[background_index];
        revision.background_tasks[background_index].id_len = copyText(&revision.background_tasks[background_index].id, task.id);
        revision.background_tasks[background_index].trigger = task.trigger;
        revision.background_tasks[background_index].expected_duration_seconds = task.expected_duration_seconds;
        revision.background_tasks[background_index].budget = task.budget;
        revision.background_tasks[background_index].network = task.network;
        revision.background_tasks[background_index].visibility = task.visibility;
    }

    revision.ai_metadata = .{};
    revision.ai_metadata.model_family_len = copyText(&revision.ai_metadata.model_family, source.ai_metadata.model_family);
    revision.ai_metadata.locality = source.ai_metadata.locality;
    revision.ai_metadata.offline_required = source.ai_metadata.offline_required;

    revision.signature = .{};
    revision.signature.format_len = copyText(&revision.signature.format, source.signature.format);
    revision.signature.signer_len = copyText(&revision.signature.signer, source.signature.signer);
    revision.signature.public_key_len = @min(source.signature.public_key_len, revision.signature.public_key.len);
    @memcpy(
        revision.signature.public_key[0..revision.signature.public_key_len],
        source.signature.public_key[0..revision.signature.public_key_len],
    );
    revision.signature.value_len = @min(source.signature.value_len, revision.signature.value.len);
    @memcpy(
        revision.signature.value[0..revision.signature.value_len],
        source.signature.value[0..revision.signature.value_len],
    );
}
