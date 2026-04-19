const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

const copyTextExact = native_util.copyTextExact;

pub const Error = manifest.ValidationError || error{
    MigrationManifestTooLong,
};

pub fn validateInstallTarget(
    comptime InstalledBundleType: type,
    bundle: manifest.BundleManifest,
    migration_manifest: []const u8,
) Error!void {
    const RevisionType = arrayFieldChildType(InstalledBundleType, "revisions");
    const StoredComponentType = arrayFieldChildType(RevisionType, "components");
    const StoredAssetType = arrayFieldChildType(RevisionType, "assets");
    const StoredInterfaceType = arrayFieldChildType(RevisionType, "provided_interfaces");
    const StoredPermissionType = arrayFieldChildType(RevisionType, "requested_permissions");
    const StoredBackgroundTaskType = arrayFieldChildType(RevisionType, "background_tasks");
    const StoredAiMetadataType = @FieldType(RevisionType, "ai_metadata");
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
    for (bundle.requested_permissions) |permission| {
        try validateTextLen(permission.resource, arrayFieldLen(StoredPermissionType, "resource"), error.PermissionResourceTooLong);
    }
    for (bundle.background_tasks) |task| {
        try validateTextLen(task.id, arrayFieldLen(StoredBackgroundTaskType, "id"), error.BackgroundTaskIdTooLong);
    }

    if (migration_manifest.len > arrayFieldLen(InstalledBundleType, "last_migration_manifest")) {
        return error.MigrationManifestTooLong;
    }
}

pub fn installNew(
    bundle: anytype,
    source: manifest.BundleManifest,
    data_schema_version: u32,
    permission_digest: [32]u8,
    migration_manifest: []const u8,
) Error!void {
    const BundleType = storageType(@TypeOf(bundle));
    try validateInstallTarget(BundleType, source, migration_manifest);

    bundle.bundle_id_len = copyTextExact(&bundle.bundle_id, source.bundle_id) catch return error.BundleIdTooLong;
    bundle.revision_count = 1;
    bundle.next_revision_id = 2;
    bundle.active_revision_slot = 0;
    bundle.rollback_revision_slot = null;
    try writeRevision(&bundle.revisions[0], source, data_schema_version, permission_digest, 1);
    bundle.last_migration_manifest_len = copyTextExact(&bundle.last_migration_manifest, migration_manifest) catch return error.MigrationManifestTooLong;
}

pub fn installRevision(
    bundle: anytype,
    source: manifest.BundleManifest,
    data_schema_version: u32,
    permission_digest: [32]u8,
    migration_manifest: []const u8,
) Error!void {
    const BundleType = storageType(@TypeOf(bundle));
    try validateInstallTarget(BundleType, source, migration_manifest);

    const target_slot = bundle.inactiveRevisionSlot();
    try writeRevision(&bundle.revisions[target_slot], source, data_schema_version, permission_digest, bundle.next_revision_id);
    bundle.next_revision_id += 1;
    if (bundle.revision_count == 0) {
        bundle.revision_count = 1;
    } else if (bundle.revision_count < bundle.revisions.len) {
        bundle.revision_count += 1;
    }
    bundle.rollback_revision_slot = bundle.active_revision_slot;
    bundle.active_revision_slot = target_slot;
    bundle.last_migration_manifest_len = copyTextExact(&bundle.last_migration_manifest, migration_manifest) catch return error.MigrationManifestTooLong;
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
) Error!void {
    revision.revision_id = revision_id;
    revision.display_name_len = copyTextExact(&revision.display_name, source.display_name) catch return error.DisplayNameTooLong;
    revision.publisher_len = copyTextExact(&revision.publisher, source.publisher) catch return error.PublisherTooLong;
    revision.version_major = source.version_major;
    revision.version_minor = source.version_minor;
    revision.channel = source.update_channel;
    revision.permission_digest = permission_digest;
    revision.schema_version = data_schema_version;
    try writeLaunchMetadata(revision, source);
    try writeManifestMetadata(revision, source);
}

fn writeLaunchMetadata(revision: anytype, source: manifest.BundleManifest) Error!void {
    if (source.components.len > revision.components.len) return error.TooManyComponents;
    revision.component_count = source.components.len;
    for (source.components, 0..) |component, component_index| {
        revision.components[component_index].id_len = copyTextExact(&revision.components[component_index].id, component.id) catch return error.ComponentIdTooLong;
        revision.components[component_index].entry_len = copyTextExact(&revision.components[component_index].entry, component.entry) catch return error.ComponentEntryTooLong;
        revision.components[component_index].abi = component.abi;
    }

    if (source.assets.len > revision.assets.len) return error.TooManyAssets;
    revision.asset_count = source.assets.len;
    for (source.assets, 0..) |asset, asset_index| {
        revision.assets[asset_index].path_len = copyTextExact(&revision.assets[asset_index].path, asset.path) catch return error.AssetPathTooLong;
        revision.assets[asset_index].content_type_len = copyTextExact(&revision.assets[asset_index].content_type, asset.content_type) catch return error.AssetContentTypeTooLong;
    }
}

fn writeManifestMetadata(revision: anytype, source: manifest.BundleManifest) Error!void {
    if (source.provided_interfaces.len > revision.provided_interfaces.len) return error.TooManyProvidedInterfaces;
    revision.provided_interface_count = source.provided_interfaces.len;
    for (source.provided_interfaces, 0..) |interface, interface_index| {
        revision.provided_interfaces[interface_index].name_len = copyTextExact(&revision.provided_interfaces[interface_index].name, interface.name) catch return error.InterfaceNameTooLong;
        revision.provided_interfaces[interface_index].version_major = interface.version_major;
        revision.provided_interfaces[interface_index].version_minor = interface.version_minor;
    }

    if (source.consumed_interfaces.len > revision.consumed_interfaces.len) return error.TooManyConsumedInterfaces;
    revision.consumed_interface_count = source.consumed_interfaces.len;
    for (source.consumed_interfaces, 0..) |interface, interface_index| {
        revision.consumed_interfaces[interface_index].name_len = copyTextExact(&revision.consumed_interfaces[interface_index].name, interface.name) catch return error.InterfaceNameTooLong;
        revision.consumed_interfaces[interface_index].version_major = interface.version_major;
        revision.consumed_interfaces[interface_index].version_minor = interface.version_minor;
    }

    if (source.requested_permissions.len > revision.requested_permissions.len) return error.TooManyPermissions;
    revision.requested_permission_count = source.requested_permissions.len;
    for (source.requested_permissions, 0..) |permission, permission_index| {
        revision.requested_permissions[permission_index].kind = permission.kind;
        revision.requested_permissions[permission_index].resource_len = copyTextExact(&revision.requested_permissions[permission_index].resource, permission.resource) catch return error.PermissionResourceTooLong;
        revision.requested_permissions[permission_index].rights = permission.rights;
        revision.requested_permissions[permission_index].required = permission.required;
        revision.requested_permissions[permission_index].local_only = permission.local_only;
        revision.requested_permissions[permission_index].max_lease_ticks = permission.max_lease_ticks;
        revision.requested_permissions[permission_index].target_id = permission.target_id;
    }

    if (source.background_tasks.len > revision.background_tasks.len) return error.TooManyBackgroundTasks;
    revision.background_task_count = source.background_tasks.len;
    for (source.background_tasks, 0..) |task, background_index| {
        revision.background_tasks[background_index].id_len = copyTextExact(&revision.background_tasks[background_index].id, task.id) catch return error.BackgroundTaskIdTooLong;
        revision.background_tasks[background_index].trigger = task.trigger;
        revision.background_tasks[background_index].expected_duration_seconds = task.expected_duration_seconds;
        revision.background_tasks[background_index].budget = task.budget;
        revision.background_tasks[background_index].network = task.network;
        revision.background_tasks[background_index].visibility = task.visibility;
    }

    revision.ai_metadata = .{};
    revision.ai_metadata.model_family_len = copyTextExact(&revision.ai_metadata.model_family, source.ai_metadata.model_family) catch return error.AiModelFamilyTooLong;
    revision.ai_metadata.locality = source.ai_metadata.locality;
    revision.ai_metadata.offline_required = source.ai_metadata.offline_required;

    revision.signature = .{};
    revision.signature.format_len = copyTextExact(&revision.signature.format, source.signature.format) catch return error.SignatureFormatTooLong;
    revision.signature.signer_len = copyTextExact(&revision.signature.signer, source.signature.signer) catch return error.SignatureSignerTooLong;
    revision.signature.public_key_len = source.signature.public_key_len;
    revision.signature.public_key = source.signature.public_key;
    revision.signature.value_len = source.signature.value_len;
    revision.signature.value = source.signature.value;
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
