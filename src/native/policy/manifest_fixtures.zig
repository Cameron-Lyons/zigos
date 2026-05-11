const manifest = @import("manifest.zig");

pub const notes_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "notes", .entry = "app.notes" },
};

pub const notes_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.workspace.document" },
};

pub const notes_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.object.workspace" },
};

pub const notes_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" },
};

pub const notes_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace:notes",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
        .max_lease_ticks = 400,
    },
    .{
        .kind = .network_egress,
        .resource = "lan.sync",
        .rights = .{ .network_policy = .{ .network_local = true } },
        .required = false,
        .local_only = true,
        .max_lease_ticks = 50,
    },
    .{
        .kind = .clipboard,
        .resource = "clipboard",
        .rights = .{ .workspace = .{ .clipboard_read = true, .clipboard_write = true } },
        .required = false,
    },
};

pub const sync_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "sync", .entry = "app.sync" },
};

pub const sync_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.sync.replication" },
};

pub const sync_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "zigos.object.workspace" },
};

pub const sync_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/sync/icon.svg", .content_type = "image/svg+xml" },
};

pub const sync_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .background_execution,
        .resource = "sync",
        .rights = .{ .task = .{ .background_run = true } },
    },
};

pub const sync_completion_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "sync",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 128 * 1024,
            .shared_memory_bytes = 8 * 1024,
        },
        .network = .local_network_only,
        .visibility = .status_only,
    },
};

pub const sync_push_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "sync",
        .trigger = .push_event,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
        },
    },
};

pub const example_writer_components = [_]manifest.ExecutionComponentDecl{
    .{ .id = "writer-ui", .entry = "com.example.writer.ui" },
};

pub const example_writer_provided_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "writer.edit/v1" },
};

pub const example_writer_consumed_interfaces = [_]manifest.InterfaceDecl{
    .{ .name = "documents.open/v1" },
    .{ .name = "export.pdf/v1" },
};

pub const example_writer_assets = [_]manifest.AssetDecl{
    .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
};

pub const example_writer_permissions = [_]manifest.PermissionRequest{
    .{
        .kind = .object_access,
        .resource = "workspace://report-alpha",
        .rights = .{ .object = .{ .object_read = true, .object_write = true } },
        .local_only = true,
    },
    .{
        .kind = .network_egress,
        .resource = "sync.example.com",
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .required = false,
    },
    .{
        .kind = .background_execution,
        .resource = "sync-complete",
        .rights = .{ .task = .{ .background_run = true } },
        .required = false,
    },
};

pub const example_writer_background_tasks = [_]manifest.BackgroundTaskDecl{
    .{
        .id = "sync-complete",
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 64 * 1024,
        },
        .network = .none,
        .visibility = .status_only,
    },
};

pub fn notesBundle() manifest.BundleManifest {
    return .{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .provided_interfaces = &notes_provided_interfaces,
        .consumed_interfaces = &notes_consumed_interfaces,
        .components = &notes_components,
        .assets = &notes_assets,
        .requested_permissions = &notes_permissions,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
    };
}

pub fn syncBundle() manifest.BundleManifest {
    return .{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .provided_interfaces = &sync_provided_interfaces,
        .consumed_interfaces = &sync_consumed_interfaces,
        .components = &sync_components,
        .assets = &sync_assets,
        .requested_permissions = &sync_permissions,
        .background_tasks = &sync_completion_background_tasks,
        .update_channel = .stable,
    };
}

pub fn syncPushBundle() manifest.BundleManifest {
    var bundle = syncBundle();
    bundle.background_tasks = &sync_push_background_tasks;
    return bundle;
}

pub fn exampleWriterBundle() manifest.BundleManifest {
    return .{
        .bundle_id = "com.example.writer",
        .display_name = "Writer",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 4,
        .provided_interfaces = &example_writer_provided_interfaces,
        .consumed_interfaces = &example_writer_consumed_interfaces,
        .components = &example_writer_components,
        .assets = &example_writer_assets,
        .requested_permissions = &example_writer_permissions,
        .background_tasks = &example_writer_background_tasks,
    };
}
