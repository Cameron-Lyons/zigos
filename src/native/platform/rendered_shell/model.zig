const manifest = @import("../../policy/manifest.zig");
const principal = @import("../../core/principal.zig");

pub const Control = enum {
    start_task,
    open_workspace,
    open_document,
    open_app_panel,
    focus_full_screen,
};

pub const JourneyControl = enum {
    install_app,
    start_task,
    open_workspace,
    open_document,
    open_app_panel,
    review_permission,
    sync_workspace,
    update_app,
    rollback_update,
    containment_denial,
    recover_system,
    remove_app,
};

pub const Config = struct {
    user: principal.PrincipalId,
    app_owner: principal.PrincipalId,
    reviewer_task_id: u64 = 0,
    workspace_id: u64,
    workspace_label: []const u8,
    document_path: []const u8,
    task_label: []const u8,
    task_entry: []const u8,
    task_title: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    ui_surface_id: u64,
    image_id: u64,
};

pub const JourneyConfig = struct {
    user: principal.PrincipalId,
    app_owner: principal.PrincipalId,
    reviewer_task_id: u64,
    workspace_id: u64,
    workspace_label: []const u8,
    document_path: []const u8,
    task_label: []const u8,
    task_entry: []const u8,
    task_title: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    source_identity: []const u8,
    install_bundle: manifest.BundleManifest,
    update_bundle: manifest.BundleManifest,
    ui_surface_id: u64,
    image_id: u64,
    sync_from_device: principal.PrincipalId,
    sync_to_device: principal.PrincipalId,
};
