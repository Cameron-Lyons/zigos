const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../../core/abi.zig");
const event_ledger = @import("../event_ledger.zig");
const generated_image_fixtures = @import("../../task/generated_image_fixtures.zig");
const ids = @import("../../core/ids.zig");
const native_ux = @import("../native_ux.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const package_service = @import("../../services/package_service.zig");
const storage_service = @import("../../storage/storage_service.zig");
const workspace = @import("../../storage/workspace.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const units = @import("../../core/units.zig");

pub const Error = native_ux.Error || generated_image_fixtures.Error;
pub const FlowError = event_ledger.Error || error{MissingTaskFlow};
pub const RecoveryError = error{RecoveryStateMissing};
pub const TaskLookupError = error{TaskRequired};

pub inline fn requireTask(runtime: *task_runtime.Runtime, task_id: u64) TaskLookupError!*task_runtime.TaskRecord {
    if (task_id == 0) return error.TaskRequired;
    return runtime.find(task_id) orelse error.TaskRequired;
}

pub inline fn openConfiguredWorkspace(
    ux: *native_ux.Controller,
    storage: *storage_service.Service,
    config: anytype,
) native_ux.Error!workspace.Entry {
    return ux.openWorkspace(
        storage,
        ids.workspace(config.workspace_id),
        config.document_path,
        config.user,
    );
}

pub inline fn openConfiguredDocument(
    ux: *native_ux.Controller,
    storage: *storage_service.Service,
    config: anytype,
    task_id: u64,
) native_ux.Error!workspace.Entry {
    return ux.openDocument(
        storage,
        ids.workspace(config.workspace_id),
        config.document_path,
        task_id,
        config.user,
    );
}

pub inline fn recordPendingTaskFlows(
    ux: *const native_ux.Controller,
    ledger: *event_ledger.Ledger,
    next_flow_order: *usize,
    tick: u64,
) FlowError!void {
    while (next_flow_order.* < ux.flow_count) : (next_flow_order.* += 1) {
        const flow = ux.flowAtOrder(next_flow_order.*) orelse return error.MissingTaskFlow;
        try ledger.recordTaskFlow(flow.*, tick);
    }
}

pub inline fn recoverRuntimeAndCompositor(
    runtime_service: anytype,
    compositor_service: anytype,
    tick: u64,
) RecoveryError!void {
    if (!runtime_service.restartFromCheckpoint(tick)) return error.RecoveryStateMissing;
    const response = compositor_service.dispatch(.{ .operation = .recover_state });
    if (response.status != .ok or !response.recovered) return error.RecoveryStateMissing;
}

pub inline fn recoverCheckpointedTaskState(
    runtime_service: anytype,
    compositor_service: anytype,
    checkpoint_store: anytype,
    state: anytype,
    tick: u64,
) RecoveryError!void {
    if (!checkpoint_store.valid) return error.RecoveryStateMissing;
    try recoverRuntimeAndCompositor(runtime_service, compositor_service, tick);
    state.* = checkpoint_store.state;
    if (state.task_id != 0 and runtime_service.runtimePtr().find(state.task_id) == null) {
        return error.RecoveryStateMissing;
    }
}

pub fn startConfiguredTask(
    ux: *native_ux.Controller,
    runtime: *task_runtime.Runtime,
    config: anytype,
) Error!*task_runtime.TaskRecord {
    return startConfiguredTaskWithPackageProvenance(ux, runtime, config, .{});
}

pub fn startConfiguredTaskWithPackageProvenance(
    ux: *native_ux.Controller,
    runtime: *task_runtime.Runtime,
    config: anytype,
    provenance: package_service.PackageLaunchProvenance,
) Error!*task_runtime.TaskRecord {
    const image = try imageForConfig(config, builtin.is_test);
    return ux.startTask(runtime, .{
        .owner = config.app_owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_200,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 2,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .ui_surface_id = config.ui_surface_id,
        .local_only = true,
        .initial_component = .{
            .label = config.task_label,
            .entry = config.task_entry,
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = config.image_id,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = config.bundle_id,
            .source_identity = provenance.source_identity,
            .release_transparency_sequence = provenance.release_transparency.sequence,
            .release_transparency_root = provenance.release_transparency.root,
            .release_transparency_log_head = provenance.release_transparency.log_head,
        },
        .userspace_image = &image,
    });
}

fn imageForConfig(config: anytype, allow_model_only_fallback: bool) generated_image_fixtures.Error!task_runtime.ExecutableImageSpec {
    return generated_image_fixtures.imageByBundleId(config.bundle_id) catch |err| switch (err) {
        error.GeneratedImageMissing => {
            if (std.mem.eql(u8, config.bundle_id, "app.notes.daily")) {
                return generated_image_fixtures.imageByBundleId("app.notes");
            }
            if (!allow_model_only_fallback) return err;

            // prod-readiness: model-only synthetic-userspace-image
            return task_runtime.syntheticUserspaceImage(config.task_label, config.task_entry);
        },
        else => return err,
    };
}

test "rendered shell task launch requires generated image outside model-only tests" {
    const config = .{
        .task_label = "unknown",
        .task_entry = "app.unknown",
        .bundle_id = "app.unknown",
    };

    try @import("std").testing.expectError(error.GeneratedImageMissing, imageForConfig(config, false));
}

test "rendered shell task launch resolves generated archive images for registered bundles" {
    const config = .{
        .task_label = "notes",
        .task_entry = "app.notes",
        .bundle_id = "app.notes",
    };

    const image = try imageForConfig(config, false);
    try @import("std").testing.expect(image.isPresent());
}

test "rendered shell task launch resolves daily driver bundle without model fallback" {
    const config = .{
        .task_label = "notes-daily",
        .task_entry = "app.notes",
        .bundle_id = "app.notes.daily",
    };

    const image = try imageForConfig(config, false);
    try @import("std").testing.expect(image.isPresent());
}
