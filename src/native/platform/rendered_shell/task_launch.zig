const abi = @import("../../core/abi.zig");
const native_ux = @import("../native_ux.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const package_service = @import("../../services/package_service.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const units = @import("../../core/units.zig");

pub fn startConfiguredTask(
    ux: *native_ux.Controller,
    runtime: *task_runtime.Runtime,
    config: anytype,
) native_ux.Error!*task_runtime.TaskRecord {
    return startConfiguredTaskWithPackageProvenance(ux, runtime, config, .{});
}

pub fn startConfiguredTaskWithPackageProvenance(
    ux: *native_ux.Controller,
    runtime: *task_runtime.Runtime,
    config: anytype,
    provenance: package_service.PackageLaunchProvenance,
) native_ux.Error!*task_runtime.TaskRecord {
    const image = task_runtime.syntheticUserspaceImage(config.task_label, config.task_entry);
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
