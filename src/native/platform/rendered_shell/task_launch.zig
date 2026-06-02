const abi = @import("../../core/abi.zig");
const native_ux = @import("../native_ux.zig");
const task_runtime = @import("../../task/task_runtime.zig");

pub fn startConfiguredTask(
    ux: *native_ux.Controller,
    runtime: *task_runtime.Runtime,
    config: anytype,
) native_ux.Error!*task_runtime.TaskRecord {
    const image = task_runtime.syntheticUserspaceImage(config.task_label, config.task_entry);
    return ux.startTask(runtime, .{
        .owner = config.app_owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_200,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 4096,
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
        },
        .userspace_image = &image,
    });
}
