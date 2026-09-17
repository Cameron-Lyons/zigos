const endpoint = @import("kernel_api/endpoint.zig");
const ipc_ring = @import("kernel_api/ipc_ring.zig");
const syscall_surface = @import("kernel_api/syscall_surface.zig");
const shared_memory = @import("kernel_api/shared_memory.zig");
const display_driver_task = @import("drivers/display_driver_task.zig");
const network_driver_task = @import("drivers/network_driver_task.zig");
const storage_driver_task = @import("drivers/storage_driver_task.zig");
const xhci_driver_task = @import("drivers/xhci_driver_task.zig");
const userspace_layout = @import("core/userspace_layout.zig");
const userspace_registry = @import("task/userspace_registry.zig");
const userspace_executor = @import("task/userspace_executor.zig");
const task_runtime = @import("task/task_runtime.zig");
const storage_volume = @import("storage/storage_volume.zig");
const cpu_baseline = @import("../arch/cpu_baseline.zig");
const x86 = @import("../arch/x86.zig");

pub const generated_from_typed_idl = true;

pub const Floor = struct {
    canonical_47_bit_user: bool,
    u64_user_stacks: bool,
    image_2m_pages: bool,
    lazy_xsaves: bool,
    register_fred_syscalls: bool,
    rings_only_ipc: bool,
    userspace_nvme_dataplane: bool,
    userspace_i225_dataplane: bool,
    userspace_xhci_dataplane: bool,
    userspace_gop_dataplane: bool,
    six_address_spaces: bool,
    checkpoint_only_cold_load: bool,
    fred_only_traps: bool,
};

pub const floor: Floor = .{
    .canonical_47_bit_user = userspace_layout.user_end_exclusive == 0x0000_8000_0000_0000 and
        userspace_layout.stack_start == 0x0000_007F_0000_0000,
    .u64_user_stacks = task_runtime.UserStackByteLength == u64,
    .image_2m_pages = userspace_layout.USES_2M_IMAGE_PAGES and
        userspace_layout.image_start % userspace_layout.huge_page_size == 0,
    .lazy_xsaves = x86.LAZY_XSAVES,
    .register_fred_syscalls = syscall_surface.REGISTER_FRED_SYSCALLS and cpu_baseline.FRED_ONLY_TRAPS,
    .rings_only_ipc = ipc_ring.DATA_PLANE_USES_SEALED_RINGS and
        endpoint.RINGS_ONLY_DATAPLANE and
        endpoint.AUTO_ATTACHES_DATA_RINGS and
        shared_memory.SEALS_IPC_RINGS,
    .userspace_nvme_dataplane = storage_driver_task.USERSPACE_NVME_DATAPLANE and
        storage_driver_task.KERNEL_LATCHES_ONLY and
        storage_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .userspace_i225_dataplane = network_driver_task.USERSPACE_I225_DATAPLANE and
        network_driver_task.KERNEL_LATCHES_ONLY,
    .userspace_xhci_dataplane = xhci_driver_task.USERSPACE_XHCI_DATAPLANE and
        xhci_driver_task.KERNEL_LATCHES_ONLY and
        xhci_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .userspace_gop_dataplane = display_driver_task.USERSPACE_GOP_DATAPLANE and
        display_driver_task.KERNEL_LATCHES_ONLY and
        display_driver_task.PRESENTS_BY_HANDLE,
    .six_address_spaces = userspace_registry.PRODUCTION_ADDRESS_SPACE_COUNT == 6 and
        userspace_registry.COLOCATES_SERVICES_BY_ADDRESS_SPACE_GROUP and
        userspace_registry.SHARES_GROUP_PAGE_TABLES and
        userspace_executor.SHARES_GROUP_PAGE_TABLES,
    .checkpoint_only_cold_load = storage_volume.USES_INCREMENTAL_LIVE_INDEX and
        storage_volume.USES_CHECKPOINT_ONLY_COLD_LOAD,
    .fred_only_traps = cpu_baseline.FRED_ONLY_TRAPS,
};

test "2026 contract floor is generated from typed flags" {
    const std = @import("std");
    try std.testing.expect(generated_from_typed_idl);
    inline for (std.meta.fields(Floor)) |field| {
        try std.testing.expect(@field(floor, field.name));
    }
}
