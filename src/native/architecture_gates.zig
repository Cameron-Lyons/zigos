const abi = @import("core/abi.zig");
const contract_2026 = @import("contract_2026.zig");
const cpu_baseline = @import("../arch/cpu_baseline.zig");
const display_driver_task = @import("drivers/display_driver_task.zig");
const display_hw = @import("../kernel/drivers/display_hw.zig");
const compositor_session = @import("platform/compositor_session.zig");
const demand_paging = @import("../kernel/memory/demand_paging.zig");
const endpoint = @import("kernel_api/endpoint.zig");
const event_wake = @import("../kernel/event_wake.zig");
const ipc_ring = @import("kernel_api/ipc_ring.zig");
const service_catalog = @import("session/service_catalog.zig");
const shared_memory = @import("kernel_api/shared_memory.zig");
const storage_driver_task = @import("drivers/storage_driver_task.zig");
const syscall_abi = @import("kernel_api/syscall_abi.zig");
const sync_service = @import("sync/sync_service.zig");
const sync_service_test = @import("sync/sync_service_test.zig");
const sync_transport = @import("sync/sync_transport.zig");
const table_backing = @import("core/table_backing.zig");
const transient_sync_service = @import("sync/transient_service.zig");
const userspace_launch = @import("task/userspace_launch.zig");
const xhci_driver_task = @import("drivers/xhci_driver_task.zig");

pub const generated_from_typed_idl = contract_2026.generated_from_typed_idl;
pub const generated_syscall_operations = syscall_abi.operations.len;

pub const sync_private_overlay = .{
    .native_transport = .{
        .uses_signed_encrypted_frames = @hasField(sync_transport.SignedEncryptedFrame, "signature"),
        .verifies_signed_frames = @hasDecl(sync_transport, "verifySignedFrame"),
        .opens_endpoint_backed_relays = @hasDecl(sync_transport.NativeTransportService, "openRelay"),
        .falls_back_through_relay_service = @hasDecl(sync_transport.NativeTransportService, "sendWithRelayFallback"),
    },
    .service_test = .{
        .runs_deterministic_two_device_overlay_replication = @hasDecl(sync_service_test, "deterministicTwoDeviceOverlayReplication"),
        .opens_overlay_sessions = @hasDecl(sync_service.SyncPort, "openOverlaySession"),
        .replicates_workspaces = @hasDecl(sync_service.SyncPort, "replicateWorkspace"),
        .submits_relay_packets = @hasDecl(sync_transport.Relay, "submit"),
    },
    .sync_service = .{
        .scopes_transient_resident_state = transient_sync_service.TRANSIENT_RESIDENT_STATE_INSTANCE and
            @hasDecl(transient_sync_service, "ResidentInstance"),
        .sends_overlay_relay_frames_via_service_port = @hasDecl(sync_service.Service, "sendOverlayRelayFrameViaService"),
    },
};

pub const native_2026 = .{
    .interrupt_driven_idle = event_wake.INTERRUPT_DRIVEN_IDLE and event_wake.WAKES_PER_CPU,
    .unified_table_backing = table_backing.HEAP_BACKS_ON_ALL_TARGETS and table_backing.UNIFIED_ALLOCATOR,
    .ring_default_ipc = ipc_ring.DATA_PLANE_USES_SEALED_RINGS and endpoint.PREFERS_SEALED_RING_DATAPLANE and endpoint.AUTO_ATTACHES_DATA_RINGS and endpoint.RINGS_ONLY_DATAPLANE,
    .present_by_handle = compositor_session.PRESENTS_BY_HANDLE and display_driver_task.PRESENTS_BY_HANDLE and abi.SURFACE_PRESENT_IS_HANDLE_PLUS_FENCE,
    .userspace_xhci_dataplane = xhci_driver_task.USERSPACE_XHCI_DATAPLANE and
        xhci_driver_task.KERNEL_LATCHES_ONLY and
        xhci_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .userspace_nvme_dataplane = storage_driver_task.USERSPACE_NVME_DATAPLANE and
        storage_driver_task.KERNEL_LATCHES_ONLY and
        storage_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .single_bootstrap_launch_mode = service_catalog.SINGLE_BOOTSTRAP_LAUNCH_MODE and
        userspace_launch.SINGLE_KERNEL_CONTRACT_LAUNCH,
    .demand_pages_user_objects = demand_paging.DEMAND_PAGES_USER_OBJECTS and
        demand_paging.REGISTERS_MAPPED_OBJECTS and
        demand_paging.COPIES_ON_WRITE and
        demand_paging.ISOLATES_REGIONS_BY_SPACE and
        demand_paging.RELEASES_REGIONS_WITH_SPACE and
        shared_memory.REGISTERS_DEMAND_PAGED_MAPPINGS,
    .production_requires_hardware_fred = cpu_baseline.PRODUCTION_REQUIRES_HARDWARE_FRED,
    .fred_only_traps = cpu_baseline.FRED_ONLY_TRAPS,
    .arc_scanout_by_handle = display_hw.PROGRAMS_SCANOUT_HANDLE and display_driver_task.ARC_SCANOUT_PREFERRED,
    .drops_gop_copies = !display_hw.COPIES_GOP_PIXELS,
    .canonical_47_bit_user = contract_2026.floor.canonical_47_bit_user,
    .u64_user_stacks = contract_2026.floor.u64_user_stacks,
    .image_2m_pages = contract_2026.floor.image_2m_pages,
    .lazy_xsaves = contract_2026.floor.lazy_xsaves,
    .register_fred_syscalls = contract_2026.floor.register_fred_syscalls,
    .rings_only_ipc = contract_2026.floor.rings_only_ipc,
    .wait_plus_rings = contract_2026.floor.wait_plus_rings,
    .userspace_i225_dataplane = contract_2026.floor.userspace_i225_dataplane,
    .userspace_gop_dataplane = contract_2026.floor.userspace_gop_dataplane,
    .six_address_spaces = contract_2026.floor.six_address_spaces,
    .checkpoint_only_cold_load = contract_2026.floor.checkpoint_only_cold_load,
    .generated_syscall_idl = generated_from_typed_idl and generated_syscall_operations == @typeInfo(abi.NativeOperation).@"enum".fields.len,
};

test "2026 architecture checklist is generated from typed flags" {
    const std = @import("std");
    try std.testing.expect(generated_from_typed_idl);
    try std.testing.expectEqual(@typeInfo(abi.NativeOperation).@"enum".fields.len, generated_syscall_operations);
    inline for (std.meta.fields(@TypeOf(native_2026))) |field| {
        try std.testing.expect(@field(native_2026, field.name));
    }
    inline for (std.meta.fields(contract_2026.Floor)) |field| {
        try std.testing.expect(@field(contract_2026.floor, field.name));
    }
}
