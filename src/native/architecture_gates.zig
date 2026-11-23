const abi = @import("core/abi.zig");
const contract_2026 = @import("contract_2026.zig");
const cpu_baseline = @import("../arch/cpu_baseline.zig");
const endpoint = @import("kernel_api/endpoint.zig");
const event_wake = @import("../kernel/event_wake.zig");
const ipc_ring = @import("kernel_api/ipc_ring.zig");
const shared_memory = @import("kernel_api/shared_memory.zig");
const storage_driver_task = @import("drivers/storage_driver_task.zig");
const operation_metadata = @import("kernel_api/operation_metadata.zig");
const sync_service = @import("sync/sync_service.zig");
const sync_service_test = @import("sync/sync_service_test.zig");
const sync_transport = @import("sync/sync_transport.zig");
const table_backing = @import("core/table_backing.zig");
const transient_sync_service = @import("sync/transient_service.zig");
const xhci_driver_task = @import("drivers/xhci_driver_task.zig");

pub const generated_from_typed_idl = contract_2026.generated_from_typed_idl;
pub const generated_syscall_operations = operation_metadata.operations.len;

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
    .interrupt_driven_idle = event_wake.INTERRUPT_DRIVEN_IDLE and event_wake.WAKES_RUNTIME_OWNER,
    .unified_table_backing = table_backing.HEAP_BACKS_ON_ALL_TARGETS and table_backing.UNIFIED_ALLOCATOR,
    .ring_default_ipc = ipc_ring.DATA_PLANE_USES_SEALED_RINGS and endpoint.PREFERS_SEALED_RING_DATAPLANE and endpoint.AUTO_ATTACHES_DATA_RINGS and endpoint.RINGS_ONLY_DATAPLANE,
    .userspace_xhci_dataplane = xhci_driver_task.USERSPACE_XHCI_DATAPLANE and
        xhci_driver_task.KERNEL_LATCHES_ONLY and
        xhci_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .userspace_nvme_dataplane = storage_driver_task.USERSPACE_NVME_DATAPLANE and
        storage_driver_task.KERNEL_LATCHES_ONLY and
        storage_driver_task.DISPATCHES_FROM_BOUND_TASK,
    .demand_pages_user_objects = shared_memory.REGISTERS_DEMAND_PAGED_MAPPINGS,
    .canonical_47_bit_user = contract_2026.floor.canonical_47_bit_user,
    .u64_user_stacks = contract_2026.floor.u64_user_stacks,
    .image_2m_pages = contract_2026.floor.image_2m_pages,
    .register_fred_syscalls = contract_2026.floor.register_fred_syscalls,
    .rings_only_ipc = contract_2026.floor.rings_only_ipc,
    .yield_plus_rings = contract_2026.floor.yield_plus_rings,
    .userspace_i225_dataplane = contract_2026.floor.userspace_i225_dataplane,
    .eight_address_spaces = contract_2026.floor.eight_address_spaces,
    .checkpoint_only_cold_load = contract_2026.floor.checkpoint_only_cold_load,
    .generated_syscall_idl = generated_from_typed_idl and generated_syscall_operations == @typeInfo(abi.NativeOperation).@"enum".field_names.len,
};

test "2026 architecture checklist is generated from typed flags" {
    const std = @import("std");
    try std.testing.expect(generated_from_typed_idl);
    try std.testing.expectEqual(@typeInfo(abi.NativeOperation).@"enum".field_names.len, generated_syscall_operations);
    inline for (@typeInfo(@TypeOf(native_2026)).@"struct".field_names) |field| {
        try std.testing.expect(@field(native_2026, field));
    }
    inline for (@typeInfo(contract_2026.Floor).@"struct".field_names) |field| {
        try std.testing.expect(@field(contract_2026.floor, field));
    }
}
