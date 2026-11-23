//! Native sources measured by the hosted `tools/benchmark_*.zig` programs,
//! one namespace per benchmark. The build imports this root as
//! `host_benchmarks` with `build_options` and `binary_cursor`.

pub const frame_allocator = @import("kernel/memory/frame_allocator.zig");
pub const heap = @import("kernel/memory/memory.zig");
pub const ipc_ring = @import("native/kernel_api/ipc_ring.zig");
pub const id_index = @import("native/core/id_index.zig");
pub const text_layout = @import("native/core/text_layout.zig");
pub const abi = @import("native/core/abi.zig");

pub const endpoint = struct {
    const table = @import("native/kernel_api/endpoint.zig");

    pub const ids = @import("native/core/ids.zig");
    pub const Table = table.Table;
    pub const MAX_ENDPOINTS = table.MAX_ENDPOINTS;
    pub const MAX_MESSAGE_BYTES = table.MAX_MESSAGE_BYTES;
    pub const no_index = @import("native/core/indexed_arena.zig").no_index;
};

pub const response_preflight = struct {
    const dispatch = @import("native/kernel_api/syscall_dispatch.zig");

    pub const UserMemoryContext = dispatch.UserMemoryContext;
    pub const DispatchResult = dispatch.DispatchResult;
    pub const AddressSpaceRecord = @import("native/task/task_runtime.zig").AddressSpaceRecord;
    pub const preflightResponse = dispatch.preflightResponse;
    pub const validateUserRange = dispatch.validateUserRange;
    pub const prepareUserRange = dispatch.prepareUserRange;
};

pub const text_scanout = struct {
    pub const scanout = @import("kernel/platform/text_scanout.zig");
    pub const framebuffer = @import("kernel/platform/framebuffer.zig");
};

pub const workspace_index = struct {
    pub const workspace_index = @import("native/storage/workspace/index.zig");
    pub const id_index = @import("native/core/id_index.zig");
};

pub const object_chunks = struct {
    pub const objects = @import("native/storage/object_store.zig");
    pub const signing = @import("native/core/signing.zig");
    pub const crypto_hash = @import("native/core/crypto_hash.zig");
    pub const MAX_TRANSFER_CHUNK = @import("native/sync/object_transfer.zig").MAX_CHUNK;
};

pub const scheduler = struct {
    const task_runtime = @import("native/task/task_runtime.zig");

    pub const Scheduler = @import("native/task/userspace_scheduler.zig").Scheduler;
    pub const Runtime = task_runtime.Runtime;
    pub const MAX_TASKS = task_runtime.MAX_TASKS;
    pub const syntheticUserspaceImage = task_runtime.syntheticUserspaceImage;
    pub const Executor = @import("native/task/userspace_executor.zig").Executor;
    pub const Catalog = @import("native/task/userspace_loader.zig").Catalog;
    pub const CapabilityTable = @import("native/kernel_api/capability.zig").CapabilityTable;
    pub const units = @import("native/core/units.zig");
};
