pub const kernel_memory = @import("kernel/memory/memory.zig");
pub const kernel_paging = @import("kernel/memory/paging64.zig");
pub const ARCHITECTURE_SMP_PROOF = true;
pub const MAPPING_XSTATE_PROOF = true;
pub const panic = @import("arch/x86_64/high_half_probe.zig").panic;

pub fn publishUserspaceActiveTaskId(task_id: u64) void {
    @import("arch/x86_64/native_entry_state.zig").current().active_task_id = task_id;
}

// This fixed-topology CPL0 artifact never admits native privilege entry.
export fn syscall_handler(_: *anyopaque) callconv(.c) void {
    @import("arch/x86_64/high_half_probe.zig").fail("unexpected Mapping-state native syscall entry");
}

comptime {
    _ = @import("arch/x86_64/high_half_probe.zig");
}
