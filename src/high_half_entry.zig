pub const kernel_memory = @import("kernel/memory/memory.zig");
pub const kernel_paging = @import("kernel/memory/paging64.zig");
// This image binds a fixed emulator topology solely for privileged evidence.
pub const ARCHITECTURE_SMP_PROOF = true;
pub const panic = @import("arch/x86_64/high_half_probe.zig").panic;

pub fn publishUserspaceActiveTaskId(task_id: u64) void {
    @import("arch/x86_64/native_entry_state.zig").current().active_task_id = task_id;
}

// The cold stack transaction links the unchanged FRED entry for its exact
// address readback. This image keeps FRED off and never admits native syscalls.
export fn syscall_handler(_: *anyopaque) callconv(.c) void {
    @import("arch/x86_64/high_half_probe.zig").fail("unexpected isolated native syscall entry");
}

comptime {
    _ = @import("arch/x86_64/high_half_probe.zig");
}
