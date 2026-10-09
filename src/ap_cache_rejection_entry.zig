pub const kernel_memory = @import("kernel/memory/memory.zig");
pub const kernel_paging = @import("kernel/memory/paging64.zig");
// This image launches only the fixed emulator AP1 for privileged evidence.
pub const ARCHITECTURE_SMP_PROOF = true;
pub const panic = @import("arch/x86_64/ap_cache_rejection_probe.zig").panic;

comptime {
    _ = @import("arch/x86_64/ap_cache_rejection_probe.zig");
}
