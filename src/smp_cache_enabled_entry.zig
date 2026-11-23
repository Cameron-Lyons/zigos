pub const kernel_memory = @import("kernel/memory/memory.zig");
pub const kernel_paging = @import("kernel/memory/paging64.zig");
// This image owns only an isolated offline AP cache-policy fixture.
pub const ARCHITECTURE_SMP_PROOF = true;
pub const panic = @import("probes/smp_cache_enabled_probe.zig").panic;

pub export fn kernel_main() callconv(.c) noreturn {
    @import("probes/smp_cache_enabled_probe.zig").main();
}
