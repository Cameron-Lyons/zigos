const x86 = @import("../../../arch/x86.zig");
const common = @import("../common.zig");
const session_manager = @import("../../process/native/session_manager.zig");
const timer = @import("../../timer/timer.zig");

pub fn run() noreturn {
    session_manager.boot();
    while (true) {
        _ = session_manager.runUserspaceScheduler(timer.getTicks());
        x86.sti();
        x86.hlt();
    }
}
