const x86 = @import("../../../arch/x86.zig");
const common = @import("../common.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");

pub fn run() noreturn {
    session_manager.boot();
    while (true) {
        timer.synchronize();
        _ = session_manager.runUserspaceScheduler(timer.getTicks());
        x86.cli();
        if (session_manager.userspaceSchedulerHasReadyTasks()) {
            timer.armSchedulerTick();
        } else {
            timer.disarmSchedulerTick();
        }
        x86.sti();
        x86.hlt();
    }
}
