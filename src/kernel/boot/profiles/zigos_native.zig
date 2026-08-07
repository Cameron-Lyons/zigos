const x86 = @import("../../../arch/x86.zig");
const common = @import("../common.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");
const xhci_hw = @import("../../drivers/xhci_hw.zig");

pub fn run() noreturn {
    session_manager.boot();
    while (true) {
        timer.synchronize();
        const now_ticks = timer.getTicks();
        _ = xhci_hw.servicePendingEvents();
        _ = session_manager.servicePendingNetworkWork(now_ticks);
        _ = session_manager.runUserspaceScheduler(now_ticks);
        x86.cli();
        if (xhci_hw.eventWorkPending() or session_manager.networkWorkPending()) {
            x86.sti();
            continue;
        }
        if (session_manager.userspaceSchedulerHasReadyTasks() or xhci_hw.lifecyclePending()) {
            timer.armSchedulerTick();
        } else {
            timer.disarmSchedulerTick();
        }
        x86.sti();
        x86.hlt();
    }
}
