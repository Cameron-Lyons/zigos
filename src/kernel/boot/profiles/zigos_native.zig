const x86 = @import("../../../arch/x86.zig");
const common = @import("../common.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");
const xhci_hw = @import("../../drivers/xhci_hw.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");

var recorded_input_report_count: u64 = 0;

pub fn run() noreturn {
    session_manager.boot();
    while (true) {
        timer.synchronize();
        const now_ticks = timer.getTicks();
        _ = xhci_hw.servicePendingEvents();
        const input_report_count = xhci_hw.keyboardReportCount();
        if (input_report_count != recorded_input_report_count) {
            if (xhci_hw.inputProof()) |proof| {
                if (xhci_hw.controllerDeviceId()) |device_id| {
                    device_inventory.registerDetected(
                        .input_device,
                        device_id,
                        .xhci_inventory,
                        false,
                    );
                }
                hardware_proof.recordInputProof(proof);
                recorded_input_report_count = input_report_count;
            }
        }
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
