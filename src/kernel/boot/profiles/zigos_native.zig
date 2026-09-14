const x86 = @import("../../../arch/x86.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const xhci_driver_task = @import("../../../native/drivers/xhci_driver_task.zig");
const event_wake = @import("../../event_wake.zig");
const smp = @import("../../smp.zig");

var recorded_input_report_count: u64 = 0;

pub const INTERRUPT_DRIVEN_IDLE = event_wake.INTERRUPT_DRIVEN_IDLE;

pub fn run() noreturn {
    session_manager.bindHardwareInput(.{
        .poll_report = pollHardwareKeyboardReport,
        .input_proof = hardwareInputProof,
    });
    session_manager.boot();
    while (true) {
        timer.synchronize();
        const now_ticks = timer.getTicks();
        const pending = event_wake.takeAll();

        if (pending.xhci or pending.timer) {
            const bound_task_id = xhci_driver_task.boundTaskId();
            if (bound_task_id == 0) {
                _ = xhci_driver_task.dispatch();
            } else {
                _ = session_manager.wakeUserspaceTask(bound_task_id, now_ticks);
            }
        }
        if (pending.network) {
            _ = session_manager.servicePendingNetworkWork(now_ticks);
        }
        _ = session_manager.runUserspaceScheduler(now_ticks);
        if (pending.xhci or pending.timer) {
            harvestInputProof();
            _ = session_manager.servicePendingInputWork(now_ticks);
        }

        x86.cli();
        const ready_tasks = session_manager.userspaceSchedulerHasReadyTasks();
        if (event_wake.any() or ready_tasks) {
            if (ready_tasks) timer.armSchedulerTick();
            x86.sti();
            continue;
        }
        if (xhci_driver_task.lifecyclePending()) {
            timer.armSchedulerTick();
        } else {
            timer.disarmSchedulerTick();
        }
        smp.idle();
    }
}

fn harvestInputProof() void {
    const input_report_count = xhci_driver_task.keyboardReportCount();
    if (input_report_count == recorded_input_report_count) return;
    const proof = xhci_driver_task.inputProof() orelse return;
    if (xhci_driver_task.controllerDeviceId()) |device_id| {
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

fn pollHardwareKeyboardReport() ?xhci_driver_task.HardwareBootKeyboardReport {
    return xhci_driver_task.pollKeyboardReport();
}

fn hardwareInputProof() ?xhci_driver_task.InputProof {
    return xhci_driver_task.inputProof();
}
