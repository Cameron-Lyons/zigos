const x86 = @import("../../../arch/x86.zig");
const common = @import("../common.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");
const xhci = @import("../../drivers/xhci.zig");
const xhci_hw = @import("../../drivers/xhci_hw.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const std = @import("std");
const console = @import("../../utils/console.zig");
const framebuffer_hw = @import("../../platform/framebuffer_hw.zig");
const compositor_view = @import("../../../native/platform/compositor_view.zig");
const boot_markers = @import("../markers.zig");

var recorded_input_report_count: u64 = 0;
var reported_scanout = false;

pub fn run() noreturn {
    framebuffer_hw.init() catch |err| {
        console.print("ZIGOS:DISPLAY:UNAVAILABLE ");
        console.print(@errorName(err));
        console.print("\n");
    };
    session_manager.bindHardwareInput(.{
        .poll_report = pollHardwareKeyboardReport,
        .input_proof = hardwareInputProof,
    });
    session_manager.boot();
    presentCompositor();
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
        const input_work = session_manager.servicePendingInputWork(now_ticks);
        const network_work = session_manager.servicePendingNetworkWork(now_ticks);
        const dispatched = session_manager.runUserspaceScheduler(now_ticks);
        if (input_work != 0 or network_work != 0 or dispatched) presentCompositor();
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

fn presentCompositor() void {
    if (!session_manager.system().initialized) return;
    const frame = framebuffer_hw.frame() orelse return;
    compositor_view.render(frame, session_manager.system().compositorSessionPtr());
    const stats = framebuffer_hw.present() catch return;
    if (!reported_scanout and stats.pixels_written != 0) {
        const info = framebuffer_hw.displayInfo().?;
        var buffer: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{s} width={d} height={d} pixels={d}\n", .{
            boot_markers.compositor_scanout_presented, info.width, info.height, stats.pixels_written,
        }) catch return;
        console.print(line);
        reported_scanout = true;
    }
}

fn pollHardwareKeyboardReport() ?xhci.HardwareBootKeyboardReport {
    return xhci_hw.pollKeyboardReport();
}

fn hardwareInputProof() ?xhci.InputProof {
    return xhci_hw.inputProof();
}
