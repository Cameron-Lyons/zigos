const builtin = @import("builtin");

pub const USERSPACE_XHCI_DATAPLANE = true;
pub const KERNEL_LATCHES_ONLY = true;
pub const DISPATCHES_FROM_BOUND_TASK = true;

const xhci = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/xhci.zig")
else
    struct {
        pub const HardwareBootKeyboardReport = struct {};
        pub const InputProof = struct {};
    };

const xhci_hw = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/xhci_hw.zig")
else
    struct {
        pub fn servicePendingEvents() usize {
            return 0;
        }
        pub fn eventWorkPending() bool {
            return false;
        }
        pub fn lifecyclePending() bool {
            return false;
        }
        pub fn keyboardReportCount() u64 {
            return 0;
        }
        pub fn pollKeyboardReport() ?xhci.HardwareBootKeyboardReport {
            return null;
        }
        pub fn inputProof() ?xhci.InputProof {
            return null;
        }
        pub fn controllerDeviceId() ?u64 {
            return null;
        }
    };

pub const HardwareBootKeyboardReport = xhci.HardwareBootKeyboardReport;
pub const InputProof = xhci.InputProof;

var bound_task_id: u64 = 0;

pub fn bindTaskId(task_id: u64) void {
    bound_task_id = task_id;
}

pub fn boundTaskId() u64 {
    return bound_task_id;
}

pub fn dispatch() usize {
    return xhci_hw.servicePendingEvents();
}

pub fn dispatchForTask(task_id: u64) usize {
    if (task_id == 0 or task_id != bound_task_id) return 0;
    return dispatch();
}

pub fn serviceController() usize {
    return dispatch();
}

pub fn workPending() bool {
    return xhci_hw.eventWorkPending() or xhci_hw.lifecyclePending();
}

pub fn lifecyclePending() bool {
    return xhci_hw.lifecyclePending();
}

pub fn keyboardReportCount() u64 {
    return xhci_hw.keyboardReportCount();
}

pub fn pollKeyboardReport() ?HardwareBootKeyboardReport {
    return xhci_hw.pollKeyboardReport();
}

pub fn inputProof() ?InputProof {
    return xhci_hw.inputProof();
}

pub fn controllerDeviceId() ?u64 {
    return xhci_hw.controllerDeviceId();
}

test "xhci driver task dispatches only for the bound task" {
    const std = @import("std");
    bindTaskId(0);
    try std.testing.expectEqual(@as(usize, 0), dispatchForTask(7));
    bindTaskId(7);
    try std.testing.expectEqual(@as(usize, 0), dispatchForTask(8));
    try std.testing.expectEqual(@as(u64, 7), boundTaskId());
    try std.testing.expect(KERNEL_LATCHES_ONLY);
    try std.testing.expect(DISPATCHES_FROM_BOUND_TASK);
    bindTaskId(0);
}
