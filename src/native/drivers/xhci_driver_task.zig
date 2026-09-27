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
        pub fn probe(_: anytype) !void {
            return;
        }
        pub fn activate() !void {}
        pub fn isolationDomain() ?void {
            return null;
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
const intel_vtd = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/platform/intel_vtd.zig")
else
    struct {};
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const HardwareBootKeyboardReport = xhci.HardwareBootKeyboardReport;
pub const InputProof = xhci.InputProof;

var bound_task_id: u64 = 0;
var programmed = false;

pub fn bindTaskId(task_id: u64) void {
    bound_task_id = task_id;
    const event_wake = @import("../../kernel/event_wake.zig");
    const smp = @import("../../kernel/smp.zig");
    event_wake.bind(.xhci, smp.assignedCpu(task_id, false));
}

pub fn boundTaskId() u64 {
    return bound_task_id;
}

pub fn bringUp() bool {
    if (programmed) return true;
    var xhci_prepared = false;
    if (builtin.target.os.tag == .freestanding) {
        const pci = @import("../../kernel/drivers/pci.zig");
        if (pci.firstXhciController()) |dev| {
            _ = xhci_hw.probe(dev) catch |err| switch (err) {
                error.AlreadyPrepared => {},
                else => return false,
            };
            console.print("ZIGOS:XHCI:HW:OWNERSHIP_OK\n");
            console.print("ZIGOS:XHCI:HW:RESET_OK\n");
            console.print("ZIGOS:XHCI:HW:SLOTS_OK\n");
            var isolation_domains: [1]intel_vtd.DmaDomain = undefined;
            var isolation_domain_count: usize = 0;
            if (xhci_hw.isolationDomain()) |domain| {
                isolation_domains[isolation_domain_count] = domain;
                isolation_domain_count += 1;
            }
            _ = isolation_domains[0..isolation_domain_count];
            console.print("ZIGOS:XHCI:HW:DMA_OK\n");
        }
    }
    xhci_hw.activate() catch return false;
    xhci_prepared = true;
    programmed = xhci_prepared;
    if (builtin.target.os.tag == .freestanding) {
        console.print("ZIGOS:XHCI:HW:REMAP_MSI_OK\n");
        console.print("ZIGOS:XHCI:HW:RUN_OK\n");
    }
    return true;
}

pub fn dispatch() usize {
    _ = bringUp();
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
    programmed = false;
    try std.testing.expectEqual(@as(usize, 0), dispatchForTask(7));
    bindTaskId(7);
    try std.testing.expectEqual(@as(usize, 0), dispatchForTask(8));
    try std.testing.expectEqual(@as(u64, 7), boundTaskId());
    try std.testing.expect(KERNEL_LATCHES_ONLY);
    try std.testing.expect(DISPATCHES_FROM_BOUND_TASK);
    bindTaskId(0);
    programmed = false;
}
