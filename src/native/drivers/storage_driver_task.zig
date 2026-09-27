const builtin = @import("builtin");

pub const USERSPACE_NVME_DATAPLANE = true;
pub const KERNEL_LATCHES_ONLY = true;
pub const DISPATCHES_FROM_BOUND_TASK = true;

const pci = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/pci.zig")
else
    struct {
        pub fn firstNvmeController() ?void {
            return null;
        }
    };
const nvme_hw = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/nvme_hw.zig")
else
    struct {
        pub fn attached() bool {
            return false;
        }
        pub fn probeAndReport(_: anytype, _: anytype, _: anytype) !?void {
            return null;
        }
        pub fn activateInterrupts() !void {}
        pub fn publishedBar() ?struct { physical_base: u64, length: u64 } {
            return null;
        }
    };
const intel_i225_hw = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/intel_i225_hw.zig")
else
    struct {
        pub fn isolationDomain() ?void {
            return null;
        }
    };
const xhci_hw = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/xhci_hw.zig")
else
    struct {
        pub fn isolationDomain() ?void {
            return null;
        }
    };
const intel_vtd = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/platform/intel_vtd.zig")
else
    struct {};
const hardware_proof = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/platform/hardware_proof.zig")
else
    struct {
        pub fn realTargetDetected() bool {
            return false;
        }
        pub fn vtdSummary() ?void {
            return null;
        }
        pub fn recordVtdIsolationProof(_: anytype) void {}
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

var bound_task_id: u64 = 0;
var programmed = false;

pub fn bindTaskId(task_id: u64) void {
    bound_task_id = task_id;
    const event_wake = @import("../../kernel/event_wake.zig");
    const smp = @import("../../kernel/smp.zig");
    event_wake.bind(.nvme, smp.assignedCpu(task_id, false));
}

pub fn boundTaskId() u64 {
    return bound_task_id;
}

pub fn bringUp() bool {
    if (programmed) return true;
    if (builtin.target.os.tag != .freestanding) {
        programmed = true;
        return true;
    }
    if (nvme_hw.attached()) {
        programmed = true;
        return true;
    }
    const dev = pci.firstNvmeController() orelse {
        programmed = true;
        return true;
    };
    var isolation_domains: [2]intel_vtd.DmaDomain = undefined;
    var isolation_domain_count: usize = 0;
    if (intel_i225_hw.isolationDomain()) |domain| {
        isolation_domains[isolation_domain_count] = domain;
        isolation_domain_count += 1;
    }
    if (xhci_hw.isolationDomain()) |domain| {
        isolation_domains[isolation_domain_count] = domain;
        isolation_domain_count += 1;
    }
    var vtd_summary = if (hardware_proof.realTargetDetected())
        hardware_proof.vtdSummary() orelse return false
    else
        null;
    const vtd_summary_ptr = if (vtd_summary) |*summary| summary else null;
    const fault_proof = nvme_hw.probeAndReport(
        dev,
        vtd_summary_ptr,
        isolation_domains[0..isolation_domain_count],
    ) catch {
        console.print("ZIGOS:NVME:HW:BRINGUP_FAIL\n");
        return false;
    };
    if (fault_proof) |proof| hardware_proof.recordVtdIsolationProof(proof);
    var interrupts_ready = true;
    nvme_hw.activateInterrupts() catch {
        interrupts_ready = false;
        if (hardware_proof.realTargetDetected()) {
            console.print("ZIGOS:NVME:HW:INTERRUPT_BRINGUP_FAIL\n");
            return false;
        }
        console.print("ZIGOS:NVME:HW:INTERRUPT_UNAVAILABLE\n");
    };
    if (interrupts_ready) console.print("ZIGOS:NVME:HW:REMAP_MSI_OK\n");
    programmed = true;
    return true;
}

pub fn bringUpForTask(task_id: u64) bool {
    if (bound_task_id != 0 and task_id != bound_task_id) return false;
    return bringUp();
}

pub fn reset() void {
    bound_task_id = 0;
    programmed = false;
}

test "storage driver task programs NVMe only for the bound task" {
    const std = @import("std");
    reset();
    try std.testing.expect(bringUpForTask(7));
    bindTaskId(7);
    try std.testing.expect(bringUpForTask(7));
    try std.testing.expect(!bringUpForTask(8));
    try std.testing.expectEqual(@as(u64, 7), boundTaskId());
    try std.testing.expect(USERSPACE_NVME_DATAPLANE);
    try std.testing.expect(KERNEL_LATCHES_ONLY);
    try std.testing.expect(DISPATCHES_FROM_BOUND_TASK);
    reset();
}
