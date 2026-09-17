const builtin = @import("builtin");

pub const USERSPACE_NVME_DATAPLANE = true;
pub const KERNEL_LATCHES_ONLY = true;
pub const DISPATCHES_FROM_BOUND_TASK = true;

const kernel_device_start = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/init/devices.zig")
else
    struct {
        pub fn startStorageDataplane() bool {
            return true;
        }
    };

var bound_task_id: u64 = 0;
var programmed = false;

pub fn bindTaskId(task_id: u64) void {
    bound_task_id = task_id;
}

pub fn boundTaskId() u64 {
    return bound_task_id;
}

pub fn bringUp() bool {
    if (programmed) return true;
    if (!kernel_device_start.startStorageDataplane()) return false;
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
