const builtin = @import("builtin");
const std = @import("std");
const task_runtime = @import("task_runtime.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_loader = @import("userspace_loader.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const Slot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    dispatch_count: u64 = 0,
    last_dispatch_tick: u64 = 0,
};

var initialized = false;
var catalog_ptr: ?*userspace_loader.Catalog = null;
var runtime_ptr: ?*task_runtime.Runtime = null;
var slots: [task_runtime.MAX_TASKS]Slot = [_]Slot{Slot{}} ** task_runtime.MAX_TASKS;
var next_index: usize = 0;
var last_dispatch_tick: u64 = 0;
var ready_marker_printed = false;
var active_marker_printed = false;

pub fn reset() void {
    initialized = false;
    catalog_ptr = null;
    runtime_ptr = null;
    slots = [_]Slot{Slot{}} ** task_runtime.MAX_TASKS;
    next_index = 0;
    last_dispatch_tick = 0;
    ready_marker_printed = false;
    active_marker_printed = false;
    userspace_executor.reset();
}

pub fn init(catalog: *userspace_loader.Catalog, runtime: *task_runtime.Runtime) void {
    catalog_ptr = catalog;
    runtime_ptr = runtime;
    initialized = true;
    next_index = 0;
    last_dispatch_tick = 0;
    userspace_executor.init();
    if (builtin.target.os.tag == .freestanding and !ready_marker_printed) {
        common.printBootMarker("ZIGOS:USERSPACE:SCHEDULER:READY");
        ready_marker_printed = true;
    }
}

pub fn registerTask(task_id: u64) bool {
    if (!initialized) return false;
    for (&slots) |*slot| {
        if (slot.in_use and slot.task_id == task_id) return false;
    }

    for (&slots) |*slot| {
        if (slot.in_use) continue;
        slot.* = .{
            .in_use = true,
            .task_id = task_id,
        };
        return true;
    }
    return false;
}

pub fn runNext(now_ticks: u64) bool {
    if (!initialized) return false;

    const catalog = catalog_ptr orelse return false;
    const runtime = runtime_ptr orelse return false;

    var attempts: usize = 0;
    while (attempts < slots.len) : (attempts += 1) {
        const index = (next_index + attempts) % slots.len;
        const slot = &slots[index];
        if (!slot.in_use) continue;

        const task = runtime.find(slot.task_id) orelse {
            slot.in_use = false;
            continue;
        };
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) {
            continue;
        }

        last_dispatch_tick = now_ticks;
        next_index = (index + 1) % slots.len;
        const yielded = dispatch(catalog, runtime, slot.task_id);
        slot.dispatch_count += 1;
        slot.last_dispatch_tick = now_ticks;
        if (builtin.target.os.tag == .freestanding and yielded and !active_marker_printed) {
            common.printBootMarker("ZIGOS:USERSPACE:SCHEDULER:ACTIVE");
            active_marker_printed = true;
        }
        return yielded;
    }

    last_dispatch_tick = now_ticks;
    return false;
}

fn dispatch(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    task_id: u64,
) bool {
    return userspace_executor.executeTask(catalog, runtime, task_id);
}
