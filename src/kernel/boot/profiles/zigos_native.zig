const common = @import("../common.zig");
const boot_markers = @import("../markers.zig");
const x86 = @import("../../../arch/x86.zig");
const session_manager = @import("root").session_manager;
const timer = @import("../../timer/timer.zig");
const hardware_proof = @import("../../platform/hardware_proof.zig");
const device_inventory = @import("../../../native/drivers/device_inventory.zig");
const xhci_driver_task = @import("../../../native/drivers/xhci_driver_task.zig");
const event_wake = @import("../../event_wake.zig");
const smp = @import("../../smp.zig");
const framebuffer_hw = @import("../../platform/framebuffer_hw.zig");
const desktop_display = @import("../../../native/platform/desktop_display.zig");

var recorded_input_report_count: u64 = 0;
var reported_scheduler_idle = false;

pub const INTERRUPT_DRIVEN_IDLE = event_wake.INTERRUPT_DRIVEN_IDLE;

pub fn run() noreturn {
    framebuffer_hw.init() catch {
        common.printBootMarker("ZIGOS:DESKTOP:FRAMEBUFFER:UNAVAILABLE");
    };
    session_manager.bindHardwareInput(.{
        .poll_report = pollHardwareKeyboardReport,
        .input_proof = hardwareInputProof,
        .continuity_epoch = xhci_driver_task.keyboardContinuityEpoch,
    });
    session_manager.boot();
    while (true) {
        timer.synchronize();
        const now_ticks = timer.getTicks();
        const pending = event_wake.take();
        // Expiry revokes input/identity authority before a userspace task can
        // consume another event, including wakes without keyboard activity.
        session_manager.system().serviceAuthenticationClock(now_ticks);

        wakeBoundXhciTask(xhci_driver_task, session_manager, pending, now_ticks);
        if (pending.network or session_manager.networkWorkPending()) {
            _ = session_manager.servicePendingNetworkWork(now_ticks);
        }
        _ = session_manager.runUserspaceScheduler(now_ticks);
        if (pending.xhci or pending.timer) {
            harvestInputProof();
            _ = session_manager.servicePendingInputWork(now_ticks);
            _ = desktop_display.present(session_manager.system().compositorSessionPtr());
        }

        x86.cli();
        const dispatchable_tasks = session_manager.userspaceSchedulerHasDispatchableTasks(timer.getTicks());
        if (event_wake.any() or dispatchable_tasks or session_manager.networkWorkPending()) {
            if (dispatchable_tasks) timer.armSchedulerTick();
            x86.sti();
            continue;
        }
        if (xhci_driver_task.lifecyclePending()) {
            timer.armSchedulerTick();
        } else if (session_manager.nextServiceWake()) |deadline| {
            timer.armWakeAt(deadline);
        } else {
            timer.disarmSchedulerTick();
            if (!reported_scheduler_idle) {
                reported_scheduler_idle = true;
                common.printBootMarker(boot_markers.userspace_scheduler_idle);
            }
        }
        smp.idle();
    }
}

inline fn wakeBoundXhciTask(driver: anytype, manager: anytype, pending: event_wake.Pending, now_ticks: u64) void {
    // IRQs always get a drain. Timer wakes only service CQ/lifecycle work,
    // including command, transfer and port deadlines without a new interrupt.
    if (pending.xhci or (pending.timer and driver.workPending())) {
        const bound_task_id = driver.boundTaskId();
        if (bound_task_id != 0) _ = manager.wakeUserspaceTask(bound_task_id, now_ticks);
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

const WakeTest = if (@import("builtin").is_test) struct {
    const std = @import("std");
    const executor_mod = @import("../../../native/task/userspace_executor.zig");
    const scheduler_mod = @import("../../../native/task/userspace_scheduler.zig");
    const runtime_mod = @import("../../../native/task/task_runtime.zig");
    const loader = @import("../../../native/task/userspace_loader.zig");
    const capability = @import("../../../native/kernel_api/capability.zig");
    executor: executor_mod.Executor = .{},
    scheduler: scheduler_mod.Scheduler = undefined,
    runtime: runtime_mod.Runtime = runtime_mod.Runtime.init(),
    catalog: loader.Catalog = loader.Catalog.init(),
    capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    task_id: u64 = 0,
    wake_calls: usize = 0,

    const Driver = struct {
        bound_id: u64,
        pending: bool = false,
        pending_reads: usize = 0,

        pub fn boundTaskId(self: *@This()) u64 {
            return self.bound_id;
        }
        pub fn workPending(self: *@This()) bool {
            self.pending_reads += 1;
            return self.pending;
        }
    };

    fn create() !*@This() {
        const self = try std.testing.allocator.create(@This());
        errdefer std.testing.allocator.destroy(self);
        self.* = .{};
        self.scheduler = scheduler_mod.Scheduler.init(&self.executor);
        self.scheduler.bind(&self.catalog, &self.runtime, &self.capabilities);
        errdefer {
            self.scheduler.deinit();
            self.runtime.reset();
        }
        const image = try @import("../../../native/task/generated_image_fixtures.zig").serviceImage();
        const task = try self.runtime.createTask(.{
            .owner = .{ .kind = .service, .serial = 1 },
            .component_class = .service_component,
            .budget = .{ .cpu_time_ticks = 2_000, .memory_bytes = 4_096, .endpoint_slots = 2, .shared_memory_bytes = 0 },
            .local_only = true,
            .launch = .{ .boundary = .userspace_process, .image_id = 1, .component_abi_version = 1, .signed = true, .bundle_id = "svc.compositor-ui-session" },
            .userspace_image = &image,
        });
        self.task_id = task.id;
        try std.testing.expect(self.scheduler.registerTaskAt(task.id, 1));
        return self;
    }

    fn destroy(self: *@This()) void {
        self.scheduler.deinit();
        self.runtime.reset();
        std.testing.allocator.destroy(self);
    }

    pub fn wakeUserspaceTask(self: *@This(), task_id: u64, now_ticks: u64) bool {
        self.wake_calls += 1;
        return self.scheduler.wakeTask(task_id, .external_event, now_ticks, 0);
    }

    fn parked(self: *@This()) !void {
        try std.testing.expect(self.scheduler.parkTaskUntilEvent(self.task_id));
        try std.testing.expectEqual(@as(usize, 0), self.scheduler.readyQueueDepth(.foreground_interactive));
    }
} else struct {};

test "native xHCI wake gate leaves an idle compositor parked on timer events" {
    const std = @import("std");
    const fixture = try WakeTest.create();
    defer fixture.destroy();
    var driver = WakeTest.Driver{ .bound_id = fixture.task_id };
    // Registration is already ready before the first driver dispatch: initial
    // controller bring-up does not depend on a timer manufacturing a wake.
    try std.testing.expectEqual(@as(usize, 1), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(fixture.scheduler.hasDispatchableTasks(1));
    try fixture.parked();
    const wakes = fixture.scheduler.taskDispatchAccounting(fixture.task_id).?.wake_event_count;
    for (2..102) |now| wakeBoundXhciTask(&driver, fixture, .{ .timer = true }, @intCast(now));
    try std.testing.expectEqual(@as(usize, 0), fixture.wake_calls);
    try std.testing.expectEqual(wakes, fixture.scheduler.taskDispatchAccounting(fixture.task_id).?.wake_event_count);
    try std.testing.expectEqual(@as(usize, 0), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(!fixture.scheduler.hasDispatchableTasks(102));
}

test "native xHCI wake gate preserves IRQ and pending timer activations" {
    const std = @import("std");
    const fixture = try WakeTest.create();
    defer fixture.destroy();
    var driver = WakeTest.Driver{ .bound_id = fixture.task_id };
    try fixture.parked();
    wakeBoundXhciTask(&driver, fixture, .{ .xhci = true }, 2);
    try std.testing.expectEqual(@as(usize, 0), driver.pending_reads);
    try std.testing.expectEqual(@as(usize, 1), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try fixture.parked();
    driver.pending = true;
    wakeBoundXhciTask(&driver, fixture, .{ .timer = true }, 3);
    try std.testing.expectEqual(@as(usize, 1), driver.pending_reads);
    try std.testing.expectEqual(@as(usize, 1), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(u64, 3), fixture.scheduler.taskDispatchAccounting(fixture.task_id).?.last_wake_tick);
    try fixture.parked();
    wakeBoundXhciTask(&driver, fixture, .{ .network = true, .nvme = true, .scheduler = true }, 4);
    try std.testing.expectEqual(@as(usize, 0), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(usize, 1), driver.pending_reads);
}

test "native xHCI wake gate coalesces latched events and ignores a missing binding" {
    const std = @import("std");
    const fixture = try WakeTest.create();
    defer fixture.destroy();
    var driver = WakeTest.Driver{ .bound_id = 0, .pending = true };
    wakeBoundXhciTask(&driver, fixture, .{ .xhci = true, .timer = true }, 2);
    try std.testing.expectEqual(@as(usize, 0), fixture.wake_calls);
    try fixture.parked();
    driver.bound_id = fixture.task_id;
    const saved_pending = event_wake.take();
    defer {
        _ = event_wake.take();
        inline for (std.meta.tags(event_wake.Kind)) |kind| {
            if ((@as(u8, @bitCast(saved_pending)) & (@as(u8, 1) << @backingInt(kind))) != 0) event_wake.raise(kind);
        }
    }
    for (0..8) |_| {
        event_wake.raise(.xhci);
        event_wake.raise(.timer);
    }
    wakeBoundXhciTask(&driver, fixture, event_wake.take(), 3);
    try std.testing.expectEqual(@as(usize, 1), fixture.wake_calls);
    try std.testing.expectEqual(@as(usize, 1), fixture.scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(u64, 2), fixture.scheduler.taskDispatchAccounting(fixture.task_id).?.wake_event_count);
    wakeBoundXhciTask(&driver, fixture, event_wake.take(), 4);
    try std.testing.expectEqual(@as(usize, 1), fixture.wake_calls);
}
