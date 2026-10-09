const std = @import("std");
const native = @import("scheduler");

const SAMPLE_COUNT = 9;
const ITERATIONS: usize = 2_000_000;
const WARMUP_ITERATIONS: usize = native.MAX_TASKS * 128;
const CPU_BUDGET: u64 = 5000;
const FOREGROUND_DEADLINE_TICKS = native.units.millisecondsToTimerTicksCeil(50);

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Native scheduler wake host benchmark: median of {d} samples, {d} iterations/sample\n", .{ SAMPLE_COUNT, ITERATIONS });
    try output.interface.flush();
    for ([_]usize{ 1, native.MAX_TASKS }) |task_count| {
        if (ITERATIONS % task_count != 0 or WARMUP_ITERATIONS % task_count != 0) return error.UnbalancedWorkload;
        inline for ([_]bool{ false, true }) |reactivate| {
            var executor = native.Executor{};
            var scheduler = native.Scheduler.init(&executor);
            var runtime = native.Runtime.init();
            defer runtime.reset();
            var catalog = native.Catalog.init();
            var capabilities = native.CapabilityTable.init();
            scheduler.bind(&catalog, &runtime, &capabilities);
            defer scheduler.deinit();
            var task_ids: [native.MAX_TASKS]u64 = undefined;
            const image = native.syntheticUserspaceImage("wake-measurement", "wake-measurement.entry");
            for (task_ids[0..task_count], 0..) |*task_id, index| {
                const task = try runtime.createTask(.{
                    .owner = .{ .kind = .app, .serial = @intCast(index + 1) },
                    .component_class = .app_component,
                    .budget = .{ .cpu_time_ticks = CPU_BUDGET, .memory_bytes = 64 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
                    .local_only = true,
                    .launch = .{ .boundary = .userspace_process, .image_id = @intCast(index + 1), .signed = true, .bundle_id = "app.wake-measurement" },
                    .userspace_image = &image,
                });
                task_id.* = task.id;
                if (!scheduler.registerTaskAt(task.id, 0)) return error.RegistrationFailed;
            }
            var now_ticks: u64 = 0;
            for (0..WARMUP_ITERATIONS) |iteration| {
                try wakeIteration(reactivate, &scheduler, &runtime, task_ids[iteration % task_count], now_ticks);
                now_ticks += 1;
            }
            var samples: [SAMPLE_COUNT]u64 = undefined;
            for (&samples) |*sample| {
                const start = std.Io.Clock.awake.now(init.io);
                for (0..ITERATIONS) |iteration| {
                    try wakeIteration(reactivate, &scheduler, &runtime, task_ids[iteration % task_count], now_ticks);
                    now_ticks += 1;
                }
                sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
            }
            std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
            if (scheduler.readyQueueDepth(.foreground_interactive) != task_count) return error.IncorrectReadyQueue;
            var checksum: u64 = 0;
            for (task_ids[0..task_count], 0..) |task_id, index| {
                const stats = scheduler.taskDispatchStats(task_id).?;
                const slot = scheduler.slots.getConst(task_id).?;
                const last_tick = WARMUP_ITERATIONS + SAMPLE_COUNT * ITERATIONS - task_count + index;
                const deadline = if (reactivate) last_tick + FOREGROUND_DEADLINE_TICKS else FOREGROUND_DEADLINE_TICKS;
                if (!stats.queued_ready or
                    stats.wake_event_count != 1 + (WARMUP_ITERATIONS + SAMPLE_COUNT * ITERATIONS) / task_count or
                    stats.last_wake_tick != last_tick or
                    slot.cpu_budget_remaining_ticks != CPU_BUDGET or
                    slot.deadline_tick != deadline or
                    runtime.findByHandle(slot.task_handle, task_id) == null)
                {
                    return error.IncorrectWakeState;
                }
                checksum +%= stats.wake_event_count + stats.last_wake_tick + slot.cpu_budget_remaining_ticks + slot.deadline_tick;
            }
            try output.interface.print("{d} tasks, {s}: {d:.2} ns/{s}; checksum={d}\n", .{
                task_count,
                if (reactivate) "reactivated" else "coalesced",
                @as(f64, @floatFromInt(samples[SAMPLE_COUNT / 2])) / ITERATIONS,
                if (reactivate) "park+wake" else "wake",
                checksum,
            });
            try output.interface.flush();
        }
    }
}

fn wakeIteration(comptime reactivate: bool, scheduler: *native.Scheduler, runtime: *native.Runtime, task_id: u64, now_ticks: u64) !void {
    if (reactivate and !scheduler.parkTaskUntilEvent(task_id)) return error.ParkFailed;
    if (!scheduler.wakeTask(task_id, .external_event, now_ticks, 0)) return error.WakeFailed;
    std.mem.doNotOptimizeAway(scheduler);
    std.mem.doNotOptimizeAway(runtime);
}
