const std = @import("std");
const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const scheduler = @import("../../process/scheduler.zig");
const process = @import("../../process/process.zig");
const smp = @import("../../smp/smp.zig");
const common = @import("../common.zig");

const smp_stress_task_count: usize = 6;
const smp_stress_rounds: usize = 256;

fn printSmpStats() void {
    const stats = scheduler.getStatistics();
    var line_buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "SMP:STATS:context_switches={d}:ready={d}:blocked={d}:cpu_usage={d}\n",
        .{ stats.context_switches, stats.ready_processes, stats.blocked_processes, stats.cpu_usage_percent },
    ) catch "SMP:STATS\n";
    console.print(line);
}

pub fn run() noreturn {
    const task_entries = [_]struct {
        name: []const u8,
        priority: scheduler.Priority,
    }{
        .{ .name = "smp-stress-0", .priority = .High },
        .{ .name = "smp-stress-1", .priority = .Normal },
        .{ .name = "smp-stress-2", .priority = .Low },
        .{ .name = "smp-stress-3", .priority = .High },
        .{ .name = "smp-stress-4", .priority = .Normal },
        .{ .name = "smp-stress-5", .priority = .Low },
    };
    var stress_processes: [smp_stress_task_count]*process.Process = undefined;
    var sink: u32 = 0;

    const runner = process.create_kernel_process("smp_stress_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running SMP scheduler stress...\n");
    common.printBootMarker("SMP:START");
    console.print("SMP:ACTIVE_CPUS:");
    common.printCpuCount(smp.getActiveCPUCount());
    console.print("\n");

    scheduler.setSchedulerType(.MultiLevelFeedback);

    for (task_entries, 0..) |task, idx| {
        const proc = process.create_kernel_process_any_cpu(task.name, common.idleTaskPlaceholder);
        _ = scheduler.setProcessPriority(proc.pid, task.priority);
        stress_processes[idx] = proc;
    }
    common.printBootMarker("SMP:TASKS_CREATED");

    for (0..smp_stress_rounds) |round| {
        const proc = stress_processes[round % stress_processes.len];
        const next_priority = task_entries[(round + 1) % task_entries.len].priority;
        _ = scheduler.setProcessPriority(proc.pid, next_priority);
        _ = scheduler.setProcessNice(proc.pid, @intCast(@as(i32, @intCast(round % 3)) - 1));

        if ((round & 1) == 0) {
            scheduler.blockProcess(proc);
            scheduler.unblockProcess(proc);
        }

        if (scheduler.tryScheduleLocalForCPU(0)) |selected| {
            sink +%= selected.pid;
        }
    }

    std.mem.doNotOptimizeAway(&sink);

    common.printBootMarker("SMP:TASKS_DONE");
    printSmpStats();

    if (scheduler.getStatistics().context_switches < 16) {
        common.printBootMarker("SMP:FAIL");
        qemu_exit.failure();
    }

    common.printBootMarker("SMP:PASS");
    qemu_exit.success();
}
